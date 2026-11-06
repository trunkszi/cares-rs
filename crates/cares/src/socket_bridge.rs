//! c-ares socket callbacks, descriptor generations, and deferred readiness.
//!
//! Interest notifications are delivered outside native processing scopes; stale
//! updates are rejected after descriptor closure or reuse.
mod hooks;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    io,
    marker::PhantomData,
    mem::{MaybeUninit, size_of},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    rc::Rc,
};

use cares_sys::{
    ares_channel_t, ares_fd_events_t, ares_socket_functions_ex, ares_socket_opt_t, ares_socket_t,
    ares_socklen_t, ares_ssize_t,
};
pub use hooks::socket_state_callback;
use hooks::{
    abind, aclose, aconnect, agetsockname, aif_indextoname, aif_nametoindex, arecvfrom, asendto,
    asetsockopt, asocket, cvt, read_int,
};
use libc::{c_char, c_int, c_uint, c_void, sockaddr, sockaddr_storage, socklen_t};
use uarch::prelude::*;

use crate::error::{AresError, Result};
const OPT_SENDBUF_SIZE: c_uint = ares_socket_opt_t::ARES_SOCKET_OPT_SENDBUF_SIZE.0;
const OPT_RECVBUF_SIZE: c_uint = ares_socket_opt_t::ARES_SOCKET_OPT_RECVBUF_SIZE.0;
const OPT_BIND_DEVICE: c_uint = ares_socket_opt_t::ARES_SOCKET_OPT_BIND_DEVICE.0;
/// READ/WRITE interest requested for one descriptor.
#[register_pass]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketInterest {
    /// The descriptor should report readable readiness.
    pub readable: bool,
    /// The descriptor should report writable readiness.
    pub writable: bool,
}
/// Consumer of socket interest changes.
/// The proactor implements this over its readiness registrations; the bridge
/// never calls it while holding an internal borrow.
pub trait ReadinessSink {
    /// Replaces the interest recorded for `fd` with `interest`.
    fn update_interest(&self, fd: ares_socket_t, interest: SocketInterest);
    /// Removes all interest for `fd` before the descriptor is closed.
    fn remove_interest(&self, fd: ares_socket_t);
}
/// Table entry for a descriptor created through the bridge.
#[derive(Default)]
struct SocketEntry {
    generation: u64,
    socket_type: c_int,
    /// Peer cached by a successful datagram `connect(2)`.
    peer: Option<(sockaddr_storage, ares_socklen_t)>,
    /// Last READ/WRITE mask accepted for this generation. Repeats are ignored.
    interest: Option<SocketInterest>,
}
/// Interest notification recorded while a process scope is active.
#[derive(Clone, Copy, Debug)]
struct PendingSocketUpdate {
    fd: ares_socket_t,
    generation: u64,
    interest: SocketInterest,
}
/// Decrements the scope depth and flushes the deferred queue on the way out.
struct ProcessScopeGuard<'a> {
    state: &'a SharedChannelState,
}
impl Drop for ProcessScopeGuard<'_> {
    fn drop(&mut self) {
        let depth = self.state.depth.get().saturating_sub(1);
        self.state.depth.set(depth);
        if depth == 0 {
            self.state.flush_pending();
        }
    }
}
/// Socket table, deferred interest and readiness queue for one resolver channel.
/// The type is `!Send + !Sync` and must stay at a stable address while a
/// channel uses it; c-ares stores its pointer for the channel's lifetime.
pub struct SharedChannelState {
    sockets: RefCell<HashMap<ares_socket_t, SocketEntry>>,
    sink: RefCell<Option<Rc<dyn ReadinessSink>>>,
    pending: RefCell<Vec<PendingSocketUpdate>>,
    ready: RefCell<Vec<ares_fd_events_t>>,
    depth: Cell<u32>,
    closing: Cell<bool>,
    sink_failed: Cell<bool>,
    sink_panic: RefCell<Option<Box<dyn std::any::Any + Send>>>,
    next_generation: Cell<u64>,
    _not_send: PhantomData<*mut ()>,
}
impl Default for SharedChannelState {
    fn default() -> Self {
        Self::new()
    }
}
impl SharedChannelState {
    /// Creates an empty bridge with no readiness sink installed.
    pub fn new() -> Self {
        Self {
            sockets: RefCell::new(HashMap::new()),
            sink: RefCell::new(None),
            pending: RefCell::new(Vec::new()),
            ready: RefCell::new(Vec::new()),
            depth: Cell::new(0),
            closing: Cell::new(false),
            sink_failed: Cell::new(false),
            sink_panic: RefCell::new(None),
            next_generation: Cell::new(0),
            _not_send: PhantomData,
        }
    }
    /// Installs the ten-hook socket function table on `channel`.
    /// `channel` must remain live throughout the call and come from
    /// [`Self::sock_state_binding`]-configured `ares_options`; `self` must stay
    /// alive and address-stable until `ares_destroy` releases its callbacks.
    /// # Errors
    /// Returns [`AresError::InvalidInput`] for a null channel and the exact
    /// c-ares status when rejected; returns [`AresError::CallbackPanicked`]
    /// after a sink panic.
    /// # Safety
    /// A non-null channel must be live, owned by this thread, and configured with
    /// this state's socket callback. Keep self address-stable until channel destruction.
    pub unsafe fn install(&self, channel: *mut ares_channel_t) -> Result<()> {
        if channel.is_null() {
            return Err(AresError::invalid_input("ares channel must not be null"));
        }
        if self.sink_failed.get() {
            return Err(AresError::CallbackPanicked);
        }
        // SAFETY: `channel` is non-null and, per this contract, live; `self` stays stable until
        // `ares_destroy`, and the table is static.
        let status = unsafe {
            cares_sys::ares_set_socket_functions_ex(
                channel,
                &SOCKET_FUNCTIONS,
                ptr::from_ref(self).cast_mut().cast(),
            )
        };
        AresError::check(status)
    }
    /// Returns the callback and data pointer for `ares_options`; set
    /// `ARES_OPT_SOCK_STATE_CB` before `ares_init_options`.
    pub fn sock_state_binding(&self) -> (cares_sys::ares_sock_state_cb, *mut c_void) {
        (
            Some(socket_state_callback),
            ptr::from_ref(self).cast_mut().cast(),
        )
    }
    pub(crate) fn socket_generation(&self, fd: ares_socket_t) -> Option<u64> {
        self.sockets.borrow().get(&fd).map(|entry| entry.generation)
    }
    /// Installs the consumer that receives interest changes.
    pub fn set_readiness_sink(&self, sink: Rc<dyn ReadinessSink>) {
        let previous = self.sink.borrow_mut().replace(sink);
        self.catch_sink(|| drop(previous));
        if self.sink_failed.get() {
            self.shutdown();
        }
    }
    /// Coalesces readiness for a live `fd`; flags are OR-ed, order is kept.
    /// The caller must cancel old registrations before fd reuse: fd-only
    /// notifications cannot identify a completion from a previous generation.
    #[inline]
    pub fn on_ready(&self, fd: ares_socket_t, readable: bool, writable: bool) {
        if fd < 0 || !self.sockets.borrow().contains_key(&fd) {
            return;
        }
        let mut events = 0u32;
        if readable {
            events |= cares_sys::ARES_FD_EVENT_READ.0;
        }
        if writable {
            events |= cares_sys::ARES_FD_EVENT_WRITE.0;
        }
        if events == 0 {
            return;
        }
        let mut ready = self.ready.borrow_mut();
        if let Some(existing) = ready.iter_mut().find(|event| event.fd == fd) {
            existing.events |= events;
        } else {
            ready.push(ares_fd_events_t { fd, events });
        }
    }
    /// Moves every coalesced event into `out` (appending) and returns the count.
    #[inline]
    pub fn drain_ready(&self, out: &mut Vec<ares_fd_events_t>) -> usize {
        let mut ready = self.ready.borrow_mut();
        let count = ready.len();
        out.append(&mut ready);
        count
    }
    /// Reports whether coalesced readiness events are waiting to be drained.
    pub fn has_pending(&self) -> bool {
        !self.ready.borrow().is_empty()
    }
    /// Closes owned descriptors after removing interest; reentrant calls are inert.
    /// A panicking sink is detached and recorded by [`Self::readiness_sink_failed`].
    #[cold_sink]
    pub fn shutdown(&self) {
        if self.closing.replace(true) {
            return;
        }
        let sockets = std::mem::take(&mut *self.sockets.borrow_mut());
        let sink = self.sink.borrow_mut().take();
        self.pending.borrow_mut().clear();
        self.ready.borrow_mut().clear();
        for fd in sockets.into_keys() {
            if !self.sink_failed.get()
                && let Some(sink) = sink.as_ref()
            {
                self.catch_sink(|| sink.remove_interest(fd));
            }
            // SAFETY: ownership was removed before callbacks, so nested shutdown cannot close this
            // descriptor or a replacement using its number.
            unsafe { libc::close(fd) };
        }
        self.catch_sink(|| drop(sink));
        self.closing.set(false);
    }
    /// Reports a caught sink panic; the bridge then rejects further I/O.
    pub fn readiness_sink_failed(&self) -> bool {
        self.sink_failed.get()
    }
    /// Takes the first sink panic payload without clearing the failure latch.
    /// Drop or resume this payload only outside a C callback.
    pub fn take_readiness_panic(&self) -> Option<Box<dyn std::any::Any + Send>> {
        self.sink_panic.borrow_mut().take()
    }
    /// Returns the number of descriptors currently owned by the bridge.
    pub fn socket_count(&self) -> usize {
        self.sockets.borrow().len()
    }
    /// Returns a snapshot of the live descriptors for a standalone poll driver.
    pub fn fds(&self) -> Vec<ares_socket_t> {
        self.sockets.borrow().keys().copied().collect()
    }
    /// Runs `f` with socket-state notifications deferred, then flushes them.
    /// The outermost scope flushes on unwind too; stale entries are discarded.
    /// # Panics
    /// Propagates a panic from `f`; sink panics are caught and fail the bridge closed.
    pub fn with_process_scope<R>(&self, f: impl FnOnce() -> R) -> R {
        self.depth.set(self.depth.get().saturating_add(1));
        let guard = ProcessScopeGuard { state: self };
        let result = f();
        drop(guard);
        result
    }
    /// Runs `ares_process_fds` inside a process scope; use this instead of
    /// calling `ares_process_fds` directly so notifications stay deferred.
    /// `channel` must be live and `events` must cover `nevents` entries, or be
    /// null when `nevents` is zero. Null violations return `ARES_EFORMERR`;
    /// a failed readiness sink returns `ARES_EDESTRUCTION`.
    /// # Safety
    /// A non-null channel must be initialized on this thread. A non-null events
    /// pointer must cover nevents initialized entries for the synchronous call.
    pub unsafe fn process_fds(
        &self,
        channel: *mut ares_channel_t,
        events: *const ares_fd_events_t,
        nevents: usize,
        flags: libc::c_uint,
    ) -> cares_sys::ares_status_t {
        if channel.is_null() || (nevents != 0 && events.is_null()) {
            return cares_sys::ARES_EFORMERR;
        }
        if self.sink_failed.get() || self.closing.get() {
            return cares_sys::ARES_EDESTRUCTION;
        }
        let status = self.with_process_scope(|| {
            // SAFETY: the caller supplies a live channel and an events array of `nevents`
            // initialized entries, or a null array when `nevents` is zero, matching the c-ares
            // contract for `ares_process_fds`.
            unsafe { cares_sys::ares_process_fds(channel, events, nevents, flags) }
        });
        if self.sink_failed.get() {
            cares_sys::ARES_EDESTRUCTION
        } else {
            status
        }
    }
    /// Creates a nonblocking close-on-exec socket and records it in the table.
    /// Stream sockets get best-effort `TCP_NODELAY`.
    /// # Errors
    /// Returns the OS error from `socket(2)`, or `EIO` during shutdown or after
    /// a sink panic, or `EOVERFLOW` when socket generations are exhausted.
    pub fn open_socket(
        &self,
        domain: c_int,
        socket_type: c_int,
        protocol: c_int,
    ) -> io::Result<ares_socket_t> {
        if self.sink_failed.get() || self.closing.get() {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let generation = self.next_generation()?;
        // SAFETY: socket(2) only reads its arguments and returns a new descriptor or -1.
        let fd = unsafe {
            libc::socket(
                domain,
                socket_type | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if socket_type == libc::SOCK_STREAM {
            let value: c_int = 1;
            // SAFETY: `fd` is a freshly created stream socket and `value` is a valid c_int readable
            // for size_of::<c_int>() bytes. The result is deliberately ignored: TCP_NODELAY is not
            // required for correctness.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    (&raw const value).cast(),
                    size_of::<c_int>() as socklen_t,
                );
            }
        }
        self.sockets.borrow_mut().insert(
            fd,
            SocketEntry {
                generation,
                socket_type,
                ..SocketEntry::default()
            },
        );
        Ok(fd)
    }
    /// Removes `fd` from the table, drops its deferred interest, tells the sink,
    /// then closes it.
    /// # Errors
    /// Returns `EBADF` when the descriptor is not in the table, otherwise the
    /// OS error from `close(2)`, or `EIO` after a sink panic. The owned descriptor
    /// is still closed when the sink panics.
    pub fn close_socket(&self, fd: ares_socket_t) -> io::Result<()> {
        let generation = match self.sockets.borrow_mut().remove(&fd) {
            Some(entry) => entry.generation,
            None => return Err(io::Error::from_raw_os_error(libc::EBADF)),
        };
        self.pending
            .borrow_mut()
            .retain(|update| !(update.fd == fd && update.generation == generation));
        self.ready.borrow_mut().retain(|event| event.fd != fd);
        self.notify_sink(|sink| sink.remove_interest(fd));
        // SAFETY: the table owned `fd`; removing the entry makes this the last use of the
        // descriptor, which the kernel now releases.
        let closed = cvt(unsafe { libc::close(fd) });
        if self.sink_failed.get() {
            Err(io::Error::from_raw_os_error(libc::EIO))
        } else {
            closed
        }
    }
    /// Applies one `asetsockopt` request from a safe byte slice.
    /// The raw hook validates its pointer and length and delegates here.
    /// # Errors
    /// Returns `EINVAL` for a short value or an empty device name, `ENOSYS`
    /// for TCP fast open and unknown options, and the `setsockopt(2)` error.
    pub fn apply_socket_option(
        &self,
        fd: ares_socket_t,
        opt: ares_socket_opt_t,
        value: &[u8],
    ) -> io::Result<()> {
        match opt.0 {
            OPT_SENDBUF_SIZE | OPT_RECVBUF_SIZE => {
                let Some(size) = read_int(value) else {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                };
                let name = if opt.0 == OPT_SENDBUF_SIZE {
                    libc::SO_SNDBUF
                } else {
                    libc::SO_RCVBUF
                };
                // SAFETY: `size` is a valid c_int readable for its own size; `fd` is expected to be
                // a live socket.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        name,
                        (&raw const size).cast(),
                        size_of::<c_int>() as socklen_t,
                    )
                };
                cvt(result)
            }
            OPT_BIND_DEVICE => {
                if value.is_empty() {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                // SAFETY: `value` is a live slice; the kernel reads `value.len()` bytes and
                // NUL-terminates the interface name.
                cvt(unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        value.as_ptr().cast(),
                        value.len() as socklen_t,
                    )
                })
            }
            _ => Err(io::Error::from_raw_os_error(libc::ENOSYS)),
        }
    }
    /// Sets `SO_SNDBUF`; see [`Self::apply_socket_option`].
    /// # Errors
    /// Returns the error from [`Self::apply_socket_option`].
    pub fn set_send_buffer_size(&self, fd: ares_socket_t, size: c_int) -> io::Result<()> {
        self.apply_socket_option(
            fd,
            ares_socket_opt_t::ARES_SOCKET_OPT_SENDBUF_SIZE,
            &size.to_ne_bytes(),
        )
    }
    /// Sets `SO_RCVBUF`; see [`Self::apply_socket_option`].
    /// # Errors
    /// Returns the error from [`Self::apply_socket_option`].
    pub fn set_receive_buffer_size(&self, fd: ares_socket_t, size: c_int) -> io::Result<()> {
        self.apply_socket_option(
            fd,
            ares_socket_opt_t::ARES_SOCKET_OPT_RECVBUF_SIZE,
            &size.to_ne_bytes(),
        )
    }
    /// Binds a descriptor to a network interface with `SO_BINDTODEVICE`.
    /// # Errors
    /// Returns `EINVAL` for an empty name and the OS error otherwise.
    pub fn bind_to_device(&self, fd: ares_socket_t, device: &str) -> io::Result<()> {
        let name = device.as_bytes();
        if name.is_empty() || name.contains(&0) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.apply_socket_option(fd, ares_socket_opt_t::ARES_SOCKET_OPT_BIND_DEVICE, name)
    }
    /// Records the READ/WRITE interest c-ares reported for `fd`.
    /// Unknown descriptors are ignored; scoped updates are queued.
    pub fn on_socket_state(&self, fd: ares_socket_t, readable: bool, writable: bool) {
        if fd < 0 {
            return;
        }
        let interest = SocketInterest { readable, writable };
        let generation = {
            let mut sockets = self.sockets.borrow_mut();
            let Some(entry) = sockets.get_mut(&fd) else {
                return;
            };
            if entry.interest.replace(interest) == Some(interest) {
                return;
            }
            entry.generation
        };
        if self.depth.get() > 0 {
            self.pending.borrow_mut().push(PendingSocketUpdate {
                fd,
                generation,
                interest,
            });
            return;
        }
        self.notify_sink(|sink| sink.update_interest(fd, interest));
    }
    /// Returns the number of interest notifications waiting for a scope to end.
    pub fn pending_interest_count(&self) -> usize {
        self.pending.borrow().len()
    }
    fn next_generation(&self) -> io::Result<u64> {
        let generation = self
            .next_generation
            .get()
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        self.next_generation.set(generation);
        Ok(generation)
    }
    fn cached_peer(&self, fd: ares_socket_t) -> Option<(sockaddr_storage, ares_socklen_t)> {
        self.sockets.borrow().get(&fd).and_then(|entry| entry.peer)
    }
    fn flush_pending(&self) {
        let pending = std::mem::take(&mut *self.pending.borrow_mut());
        if pending.is_empty() {
            return;
        }
        for update in pending {
            let current = self.sockets.borrow().get(&update.fd).map(|e| e.generation);
            if current != Some(update.generation) {
                continue;
            }
            self.notify_sink(|sink| sink.update_interest(update.fd, update.interest));
        }
    }
    fn catch_sink(&self, callback: impl FnOnce()) {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(callback)) {
            self.sink_failed.set(true);
            let mut first = self.sink_panic.borrow_mut();
            if first.is_none() {
                *first = Some(payload);
            } else {
                // A second payload may panic on drop inside a C callback.
                std::mem::forget(payload);
            }
        }
    }
    fn notify_sink(&self, callback: impl FnOnce(&dyn ReadinessSink)) {
        if self.sink_failed.get() {
            return;
        }
        let sink = self.sink.borrow().clone();
        if let Some(sink) = sink.as_ref() {
            self.catch_sink(|| callback(sink.as_ref()));
        }
        self.catch_sink(|| drop(sink));
        if self.sink_failed.get() {
            self.shutdown();
        }
    }
}
impl Drop for SharedChannelState {
    fn drop(&mut self) {
        self.shutdown();
        // A retained payload may itself panic on drop, including during another unwind.
        let payload = self.sink_panic.get_mut().take();
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
            std::mem::forget(payload);
        }
    }
}
/// The ABI version 1 socket function table used by [`SharedChannelState::install`].
/// All ten hooks are present and it advertises `ARES_SOCKFUNC_FLAG_NONBLOCKING`.
pub static SOCKET_FUNCTIONS: ares_socket_functions_ex = ares_socket_functions_ex {
    version: 1,
    flags: cares_sys::ARES_SOCKFUNC_FLAG_NONBLOCKING.0,
    asocket: Some(asocket),
    aclose: Some(aclose),
    asetsockopt: Some(asetsockopt),
    aconnect: Some(aconnect),
    arecvfrom: Some(arecvfrom),
    asendto: Some(asendto),
    agetsockname: Some(agetsockname),
    abind: Some(abind),
    aif_nametoindex: Some(aif_nametoindex),
    aif_indextoname: Some(aif_indextoname),
};

uarch::layout::assert_layout!(SocketInterest, size = 2, align = 1, fields = { readable: 0, writable: 1 });

#[cfg(test)]
mod generation_tests {
    use super::*;

    #[test]
    fn socket_generation_exhaustion_rejects_without_opening_another_descriptor() {
        let state = SharedChannelState::new();
        state.next_generation.set(u64::MAX - 1);
        let last = state.open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        assert!(last.is_ok());
        let last = match last {
            Ok(fd) => fd,
            Err(error) => panic!("last generation: {error}"),
        };
        assert_eq!(state.socket_generation(last), Some(u64::MAX));
        let next = state.open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        assert_eq!(
            next.as_ref().err().and_then(io::Error::raw_os_error),
            Some(libc::EOVERFLOW)
        );
        assert_eq!(state.socket_count(), 1);
        assert!(state.close_socket(last).is_ok());
    }
}
