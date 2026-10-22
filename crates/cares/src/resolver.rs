//! Channel lifecycle, completion dispatch, and per-query callback bookkeeping.
//!
//! A [`Resolver`] is `!Send + !Sync` and owns one channel built with
//! `CARES_THREADS=OFF`. Every FFI call that can deliver a completion runs under
//! DrivingGuard. Trampolines reach resolver state only through
//! `Weak<ResolverHost>` or the server-state `data` pointer, and no `RefCell` borrow is
//! held across an FFI call or user code.

use std::{
    cell::RefCell,
    collections::HashMap,
    ffi::CString,
    ptr,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use cares_sys as sys;
use libc::c_int;
use liburing::{id::OpId, socket_bridge::BridgeSubmission};
use liburing_sys::io_uring_sqe;

pub use crate::{LibraryGuard, QueryHandle, callbacks::ServerStateEvent};
use crate::{
    callbacks::CallbackState,
    error::{AresError, AresStatus, Result},
    options::ResolverOptions,
    record::{DnsRecord, DnsRecordRef},
    socket_bridge::{ReadinessSink, SharedChannelState, SocketInterest},
    support::{
        CallbackTable, DrivingGuard, HostFn, NameInfoFn, QueryFn, ResolverHost, Submission,
        dispatch, host_slot, nameinfo_slot, query_slot, reclaim, server_state_trampoline,
        submit_query_on,
    },
    timer::{TimerDeadline, TimerState},
    types::{DnsRecordType, HostEntry, NameInfo},
};

/// Upper bound on one `poll(2)` wait, so a standalone driver re-reads timers and the
/// socket set promptly.
const MAX_POLL_MILLIS: u64 = 1_000;

static NEXT_RESOLVER_ID: AtomicU64 = AtomicU64::new(1);

/// Result delivered to a DNS query callback.
pub struct QueryOutcome<'cb> {
    pub status: AresStatus,
    pub timeouts: usize,
    pub record: Option<DnsRecordRef<'cb>>,
}

/// Result delivered to a host lookup callback.
pub struct HostOutcome {
    pub status: AresStatus,
    pub timeouts: usize,
    pub host: Option<HostEntry>,
}

/// Result delivered to a name-info callback.
pub struct NameInfoOutcome {
    pub status: AresStatus,
    pub timeouts: usize,
    pub nameinfo: Option<NameInfo>,
}

/// One completion delivered by an external proactor.
#[derive(Clone, Copy, Debug)]
pub enum ResolverCqe {
    /// A channel socket became readable, writable, or reported an error.
    Socket {
        fd: sys::ares_socket_t,
        readable: bool,
        writable: bool,
    },
    /// The proactor timer armed from the most recent deadline fired.
    Timer { generation: u64 },
}

/// Summary of one completion-driving pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct PollOutcome {
    pub advanced: bool,
    pub pending: usize,
}

/// Tracks the descriptors c-ares currently wants polled, for the standalone driver.
#[derive(Default)]
struct PollInterest {
    interests: RefCell<HashMap<sys::ares_socket_t, SocketInterest>>,
}

impl ReadinessSink for PollInterest {
    fn update_interest(&self, fd: sys::ares_socket_t, interest: SocketInterest) {
        self.interests.borrow_mut().insert(fd, interest);
    }
    fn remove_interest(&self, fd: sys::ares_socket_t) {
        self.interests.borrow_mut().remove(&fd);
    }
}

/// A threadless `c-ares` resolver channel.
///
/// The value owns the channel, the socket bridge, the timer state, and the callback
/// table. Drop destroys c-ares state before releasing the library reference.
pub struct Resolver {
    host: Rc<ResolverHost>,
    sockets: Rc<SharedChannelState>,
    interest: Rc<PollInterest>,
    timer: TimerState,
    /// Kept alive because c-ares may retain pointers into these options.
    _options: ResolverOptions,
    /// Declared last so `ares_library_cleanup` is the final c-ares call.
    _guard: LibraryGuard,
}

impl Resolver {
    /// Creates a channel from validated options.
    ///
    /// # Errors
    /// Returns a library-initialization status, the `ares_init_options` status, or the
    /// socket-bridge installation error. A partial channel is destroyed first.
    pub fn new(options: ResolverOptions) -> Result<Self> {
        let guard = LibraryGuard::acquire()?;
        let sockets = Rc::new(SharedChannelState::new());
        let interest = Rc::new(PollInterest::default());
        let (sock_state_cb, sock_state_data) = sockets.sock_state_binding();
        let options = options.with_sock_state_cb(sock_state_cb, sock_state_data);
        let resolver_id = NEXT_RESOLVER_ID.fetch_add(1, Ordering::Relaxed);
        let host = Rc::new_cyclic(|weak| ResolverHost {
            channel: std::cell::Cell::new(ptr::null_mut()),
            resolver_id,
            state: Rc::new(CallbackState::new()),
            sockets: Rc::clone(&sockets),
            table: RefCell::new(CallbackTable::default()),
            driving: std::cell::Cell::new(false),
            server_state_cb: RefCell::new(None),
            self_weak: weak.clone(),
        });
        let timer = TimerState::new();
        let (raw_options, optmask) = options.as_raw();
        let mut channel: *mut sys::ares_channel_t = ptr::null_mut();
        // SAFETY: `raw_options` points into `options`, which outlives the call, and
        // c-ares copies every referenced allocation during initialization. The
        // socket-state data pointer names `sockets`, which stays alive in its `Rc`
        // allocation until after `ares_destroy`. On failure c-ares destroys its own
        // partial channel and leaves the output untouched.
        let status = unsafe { sys::ares_init_options(&mut channel, raw_options, optmask) };
        if !AresStatus::from(status).is_success() {
            return Err(AresError::from_status(status));
        }
        host.channel.set(channel);
        if let Err(error) = sockets.install(channel) {
            // SAFETY: `channel` is a live initialized channel with no queries.
            unsafe { sys::ares_destroy(channel) };
            host.channel.set(ptr::null_mut());
            return Err(error);
        }
        sockets.set_readiness_sink(Rc::clone(&interest) as Rc<dyn ReadinessSink>);
        // SAFETY: the `data` pointer is the live `Rc<ResolverHost>` allocation, kept
        // alive until after the final `ares_destroy` call that can reach it.
        unsafe {
            sys::ares_set_server_state_callback(
                channel,
                Some(server_state_trampoline),
                Rc::as_ptr(&host).cast_mut().cast(),
            );
        }
        let _deadline = timer.refresh(channel);
        Ok(Self {
            host,
            sockets,
            interest,
            timer,
            _options: options,
            _guard: guard,
        })
    }

    /// Submits a DNS query with a completion callback.
    ///
    /// # Errors
    /// Returns a poisoned-resolver, name-input, or c-ares submission error.
    pub fn submit_query<F>(
        &mut self,
        name: &str,
        record_type: DnsRecordType,
        callback: F,
    ) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        submit_query_on(&self.host, name, record_type, callback)
    }

    /// Sends a pre-built DNS message with a completion callback.
    ///
    /// # Errors
    /// Returns a poisoned-resolver, message-cloning, or c-ares submission error.
    pub fn submit_record<F>(&mut self, record: &DnsRecord, callback: F) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        let owned = record.try_clone()?;
        let raw = owned.as_ref().as_ptr();
        dispatch(
            &self.host,
            query_slot(&self.host, callback),
            Some(owned),
            Submission::Record { raw },
            reclaim::<QueryFn>,
        )
    }

    /// Looks up a host name through the c-ares host API.
    ///
    /// # Errors
    /// Returns a poisoned-resolver, name-input, or channel-liveness error.
    pub fn gethostbyname<F>(
        &mut self,
        name: &str,
        family: c_int,
        callback: F,
    ) -> Result<QueryHandle>
    where
        F: FnOnce(&ChannelCtx<'_>, HostOutcome) + 'static,
    {
        if name.is_empty() {
            return Err(AresError::invalid_input("host name must not be empty"));
        }
        dispatch(
            &self.host,
            host_slot(&self.host, callback),
            None,
            Submission::HostName {
                name: CString::new(name)?,
                family,
            },
            reclaim::<HostFn>,
        )
    }

    /// Looks up a host name from raw address bytes and an address family.
    ///
    /// # Errors
    /// Returns a poisoned-resolver, address-input, or channel-liveness error.
    pub fn gethostbyaddr<F>(
        &mut self,
        address: &[u8],
        family: c_int,
        callback: F,
    ) -> Result<QueryHandle>
    where
        F: FnOnce(&ChannelCtx<'_>, HostOutcome) + 'static,
    {
        if family != libc::AF_INET && family != libc::AF_INET6 {
            return Err(AresError::invalid_input("unsupported address family"));
        }
        if address.is_empty() || c_int::try_from(address.len()).is_err() {
            return Err(AresError::invalid_input("address length is invalid"));
        }
        dispatch(
            &self.host,
            host_slot(&self.host, callback),
            None,
            Submission::HostAddress { address, family },
            reclaim::<HostFn>,
        )
    }

    /// Resolves a socket address to a node name and service.
    ///
    /// # Errors
    /// Returns a poisoned-resolver, sockaddr-input, or channel-liveness error.
    pub fn getnameinfo<F>(
        &mut self,
        sockaddr: &[u8],
        flags: c_int,
        callback: F,
    ) -> Result<QueryHandle>
    where
        F: FnOnce(&ChannelCtx<'_>, NameInfoOutcome) + 'static,
    {
        if !(2..=core::mem::size_of::<libc::sockaddr_storage>()).contains(&sockaddr.len()) {
            return Err(AresError::invalid_input(
                "socket address length is outside the sockaddr bounds",
            ));
        }
        dispatch(
            &self.host,
            nameinfo_slot(&self.host, callback),
            None,
            Submission::NameInfo { sockaddr, flags },
            reclaim::<NameInfoFn>,
        )
    }

    /// Cancels every query pending at entry.
    ///
    /// c-ares delivers [`AresStatus::Cancelled`] to each affected callback
    /// synchronously; the channel stays usable.
    ///
    /// # Errors
    /// Returns [`AresError::CallbackPanicked`] when a callback panicked, or the
    /// channel-liveness error.
    pub fn cancel(&mut self) -> Result<()> {
        let channel = self.host.ready()?;
        {
            let _driving = DrivingGuard::enter(&self.host);
            // SAFETY: `channel` is live and remains usable after cancellation.
            unsafe { sys::ares_cancel(channel) };
        }
        self.advance()?;
        let _deadline = self.timer.refresh(channel);
        Ok(())
    }

    /// Cancels one query without disturbing the rest of the channel.
    ///
    /// # Errors
    /// Returns [`AresError::CallbackPanicked`] for a poisoned resolver or
    /// [`AresError::InvalidInput`] for a stale handle.
    pub fn cancel_query(&mut self, handle: QueryHandle) -> Result<()> {
        cancel_query_on(&self.host, handle)
    }

    /// Re-reads system resolver configuration into the live channel.
    ///
    /// # Errors
    /// Returns the `ares_reinit` status or the channel-liveness error.
    pub fn reinit(&mut self) -> Result<()> {
        let channel = self.host.ready()?;
        // SAFETY: `channel` is live; reinit replaces configuration in place.
        let status = unsafe { sys::ares_reinit(channel) };
        AresError::check(status)?;
        let _deadline = self.timer.refresh(channel);
        Ok(())
    }

    /// Replaces the server list with a `host[:port][,host[:port]...]` string.
    ///
    /// # Errors
    /// Returns an input error for an interior NUL, the `ares_set_servers_ports_csv`
    /// status, or the channel-liveness error.
    pub fn set_servers_csv(&mut self, csv: &str) -> Result<()> {
        let channel = self.host.ready()?;
        let csv = CString::new(csv)?;
        let status = {
            let _driving = DrivingGuard::enter(&self.host);
            // SAFETY: `channel` is live and `csv` is NUL-terminated; c-ares copies the
            // string before returning.
            unsafe { sys::ares_set_servers_ports_csv(channel, csv.as_ptr()) }
        };
        if self.is_poisoned() {
            return Err(AresError::CallbackPanicked);
        }
        AresError::check(status)?;
        let _deadline = self.timer.refresh(channel);
        Ok(())
    }

    /// Returns the configured servers in c-ares' CSV form.
    ///
    /// # Errors
    /// Returns [`AresError::AllocationFailed`] when c-ares cannot allocate the result,
    /// or the channel-liveness error.
    pub fn servers_csv(&self) -> Result<String> {
        let channel = self.host.ready()?;
        // SAFETY: `channel` is live; the result is a newly allocated NUL-terminated
        // string owned by the caller, or null on allocation failure.
        let raw = unsafe { sys::ares_get_servers_csv(channel) };
        if raw.is_null() {
            return Err(AresError::AllocationFailed);
        }
        // SAFETY: the pointer is non-null and NUL-terminated until it is freed below.
        let text = unsafe { std::ffi::CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: a successful ares_get_servers_csv transfers this allocation to us.
        unsafe { sys::ares_free_string(raw.cast()) };
        Ok(text)
    }

    /// Installs a callback for server health transitions, replacing any previous one.
    pub fn set_server_state_callback<F>(&mut self, callback: F)
    where
        F: Fn(ServerStateEvent) + 'static,
    {
        *self.host.server_state_cb.borrow_mut() = Some(Rc::new(callback));
    }

    /// Reports whether a completion callback panicked.
    pub fn is_poisoned(&self) -> bool {
        self.host.is_poisoned()
    }

    /// Returns the next c-ares deadline for the caller's proactor timer.
    ///
    /// Shared-ring callers arm their timeout operation from this deadline and
    /// pass the returned generation back in [`ResolverCqe::Timer`]. Re-read it
    /// after every submission and completion so the armed deadline follows
    /// c-ares' retry schedule.
    ///
    /// # Errors
    /// Returns the channel-liveness error after the resolver is destroyed.
    pub fn timer_deadline(&mut self) -> Result<Option<TimerDeadline>> {
        let channel = self.host.ready()?;
        Ok(self.timer.refresh(channel))
    }

    /// Replaces the readiness sink driven by the internal socket bridge.
    ///
    /// Shared-ring callers install a sink that translates c-ares interest
    /// changes into proactor registrations; the resolver then consumes the
    /// resulting completions through [`Self::on_cqe`]. Standalone polling is no
    /// longer used after a sink is installed.
    ///
    /// # Errors
    /// Returns the channel-liveness error after the resolver is destroyed.
    pub fn install_readiness_sink(&mut self, sink: Rc<dyn ReadinessSink>) -> Result<()> {
        self.host.ready()?;
        self.sockets.set_readiness_sink(sink);
        Ok(())
    }

    /// Delivers one proactor completion to the channel.
    ///
    /// # Errors
    /// Returns [`AresError::ReentrantDriveForbidden`] when called from a callback,
    /// [`AresError::CallbackPanicked`] for a poisoned resolver, or the channel-liveness
    /// error.
    pub fn on_cqe(&mut self, cqe: ResolverCqe) -> Result<()> {
        if self.host.driving.get() {
            return Err(AresError::ReentrantDriveForbidden);
        }
        self.host.ready()?;
        match cqe {
            ResolverCqe::Socket {
                fd,
                readable,
                writable,
            } => self.sockets.on_ready(fd, readable, writable),
            ResolverCqe::Timer { generation } => {
                let _expired = self.timer.on_timer(generation);
            }
        }
        self.advance()?;
        Ok(())
    }

    /// Processes buffered events without blocking.
    ///
    /// # Errors
    /// Returns [`AresError::ReentrantDriveForbidden`] when called from a callback,
    /// [`AresError::CallbackPanicked`] for a poisoned resolver, or the channel-liveness
    /// error.
    pub fn poll_completions(&mut self) -> Result<PollOutcome> {
        if self.host.driving.get() {
            return Err(AresError::ReentrantDriveForbidden);
        }
        let advanced = self.advance()?;
        Ok(PollOutcome {
            advanced,
            pending: self.active_queries(),
        })
    }

    /// Drives the channel with `poll(2)` until no query is pending or `timeout` ends.
    ///
    /// # Errors
    /// Returns [`AresError::ReentrantDriveForbidden`] when called from a callback,
    /// [`AresError::CallbackPanicked`] for a poisoned resolver, a `poll(2)` failure
    /// other than interruption, or the channel-liveness error.
    pub fn wait_completions(&mut self, timeout: Duration) -> Result<PollOutcome> {
        if self.host.driving.get() {
            return Err(AresError::ReentrantDriveForbidden);
        }
        self.host.ready()?;
        let deadline = Instant::now().checked_add(timeout);
        let mut advanced = false;
        while self.active_queries() > 0 {
            let now = Instant::now();
            let remaining = match deadline {
                Some(limit) if now >= limit => break,
                Some(limit) => limit.saturating_duration_since(now),
                None => Duration::MAX,
            };
            let timer_wait = self
                .timer
                .deadline()
                .map_or(Duration::from_secs(1), |timer| {
                    timer.at.saturating_duration_since(now)
                });
            let wait = remaining
                .min(timer_wait)
                .min(Duration::from_millis(MAX_POLL_MILLIS));
            let millis = i32::try_from(wait.as_millis()).unwrap_or(MAX_POLL_MILLIS as i32);
            let mut pollfds: Vec<libc::pollfd> = self
                .interest
                .interests
                .borrow()
                .iter()
                .map(|(fd, interest)| libc::pollfd {
                    fd: *fd,
                    events: (libc::POLLIN * i16::from(interest.readable))
                        | (libc::POLLOUT * i16::from(interest.writable)),
                    revents: 0,
                })
                .collect();
            // SAFETY: `pollfds` holds `pollfds.len()` initialized entries, or is empty
            // with a null pointer (the documented sleep-only form). `millis` is
            // non-negative.
            let ready = unsafe {
                if pollfds.is_empty() {
                    libc::poll(ptr::null_mut(), 0, millis)
                } else {
                    libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, millis)
                }
            };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(AresError::invalid_input(format!("poll failed: {error}")));
            }
            for pollfd in &pollfds {
                if pollfd.revents == 0 {
                    continue;
                }
                let readable = pollfd.revents
                    & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                    != 0;
                let writable =
                    pollfd.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0;
                self.sockets.on_ready(pollfd.fd, readable, writable);
            }
            if let Some(timer) = self.timer.deadline()
                && timer.at <= Instant::now()
            {
                let _expired = self.timer.on_timer(timer.generation);
            }
            advanced |= self.advance()?;
        }
        Ok(PollOutcome {
            advanced,
            pending: self.active_queries(),
        })
    }

    /// Returns the number of queries that have not yet been retired.
    pub fn active_queries(&self) -> usize {
        self.host.table.borrow().active_count()
    }

    /// Resolves one name and returns an owned response message.
    ///
    /// # Errors
    /// Returns [`AresError::ReentrantDriveForbidden`] when a callback is driving the
    /// channel, [`AresStatus::Timeout`] when the deadline expires, or the query's own
    /// failure status.
    pub fn resolve(
        &mut self,
        name: &str,
        record_type: DnsRecordType,
        timeout: Duration,
    ) -> Result<DnsRecord> {
        if self.host.driving.get() {
            return Err(AresError::ReentrantDriveForbidden);
        }
        let sink: Rc<RefCell<Option<Result<DnsRecord>>>> = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&sink);
        self.submit_query(name, record_type, move |_ctx, outcome| {
            *captured.borrow_mut() = Some(match outcome.record {
                Some(record) => record.to_owned_record(),
                None => Err(AresError::from_status(outcome.status)),
            });
        })?;
        let deadline = Instant::now().checked_add(timeout);
        loop {
            if let Some(value) = sink.borrow_mut().take() {
                return value;
            }
            let now = Instant::now();
            let remaining = match deadline {
                Some(limit) if now >= limit => {
                    return Err(AresError::from_status(AresStatus::Timeout));
                }
                Some(limit) => limit.saturating_duration_since(now),
                None => Duration::MAX,
            };
            let chunk = remaining.min(Duration::from_millis(MAX_POLL_MILLIS));
            let outcome = self.wait_completions(chunk)?;
            if let Some(value) = sink.borrow_mut().take() {
                return value;
            }
            if outcome.pending == 0 {
                // The callback is the only writer of `sink`, so an empty sink with no
                // pending entries means the query was retired without completing.
                return Err(AresError::from_status(AresStatus::Timeout));
            }
        }
    }

    /// Hands buffered socket events and one expired timer deadline to c-ares.
    ///
    /// Callbacks reach the resolver only through `Weak<ResolverHost>` or
    /// `ChannelCtx`; no `RefCell` borrow is held across the FFI calls, so a callback
    /// may submit follow-up queries while an outer slice of the table is processed.
    fn advance(&mut self) -> Result<bool> {
        let channel = self.host.ready()?;
        let mut events: Vec<sys::ares_fd_events_t> = Vec::new();
        self.sockets.drain_ready(&mut events);
        let mut advanced = false;
        {
            let _driving = DrivingGuard::enter(&self.host);
            if !events.is_empty() {
                self.sockets.process_fds(
                    channel,
                    events.as_ptr(),
                    events.len(),
                    sys::ARES_PROCESS_FLAG_SKIP_NON_FD.0,
                );
                advanced = true;
            }
            if self.timer.take_expired() {
                self.sockets
                    .process_fds(channel, ptr::null(), 0, sys::ARES_PROCESS_FLAG_NONE.0);
                advanced = true;
            }
        }
        if self.is_poisoned() || self.sockets.readiness_sink_failed() {
            return Err(AresError::CallbackPanicked);
        }
        let _deadline = self.timer.refresh(channel);
        self.host.table.borrow_mut().sweep();
        Ok(advanced)
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        let channel = self.host.channel.replace(ptr::null_mut());
        if !channel.is_null() {
            // SAFETY: the channel is live, and the host, callback slots and socket
            // state stay valid while ares_destroy delivers ARES_EDESTRUCTION to every
            // pending query. New submissions are refused because the stored channel
            // pointer is already null.
            unsafe { sys::ares_destroy(channel) };
        }
        self.sockets.shutdown();
        self.timer.disarm();
    }
}

/// Restricted channel handle exposed to completion callbacks.
///
/// The handle permits follow-up submissions and per-query cancellation. It cannot
/// drive the event loop, reinitialize, or destroy the channel.
pub struct ChannelCtx<'cb> {
    pub(crate) host: &'cb ResolverHost,
}

impl ChannelCtx<'_> {
    /// Submits a follow-up DNS query from inside a completion callback.
    ///
    /// # Errors
    /// Returns the same errors as [`Resolver::submit_query`].
    pub fn submit_query<F>(
        &self,
        name: &str,
        record_type: DnsRecordType,
        callback: F,
    ) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        submit_query_on(self.host, name, record_type, callback)
    }

    /// Sends a pre-built message from inside a completion callback.
    ///
    /// # Errors
    /// Returns the same errors as [`Resolver::submit_record`].
    pub fn submit_record<F>(&self, record: &DnsRecord, callback: F) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        let owned = record.try_clone()?;
        let raw = owned.as_ref().as_ptr();
        dispatch(
            self.host,
            query_slot(self.host, callback),
            Some(owned),
            Submission::Record { raw },
            reclaim::<QueryFn>,
        )
    }

    /// Cancels one query without disturbing the rest of the channel.
    ///
    /// # Errors
    /// Returns the same errors as [`Resolver::cancel_query`].
    pub fn cancel(&self, handle: QueryHandle) -> Result<()> {
        cancel_query_on(self.host, handle)
    }

    /// Reports whether a completion callback panicked.
    pub fn is_poisoned(&self) -> bool {
        self.host.is_poisoned()
    }
}

fn cancel_query_on(host: &ResolverHost, handle: QueryHandle) -> Result<()> {
    if host.is_poisoned() {
        return Err(AresError::CallbackPanicked);
    }
    if handle.resolver_id != host.resolver_id {
        return Err(AresError::invalid_input(
            "query handle belongs to another resolver",
        ));
    }
    if host.table.borrow_mut().take_slot(handle) {
        Ok(())
    } else {
        Err(AresError::invalid_input("query handle is stale"))
    }
}

/// Copies a validated socket-address slice into an aligned C structure.
pub(crate) fn aligned_sockaddr(bytes: &[u8]) -> libc::sockaddr_storage {
    let mut storage = core::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let destination = storage.as_mut_ptr().cast::<u8>();
    // SAFETY: `getnameinfo` rejects slices longer than the storage, so the copy stays
    // inside the allocation.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
    // SAFETY: `storage` was zeroed and the copy only initialized bytes inside it.
    unsafe { storage.assume_init() }
}

/// Prepares one bridge submission as an io_uring SQE.
///
/// # Safety
/// `sqe` must be exclusive initialized SQE storage. Descriptor and target
/// identifiers remain owned by the socket bridge until their final CQEs.
pub(crate) unsafe fn prepare_bridge_sqe(
    sqe: *mut io_uring_sqe,
    submission: BridgeSubmission<OpId>,
) {
    match submission {
        // SAFETY: The caller guarantees exclusive initialized SQE storage.
        BridgeSubmission::PollAdd { fd, interest } => unsafe {
            liburing::ops::net::prep_poll_add(sqe, fd, interest.poll_mask())
        },
        // SAFETY: The caller guarantees exclusive initialized SQE storage.
        BridgeSubmission::PollRemove { target, .. } => unsafe {
            liburing::ops::net::prep_poll_remove(sqe, target)
        },
        // SAFETY: The caller guarantees exclusive initialized SQE storage.
        BridgeSubmission::Cancel { target, .. } => unsafe {
            liburing::ops::net::prep_cancel(sqe, target, 0)
        },
        // SAFETY: The caller guarantees exclusive initialized SQE storage.
        BridgeSubmission::Close { fd } => unsafe { liburing::ops::net::prep_close(sqe, fd) },
        BridgeSubmission::Connect { .. } => {}
    }
}
