//! Reentrant, single-threaded callback ownership and C unwind boundaries.

use std::{
    any::Any,
    cell::{Cell, RefCell},
    collections::VecDeque,
    ffi::{CStr, c_char, c_int, c_void},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

use cares_sys as sys;

use crate::{
    error::{AresError, AresStatus, Result},
    record::DnsRecordRef,
    types::{HostEntry, NameInfo, ServerStateFlags},
};

/// A panic caught at the C callback boundary.
pub type PanicPayload = Box<dyn Any + Send + 'static>;

/// Channel-wide panic quarantine and callback nesting information.
///
/// Completion belongs to an individual [`CallbackSlot`]. The state completion
/// flag indicates that some callback completed; it must not reclaim other slots.
/// Once poisoned, pending slots complete without user delivery and queued
/// notifications are discarded. Disabled closures are dropped inside an unwind
/// boundary so their destructors cannot unwind through C.
#[derive(Default)]
pub struct CallbackState {
    poisoned: Cell<bool>,
    panic: RefCell<Option<PanicPayload>>,
    depth: Cell<usize>,
    completed: Cell<bool>,
}

impl CallbackState {
    /// Creates an unpoisoned state with no active callbacks.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether a user callback has panicked.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.get()
    }

    /// Returns whether a user callback has panicked.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn poisoned(&self) -> bool {
        self.is_poisoned()
    }

    /// Quarantines the channel and retains the first panic payload.
    ///
    /// Later payloads are forgotten because their destructors can panic while
    /// the first panic is being handled. Poisoning remains sticky after retrieval.
    ///
    /// # Panics
    /// This function does not invoke payload destructors or user code.
    pub fn poison(&self, payload: PanicPayload) {
        self.poisoned.set(true);
        let mut stored = self.panic.borrow_mut();
        if stored.is_none() {
            *stored = Some(payload);
        } else {
            std::mem::forget(payload);
        }
    }

    /// Removes the retained panic for propagation outside the C stack.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn take_panic(&self) -> Option<PanicPayload> {
        self.panic.borrow_mut().take()
    }

    /// Records entry into a user callback.
    ///
    /// # Panics
    /// This function does not panic; depth saturates at `usize::MAX`.
    pub fn enter(&self) {
        self.depth.set(self.depth.get().saturating_add(1));
    }

    /// Records return from a user callback.
    ///
    /// # Panics
    /// This function does not panic; unbalanced leaves remain at zero.
    pub fn leave(&self) {
        self.depth.set(self.depth.get().saturating_sub(1));
    }

    /// Returns the current user callback nesting depth.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn depth(&self) -> usize {
        self.depth.get()
    }

    /// Reports whether recursive resolver driving must be rejected.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn in_callback(&self) -> bool {
        self.depth() != 0
    }

    /// Records that a callback completed; use slot completion for reclamation.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn mark_completed(&self) {
        self.completed.set(true);
    }

    /// Reports whether any callback using this state has completed.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn is_completed(&self) -> bool {
        self.completed.get()
    }
}

impl Drop for CallbackState {
    fn drop(&mut self) {
        // A panic payload can have a panicking destructor. State may lose its
        // final owner inside an extern callback, so that destructor is isolated.
        if let Some(payload) = self.panic.get_mut().take()
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(payload)))
        {
            std::mem::forget(payload);
        }
    }
}

/// A pre-registered completion whose C argument owns one strong `Rc` reference.
///
/// The query table retains another strong reference for logical cancellation.
/// Taking the closure cancels user delivery without releasing the C reference.
///
/// A callback-scoped record cannot be stored as a longer-lived borrowed value:
///
/// ```compile_fail
/// use std::{cell::RefCell, rc::Rc};
/// use cares::{error::Result, record::DnsRecordRef};
/// let escaped = Rc::new(RefCell::new(None::<DnsRecordRef<'static>>));
/// let callback: Box<dyn for<'cb> FnOnce(Result<DnsRecordRef<'cb>>, usize)> =
///     Box::new(move |record, _| *escaped.borrow_mut() = record.ok());
/// ```
pub struct CallbackSlot<F> {
    callback: RefCell<Option<F>>,
    state: Rc<CallbackState>,
    completed: Cell<bool>,
}

impl<F> CallbackSlot<F> {
    /// Allocates a callback slot before submitting a query to c-ares.
    ///
    /// # Panics
    /// This function has no explicit panic path; allocation follows Rust's
    /// allocator failure policy.
    pub fn new(state: Rc<CallbackState>, callback: F) -> Rc<Self> {
        Rc::new(Self {
            callback: RefCell::new(Some(callback)),
            state,
            completed: Cell::new(false),
        })
    }

    /// Removes the callback while releasing the internal borrow before return.
    ///
    /// # Panics
    /// This function does not invoke the closure or panic.
    pub fn take(&self) -> Option<F> {
        self.callback.borrow_mut().take()
    }

    /// Borrows the channel's panic and nesting state.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn state(&self) -> &Rc<CallbackState> {
        &self.state
    }

    /// Reports whether c-ares has delivered this slot's final callback.
    ///
    /// Cancellation alone does not complete the slot.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn is_completed(&self) -> bool {
        self.completed.get()
    }

    /// Marks this slot complete after C delivery, including cancelled delivery.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn mark_completed(&self) {
        self.completed.set(true);
        self.state.mark_completed();
    }
}

unsafe fn invoke_once<F, T>(arg: *mut c_void, timeouts: usize, prepare: impl FnOnce() -> Result<T>)
where
    F: FnOnce(Result<T>, usize) + 'static,
{
    if arg.is_null() {
        return;
    }
    // SAFETY: The trampoline contract requires exactly one strong reference
    // produced by Rc::into_raw for this exact CallbackSlot<F> instantiation.
    let slot = unsafe { Rc::from_raw(arg.cast::<CallbackSlot<F>>()) };
    let state = Rc::clone(slot.state());
    if let Some(callback) = slot.take() {
        state.enter();
        let suppressed = state.is_poisoned();
        // Conversion, invocation, and destruction of the owned FnOnce closure
        // all occur within the boundary. No slot borrow reaches user code.
        if let Err(payload) = catch_unwind(AssertUnwindSafe(move || {
            if suppressed {
                drop(callback);
            } else {
                callback(prepare(), timeouts);
            }
        })) {
            state.poison(payload);
        }
        state.leave();
    }
    slot.mark_completed();
}

/// Delivers a DNS message borrowed only for this callback invocation.
///
/// # Safety
/// `arg` must be null or an unconsumed `Rc::into_raw` strong reference to
/// `CallbackSlot<F>`. It must be delivered exactly once on the owning thread.
/// A successful non-null `record` must remain a valid immutable c-ares message
/// throughout this call. No caller may destroy its channel reentrantly.
///
/// # Panics
/// User panics are caught and retained in the slot's `CallbackState`.
pub unsafe extern "C" fn dns_trampoline<F>(
    arg: *mut c_void,
    status: sys::ares_status_t,
    timeouts: usize,
    record: *const sys::ares_dns_record_t,
) where
    F: for<'cb> FnOnce(Result<DnsRecordRef<'cb>>, usize) + 'static,
{
    // SAFETY: This function forwards its documented slot and record guarantees;
    // the higher-ranked closure cannot retain the temporary borrowed message.
    unsafe {
        invoke_once::<F, _>(arg, timeouts, || {
            let status = AresStatus::from(status);
            if status != AresStatus::Success {
                return Err(AresError::from_status(status));
            }
            if record.is_null() {
                return Err(AresError::invalid_record(
                    "successful DNS callback has no record",
                ));
            }
            DnsRecordRef::from_raw(record)
        });
    }
}

/// DNS-record trampoline with the explicit record callback name.
pub use dns_trampoline as dns_rec_trampoline;

/// Copies the temporary C host result and delivers an owned Rust result.
///
/// # Safety
/// `arg` has the same ownership and single-threaded delivery contract as
/// [`dns_trampoline`]. On success, `host` and its NUL-terminated pointer arrays,
/// strings, and address buffers must remain readable throughout this call.
///
/// # Panics
/// Conversion and user panics are caught and retained in `CallbackState`.
pub unsafe extern "C" fn host_trampoline<F>(
    arg: *mut c_void,
    status: c_int,
    timeouts: c_int,
    host: *mut libc::hostent,
) where
    F: FnOnce(Result<HostEntry>, usize) + 'static,
{
    // SAFETY: The caller guarantees the slot ownership and temporary host
    // allocation invariants; copying finishes before this callback returns.
    unsafe {
        invoke_once::<F, _>(arg, nonnegative_timeouts(timeouts), || {
            let status = AresStatus::from_raw(status);
            if status != AresStatus::Success {
                return Err(AresError::from_status(status));
            }
            copy_host(host)
        });
    }
}

/// Copies reverse-lookup strings and delivers an owned Rust result.
///
/// # Safety
/// `arg` has the same ownership and single-threaded delivery contract as
/// [`dns_trampoline`]. Non-null strings must be valid NUL-terminated C strings
/// that remain readable throughout this callback.
///
/// # Panics
/// Conversion and user panics are caught and retained in `CallbackState`.
pub unsafe extern "C" fn nameinfo_trampoline<F>(
    arg: *mut c_void,
    status: c_int,
    timeouts: c_int,
    node: *mut c_char,
    service: *mut c_char,
) where
    F: FnOnce(Result<NameInfo>, usize) + 'static,
{
    // SAFETY: The caller guarantees the slot and C string lifetimes. The
    // resulting strings own their bytes and do not escape borrowed C storage.
    unsafe {
        invoke_once::<F, _>(arg, nonnegative_timeouts(timeouts), || {
            let status = AresStatus::from_raw(status);
            if status != AresStatus::Success {
                return Err(AresError::from_status(status));
            }
            Ok(NameInfo {
                node: copy_optional_string(node),
                service: copy_optional_string(service),
            })
        });
    }
}

fn nonnegative_timeouts(timeouts: c_int) -> usize {
    usize::try_from(timeouts).unwrap_or_default()
}

unsafe fn copy_optional_string(value: *const c_char) -> Option<String> {
    if value.is_null() {
        None
    } else {
        // SAFETY: The caller guarantees a readable NUL-terminated string until
        // copying finishes; to_string_lossy returns an independent owned value.
        Some(
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

unsafe fn copy_host(host: *const libc::hostent) -> Result<HostEntry> {
    if host.is_null() {
        return Err(AresError::invalid_record(
            "successful host callback has no host entry",
        ));
    }
    // SAFETY: The caller guarantees a live, fully initialized hostent for the
    // duration of the callback; it is borrowed immutably while copying.
    let host = unsafe { &*host };
    // SAFETY: h_name is null or a readable NUL-terminated string supplied by
    // c-ares; its owned copy is created before callback return.
    let name = unsafe { copy_optional_string(host.h_name) }.unwrap_or_default();
    let mut aliases = Vec::new();
    if !host.h_aliases.is_null() {
        let mut current = host.h_aliases;
        loop {
            // SAFETY: c-ares supplies a readable null-terminated pointer array.
            let value = unsafe { *current };
            if value.is_null() {
                break;
            }
            // SAFETY: Non-null alias pointers refer to NUL-terminated strings
            // valid for the same callback duration as the hostent.
            if let Some(value) = unsafe { copy_optional_string(value) } {
                aliases.push(value);
            }
            // SAFETY: The array contains another readable element or its null
            // terminator; the caller guarantees the complete hostent arrays.
            current = unsafe { current.add(1) };
        }
    }
    let length = match (host.h_addrtype, host.h_length) {
        (libc::AF_INET, 4) => 4,
        (libc::AF_INET6, 16) => 16,
        _ => {
            return Err(AresError::invalid_record(
                "unsupported host address family or length",
            ));
        }
    };
    let mut addresses = Vec::new();
    if !host.h_addr_list.is_null() {
        let mut current = host.h_addr_list;
        loop {
            // SAFETY: c-ares supplies a readable null-terminated address array.
            let value = unsafe { *current };
            if value.is_null() {
                break;
            }
            // SAFETY: Each address points to h_length initialized address bytes;
            // the validated family requires exactly 4 or 16 bytes respectively.
            let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), length) };
            let address = if length == 4 {
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            } else {
                let mut octets = [0; 16];
                octets.copy_from_slice(bytes);
                IpAddr::V6(Ipv6Addr::from(octets))
            };
            addresses.push(address);
            // SAFETY: The pointer array includes a subsequent readable entry
            // or its terminating null pointer throughout the callback.
            current = unsafe { current.add(1) };
        }
    }
    Ok(HostEntry {
        name,
        aliases,
        addresses,
    })
}

/// Owned server status notification, including unknown future flag bits.
#[derive(Clone, Debug)]
pub struct ServerStateEvent {
    /// Server endpoint text supplied by c-ares.
    pub server: Option<String>,
    /// Whether the server responded successfully.
    pub success: bool,
    /// Transport and status flags.
    pub flags: ServerStateFlags,
}

/// Socket interest notification copied from c-ares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketStateEvent {
    /// Socket descriptor whose interest changed.
    pub socket: sys::ares_socket_t,
    /// Whether c-ares wants read readiness.
    pub readable: bool,
    /// Whether c-ares wants write readiness.
    pub writable: bool,
}

/// Persistent notification storage with queued recursive delivery.
///
/// Its raw C pointer is borrowed, never consumed by a trampoline. Keep an `Rc`
/// alive until the corresponding c-ares callback has been unregistered.
pub struct NotificationSlot<F, E> {
    callback: RefCell<Option<F>>,
    pending: RefCell<VecDeque<E>>,
    dispatching: Cell<bool>,
    state: Rc<CallbackState>,
}

impl<F, E> NotificationSlot<F, E>
where
    F: FnMut(E),
{
    /// Allocates a persistent callback; recursive events are delivered in order.
    ///
    /// # Panics
    /// This function has no explicit panic path; allocation follows Rust's
    /// allocator failure policy.
    pub fn new(state: Rc<CallbackState>, callback: F) -> Rc<Self> {
        Rc::new(Self {
            callback: RefCell::new(Some(callback)),
            pending: RefCell::new(VecDeque::new()),
            dispatching: Cell::new(false),
            state,
        })
    }

    fn deliver(&self, event: E) {
        self.pending.borrow_mut().push_back(event);
        if self.dispatching.replace(true) {
            return;
        }
        let callback = self.callback.borrow_mut().take();
        if let Some(mut callback) = callback {
            loop {
                let event = self.pending.borrow_mut().pop_front();
                let Some(event) = event else { break };
                self.state.enter();
                let result = catch_unwind(AssertUnwindSafe(|| callback(event)));
                self.state.leave();
                if let Err(payload) = result {
                    self.state.poison(payload);
                }
                if self.state.is_poisoned() {
                    // Drop the disabled callback in a separate boundary so a
                    // destructor panic cannot unwind through the C frame.
                    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(callback))) {
                        self.state.poison(payload);
                    }
                    self.pending.borrow_mut().clear();
                    self.dispatching.set(false);
                    return;
                }
            }
            *self.callback.borrow_mut() = Some(callback);
        }
        self.dispatching.set(false);
    }
}

unsafe fn notify<F, E>(arg: *mut c_void, prepare: impl FnOnce() -> E)
where
    F: FnMut(E),
{
    if arg.is_null() {
        return;
    }
    // SAFETY: Notification trampoline callers keep this exact slot type alive
    // until unregistering and invoke it only on its owning thread.
    let slot = unsafe { &*arg.cast::<NotificationSlot<F, E>>() };
    if slot.state.is_poisoned() {
        return;
    }
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| slot.deliver(prepare()))) {
        slot.dispatching.set(false);
        slot.state.poison(payload);
    }
}

/// Delivers a persistent server-status notification without holding slot borrows.
///
/// # Safety
/// `arg` must be null or point to a live `NotificationSlot<F, ServerStateEvent>`
/// on its owning thread. Its owner must survive callback delivery and unregister
/// before dropping the slot. Non-null `server` must be a readable C string.
///
/// # Panics
/// Conversion, callback, and callback-destructor panics poison the shared state.
pub unsafe extern "C" fn server_state_trampoline<F>(
    server: *const c_char,
    success: sys::ares_bool_t,
    flags: c_int,
    arg: *mut c_void,
) where
    F: FnMut(ServerStateEvent),
{
    // SAFETY: Slot and string validity are guaranteed by this function's caller;
    // all string conversion and user execution remain inside notify's boundary.
    unsafe {
        notify::<F, _>(arg, || ServerStateEvent {
            server: copy_optional_string(server),
            success: success != sys::ARES_FALSE,
            flags: ServerStateFlags::from_bits_retain(flags),
        });
    }
}

/// Delivers persistent socket interest changes and queues recursive events.
///
/// # Safety
/// `arg` must be null or point to a live `NotificationSlot<F, SocketStateEvent>`
/// on its owning thread. The owner must unregister the C callback before dropping
/// its last strong reference, and must not destroy it from inside user code.
///
/// # Panics
/// User callback and callback-destructor panics poison the shared state.
pub unsafe extern "C" fn sock_state_trampoline<F>(
    arg: *mut c_void,
    socket: sys::ares_socket_t,
    readable: c_int,
    writable: c_int,
) where
    F: FnMut(SocketStateEvent),
{
    // SAFETY: The caller guarantees that the persistent slot remains live on
    // its owning thread; the event contains only copied scalar values.
    unsafe {
        notify::<F, _>(arg, || SocketStateEvent {
            socket,
            readable: readable != 0,
            writable: writable != 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Handler = Box<dyn for<'cb> FnOnce(Result<DnsRecordRef<'cb>>, usize)>;

    fn finish(state: &Rc<CallbackState>, callback: Handler) -> bool {
        let slot = CallbackSlot::new(Rc::clone(state), callback);
        // SAFETY: one exact matching Rc is transferred into the trampoline;
        // the error status requires no DNS record and delivery happens once.
        unsafe {
            dns_trampoline::<Handler>(
                Rc::into_raw(Rc::clone(&slot)).cast_mut().cast(),
                sys::ARES_ENOTFOUND,
                0,
                std::ptr::null(),
            );
        }
        slot.is_completed()
    }

    #[test]
    fn nested_poison_discards_notifications_queued_before_the_panic() {
        type Callback = Box<dyn FnMut(usize)>;
        type Slot = NotificationSlot<Callback, usize>;
        let state = Rc::new(CallbackState::new());
        let weak: Rc<RefCell<std::rc::Weak<Slot>>> = Rc::default();
        let weak_capture = Rc::clone(&weak);
        let nested_state = Rc::clone(&state);
        let calls = Rc::new(RefCell::new(Vec::new()));
        let calls_capture = Rc::clone(&calls);
        let callback: Callback = Box::new(move |event| {
            calls_capture.borrow_mut().push(event);
            if event == 1 {
                let slot = match weak_capture.borrow().upgrade() {
                    Some(slot) => slot,
                    None => panic!("notification owner missing"),
                };
                slot.deliver(2);
                assert!(finish(
                    &nested_state,
                    Box::new(|_, _| panic!("nested panic"))
                ));
            }
        });
        let slot = NotificationSlot::new(Rc::clone(&state), callback);
        *weak.borrow_mut() = Rc::downgrade(&slot);
        slot.deliver(1);
        assert_eq!(*calls.borrow(), [1]);
        assert!(slot.pending.borrow().is_empty());
        assert!(slot.callback.borrow().is_none());
        assert!(state.is_poisoned());
        assert_eq!(state.depth(), 0);
    }

    #[test]
    fn poisoned_completions_suppress_user_code_and_catch_destructor_panics() {
        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("disabled closure destructor");
            }
        }
        let state = Rc::new(CallbackState::new());
        state.poison(Box::new("original panic"));
        let calls = Rc::new(Cell::new(0));
        let capture = Rc::clone(&calls);
        let dropper = PanicOnDrop;
        assert!(finish(
            &state,
            Box::new(move |_, _| {
                let _keep_alive = &dropper;
                capture.set(capture.get() + 1);
            })
        ));
        assert_eq!(calls.get(), 0);
        assert_eq!(state.depth(), 0);
        let payload = state.take_panic();
        assert_eq!(
            payload.as_ref().and_then(|p| p.downcast_ref::<&str>()),
            Some(&"original panic")
        );
    }
}
