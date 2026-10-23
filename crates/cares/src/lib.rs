//! Single-threaded, threadless, completion-driven `c-ares` bindings.
//!
//! [`Resolver`] owns one `c-ares` channel compiled with `CARES_THREADS=OFF` and is
//! `!Send + !Sync`. Shared-ring callers forward socket and timer completions from a
//! proactor through [`Resolver::on_cqe`]; standalone callers drive the channel with
//! [`Resolver::wait_completions`], [`Resolver::poll_completions`], or
//! [`Resolver::resolve`].
//!
//! Completion callbacks run synchronously on the driving thread, either from inside
//! an `ares_process_fds` call or from the submission call itself. A callback receives
//! a [`ChannelCtx`] that allows follow-up submissions and per-query cancellation on
//! the same channel, but cannot recursively drive the resolver.

mod library;

pub mod callbacks;
pub mod error;
pub mod options;
pub mod proactor;
pub mod record;
pub mod record_rr;
pub mod resolver;
pub mod socket_bridge;
pub mod timer;
pub mod types;

pub use cares_macros::*;
pub use error::{AresError, AresStatus, Result};
pub use library::LibraryGuard;
pub use options::{ResolverBuilder, ResolverOptions};
pub use proactor::ProactorResolver;
pub use record::{DnsRecord, DnsRecordRef};
pub use record_rr::{
    ARecord, AaaaRecord, CaaRecord, CnameRecord, HttpsRecord, MxRecord, NaptrRecord, NsRecord,
    OptRecord, PtrRecord, SoaRecord, SrvRecord, SvcbRecord, TlsaRecord, TxtRecord, UriRecord,
};
pub use resolver::{
    ChannelCtx, HostOutcome, NameInfoOutcome, PollOutcome, QueryOutcome, Resolver, ResolverCqe,
    ServerStateEvent,
};
pub use types::{DnsClass, DnsRecordType, DnsSection, HostEntry, NameInfo};

/// Identifies one in-flight query within a [`Resolver`].
///
/// Handles are generational, so a retired handle never addresses a newer occupant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QueryHandle {
    pub(crate) index: u32,
    pub(crate) generation: u32,
    pub(crate) resolver_id: u64,
}

impl QueryHandle {
    /// Returns the callback-table slot index.
    pub fn index(&self) -> u32 {
        self.index
    }
    /// Returns the slot generation current when this handle was issued.
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

/// Private machinery shared by the resolver and its callback trampolines.
///
/// Owns callback slots and channel state shared across the FFI boundary.
mod support {
    use std::{
        cell::{Cell, RefCell},
        ffi::{CStr, CString},
        panic::{AssertUnwindSafe, catch_unwind},
        ptr,
        rc::{Rc, Weak},
    };

    use cares_sys as sys;
    use libc::{c_char, c_int, c_void};

    use crate::{
        callbacks::{
            CallbackSlot, CallbackState, dns_trampoline, host_trampoline, nameinfo_trampoline,
        },
        error::{AresError, AresStatus, Result},
        record::{DnsRecord, DnsRecordRef},
        resolver::{
            ChannelCtx, HostOutcome, NameInfoOutcome, QueryHandle, QueryOutcome, ServerStateEvent,
        },
        socket_bridge::SharedChannelState,
        types::{DnsClass, DnsRecordType, HostEntry, NameInfo, ServerStateFlags},
    };

    pub(crate) type QueryFn = Box<dyn for<'cb> FnOnce(Result<DnsRecordRef<'cb>>, usize) + 'static>;
    pub(crate) type HostFn = Box<dyn FnOnce(Result<HostEntry>, usize) + 'static>;
    pub(crate) type NameInfoFn = Box<dyn FnOnce(Result<NameInfo>, usize) + 'static>;
    pub(crate) type ServerStateCallback = Option<Rc<dyn Fn(ServerStateEvent)>>;

    /// Type-erased callback slot held by one table entry.
    pub(crate) enum SlotKind {
        Query(Rc<CallbackSlot<QueryFn>>),
        Host(Rc<CallbackSlot<HostFn>>),
        NameInfo(Rc<CallbackSlot<NameInfoFn>>),
    }

    impl SlotKind {
        fn is_completed(&self) -> bool {
            match self {
                Self::Query(slot) => slot.is_completed(),
                Self::Host(slot) => slot.is_completed(),
                Self::NameInfo(slot) => slot.is_completed(),
            }
        }
        /// Creates the strong reference handed to c-ares as its `arg` pointer.
        fn raw_arg(&self) -> *mut c_void {
            match self {
                Self::Query(slot) => Rc::into_raw(Rc::clone(slot)) as *mut c_void,
                Self::Host(slot) => Rc::into_raw(Rc::clone(slot)) as *mut c_void,
                Self::NameInfo(slot) => Rc::into_raw(Rc::clone(slot)) as *mut c_void,
            }
        }
        /// Drops the closure uninvoked; a later C callback only marks the slot complete.
        fn take(&self) {
            match self {
                Self::Query(slot) => drop(slot.take()),
                Self::Host(slot) => drop(slot.take()),
                Self::NameInfo(slot) => drop(slot.take()),
            }
        }
    }

    struct Entry {
        generation: u32,
        slot: SlotKind,
        /// Clone handed to `ares_send_dnsrec`, kept alive until the callback fires.
        _record: Option<DnsRecord>,
    }

    /// Generational slot table with a free list.
    #[derive(Default)]
    pub(crate) struct CallbackTable {
        entries: Vec<Option<Entry>>,
        /// Retired index and the generation the next occupant must use.
        free: Vec<(u32, u32)>,
    }

    impl CallbackTable {
        fn insert(
            &mut self,
            slot: SlotKind,
            record: Option<DnsRecord>,
            resolver_id: u64,
        ) -> Result<QueryHandle> {
            if let Some((index, generation)) = self.free.pop() {
                self.entries[index as usize] = Some(Entry {
                    generation,
                    slot,
                    _record: record,
                });
                return Ok(QueryHandle {
                    index,
                    generation,
                    resolver_id,
                });
            }
            let index = u32::try_from(self.entries.len())
                .map_err(|_| AresError::invalid_input("too many in-flight queries"))?;
            self.entries.push(Some(Entry {
                generation: 1,
                slot,
                _record: record,
            }));
            Ok(QueryHandle {
                index,
                generation: 1,
                resolver_id,
            })
        }
        fn get(&self, handle: QueryHandle) -> Option<&Entry> {
            self.entries
                .get(handle.index as usize)
                .and_then(|entry| entry.as_ref())
                .filter(|entry| entry.generation == handle.generation)
        }
        fn retire(&mut self, index: u32) {
            let taken = self
                .entries
                .get_mut(index as usize)
                .and_then(|entry| entry.take());
            if let Some(entry) = taken {
                self.free.push((index, entry.generation.wrapping_add(1)));
            }
        }
        pub(crate) fn take_slot(&mut self, handle: QueryHandle) -> bool {
            match self.get(handle) {
                Some(entry) => {
                    entry.slot.take();
                    true
                }
                None => false,
            }
        }
        /// Retires every slot whose callback already ran.
        pub(crate) fn sweep(&mut self) {
            for index in 0..self.entries.len() {
                if self.entries[index]
                    .as_ref()
                    .is_some_and(|entry| entry.slot.is_completed())
                {
                    self.retire(index as u32);
                }
            }
        }
        pub(crate) fn active_count(&self) -> usize {
            self.entries
                .iter()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .is_some_and(|entry| !entry.slot.is_completed())
                })
                .count()
        }
    }

    /// Mutable state shared with callbacks and [`ChannelCtx`].
    pub(crate) struct ResolverHost {
        /// Raw channel pointer; null once the channel is destroyed.
        pub(crate) channel: Cell<*mut sys::ares_channel_t>,
        /// Channel-wide panic and nesting state owned by the trampolines.
        pub(crate) state: Rc<CallbackState>,
        pub(crate) resolver_id: u64,
        /// Socket table shared with the resolver, needed for deferred notifications.
        pub(crate) sockets: Rc<SharedChannelState>,
        pub(crate) table: RefCell<CallbackTable>,
        /// Set while an FFI call that may invoke user code is on the stack.
        pub(crate) driving: Cell<bool>,
        pub(crate) stopping: Cell<bool>,
        pub(crate) server_state_cb: RefCell<ServerStateCallback>,
        /// Self-reference for upgrades inside callbacks, without a strong cycle.
        pub(crate) self_weak: Weak<ResolverHost>,
    }

    impl ResolverHost {
        pub(crate) fn is_poisoned(&self) -> bool {
            self.state.is_poisoned() || self.sockets.readiness_sink_failed()
        }
        /// Returns the live channel, rejecting a poisoned or destroyed resolver.
        pub(crate) fn ready(&self) -> Result<*mut sys::ares_channel_t> {
            if self.is_poisoned() {
                return Err(AresError::CallbackPanicked);
            }
            let channel = self.channel.get();
            if channel.is_null() {
                Err(AresError::from_status(AresStatus::NotInitialized))
            } else {
                Ok(channel)
            }
        }
    }

    /// Marks the resolver as driving user code; nesting restores the previous value so a
    /// re-entrant submission inside a callback cannot clear the outer FFI call's flag.
    pub(crate) struct DrivingGuard<'a> {
        host: &'a ResolverHost,
        previous: bool,
    }

    impl<'a> DrivingGuard<'a> {
        pub(crate) fn enter(host: &'a ResolverHost) -> Self {
            Self {
                host,
                previous: host.driving.replace(true),
            }
        }
    }

    impl Drop for DrivingGuard<'_> {
        fn drop(&mut self) {
            self.host.driving.set(self.previous);
        }
    }

    /// Splits a callback result into the status and optional value reported to users.
    fn outcome_parts<T>(result: Result<T>) -> (AresStatus, Option<T>) {
        match result {
            Ok(value) => (AresStatus::Success, Some(value)),
            Err(error) => (error.status().unwrap_or(AresStatus::Unknown(-1)), None),
        }
    }

    pub(crate) fn query_slot<F>(host: &ResolverHost, callback: F) -> SlotKind
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        SlotKind::Query(CallbackSlot::new(
            Rc::clone(&host.state),
            wrap_query_callback(host.self_weak.clone(), callback),
        ))
    }

    pub(crate) fn host_slot<F>(host: &ResolverHost, callback: F) -> SlotKind
    where
        F: FnOnce(&ChannelCtx<'_>, HostOutcome) + 'static,
    {
        SlotKind::Host(CallbackSlot::new(
            Rc::clone(&host.state),
            wrap_host_callback(host.self_weak.clone(), callback),
        ))
    }

    pub(crate) fn nameinfo_slot<F>(host: &ResolverHost, callback: F) -> SlotKind
    where
        F: FnOnce(&ChannelCtx<'_>, NameInfoOutcome) + 'static,
    {
        SlotKind::NameInfo(CallbackSlot::new(
            Rc::clone(&host.state),
            wrap_nameinfo_callback(host.self_weak.clone(), callback),
        ))
    }

    /// Generates an owned wrapper around a `FnOnce(&ChannelCtx, Outcome)` callback.
    macro_rules! wrap_value_callback {
        ($name:ident, $value:ty, $outcome:ident, $field:ident, $fn_ty:ident) => {
            pub(crate) fn $name<F>(weak: Weak<ResolverHost>, callback: F) -> $fn_ty
            where
                F: FnOnce(&ChannelCtx<'_>, $outcome) + 'static,
            {
                Box::new(move |result: Result<$value>, timeouts: usize| {
                    let Some(host) = weak.upgrade() else { return };
                    let (status, value) = outcome_parts(result);
                    callback(
                        &ChannelCtx {
                            host: host.as_ref(),
                        },
                        $outcome {
                            status,
                            timeouts,
                            $field: value,
                        },
                    );
                })
            }
        };
    }

    wrap_value_callback!(wrap_host_callback, HostEntry, HostOutcome, host, HostFn);
    wrap_value_callback!(
        wrap_nameinfo_callback,
        NameInfo,
        NameInfoOutcome,
        nameinfo,
        NameInfoFn
    );

    fn wrap_query_callback<F>(weak: Weak<ResolverHost>, callback: F) -> QueryFn
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        Box::new(move |result: Result<DnsRecordRef<'_>>, timeouts: usize| {
            let Some(host) = weak.upgrade() else { return };
            let (status, record) = outcome_parts(result);
            let ctx = ChannelCtx {
                host: host.as_ref(),
            };
            callback(
                &ctx,
                QueryOutcome {
                    status,
                    timeouts,
                    record,
                },
            );
        })
    }

    /// The FFI entry point that starts one registered submission.
    pub(crate) enum Submission<'a> {
        Query {
            name: CString,
            record_type: DnsRecordType,
        },
        Record {
            raw: *const sys::ares_dns_record_t,
        },
        HostName {
            name: CString,
            family: c_int,
        },
        HostAddress {
            address: &'a [u8],
            family: c_int,
        },
        NameInfo {
            sockaddr: &'a [u8],
            flags: c_int,
        },
    }

    pub(crate) fn submit_query_on<F>(
        host: &ResolverHost,
        name: &str,
        record_type: DnsRecordType,
        callback: F,
    ) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        if name.is_empty() {
            return Err(AresError::invalid_input("DNS name must not be empty"));
        }
        let name = CString::new(name)?;
        dispatch(
            host,
            query_slot(host, callback),
            None,
            Submission::Query { name, record_type },
            reclaim::<QueryFn>,
        )
    }

    /// Registers `slot`, starts the submission, and reclaims the slot when c-ares reports
    /// a failure without delivering a callback.
    pub(crate) fn dispatch(
        host: &ResolverHost,
        slot: SlotKind,
        record: Option<DnsRecord>,
        submission: Submission<'_>,
        reclaim: unsafe fn(*mut c_void),
    ) -> Result<QueryHandle> {
        if host.stopping.get() {
            return Err(AresError::from_status(AresStatus::Cancelled));
        }
        let channel = host.ready()?;
        let arg = slot.raw_arg();
        let handle = match host
            .table
            .borrow_mut()
            .insert(slot, record, host.resolver_id)
        {
            Ok(handle) => handle,
            Err(error) => {
                // SAFETY: the raw reference was never handed to c-ares.
                unsafe { reclaim(arg) };
                return Err(error);
            }
        };
        let status = {
            let _driving = DrivingGuard::enter(host);
            host.sockets
                .with_process_scope(|| -> Result<sys::ares_status_t> {
                    match submission {
                        Submission::Query { name, record_type } => {
                            // SAFETY: the channel is live, `name` is NUL-terminated for the
                            // call, and `arg` is a strong reference created by `raw_arg`.
                            Ok(unsafe {
                                sys::ares_query_dnsrec(
                                    channel,
                                    name.as_ptr(),
                                    sys::ares_dns_class_t(DnsClass::IN.as_raw()),
                                    sys::ares_dns_rec_type_t(record_type.as_raw()),
                                    Some(dns_trampoline::<QueryFn>),
                                    arg,
                                    ptr::null_mut(),
                                )
                            })
                        }
                        Submission::Record { raw } => {
                            // SAFETY: the channel is live, `raw` points at the clone
                            // retained by the table entry, and `arg` is a strong reference.
                            Ok(unsafe {
                                sys::ares_send_dnsrec(
                                    channel,
                                    raw,
                                    Some(dns_trampoline::<QueryFn>),
                                    arg,
                                    ptr::null_mut(),
                                )
                            })
                        }
                        Submission::HostName { name, family } => {
                            // SAFETY: the channel is live, `name` is NUL-terminated for the
                            // call, and `arg` is a strong reference to the slot.
                            unsafe {
                                sys::ares_gethostbyname(
                                    channel,
                                    name.as_ptr(),
                                    family,
                                    Some(host_trampoline::<HostFn>),
                                    arg,
                                );
                            }
                            Ok(sys::ares_status_t::ARES_SUCCESS)
                        }
                        Submission::HostAddress { address, family } => {
                            let length = c_int::try_from(address.len())
                                .map_err(|_| AresError::invalid_input("address is too long"))?;
                            // SAFETY: the channel is live, `address` is readable for
                            // `length` bytes, and `arg` is a strong reference to the slot.
                            unsafe {
                                sys::ares_gethostbyaddr(
                                    channel,
                                    address.as_ptr().cast(),
                                    length,
                                    family,
                                    Some(host_trampoline::<HostFn>),
                                    arg,
                                );
                            }
                            Ok(sys::ares_status_t::ARES_SUCCESS)
                        }
                        Submission::NameInfo { sockaddr, flags } => {
                            let length = u32::try_from(sockaddr.len()).map_err(|_| {
                                AresError::invalid_input("socket address is too long")
                            })?;
                            let storage = crate::resolver::aligned_sockaddr(sockaddr);
                            // SAFETY: the channel is live, `storage` is aligned and readable
                            // for `length` bytes, and `arg` is a strong reference to the slot.
                            unsafe {
                                sys::ares_getnameinfo(
                                    channel,
                                    (&raw const storage).cast::<libc::sockaddr>(),
                                    length,
                                    flags,
                                    Some(nameinfo_trampoline::<NameInfoFn>),
                                    arg,
                                );
                            }
                            Ok(sys::ares_status_t::ARES_SUCCESS)
                        }
                    }
                })?
        };
        if host.is_poisoned() || host.sockets.readiness_sink_failed() {
            return Err(AresError::CallbackPanicked);
        }
        let completed = host
            .table
            .borrow()
            .get(handle)
            .is_some_and(|entry| entry.slot.is_completed());
        if !completed && !AresStatus::from(status).is_success() {
            // SAFETY: c-ares failed without delivering a callback, so the trampoline never
            // reconstructed the raw reference.
            unsafe { reclaim(arg) };
            host.table.borrow_mut().retire(handle.index);
            return Err(AresError::from_status(status));
        }
        Ok(handle)
    }

    /// # Safety
    /// `arg` must be a pointer produced by `Rc::into_raw` for a slot of type `F` whose
    /// ownership was never transferred to a c-ares callback.
    pub(crate) unsafe fn reclaim<F>(arg: *mut c_void) {
        // SAFETY: the caller guarantees the pointer came from Rc::into_raw for this slot
        // type and was not consumed by a trampoline.
        drop(unsafe { Rc::from_raw(arg.cast::<CallbackSlot<F>>()) });
    }

    /// Forwards one server health transition to the registered Rust closure.
    ///
    /// # Safety
    /// `data` must be non-null and point to the registered `ResolverHost` allocation,
    /// which must remain alive throughout this callback and every callback issued
    /// during channel destruction. If non-null, `server_string` must point to a
    /// readable NUL-terminated C string valid for the duration of this call. The
    /// callback must execute on the channel owner thread without an exclusive
    /// reference to the host.
    pub(crate) unsafe extern "C" fn server_state_trampoline(
        server_string: *const c_char,
        success: sys::ares_bool_t,
        flags: c_int,
        data: *mut c_void,
    ) {
        // SAFETY: `data` is the `Rc<ResolverHost>` allocation registered once with this
        // channel; the resolver keeps it alive until after the final ares_destroy call.
        let host = unsafe { &*data.cast::<ResolverHost>() };
        if host.is_poisoned() {
            return;
        }
        let server = if server_string.is_null() {
            None
        } else {
            // SAFETY: c-ares passes a NUL-terminated string valid for the call.
            Some(
                unsafe { CStr::from_ptr(server_string) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        let event = ServerStateEvent {
            server,
            success: success == sys::ares_bool_t::ARES_TRUE,
            flags: ServerStateFlags::from_bits_retain(flags),
        };
        let callback = match host.server_state_cb.try_borrow() {
            Ok(borrowed) => borrowed.as_ref().cloned(),
            Err(_) => None,
        };
        let Some(callback) = callback else { return };
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| callback(event))) {
            host.state.poison(payload);
        }
    }
}
