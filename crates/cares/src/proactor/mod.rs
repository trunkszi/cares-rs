//! Unified caller-owned DNS resolver and completion dispatcher on [`liburing::Proactor`].
//!
//! c-ares uses synchronous socket callbacks, so [`Resolver`] owns both the threadless
//! c-ares channel and its `POLL_ADD` / `TIMEOUT` registrations. The ring owns neither
//! the resolver nor its dispatcher.

mod polls;
use std::{
    cell::Cell,
    os::fd::{AsRawFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

use libc::c_int;
use liburing::{
    Completion, CompletionDispatcher, OperationId, Proactor, SubmissionContext, SubsystemId,
    UringError, ops::Timeout,
};
use polls::{Identities, Polls};
use uarch::prelude::*;

use crate::{
    ChannelCtx, DnsRecord, DnsRecordType, HostOutcome, NameInfoOutcome, PollOutcome, QueryHandle,
    QueryOutcome, ResolverCqe, ServerStateEvent,
    error::{AresError, AresStatus, Result},
    options::ResolverOptions,
    resolver::{Channel, completion::ResolverCqeWords},
    socket_bridge::ReadinessSink,
    timer::TimerDeadline,
};

/// Active half of the driver hierarchy: nothing queued, or work is staged.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivePhase {
    /// No DNS poll, timeout, or cancel control is queued.
    Idle = 0,
    /// At least one registration is staged or in flight.
    Armed = 1,
}

/// Shutdown half of the driver hierarchy. Leaves stay sticky until work retires.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShutdownPhase {
    /// Socket polls still need a cancel submission or a terminal CQE.
    CancelingPolls = 0,
    /// Timeouts or cancel controls are still outstanding.
    DrainingTimers = 1,
    /// Every DNS registration owned by this driver has retired.
    Stopped = 2,
}

/// One-byte driver phase.
///
/// `Active` is [`ActivePhase`], `Faulted` means a channel error is stored and
/// shutdown has not started, and `ShuttingDown` is [`ShutdownPhase`]. A stored
/// [`AresError`] stays beside this byte because it does not fit in the phase.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DriverPhase {
    Idle = 0,
    Armed = 1,
    Faulted = 2,
    CancelingPolls = 3,
    DrainingTimers = 4,
    Stopped = 5,
}

impl DriverPhase {
    #[hot_inline]
    const fn is_shutdown(self) -> bool {
        matches!(
            self,
            Self::CancelingPolls | Self::DrainingTimers | Self::Stopped
        )
    }

    #[inline]
    fn sync(self, polls_pending: bool, timers_pending: bool) -> Self {
        if self.is_shutdown() {
            let leaf = if polls_pending {
                ShutdownPhase::CancelingPolls
            } else if timers_pending {
                ShutdownPhase::DrainingTimers
            } else {
                ShutdownPhase::Stopped
            };
            Self::from(leaf)
        } else if self == Self::Faulted {
            Self::Faulted
        } else if polls_pending || timers_pending {
            Self::from(ActivePhase::Armed)
        } else {
            Self::from(ActivePhase::Idle)
        }
    }
}

impl From<ActivePhase> for DriverPhase {
    fn from(phase: ActivePhase) -> Self {
        match phase {
            ActivePhase::Idle => Self::Idle,
            ActivePhase::Armed => Self::Armed,
        }
    }
}

impl From<ShutdownPhase> for DriverPhase {
    fn from(phase: ShutdownPhase) -> Self {
        match phase {
            ShutdownPhase::CancelingPolls => Self::CancelingPolls,
            ShutdownPhase::DrainingTimers => Self::DrainingTimers,
            ShutdownPhase::Stopped => Self::Stopped,
        }
    }
}

/// Lifecycle of one armed DNS timeout slot.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimerSlotPhase {
    /// The timeout SQE is the generation currently requested.
    Armed = 0,
    /// A cancel SQE has been accepted for this timeout.
    Canceling = 1,
    /// The timeout CQE was consumed and the slot can leave the table.
    Retired = 2,
}

struct TimerOperation {
    id: OperationId,
    generation: u64,
    timeout: Timeout,
    phase: TimerSlotPhase,
}

/// Single-threaded, completion-driven c-ares resolver backed by [`liburing::Proactor`].
///
/// Pass this resolver to completion dispatch directly, or route its subsystem from
/// a caller-owned worker dispatcher. Call [`Proactor::shutdown_with`] or
/// [`Self::shutdown`] before dropping it so all timeout operands are reclaimed.
/// Early drop retains pending timeout operands rather than freeing kernel memory.
pub struct Resolver {
    /// Underlying threadless c-ares channel.
    pub(crate) channel: Channel,
    polls: Polls,
    subsystem: SubsystemId,
    timers: Vec<TimerOperation>,
    identities: Identities,
    phase: DriverPhase,
    failure: Option<AresError>,
    proactor_owner_id: Option<u64>,
}

impl Resolver {
    /// Creates a DNS resolver configured with `servers_csv`; `capacity` is the initial
    /// socket-table reservation.
    ///
    /// # Errors
    /// Rejects [`SubsystemId::INTERNAL`], zero `capacity`, an empty `servers_csv`, or
    /// c-ares channel initialization failure.
    pub fn new(
        subsystem: SubsystemId,
        options: ResolverOptions,
        servers_csv: &str,
        capacity: usize,
    ) -> Result<Self> {
        if subsystem == SubsystemId::INTERNAL || capacity == 0 {
            return Err(AresError::invalid_input(
                "DNS subsystem and socket capacity must be nonzero",
            ));
        }
        if servers_csv.trim().is_empty() {
            return Err(AresError::invalid_input(
                "DNS server list must not be empty",
            ));
        }
        let mut channel = Channel::new(options)?;
        channel.set_servers_csv(servers_csv)?;
        Ok(Self::from_channel(subsystem, channel, capacity))
    }

    /// Creates a DNS resolver initialized from system DNS configuration (such as
    /// `/etc/resolv.conf`); `capacity` is the initial socket-table reservation.
    ///
    /// # Errors
    /// Rejects [`SubsystemId::INTERNAL`], zero `capacity`, an empty system server list,
    /// or c-ares channel initialization failure.
    pub fn from_system(
        subsystem: SubsystemId,
        options: ResolverOptions,
        capacity: usize,
    ) -> Result<Self> {
        if subsystem == SubsystemId::INTERNAL || capacity == 0 {
            return Err(AresError::invalid_input(
                "DNS subsystem and socket capacity must be nonzero",
            ));
        }
        let channel = Channel::new(options)?;
        if channel.servers_csv()?.trim().is_empty() {
            return Err(AresError::invalid_input("system DNS server list is empty"));
        }
        Ok(Self::from_channel(subsystem, channel, capacity))
    }

    fn from_channel(subsystem: SubsystemId, channel: Channel, capacity: usize) -> Self {
        Self {
            channel,
            polls: Polls::new(capacity),
            subsystem,
            timers: Vec::new(),
            identities: Identities::new(subsystem),
            phase: DriverPhase::from(ActivePhase::Idle),
            failure: None,
            proactor_owner_id: None,
        }
    }

    /// Submits a DNS query with a completion callback.
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
        self.channel.submit_query(name, record_type, callback)
    }

    /// Sends a pre-built DNS message with a completion callback.
    /// # Errors
    /// Returns a poisoned-resolver, message-cloning, or c-ares submission error.
    pub fn submit_record<F>(&mut self, record: &DnsRecord, callback: F) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        self.channel.submit_record(record, callback)
    }

    /// Looks up a host name through the c-ares host API.
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
        self.channel.gethostbyname(name, family, callback)
    }

    /// Looks up a host name from raw address bytes and an address family.
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
        self.channel.gethostbyaddr(address, family, callback)
    }

    /// Resolves a socket address to a node name and service.
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
        self.channel.getnameinfo(sockaddr, flags, callback)
    }

    /// Cancels every query pending at entry.
    /// # Errors
    /// Returns [`AresError::CallbackPanicked`] or the channel-liveness error.
    pub fn cancel(&mut self) -> Result<()> {
        self.channel.cancel()
    }

    /// Cancels one query without disturbing the rest of the channel.
    /// # Errors
    /// Returns [`AresError::CallbackPanicked`] or [`AresError::InvalidInput`] for a stale handle.
    pub fn cancel_query(&mut self, handle: QueryHandle) -> Result<()> {
        self.channel.cancel_query(handle)
    }

    /// Re-reads system resolver configuration into the live channel.
    /// # Errors
    /// Returns the `ares_reinit` status or the channel-liveness error.
    pub fn reinit(&mut self) -> Result<()> {
        self.channel.reinit()
    }

    /// Replaces the server list with a `host[:port][,host[:port]...]` string.
    /// # Errors
    /// Returns an input error, the `ares_set_servers_ports_csv` status, or liveness error.
    pub fn set_servers_csv(&mut self, csv: &str) -> Result<()> {
        self.channel.set_servers_csv(csv)
    }

    /// Returns the configured servers in c-ares' CSV form.
    /// # Errors
    /// Returns [`AresError::AllocationFailed`] or the channel-liveness error.
    pub fn servers_csv(&self) -> Result<String> {
        self.channel.servers_csv()
    }

    /// Installs a callback for server health transitions, replacing any previous one.
    pub fn set_server_state_callback<F>(&mut self, callback: F)
    where
        F: Fn(ServerStateEvent) + 'static,
    {
        self.channel.set_server_state_callback(callback);
    }

    /// Reports whether a completion callback or readiness sink panicked.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.channel.is_poisoned()
    }

    /// Returns the number of queries that have not yet been retired.
    #[must_use]
    pub fn active_queries(&self) -> usize {
        self.channel.active_queries()
    }

    /// Returns the next c-ares deadline for the caller's proactor timer.
    ///
    /// # Errors
    /// Returns [`AresError::CallbackPanicked`] for a poisoned resolver, or the
    /// channel-liveness error after destruction, or an input error on generation exhaustion.
    pub fn timer_deadline(&mut self) -> Result<Option<TimerDeadline>> {
        self.channel.timer_deadline()
    }

    /// Replaces the readiness sink driven by the internal socket bridge.
    ///
    /// # Errors
    /// Returns the channel-liveness error after the resolver is destroyed.
    pub fn install_readiness_sink(&mut self, sink: Rc<dyn ReadinessSink>) -> Result<()> {
        self.channel.install_readiness_sink(sink)
    }

    /// Delivers one proactor completion to the channel.
    ///
    /// # Errors
    /// Returns [`AresError::ReentrantDriveForbidden`] when called from a callback,
    /// [`AresError::CallbackPanicked`] for a poisoned resolver, or the channel-liveness
    /// error.
    #[inline]
    pub fn on_cqe(&mut self, cqe: ResolverCqe) -> Result<()> {
        self.channel.on_cqe(cqe)
    }

    /// Processes buffered events without blocking.
    ///
    /// # Errors
    /// Returns [`AresError::ReentrantDriveForbidden`] when called from a callback,
    /// [`AresError::CallbackPanicked`] for a poisoned resolver, or the channel-liveness
    /// error.
    pub fn poll_completions(&mut self) -> Result<PollOutcome> {
        self.channel.poll_completions()
    }

    /// Submits a single query for `(name, record_type)` and drives `proactor` until
    /// the query completes or `timeout` expires.
    ///
    /// Note: `proactor` completions are dispatched directly to `self`, so `proactor`
    /// must not deliver unrelated subsystem completions during this call.
    ///
    /// # Errors
    /// Returns [`AresError::ReentrantDriveForbidden`] when called from a callback,
    /// [`AresStatus::Timeout`] when `timeout` elapses, or the query / proactor failure.
    pub fn resolve(
        &mut self,
        proactor: &mut Proactor,
        name: &str,
        record_type: DnsRecordType,
        timeout: Duration,
    ) -> Result<DnsRecord> {
        if self.channel.is_driving() {
            return Err(AresError::ReentrantDriveForbidden);
        }
        if let Some(error) = self.failure.clone() {
            return Err(error);
        }
        self.bind_owner(proactor)?;
        let deadline = Instant::now().checked_add(timeout);
        let sink: Rc<Cell<Option<Result<DnsRecord>>>> = Rc::new(Cell::new(None));
        let captured = Rc::clone(&sink);
        let handle = self
            .channel
            .submit_query(name, record_type, move |_ctx, outcome| {
                captured.set(Some(match outcome.record {
                    Some(record) => record.to_owned_record(),
                    None => Err(AresError::from_status(outcome.status)),
                }));
            })?;
        loop {
            if let Some(value) = sink.take() {
                return value;
            }
            self.flush(proactor)
                .inspect_err(|_| drop(self.cancel_query(handle)))?;
            if let Some(value) = sink.take() {
                return value;
            }
            let now = Instant::now();
            let remaining = match deadline {
                Some(limit) if now >= limit => {
                    drop(self.cancel_query(handle));
                    drop(self.flush(proactor));
                    return Err(AresError::from_status(AresStatus::Timeout));
                }
                Some(limit) => limit.saturating_duration_since(now),
                None => Duration::from_secs(1),
            };
            if self.channel.active_queries() == 0 {
                return sink
                    .take()
                    .unwrap_or_else(|| Err(AresError::from_status(AresStatus::Timeout)));
            }
            let drive_result = if proactor.mode().allows_blocking_wait() {
                proactor.wait_completions(1, Some(remaining.min(Duration::from_millis(20))), self)
            } else {
                let res = proactor.tick(self);
                std::hint::spin_loop();
                res
            };
            if let Some(error) = self.failure.clone() {
                drop(self.cancel_query(handle));
                return Err(error);
            }
            drive_result
                .map_err(|error| proactor_error("DNS resolve", error))
                .inspect_err(|_| drop(self.cancel_query(handle)))?;
        }
    }

    /// Stages current socket interests and the c-ares retry deadline.
    ///
    /// Call again after new queries or when other subsystems release ring credit.
    /// The first flush or shutdown permanently binds this driver to that ring.
    /// # Errors
    /// Returns a channel error, foreign-ring error, or named submission failure.
    pub fn flush(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.bind_owner(proactor)?;
        self.flush_to(proactor).map_err(|error| {
            self.failure
                .clone()
                .unwrap_or_else(|| proactor_error("DNS proactor", error))
        })
    }

    fn bind_owner(&mut self, proactor: &Proactor) -> Result<()> {
        let owner = proactor.owner_id();
        if self.proactor_owner_id.is_some_and(|bound| bound != owner) {
            return Err(AresError::invalid_input(
                "DNS driver belongs to another proactor",
            ));
        }
        self.proactor_owner_id = Some(owner);
        Ok(())
    }

    /// Returns the first channel failure retained by completion dispatch.
    #[must_use]
    pub fn failure(&self) -> Option<&AresError> {
        self.failure.as_ref()
    }

    fn deadline(&mut self) -> liburing::Result<Option<crate::timer::TimerDeadline>> {
        self.channel.timer_deadline().map_err(|error| {
            self.remember(error);
            UringError::InvalidConfig("DNS resolver deadline failed")
        })
    }

    #[cold_sink]
    fn remember(&mut self, error: AresError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        if !self.phase.is_shutdown() {
            self.phase = DriverPhase::Faulted;
        }
    }

    #[inline]
    fn sync_phase(&mut self) {
        self.phase = self.phase.sync(
            self.polls.pending > 0,
            !self.timers.is_empty() || self.identities.has_pending(),
        );
    }

    fn flush_to(&mut self, submit: &mut impl Submit) -> liburing::Result<()> {
        let result = if self.phase.is_shutdown() {
            self.stop_to(submit)
        } else {
            self.stage_to(submit)
        };
        self.sync_phase();
        result
    }

    fn stage_to(&mut self, submit: &mut impl Submit) -> liburing::Result<()> {
        let deadline = self.deadline()?;
        let current = deadline.map(|value| value.generation);
        for timer in &mut self.timers {
            if Some(timer.generation) != current && timer.phase == TimerSlotPhase::Armed {
                match self.identities.cancel(submit, timer.id) {
                    Ok(()) => timer.phase = TimerSlotPhase::Canceling,
                    Err(UringError::SqRingFull) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        }
        self.polls
            .reconcile(&self.channel, submit, &mut self.identities)?;
        if let Some(deadline) = deadline
            && !self
                .timers
                .iter()
                .any(|timer| timer.generation == deadline.generation)
        {
            let timeout = Timeout::new(deadline.at.saturating_duration_since(Instant::now()))?;
            let id = self.identities.next()?;
            match submit.timeout(id, &timeout) {
                Ok(()) => self.timers.push(TimerOperation {
                    id,
                    generation: deadline.generation,
                    timeout,
                    phase: TimerSlotPhase::Armed,
                }),
                Err(UringError::SqRingFull) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        self.polls.arm(submit, &mut self.identities)
    }

    /// Counts staged/in-flight DNS polls, timeouts, and cancellation controls.
    ///
    /// A cancel acknowledgment and its target are counted independently until
    /// each final CQE is consumed. Peer subsystem operations are excluded.
    #[must_use]
    #[hot_inline]
    pub fn inflight_count(&self) -> usize {
        self.polls.inflight_count() + self.timers.len() + self.identities.inflight_count()
    }

    /// Reports queued or in-flight DNS polls, timeouts, and cancel acknowledgments.
    #[must_use]
    #[inline]
    pub fn has_pending_io(&self) -> bool {
        match self.phase {
            DriverPhase::Idle | DriverPhase::Stopped => false,
            DriverPhase::Faulted => {
                self.polls.pending > 0 || !self.timers.is_empty() || self.identities.has_pending()
            }
            DriverPhase::Armed | DriverPhase::CancelingPolls | DriverPhase::DrainingTimers => true,
        }
    }

    /// Stops accepting queries and requests cancellation without closing the ring.
    ///
    /// Drive the caller's dispatcher and call flush while has_pending_io is true.
    /// No new socket or timer registration is armed after this call. Cancellation
    /// controls remain queued logically when ring credit is temporarily exhausted.
    /// # Errors
    /// Returns channel cancellation, foreign-ring, or ring submission failure.
    /// Foreign rings are rejected before stopping queries or changing pending state.
    pub fn begin_shutdown(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.bind_owner(proactor)?;
        if !self.phase.is_shutdown() {
            self.phase = DriverPhase::from(ShutdownPhase::CancelingPolls);
        }
        let channel = self.channel.stop_submissions();
        let registrations = self.flush(proactor);
        channel.and(registrations)
    }

    /// Drains this DNS-only dispatch loop within a five-second budget.
    ///
    /// Shared-ring owners with other subsystems use begin_shutdown and their own
    /// dispatcher. This method leaves the ring open and does not cancel peer I/O.
    /// # Errors
    /// Returns cancellation, foreign-subsystem, wait, or budget-exhaustion errors.
    pub fn shutdown(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.shutdown_within(proactor, Duration::from_secs(5))
    }

    /// Drains a DNS-only ring dispatch loop within the caller's explicit budget.
    /// # Errors
    /// Returns cancellation, foreign-subsystem, wait, or budget-exhaustion errors.
    pub fn shutdown_within(&mut self, proactor: &mut Proactor, budget: Duration) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| AresError::invalid_input("DNS shutdown budget overflows"))?;
        self.begin_shutdown(proactor)?;
        while self.has_pending_io() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(AresError::invalid_input(
                    "DNS shutdown budget exhausted with pending I/O",
                ));
            }
            self.flush(proactor)?;
            if proactor.mode().allows_blocking_wait() {
                proactor
                    .wait_completions(1, Some(remaining.min(Duration::from_millis(20))), self)
                    .map_err(|error| proactor_error("DNS shutdown wait", error))?;
            } else {
                proactor
                    .tick(self)
                    .map_err(|error| proactor_error("DNS shutdown tick", error))?;
                std::hint::spin_loop();
            }
        }
        Ok(())
    }

    #[cold_sink]
    fn stop_to(&mut self, submit: &mut impl Submit) -> liburing::Result<()> {
        self.polls.stop(submit, &mut self.identities)?;
        for timer in &mut self.timers {
            if timer.phase == TimerSlotPhase::Armed {
                match self.identities.cancel(submit, timer.id) {
                    Ok(()) => timer.phase = TimerSlotPhase::Canceling,
                    Err(UringError::SqRingFull) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn deliver(&mut self, cqe: ResolverCqeWords) -> liburing::Result<()> {
        self.channel.on_cqe_words(cqe).map(|_| ()).map_err(|error| {
            self.remember(error);
            UringError::InvalidConfig("DNS resolver completion failed")
        })
    }
}

impl CompletionDispatcher for Resolver {
    #[inline]
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        if completion.operation_id.subsystem_id() != self.subsystem {
            return Err(UringError::InvalidSubsystemId(
                completion.operation_id.subsystem_id().raw(),
            ));
        }
        if self.proactor_owner_id != Some(submissions.owner_id()) {
            return Err(UringError::InvalidConfig(
                "DNS completion belongs to another proactor",
            ));
        }
        submissions.claim_completion(completion)?;
        if self.identities.complete(completion.operation_id) {
            self.sync_phase();
            if !matches!(completion.result, 0)
                && ![-libc::ENOENT, -libc::EALREADY, -libc::ECANCELED].contains(&completion.result)
            {
                return Err(UringError::syscalls("DNS cancel", completion.result));
            }
        } else if let Some(index) = self
            .timers
            .iter()
            .position(|timer| timer.id == completion.operation_id)
        {
            let mut timer = self.timers.swap_remove(index);
            let generation = timer.generation;
            let _previous = std::mem::replace(&mut timer.phase, TimerSlotPhase::Retired);
            self.sync_phase();
            if completion.result == -libc::ETIME && !self.phase.is_shutdown() {
                self.deliver(ResolverCqeWords::timer(generation))?;
            } else if completion.result != -libc::ECANCELED && completion.result != -libc::ETIME {
                return Err(UringError::syscalls("DNS timeout", completion.result));
            }
        } else {
            let event = self.polls.complete(completion, &self.channel);
            self.sync_phase();
            if completion.result < 0 && completion.result != -libc::ECANCELED {
                return Err(UringError::syscalls("DNS poll", completion.result));
            }
            if let Some((fd, readable, writable)) = event
                && !self.phase.is_shutdown()
            {
                self.deliver(ResolverCqeWords::socket(fd, readable, writable))?;
            }
        }
        // Teardown dispatch has no submission credit and must only retire state.
        if submissions.remaining_capacity() == 0 {
            self.sync_phase();
            return Ok(());
        }
        self.flush_to(submissions)
    }
}

impl Drop for Resolver {
    #[cold_sink]
    fn drop(&mut self) {
        // A dispatcher can be dropped before its ring. Pending timeout SQEs may
        // still reference these operands; only their target CQEs prove retirement.
        for timer in self.timers.drain(..) {
            std::mem::forget(timer.timeout);
        }
    }
}

trait Submit {
    fn poll(&mut self, id: OperationId, socket: Rc<OwnedFd>, mask: u32) -> liburing::Result<()>;
    fn timeout(&mut self, id: OperationId, timeout: &Timeout) -> liburing::Result<()>;
    fn cancel(&mut self, id: OperationId, target: OperationId) -> liburing::Result<()>;
}

macro_rules! impl_submit {
    ($target:ty) => {
        impl Submit for $target {
            fn poll(
                &mut self,
                id: OperationId,
                socket: Rc<OwnedFd>,
                mask: u32,
            ) -> liburing::Result<()> {
                let fd = socket.as_raw_fd();
                self.prepare_owned_sqe_with(id, socket, None, |sqe| {
                    // SAFETY: The ring retains the descriptor through its final
                    // CQE; POLL_ADD references no userspace DMA storage.
                    unsafe { liburing::ops::net::prep_poll_add(sqe, fd, mask) };
                })
            }
            fn timeout(&mut self, id: OperationId, timeout: &Timeout) -> liburing::Result<()> {
                self.prepare_sqe_with(id, |sqe| {
                    // SAFETY: The driver retains this stable operand through its
                    // terminal CQE and retains it if teardown cannot prove drain.
                    unsafe { timeout.prepare(sqe) };
                })
            }
            fn cancel(&mut self, id: OperationId, target: OperationId) -> liburing::Result<()> {
                self.prepare_sqe_with(id, |sqe| {
                    // SAFETY: The ring translates the caller target identity to
                    // its current operation generation before publishing cancel.
                    unsafe { liburing::ops::net::prep_cancel(sqe, target, 0) };
                })
            }
        }
    };
}
impl_submit!(Proactor);
impl_submit!(SubmissionContext<'_>);

#[cold_sink]
fn proactor_error(context: &'static str, error: UringError) -> AresError {
    AresError::invalid_input(format!("{context}: {error}"))
}
