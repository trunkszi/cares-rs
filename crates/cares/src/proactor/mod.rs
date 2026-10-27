//! Caller-owned DNS completion dispatch on a shared ring.
//!
//! c-ares uses synchronous socket callbacks, so this adapter alone owns its
//! POLL_ADD readiness state. The ring owns neither the resolver nor its dispatcher.

mod polls;

use std::{
    os::fd::{AsRawFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

use liburing::{
    Completion, CompletionDispatcher, OperationId, Proactor, SubmissionContext, SubsystemId,
    UringError, ops::Timeout,
};
use polls::{Identities, Polls};

use crate::{
    Resolver, ResolverCqe,
    error::{AresError, Result},
    options::ResolverOptions,
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
    const fn is_shutdown(self) -> bool {
        matches!(
            self,
            Self::CancelingPolls | Self::DrainingTimers | Self::Stopped
        )
    }

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

/// Owns one resolver and its socket/deadline registrations outside the ring.
///
/// Pass this driver to completion dispatch directly, or route its subsystem from
/// a caller-owned worker dispatcher. Call [`Proactor::shutdown_with`] with the
/// same dispatcher before dropping it so all timeout operands are reclaimed.
/// Early drop retains pending timeout operands rather than freeing kernel memory.
pub struct ProactorResolver {
    /// Channel owned and accessed directly by the caller.
    pub resolver: Resolver,
    polls: Polls,
    subsystem: SubsystemId,
    timers: Vec<TimerOperation>,
    identities: Identities,
    phase: DriverPhase,
    failure: Option<AresError>,
}

impl ProactorResolver {
    /// Creates a DNS driver; `capacity` is the initial socket-table reservation.
    ///
    /// # Errors
    /// Rejects an internal subsystem, zero reservation, or resolver setup failure.
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
        let mut resolver = Resolver::new(options)?;
        resolver.set_servers_csv(servers_csv)?;
        Ok(Self {
            resolver,
            polls: Polls::new(capacity),
            subsystem,
            timers: Vec::new(),
            identities: Identities::new(subsystem),
            phase: DriverPhase::from(ActivePhase::Idle),
            failure: None,
        })
    }

    /// Stages current socket interests and the c-ares retry deadline.
    ///
    /// Call again after new queries or when other subsystems release ring credit.
    /// # Errors
    /// Returns a channel error or named submission failure, preserving pending work.
    pub fn flush(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.flush_to(proactor).map_err(|error| {
            self.failure
                .clone()
                .unwrap_or_else(|| AresError::invalid_input(format!("DNS proactor: {error}")))
        })
    }

    /// Returns the first channel failure retained by completion dispatch.
    #[must_use]
    pub fn failure(&self) -> Option<&AresError> {
        self.failure.as_ref()
    }

    fn deadline(&mut self) -> liburing::Result<Option<crate::timer::TimerDeadline>> {
        self.resolver.timer_deadline().map_err(|error| {
            self.remember(error);
            UringError::InvalidConfig("DNS resolver deadline failed")
        })
    }

    fn remember(&mut self, error: AresError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        if !self.phase.is_shutdown() {
            self.phase = DriverPhase::Faulted;
        }
    }

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
            .reconcile(&self.resolver, submit, &mut self.identities)?;
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
    pub fn inflight_count(&self) -> usize {
        self.polls.inflight_count() + self.timers.len() + self.identities.inflight_count()
    }

    /// Reports queued or in-flight DNS polls, timeouts, and cancel acknowledgments.
    #[must_use]
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
    /// Returns channel cancellation or ring submission failure; pending state remains owned.
    pub fn begin_shutdown(&mut self, proactor: &mut Proactor) -> Result<()> {
        if !self.phase.is_shutdown() {
            self.phase = DriverPhase::from(ShutdownPhase::CancelingPolls);
        }
        let channel = self.resolver.stop_submissions();
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
            proactor
                .wait_completions(1, Some(remaining.min(Duration::from_millis(20))), self)
                .map_err(|error| AresError::invalid_input(format!("DNS shutdown wait: {error}")))?;
        }
        Ok(())
    }

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

    fn deliver(&mut self, cqe: ResolverCqe) -> liburing::Result<()> {
        self.resolver.on_cqe(cqe).map(|_| ()).map_err(|error| {
            self.remember(error);
            UringError::InvalidConfig("DNS resolver completion failed")
        })
    }
}

impl CompletionDispatcher for ProactorResolver {
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
                self.deliver(ResolverCqe::Timer { generation })?;
            } else if completion.result != -libc::ECANCELED && completion.result != -libc::ETIME {
                return Err(UringError::syscalls("DNS timeout", completion.result));
            }
        } else {
            let event = self.polls.complete(completion, &self.resolver);
            self.sync_phase();
            if completion.result < 0 && completion.result != -libc::ECANCELED {
                return Err(UringError::syscalls("DNS poll", completion.result));
            }
            if let Some((fd, readable, writable)) = event
                && !self.phase.is_shutdown()
            {
                self.deliver(ResolverCqe::Socket {
                    fd,
                    readable,
                    writable,
                })?;
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

impl Drop for ProactorResolver {
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
