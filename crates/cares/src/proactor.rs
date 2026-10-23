//! Caller-owned DNS completion dispatch on a shared ring.
//!
//! c-ares uses synchronous socket callbacks, so this adapter alone owns its
//! POLL_ADD readiness state. The ring owns neither the resolver nor its dispatcher.

use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

use liburing::{
    Completion, CompletionDispatcher, OperationId, OperationPayload, Proactor, SubmissionContext,
    SubsystemId, UringError, ops::Timeout,
};

use crate::{
    Resolver, ResolverCqe,
    error::{AresError, Result},
    options::ResolverOptions,
    socket_bridge::SocketInterest,
};

struct TimerOperation {
    id: OperationId,
    generation: u64,
    timeout: Timeout,
    canceling: bool,
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
    shutting_down: bool,
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
            shutting_down: false,
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
            self.failure.get_or_insert(error);
            UringError::InvalidConfig("DNS resolver deadline failed")
        })
    }

    fn flush_to(&mut self, submit: &mut impl Submit) -> liburing::Result<()> {
        if self.shutting_down {
            return self.stop_to(submit);
        }
        let deadline = self.deadline()?;
        let current = deadline.map(|value| value.generation);
        for timer in &mut self.timers {
            if Some(timer.generation) != current && !timer.canceling {
                match self.identities.cancel(submit, timer.id) {
                    Ok(()) => timer.canceling = true,
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
                    canceling: false,
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
        self.polls.has_pending() || !self.timers.is_empty() || self.identities.has_pending()
    }

    /// Stops accepting queries and requests cancellation without closing the ring.
    ///
    /// Drive the caller's dispatcher and call flush while has_pending_io is true.
    /// No new socket or timer registration is armed after this call. Cancellation
    /// controls remain queued logically when ring credit is temporarily exhausted.
    /// # Errors
    /// Returns channel cancellation or ring submission failure; pending state remains owned.
    pub fn begin_shutdown(&mut self, proactor: &mut Proactor) -> Result<()> {
        self.shutting_down = true;
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
            if !timer.canceling {
                match self.identities.cancel(submit, timer.id) {
                    Ok(()) => timer.canceling = true,
                    Err(UringError::SqRingFull) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn deliver(&mut self, cqe: ResolverCqe) -> liburing::Result<()> {
        self.resolver.on_cqe(cqe).map(|_| ()).map_err(|error| {
            self.failure.get_or_insert(error);
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
            let timer = self.timers.swap_remove(index);
            if completion.result == -libc::ETIME && !self.shutting_down {
                self.deliver(ResolverCqe::Timer {
                    generation: timer.generation,
                })?;
            } else if completion.result != -libc::ECANCELED && completion.result != -libc::ETIME {
                return Err(UringError::syscalls("DNS timeout", completion.result));
            }
        } else {
            let event = self.polls.complete(completion, &self.resolver);
            if completion.result < 0 && completion.result != -libc::ECANCELED {
                return Err(UringError::syscalls("DNS poll", completion.result));
            }
            if let Some((fd, readable, writable)) = event
                && !self.shutting_down
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

struct Identities {
    subsystem: SubsystemId,
    next: u64,
    controls: Vec<OperationId>,
}

impl Identities {
    fn new(subsystem: SubsystemId) -> Self {
        Self {
            subsystem,
            next: 1,
            controls: Vec::new(),
        }
    }
    fn next(&mut self) -> liburing::Result<OperationId> {
        let payload =
            OperationPayload::new(self.next).ok_or(UringError::PayloadOverflow(self.next))?;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(UringError::PayloadOverflow(self.next))?;
        Ok(OperationId::pack(self.subsystem, payload))
    }
    fn cancel(&mut self, submit: &mut impl Submit, target: OperationId) -> liburing::Result<()> {
        let id = self.next()?;
        submit.cancel(id, target)?;
        self.controls.push(id);
        Ok(())
    }
    fn complete(&mut self, id: OperationId) -> bool {
        if let Some(index) = self.controls.iter().position(|&control| control == id) {
            self.controls.swap_remove(index);
            true
        } else {
            false
        }
    }
    fn inflight_count(&self) -> usize {
        self.controls.len()
    }
    fn has_pending(&self) -> bool {
        !self.controls.is_empty()
    }
}

struct PollState {
    fd: i32,
    generation: u64,
    socket: Rc<OwnedFd>,
    desired: SocketInterest,
    submitted: SocketInterest,
    active: Option<OperationId>,
    canceling: bool,
    wanted: bool,
}

struct Polls {
    states: Vec<PollState>,
    interests: Vec<(i32, u64, SocketInterest)>,
}

impl Polls {
    fn new(capacity: usize) -> Self {
        Self {
            states: Vec::with_capacity(capacity),
            interests: Vec::with_capacity(capacity),
        }
    }

    fn reconcile(
        &mut self,
        resolver: &Resolver,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<()> {
        resolver.poll_interests(&mut self.interests);
        for state in &mut self.states {
            state.wanted = false;
        }
        for &(fd, generation, interest) in &self.interests {
            if !interest.readable && !interest.writable {
                continue;
            }
            if let Some(state) = self
                .states
                .iter_mut()
                .find(|state| state.fd == fd && state.generation == generation)
            {
                state.desired = interest;
                state.wanted = true;
            } else {
                // SAFETY: c-ares still owns this live descriptor on the caller
                // thread. The duplicate retains this socket across original-fd
                // closure, reuse, and staged or canceling poll operations.
                let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if duplicate < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                // SAFETY: fcntl returned a new descriptor owned by this call.
                let socket = Rc::new(unsafe { OwnedFd::from_raw_fd(duplicate) });
                self.states.push(PollState {
                    fd,
                    generation,
                    socket,
                    desired: interest,
                    submitted: SocketInterest::default(),
                    active: None,
                    canceling: false,
                    wanted: true,
                });
            }
        }
        self.cancel_changed(submit, ids)
    }

    fn stop(&mut self, submit: &mut impl Submit, ids: &mut Identities) -> liburing::Result<()> {
        for state in &mut self.states {
            state.wanted = false;
        }
        self.cancel_changed(submit, ids)
    }

    fn cancel_changed(
        &mut self,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<()> {
        for state in &mut self.states {
            if let Some(id) = state.active
                && (!state.wanted || state.desired != state.submitted)
                && !state.canceling
            {
                match ids.cancel(submit, id) {
                    Ok(()) => state.canceling = true,
                    Err(UringError::SqRingFull) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        }
        self.states
            .retain(|state| state.wanted || state.active.is_some());
        Ok(())
    }

    fn inflight_count(&self) -> usize {
        self.states
            .iter()
            .filter(|state| state.active.is_some())
            .count()
    }

    fn has_pending(&self) -> bool {
        self.states
            .iter()
            .any(|state| state.wanted || state.active.is_some())
    }

    fn arm(&mut self, submit: &mut impl Submit, ids: &mut Identities) -> liburing::Result<()> {
        for state in &mut self.states {
            if !state.wanted || state.active.is_some() {
                continue;
            }
            let mask = if state.desired.readable {
                libc::POLLIN as u32
            } else {
                0
            } | if state.desired.writable {
                libc::POLLOUT as u32
            } else {
                0
            };
            let id = ids.next()?;
            match submit.poll(id, Rc::clone(&state.socket), mask) {
                Ok(()) => {
                    state.active = Some(id);
                    state.submitted = state.desired;
                    state.canceling = false;
                }
                Err(UringError::SqRingFull) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn complete(
        &mut self,
        completion: Completion,
        resolver: &Resolver,
    ) -> Option<(i32, bool, bool)> {
        let state = self
            .states
            .iter_mut()
            .find(|state| state.active == Some(completion.operation_id))?;
        state.active = None;
        state.canceling = false;
        if !resolver.owns_socket(state.fd, state.generation) || completion.result < 0 {
            return None;
        }
        let flags = completion.result;
        let errors = i32::from(libc::POLLERR | libc::POLLHUP | libc::POLLNVAL);
        Some((
            state.fd,
            flags & (i32::from(libc::POLLIN) | errors) != 0,
            flags & (i32::from(libc::POLLOUT) | errors) != 0,
        ))
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
