//! Socket readiness slots and operation identities owned by the DNS driver.
//!
//! Each live c-ares descriptor is duplicated for `POLL_ADD`. Removing a slot
//! clears the interest snapshot so the same mask is submitted again.

#[cfg(test)]
use std::os::fd::AsRawFd;
use std::{
    os::fd::{FromRawFd, OwnedFd},
    rc::Rc,
};

#[cfg(test)]
use liburing::ops::Timeout;
use liburing::{Completion, OperationId, OperationPayload, SubsystemId, UringError};

use super::Submit;
#[cfg(test)]
use crate::options::ResolverOptions;
use crate::{Resolver, socket_bridge::SocketInterest};

/// Lifecycle of one socket readiness slot. Cancel-in-flight is the high bit.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PollSlotPhase {
    /// The submitted mask matches the desired mask and a poll is active.
    Synced = 0,
    /// The slot is wanted and still needs `POLL_ADD`.
    PendingAdd = 1,
    /// An active poll must be canceled before the new mask is armed.
    PendingModify = 2,
    /// The slot is no longer wanted and must drain or leave the table.
    PendingRemove = 3,
}

const POLL_CANCEL_BIT: u8 = 0x80;

pub(super) struct Identities {
    subsystem: SubsystemId,
    next: u64,
    controls: Vec<OperationId>,
}

impl Identities {
    pub(super) fn new(subsystem: SubsystemId) -> Self {
        Self {
            subsystem,
            next: 1,
            controls: Vec::new(),
        }
    }

    pub(super) fn next(&mut self) -> liburing::Result<OperationId> {
        let payload =
            OperationPayload::new(self.next).ok_or(UringError::PayloadOverflow(self.next))?;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(UringError::PayloadOverflow(self.next))?;
        Ok(OperationId::pack(self.subsystem, payload))
    }

    pub(super) fn cancel(
        &mut self,
        submit: &mut impl Submit,
        target: OperationId,
    ) -> liburing::Result<()> {
        let id = self.next()?;
        submit.cancel(id, target)?;
        self.controls.push(id);
        Ok(())
    }

    pub(super) fn complete(&mut self, id: OperationId) -> bool {
        let Some(index) = self.controls.iter().position(|&control| control == id) else {
            return false;
        };
        self.controls.swap_remove(index);
        true
    }

    pub(super) fn inflight_count(&self) -> usize {
        self.controls.len()
    }

    pub(super) fn has_pending(&self) -> bool {
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
    /// Low bits are [`PollSlotPhase`]; [`POLL_CANCEL_BIT`] means cancel was submitted.
    raw: u8,
}

impl PollState {
    fn phase(&self) -> PollSlotPhase {
        match self.raw & !POLL_CANCEL_BIT {
            0 => PollSlotPhase::Synced,
            1 => PollSlotPhase::PendingAdd,
            2 => PollSlotPhase::PendingModify,
            _ => PollSlotPhase::PendingRemove,
        }
    }

    fn canceling(&self) -> bool {
        self.raw & POLL_CANCEL_BIT != 0
    }

    fn wanted(&self) -> bool {
        self.phase() != PollSlotPhase::PendingRemove
    }

    fn set(&mut self, phase: PollSlotPhase, canceling: bool) {
        self.raw = phase as u8 | if canceling { POLL_CANCEL_BIT } else { 0 };
    }

    fn disarm(&mut self) {
        self.set(PollSlotPhase::PendingRemove, self.canceling());
    }

    fn apply_interest(&mut self, interest: SocketInterest) {
        self.desired = interest;
        if self.active.is_some() && (self.desired != self.submitted || self.canceling()) {
            self.set(PollSlotPhase::PendingModify, self.canceling());
        } else if self.active.is_some() {
            self.set(PollSlotPhase::Synced, false);
        } else {
            self.set(PollSlotPhase::PendingAdd, false);
        }
    }

    fn stable(&self) -> bool {
        !self.canceling()
            && matches!(
                self.phase(),
                PollSlotPhase::Synced | PollSlotPhase::PendingAdd
            )
    }
}

pub(super) struct Polls {
    states: Vec<PollState>,
    interests: Vec<(i32, u64, SocketInterest)>,
    snapshot: Vec<(i32, u64, SocketInterest)>,
    /// Slots that are wanted or still have an in-flight poll. Maintained without a rescan.
    pub(super) pending: usize,
}

impl Polls {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            states: Vec::with_capacity(capacity),
            interests: Vec::with_capacity(capacity),
            snapshot: Vec::with_capacity(capacity),
            pending: 0,
        }
    }

    pub(super) fn reconcile(
        &mut self,
        resolver: &Resolver,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<()> {
        resolver.poll_interests(&mut self.interests);
        self.reconcile_ready(submit, ids)
    }

    fn reconcile_ready(
        &mut self,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<()> {
        // Same masks and settled slots: skip the linear dup/cancel scan.
        if self.interests == self.snapshot && self.states.iter().all(PollState::stable) {
            return Ok(());
        }
        for state in &mut self.states {
            state.disarm();
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
                state.apply_interest(interest);
            } else {
                // SAFETY: c-ares still owns this live descriptor on the caller
                // thread. The duplicate retains this socket across original-fd
                // closure, reuse, and staged or canceling poll operations.
                let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                if duplicate < 0 {
                    self.recount();
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
                    raw: PollSlotPhase::PendingAdd as u8,
                });
            }
        }
        if self.cancel_changed(submit, ids)? {
            self.snapshot.clone_from(&self.interests);
        }
        Ok(())
    }

    pub(super) fn stop(
        &mut self,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<()> {
        for state in &mut self.states {
            state.disarm();
        }
        self.cancel_changed(submit, ids).map(|_| ())
    }

    fn recount(&mut self) {
        self.pending = self
            .states
            .iter()
            .filter(|state| state.wanted() || state.active.is_some())
            .count();
    }

    /// Returns whether every required cancel was submitted.
    ///
    /// `SqRingFull` leaves the remaining slots unmarked so a later flush can
    /// retry. The readiness snapshot must stay stale in that case. A slot that
    /// `retain` drops clears the snapshot.
    fn cancel_changed(
        &mut self,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<bool> {
        for state in &mut self.states {
            if let Some(id) = state.active
                && (!state.wanted() || state.desired != state.submitted)
                && !state.canceling()
            {
                match ids.cancel(submit, id) {
                    Ok(()) => state.set(state.phase(), true),
                    Err(UringError::SqRingFull) => {
                        self.recount();
                        return Ok(false);
                    }
                    Err(error) => {
                        self.recount();
                        return Err(error);
                    }
                }
            }
        }
        let before = self.states.len();
        self.states
            .retain(|state| state.wanted() || state.active.is_some());
        if self.states.len() != before {
            self.snapshot.clear();
        }
        self.recount();
        Ok(true)
    }

    pub(super) fn inflight_count(&self) -> usize {
        self.states
            .iter()
            .filter(|state| state.active.is_some())
            .count()
    }

    pub(super) fn arm(
        &mut self,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<()> {
        for state in &mut self.states {
            if !state.wanted() || state.active.is_some() {
                continue;
            }
            let mask = (u32::from(state.desired.readable) * libc::POLLIN as u32)
                | (u32::from(state.desired.writable) * libc::POLLOUT as u32);
            let id = ids.next()?;
            match submit.poll(id, Rc::clone(&state.socket), mask) {
                Ok(()) => {
                    state.active = Some(id);
                    state.submitted = state.desired;
                    state.set(PollSlotPhase::Synced, false);
                }
                Err(UringError::SqRingFull) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(super) fn complete(
        &mut self,
        completion: Completion,
        resolver: &Resolver,
    ) -> Option<(i32, bool, bool)> {
        let index = self
            .states
            .iter()
            .position(|state| state.active == Some(completion.operation_id))?;
        let fd = self.states[index].fd;
        let generation = self.states[index].generation;
        let retiring = self.states[index].phase() == PollSlotPhase::PendingRemove;
        let state = &mut self.states[index];
        state.active = None;
        let next = if retiring {
            PollSlotPhase::PendingRemove
        } else {
            PollSlotPhase::PendingAdd
        };
        state.set(next, false);
        let event = if !resolver.owns_socket(fd, generation) || completion.result < 0 {
            None
        } else {
            let flags = completion.result;
            let errors = i32::from(libc::POLLERR | libc::POLLHUP | libc::POLLNVAL);
            Some((
                fd,
                flags & (i32::from(libc::POLLIN) | errors) != 0,
                flags & (i32::from(libc::POLLOUT) | errors) != 0,
            ))
        };
        // A finished removal must not keep the unchanged-mask fast path closed.
        if retiring {
            self.states.swap_remove(index);
            self.pending = self.pending.saturating_sub(1);
            self.snapshot.clear();
        }
        event
    }
}

#[cfg(test)]
struct CancelGate {
    polls: u8,
    full: bool,
}

#[cfg(test)]
impl Submit for CancelGate {
    fn poll(&mut self, _: OperationId, _: Rc<OwnedFd>, _: u32) -> liburing::Result<()> {
        self.polls += 1;
        Ok(())
    }

    fn timeout(&mut self, _: OperationId, _: &Timeout) -> liburing::Result<()> {
        Ok(())
    }

    fn cancel(&mut self, _: OperationId, _: OperationId) -> liburing::Result<()> {
        if self.full {
            Err(UringError::SqRingFull)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
fn must(result: liburing::Result<()>) {
    if let Err(error) = result {
        panic!("dns poll regression: {error}");
    }
}

#[cfg(test)]
#[test]
fn rearm_after_sq_full_drops_slot() {
    // SAFETY: socket(2) returns a new descriptor or -1 and reads only its arguments.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(raw >= 0, "regression socket");
    // SAFETY: `raw` is a newly created descriptor owned exclusively by this test.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = socket.as_raw_fd();
    let Some(subsystem) = SubsystemId::new(3) else {
        panic!("regression subsystem was rejected");
    };
    let mut polls = Polls::new(1);
    let mut ids = Identities::new(subsystem);
    let mut gate = CancelGate {
        polls: 0,
        full: false,
    };
    let readable = SocketInterest {
        readable: true,
        writable: false,
    };
    polls.interests.push((fd, 1, readable));
    must(polls.reconcile_ready(&mut gate, &mut ids));
    must(polls.arm(&mut gate, &mut ids));
    assert_eq!(gate.polls, 1);
    let Some(operation_id) = polls.states[0].active else {
        panic!("regression poll was not armed");
    };
    polls.interests.clear();
    gate.full = true;
    must(polls.reconcile_ready(&mut gate, &mut ids));
    assert!(polls.snapshot.iter().any(|item| item.0 == fd));
    let Ok(resolver) = Resolver::new(ResolverOptions::default()) else {
        panic!("regression resolver failed");
    };
    let completion = Completion {
        operation_id,
        result: 0,
        flags: 0,
    };
    assert!(polls.complete(completion, &resolver).is_none());
    assert!(polls.states.is_empty() && polls.snapshot.is_empty());
    polls.interests.push((fd, 1, readable));
    gate.full = false;
    must(polls.reconcile_ready(&mut gate, &mut ids));
    must(polls.arm(&mut gate, &mut ids));
    assert_eq!(gate.polls, 2);
}
