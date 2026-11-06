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
use uarch::prelude::*;

mod active;
use active::ActiveSlots;

use super::Submit;
#[cfg(test)]
use crate::options::ResolverOptions;
use crate::{Resolver, socket_bridge::SocketInterest};

/// Lifecycle of one socket readiness slot. Cancellation is tracked independently.
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

bitword! {
    struct PollSlotWord(u64) {
        [0] DESIRED_READ,
        [1] DESIRED_WRITE,
        [2] SUBMITTED_READ,
        [3] SUBMITTED_WRITE,
        [4] CANCELING,
        [8..=10] PHASE: u8,
    }
}

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

    #[inline]
    pub(super) fn complete(&mut self, id: OperationId) -> bool {
        let Some(index) = self.controls.iter().position(|&control| control == id) else {
            return false;
        };
        self.controls.swap_remove(index);
        true
    }

    #[hot_inline]
    pub(super) fn inflight_count(&self) -> usize {
        self.controls.len()
    }

    #[hot_inline]
    pub(super) fn has_pending(&self) -> bool {
        !self.controls.is_empty()
    }
}

struct PollState {
    fd: i32,
    generation: u64,
    socket: Rc<OwnedFd>,
    word: PollSlotWord,
    active: Option<OperationId>,
}

impl PollState {
    #[hot_inline]
    fn phase(&self) -> PollSlotPhase {
        match self.word.get(PollSlotWord::PHASE) {
            0 => PollSlotPhase::Synced,
            1 => PollSlotPhase::PendingAdd,
            2 => PollSlotPhase::PendingModify,
            _ => PollSlotPhase::PendingRemove,
        }
    }

    #[hot_inline]
    fn canceling(&self) -> bool {
        self.word.matches(pattern!(PollSlotWord { CANCELING }))
    }

    #[hot_inline]
    fn wanted(&self) -> bool {
        self.word.get(PollSlotWord::PHASE) < 3
    }

    #[hot_inline]
    fn set(&mut self, phase: PollSlotPhase, canceling: bool) {
        self.word = self.word.patch(
            uarch::bits::BitPatch::EMPTY
                .with_field(PollSlotWord::PHASE, (phase as u64) & 0x7)
                .with_flag(PollSlotWord::CANCELING, canceling),
        );
    }

    #[hot_inline]
    fn disarm(&mut self) {
        self.word = self.word.patch(patch!(PollSlotWord { PHASE: 3 }));
    }

    #[inline]
    fn apply_interest(&mut self, interest: SocketInterest) {
        self.word = self.word.patch(
            uarch::bits::BitPatch::EMPTY
                .with_flag(PollSlotWord::DESIRED_READ, interest.readable)
                .with_flag(PollSlotWord::DESIRED_WRITE, interest.writable),
        );
        if self.active.is_some() && (!self.interest_matches() || self.canceling()) {
            self.set(PollSlotPhase::PendingModify, self.canceling());
        } else if self.active.is_some() {
            self.set(PollSlotPhase::Synced, false);
        } else {
            self.set(PollSlotPhase::PendingAdd, false);
        }
    }

    #[hot_inline]
    fn desired(&self) -> SocketInterest {
        SocketInterest {
            readable: self.word.test(PollSlotWord::DESIRED_READ),
            writable: self.word.test(PollSlotWord::DESIRED_WRITE),
        }
    }

    #[hot_inline]
    fn submitted_interest(&self) -> SocketInterest {
        SocketInterest {
            readable: self.word.test(PollSlotWord::SUBMITTED_READ),
            writable: self.word.test(PollSlotWord::SUBMITTED_WRITE),
        }
    }

    #[hot_inline]
    fn interest_matches(&self) -> bool {
        self.desired() == self.submitted_interest()
    }

    #[hot_inline]
    fn submitted(&mut self) {
        let desired = self.desired();
        self.word = self.word.patch(
            uarch::bits::BitPatch::EMPTY
                .with_flag(PollSlotWord::SUBMITTED_READ, desired.readable)
                .with_flag(PollSlotWord::SUBMITTED_WRITE, desired.writable),
        );
    }

    #[hot_inline]
    fn mask(&self) -> u32 {
        (predicate(self.word.test(PollSlotWord::DESIRED_READ)) * libc::POLLIN as u32)
            | (predicate(self.word.test(PollSlotWord::DESIRED_WRITE)) * libc::POLLOUT as u32)
    }

    #[hot_inline]
    fn stable(&self) -> bool {
        self.word
            .matches(pattern!(PollSlotWord { !CANCELING & PHASE == 0 }))
            | self
                .word
                .matches(pattern!(PollSlotWord { !CANCELING & PHASE == 1 }))
    }
}

pub(super) struct Polls {
    active: ActiveSlots,
    states: Vec<PollState>,
    interests: Vec<(i32, u64, SocketInterest)>,
    snapshot: Vec<(i32, u64, SocketInterest)>,
    /// Slots that are wanted or still have an in-flight poll. Maintained without a rescan.
    pub(super) pending: usize,
}

impl Polls {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            active: ActiveSlots::new(capacity),
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
                    word: PollSlotWord::new(0)
                        .patch(patch!(PollSlotWord { PHASE: 1 }))
                        .patch(
                            uarch::bits::BitPatch::EMPTY
                                .with_flag(PollSlotWord::DESIRED_READ, interest.readable)
                                .with_flag(PollSlotWord::DESIRED_WRITE, interest.writable),
                        ),
                    active: None,
                });
            }
        }
        if self.cancel_changed(submit, ids)? {
            self.snapshot.clone_from(&self.interests);
        }
        Ok(())
    }

    #[cold_sink]
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

    #[inline]
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
        let mut next = self.active.next(0);
        while let Some(index) = next {
            next = self.active.next(index + 1);
            self.prefetch(next);
            let Some(state) = self.states.get_mut(index) else {
                return Err(UringError::InvalidConfig(
                    "poll bitmap index is out of bounds",
                ));
            };
            if let Some(id) = state.active
                && (!state.wanted() || !state.interest_matches())
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
            self.active
                .rebuild(self.states.iter().map(|state| state.active.is_some()));
        }
        self.recount();
        Ok(true)
    }

    #[hot_inline]
    pub(super) fn inflight_count(&self) -> usize {
        self.active.len()
    }

    #[inline]
    pub(super) fn arm(
        &mut self,
        submit: &mut impl Submit,
        ids: &mut Identities,
    ) -> liburing::Result<()> {
        for (index, state) in self.states.iter_mut().enumerate() {
            if !state.wanted() || state.active.is_some() {
                continue;
            }
            let mask = state.mask();
            let id = ids.next()?;
            match submit.poll(id, Rc::clone(&state.socket), mask) {
                Ok(()) => {
                    state.active = Some(id);
                    self.active.insert(index);
                    state.submitted();
                    state.set(PollSlotPhase::Synced, false);
                }
                Err(UringError::SqRingFull) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    #[hot_inline]
    fn prefetch(&self, next: Option<usize>) {
        if let Some(state) = next.and_then(|index| self.states.get(index)) {
            prefetch_read::<L1, _>(state as *const PollState);
        }
    }

    #[inline]
    pub(super) fn complete(
        &mut self,
        completion: Completion,
        resolver: &Resolver,
    ) -> Option<(i32, bool, bool)> {
        let index = self.active.indices().find(|&index| {
            self.prefetch(self.active.next(index + 1));
            self.states
                .get(index)
                .is_some_and(|state| state.active == Some(completion.operation_id))
        })?;
        self.active.remove(index);
        let state = self.states.get_mut(index)?;
        let fd = state.fd;
        let generation = state.generation;
        let retiring = state.phase() == PollSlotPhase::PendingRemove;
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
            self.active.swap_remove(index, self.states.len() - 1);
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

#[cfg(test)]
#[test]
fn packed_poll_state_preserves_interest_cancel_and_phase_fields() {
    use std::os::unix::net::UnixStream;
    let Ok((socket, _peer)) = UnixStream::pair() else {
        panic!("test socket pair");
    };
    let socket: OwnedFd = socket.into();
    let mut state = PollState {
        fd: socket.as_raw_fd(),
        generation: 1,
        socket: Rc::new(socket),
        word: PollSlotWord::new(0),
        active: None,
    };
    for (readable, writable) in [(false, false), (true, false), (false, true), (true, true)] {
        let interest = SocketInterest { readable, writable };
        state.apply_interest(interest);
        assert_eq!(state.desired(), interest);
        assert_eq!(
            state.mask(),
            if readable { libc::POLLIN as u32 } else { 0 }
                | if writable { libc::POLLOUT as u32 } else { 0 }
        );
        for phase in [
            PollSlotPhase::Synced,
            PollSlotPhase::PendingAdd,
            PollSlotPhase::PendingModify,
            PollSlotPhase::PendingRemove,
        ] {
            for canceling in [false, true] {
                state.set(phase, canceling);
                assert_eq!(state.phase(), phase);
                assert_eq!(state.canceling(), canceling);
                assert_eq!(state.desired(), interest);
                assert_eq!(
                    state.stable(),
                    !canceling
                        && matches!(phase, PollSlotPhase::Synced | PollSlotPhase::PendingAdd)
                );
                assert_eq!(
                    state.word.raw() & 0x13,
                    u64::from(readable) | (u64::from(writable) << 1) | (u64::from(canceling) << 4)
                );
            }
        }
        state.submitted();
        assert_eq!(state.desired(), state.submitted_interest());
        assert!(state.interest_matches());
    }
}

#[cfg(test)]
#[test]
fn packed_poll_modify_keeps_cancel_until_terminal_completion() {
    use std::os::unix::net::UnixStream;
    let Ok((socket, _peer)) = UnixStream::pair() else {
        panic!("test socket pair");
    };
    let socket: OwnedFd = socket.into();
    let mut state = PollState {
        fd: socket.as_raw_fd(),
        generation: 1,
        socket: Rc::new(socket),
        word: PollSlotWord::new(0),
        active: None,
    };
    state.apply_interest(SocketInterest {
        readable: true,
        writable: false,
    });
    state.submitted();
    state.active = Some(OperationId::pack(SubsystemId(3), OperationPayload(1)));
    state.apply_interest(SocketInterest {
        readable: false,
        writable: true,
    });
    assert_eq!(state.phase(), PollSlotPhase::PendingModify);
    state.set(state.phase(), true);
    state.apply_interest(SocketInterest {
        readable: true,
        writable: false,
    });
    assert!(state.canceling());
    assert_eq!(state.phase(), PollSlotPhase::PendingModify);
    state.disarm();
    assert!(state.canceling());
    assert_eq!(state.phase(), PollSlotPhase::PendingRemove);
}

#[cfg(test)]
#[test]
fn readiness_values_have_proven_compact_register_layouts() {
    fn no_padding<T: uarch::layout::NoPadding>() {}
    no_padding::<SocketInterest>();
    assert_eq!(std::mem::size_of::<SocketInterest>(), 2);
    assert_eq!(std::mem::align_of::<SocketInterest>(), 1);
    assert_eq!(
        std::mem::size_of::<crate::resolver::completion::ResolverCqeWords>(),
        16
    );
    no_padding::<crate::resolver::completion::ResolverCqeWords>();
}

assert_layout!(PollSlotWord, size = 8, align = 8);
const _: () = uarch::layout::assert_register_leaf::<PollSlotWord>();

#[cfg(test)]
#[test]
fn active_bitmap_tracks_dense_slot_movement_after_terminal_removal() {
    use std::os::unix::net::UnixStream;
    let mut sockets = Vec::new();
    let mut polls = Polls::new(1);
    for index in 0..70 {
        let Ok((socket, peer)) = UnixStream::pair() else {
            panic!("test socket pair");
        };
        polls.interests.push((
            socket.as_raw_fd(),
            index + 1,
            SocketInterest {
                readable: true,
                writable: false,
            },
        ));
        sockets.push((socket, peer));
    }
    let mut ids = Identities::new(SubsystemId(3));
    let mut gate = CancelGate {
        polls: 0,
        full: false,
    };
    must(polls.reconcile_ready(&mut gate, &mut ids));
    must(polls.arm(&mut gate, &mut ids));
    assert_eq!(polls.inflight_count(), 70);
    let keys: Vec<_> = polls
        .states
        .iter()
        .filter_map(|state| state.active)
        .collect();
    polls.interests.remove(0);
    must(polls.reconcile_ready(&mut gate, &mut ids));
    let Ok(resolver) = Resolver::new(ResolverOptions::default()) else {
        panic!("test resolver");
    };
    for index in [0, 69].into_iter().chain(1..69) {
        assert!(
            polls
                .complete(
                    Completion {
                        operation_id: keys[index],
                        result: -libc::ECANCELED,
                        flags: 0
                    },
                    &resolver
                )
                .is_none()
        );
    }
    assert_eq!(polls.inflight_count(), 0);
    assert_eq!(polls.states.len(), 69);
    must(polls.arm(&mut gate, &mut ids));
    assert_eq!(polls.inflight_count(), 69);
    assert_eq!(gate.polls, 139);
    assert_eq!(
        polls.active.indices().collect::<Vec<_>>(),
        (0..69).collect::<Vec<_>>()
    );
}

#[cfg(test)]
#[test]
fn every_raw_poll_phase_has_consistent_admission_and_total_decoding() -> std::io::Result<()> {
    let (socket, _peer) = std::os::unix::net::UnixStream::pair()?;
    let socket: OwnedFd = socket.into();
    let mut state = PollState {
        fd: socket.as_raw_fd(),
        generation: 1,
        socket: Rc::new(socket),
        word: PollSlotWord::new(0),
        active: None,
    };
    for raw in 0..2048 {
        state.word = PollSlotWord::new(raw);
        let phase = (raw >> 8) & 7;
        let canceling = raw & 16 != 0;
        assert_eq!(state.canceling(), canceling);
        assert_eq!(
            state.wanted(),
            state.phase() != PollSlotPhase::PendingRemove
        );
        assert_eq!(state.stable(), !canceling && phase < 2);
        assert_eq!(state.interest_matches(), (raw & 3) == ((raw >> 2) & 3));
        assert_eq!(
            state.mask(),
            (u32::from(raw & 1 != 0) * libc::POLLIN as u32)
                | (u32::from(raw & 2 != 0) * libc::POLLOUT as u32)
        );
    }
    Ok(())
}
