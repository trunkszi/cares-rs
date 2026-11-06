//! Fault snapshots retained until the last mock server worker exits.

use std::{
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, Ordering},
};

use super::Behavior;

struct Snapshot {
    behavior: Behavior,
    drops: AtomicU32,
    previous: *mut Snapshot,
}

pub(super) struct FaultState {
    current: AtomicPtr<Snapshot>,
}

impl Default for FaultState {
    fn default() -> Self {
        let state = Self {
            current: AtomicPtr::new(ptr::null_mut()),
        };
        state.set(Behavior::Normal);
        state
    }
}

impl FaultState {
    fn snapshot(&self) -> &Snapshot {
        let pointer = self.current.load(Ordering::Acquire);
        // SAFETY: construction publishes a snapshot before sharing this object.
        // Updates retain every old snapshot until exclusive destruction, so a
        // shared borrow keeps the loaded pointer alive even across updates.
        unsafe { &*pointer }
    }

    pub(super) fn get(&self) -> Behavior {
        self.snapshot().behavior
    }

    pub(super) fn consume_udp_drop(&self) -> bool {
        let snapshot = self.snapshot();
        snapshot
            .drops
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
    }

    pub(super) fn set(&self, behavior: Behavior) {
        let drops = match behavior {
            Behavior::DropUdp(n) => n,
            _ => 0,
        };
        let pointer = Box::into_raw(Box::new(Snapshot {
            behavior,
            drops: AtomicU32::new(drops),
            previous: ptr::null_mut(),
        }));
        let mut previous = self.current.load(Ordering::Acquire);
        loop {
            // SAFETY: this unpublished node belongs exclusively to this call;
            // no worker can read it before the successful release publication.
            unsafe { (*pointer).previous = previous };
            match self.current.compare_exchange_weak(
                previous,
                pointer,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => previous = current,
            }
        }
    }
}

impl Drop for FaultState {
    fn drop(&mut self) {
        let mut pointer = *self.current.get_mut();
        while !pointer.is_null() {
            // SAFETY: exclusive destruction means all shared worker references
            // have ended. Each published allocation occurs exactly once in this
            // predecessor chain, which updates never unlink or reclaim.
            let snapshot = unsafe { Box::from_raw(pointer) };
            pointer = snapshot.previous;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread, time::Duration};

    use super::{Behavior, FaultState};

    #[test]
    fn unit_scenario_fault_updates_preserve_delay_and_exact_loss_budget() {
        let state = Arc::new(FaultState::default());
        let delay = Duration::new(u64::MAX, 123);
        state.set(Behavior::Delay(delay));
        assert!(matches!(state.get(), Behavior::Delay(value) if value == delay));
        state.set(Behavior::DropUdp(64));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let state = Arc::clone(&state);
                thread::spawn(move || (0..64).filter(|_| state.consume_udp_drop()).count())
            })
            .collect();
        let consumed: usize = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .sum();
        assert_eq!(consumed, 64);
        assert!(!state.consume_udp_drop());
        state.set(Behavior::Normal);
        assert!(matches!(state.get(), Behavior::Normal));
    }
}
