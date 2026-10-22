//! Query-deadline tracking for the io_uring bridge.
//!
//! c-ares reports its earliest pending query timeout through
//! [`cares_sys::ares_timeout`] as a *relative* `timeval`. This module converts
//! that value into an absolute [`Instant`] and tags it with a generation.
//!
//! # Division of responsibility
//!
//! This module never touches the ring: it submits neither `IORING_OP_TIMEOUT`
//! nor `IORING_OP_TIMEOUT_REMOVE`. The resolver/proactor owner holds the single
//! timeout SQE and uses [`TimerDeadline::generation`] as the identity of the
//! deadline it armed. A new generation means "cancel the armed SQE and arm a
//! new one"; an unchanged generation means "leave the armed SQE alone". That is
//! why reading the same c-ares deadline again must not bump the generation.
//!
//! When the timeout SQE completes, the owner calls
//! `ares_process_fds(channel, NULL, 0, ARES_PROCESS_FLAG_NONE)` so c-ares can
//! run its timeout handling, and then [`TimerState::refresh`] to obtain the
//! next deadline.

use std::{
    cell::Cell,
    ptr,
    time::{Duration, Instant},
};

use cares_sys::ares_channel_t;

/// Absolute deadlines closer than this are treated as the same deadline.
///
/// Each [`TimerState::refresh`] re-derives the deadline from `Instant::now()`
/// plus the relative value c-ares just computed, so microseconds of drift
/// between processing batches are expected. Bumping the generation for that
/// drift would invalidate the in-flight timeout SQE on every batch.
pub const DEADLINE_TOLERANCE: Duration = Duration::from_millis(1);

/// An absolute query deadline and the generation that identifies it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerDeadline {
    /// Instant at which c-ares wants its timers processed.
    pub at: Instant,
    /// Identity of this armed deadline. It changes when the deadline is newly
    /// armed, moves by more than [`DEADLINE_TOLERANCE`], or is disarmed.
    pub generation: u64,
}

/// The latest c-ares deadline, its generation, and a one-shot expiry flag.
///
/// Every field lives behind a [`Cell`], so all methods take `&self`. The state
/// is intended to be driven from the thread that owns the channel.
pub struct TimerState {
    deadline: Cell<Option<TimerDeadline>>,
    generation: Cell<u64>,
    expired: Cell<bool>,
}

impl TimerState {
    /// Creates an unarmed timer at generation zero.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deadline: Cell::new(None),
            generation: Cell::new(0),
            expired: Cell::new(false),
        }
    }

    /// Reads the earliest pending c-ares timeout and folds it into this state.
    ///
    /// `channel` must be null or point to a live channel for the duration of
    /// the call. A null channel reports no pending timeout. A `{0, 0}`
    /// relative `timeval` from c-ares is a valid immediate deadline, not an
    /// absence of one.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn refresh(&self, channel: *mut ares_channel_t) -> Option<TimerDeadline> {
        if channel.is_null() {
            return self.refresh_from_deadline(None);
        }

        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: `channel` was checked for null and, by this method's pointer
        // contract, names a live `ares_channel_t` for the duration of the call.
        // `maxtv` is null, which asks for no upper bound, and `tv` points to a
        // writable local. c-ares copies out of both and retains neither
        // pointer after returning.
        let timeout =
            unsafe { cares_sys::ares_timeout(channel.cast_const(), ptr::null_mut(), &mut tv) };

        if timeout.is_null() {
            self.refresh_from_deadline(None)
        } else {
            self.refresh_from_deadline(Some(relative_to_instant(&tv)))
        }
    }

    /// Accepts a timeout completion for the currently armed deadline.
    ///
    /// Returns `true` and records the expiry only when `generation` matches the
    /// current deadline. Accepting it consumes the armed deadline, so duplicate
    /// completions and completions from cancelled or superseded SQEs are ignored.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn on_timer(&self, generation: u64) -> bool {
        match self.deadline.get() {
            Some(deadline) if deadline.generation == generation => {
                self.deadline.set(None);
                self.expired.set(true);
                true
            }
            _ => false,
        }
    }

    /// Returns and clears the recorded expiry flag.
    ///
    /// The flag is one-shot: each accepted [`TimerState::on_timer`] call makes
    /// this method return `true` at most once. Refreshing preserves a recorded
    /// expiry until it is taken here or cleared by [`TimerState::disarm`].
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn take_expired(&self) -> bool {
        self.expired.replace(false)
    }

    /// Clears the deadline, invalidates its generation, and clears expiry.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn disarm(&self) {
        self.deadline.set(None);
        self.bump_generation();
        self.expired.set(false);
    }

    /// Returns the currently armed deadline, if any.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn deadline(&self) -> Option<TimerDeadline> {
        self.deadline.get()
    }

    /// Folds an already-computed absolute deadline into this state.
    ///
    /// This is the deterministic seam used by tests; production code enters
    /// through [`TimerState::refresh`]. When the new deadline lies within
    /// [`DEADLINE_TOLERANCE`] of the armed one, the armed deadline is returned
    /// unchanged: retaining its exact instant guarantees that the returned
    /// value is still the deadline the proactor armed.
    /// A consumed deadline is unarmed and therefore always receives a fresh
    /// generation.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn refresh_from_deadline(&self, deadline: Option<Instant>) -> Option<TimerDeadline> {
        let current = self.deadline.get();
        let next = match (current, deadline) {
            (None, None) => None,
            (None, Some(at)) => Some(self.arm(at)),
            (Some(_), None) => {
                self.bump_generation();
                None
            }
            (Some(armed), Some(at)) => {
                if exceeds_tolerance(armed.at, at) {
                    Some(self.arm(at))
                } else {
                    Some(armed)
                }
            }
        };
        self.deadline.set(next);
        next
    }

    /// Advances and returns the generation counter.
    fn bump_generation(&self) -> u64 {
        // Wrapping rather than checked addition: exhausting a u64 counter is
        // not reachable in practice, and a rollover must not abort the process.
        let generation = self.generation.get().wrapping_add(1);
        self.generation.set(generation);
        generation
    }

    /// Records `at` as the armed deadline under a fresh generation.
    fn arm(&self, at: Instant) -> TimerDeadline {
        TimerDeadline {
            at,
            generation: self.bump_generation(),
        }
    }
}

impl Default for TimerState {
    /// Creates an unarmed timer, identical to [`TimerState::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Reports whether two absolute deadlines differ by more than the tolerance.
fn exceeds_tolerance(armed: Instant, candidate: Instant) -> bool {
    let delta = if candidate >= armed {
        candidate.duration_since(armed)
    } else {
        armed.duration_since(candidate)
    };
    delta > DEADLINE_TOLERANCE
}

/// Converts the relative `timeval` from `ares_timeout` into an absolute instant.
///
/// A negative component means the deadline is already in the past; c-ares
/// clamps such remainders to zero, and `try_from` maps them to 0 here as well.
/// `checked_add` guards an overflowing `timeval` and falls back to an immediate
/// deadline, which c-ares processes on the next poll round.
fn relative_to_instant(tv: &libc::timeval) -> Instant {
    let seconds = u64::try_from(tv.tv_sec).unwrap_or_default();
    let microseconds = u64::try_from(tv.tv_usec).unwrap_or_default();
    let relative = Duration::from_secs(seconds).saturating_add(Duration::from_micros(microseconds));
    Instant::now()
        .checked_add(relative)
        .unwrap_or_else(Instant::now)
}
