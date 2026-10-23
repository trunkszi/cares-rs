//! Process-wide library references with serialized first/last transitions.

use std::{
    marker::PhantomData,
    sync::atomic::{AtomicUsize, Ordering},
};

use cares_sys as sys;

use crate::{AresError, Result};

const TRANSITION: usize = usize::MAX;
static LIBRARY_USERS: AtomicUsize = AtomicUsize::new(0);

/// Keeps the threadless c-ares library initialized while held.
///
/// The first guard initializes the library; the last guard cleans it up. Atomic
/// transitions serialize those calls across threads. Waiting is limited to
/// acquisition and final cleanup; resolver socket progress never enters it.
/// Each guard remains confined to its acquiring thread (`!Send + !Sync`).
pub struct LibraryGuard {
    _not_send: PhantomData<*mut ()>,
}

impl LibraryGuard {
    /// Acquires a process-wide reference to the c-ares library.
    ///
    /// # Errors
    /// Returns the initialization status, [`AresError::ThreadSafetyEnabled`], or
    /// an error if the reference count cannot grow. Failure leaves no reference.
    pub fn acquire() -> Result<Self> {
        loop {
            let users = LIBRARY_USERS.load(Ordering::Acquire);
            if users == TRANSITION {
                std::thread::yield_now();
                continue;
            }
            if users == TRANSITION - 1 {
                return Err(AresError::invalid_input(
                    "library reference count exhausted",
                ));
            }
            let next = if users == 0 { TRANSITION } else { users + 1 };
            if LIBRARY_USERS
                .compare_exchange_weak(users, next, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            if users == 0 {
                // SAFETY: the transition sentinel excludes all other first/last
                // transitions, and zero references means no live guarded channel.
                let status = unsafe { sys::ares_library_init(sys::ARES_LIB_INIT_ALL) };
                if status != 0 {
                    LIBRARY_USERS.store(0, Ordering::Release);
                    return Err(AresError::from_status(status));
                }
                // SAFETY: initialization succeeded; this query takes no pointers.
                if unsafe { sys::ares_threadsafety() } != sys::ares_bool_t::ARES_FALSE {
                    // SAFETY: balances this transition's initialization, with no
                    // other guard able to acquire while the sentinel is present.
                    unsafe { sys::ares_library_cleanup() };
                    LIBRARY_USERS.store(0, Ordering::Release);
                    return Err(AresError::ThreadSafetyEnabled);
                }
                LIBRARY_USERS.store(1, Ordering::Release);
            }
            return Ok(Self {
                _not_send: PhantomData,
            });
        }
    }
}

impl Drop for LibraryGuard {
    fn drop(&mut self) {
        loop {
            let users = LIBRARY_USERS.load(Ordering::Acquire);
            let next = if users == 1 { TRANSITION } else { users - 1 };
            if LIBRARY_USERS
                .compare_exchange_weak(users, next, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            if users == 1 {
                // SAFETY: this was the final guard. The sentinel prevents a new
                // initialization until cleanup completes; guarded channels have
                // already been destroyed before releasing their guards.
                unsafe { sys::ares_library_cleanup() };
                LIBRARY_USERS.store(0, Ordering::Release);
            }
            return;
        }
    }
}
