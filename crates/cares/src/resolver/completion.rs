//! Scalar handoff between the ring dispatcher and the resolver's native driver.
use uarch::prelude::*;

use super::ResolverCqe;

// The public enum retains its variant fields; this internal form has no padding.
#[register_pass]
#[derive(Clone, Copy)]
pub(crate) struct ResolverCqeWords {
    payload: u64,
    flags: u64,
}
impl ResolverCqeWords {
    #[hot_inline]
    pub(crate) const fn socket(fd: i32, readable: bool, writable: bool) -> Self {
        Self {
            payload: fd as u32 as u64,
            flags: (readable as u64) | ((writable as u64) << 1),
        }
    }
    #[hot_inline]
    pub(crate) const fn timer(generation: u64) -> Self {
        Self {
            payload: generation,
            flags: 4,
        }
    }
    #[hot_inline]
    pub(crate) const fn generation(self) -> Option<u64> {
        if self.flags & 4 != 0 {
            Some(self.payload)
        } else {
            None
        }
    }
    #[hot_inline]
    pub(crate) const fn readiness(self) -> (i32, bool, bool) {
        (
            self.payload as u32 as i32,
            self.flags & 1 != 0,
            self.flags & 2 != 0,
        )
    }
}
impl From<ResolverCqe> for ResolverCqeWords {
    #[hot_inline]
    fn from(value: ResolverCqe) -> Self {
        match value {
            ResolverCqe::Socket {
                fd,
                readable,
                writable,
            } => Self::socket(fd, readable, writable),
            ResolverCqe::Timer { generation } => Self::timer(generation),
        }
    }
}
assert_layout!(ResolverCqeWords, size = 16, align = 8, fields = { payload: 0, flags: 8 });

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_socket_variants_preserve_signed_descriptors_and_both_readiness_flags() {
        for fd in [i32::MIN, -1, 0, i32::MAX] {
            for (readable, writable) in [(false, false), (true, false), (false, true), (true, true)]
            {
                let words = ResolverCqeWords::from(ResolverCqe::Socket {
                    fd,
                    readable,
                    writable,
                });
                assert_eq!(words.generation(), None);
                assert_eq!(words.readiness(), (fd, readable, writable));
            }
        }
    }
    #[test]
    fn public_timer_variant_keeps_all_generation_bits() {
        for generation in [0, 1, 1 << 63, u64::MAX] {
            let words = ResolverCqeWords::from(ResolverCqe::Timer { generation });
            assert_eq!(words.generation(), Some(generation));
        }
    }
}
