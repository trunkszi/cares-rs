//! Raw FFI for the threadless, statically linked c-ares DNS library.
//!
//! The default `pre-release` feature builds upstream `main`; `stable` selects
//! v1.34.9. `CARES_DIR` overrides the source checkout. Both builds disable the
//! internal c-ares threads and event thread support.
//!
//! All functions are unsafe: callers uphold the upstream C contracts, including
//! pointer validity, ownership and callback lifetimes. DNS callback records are
//! borrowed only for the callback duration and must be duplicated to retain them.
//! Integer wrappers preserve the full C enum domain, including unnamed DNS wire
//! values. Named values are available both at the crate root and on their type.

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

mod channel;
mod consts;
mod dns_rec;
mod enums;
mod socket_ex;
mod types;

pub use channel::*;
pub use consts::*;
pub use dns_rec::*;
pub use enums::*;
pub use socket_ex::*;
pub use types::*;
