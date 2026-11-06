//! Extended socket callback table, ABI version 1.
//!
//! The callbacks and `user_data` must remain valid while registered on a live
//! channel. Upstream copies this table during registration. All sockets returned
//! by `asocket` must be nonblocking; the callback receives no creation flags.

use libc::{c_char, c_int, c_uint, c_void, sockaddr};

use crate::{ares_socket_opt_t, ares_socket_t, ares_socklen_t, ares_ssize_t};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ares_socket_functions_ex {
    /// Set to 1 before registering this table.
    pub version: c_uint,
    /// A mask of `ares_sockfunc_flags_t` values.
    pub flags: c_uint,
    /// # Safety
    /// Create a real nonblocking socket; preserve user data and never unwind.
    /// Return ARES_SOCKET_BAD and set errno on failure.
    pub asocket: Option<
        unsafe extern "C" fn(
            domain: c_int,
            r#type: c_int,
            protocol: c_int,
            user_data: *mut c_void,
        ) -> ares_socket_t,
    >,
    /// # Safety
    /// Close the supplied owned socket once, preserve user data, and never unwind.
    pub aclose: Option<unsafe extern "C" fn(sock: ares_socket_t, user_data: *mut c_void) -> c_int>,
    /// # Safety
    /// Read val only for val_size bytes according to opt; preserve user data and
    /// report unsupported options/errors with the documented errno convention.
    pub asetsockopt: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            opt: ares_socket_opt_t,
            val: *const c_void,
            val_size: ares_socklen_t,
            user_data: *mut c_void,
        ) -> c_int,
    >,
    /// # Safety
    /// Read only address_len initialized address bytes; preserve user data,
    /// obey nonblocking/errno semantics, and never unwind.
    pub aconnect: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            address: *const sockaddr,
            address_len: ares_socklen_t,
            flags: c_uint,
            user_data: *mut c_void,
        ) -> c_int,
    >,
    /// # Safety
    /// Write at most length bytes; respect optional address buffer capacities
    /// and populate the actual UDP peer. Return a byte count or -1 with errno.
    pub arecvfrom: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            buffer: *mut c_void,
            length: usize,
            flags: c_int,
            address: *mut sockaddr,
            address_len: *mut ares_socklen_t,
            user_data: *mut c_void,
        ) -> ares_ssize_t,
    >,
    /// # Safety
    /// Read at most length bytes and the optional address_len address bytes.
    /// Copy queued data before returning; return accepted bytes or -1 and never
    /// unwind. The input buffers are borrowed for this callback only.
    pub asendto: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            buffer: *const c_void,
            length: usize,
            flags: c_int,
            address: *const sockaddr,
            address_len: ares_socklen_t,
            user_data: *mut c_void,
        ) -> ares_ssize_t,
    >,
    /// # Safety
    /// Respect the input address capacity and write its actual length; preserve
    /// user data, report errors via errno, and never unwind.
    pub agetsockname: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            address: *mut sockaddr,
            address_len: *mut ares_socklen_t,
            user_data: *mut c_void,
        ) -> c_int,
    >,
    /// # Safety
    /// Read only address_len initialized address bytes; preserve user data,
    /// honor flags, and never unwind through the callback.
    pub abind: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            flags: c_uint,
            address: *const sockaddr,
            address_len: libc::socklen_t,
            user_data: *mut c_void,
        ) -> c_int,
    >,
    /// # Safety
    /// Read the NUL-terminated interface name only during the call; preserve
    /// user data and return zero on failure without unwinding.
    pub aif_nametoindex:
        Option<unsafe extern "C" fn(ifname: *const c_char, user_data: *mut c_void) -> c_uint>,
    /// # Safety
    /// Write at most ifname_buf_len bytes including the terminator; return the
    /// supplied buffer or null. Preserve user data and never unwind.
    pub aif_indextoname: Option<
        unsafe extern "C" fn(
            ifindex: c_uint,
            ifname_buf: *mut c_char,
            ifname_buf_len: usize,
            user_data: *mut c_void,
        ) -> *const c_char,
    >,
}

use uarch::prelude::*;
assert_layout!(ares_socket_functions_ex, size = 88, align = 8, fields = { version: 0, flags: 4, asocket: 8, aclose: 16, asetsockopt: 24, aconnect: 32, arecvfrom: 40, asendto: 48, agetsockname: 56, abind: 64, aif_nametoindex: 72, aif_indextoname: 80 });
// SAFETY: The two u32 headers occupy eight bytes followed by ten adjacent nullable
// function pointers. The locked offsets and size prove no internal or tail padding.
unsafe impl NoPadding for ares_socket_functions_ex {}
