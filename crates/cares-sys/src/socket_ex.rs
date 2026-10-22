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
    pub version: c_uint,
    pub flags: c_uint,
    pub asocket: Option<
        unsafe extern "C" fn(
            domain: c_int,
            r#type: c_int,
            protocol: c_int,
            user_data: *mut c_void,
        ) -> ares_socket_t,
    >,
    pub aclose: Option<unsafe extern "C" fn(sock: ares_socket_t, user_data: *mut c_void) -> c_int>,
    pub asetsockopt: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            opt: ares_socket_opt_t,
            val: *const c_void,
            val_size: ares_socklen_t,
            user_data: *mut c_void,
        ) -> c_int,
    >,
    pub aconnect: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            address: *const sockaddr,
            address_len: ares_socklen_t,
            flags: c_uint,
            user_data: *mut c_void,
        ) -> c_int,
    >,
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
    pub agetsockname: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            address: *mut sockaddr,
            address_len: *mut ares_socklen_t,
            user_data: *mut c_void,
        ) -> c_int,
    >,
    pub abind: Option<
        unsafe extern "C" fn(
            sock: ares_socket_t,
            flags: c_uint,
            address: *const sockaddr,
            address_len: libc::socklen_t,
            user_data: *mut c_void,
        ) -> c_int,
    >,
    pub aif_nametoindex:
        Option<unsafe extern "C" fn(ifname: *const c_char, user_data: *mut c_void) -> c_uint>,
    pub aif_indextoname: Option<
        unsafe extern "C" fn(
            ifindex: c_uint,
            ifname_buf: *mut c_char,
            ifname_buf_len: usize,
            user_data: *mut c_void,
        ) -> *const c_char,
    >,
}
