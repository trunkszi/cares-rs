//! Public C data layouts and callback types for Linux.

use core::marker::{PhantomData, PhantomPinned};

use libc::{c_char, c_int, c_uint, c_void};

use crate::{ares_bool_t, ares_evsys_t, ares_status_t};

pub type ares_socket_t = c_int;
pub type ares_socklen_t = libc::socklen_t;
pub type ares_ssize_t = libc::ssize_t;
pub type ares_channel = *mut ares_channel_t;

macro_rules! opaque {
    ($($name:ident),* $(,)?) => {$(
        #[repr(C)]
        pub struct $name {
            _private: [u8; 0],
            _marker: PhantomData<(*mut u8, PhantomPinned)>,
        }
    )*};
}

opaque!(
    ares_channeldata,
    ares_dns_record,
    ares_dns_rr,
    ares_dns_qd,
    apattern
);
pub type ares_channel_t = ares_channeldata;
pub type ares_dns_record_t = ares_dns_record;
pub type ares_dns_rr_t = ares_dns_rr;
pub type ares_dns_qd_t = ares_dns_qd;

pub type ares_sock_state_cb = Option<
    unsafe extern "C" fn(
        data: *mut c_void,
        socket_fd: ares_socket_t,
        readable: c_int,
        writable: c_int,
    ),
>;
pub type ares_callback = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        status: c_int,
        timeouts: c_int,
        abuf: *mut u8,
        alen: c_int,
    ),
>;
pub type ares_callback_dnsrec = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        status: ares_status_t,
        timeouts: usize,
        dnsrec: *const ares_dns_record_t,
    ),
>;
pub type ares_host_callback = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        status: c_int,
        timeouts: c_int,
        hostent: *mut libc::hostent,
    ),
>;
pub type ares_nameinfo_callback = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        status: c_int,
        timeouts: c_int,
        node: *mut c_char,
        service: *mut c_char,
    ),
>;
pub type ares_server_state_callback = Option<
    unsafe extern "C" fn(
        server_string: *const c_char,
        success: ares_bool_t,
        flags: c_int,
        data: *mut c_void,
    ),
>;
pub type ares_sock_create_callback = Option<
    unsafe extern "C" fn(socket_fd: ares_socket_t, r#type: c_int, data: *mut c_void) -> c_int,
>;
pub type ares_sock_config_callback = ares_sock_create_callback;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ares_server_failover_options {
    pub retry_chance: u16,
    pub retry_delay: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ares_options {
    pub flags: c_int,
    pub timeout: c_int,
    pub tries: c_int,
    pub ndots: c_int,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub socket_send_buffer_size: c_int,
    pub socket_receive_buffer_size: c_int,
    pub servers: *mut libc::in_addr,
    pub nservers: c_int,
    pub domains: *mut *mut c_char,
    pub ndomains: c_int,
    pub lookups: *mut c_char,
    pub sock_state_cb: ares_sock_state_cb,
    pub sock_state_cb_data: *mut c_void,
    pub sortlist: *mut apattern,
    pub nsort: c_int,
    pub ednspsz: c_int,
    pub resolvconf_path: *mut c_char,
    pub hosts_path: *mut c_char,
    pub udp_max_queries: c_int,
    pub maxtimeout: c_int,
    pub qcache_max_ttl: c_uint,
    pub evsys: ares_evsys_t,
    pub server_failover_opts: ares_server_failover_options,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ares_in6_addr__bindgen_ty_1 {
    pub _S6_u8: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ares_in6_addr {
    pub _S6_un: ares_in6_addr__bindgen_ty_1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ares_addr__bindgen_ty_1 {
    pub addr4: libc::in_addr,
    pub addr6: ares_in6_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ares_addr {
    pub family: c_int,
    pub addr: ares_addr__bindgen_ty_1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ares_fd_events_t {
    pub fd: ares_socket_t,
    pub events: c_uint,
}
