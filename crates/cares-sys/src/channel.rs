//! Channel lifecycle, configuration, event processing and auxiliary queries.

use libc::{c_char, c_int, c_uint, c_void};

use crate::*;

unsafe extern "C" {
    pub fn ares_library_init(flags: c_int) -> c_int;
    pub fn ares_library_init_mem(
        flags: c_int,
        amalloc: Option<unsafe extern "C" fn(size: usize) -> *mut c_void>,
        afree: Option<unsafe extern "C" fn(ptr: *mut c_void)>,
        arealloc: Option<unsafe extern "C" fn(ptr: *mut c_void, size: usize) -> *mut c_void>,
    ) -> c_int;
    pub fn ares_library_initialized() -> c_int;
    pub fn ares_library_cleanup();
    pub fn ares_threadsafety() -> ares_bool_t;
    pub fn ares_version(version: *mut c_int) -> *const c_char;
    pub fn ares_init(channelptr: *mut *mut ares_channel_t) -> c_int;
    pub fn ares_init_options(
        channelptr: *mut *mut ares_channel_t,
        options: *const ares_options,
        optmask: c_int,
    ) -> c_int;
    pub fn ares_save_options(
        channel: *const ares_channel_t,
        options: *mut ares_options,
        optmask: *mut c_int,
    ) -> c_int;
    pub fn ares_destroy_options(options: *mut ares_options);
    pub fn ares_destroy(channel: *mut ares_channel_t);
    pub fn ares_reinit(channel: *mut ares_channel_t) -> ares_status_t;
    pub fn ares_dup(dest: *mut *mut ares_channel_t, src: *const ares_channel_t) -> c_int;
    pub fn ares_cancel(channel: *mut ares_channel_t);
    pub fn ares_set_servers_csv(channel: *mut ares_channel_t, servers: *const c_char) -> c_int;
    pub fn ares_set_servers_ports_csv(
        channel: *mut ares_channel_t,
        servers: *const c_char,
    ) -> c_int;
    pub fn ares_get_servers_csv(channel: *const ares_channel_t) -> *mut c_char;
    pub fn ares_set_local_ip4(channel: *mut ares_channel_t, local_ip: c_uint);
    pub fn ares_set_local_ip6(channel: *mut ares_channel_t, local_ip6: *const u8);
    pub fn ares_set_local_dev(channel: *mut ares_channel_t, local_dev_name: *const c_char);
    pub fn ares_set_socket_callback(
        channel: *mut ares_channel_t,
        callback: ares_sock_create_callback,
        user_data: *mut c_void,
    );
    pub fn ares_set_socket_configure_callback(
        channel: *mut ares_channel_t,
        callback: ares_sock_config_callback,
        user_data: *mut c_void,
    );
    pub fn ares_set_socket_functions_ex(
        channel: *mut ares_channel_t,
        funcs: *const ares_socket_functions_ex,
        user_data: *mut c_void,
    ) -> ares_status_t;
    pub fn ares_set_server_state_callback(
        channel: *mut ares_channel_t,
        callback: ares_server_state_callback,
        user_data: *mut c_void,
    );
    pub fn ares_process_fds(
        channel: *mut ares_channel_t,
        events: *const ares_fd_events_t,
        nevents: usize,
        flags: c_uint,
    ) -> ares_status_t;
    pub fn ares_process_fd(
        channel: *mut ares_channel_t,
        read_fd: ares_socket_t,
        write_fd: ares_socket_t,
    );
    pub fn ares_timeout(
        channel: *const ares_channel_t,
        maxtv: *mut libc::timeval,
        tv: *mut libc::timeval,
    ) -> *mut libc::timeval;
    pub fn ares_fds(
        channel: *const ares_channel_t,
        read_fds: *mut libc::fd_set,
        write_fds: *mut libc::fd_set,
    ) -> c_int;
    pub fn ares_getsock(
        channel: *const ares_channel_t,
        socks: *mut ares_socket_t,
        numsocks: c_int,
    ) -> c_int;
    pub fn ares_strerror(code: c_int) -> *const c_char;
    pub fn ares_free_data(dataptr: *mut c_void);
    pub fn ares_free_string(str: *mut c_void);
    pub fn ares_free_hostent(host: *mut libc::hostent);
    pub fn ares_query_dnsrec(
        channel: *mut ares_channel_t,
        name: *const c_char,
        dnsclass: ares_dns_class_t,
        r#type: ares_dns_rec_type_t,
        callback: ares_callback_dnsrec,
        arg: *mut c_void,
        qid: *mut u16,
    ) -> ares_status_t;
    pub fn ares_send_dnsrec(
        channel: *mut ares_channel_t,
        dnsrec: *const ares_dns_record_t,
        callback: ares_callback_dnsrec,
        arg: *mut c_void,
        qid: *mut u16,
    ) -> ares_status_t;
    pub fn ares_search_dnsrec(
        channel: *mut ares_channel_t,
        dnsrec: *const ares_dns_record_t,
        callback: ares_callback_dnsrec,
        arg: *mut c_void,
    ) -> ares_status_t;
    pub fn ares_gethostbyname(
        channel: *mut ares_channel_t,
        name: *const c_char,
        family: c_int,
        callback: ares_host_callback,
        arg: *mut c_void,
    );
    pub fn ares_gethostbyaddr(
        channel: *mut ares_channel_t,
        addr: *const c_void,
        addrlen: c_int,
        family: c_int,
        callback: ares_host_callback,
        arg: *mut c_void,
    );
    pub fn ares_getnameinfo(
        channel: *mut ares_channel_t,
        sa: *const libc::sockaddr,
        salen: ares_socklen_t,
        flags: c_int,
        callback: ares_nameinfo_callback,
        arg: *mut c_void,
    );
    pub fn ares_inet_ntop(
        af: c_int,
        src: *const c_void,
        dst: *mut c_char,
        size: ares_socklen_t,
    ) -> *const c_char;
    pub fn ares_inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
}
