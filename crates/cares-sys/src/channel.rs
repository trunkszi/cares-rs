//! Channel lifecycle, configuration, event processing and auxiliary queries.

use libc::{c_char, c_int, c_uint, c_void};

use crate::*;

unsafe extern "C" {
    /// # Safety
    /// Serialize library initialization and cleanup on the calling thread. Call cleanup only after
    /// every channel and library-owned object is released.
    pub fn ares_library_init(flags: c_int) -> c_int;
    /// # Safety
    /// Serialize global initialization. Allocator callbacks must implement malloc/free/realloc
    /// semantics, remain callable until cleanup, and never unwind into C.
    pub fn ares_library_init_mem(
        flags: c_int,
        amalloc: Option<unsafe extern "C" fn(size: usize) -> *mut c_void>,
        afree: Option<unsafe extern "C" fn(ptr: *mut c_void)>,
        arealloc: Option<unsafe extern "C" fn(ptr: *mut c_void, size: usize) -> *mut c_void>,
    ) -> c_int;
    /// # Safety
    /// Do not race this global-state query with initialization or cleanup.
    pub fn ares_library_initialized() -> c_int;
    /// # Safety
    /// Balance successful initialization calls. Destroy all channels and release library-owned
    /// objects first; do not race other library operations.
    pub fn ares_library_cleanup();
    /// # Safety
    /// This capability query has no pointer or initialization prerequisites; the selected static
    /// build always disables thread support.
    pub fn ares_threadsafety() -> ares_bool_t;
    /// # Safety
    /// If non-null, version must point to writable int storage. The returned string is static and
    /// must not be freed.
    pub fn ares_version(version: *mut c_int) -> *const c_char;
    /// # Safety
    /// Initialize the library first. channelptr must be writable; on success the returned channel
    /// must be destroyed once, on its creating thread.
    pub fn ares_init(channelptr: *mut *mut ares_channel_t) -> c_int;
    /// # Safety
    /// Initialize the library first. channelptr must be writable, and options plus fields selected
    /// by optmask must be readable with valid lengths. Retained callback data must outlive the
    /// channel.
    pub fn ares_init_options(
        channelptr: *mut *mut ares_channel_t,
        options: *const ares_options,
        optmask: c_int,
    ) -> c_int;
    /// # Safety
    /// channel must be live. options and optmask must be writable; release saved option
    /// allocations with ares_destroy_options, not a general allocator.
    pub fn ares_save_options(
        channel: *const ares_channel_t,
        options: *mut ares_options,
        optmask: *mut c_int,
    ) -> c_int;
    /// # Safety
    /// options must be writable and own the allocations returned by ares_save_options. Do not free
    /// copied pointers twice.
    pub fn ares_destroy_options(options: *mut ares_options);
    /// # Safety
    /// channel must be a live exclusively owned channel. Destruction may synchronously invoke
    /// callbacks, so their data must remain valid until this returns. Never destroy from its
    /// callback.
    pub fn ares_destroy(channel: *mut ares_channel_t);
    /// # Safety
    /// channel must be live on its owning thread. Do not call recursively from a callback or while
    /// another operation holds invalidatable channel borrows.
    pub fn ares_reinit(channel: *mut ares_channel_t) -> ares_status_t;
    /// # Safety
    /// dest must be writable and src a live channel. On success destroy the new channel once; any
    /// shared callback data must remain valid for both channels.
    pub fn ares_dup(dest: *mut *mut ares_channel_t, src: *const ares_channel_t) -> c_int;
    /// # Safety
    /// channel must be live on its owning thread. All pending query callbacks may run
    /// synchronously; their user data must remain valid and callbacks must not unwind.
    pub fn ares_cancel(channel: *mut ares_channel_t);
    /// # Safety
    /// channel must be live and servers a readable NUL-terminated server list. Call on the channel
    /// thread without overlapping mutation.
    pub fn ares_set_servers_csv(channel: *mut ares_channel_t, servers: *const c_char) -> c_int;
    /// # Safety
    /// channel must be live and servers a readable NUL-terminated server list. Call on the channel
    /// thread without overlapping mutation.
    pub fn ares_set_servers_ports_csv(
        channel: *mut ares_channel_t,
        servers: *const c_char,
    ) -> c_int;
    /// # Safety
    /// channel must be live. A non-null result is newly allocated and must be released once with
    /// ares_free_string.
    pub fn ares_get_servers_csv(channel: *const ares_channel_t) -> *mut c_char;
    /// # Safety
    /// channel must be live on its owning thread; local_ip is the IPv4 address in host byte order.
    pub fn ares_set_local_ip4(channel: *mut ares_channel_t, local_ip: c_uint);
    /// # Safety
    /// channel must be live on its owning thread and local_ip6 must point to at least 16 readable
    /// address bytes.
    pub fn ares_set_local_ip6(channel: *mut ares_channel_t, local_ip6: *const u8);
    /// # Safety
    /// channel must be live on its owning thread and local_dev_name must point to a readable NUL-
    /// terminated device name.
    pub fn ares_set_local_dev(channel: *mut ares_channel_t, local_dev_name: *const c_char);
    /// # Safety
    /// channel must be live. Any callback and user_data must remain valid while registered, obey
    /// the C socket contract, and never unwind.
    pub fn ares_set_socket_callback(
        channel: *mut ares_channel_t,
        callback: ares_sock_create_callback,
        user_data: *mut c_void,
    );
    /// # Safety
    /// channel must be live. Any callback and user_data must remain valid while registered, obey
    /// the C socket contract, and never unwind.
    pub fn ares_set_socket_configure_callback(
        channel: *mut ares_channel_t,
        callback: ares_sock_config_callback,
        user_data: *mut c_void,
    );
    /// # Safety
    /// channel must be live and funcs must point to a readable ABI-version-1 table with all
    /// required callbacks. The table is copied; callback code and user_data must outlive
    /// registration, and callbacks must never unwind.
    pub fn ares_set_socket_functions_ex(
        channel: *mut ares_channel_t,
        funcs: *const ares_socket_functions_ex,
        user_data: *mut c_void,
    ) -> ares_status_t;
    /// # Safety
    /// channel must be live. Callback code and user_data must remain valid while registered;
    /// server_string is borrowed for each callback only and callbacks must never unwind.
    pub fn ares_set_server_state_callback(
        channel: *mut ares_channel_t,
        callback: ares_server_state_callback,
        user_data: *mut c_void,
    );
    /// # Safety
    /// channel must be live on its owning thread. events must describe nevents readable
    /// initialized entries, or be null when nevents is zero. Callbacks may run synchronously;
    /// never drive recursively from a callback.
    pub fn ares_process_fds(
        channel: *mut ares_channel_t,
        events: *const ares_fd_events_t,
        nevents: usize,
        flags: c_uint,
    ) -> ares_status_t;
    /// # Safety
    /// channel must be live on its owning thread. Descriptors must belong to that channel or be
    /// ARES_SOCKET_BAD; callbacks may run synchronously. Never drive recursively from a callback.
    pub fn ares_process_fd(
        channel: *mut ares_channel_t,
        read_fd: ares_socket_t,
        write_fd: ares_socket_t,
    );
    /// # Safety
    /// channel must be live; tv must be writable and non-null. If maxtv is non-null it must be
    /// readable. The result aliases an input buffer, not a new allocation.
    pub fn ares_timeout(
        channel: *const ares_channel_t,
        maxtv: *mut libc::timeval,
        tv: *mut libc::timeval,
    ) -> *mut libc::timeval;
    /// # Safety
    /// channel must be live. read_fds and write_fds must be writable initialized fd_sets large
    /// enough for every channel descriptor; exclude descriptors at or above FD_SETSIZE.
    pub fn ares_fds(
        channel: *const ares_channel_t,
        read_fds: *mut libc::fd_set,
        write_fds: *mut libc::fd_set,
    ) -> c_int;
    /// # Safety
    /// channel must be live and socks must hold numsocks writable descriptors. Respect
    /// ARES_GETSOCK_MAXNUM when interpreting the returned readiness mask.
    pub fn ares_getsock(
        channel: *const ares_channel_t,
        socks: *mut ares_socket_t,
        numsocks: c_int,
    ) -> c_int;
    /// # Safety
    /// The returned error text is static storage and must not be modified or freed.
    pub fn ares_strerror(code: c_int) -> *const c_char;
    /// # Safety
    /// dataptr must be null or an owned allocation from a compatible c-ares data-returning API. Do
    /// not pass borrowed record pointers, strings, or already-freed data.
    pub fn ares_free_data(dataptr: *mut c_void);
    /// # Safety
    /// str must be null or an owned c-ares string/wire allocation whose API specifies this
    /// deallocator. Free each allocation once.
    pub fn ares_free_string(str: *mut c_void);
    /// # Safety
    /// host must be null or an owned hostent allocated by c-ares. Never free a hostent borrowed by
    /// a completion callback.
    pub fn ares_free_hostent(host: *mut libc::hostent);
    /// # Safety
    /// channel and name must be valid, with name NUL-terminated. callback and arg must remain
    /// valid until completion, possibly during this call. qid may be null or writable. The
    /// callback must not unwind; its DNS record is borrowed only until callback return.
    pub fn ares_query_dnsrec(
        channel: *mut ares_channel_t,
        name: *const c_char,
        dnsclass: ares_dns_class_t,
        r#type: ares_dns_rec_type_t,
        callback: ares_callback_dnsrec,
        arg: *mut c_void,
        qid: *mut u16,
    ) -> ares_status_t;
    /// # Safety
    /// channel and dnsrec must be live during submission. callback and arg must remain valid until
    /// completion, which may be synchronous; qid may be null or writable. Never unwind from the
    /// callback or retain its record without duplication.
    pub fn ares_send_dnsrec(
        channel: *mut ares_channel_t,
        dnsrec: *const ares_dns_record_t,
        callback: ares_callback_dnsrec,
        arg: *mut c_void,
        qid: *mut u16,
    ) -> ares_status_t;
    /// # Safety
    /// channel and dnsrec must be live during submission. callback and arg must remain valid until
    /// completion, which may be synchronous. Never unwind from the callback or retain its record
    /// without duplication.
    pub fn ares_search_dnsrec(
        channel: *mut ares_channel_t,
        dnsrec: *const ares_dns_record_t,
        callback: ares_callback_dnsrec,
        arg: *mut c_void,
    ) -> ares_status_t;
    /// # Safety
    /// channel must be live and name NUL-terminated. callback and arg must survive possibly
    /// synchronous completion; hostent is borrowed only within the callback, which must not
    /// unwind.
    pub fn ares_gethostbyname(
        channel: *mut ares_channel_t,
        name: *const c_char,
        family: c_int,
        callback: ares_host_callback,
        arg: *mut c_void,
    );
    /// # Safety
    /// channel must be live; addr must hold addrlen readable bytes matching family. callback and
    /// arg must survive completion; callback hostent is borrowed and the callback must not unwind.
    pub fn ares_gethostbyaddr(
        channel: *mut ares_channel_t,
        addr: *const c_void,
        addrlen: c_int,
        family: c_int,
        callback: ares_host_callback,
        arg: *mut c_void,
    );
    /// # Safety
    /// channel must be live and sa must hold salen initialized address bytes. callback and arg
    /// must survive completion; node and service are callback-scoped borrowed strings, and the
    /// callback must not unwind.
    pub fn ares_getnameinfo(
        channel: *mut ares_channel_t,
        sa: *const libc::sockaddr,
        salen: ares_socklen_t,
        flags: c_int,
        callback: ares_nameinfo_callback,
        arg: *mut c_void,
    );
    /// # Safety
    /// src must hold an initialized address for af. dst must be writable for size bytes; any
    /// returned pointer aliases dst and is valid only while its buffer lives.
    pub fn ares_inet_ntop(
        af: c_int,
        src: *const c_void,
        dst: *mut c_char,
        size: ares_socklen_t,
    ) -> *const c_char;
    /// # Safety
    /// src must be a readable NUL-terminated address and dst writable for the address size
    /// selected by af.
    pub fn ares_inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
}
