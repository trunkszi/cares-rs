//! Owned resolver configuration and a borrowing view of its C representation.

use std::{
    ffi::CString, fmt, net::Ipv4Addr, os::unix::ffi::OsStrExt, path::Path, ptr, time::Duration,
};

use bitflags::bitflags;

use crate::error::{AresError, Result};

bitflags! {
    /// Channel behavior flags, distinct from DNS message header flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ResolverFlags: libc::c_int {
        /// Send DNS queries over TCP.
        const USE_TCP = cares_sys::ARES_FLAG_USEVC;
        /// Use only the primary server.
        const PRIMARY = cares_sys::ARES_FLAG_PRIMARY;
        /// Ignore truncation instead of retrying over TCP.
        const IGNORE_TRUNCATION = cares_sys::ARES_FLAG_IGNTC;
        /// Omit recursion-desired from outgoing queries.
        const NO_RECURSE = cares_sys::ARES_FLAG_NORECURSE;
        /// Keep sockets open between requests.
        const STAY_OPEN = cares_sys::ARES_FLAG_STAYOPEN;
        /// Disable search-domain expansion.
        const NO_SEARCH = cares_sys::ARES_FLAG_NOSEARCH;
        /// Ignore the HOSTALIASES environment variable.
        const NO_ALIASES = cares_sys::ARES_FLAG_NOALIASES;
        /// Disable response-code validation by the query layer.
        const NO_CHECK_RESPONSE = cares_sys::ARES_FLAG_NOCHECKRESP;
        /// Advertise EDNS support.
        const EDNS = cares_sys::ARES_FLAG_EDNS;
        /// Fail initialization if no DNS servers are configured.
        const NO_DEFAULT_SERVER = cares_sys::ARES_FLAG_NO_DFLT_SVR;
        /// Randomize query-name case to improve response authentication.
        const DNS0X20 = cares_sys::ARES_FLAG_DNS0x20;
    }
}

/// Lookup sources and their order for host queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupStrategy {
    /// Query DNS only.
    DnsOnly,
    /// Read the hosts file only.
    FilesOnly,
    /// Query DNS before reading the hosts file.
    DnsThenFiles,
    /// Read the hosts file before querying DNS.
    FilesThenDns,
}

impl LookupStrategy {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::DnsOnly => b"b",
            Self::FilesOnly => b"f",
            Self::DnsThenFiles => b"bf",
            Self::FilesThenDns => b"fb",
        }
    }
}

/// Builder retaining Rust values until validation and C conversion.
///
/// Unspecified fields leave their option bits unset, preserving c-ares defaults.
#[derive(Clone, Debug, Default)]
pub struct ResolverBuilder {
    flags: Option<ResolverFlags>,
    timeout: Option<Duration>,
    max_timeout: Option<Duration>,
    tries: Option<u32>,
    ndots: Option<u32>,
    udp_port: Option<u16>,
    tcp_port: Option<u16>,
    udp_max_queries: Option<u32>,
    tcp_max_queries: Option<u32>,
    send_buffer: Option<usize>,
    receive_buffer: Option<usize>,
    edns_payload_size: Option<u32>,
    domains: Option<Vec<Vec<u8>>>,
    servers: Option<Vec<Ipv4Addr>>,
    lookups: Option<Vec<u8>>,
    resolvconf_path: Option<Vec<u8>>,
    hosts_path: Option<Vec<u8>>,
    rotate: Option<bool>,
    query_cache_ttl: Option<Duration>,
    server_failover: Option<(u16, Duration)>,
}

/// Validated configuration owning every allocation referenced by `ares_options`.
///
/// The C view is borrowed from this owner and must not outlive it. c-ares copies
/// these values during `ares_init_options`; do not call `ares_destroy_options`
/// on this view because its storage is owned by Rust.
pub struct ResolverOptions {
    raw: cares_sys::ares_options,
    optmask: libc::c_int,
    _domains: Vec<CString>,
    _servers: Box<[libc::in_addr]>,
    _domain_pointers: Box<[*mut libc::c_char]>,
    _lookups: Option<CString>,
    _resolvconf_path: Option<CString>,
    _hosts_path: Option<CString>,
}

impl fmt::Debug for ResolverOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolverOptions")
            .field("optmask", &self.optmask)
            .finish_non_exhaustive()
    }
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            raw: empty_options(),
            optmask: 0,
            _domains: Vec::new(),
            _servers: Box::default(),
            _domain_pointers: Box::default(),
            _lookups: None,
            _resolvconf_path: None,
            _hosts_path: None,
        }
    }
}

impl ResolverOptions {
    /// Starts a builder with all options unspecified.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn builder() -> ResolverBuilder {
        ResolverBuilder::new()
    }

    /// Borrows the C options and their matching option mask.
    ///
    /// The returned pointers remain valid until this owner is dropped, including
    /// when the owner moves. C consumers must treat the pointed-to data as read-only.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn as_raw(&self) -> (&cares_sys::ares_options, libc::c_int) {
        (&self.raw, self.optmask)
    }

    /// Installs socket notifications for the initial `ares_init_options` call.
    ///
    /// The C consumer must keep `data` valid until the channel is destroyed and
    /// uphold the callback's safety contract when calling the unsafe C APIs.
    /// Passing `None` explicitly disables notifications.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn with_sock_state_cb(
        mut self,
        callback: cares_sys::ares_sock_state_cb,
        data: *mut std::ffi::c_void,
    ) -> Self {
        self.raw.sock_state_cb = callback;
        self.raw.sock_state_cb_data = data;
        self.optmask |= cares_sys::ARES_OPT_SOCK_STATE_CB;
        self
    }

    /// Borrows the C options whose allocations are owned by this configuration.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn raw_options(&self) -> &cares_sys::ares_options {
        &self.raw
    }

    /// Returns the mask to pass alongside [`Self::raw_options`].
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn optmask(&self) -> libc::c_int {
        self.optmask
    }
}

impl ResolverBuilder {
    /// Starts a builder preserving the upstream defaults.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces all channel behavior flags, including the upstream EDNS default.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn flags(mut self, flags: ResolverFlags) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the initial per-attempt timeout, exactly representable in milliseconds.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the maximum adaptive timeout, exactly representable in milliseconds.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn max_timeout(mut self, timeout: Duration) -> Self {
        self.max_timeout = Some(timeout);
        self
    }

    /// Sets the positive number of query attempts.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn tries(mut self, tries: u32) -> Self {
        self.tries = Some(tries);
        self
    }

    /// Sets the number of dots required to try an absolute name first.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn ndots(mut self, ndots: u32) -> Self {
        self.ndots = Some(ndots);
        self
    }

    /// Sets the UDP DNS server port in host byte order.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn udp_port(mut self, port: u16) -> Self {
        self.udp_port = Some(port);
        self
    }

    /// Sets the TCP DNS server port in host byte order.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn tcp_port(mut self, port: u16) -> Self {
        self.tcp_port = Some(port);
        self
    }

    /// Sets the maximum queries sent on each UDP socket; zero means unlimited.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn udp_max_queries(mut self, maximum: u32) -> Self {
        self.udp_max_queries = Some(maximum);
        self
    }

    /// Requests a TCP query limit, which c-ares 1.34.9 cannot represent.
    ///
    /// [`Self::build`] returns an error when this setting is supplied; upstream
    /// exposes neither a TCP maximum-query field nor a corresponding setter.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn tcp_max_queries(mut self, maximum: u32) -> Self {
        self.tcp_max_queries = Some(maximum);
        self
    }

    /// Sets a positive socket send-buffer size in bytes.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn socket_send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer = Some(size);
        self
    }

    /// Sets a positive socket receive-buffer size in bytes.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn socket_receive_buffer_size(mut self, size: usize) -> Self {
        self.receive_buffer = Some(size);
        self
    }

    /// Sets an EDNS payload size from 512 through 65535 bytes and enables EDNS.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn edns0_payload_size(mut self, size: u32) -> Self {
        self.edns_payload_size = Some(size);
        self.set_flag(ResolverFlags::EDNS, true);
        self
    }

    /// Enables or disables EDNS while preserving other configured flags.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn edns0(mut self, enabled: bool) -> Self {
        self.set_flag(ResolverFlags::EDNS, enabled);
        self
    }

    /// Enables or disables DNS name case randomization.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn dns0x20(mut self, enabled: bool) -> Self {
        self.set_flag(ResolverFlags::DNS0X20, enabled);
        self
    }

    /// Selects whether to rotate through configured DNS servers.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn rotate(mut self, enabled: bool) -> Self {
        self.rotate = Some(enabled);
        self
    }

    /// Selects whether to restrict resolution to the primary server.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn primary(mut self, enabled: bool) -> Self {
        self.set_flag(ResolverFlags::PRIMARY, enabled);
        self
    }

    /// Selects whether queries use TCP from the outset.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn use_tcp(mut self, enabled: bool) -> Self {
        self.set_flag(ResolverFlags::USE_TCP, enabled);
        self
    }

    /// Selects whether search-domain expansion is disabled.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn no_search(mut self, enabled: bool) -> Self {
        self.set_flag(ResolverFlags::NO_SEARCH, enabled);
        self
    }

    /// Replaces the IPv4 servers passed directly to `ares_init_options`.
    ///
    /// c-ares' options structure represents IPv4 addresses only. IPv6 endpoints
    /// and per-server ports require the channel's server-list setter.
    ///
    /// # Panics
    /// Panics from the supplied iterator propagate; allocation follows Rust's policy.
    pub fn servers(mut self, servers: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        self.servers = Some(servers.into_iter().collect());
        self
    }

    /// Replaces the ordered search-domain list.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    /// Panics from caller-provided iteration or conversions propagate.
    /// Allocation follows Rust's allocation policy.
    pub fn search_domains<I, S>(mut self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.domains = Some(
            domains
                .into_iter()
                .map(|s| s.as_ref().as_bytes().to_vec())
                .collect(),
        );
        self
    }

    /// Selects the sources and their order for host queries.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    /// Allocation follows Rust's allocation policy.
    pub fn lookup_strategy(mut self, strategy: LookupStrategy) -> Self {
        self.lookups = Some(strategy.bytes().to_vec());
        self
    }

    /// Sets upstream lookup codes (`b` for DNS and `f` for the hosts file).
    ///
    /// [`Self::build`] rejects empty orders, duplicate codes, and unknown codes.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    /// Panics from caller-provided iteration or conversions propagate.
    /// Allocation follows Rust's allocation policy.
    pub fn lookups(mut self, order: impl AsRef<str>) -> Self {
        self.lookups = Some(order.as_ref().as_bytes().to_vec());
        self
    }

    /// Replaces the resolv.conf path, retaining non-UTF-8 Unix path bytes.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    /// Panics from caller-provided iteration or conversions propagate.
    /// Allocation follows Rust's allocation policy.
    pub fn resolvconf_path(mut self, path: impl AsRef<Path>) -> Self {
        self.resolvconf_path = Some(path.as_ref().as_os_str().as_bytes().to_vec());
        self
    }

    /// Replaces the hosts file path, retaining non-UTF-8 Unix path bytes.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    /// Panics from caller-provided iteration or conversions propagate.
    /// Allocation follows Rust's allocation policy.
    pub fn hosts_path(mut self, path: impl AsRef<Path>) -> Self {
        self.hosts_path = Some(path.as_ref().as_os_str().as_bytes().to_vec());
        self
    }

    /// Sets the query-cache lifetime in whole seconds; zero disables caching.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn query_cache_ttl(mut self, ttl: Duration) -> Self {
        self.query_cache_ttl = Some(ttl);
        self
    }

    /// Sets failed-server retry probability (1/N) and delay in milliseconds.
    ///
    /// A zero retry chance disables retries; zero delay allows immediate retry.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    pub fn server_failover(mut self, retry_chance: u16, retry_delay: Duration) -> Self {
        self.server_failover = Some((retry_chance, retry_delay));
        self
    }

    /// Validates all supplied values and owns their stable C representations.
    ///
    /// # Errors
    /// Returns an error for interior NUL bytes, empty paths or domain names,
    /// unsupported flags or TCP query limits, invalid lookup orders, zero values
    /// that upstream would ignore, and values that cannot be represented exactly.
    ///
    /// # Panics
    /// This function has no explicit panic paths.
    /// Allocation follows Rust's allocation policy.
    pub fn build(self) -> Result<ResolverOptions> {
        if self.tcp_max_queries.is_some() {
            return Err(AresError::invalid_input(
                "c-ares 1.34.9 does not support TCP maximum queries",
            ));
        }
        let mut result = ResolverOptions::default();
        let raw = &mut result.raw;
        let mask = &mut result.optmask;
        if let Some(flags) = self.flags {
            if flags.bits() & !ResolverFlags::all().bits() != 0 {
                return Err(AresError::invalid_input("unknown resolver flags"));
            }
            raw.flags = flags.bits();
            *mask |= cares_sys::ARES_OPT_FLAGS;
        }
        if let Some(timeout) = self.timeout {
            raw.timeout = milliseconds(timeout, "timeout")?;
            *mask |= cares_sys::ARES_OPT_TIMEOUTMS;
        }
        if let Some(timeout) = self.max_timeout {
            raw.maxtimeout = milliseconds(timeout, "maximum timeout")?;
            *mask |= cares_sys::ARES_OPT_MAXTIMEOUTMS;
        }
        if let Some(tries) = self.tries {
            raw.tries = positive_int(tries as u128, "tries")?;
            *mask |= cares_sys::ARES_OPT_TRIES;
        }
        if let Some(ndots) = self.ndots {
            raw.ndots = checked_int(ndots as u128, "ndots")?;
            *mask |= cares_sys::ARES_OPT_NDOTS;
        }
        if let Some(port) = self.udp_port {
            raw.udp_port = port;
            *mask |= cares_sys::ARES_OPT_UDP_PORT;
        }
        if let Some(port) = self.tcp_port {
            raw.tcp_port = port;
            *mask |= cares_sys::ARES_OPT_TCP_PORT;
        }
        if let Some(maximum) = self.udp_max_queries {
            raw.udp_max_queries = checked_int(maximum as u128, "UDP maximum queries")?;
            *mask |= cares_sys::ARES_OPT_UDP_MAX_QUERIES;
        }
        if let Some(size) = self.send_buffer {
            raw.socket_send_buffer_size = positive_int(size as u128, "socket send buffer size")?;
            *mask |= cares_sys::ARES_OPT_SOCK_SNDBUF;
        }
        if let Some(size) = self.receive_buffer {
            raw.socket_receive_buffer_size =
                positive_int(size as u128, "socket receive buffer size")?;
            *mask |= cares_sys::ARES_OPT_SOCK_RCVBUF;
        }
        if let Some(size) = self.edns_payload_size {
            if !(512..=65535).contains(&size) {
                return Err(AresError::invalid_input(
                    "EDNS payload size must be 512..=65535",
                ));
            }
            raw.ednspsz = checked_int(size as u128, "EDNS payload size")?;
            *mask |= cares_sys::ARES_OPT_EDNSPSZ;
        }
        if let Some(servers) = self.servers {
            raw.nservers = checked_int(servers.len() as u128, "server count")?;
            result._servers = servers
                .into_iter()
                .map(|address| libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                })
                .collect();
            raw.servers = if result._servers.is_empty() {
                ptr::null_mut()
            } else {
                result._servers.as_mut_ptr()
            };
            *mask |= cares_sys::ARES_OPT_SERVERS;
        }
        if let Some(domains) = self.domains {
            raw.ndomains = checked_int(domains.len() as u128, "search domain count")?;
            result._domains = domains
                .into_iter()
                .map(|s| c_string(s, "search domain"))
                .collect::<Result<_>>()?;
            result._domain_pointers = result
                ._domains
                .iter()
                .map(|s| s.as_ptr().cast_mut())
                .collect();
            raw.domains = if result._domain_pointers.is_empty() {
                ptr::null_mut()
            } else {
                result._domain_pointers.as_mut_ptr()
            };
            *mask |= cares_sys::ARES_OPT_DOMAINS;
        }
        if let Some(lookups) = self.lookups {
            if !matches!(lookups.as_slice(), b"b" | b"f" | b"bf" | b"fb") {
                return Err(AresError::invalid_input(
                    "lookup order must be b, f, bf, or fb",
                ));
            }
            result._lookups = Some(c_string(lookups, "lookup order")?);
            raw.lookups = string_pointer(&result._lookups);
            *mask |= cares_sys::ARES_OPT_LOOKUPS;
        }
        if let Some(path) = self.resolvconf_path {
            result._resolvconf_path = Some(c_string(path, "resolv.conf path")?);
            raw.resolvconf_path = string_pointer(&result._resolvconf_path);
            *mask |= cares_sys::ARES_OPT_RESOLVCONF;
        }
        if let Some(path) = self.hosts_path {
            result._hosts_path = Some(c_string(path, "hosts path")?);
            raw.hosts_path = string_pointer(&result._hosts_path);
            *mask |= cares_sys::ARES_OPT_HOSTS_FILE;
        }
        if let Some(rotate) = self.rotate {
            *mask |= if rotate {
                cares_sys::ARES_OPT_ROTATE
            } else {
                cares_sys::ARES_OPT_NOROTATE
            };
        }
        if let Some(ttl) = self.query_cache_ttl {
            if ttl.subsec_nanos() != 0 {
                return Err(AresError::invalid_input(
                    "query cache TTL must use whole seconds",
                ));
            }
            raw.qcache_max_ttl = ttl
                .as_secs()
                .try_into()
                .map_err(|_| AresError::invalid_input("query cache TTL exceeds unsigned int"))?;
            *mask |= cares_sys::ARES_OPT_QUERY_CACHE;
        }
        if let Some((chance, delay)) = self.server_failover {
            if !delay.subsec_nanos().is_multiple_of(1_000_000) {
                return Err(AresError::invalid_input(
                    "server failover requires a whole-millisecond delay",
                ));
            }
            raw.server_failover_opts.retry_chance = chance;
            raw.server_failover_opts.retry_delay = delay
                .as_millis()
                .try_into()
                .map_err(|_| AresError::invalid_input("server failover delay exceeds size_t"))?;
            *mask |= cares_sys::ARES_OPT_SERVER_FAILOVER;
        }
        Ok(result)
    }

    fn set_flag(&mut self, flag: ResolverFlags, enabled: bool) {
        let flags = self.flags.get_or_insert(ResolverFlags::EDNS);
        flags.set(flag, enabled);
    }
}

fn empty_options() -> cares_sys::ares_options {
    // SAFETY: ares_options is a C aggregate containing only integers, raw
    // pointers, an optional C function pointer, and ares_evsys_t whose zero
    // discriminant is ARES_EVSYS_DEFAULT. Zero initializes each valid value;
    // the zero option mask ensures upstream does not interpret absent fields.
    unsafe { std::mem::zeroed() }
}

fn checked_int(value: u128, field: &str) -> Result<libc::c_int> {
    value
        .try_into()
        .map_err(|_| AresError::invalid_input(format!("{field} exceeds signed int")))
}

fn positive_int(value: u128, field: &str) -> Result<libc::c_int> {
    if value == 0 {
        return Err(AresError::invalid_input(format!(
            "{field} must be positive"
        )));
    }
    checked_int(value, field)
}

fn milliseconds(value: Duration, field: &str) -> Result<libc::c_int> {
    if !value.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(AresError::invalid_input(format!(
            "{field} must use whole milliseconds"
        )));
    }
    positive_int(value.as_millis(), field)
}

fn c_string(value: Vec<u8>, field: &str) -> Result<CString> {
    if value.is_empty() {
        return Err(AresError::invalid_input(format!(
            "{field} must not be empty"
        )));
    }
    CString::new(value)
        .map_err(|_| AresError::invalid_input(format!("{field} contains an interior NUL byte")))
}

fn string_pointer(value: &Option<CString>) -> *mut libc::c_char {
    value
        .as_ref()
        .map_or(ptr::null_mut(), |s| s.as_ptr().cast_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_copies_servers_domains_and_lookups_before_options_drop() -> Result<()> {
        // SAFETY: this unit-test process initializes c-ares once and never
        // cleans it up while any test-owned C allocations remain live.
        AresError::check(unsafe { cares_sys::ares_library_init(cares_sys::ARES_LIB_INIT_ALL) })?;
        let options = ResolverBuilder::new()
            .servers([Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 53)])
            .search_domains(["one.test", "two.test"])
            .lookup_strategy(LookupStrategy::FilesThenDns)
            .resolvconf_path("/dev/null")
            .hosts_path("/dev/null")
            .build()?;
        let moved = Box::new(options);
        let (raw, mask) = moved.as_raw();
        let mut channel = ptr::null_mut();
        // SAFETY: moved owns every input allocation throughout initialization;
        // channel points to writable storage for the new channel allocation.
        AresError::check(unsafe { cares_sys::ares_init_options(&mut channel, raw, mask) })?;
        struct Channel(*mut cares_sys::ares_channel_t);
        impl Drop for Channel {
            fn drop(&mut self) {
                // SAFETY: this guard uniquely owns the initialized channel.
                unsafe { cares_sys::ares_destroy(self.0) };
            }
        }
        let channel = Channel(channel);
        drop(moved);
        struct Saved(cares_sys::ares_options);
        impl Drop for Saved {
            fn drop(&mut self) {
                // SAFETY: save_options initializes this independent C-owned
                // options aggregate; destroy_options frees only its contents.
                unsafe { cares_sys::ares_destroy_options(&mut self.0) };
            }
        }
        let mut saved = Saved(empty_options());
        let mut mask = 0;
        // SAFETY: channel is live and the output aggregates are writable;
        // saved owns all C allocations produced by this call, even on failure.
        AresError::check(unsafe {
            cares_sys::ares_save_options(channel.0, &mut saved.0, &mut mask)
        })?;
        assert_eq!((saved.0.nservers, saved.0.ndomains), (2, 2));
        // SAFETY: successful save_options produced the validated counts above
        // and independently allocated NUL-terminated strings and address data.
        unsafe {
            assert_eq!((*saved.0.servers).s_addr.to_ne_bytes(), [127, 0, 0, 1]);
            assert_eq!(
                (*saved.0.servers.add(1)).s_addr.to_ne_bytes(),
                [192, 0, 2, 53]
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(*saved.0.domains).to_bytes(),
                b"one.test"
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(*saved.0.domains.add(1)).to_bytes(),
                b"two.test"
            );
            assert_eq!(std::ffi::CStr::from_ptr(saved.0.lookups).to_bytes(), b"fb");
            assert_eq!(
                std::ffi::CStr::from_ptr(saved.0.resolvconf_path).to_bytes(),
                b"/dev/null"
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(saved.0.hosts_path).to_bytes(),
                b"/dev/null"
            );
        }
        let empty = ResolverBuilder::new()
            .servers([])
            .search_domains([] as [&str; 0])
            .build()?;
        assert!(empty.raw_options().servers.is_null());
        assert!(empty.raw_options().domains.is_null());
        assert_eq!(
            (empty.raw_options().nservers, empty.raw_options().ndomains),
            (0, 0)
        );
        assert_ne!(empty.optmask() & cares_sys::ARES_OPT_SERVERS, 0);
        Ok(())
    }
}
