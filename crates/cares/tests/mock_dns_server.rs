//! Deterministic localhost DNS server used by the adversarial integration tests.
//!
//! UDP and TCP listeners bind independent ephemeral ports on `127.0.0.1` and
//! answer from an in-memory zone. Each transport gets one worker thread; every
//! blocking wait has a timeout and the workers poll a stop flag, so
//! [`MockDnsServer::stop`] and `Drop` cannot hang.
//! TCP framing is the RFC 1035 two-byte big-endian length prefix. c-ares reuses
//! the UDP port for TCP unless the server string overrides it, so
//! [`MockDnsServer::servers_csv`] names the UDP endpoint while
//! [`MockDnsServer::servers_csv_with_tcp`] uses the c-ares URI form
//! `dns://127.0.0.1:<udp_port>?tcpport=<tcp_port>` to route both transports here.

use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use cares_sys::*;

const DEFAULT_TTL: u32 = 300;
const UDP_BUFFER_SIZE: usize = 65_535;
const UDP_POLL_TIMEOUT: Duration = Duration::from_millis(100);
const TCP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Fault injection. `Normal` answers from the zone (NXDOMAIN unknown name, NODATA unknown type).
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
pub enum Behavior {
    #[default]
    Normal,
    /// UDP answers carry `TC=1` without records; TCP answers stay complete.
    TruncateUdp,
    /// Silently drop the next `n` UDP datagrams, then revert to Normal.
    DropUdp(u32),
    /// Delay every response on both transports.
    Delay(Duration),
    /// Answer `SERVFAIL` without records.
    ServFail,
    /// Answer `NXDOMAIN` without records.
    NxDomain,
}

#[derive(Default)]
struct SharedState {
    behavior: Mutex<Behavior>,
    stop: AtomicBool,
    udp_queries: AtomicUsize,
    tcp_queries: AtomicUsize,
}
impl SharedState {
    fn is_stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn behavior(&self) -> Behavior {
        self.behavior.lock().map(|guard| *guard).unwrap_or_default()
    }

    /// Consumes one injected drop; the last drop restores normal answering.
    #[rustfmt::skip]
    fn consume_udp_drop(&self) -> bool {
        let Ok(mut behavior) = self.behavior.lock() else { return false };
        match *behavior {
            Behavior::DropUdp(0) => { *behavior = Behavior::Normal; false }
            Behavior::DropUdp(1) => { *behavior = Behavior::Normal; true }
            Behavior::DropUdp(remaining) => { *behavior = Behavior::DropUdp(remaining - 1); true }
            _ => false,
        }
    }
}

/// One RDATA write; the key always belongs to the record type in [`Answer`].
#[allow(dead_code)]
enum Op {
    Str(ares_dns_rr_key_t, CString),
    U8(ares_dns_rr_key_t, u8),
    U16(ares_dns_rr_key_t, u16),
    U32(ares_dns_rr_key_t, u32),
    Bin(ares_dns_rr_key_t, Vec<u8>),
    Abin(ares_dns_rr_key_t, Vec<Vec<u8>>),
    Opt(ares_dns_rr_key_t, Vec<(u16, Vec<u8>)>),
    Addr4(ares_dns_rr_key_t, Ipv4Addr),
    Addr6(ares_dns_rr_key_t, Ipv6Addr),
}

/// One resource record held by a [`Zone`].
pub struct Answer {
    name: CString,
    ttl: u32,
    record_type: ares_dns_rec_type_t,
    ops: Vec<Op>,
}

/// Authoritative in-memory zone keyed by normalized name and record type.
#[derive(Default)]
pub struct Zone {
    records: HashMap<(String, ares_dns_rec_type_t), Vec<Answer>>,
}

#[allow(dead_code)]
#[rustfmt::skip]
impl Zone {
    pub fn new() -> Self { Self::default() }

    fn put(mut self, name: &str, record_type: ares_dns_rec_type_t, ops: Vec<Op>) -> Self {
        let answer = Answer { name: fqdn(name), ttl: DEFAULT_TTL, record_type, ops };
        self.records.entry((normalize_name(name), record_type)).or_default().push(answer);
        self
    }

    pub fn a(self, name: &str, address: Ipv4Addr) -> Self {
        self.put(name, ARES_REC_TYPE_A, vec![Op::Addr4(ARES_RR_A_ADDR, address)])
    }

    pub fn aaaa(self, name: &str, address: Ipv6Addr) -> Self {
        self.put(name, ARES_REC_TYPE_AAAA, vec![Op::Addr6(ARES_RR_AAAA_ADDR, address)])
    }

    pub fn cname(self, name: &str, target: &str) -> Self {
        self.put(name, ARES_REC_TYPE_CNAME, vec![Op::Str(ARES_RR_CNAME_CNAME, fqdn(target))])
    }

    pub fn mx(self, name: &str, preference: u16, exchange: &str) -> Self {
        self.put(name, ARES_REC_TYPE_MX, vec![
            Op::U16(ARES_RR_MX_PREFERENCE, preference),
            Op::Str(ARES_RR_MX_EXCHANGE, fqdn(exchange)),
        ])
    }

    /// `chunks` maps to consecutive TXT character-strings in one record.
    pub fn txt(self, name: &str, chunks: &[&str]) -> Self {
        let chunks = chunks.iter().map(|chunk| chunk.as_bytes().to_vec()).collect();
        self.put(name, ARES_REC_TYPE_TXT, vec![Op::Abin(ARES_RR_TXT_DATA, chunks)])
    }

    pub fn srv(self, name: &str, priority: u16, weight: u16, port: u16, target: &str) -> Self {
        self.put(name, ARES_REC_TYPE_SRV, vec![
            Op::U16(ARES_RR_SRV_PRIORITY, priority),
            Op::U16(ARES_RR_SRV_WEIGHT, weight),
            Op::U16(ARES_RR_SRV_PORT, port),
            Op::Str(ARES_RR_SRV_TARGET, fqdn(target)),
        ])
    }

    pub fn ptr(self, name: &str, target: &str) -> Self {
        self.put(name, ARES_REC_TYPE_PTR, vec![Op::Str(ARES_RR_PTR_DNAME, fqdn(target))])
    }

    /// Counters: `serial`, `refresh`, `retry`, `expire`, `minimum`.
    pub fn soa(self, name: &str, mname: &str, rname: &str, counters: [u32; 5]) -> Self {
        self.put(name, ARES_REC_TYPE_SOA, vec![
            Op::Str(ARES_RR_SOA_MNAME, fqdn(mname)),
            Op::Str(ARES_RR_SOA_RNAME, fqdn(rname)),
            Op::U32(ARES_RR_SOA_SERIAL, counters[0]),
            Op::U32(ARES_RR_SOA_REFRESH, counters[1]),
            Op::U32(ARES_RR_SOA_RETRY, counters[2]),
            Op::U32(ARES_RR_SOA_EXPIRE, counters[3]),
            Op::U32(ARES_RR_SOA_MINIMUM, counters[4]),
        ])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn naptr(self, name: &str, order: u16, preference: u16,
                 flags: &str, services: &str, regexp: &str, replacement: &str) -> Self {
        self.put(name, ARES_REC_TYPE_NAPTR, vec![
            Op::U16(ARES_RR_NAPTR_ORDER, order),
            Op::U16(ARES_RR_NAPTR_PREFERENCE, preference),
            Op::Str(ARES_RR_NAPTR_FLAGS, to_cstring(flags)),
            Op::Str(ARES_RR_NAPTR_SERVICES, to_cstring(services)),
            Op::Str(ARES_RR_NAPTR_REGEXP, to_cstring(regexp)),
            Op::Str(ARES_RR_NAPTR_REPLACEMENT, fqdn(replacement)),
        ])
    }

    pub fn uri(self, name: &str, priority: u16, weight: u16, target: &str) -> Self {
        self.put(name, ARES_REC_TYPE_URI, vec![
            Op::U16(ARES_RR_URI_PRIORITY, priority),
            Op::U16(ARES_RR_URI_WEIGHT, weight),
            Op::Str(ARES_RR_URI_TARGET, to_cstring(target)),
        ])
    }

    pub fn caa(self, name: &str, critical: u8, tag: &str, value: &str) -> Self {
        self.put(name, ARES_REC_TYPE_CAA, vec![
            Op::U8(ARES_RR_CAA_CRITICAL, critical),
            Op::Str(ARES_RR_CAA_TAG, to_cstring(tag)),
            Op::Bin(ARES_RR_CAA_VALUE, value.as_bytes().to_vec()),
        ])
    }

    pub fn tlsa(self, name: &str, usage: u8, selector: u8, matching: u8, data: &[u8]) -> Self {
        self.put(name, ARES_REC_TYPE_TLSA, vec![
            Op::U8(ARES_RR_TLSA_CERT_USAGE, usage),
            Op::U8(ARES_RR_TLSA_SELECTOR, selector),
            Op::U8(ARES_RR_TLSA_MATCH, matching),
            Op::Bin(ARES_RR_TLSA_DATA, data.to_vec()),
        ])
    }

    pub fn https(self, name: &str, priority: u16, target: &str) -> Self {
        self.https_params(name, priority, target, &[])
    }

    pub fn svcb(self, name: &str, priority: u16, target: &str) -> Self {
        self.svcb_params(name, priority, target, &[])
    }

    /// SVCB/HTTPS parameters are already in wire form; a `PORT` parameter is
    /// two big-endian bytes and an `ALPN` parameter is length-prefixed strings.
    pub fn https_params(self, name: &str, priority: u16, target: &str,
                        params: &[(u16, &[u8])]) -> Self {
        let mut ops = vec![Op::U16(ARES_RR_HTTPS_PRIORITY, priority),
                           Op::Str(ARES_RR_HTTPS_TARGET, fqdn(target))];
        if !params.is_empty() { ops.push(Op::Opt(ARES_RR_HTTPS_PARAMS, clone_params(params))); }
        self.put(name, ARES_REC_TYPE_HTTPS, ops)
    }

    pub fn svcb_params(self, name: &str, priority: u16, target: &str,
                       params: &[(u16, &[u8])]) -> Self {
        let mut ops = vec![Op::U16(ARES_RR_SVCB_PRIORITY, priority),
                           Op::Str(ARES_RR_SVCB_TARGET, fqdn(target))];
        if !params.is_empty() { ops.push(Op::Opt(ARES_RR_SVCB_PARAMS, clone_params(params))); }
        self.put(name, ARES_REC_TYPE_SVCB, ops)
    }

    pub fn lookup(&self, name: &str, rtype: ares_dns_rec_type_t) -> Option<&[Answer]> {
        self.records.get(&(normalize_name(name), rtype)).map(Vec::as_slice)
    }

    fn resolve(&self, question: &Question) -> (ares_dns_rcode_t, Vec<&Answer>) {
        let exact = self.lookup(&question.name, question.qtype);
        // A CNAME is authoritative for every type, so an aliased name returns
        // the CNAME and lets c-ares issue the follow-up query for the target.
        let alias = if exact.is_none() && question.qtype != ARES_REC_TYPE_CNAME {
            self.lookup(&question.name, ARES_REC_TYPE_CNAME)
        } else { None };
        if let Some(answers) = exact.or(alias) {
            return (ARES_RCODE_NOERROR, answers.iter().collect());
        }
        let normalized = normalize_name(&question.name);
        if self.records.keys().any(|(name, _)| *name == normalized) {
            (ARES_RCODE_NOERROR, Vec::new())
        } else {
            (ARES_RCODE_NXDOMAIN, Vec::new())
        }
    }
}

#[allow(dead_code)]
fn clone_params(params: &[(u16, &[u8])]) -> Vec<(u16, Vec<u8>)> {
    params
        .iter()
        .map(|(code, value)| (*code, value.to_vec()))
        .collect()
}

/// Names are matched case-insensitively, so zone keys and RR owner names are
/// lowercased and given a trailing dot.
fn normalize_name(name: &str) -> String {
    let mut normalized: String = name
        .trim()
        .chars()
        .filter(|character| *character != '\0')
        .map(|character| character.to_ascii_lowercase())
        .collect();
    if !normalized.ends_with('.') {
        normalized.push('.');
    }
    normalized
}

#[allow(dead_code)]
fn fqdn(name: &str) -> CString {
    to_cstring(&normalize_name(name))
}

/// c-ares takes C strings, so embedded NUL bytes are dropped instead of
/// silently truncating the value in C.
fn to_cstring(value: &str) -> CString {
    let bytes: Vec<u8> = value.bytes().filter(|byte| *byte != 0).collect();
    CString::new(bytes).unwrap_or_default()
}

struct RecordGuard(*mut ares_dns_record_t);
impl Drop for RecordGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is a record allocated by a c-ares constructor and
            // this guard is its unique owner, so destroying it here is valid.
            unsafe { ares_dns_record_destroy(self.0) };
        }
    }
}

struct Question {
    name: String,
    qtype: ares_dns_rec_type_t,
    qclass: ares_dns_class_t,
}

struct ParsedRequest {
    id: u16,
    opcode: ares_dns_opcode_t,
    question: Option<Question>,
    _record: RecordGuard,
}

#[rustfmt::skip]
fn parse_request(bytes: &[u8]) -> Option<ParsedRequest> {
    let mut record: *mut ares_dns_record_t = ptr::null_mut();
    // SAFETY: `bytes` is a live slice and `record` is a valid out-pointer; on
    // success c-ares returns a new record owned by the guard below.
    let status = unsafe { ares_dns_parse(bytes.as_ptr(), bytes.len(), 0, &mut record) };
    let record = RecordGuard(record);
    if status != ARES_SUCCESS || record.0.is_null() { return None; }
    // SAFETY: `record.0` is a live parsed request for the whole block, the
    // out-pointers are valid, and the name is copied before the record drops.
    let (id, opcode, question) = unsafe {
        let id = ares_dns_record_get_id(record.0);
        let opcode = ares_dns_record_get_opcode(record.0);
        let question = if ares_dns_record_query_cnt(record.0) == 0 {
            None
        } else {
            let mut name: *const libc::c_char = ptr::null();
            let mut qtype = ARES_REC_TYPE_A;
            let mut qclass = ARES_CLASS_IN;
            let status = ares_dns_record_query_get(record.0, 0, &mut name, &mut qtype, &mut qclass);
            if status != ARES_SUCCESS || name.is_null() { return None; }
            let name = CStr::from_ptr(name).to_string_lossy().into_owned();
            Some(Question { name, qtype, qclass })
        };
        (id, opcode, question)
    };
    Some(ParsedRequest { id, opcode, question, _record: record })
}
fn ck(status: ares_status_t) -> io::Result<()> {
    if status == ARES_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::other(format!("c-ares status {}", status.0)))
    }
}
fn apply_ops(rr: *mut ares_dns_rr_t, ops: &[Op]) -> io::Result<()> {
    for op in ops {
        // SAFETY: `rr` is a live record, every key below matches the record type
        // that created it, and each pointer is valid for the length passed.
        unsafe {
            match op {
                Op::Str(key, value) => ck(ares_dns_rr_set_str(rr, *key, value.as_ptr()))?,
                Op::U8(key, value) => ck(ares_dns_rr_set_u8(rr, *key, *value))?,
                Op::U16(key, value) => ck(ares_dns_rr_set_u16(rr, *key, *value))?,
                Op::U32(key, value) => ck(ares_dns_rr_set_u32(rr, *key, *value))?,
                Op::Bin(key, value) => {
                    ck(ares_dns_rr_set_bin(rr, *key, value.as_ptr(), value.len()))?
                }
                Op::Abin(key, chunks) => {
                    for chunk in chunks {
                        ck(ares_dns_rr_add_abin(rr, *key, chunk.as_ptr(), chunk.len()))?;
                    }
                }
                Op::Opt(key, params) => {
                    for (code, value) in params {
                        ck(ares_dns_rr_set_opt(
                            rr,
                            *key,
                            *code,
                            value.as_ptr(),
                            value.len(),
                        ))?;
                    }
                }
                Op::Addr4(key, address) => {
                    let address = libc::in_addr {
                        s_addr: u32::from_ne_bytes(address.octets()),
                    };
                    ck(ares_dns_rr_set_addr(rr, *key, &address))?;
                }
                Op::Addr6(key, address) => {
                    let address = ares_in6_addr {
                        _S6_un: ares_in6_addr__bindgen_ty_1 {
                            _S6_u8: address.octets(),
                        },
                    };
                    ck(ares_dns_rr_set_addr6(rr, *key, &address))?;
                }
            }
        }
    }
    Ok(())
}

fn add_answer(record: *mut ares_dns_record_t, answer: &Answer) -> io::Result<()> {
    let mut rr: *mut ares_dns_rr_t = ptr::null_mut();
    // SAFETY: `record` is live and `rr` is a valid out-pointer; the name is
    // NUL-terminated and the returned RR is owned by the record.
    let status = unsafe {
        ares_dns_record_rr_add(
            &mut rr,
            record,
            ARES_SECTION_ANSWER,
            answer.name.as_ptr(),
            answer.record_type,
            ARES_CLASS_IN,
            answer.ttl,
        )
    };
    ck(status)?;
    if rr.is_null() {
        return Err(io::Error::other(
            "ares_dns_record_rr_add returned a null record",
        ));
    }
    apply_ops(rr, &answer.ops)
}

#[rustfmt::skip]
pub(crate) fn make_response(zone: &Zone, request: &[u8], truncate: bool, forced_rcode: Option<ares_dns_rcode_t>)
    -> io::Result<Option<Vec<u8>>> {
    let Some(request) = parse_request(request) else { return Ok(None) };
    let (rcode, answers) = match forced_rcode {
        Some(rcode) => (rcode, Vec::new()),
        None => match &request.question {
            Some(question) => zone.resolve(question),
            None => (ARES_RCODE_FORMERR, Vec::new()),
        },
    };
    let answers: Vec<&Answer> = if truncate { Vec::new() } else { answers };
    let mut flags = (ARES_FLAG_QR.0 | ARES_FLAG_RD.0 | ARES_FLAG_RA.0) as u16;
    if truncate { flags |= ARES_FLAG_TC.0 as u16; }
    let mut record: *mut ares_dns_record_t = ptr::null_mut();
    // SAFETY: `record` is a valid out-pointer; on success c-ares returns a new
    // record that the guard owns until the end of this function.
    let status = unsafe { ares_dns_record_create(&mut record, request.id, flags, request.opcode, rcode) };
    let record = RecordGuard(record);
    ck(status)?;
    if record.0.is_null() { return Err(io::Error::other("ares_dns_record_create returned null")); }
    if let Some(question) = &request.question {
        let name = to_cstring(&question.name);
        // SAFETY: `record` is live and `name` is NUL-terminated; the question is
        // copied into the record.
        let status = unsafe {
            ares_dns_record_query_add(record.0, name.as_ptr(), question.qtype, question.qclass)
        };
        ck(status)?;
    }
    for answer in &answers { add_answer(record.0, answer)?; }
    let mut buffer: *mut u8 = ptr::null_mut();
    let mut length: usize = 0;
    // SAFETY: `record` is live and both out-pointers are valid; on success the
    // caller owns `buffer` and must release it with `ares_free_string`.
    let status = unsafe { ares_dns_write(record.0, &mut buffer, &mut length) };
    ck(status)?;
    if buffer.is_null() { return Err(io::Error::other("ares_dns_write returned a null buffer")); }
    // SAFETY: a successful write returned `length` initialized bytes at
    // `buffer`; the copy is made before the allocation is released.
    let bytes = unsafe { std::slice::from_raw_parts(buffer, length) }.to_vec();
    // SAFETY: `buffer` came from `ares_dns_write`, which the c-ares
    // documentation requires the caller to free with `ares_free_string`.
    unsafe { ares_free_string(buffer.cast()) };
    Ok(Some(bytes))
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// `park_timeout` is the only wait here; the mock has no reactor to schedule on.
fn delay_response(behavior: Behavior) {
    let Behavior::Delay(delay) = behavior else {
        return;
    };
    let Some(deadline) = Instant::now().checked_add(delay) else {
        return;
    };
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        thread::park_timeout(remaining);
    }
}

fn udp_loop(socket: UdpSocket, zone: Arc<Zone>, shared: Arc<SharedState>) {
    let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
    while !shared.is_stopping() {
        let (length, peer) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if is_timeout(&error) => continue,
            Err(_) => return,
        };
        shared.udp_queries.fetch_add(1, Ordering::Relaxed);
        if shared.consume_udp_drop() {
            continue;
        }
        let behavior = shared.behavior();
        let (truncate, forced) = match behavior {
            Behavior::TruncateUdp => (true, None),
            Behavior::ServFail => (false, Some(ARES_RCODE_SERVFAIL)),
            Behavior::NxDomain => (false, Some(ARES_RCODE_NXDOMAIN)),
            _ => (false, None),
        };
        let response = match make_response(&zone, &buffer[..length], truncate, forced) {
            Ok(Some(response)) => response,
            Ok(None) | Err(_) => continue,
        };
        delay_response(behavior);
        if socket.send_to(&response, peer).is_err() {
            return;
        }
    }
}

fn tcp_loop(listener: TcpListener, zone: Arc<Zone>, shared: Arc<SharedState>) {
    while !shared.is_stopping() {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let (zone, shared) = (Arc::clone(&zone), Arc::clone(&shared));
                thread::spawn(move || handle_tcp_connection(stream, &zone, &shared));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::park_timeout(ACCEPT_POLL_INTERVAL);
            }
            Err(_) => return,
        }
    }
}

#[rustfmt::skip]
fn handle_tcp_connection(mut stream: TcpStream, zone: &Zone, shared: &SharedState) {
    if stream.set_nonblocking(false).is_err() || stream.set_read_timeout(Some(TCP_READ_TIMEOUT)).is_err() {
        return;
    }
    loop {
        if shared.is_stopping() { return; }
        let mut prefix = [0u8; 2];
        // `read_exact` reassembles a prefix or body split across writes, which
        // is the framing rule c-ares depends on.
        if stream.read_exact(&mut prefix).is_err() { return; }
        let length = usize::from(u16::from_be_bytes(prefix));
        if length == 0 { return; }
        let mut message = vec![0u8; length];
        if stream.read_exact(&mut message).is_err() { return; }
        shared.tcp_queries.fetch_add(1, Ordering::Relaxed);
        let behavior = shared.behavior();
        let forced = match behavior {
            Behavior::ServFail => Some(ARES_RCODE_SERVFAIL),
            Behavior::NxDomain => Some(ARES_RCODE_NXDOMAIN),
            _ => None,
        };
        let response = match make_response(zone, &message, false, forced) {
            Ok(Some(response)) => response,
            Ok(None) | Err(_) => continue,
        };
        delay_response(behavior);
        let Ok(length) = u16::try_from(response.len()) else { return };
        let mut frame = Vec::with_capacity(response.len() + 2);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&response);
        if stream.write_all(&frame).is_err() { return; }
    }
}

/// Localhost DNS server with independent UDP and TCP ports.
pub struct MockDnsServer {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    shared: Arc<SharedState>,
    udp_thread: Option<JoinHandle<()>>,
    tcp_thread: Option<JoinHandle<()>>,
}

#[rustfmt::skip]
impl MockDnsServer {
    /// Binds both transports on `127.0.0.1:0` and starts one worker each.
    ///
    /// # Errors
    ///
    /// Returns the socket bind/configuration error, or the error from spawning
    /// either worker thread.
    pub fn start(zone: Zone) -> io::Result<Self> {
        let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp_socket.set_read_timeout(Some(UDP_POLL_TIMEOUT))?;
        tcp_listener.set_nonblocking(true)?;
        let udp_addr = udp_socket.local_addr()?;
        let tcp_addr = tcp_listener.local_addr()?;
        let shared = Arc::new(SharedState::default());
        let zone = Arc::new(zone);
        let udp_thread = thread::Builder::new().name(String::from("mock-dns-udp")).spawn({
            let zone = Arc::clone(&zone);
            let shared = Arc::clone(&shared);
            move || udp_loop(udp_socket, zone, shared)
        })?;
        let tcp_thread = match thread::Builder::new().name(String::from("mock-dns-tcp")).spawn({
            let zone = Arc::clone(&zone);
            let shared = Arc::clone(&shared);
            move || tcp_loop(tcp_listener, zone, shared)
        }) {
            Ok(handle) => handle,
            Err(error) => {
                shared.stop.store(true, Ordering::SeqCst);
                // The UDP worker only observes the flag on its next timeout;
                // discarding the join result keeps the spawn error authoritative.
                drop(udp_thread.join());
                return Err(error);
            }
        };
        Ok(Self { udp_addr, tcp_addr, shared, udp_thread: Some(udp_thread), tcp_thread: Some(tcp_thread) })
    }

    /// `127.0.0.1:<udp_port>`, for a resolver that uses only UDP or reuses the
    /// UDP port for TCP.
    pub fn servers_csv(&self) -> String { format!("127.0.0.1:{}", self.udp_addr.port()) }

    /// `dns://127.0.0.1:<udp_port>?tcpport=<tcp_port>`, the c-ares URI form that
    /// routes TCP to this mock's independent port.
    pub fn servers_csv_with_tcp(&self) -> String {
        format!("dns://127.0.0.1:{}?tcpport={}", self.udp_addr.port(), self.tcp_addr.port())
    }

    /// Alias for [`MockDnsServer::servers_csv_with_tcp`].
    pub fn tcp_override_csv(&self) -> String { self.servers_csv_with_tcp() }

    pub fn udp_addr(&self) -> SocketAddr { self.udp_addr }

    pub fn tcp_addr(&self) -> SocketAddr { self.tcp_addr }

    pub fn udp_queries(&self) -> usize { self.shared.udp_queries.load(Ordering::Acquire) }

    pub fn tcp_queries(&self) -> usize { self.shared.tcp_queries.load(Ordering::Acquire) }

    pub fn set_behavior(&self, behavior: Behavior) {
        match self.shared.behavior.lock() {
            Ok(mut current) => *current = behavior,
            Err(poisoned) => *poisoned.into_inner() = behavior,
        }
    }

    /// Stops both workers and waits for them; `Drop` performs the same shutdown.
    pub fn stop(mut self) { self.shutdown(); }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for handle in [self.udp_thread.take(), self.tcp_thread.take()].into_iter().flatten() {
            // A worker panic surfaces through socket timeouts; it must not abort
            // cleanup or mask the test's own error.
            drop(handle.join());
        }
    }
}

impl Drop for MockDnsServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[rustfmt::skip]
fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + name.len());
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.').filter(|label| !label.is_empty()) {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&[0x00, 0x01]);
    message
}

fn udp_exchange(server: &MockDnsServer, query: &[u8]) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.send_to(query, server.udp_addr())?;
    let mut buffer = [0u8; 4096];
    let (length, _source) = socket.recv_from(&mut buffer)?;
    Ok(buffer[..length].to_vec())
}

fn tcp_exchange(server: &MockDnsServer, query: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(server.tcp_addr())?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let length = u16::try_from(query.len()).map_err(|_| io::Error::other("query too long"))?;
    let prefix = length.to_be_bytes();
    // Separate writes make the server's `read_exact` path reassemble a
    // fragmented frame.
    stream.write_all(&prefix[..1])?;
    stream.write_all(&prefix[1..])?;
    stream.write_all(query)?;
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix)?;
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response)?;
    Ok(response)
}

struct Response {
    id: u16,
    flags: u16,
    rcode: ares_dns_rcode_t,
    answers: usize,
    first_a: Option<Ipv4Addr>,
}

#[rustfmt::skip]
fn parse_response(bytes: &[u8]) -> io::Result<Response> {
    let mut record: *mut ares_dns_record_t = ptr::null_mut();
    // SAFETY: `bytes` is live and `record` is a valid out-pointer; the guard
    // owns the parsed record for the rest of this function.
    let status = unsafe { ares_dns_parse(bytes.as_ptr(), bytes.len(), 0, &mut record) };
    let record = RecordGuard(record);
    ck(status)?;
    if record.0.is_null() { return Err(io::Error::other("ares_dns_parse returned a null record")); }
    // SAFETY: the guard keeps the record alive for these read-only getters.
    let (id, flags, rcode, answers) = unsafe {
        (ares_dns_record_get_id(record.0), ares_dns_record_get_flags(record.0),
         ares_dns_record_get_rcode(record.0), ares_dns_record_rr_cnt(record.0, ARES_SECTION_ANSWER))
    };
    let mut first_a = None;
    for index in 0..answers {
        // SAFETY: `index` is below the answer count and `rr` remains valid until
        // the record is dropped.
        let rr = unsafe { ares_dns_record_rr_get_const(record.0, ARES_SECTION_ANSWER, index) };
        if rr.is_null() { continue; }
        // SAFETY: `rr` is a live answer record, so its type is readable.
        if unsafe { ares_dns_rr_get_type(rr) } != ARES_REC_TYPE_A { continue; }
        // SAFETY: `rr` is an A record, so the address key is valid and the
        // returned pointer is owned by `rr`.
        let address = unsafe { ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR) };
        if address.is_null() { continue; }
        // SAFETY: `address` points at an in_addr owned by `rr`; the stored bytes
        // are the network-order octets.
        let octets = unsafe { (*address).s_addr.to_ne_bytes() };
        first_a = Some(Ipv4Addr::from(octets));
    }
    Ok(Response { id, flags, rcode, answers, first_a })
}

const TEST_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn test_server() -> io::Result<MockDnsServer> {
    MockDnsServer::start(Zone::new().a("a.test.", TEST_ADDRESS))
}

#[test]
fn udp_and_tcp_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let server = test_server()?;
    let query = encode_query(0x1234, "a.test.", 1);
    let udp = parse_response(&udp_exchange(&server, &query)?)?;
    assert_eq!(server.udp_queries(), 1);
    assert_eq!(
        (udp.id, udp.rcode, udp.answers),
        (0x1234, ARES_RCODE_NOERROR, 1)
    );
    assert_ne!(udp.flags & (ARES_FLAG_QR.0 as u16), 0);
    assert_ne!(udp.flags & (ARES_FLAG_RA.0 as u16), 0);
    assert_eq!(udp.first_a, Some(TEST_ADDRESS));
    let tcp = parse_response(&tcp_exchange(&server, &query)?)?;
    assert_eq!(server.tcp_queries(), 1);
    assert_eq!((tcp.id, tcp.answers), (0x1234, 1));
    assert_eq!(tcp.first_a, Some(TEST_ADDRESS));
    assert_eq!(
        server.servers_csv(),
        format!("127.0.0.1:{}", server.udp_addr().port())
    );
    assert_eq!(server.tcp_override_csv(), server.servers_csv_with_tcp());
    server.stop();
    Ok(())
}

#[test]
fn truncate_udp_leaves_tcp_complete() -> Result<(), Box<dyn std::error::Error>> {
    let server = test_server()?;
    server.set_behavior(Behavior::TruncateUdp);
    let query = encode_query(0x0BAD, "a.test.", 1);
    let udp = parse_response(&udp_exchange(&server, &query)?)?;
    assert_ne!(udp.flags & (ARES_FLAG_TC.0 as u16), 0);
    assert_eq!((udp.rcode, udp.answers), (ARES_RCODE_NOERROR, 0));
    let tcp = parse_response(&tcp_exchange(&server, &query)?)?;
    assert_eq!(tcp.flags & (ARES_FLAG_TC.0 as u16), 0);
    assert_eq!(tcp.answers, 1);
    assert_eq!(tcp.first_a, Some(TEST_ADDRESS));
    server.stop();
    Ok(())
}
