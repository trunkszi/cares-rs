//! Resolver lifecycle, TCP framing, and failure-injection integration tests.

#[path = "mock_dns_server.rs"]
mod mock_dns_server;

use std::{
    cell::{Cell, RefCell},
    error::Error,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use cares::{
    error::{AresError, AresStatus},
    options::ResolverOptions,
    record::DnsRecord,
    resolver::{QueryOutcome, Resolver, ServerStateEvent},
    types::{DnsRecordType, DnsSection},
};
use mock_dns_server::{Behavior, MockDnsServer, Zone, make_response};

type TestError = Box<dyn Error>;
type TestResult = Result<(), TestError>;
type Collected = (AresStatus, Result<DnsRecord, AresError>);
type Sink = Rc<RefCell<Option<Collected>>>;

const TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
const FRAME_POLL: Duration = Duration::from_millis(20);
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);
/// How long the coalescing server waits for a second query frame.
const COALESCE_WINDOW: Duration = Duration::from_millis(200);

fn failure(message: impl Into<String>) -> TestError {
    Box::<dyn Error>::from(message.into())
}

/// Pins a completion into owned form before c-ares frees the record.
fn collect(outcome: QueryOutcome<'_>) -> Collected {
    let record = outcome
        .record
        .map(|record| record.to_owned_record())
        .unwrap_or_else(|| {
            Err(AresError::invalid_record(
                "completion carried no DNS record",
            ))
        });
    (outcome.status, record)
}

fn drive_until(
    resolver: &mut Resolver,
    deadline: Instant,
    mut finished: impl FnMut() -> bool,
) -> TestResult {
    while !finished() {
        if Instant::now() >= deadline {
            return Err(failure("deadline elapsed before the resolver completed"));
        }
        resolver.wait_completions(Duration::from_millis(25))?;
    }
    Ok(())
}

fn a_address(record: &DnsRecord) -> Result<Ipv4Addr, TestError> {
    Ok(record.rr(DnsSection::Answer, 0)?.as_a()?.address)
}

fn query_owned(
    resolver: &mut Resolver,
    name: &str,
    record_type: DnsRecordType,
    timeout: Duration,
) -> Result<DnsRecord, TestError> {
    let sink: Sink = Rc::new(RefCell::new(None));
    let slot = Rc::clone(&sink);
    resolver.submit_query(name, record_type, move |_ctx, outcome| {
        *slot.borrow_mut() = Some(collect(outcome));
    })?;
    drive_until(resolver, Instant::now() + timeout, || {
        sink.borrow().is_some()
    })?;
    let (status, record) = sink
        .borrow_mut()
        .take()
        .ok_or_else(|| failure(format!("no completion for {name} {record_type:?}")))?;
    if status != AresStatus::Success {
        return Err(failure(format!(
            "{name} {record_type:?} completed with {status:?}: {}",
            status.message()
        )));
    }
    Ok(record?)
}

fn v4(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, host)
}

fn options_with(tries: u32, timeout: Duration) -> Result<ResolverOptions, TestError> {
    ResolverOptions::builder()
        .tries(tries)
        .timeout(timeout)
        .query_cache_ttl(Duration::ZERO)
        .build()
        .map_err(|error| failure(format!("invalid resolver options: {error}")))
}

fn framing_resolver_for(server: &FramingServer, timeout: Duration) -> Result<Resolver, TestError> {
    let options = ResolverOptions::builder()
        .tries(1)
        .timeout(timeout)
        .query_cache_ttl(Duration::ZERO)
        .use_tcp(true)
        .build()
        .map_err(|error| failure(format!("invalid resolver options: {error}")))?;
    let mut resolver = Resolver::new(options)
        .map_err(|error| failure(format!("resolver init failed: {error}")))?;
    resolver
        .set_servers_csv(&format!("127.0.0.1:{}", server.port))
        .map_err(|error| failure(format!("set_servers_csv failed: {error}")))?;
    Ok(resolver)
}

#[derive(Clone, Copy)]
enum Mode {
    Fragment,
    Coalesce,
}

#[derive(Default)]
struct Stats {
    connections: AtomicUsize,
    queries: AtomicUsize,
    writes: AtomicUsize,
    body_bytes: AtomicUsize,
    coalesced_batches: AtomicUsize,
}

/// A TCP-only DNS server whose workers are joined in [`Drop`].
struct FramingServer {
    port: u16,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    accept: Option<JoinHandle<()>>,
}

impl FramingServer {
    fn start(zone: Zone, mode: Mode) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());
        let accept = thread::Builder::new()
            .name(String::from("c2-tcp-accept"))
            .spawn({
                let zone = Arc::new(zone);
                let stop = Arc::clone(&stop);
                let stats = Arc::clone(&stats);
                move || accept_loop(listener, zone, stats, stop, mode)
            })?;
        Ok(Self {
            port,
            stop,
            stats,
            accept: Some(accept),
        })
    }
}

impl Drop for FramingServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept.take() {
            drop(handle.join());
        }
    }
}

fn serve(stream: TcpStream, zone: &Zone, stats: &Stats, stop: &AtomicBool, mode: Mode) {
    match mode {
        Mode::Fragment => serve_fragmented(stream, zone, stats, stop),
        Mode::Coalesce => serve_coalesced(stream, zone, stats, stop),
    }
}

fn accept_loop(
    listener: TcpListener,
    zone: Arc<Zone>,
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
    mode: Mode,
) {
    let mut workers = Vec::new();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                stats.connections.fetch_add(1, Ordering::Relaxed);
                let connection_zone = Arc::clone(&zone);
                let connection_stats = Arc::clone(&stats);
                let connection_stop = Arc::clone(&stop);
                let spawned = thread::Builder::new()
                    .name(String::from("c2-tcp-conn"))
                    .spawn(move || {
                        serve(
                            stream,
                            &connection_zone,
                            &connection_stats,
                            &connection_stop,
                            mode,
                        )
                    });
                match spawned {
                    Ok(handle) => workers.push(handle),
                    Err(error) => {
                        eprintln!("framing server could not spawn a worker: {error}");
                        break;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::park_timeout(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    for worker in workers {
        drop(worker.join());
    }
}

enum FrameRead {
    Frame(Vec<u8>),
    Idle,
    Closed,
}

/// Pulls one length-prefixed frame out of `buffer`, keeping any partial frame
/// for the next call so a split prefix or body is reassembled.
fn next_frame(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<FrameRead> {
    loop {
        if buffer.len() >= 2 {
            let length = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
            if length == 0 {
                return Ok(FrameRead::Closed);
            }
            if buffer.len() >= length + 2 {
                let message = buffer[2..2 + length].to_vec();
                buffer.drain(..2 + length);
                return Ok(FrameRead::Frame(message));
            }
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(FrameRead::Closed),
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(FrameRead::Idle),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(FrameRead::Idle),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn prepare(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(FRAME_POLL))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))
}

fn append_frame(frames: &mut Vec<u8>, response: &[u8]) -> io::Result<()> {
    let length = u16::try_from(response.len())
        .map_err(|_| io::Error::other("DNS response exceeds the TCP frame limit"))?;
    frames.extend_from_slice(&length.to_be_bytes());
    frames.extend_from_slice(response);
    Ok(())
}

fn write_frame(stream: &mut TcpStream, response: &[u8], stats: &Stats) -> io::Result<()> {
    let mut frame = Vec::with_capacity(response.len() + 2);
    append_frame(&mut frame, response)?;
    stream.write_all(&frame)?;
    stats.writes.fetch_add(1, Ordering::Relaxed);
    stats
        .body_bytes
        .fetch_add(response.len(), Ordering::Relaxed);
    stream.flush()
}

/// Writes the prefix and every body byte with its own `write_all`.
fn write_fragmented(stream: &mut TcpStream, response: &[u8], stats: &Stats) -> io::Result<()> {
    let length = u16::try_from(response.len())
        .map_err(|_| io::Error::other("DNS response exceeds the TCP frame limit"))?;
    for byte in length.to_be_bytes() {
        stream.write_all(&[byte])?;
        stats.writes.fetch_add(1, Ordering::Relaxed);
    }
    for byte in response {
        stream.write_all(std::slice::from_ref(byte))?;
        stats.writes.fetch_add(1, Ordering::Relaxed);
    }
    stats
        .body_bytes
        .fetch_add(response.len(), Ordering::Relaxed);
    stream.flush()
}

fn serve_fragmented(mut stream: TcpStream, zone: &Zone, stats: &Stats, stop: &AtomicBool) {
    if prepare(&stream).is_err() {
        return;
    }
    let mut buffer = Vec::new();
    while !stop.load(Ordering::Acquire) {
        match next_frame(&mut stream, &mut buffer) {
            Ok(FrameRead::Frame(message)) => {
                stats.queries.fetch_add(1, Ordering::Relaxed);
                let Ok(Some(response)) = make_response(zone, &message, false, None) else {
                    continue;
                };
                if write_fragmented(&mut stream, &response, stats).is_err() {
                    return;
                }
            }
            Ok(FrameRead::Idle) => {}
            Ok(FrameRead::Closed) | Err(_) => return,
        }
    }
}

fn serve_coalesced(mut stream: TcpStream, zone: &Zone, stats: &Stats, stop: &AtomicBool) {
    if prepare(&stream).is_err() {
        return;
    }
    let mut buffer = Vec::new();
    while !stop.load(Ordering::Acquire) {
        let first = match next_frame(&mut stream, &mut buffer) {
            Ok(FrameRead::Frame(message)) => message,
            Ok(FrameRead::Idle) => continue,
            Ok(FrameRead::Closed) | Err(_) => return,
        };
        stats.queries.fetch_add(1, Ordering::Relaxed);
        let Ok(Some(first_response)) = make_response(zone, &first, false, None) else {
            continue;
        };
        // Both queries are queued on one connection before it connects.
        let deadline = Instant::now() + COALESCE_WINDOW;
        let mut second_response = None;
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            match next_frame(&mut stream, &mut buffer) {
                Ok(FrameRead::Frame(message)) => {
                    stats.queries.fetch_add(1, Ordering::Relaxed);
                    second_response = make_response(zone, &message, false, None).ok().flatten();
                    break;
                }
                Ok(FrameRead::Idle) => {}
                Ok(FrameRead::Closed) | Err(_) => return,
            }
        }
        match second_response {
            Some(second_response) => {
                let mut batch =
                    Vec::with_capacity(first_response.len() + second_response.len() + 4);
                if append_frame(&mut batch, &first_response).is_err()
                    || append_frame(&mut batch, &second_response).is_err()
                {
                    return;
                }
                stats.coalesced_batches.fetch_add(1, Ordering::Relaxed);
                stats.writes.fetch_add(1, Ordering::Relaxed);
                stats.body_bytes.fetch_add(
                    first_response.len() + second_response.len(),
                    Ordering::Relaxed,
                );
                if stream.write_all(&batch).is_err() {
                    return;
                }
            }
            None => {
                if write_frame(&mut stream, &first_response, stats).is_err() {
                    return;
                }
            }
        }
    }
}

#[test]
fn tcp_prefix_and_body_fragmentation_reassembled() -> TestResult {
    let server = FramingServer::start(
        Zone::new()
            .a("framed.test.", Ipv4Addr::new(192, 0, 2, 71))
            .a("coalesced.test.", Ipv4Addr::new(192, 0, 2, 72)),
        Mode::Fragment,
    )?;
    let mut resolver = framing_resolver_for(&server, Duration::from_millis(500))?;
    let record = query_owned(&mut resolver, "framed.test.", DnsRecordType::A, TIMEOUT)?;
    assert_eq!(a_address(&record)?, Ipv4Addr::new(192, 0, 2, 71));
    assert_eq!(resolver.active_queries(), 0, "queries left in flight");
    let stats = Arc::clone(&server.stats);
    drop(resolver);
    drop(server); // Join writers before observing their final byte/write counters.
    assert_eq!(
        stats.connections.load(Ordering::Acquire),
        1,
        "expected exactly one TCP connection"
    );
    assert_eq!(
        stats.queries.load(Ordering::Acquire),
        1,
        "one lookup produced {} query frames",
        stats.queries.load(Ordering::Acquire)
    );
    let writes = stats.writes.load(Ordering::Acquire);
    let body_bytes = stats.body_bytes.load(Ordering::Acquire);
    assert!(
        body_bytes > 12,
        "measured a {body_bytes}-byte body, which cannot be a DNS response"
    );
    assert_eq!(
        writes,
        body_bytes + 2,
        "response was not fragmented one byte per write: {writes} writes for {body_bytes} body \
         bytes"
    );
    Ok(())
}

#[test]
fn two_concurrent_tcp_queries_share_one_connection_and_coalesce() -> TestResult {
    let server = FramingServer::start(
        Zone::new()
            .a("framed.test.", Ipv4Addr::new(192, 0, 2, 71))
            .a("coalesced.test.", Ipv4Addr::new(192, 0, 2, 72)),
        Mode::Coalesce,
    )?;
    let mut resolver = framing_resolver_for(&server, Duration::from_millis(500))?;
    let framed: Sink = Rc::new(RefCell::new(None));
    let coalesced: Sink = Rc::new(RefCell::new(None));
    let framed_slot = Rc::clone(&framed);
    let coalesced_slot = Rc::clone(&coalesced);
    // Both submissions happen before any event processing, so c-ares queues both
    // frames on one TCP connection.
    resolver.submit_query("framed.test.", DnsRecordType::A, move |_ctx, outcome| {
        *framed_slot.borrow_mut() = Some(collect(outcome));
    })?;
    resolver.submit_query("coalesced.test.", DnsRecordType::A, move |_ctx, outcome| {
        *coalesced_slot.borrow_mut() = Some(collect(outcome));
    })?;
    drive_until(&mut resolver, Instant::now() + TIMEOUT, || {
        framed.borrow().is_some() && coalesced.borrow().is_some()
    })?;
    let (framed_status, framed_record) = framed
        .borrow_mut()
        .take()
        .ok_or_else(|| failure("framed.test. never completed"))?;
    assert_eq!(framed_status, AresStatus::Success);
    assert_eq!(a_address(&framed_record?)?, Ipv4Addr::new(192, 0, 2, 71));
    let (coalesced_status, coalesced_record) = coalesced
        .borrow_mut()
        .take()
        .ok_or_else(|| failure("coalesced.test. never completed"))?;
    assert_eq!(coalesced_status, AresStatus::Success);
    assert_eq!(a_address(&coalesced_record?)?, Ipv4Addr::new(192, 0, 2, 72));
    let stats = &server.stats;
    assert_eq!(
        stats.queries.load(Ordering::Acquire),
        2,
        "two lookups produced {} query frames",
        stats.queries.load(Ordering::Acquire)
    );
    assert_eq!(
        stats.connections.load(Ordering::Acquire),
        1,
        "c-ares opened {} TCP connections for two queries",
        stats.connections.load(Ordering::Acquire)
    );
    assert_eq!(
        stats.coalesced_batches.load(Ordering::Acquire),
        1,
        "observed {} coalesced writes from {} query frames",
        stats.coalesced_batches.load(Ordering::Acquire),
        stats.queries.load(Ordering::Acquire)
    );
    assert_eq!(resolver.active_queries(), 0, "queries left in flight");
    drop(resolver);
    drop(server);
    Ok(())
}
#[test]
fn refused_loopback_port_fails_over_to_the_live_server() -> TestResult {
    // Reserve and release a loopback UDP port: datagrams to it draw ICMP
    // port-unreachable, which must drive failover rather than a timeout.
    let closed_port = {
        let reserved = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        reserved.local_addr()?.port()
    };
    let server = MockDnsServer::start(Zone::new().a("failover.test.", v4(81)))?;
    let options = ResolverOptions::builder()
        .tries(2)
        .timeout(Duration::from_millis(200))
        .server_failover(1, Duration::from_millis(10))
        .query_cache_ttl(Duration::ZERO)
        .build()
        .map_err(|error| failure(format!("invalid resolver options: {error}")))?;
    let mut resolver = Resolver::new(options)
        .map_err(|error| failure(format!("resolver init failed: {error}")))?;
    let events: Rc<RefCell<Vec<ServerStateEvent>>> = Rc::new(RefCell::new(Vec::new()));
    let event_sink = Rc::clone(&events);
    resolver.set_server_state_callback(move |event| event_sink.borrow_mut().push(event));
    resolver
        .set_servers_csv(&format!(
            "127.0.0.1:{closed_port},127.0.0.1:{}",
            server.udp_addr().port()
        ))
        .map_err(|error| failure(format!("set_servers_csv failed: {error}")))?;
    let started = Instant::now();
    let record = query_owned(
        &mut resolver,
        "failover.test.",
        DnsRecordType::A,
        Duration::from_secs(3),
    )?;
    let elapsed = started.elapsed();
    assert_eq!(a_address(&record)?, v4(81));
    assert!(server.udp_queries() >= 1, "the live server saw no query");
    // A timeout-driven failover cannot finish before the per-try timeout ends.
    assert!(
        elapsed < Duration::from_millis(200),
        "failover took {elapsed:?}; ICMP did not drive it"
    );
    let events = events.borrow();
    let closed = closed_port.to_string();
    assert!(
        events.iter().any(|event| !event.success
            && event
                .server
                .as_deref()
                .is_some_and(|name| name.contains(&closed))),
        "no failure was reported for the closed port: {:?}",
        events
            .iter()
            .map(|event| (event.server.clone(), event.success))
            .collect::<Vec<_>>()
    );
    assert!(
        events.iter().any(|event| event.success),
        "no successful-server event"
    );
    drop(events);
    drop(resolver);
    server.stop();
    Ok(())
}

#[test]
fn dropped_datagram_is_retried_against_the_same_server() -> TestResult {
    let server = MockDnsServer::start(Zone::new().a("loss.test.", v4(82)))?;
    // The first datagram is consumed and never answered, so only a retry after
    // the per-try timeout can produce the record.
    server.set_behavior(Behavior::DropUdp(1));
    let mut resolver = Resolver::new(options_with(2, Duration::from_millis(100))?)
        .map_err(|error| failure(format!("resolver init failed: {error}")))?;
    resolver
        .set_servers_csv(&server.servers_csv())
        .map_err(|error| failure(format!("set_servers_csv failed: {error}")))?;
    let started = Instant::now();
    let record = query_owned(&mut resolver, "loss.test.", DnsRecordType::A, TIMEOUT)?;
    let elapsed = started.elapsed();
    assert_eq!(a_address(&record)?, v4(82));
    assert!(
        server.udp_queries() >= 2,
        "the mock saw {} datagrams; the dropped one must be retried",
        server.udp_queries()
    );
    assert!(
        elapsed >= Duration::from_millis(100),
        "answer arrived after {elapsed:?}, before the per-try timeout expired"
    );
    assert_eq!(resolver.active_queries(), 0, "queries left in flight");
    drop(resolver);
    server.stop();
    Ok(())
}

type DestructionSink = Rc<RefCell<Vec<(AresStatus, Option<DnsRecord>)>>>;
#[path = "support/serial.rs"]
mod serial;
use serial::serial_guard;

const DESTRUCTION_ROUNDS: usize = 32;

fn resolver_at(csv: &str, options: ResolverOptions) -> Result<Resolver, TestError> {
    let mut resolver = Resolver::new(options)
        .map_err(|error| failure(format!("resolver init failed: {error}")))?;
    resolver
        .set_servers_csv(csv)
        .map_err(|error| failure(format!("set_servers_csv failed: {error}")))?;
    Ok(resolver)
}

fn resolver_for(server: &MockDnsServer, options: ResolverOptions) -> Result<Resolver, TestError> {
    resolver_at(&server.servers_csv_with_tcp(), options)
}

#[path = "support/socket_census.rs"]
mod socket_census;
use socket_census::socket_identities;

#[test]
fn sibling_cancellation_on_one_shared_socket() -> TestResult {
    let _serial = serial_guard()?;
    let server = MockDnsServer::start(
        Zone::new()
            .a("cancel-a.test.", v4(101))
            .a("cancel-b.test.", v4(102))
            .a("after-cancel.test.", v4(103)),
    )?;
    let mut resolver = resolver_for(&server, options_with(1, Duration::from_millis(500))?)?;
    server.set_behavior(Behavior::Delay(Duration::from_millis(50)));
    let a_invocations = Rc::new(Cell::new(0usize));
    let a_sink = Rc::clone(&a_invocations);
    let handle_a =
        resolver.submit_query("cancel-a.test.", DnsRecordType::A, move |_ctx, _outcome| {
            a_sink.set(a_sink.get() + 1);
        })?;
    let b_sink: Sink = Rc::new(RefCell::new(None));
    let b_out = Rc::clone(&b_sink);
    resolver.submit_query("cancel-b.test.", DnsRecordType::A, move |_ctx, outcome| {
        *b_out.borrow_mut() = Some(collect(outcome));
    })?;
    assert_eq!(
        resolver.active_queries(),
        2,
        "both sibling queries must be in flight"
    );
    resolver
        .cancel_query(handle_a)
        .map_err(|error| failure(format!("cancel_query(a) failed: {error}")))?;
    // B shares A's UDP socket; completing B also proves A's answer arrived.
    drive_until(&mut resolver, Instant::now() + TIMEOUT, || {
        b_sink.borrow().is_some()
    })?;
    let (status, record) = b_sink
        .borrow_mut()
        .take()
        .ok_or_else(|| failure("sibling B never completed"))?;
    assert_eq!(status, AresStatus::Success, "sibling B failed");
    assert_eq!(
        a_address(&record?)?,
        v4(102),
        "sibling B got the wrong answer"
    );
    // The cancelled slot retires only after c-ares delivers its final callback.
    let drain_deadline = Instant::now() + TIMEOUT;
    while resolver.active_queries() > 0 {
        if Instant::now() >= drain_deadline {
            return Err(failure("cancelled query slot never retired"));
        }
        resolver.wait_completions(Duration::from_millis(25))?;
    }
    assert_eq!(a_invocations.get(), 0, "the cancelled callback ran");
    server.set_behavior(Behavior::Normal);
    let record = query_owned(
        &mut resolver,
        "after-cancel.test.",
        DnsRecordType::A,
        TIMEOUT,
    )?;
    assert_eq!(a_address(&record)?, v4(103));
    assert_eq!(resolver.active_queries(), 0);
    server.stop();
    Ok(())
}

#[test]
fn dropping_a_resolver_with_a_pending_query() -> TestResult {
    // A process-wide census must not include sockets opened by sibling test cases.
    if std::env::var_os("CARES_DESTRUCTION_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "dropping_a_resolver_with_a_pending_query",
                "--nocapture",
            ])
            .env("CARES_DESTRUCTION_CHILD", "1")
            .status()?;
        if !status.success() {
            return Err(failure(format!(
                "isolated resolver destruction failed: {status}"
            )));
        }
        return Ok(());
    }
    let _serial = serial_guard()?;
    // A bound but never-reading UDP socket keeps the query pending forever.
    let blackhole = UdpSocket::bind(("127.0.0.1", 0))?;
    let blackhole_csv = format!("127.0.0.1:{}", blackhole.local_addr()?.port());
    let events: DestructionSink = Rc::new(RefCell::new(Vec::new()));
    let event_sink = Rc::clone(&events);
    let mut resolver = resolver_at(&blackhole_csv, options_with(1, Duration::from_millis(500))?)?;
    resolver.submit_query("drop.test.", DnsRecordType::A, move |_ctx, outcome| {
        let record = outcome
            .record
            .and_then(|record| record.to_owned_record().ok());
        event_sink.borrow_mut().push((outcome.status, record));
    })?;
    assert_eq!(
        resolver.active_queries(),
        1,
        "the query must still be pending when the resolver drops"
    );
    drop(resolver);
    let recorded = events.borrow();
    assert_eq!(
        recorded.len(),
        1,
        "destruction callback ran {} time(s)",
        recorded.len()
    );
    assert_eq!(
        recorded[0].0,
        AresStatus::Destruction,
        "a pending query must observe ARES_EDESTRUCTION"
    );
    assert!(
        recorded[0].1.is_none(),
        "a destroyed query delivered a record"
    );
    drop(recorded);
    // Warm up library-level descriptors before the per-cycle measurement.
    {
        let mut warmup = resolver_at(&blackhole_csv, options_with(1, Duration::from_millis(500))?)?;
        warmup.submit_query("warmup.test.", DnsRecordType::A, |_ctx, _outcome| {})?;
        drop(warmup);
    }
    let loop_start = socket_identities()?;
    let (mut opened_cycles, mut balanced_cycles) = (0usize, 0usize);
    for _ in 0..DESTRUCTION_ROUNDS {
        let before = socket_identities()?;
        let mut round = resolver_at(&blackhole_csv, options_with(1, Duration::from_millis(500))?)?;
        round.submit_query("leak.test.", DnsRecordType::A, |_ctx, _outcome| {})?;
        if socket_identities()?.difference(&before).next().is_some() {
            opened_cycles += 1;
        }
        drop(round);
        if socket_identities()? == before {
            balanced_cycles += 1;
        }
    }
    let global_delta = socket_identities()?.len() as isize - loop_start.len() as isize;
    // Every submission must open a distinct socket and restore the exact prior inode set.
    assert_eq!(
        opened_cycles, DESTRUCTION_ROUNDS,
        "every submission must open a socket"
    );
    assert_eq!(
        balanced_cycles, DESTRUCTION_ROUNDS,
        "every cycle must retire its sockets"
    );
    assert_eq!(global_delta, 0, "resolver destruction leaked a socket");
    let server = MockDnsServer::start(Zone::new().a("after-drop.test.", v4(120)))?;
    let mut fresh = resolver_for(&server, options_with(1, Duration::from_millis(500))?)?;
    let record = query_owned(&mut fresh, "after-drop.test.", DnsRecordType::A, TIMEOUT)?;
    assert_eq!(a_address(&record)?, v4(120));
    assert_eq!(fresh.active_queries(), 0);
    server.stop();
    Ok(())
}
