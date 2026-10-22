//! Adversarial end-to-end coverage for `Resolver` against a localhost mock DNS
//! server: fourteen record types, TCP fallback, failover, cancellation, a
//! reentrant follow-up, and panic poisoning plus a 10,000-query stress run.

#[path = "mock_dns_server.rs"]
mod mock_dns_server;

use std::{
    cell::{Cell, RefCell},
    error::Error,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    rc::Rc,
    time::{Duration, Instant},
};

use cares::{
    ProactorResolver,
    error::{AresError, AresStatus},
    options::ResolverOptions,
    record::DnsRecord,
    record_rr::{
        CaaRecord, CnameRecord, MxRecord, NaptrRecord, PtrRecord, SoaRecord, SrvRecord, SvcbRecord,
        TlsaRecord, UriRecord,
    },
    resolver::{QueryOutcome, Resolver, ServerStateEvent},
    types::{DnsRecordType, DnsSection},
};
use mock_dns_server::{Behavior, MockDnsServer, Zone};

type TestError = Box<dyn Error>;
type TestResult = Result<(), TestError>;
type Collected = (AresStatus, Result<DnsRecord, AresError>);
type CollectedSink = Rc<RefCell<Option<Collected>>>;
type CnameSink = Rc<RefCell<Option<(AresStatus, Option<String>)>>>;
type AddressSink = Rc<RefCell<Option<(AresStatus, Option<Ipv4Addr>)>>>;
type ProactorResult = Rc<RefCell<Option<(AresStatus, Result<DnsRecord, AresError>)>>>;

/// Drive budget shared by every lookup that does not override it.
const TIMEOUT: Duration = Duration::from_secs(5);

fn failure(message: impl Into<String>) -> TestError {
    Box::<dyn Error>::from(message.into())
}
/// Pins a completion into owned form: c-ares frees the borrowed record as soon
/// as the callback returns, so anything inspected later must be duplicated.
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
/// Submits one query, drives completions until its callback fires, and returns
/// the duplicated record. A non-success status becomes an error.
fn query_owned(
    resolver: &mut Resolver,
    name: &str,
    record_type: DnsRecordType,
    timeout: Duration,
) -> Result<DnsRecord, TestError> {
    let sink: CollectedSink = Rc::new(RefCell::new(None));
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
fn a_address(record: &DnsRecord) -> Result<Ipv4Addr, TestError> {
    Ok(record.rr(DnsSection::Answer, 0)?.as_a()?.address)
}
/// Addresses in the documentation range `192.0.2.0/24`, distinguished by host.
fn v4(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, host)
}
fn fast_options(tries: u32, timeout: Duration) -> Result<ResolverOptions, TestError> {
    ResolverOptions::builder()
        .tries(tries)
        .timeout(timeout)
        .query_cache_ttl(Duration::ZERO)
        .build()
        .map_err(|error| failure(format!("invalid resolver options: {error}")))
}
fn resolver_for(server: &MockDnsServer, options: ResolverOptions) -> Result<Resolver, TestError> {
    let mut resolver = Resolver::new(options)
        .map_err(|error| failure(format!("resolver init failed: {error}")))?;
    resolver
        .set_servers_csv(&server.servers_csv_with_tcp())
        .map_err(|error| failure(format!("set_servers_csv failed: {error}")))?;
    Ok(resolver)
}
/// A zone carrying exactly one record of each of the fourteen types the suite
/// must resolve end to end.
fn zone_all_types() -> Zone {
    Zone::new()
        .a("a.test.", v4(10))
        .aaaa(
            "aaaa.test.",
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010),
        )
        .cname("cname.test.", "target.test.")
        .a("target.test.", v4(20))
        .mx("mx.test.", 10, "mail.test.")
        .txt("txt.test.", &["hello", "world"])
        .srv("srv.test.", 1, 2, 8080, "srv-target.test.")
        .ptr("ptr.test.", "host.test.")
        .soa(
            "soa.test.",
            "ns.test.",
            "admin.test.",
            [2024010101, 3600, 600, 86400, 300],
        )
        .naptr(
            "naptr.test.",
            100,
            10,
            "S",
            "SIP+D2U",
            "!^.*$!sip:info@test.!",
            "_sip._udp.test.",
        )
        .uri("uri.test.", 10, 1, "https://uri.test/path")
        .caa("caa.test.", 0, "issue", "letsencrypt.org")
        .tlsa("tlsa.test.", 3, 1, 1, &[0xde, 0xad, 0xbe, 0xef])
        .https("https.test.", 1, ".")
        .svcb("svcb.test.", 1, "svc-target.test.")
}
/// c-ares drops the trailing root dot when it stores an RR owner or target name,
/// so the names pinned here omit it.
fn check_record(record: &DnsRecord, record_type: DnsRecordType) -> TestResult {
    let answer = record.rr(DnsSection::Answer, 0)?;
    match record_type {
        DnsRecordType::A => assert_eq!(answer.as_a()?.address, v4(10)),
        DnsRecordType::AAAA => assert_eq!(
            answer.as_aaaa()?.address,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010)
        ),
        DnsRecordType::CNAME => assert_eq!(answer.extract::<CnameRecord>()?.cname, "target.test"),
        DnsRecordType::MX => {
            let value = answer.extract::<MxRecord>()?;
            let fields = (value.preference, value.exchange.as_str());
            assert_eq!(fields, (10, "mail.test"));
        }
        DnsRecordType::TXT => {
            let chunks = answer.as_txt()?.chunks;
            assert_eq!(chunks, vec![b"hello".to_vec(), b"world".to_vec()]);
        }
        DnsRecordType::SRV => {
            let value = answer.extract::<SrvRecord>()?;
            assert_eq!((value.priority, value.weight, value.port), (1, 2, 8080));
            assert_eq!(value.target, "srv-target.test");
        }
        DnsRecordType::PTR => assert_eq!(answer.extract::<PtrRecord>()?.dname, "host.test"),
        DnsRecordType::SOA => {
            let value = answer.extract::<SoaRecord>()?;
            let names = (value.mname.as_str(), value.rname.as_str());
            assert_eq!(names, ("ns.test", "admin.test"));
            let ttl = (
                value.serial,
                value.refresh,
                value.retry,
                value.expire,
                value.minimum,
            );
            assert_eq!(ttl, (2024010101, 3600, 600, 86400, 300));
        }
        DnsRecordType::NAPTR => {
            let value = answer.extract::<NaptrRecord>()?;
            assert_eq!((value.order, value.preference), (100, 10));
            assert_eq!(value.flags, "S");
            assert_eq!(value.services, "SIP+D2U");
            assert_eq!(value.regexp, "!^.*$!sip:info@test.!");
            assert_eq!(value.replacement, "_sip._udp.test");
        }
        DnsRecordType::URI => {
            let value = answer.extract::<UriRecord>()?;
            assert_eq!((value.priority, value.weight), (10, 1));
            assert_eq!(value.target, "https://uri.test/path");
        }
        DnsRecordType::CAA => {
            let value = answer.extract::<CaaRecord>()?;
            assert_eq!(value.critical, 0);
            assert_eq!(value.tag, "issue");
            assert_eq!(value.value, b"letsencrypt.org".to_vec());
        }
        DnsRecordType::TLSA => {
            let value = answer.extract::<TlsaRecord>()?;
            let fields = (value.cert_usage, value.selector, value.matching_type);
            assert_eq!(fields, (3, 1, 1));
            assert_eq!(value.data, vec![0xde, 0xad, 0xbe, 0xef]);
        }
        DnsRecordType::HTTPS => {
            let value = answer.as_https()?;
            assert_eq!(value.priority, 1);
            assert!(value.target.is_empty() || value.target == ".");
            // The fixture declares no service parameters; anything else means the
            // parameter list was corrupted in transit.
            assert!(value.params.is_empty(), "unexpected HTTPS params");
        }
        DnsRecordType::SVCB => {
            let value: SvcbRecord = answer.extract()?;
            assert_eq!(value.priority, 1);
            assert_eq!(value.target, "svc-target.test");
            assert!(value.params.is_empty(), "unexpected SVCB params");
        }
        _ => return Err(failure(format!("unsupported record type {record_type:?}"))),
    }
    Ok(())
}
#[test]
fn all_fourteen_record_types_resolve_end_to_end() -> TestResult {
    let server = MockDnsServer::start(zone_all_types())?;
    let mut resolver = resolver_for(&server, fast_options(1, Duration::from_millis(500))?)?;
    let cases: [(&str, DnsRecordType); 14] = [
        ("a.test.", DnsRecordType::A),
        ("aaaa.test.", DnsRecordType::AAAA),
        ("cname.test.", DnsRecordType::CNAME),
        ("mx.test.", DnsRecordType::MX),
        ("txt.test.", DnsRecordType::TXT),
        ("srv.test.", DnsRecordType::SRV),
        ("ptr.test.", DnsRecordType::PTR),
        ("soa.test.", DnsRecordType::SOA),
        ("naptr.test.", DnsRecordType::NAPTR),
        ("uri.test.", DnsRecordType::URI),
        ("caa.test.", DnsRecordType::CAA),
        ("tlsa.test.", DnsRecordType::TLSA),
        ("https.test.", DnsRecordType::HTTPS),
        ("svcb.test.", DnsRecordType::SVCB),
    ];
    for (name, record_type) in cases {
        let record = query_owned(&mut resolver, name, record_type, TIMEOUT)?;
        let answer = record.rr(DnsSection::Answer, 0)?;
        assert_eq!(
            answer.name()?.trim_end_matches('.'),
            name.trim_end_matches('.'),
            "answer owner for {name}"
        );
        check_record(&record, record_type)?;
    }
    let direct = resolver.resolve("a.test.", DnsRecordType::A, TIMEOUT)?;
    assert_eq!(a_address(&direct)?, v4(10));
    assert_eq!(resolver.active_queries(), 0, "queries left in flight");
    drop(resolver);
    server.stop();
    Ok(())
}
fn big_txt_parts() -> Vec<String> {
    ["a", "b", "c", "d"].map(|part| part.repeat(255)).to_vec()
}
#[test]
fn truncated_udp_falls_back_to_tcp() -> TestResult {
    let parts = big_txt_parts();
    let chunks: Vec<&str> = parts.iter().map(String::as_str).collect();
    let server = MockDnsServer::start(
        Zone::new()
            .txt("big.txt.test.", &chunks)
            .https("https.test.", 1, ".")
            .a("a.test.", v4(30)),
    )?;
    server.set_behavior(Behavior::TruncateUdp);
    let mut resolver = resolver_for(&server, fast_options(1, Duration::from_millis(500))?)?;
    // Four 255-byte chunks cannot fit a 512-byte UDP payload, and the mock
    // truncates every answer, so this lookup always takes the TCP path.
    let record = query_owned(&mut resolver, "big.txt.test.", DnsRecordType::TXT, TIMEOUT)?;
    let txt = record.rr(DnsSection::Answer, 0)?.as_txt()?;
    assert_eq!(txt.chunks.len(), 4, "TXT chunk count across TCP fallback");
    assert!(
        txt.chunks
            .iter()
            .zip(&parts)
            .all(|(got, want)| got.as_slice() == want.as_bytes()),
        "TXT content lost across TCP fallback"
    );
    assert!(
        server.tcp_queries() >= 1,
        "expected a TCP retry after the truncated UDP answer"
    );
    let record = query_owned(&mut resolver, "https.test.", DnsRecordType::HTTPS, TIMEOUT)?;
    let https = record.rr(DnsSection::Answer, 0)?.as_https()?;
    assert_eq!(https.priority, 1);
    assert!(https.target.is_empty() || https.target == ".");
    assert!(
        server.tcp_queries() >= 2,
        "HTTPS answer did not exercise a second TCP query"
    );
    server.set_behavior(Behavior::Normal);
    // An explicit USE_TCP resolver must never emit a UDP query for the lookup.
    let udp_before = server.udp_queries();
    let tcp_before = server.tcp_queries();
    let mut tcp_resolver = resolver_for(
        &server,
        ResolverOptions::builder()
            .tries(1)
            .timeout(Duration::from_millis(500))
            .use_tcp(true)
            .build()
            .map_err(|error| failure(format!("invalid resolver options: {error}")))?,
    )?;
    let record = query_owned(&mut tcp_resolver, "a.test.", DnsRecordType::A, TIMEOUT)?;
    assert_eq!(a_address(&record)?, v4(30));
    assert!(
        server.tcp_queries() > tcp_before,
        "explicit use_tcp(true) did not send a TCP query"
    );
    assert_eq!(
        server.udp_queries(),
        udp_before,
        "explicit use_tcp(true) leaked a UDP query"
    );
    drop(tcp_resolver);
    drop(resolver);
    server.stop();
    Ok(())
}
#[test]
fn dead_server_timeout_retries_and_failover() -> TestResult {
    // A bound but never-reading UDP socket: the kernel accepts the datagrams
    // and nothing ever answers on them.
    let blackhole = UdpSocket::bind(("127.0.0.1", 0))?;
    blackhole.set_read_timeout(Some(Duration::from_millis(500)))?;
    let blackhole_port = blackhole.local_addr()?.port();
    let server = MockDnsServer::start(Zone::new().a("a.test.", v4(40)))?;
    let options = ResolverOptions::builder()
        .tries(2)
        .timeout(Duration::from_millis(100))
        .server_failover(1, Duration::from_millis(10))
        .build()
        .map_err(|error| failure(format!("invalid resolver options: {error}")))?;
    let mut resolver = Resolver::new(options)
        .map_err(|error| failure(format!("resolver init failed: {error}")))?;
    let events: Rc<RefCell<Vec<ServerStateEvent>>> = Rc::new(RefCell::new(Vec::new()));
    let event_sink = Rc::clone(&events);
    resolver.set_server_state_callback(move |event| event_sink.borrow_mut().push(event));
    resolver
        .set_servers_csv(&format!(
            "127.0.0.1:{blackhole_port},127.0.0.1:{}",
            server.udp_addr().port()
        ))
        .map_err(|error| failure(format!("set_servers_csv failed: {error}")))?;
    let started = Instant::now();
    let record = query_owned(
        &mut resolver,
        "a.test.",
        DnsRecordType::A,
        Duration::from_secs(6),
    )?;
    let elapsed = started.elapsed();
    assert_eq!(a_address(&record)?, v4(40));
    assert!(
        server.udp_queries() >= 1,
        "the live server never received the failed-over query"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "failover took {elapsed:?}; a dead primary must not stall the query"
    );
    // Causal evidence that the dead server really was tried first: its socket
    // holds the query the resolver sent before giving up on it.
    let mut datagram = [0u8; 2048];
    let (received, _) = blackhole
        .recv_from(&mut datagram)
        .map_err(|error| failure(format!("dead primary never received a query: {error}")))?;
    assert!(
        received >= 12,
        "dead primary received a runt datagram ({received} bytes)"
    );
    // v1.34.9 queues a server-state notification on both the timeout
    // (success = false) and the successful answer (success = true).
    let events = events.borrow();
    assert!(
        events.iter().any(|event| !event.success),
        "no failed-server event among {} notifications",
        events.len()
    );
    assert!(
        events.iter().any(|event| event.success),
        "no successful-server event among {} notifications",
        events.len()
    );
    drop(events);
    drop(resolver);
    server.stop();
    Ok(())
}
#[test]
fn cancel_in_flight_returns_cancelled_and_channel_stays_usable() -> TestResult {
    let server = MockDnsServer::start(
        Zone::new()
            .a("a.test.", v4(50))
            .a("cancel-one.test.", v4(51))
            .a("cancel-two.test.", v4(52)),
    )?;
    let mut resolver = resolver_for(&server, fast_options(1, Duration::from_millis(500))?)?;
    // Channel-wide cancellation: ares_cancel delivers ARES_ECANCELLED to each
    // pending callback before returning, and the channel remains usable.
    server.set_behavior(Behavior::Delay(Duration::from_millis(300)));
    let statuses: Rc<RefCell<Vec<AresStatus>>> = Rc::new(RefCell::new(Vec::new()));
    let status_sink = Rc::clone(&statuses);
    resolver.submit_query(
        "cancel-one.test.",
        DnsRecordType::A,
        move |_ctx, outcome| {
            status_sink.borrow_mut().push(outcome.status);
        },
    )?;
    resolver
        .cancel()
        .map_err(|error| failure(format!("cancel failed: {error}")))?;
    drive_until(
        &mut resolver,
        Instant::now() + Duration::from_secs(2),
        || !statuses.borrow().is_empty(),
    )?;
    assert_eq!(
        statuses.borrow().as_slice(),
        [AresStatus::Cancelled].as_slice(),
        "channel-wide cancel did not report ARES_ECANCELLED"
    );
    assert_eq!(resolver.active_queries(), 0, "cancelled query still active");
    server.set_behavior(Behavior::Normal);
    let record = query_owned(&mut resolver, "a.test.", DnsRecordType::A, TIMEOUT)?;
    assert_eq!(
        a_address(&record)?,
        v4(50),
        "channel did not recover after cancel()"
    );
    // Logical per-query cancellation: the tombstoned slot must never run user
    // code, while other work on the same channel continues.
    server.set_behavior(Behavior::Delay(Duration::from_millis(300)));
    let invoked = Rc::new(Cell::new(false));
    let invoked_sink = Rc::clone(&invoked);
    let handle = resolver.submit_query(
        "cancel-two.test.",
        DnsRecordType::A,
        move |_ctx, _outcome| {
            invoked_sink.set(true);
        },
    )?;
    resolver
        .cancel_query(handle)
        .map_err(|error| failure(format!("cancel_query failed: {error}")))?;
    // The tombstone may retire the slot immediately while the underlying UDP
    // answer is still in flight, so wait past the mock's delay before judging
    // whether user code ran. wait_completions blocks; the test thread sleeps
    // nowhere.
    let settle_deadline = Instant::now() + Duration::from_millis(700);
    while Instant::now() < settle_deadline {
        resolver.wait_completions(Duration::from_millis(25))?;
    }
    assert!(
        !invoked.get(),
        "cancel_query still invoked the user callback"
    );
    assert_eq!(resolver.active_queries(), 0, "cancelled query still active");
    let mut other = resolver_for(&server, fast_options(1, Duration::from_millis(500))?)?;
    let handle = other.submit_query("a.test.", DnsRecordType::A, |_c, _o| {})?;
    assert!(
        resolver.cancel_query(handle).is_err(),
        "foreign handle accepted"
    );
    other.cancel_query(handle)?;
    drop(other);
    server.set_behavior(Behavior::Normal);
    let record = query_owned(&mut resolver, "a.test.", DnsRecordType::A, TIMEOUT)?;
    assert_eq!(
        a_address(&record)?,
        v4(50),
        "channel did not recover after cancel_query()"
    );
    assert!(
        !resolver.is_poisoned(),
        "logical cancellation poisoned the resolver"
    );
    drop(resolver);
    server.stop();
    Ok(())
}
#[test]
fn reentrant_followup_query_from_callback() -> TestResult {
    let server = MockDnsServer::start(
        Zone::new()
            .cname("alias.test.", "target.test.")
            .a("target.test.", v4(60)),
    )?;
    let mut resolver = resolver_for(&server, fast_options(1, Duration::from_millis(500))?)?;
    let alias_sink: CnameSink = Rc::new(RefCell::new(None));
    let address_sink: AddressSink = Rc::new(RefCell::new(None));
    let submit_error: Rc<RefCell<Option<AresError>>> = Rc::new(RefCell::new(None));
    let alias_out = Rc::clone(&alias_sink);
    let address_out = Rc::clone(&address_sink);
    let error_out = Rc::clone(&submit_error);
    // The outer callback observes a CNAME answer and immediately chains an A
    // query. It only uses ChannelCtx: the &mut Resolver stays on the test thread.
    resolver.submit_query("alias.test.", DnsRecordType::CNAME, move |ctx, outcome| {
        let cname = outcome.record.and_then(|borrowed| {
            let record = borrowed.to_owned_record().ok()?;
            let answer = record.rr(DnsSection::Answer, 0).ok()?;
            answer.as_cname().ok().map(|value| value.cname)
        });
        *alias_out.borrow_mut() = Some((outcome.status, cname));
        if !outcome.status.is_success() {
            return;
        }
        let inner_address = Rc::clone(&address_out);
        let submitted = ctx.submit_query("target.test.", DnsRecordType::A, move |_ctx, outcome| {
            let address = outcome.record.and_then(|borrowed| {
                let record = borrowed.to_owned_record().ok()?;
                let answer = record.rr(DnsSection::Answer, 0).ok()?;
                answer.as_a().ok().map(|value| value.address)
            });
            *inner_address.borrow_mut() = Some((outcome.status, address));
        });
        if let Err(error) = submitted {
            *error_out.borrow_mut() = Some(error);
        }
    })?;
    drive_until(&mut resolver, Instant::now() + TIMEOUT, || {
        (alias_sink.borrow().is_some() && address_sink.borrow().is_some())
            || submit_error.borrow().is_some()
    })?;
    if let Some(error) = submit_error.borrow_mut().take() {
        return Err(failure(format!("reentrant submit_query failed: {error}")));
    }
    let taken = alias_sink.borrow_mut().take();
    let (alias_status, cname) = taken.ok_or_else(|| failure("CNAME callback never ran"))?;
    assert_eq!(alias_status, AresStatus::Success);
    assert_eq!(cname.as_deref(), Some("target.test"));
    let taken = address_sink.borrow_mut().take();
    let (address_status, address) =
        taken.ok_or_else(|| failure("follow-up A callback never ran"))?;
    assert_eq!(address_status, AresStatus::Success);
    assert_eq!(address, Some(v4(60)));
    assert_eq!(
        resolver.active_queries(),
        0,
        "reentrant chain left work pending"
    );
    assert!(
        !resolver.is_poisoned(),
        "reentrant callback poisoned the resolver"
    );
    drop(resolver);
    server.stop();
    Ok(())
}
#[test]
fn panic_poison_and_ten_thousand_query_stress() -> TestResult {
    // A panicking callback must be caught at the FFI boundary and turn the
    // resolver into a poisoned object rather than unwinding through C.
    let server = MockDnsServer::start(Zone::new().a("a.test.", v4(70)))?;
    let mut resolver = resolver_for(&server, fast_options(1, Duration::from_millis(500))?)?;
    let panicked = Rc::new(Cell::new(false));
    let panic_flag = Rc::clone(&panicked);
    resolver.submit_query("a.test.", DnsRecordType::A, move |_ctx, _outcome| {
        panic_flag.set(true);
        panic!("injected callback panic");
    })?;
    let deadline = Instant::now() + TIMEOUT;
    while !panicked.get() {
        if Instant::now() >= deadline {
            return Err(failure("injected callback panic never fired"));
        }
        // A poisoned drive may return Err; the poison flag is the contract.
        let driven = resolver.wait_completions(Duration::from_millis(50));
        assert!(
            driven.is_ok() || resolver.is_poisoned(),
            "drive failed: {driven:?}"
        );
    }
    assert!(resolver.is_poisoned(), "panic did not poison");
    match resolver.submit_query("a.test.", DnsRecordType::A, |_ctx, _outcome| {}) {
        Err(AresError::CallbackPanicked) => {}
        other => {
            return Err(failure(format!(
                "expected CallbackPanicked from a poisoned resolver, got {other:?}"
            )));
        }
    }
    drop(resolver);
    server.stop();
    // Sustained load: ten thousand lookups, at most one hundred in flight. The
    // query cache is left at its disabled default so every submission reaches
    // the wire, which makes the server-side count meaningful.
    let stress_server = MockDnsServer::start(Zone::new().a("stress.test.", v4(80)))?;
    let mut stress = resolver_for(
        &stress_server,
        fast_options(1, Duration::from_millis(1_000))?,
    )?;
    let successes = Rc::new(Cell::new(0usize));
    let failures = Rc::new(Cell::new(0usize));
    const TOTAL: usize = 10_000;
    const BATCH: usize = 100;
    let started = Instant::now();
    let overall_deadline = started + Duration::from_secs(55);
    let mut submitted = 0usize;
    while submitted < TOTAL {
        let batch = BATCH.min(TOTAL - submitted);
        for _ in 0..batch {
            let success_sink = Rc::clone(&successes);
            let failure_sink = Rc::clone(&failures);
            stress.submit_query("stress.test.", DnsRecordType::A, move |_ctx, outcome| {
                if outcome.status.is_success() {
                    success_sink.set(success_sink.get() + 1);
                } else {
                    failure_sink.set(failure_sink.get() + 1);
                }
            })?;
        }
        submitted += batch;
        drive_until(&mut stress, overall_deadline, || {
            successes.get() + failures.get() >= submitted
        })?;
    }
    assert_eq!(
        successes.get(),
        TOTAL,
        "only {} of {} callbacks succeeded ({} failed)",
        successes.get(),
        TOTAL,
        failures.get()
    );
    assert_eq!(failures.get(), 0, "failed completions during stress");
    assert_eq!(
        stress.active_queries(),
        0,
        "queries still active after stress"
    );
    let served = stress_server.udp_queries() + stress_server.tcp_queries();
    assert!(
        served >= TOTAL,
        "server observed {served} queries for {TOTAL} submissions"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "stress run exceeded its budget: {elapsed:?}"
    );
    drop(stress);
    stress_server.stop();
    // The teardown proxy is end to end: after the 10,000-query resolver and its
    // server are gone, a brand-new resolver must still resolve a fresh name.
    let final_server = MockDnsServer::start(Zone::new().a("final.test.", v4(90)))?;
    let mut final_resolver =
        resolver_for(&final_server, fast_options(1, Duration::from_millis(500))?)?;
    let record = query_owned(
        &mut final_resolver,
        "final.test.",
        DnsRecordType::A,
        TIMEOUT,
    )?;
    assert_eq!(
        a_address(&record)?,
        v4(90),
        "a fresh resolver failed after the stress teardown"
    );
    drop(final_resolver);
    final_server.stop();
    Ok(())
}

struct NopSeen {
    seen: Rc<Cell<usize>>,
}

impl liburing::SubsystemHandler for NopSeen {
    fn on_completion(
        &mut self,
        _: liburing::Completion,
        _: &mut liburing::SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        self.seen.set(self.seen.get().saturating_add(1));
        Ok(())
    }
}

#[test]
fn io_uring_proactor_drives_resolver_against_mock() -> TestResult {
    let config = liburing::ProactorConfig {
        entries: 64,
        staged_capacity: 256,
        max_cqe_batch: 64,
        enable_waker: false,
        ..liburing::ProactorConfig::default()
    };
    let mut proactor = match liburing::Proactor::new(config) {
        Ok(proactor) => proactor,
        Err(liburing::UringError::RingInit(errno))
            if matches!(errno.abs(), libc::EPERM | libc::EACCES | libc::ENOSYS) =>
        {
            eprintln!("io_uring unavailable: errno {}", errno.abs());
            return Ok(());
        }
        Err(error) => return Err(failure(format!("proactor init failed: {error}"))),
    };
    let server =
        MockDnsServer::start(Zone::new().a("proactor.test.", Ipv4Addr::new(192, 0, 2, 200)))?;
    server.set_behavior(Behavior::Delay(Duration::from_millis(10)));
    let dns_id = liburing::id::SubsystemId::new(1).ok_or_else(|| failure("dns subsystem id"))?;
    let nop_id = liburing::id::SubsystemId::new(2).ok_or_else(|| failure("nop subsystem id"))?;
    let mut driver = ProactorResolver::new(
        dns_id,
        fast_options(1, Duration::from_secs(2))?,
        &server.servers_csv(),
        8,
    )?;
    let result: ProactorResult = Rc::new(RefCell::new(None));
    let result_sink = Rc::clone(&result);
    driver
        .resolver
        .submit_query("proactor.test.", DnsRecordType::A, move |_ctx, outcome| {
            let record = outcome
                .record
                .map(|record| record.to_owned_record())
                .unwrap_or_else(|| Err(AresError::invalid_record("missing record")));
            *result_sink.borrow_mut() = Some((outcome.status, record));
        })?;
    driver.flush(&mut proactor)?;
    proactor.register_subsystem(dns_id, driver)?;
    let nop_seen = Rc::new(Cell::new(0));
    proactor.register_subsystem(
        nop_id,
        NopSeen {
            seen: Rc::clone(&nop_seen),
        },
    )?;
    let nop_op = liburing::id::OpId::pack(
        nop_id,
        liburing::id::OpPayload::new(1).ok_or_else(|| failure("nop token"))?,
    );
    proactor.prepare_sqe_with(nop_op, |sqe| {
        // SAFETY: The closure owns exclusive initialized SQE storage.
        unsafe { liburing::ops::nop::prep_nop(sqe) };
    })?;
    let timer = liburing::ops::timeout::Timeout::new(Duration::from_millis(2))?;
    let timer_op = liburing::id::OpId::pack(
        nop_id,
        liburing::id::OpPayload::new(2).ok_or_else(|| failure("timer token"))?,
    );
    proactor.prepare_sqe_with(timer_op, |sqe| {
        // SAFETY: `timer` outlives its final CQE or ring shutdown.
        unsafe { timer.prepare(sqe) };
    })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while result.borrow().is_none() && Instant::now() < deadline {
        proactor.wait_completions(8, Some(Duration::from_millis(20)), |_, _| Ok(()))?;
    }
    let (status, record) = result
        .borrow_mut()
        .take()
        .ok_or_else(|| failure("real proactor did not complete the DNS query"))?;
    assert_eq!(status, AresStatus::Success);
    assert_eq!(
        record?.rr(DnsSection::Answer, 0)?.as_a()?.address,
        Ipv4Addr::new(192, 0, 2, 200)
    );
    assert!(
        nop_seen.get() >= 2,
        "expected the NOP and its timer completion, saw {}",
        nop_seen.get()
    );
    proactor.shutdown()?;
    drop(proactor);
    drop(timer);
    server.stop();
    Ok(())
}
