//! Standalone, offline resolution against an in-process DNS responder.
//!
//! The responder binds UDP and TCP listeners on separate `127.0.0.1:0` ports and
//! answers only the questions declared in this example's query table. One
//! threadless [`Resolver`] is pointed at both ports through the c-ares server URI
//! form and driven entirely by [`Resolver::wait_completions`].
//!
//! The printed records cover the `DnsRecordExtract` derive (`A`), the typed record
//! models (`AAAA`, `TXT`, `SRV`), a reentrant `CNAME -> A` chain submitted from the
//! first callback through [`cares::ChannelCtx::submit_query`], and one `A` lookup
//! carried over TCP.

#![forbid(unsafe_code)]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use cares::{
    DnsRecordExtract, LibraryGuard, Resolver,
    error::AresError,
    options::ResolverOptions,
    record::{DnsRecord, DnsRecordRef, FromDnsRecord},
    record_rr::{ARecord, AaaaRecord, CnameRecord, SrvRecord, TxtRecord},
    resolver::QueryOutcome,
    types::{DnsClass, DnsFlags, DnsRecordType, DnsSection},
};

/// A fixed TTL keeps the printed values stable across runs.
const ANSWER_TTL: u32 = 60;
const A_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const AAAA_ADDRESS: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10);
const SRV_TARGET: &str = "srv-target.test";

const UDP_BUFFER_SIZE: usize = 65_535;
const UDP_POLL_TIMEOUT: Duration = Duration::from_millis(50);
const TCP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const QUERY_TIMEOUT: Duration = Duration::from_millis(500);
const WAIT_SLICE: Duration = Duration::from_millis(25);
const DRIVE_BUDGET: Duration = Duration::from_secs(5);

/// Five outer completions plus the follow-up submitted from the `CNAME` callback.
const EXPECTED_FINDINGS: usize = 6;

type ExampleResult = Result<(), Box<dyn std::error::Error>>;

/// One rendered completion per key; the error side is already formatted text.
type Findings = Rc<RefCell<BTreeMap<&'static str, Result<String, String>>>>;

/// Fixed print order, independent of completion order.
const FINDING_ORDER: [(&str, &str); EXPECTED_FINDINGS] = [
    ("a", "a.test A"),
    ("aaaa", "aaaa.test AAAA"),
    ("txt", "txt.test TXT"),
    ("srv", "srv.test SRV"),
    ("alias", "alias.test CNAME"),
    ("alias_address", "alias.test -> a.test A (reentrant)"),
];

cares::cares_query_table! {
    enum Queries {
        web_a { name: "a.test", rr_type: A, class: IN },
        web_aaaa { name: "aaaa.test", rr_type: AAAA, class: IN },
        web_txt { name: "txt.test", rr_type: TXT, class: IN },
        web_srv { name: "srv.test", rr_type: SRV, class: IN },
        alias_cname { name: "alias.test", rr_type: CNAME, class: IN },
    }
}

/// Decoded through the derive; `owner`, `ttl`, and `dns_class` come from the RR
/// itself rather than from the record model.
#[derive(DnsRecordExtract)]
#[dns(rr_type = "A", section = "Answer")]
struct Host {
    address: Ipv4Addr,
    owner: String,
    ttl: u32,
    dns_class: DnsClass,
}

fn main() -> ExampleResult {
    // Held for the whole run; each `Resolver::new` adds its own library reference.
    let _library = LibraryGuard::acquire()?;
    let responder = Responder::start()?;
    let outcome = run(&responder);
    let udp_queries = responder.udp_queries();
    let tcp_queries = responder.tcp_queries();
    // Shut the workers down before reporting, so the counts are final.
    let shutdown = responder.stop();
    outcome?;
    shutdown?;
    println!("responder: udp_queries={udp_queries} tcp_queries={tcp_queries}");
    Ok(())
}

fn run(responder: &Responder) -> ExampleResult {
    print_query_table()?;
    let findings: Findings = Rc::new(RefCell::new(BTreeMap::new()));
    {
        let mut resolver = resolver_for(responder, false)?;
        submit_typed(&mut resolver, Queries::WebA, "a", &findings, parse_a)?;
        submit_typed(
            &mut resolver,
            Queries::WebAaaa,
            "aaaa",
            &findings,
            parse_aaaa,
        )?;
        submit_typed(&mut resolver, Queries::WebTxt, "txt", &findings, parse_txt)?;
        submit_typed(&mut resolver, Queries::WebSrv, "srv", &findings, parse_srv)?;
        submit_cname_chain(&mut resolver, &findings)?;
        drive_until(&mut resolver, &findings, EXPECTED_FINDINGS)?;
    }
    for (key, label) in FINDING_ORDER {
        print_finding(&findings, key, label)?;
    }
    run_tcp_query(responder)
}

fn resolver_for(
    responder: &Responder,
    use_tcp: bool,
) -> Result<Resolver, Box<dyn std::error::Error>> {
    let options = ResolverOptions::builder()
        .tries(1)
        .timeout(QUERY_TIMEOUT)
        .query_cache_ttl(Duration::ZERO)
        // Search-domain expansion would send questions the responder never
        // answers, so the example would depend on the host's resolv.conf.
        .no_search(true)
        .use_tcp(use_tcp)
        .build()?;
    let mut resolver = Resolver::new(options)?;
    let csv = responder.servers_csv();
    resolver.set_servers_csv(&csv)?;
    Ok(resolver)
}

/// Validates the generated table against its slots and prints the routing metadata.
fn print_query_table() -> ExampleResult {
    const SLOTS: [Queries; 5] = [
        Queries::WebA,
        Queries::WebAaaa,
        Queries::WebTxt,
        Queries::WebSrv,
        Queries::AliasCname,
    ];
    if SLOTS.len() != Queries::SLOT_COUNT || Queries::dispatch().len() != Queries::SLOT_COUNT {
        return Err(io::Error::other("query table slot count disagrees with its slots").into());
    }
    println!("query table: {} slots", Queries::SLOT_COUNT);
    for (slot, metadata) in SLOTS.iter().zip(Queries::DISPATCH) {
        if slot.slot_name() != metadata.name
            || slot.qname() != metadata.qname
            || slot.rr_type() != metadata.rr_type
            || slot.dns_class() != metadata.dns_class
        {
            return Err(io::Error::other("query table metadata disagrees with its slot").into());
        }
        println!(
            "  {} -> {} type={} class={}",
            metadata.name, metadata.qname, metadata.rr_type, metadata.dns_class
        );
    }
    let mut buffer = [0u8; 512];
    for slot in SLOTS {
        let length = slot.encode(0x4242, &mut buffer).map_err(io::Error::other)?;
        let decoded = Queries::decode(&buffer[..length]).map_err(io::Error::other)?;
        if decoded != slot {
            return Err(io::Error::other("encoded question did not decode to its slot").into());
        }
    }
    println!(
        "query table encode/decode round trip: {} slots",
        SLOTS.len()
    );
    Ok(())
}

fn submit_typed(
    resolver: &mut Resolver,
    slot: Queries,
    key: &'static str,
    findings: &Findings,
    parse: fn(DnsRecordRef<'_>) -> Result<String, AresError>,
) -> Result<(), AresError> {
    let record_type = DnsRecordType::try_from(slot.rr_type())?;
    let sink = Rc::clone(findings);
    resolver.submit_query(slot.qname(), record_type, move |_ctx, outcome| {
        let value = borrowed_record(&outcome).and_then(parse);
        sink.borrow_mut()
            .insert(key, value.map_err(|error| error.to_string()));
    })?;
    Ok(())
}

/// Queries the alias as `CNAME`, so c-ares returns the alias instead of chasing it,
/// then issues the `A` question for the target through `ChannelCtx`.
fn submit_cname_chain(resolver: &mut Resolver, findings: &Findings) -> Result<(), AresError> {
    let record_type = DnsRecordType::try_from(Queries::AliasCname.rr_type())?;
    let sink = Rc::clone(findings);
    resolver.submit_query(
        Queries::AliasCname.qname(),
        record_type,
        move |ctx, outcome| {
            let alias = borrowed_record(&outcome).and_then(parse_cname);
            let rendered = match &alias {
                Ok(cname) => format!("target={cname}"),
                Err(error) => error.to_string(),
            };
            sink.borrow_mut().insert("alias", Ok(rendered));
            let Ok(cname) = alias else {
                return;
            };
            let follow_up = Rc::clone(&sink);
            let submitted = ctx.submit_query(&cname, DnsRecordType::A, move |_ctx, outcome| {
                let value = borrowed_record(&outcome).and_then(parse_a_address);
                follow_up
                    .borrow_mut()
                    .insert("alias_address", value.map_err(|error| error.to_string()));
            });
            if let Err(error) = submitted {
                sink.borrow_mut().insert(
                    "alias_address",
                    Err(format!("follow-up submission failed: {error}")),
                );
            }
        },
    )?;
    Ok(())
}

fn drive_until(resolver: &mut Resolver, findings: &Findings, expected: usize) -> ExampleResult {
    let Some(deadline) = Instant::now().checked_add(DRIVE_BUDGET) else {
        return Err(io::Error::other("completion deadline overflow").into());
    };
    loop {
        let completed = findings.borrow().len();
        if completed >= expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "{completed} of {expected} completions arrived within {DRIVE_BUDGET:?}"
            ))
            .into());
        }
        resolver.wait_completions(WAIT_SLICE)?;
    }
}

fn print_finding(findings: &Findings, key: &str, label: &str) -> ExampleResult {
    let value = findings
        .borrow()
        .get(key)
        .cloned()
        .ok_or_else(|| io::Error::other(format!("no completion recorded for {label}")))?;
    let text = value.map_err(|message| io::Error::other(format!("{label} failed: {message}")))?;
    println!("{label}: {text}");
    Ok(())
}

fn run_tcp_query(responder: &Responder) -> ExampleResult {
    let mut resolver = resolver_for(responder, true)?;
    let findings: Findings = Rc::new(RefCell::new(BTreeMap::new()));
    submit_typed(
        &mut resolver,
        Queries::WebA,
        "tcp_a",
        &findings,
        parse_a_address,
    )?;
    drive_until(&mut resolver, &findings, 1)?;
    print_finding(&findings, "tcp_a", "a.test A over TCP")
}

fn borrowed_record<'cb>(outcome: &QueryOutcome<'cb>) -> Result<DnsRecordRef<'cb>, AresError> {
    if !outcome.status.is_success() {
        return Err(AresError::from_status(outcome.status));
    }
    outcome
        .record
        .ok_or_else(|| AresError::invalid_record("completion carried no DNS record"))
}

fn parse_a(record: DnsRecordRef<'_>) -> Result<String, AresError> {
    let owned = record.to_owned_record()?;
    let host = Host::from_dns_record(owned.as_ref())?;
    let matching = Host::extract_from_record(owned.as_ref())?;
    if matching.len() != 1 {
        return Err(AresError::invalid_record(format!(
            "expected exactly one derived A record, found {}",
            matching.len()
        )));
    }
    if Host::RR_TYPE_CODE != Queries::WebA.rr_type() {
        return Err(AresError::invalid_record(
            "derived A record type disagrees with the query table",
        ));
    }
    Ok(format!(
        "owner={} ttl={} class={} address={}",
        host.owner,
        host.ttl,
        host.dns_class.as_raw(),
        host.address
    ))
}

fn parse_aaaa(record: DnsRecordRef<'_>) -> Result<String, AresError> {
    let answers = record.records::<AaaaRecord>(DnsSection::Answer)?;
    Ok(exactly_one(&answers, "AAAA")?.address.to_string())
}

fn parse_txt(record: DnsRecordRef<'_>) -> Result<String, AresError> {
    let answers = record.records::<TxtRecord>(DnsSection::Answer)?;
    let text = exactly_one(&answers, "TXT")?;
    let chunks = text
        .chunks
        .iter()
        .map(|chunk| format!("{:?}", String::from_utf8_lossy(chunk)))
        .collect::<Vec<_>>();
    Ok(chunks.join(" "))
}

fn parse_srv(record: DnsRecordRef<'_>) -> Result<String, AresError> {
    let answers = record.records::<SrvRecord>(DnsSection::Answer)?;
    let service = exactly_one(&answers, "SRV")?;
    Ok(format!(
        "priority={} weight={} port={} target={}",
        service.priority, service.weight, service.port, service.target
    ))
}

fn parse_cname(record: DnsRecordRef<'_>) -> Result<String, AresError> {
    let answers = record.records::<CnameRecord>(DnsSection::Answer)?;
    Ok(exactly_one(&answers, "CNAME")?.cname)
}

fn parse_a_address(record: DnsRecordRef<'_>) -> Result<String, AresError> {
    let answers = record.records::<ARecord>(DnsSection::Answer)?;
    Ok(exactly_one(&answers, "A")?.address.to_string())
}

fn exactly_one<T: Clone>(values: &[T], kind: &str) -> Result<T, AresError> {
    match values {
        [value] => Ok(value.clone()),
        _ => Err(AresError::invalid_record(format!(
            "expected exactly one {kind} record, found {}",
            values.len()
        ))),
    }
}

/// Deterministic in-process DNS responder; it answers only the table's questions.
struct Responder {
    udp_port: u16,
    tcp_port: u16,
    stop: Arc<AtomicBool>,
    udp_queries: Arc<AtomicUsize>,
    tcp_queries: Arc<AtomicUsize>,
    workers: Vec<JoinHandle<()>>,
}

impl Responder {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp.set_read_timeout(Some(UDP_POLL_TIMEOUT))?;
        tcp.set_nonblocking(true)?;
        let udp_port = udp.local_addr()?.port();
        let tcp_port = tcp.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let udp_queries = Arc::new(AtomicUsize::new(0));
        let tcp_queries = Arc::new(AtomicUsize::new(0));
        let udp_worker = thread::Builder::new()
            .name(String::from("example-dns-udp"))
            .spawn({
                let stop = Arc::clone(&stop);
                let udp_queries = Arc::clone(&udp_queries);
                move || serve_udp(udp, &stop, &udp_queries)
            })?;
        let tcp_worker = match thread::Builder::new()
            .name(String::from("example-dns-tcp"))
            .spawn({
                let stop = Arc::clone(&stop);
                let tcp_queries = Arc::clone(&tcp_queries);
                move || serve_tcp(tcp, &stop, &tcp_queries)
            }) {
            Ok(worker) => worker,
            Err(error) => {
                stop.store(true, Ordering::Release);
                drop(udp_worker.join());
                return Err(Box::new(error));
            }
        };
        Ok(Self {
            udp_port,
            tcp_port,
            stop,
            udp_queries,
            tcp_queries,
            workers: vec![udp_worker, tcp_worker],
        })
    }

    /// c-ares URI form: UDP on the named port, TCP on `tcpport`.
    fn servers_csv(&self) -> String {
        format!(
            "dns://127.0.0.1:{}?tcpport={}",
            self.udp_port, self.tcp_port
        )
    }

    fn udp_queries(&self) -> usize {
        self.udp_queries.load(Ordering::Acquire)
    }

    fn tcp_queries(&self) -> usize {
        self.tcp_queries.load(Ordering::Acquire)
    }

    fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            worker
                .join()
                .map_err(|_| io::Error::other("a responder worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            // The explicit `stop` path reports a worker panic; teardown via `Drop`
            // must not mask an earlier error with a second one.
            drop(worker.join());
        }
    }
}

fn serve_udp(socket: UdpSocket, stop: &AtomicBool, queries: &AtomicUsize) {
    let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
    while !stop.load(Ordering::Acquire) {
        let (length, peer) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if is_timeout(&error) => continue,
            Err(_) => return,
        };
        queries.fetch_add(1, Ordering::Relaxed);
        let Some(response) = response_for(&buffer[..length]) else {
            // Questions outside the table are dropped, not answered.
            continue;
        };
        if socket.send_to(&response, peer).is_err() {
            return;
        }
    }
}

fn serve_tcp(listener: TcpListener, stop: &AtomicBool, queries: &AtomicUsize) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => serve_tcp_connection(stream, stop, queries),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::park_timeout(ACCEPT_POLL_INTERVAL);
            }
            Err(_) => return,
        }
    }
}

/// RFC 1035 TCP framing: a two-byte big-endian length precedes each message.
fn serve_tcp_connection(mut stream: TcpStream, stop: &AtomicBool, queries: &AtomicUsize) {
    if stream.set_read_timeout(Some(TCP_READ_TIMEOUT)).is_err() {
        return;
    }
    while !stop.load(Ordering::Acquire) {
        let mut prefix = [0u8; 2];
        if stream.read_exact(&mut prefix).is_err() {
            return;
        }
        let length = usize::from(u16::from_be_bytes(prefix));
        if length == 0 {
            return;
        }
        let mut message = vec![0u8; length];
        if stream.read_exact(&mut message).is_err() {
            return;
        }
        queries.fetch_add(1, Ordering::Relaxed);
        let Some(response) = response_for(&message) else {
            return;
        };
        let Ok(frame_length) = u16::try_from(response.len()) else {
            return;
        };
        let mut frame = Vec::with_capacity(response.len() + 2);
        frame.extend_from_slice(&frame_length.to_be_bytes());
        frame.extend_from_slice(&response);
        if stream.write_all(&frame).is_err() {
            return;
        }
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn response_for(request: &[u8]) -> Option<Vec<u8>> {
    let parsed = DnsRecord::parse_wire(request).ok()?;
    let question = parsed.question(0).ok()?;
    let slot = Queries::decode(request).ok()?;
    let mut response = DnsRecord::builder()
        .id(parsed.id())
        .flags(DnsFlags::QR | DnsFlags::RD | DnsFlags::RA)
        .question(question.name, question.record_type, question.class)
        .build()
        .ok()?;
    let added = match slot {
        Queries::WebA => response.add_record(
            DnsSection::Answer,
            question.name,
            DnsClass::IN,
            ANSWER_TTL,
            &ARecord { address: A_ADDRESS },
        ),
        Queries::WebAaaa => response.add_record(
            DnsSection::Answer,
            question.name,
            DnsClass::IN,
            ANSWER_TTL,
            &AaaaRecord {
                address: AAAA_ADDRESS,
            },
        ),
        Queries::WebTxt => response.add_record(
            DnsSection::Answer,
            question.name,
            DnsClass::IN,
            ANSWER_TTL,
            &TxtRecord {
                chunks: txt_chunks(),
            },
        ),
        Queries::WebSrv => response.add_record(
            DnsSection::Answer,
            question.name,
            DnsClass::IN,
            ANSWER_TTL,
            &SrvRecord {
                priority: 1,
                weight: 5,
                port: 8443,
                target: String::from(SRV_TARGET),
            },
        ),
        Queries::AliasCname => response.add_record(
            DnsSection::Answer,
            question.name,
            DnsClass::IN,
            ANSWER_TTL,
            &CnameRecord {
                cname: String::from(Queries::WebA.qname()),
            },
        ),
    };
    added.ok()?;
    response.write_wire().ok()
}

fn txt_chunks() -> Vec<Vec<u8>> {
    vec![b"hello".to_vec(), b"world".to_vec()]
}
