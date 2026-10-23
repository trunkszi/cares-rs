//! One shared io_uring ring drives a c-ares resolver and a heartbeat subsystem.
//!
//! A deterministic localhost responder answers the first UDP query with `TC=1`
//! and no records; c-ares then retries the query over TCP, where the full `A`
//! record is available. `ProactorResolver` reserves one DNS poll slot initially;
//! TCP fallback grows the caller-owned table for the second descriptor.
//!
//! `ProactorResolver::flush` also arms the c-ares deadline as an
//! `IORING_OP_TIMEOUT` on the same ring. The heartbeat subsystem re-arms a NOP
//! from inside its completion handler, so both subsystems make progress in one
//! `Proactor::wait_completions` loop. The responder threads are the only
//! threads in this example; the ring owner never sleeps.

use std::{
    cell::Cell,
    io::{self, ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use cares::{
    ARecord, DnsClass, DnsRecord, DnsRecordType, DnsSection, ProactorResolver,
    error::{AresError, AresStatus},
    options::ResolverOptions,
    types::{DnsFlags, DnsOpcode, DnsRcode},
};
use liburing::{
    Completion, CompletionDispatcher, OperationId, OperationPayload, Proactor, SubmissionContext,
    SubsystemId, UringError,
};
use liburing_macros::define_subsystems;

define_subsystems! {
    pub enum DemoSubsystems {
        Dns = 1,
        Heartbeat = 2,
    }
}

/// Name answered by the embedded responder.
const QUERY_NAME: &str = "proactor.test.";
/// Address returned by the TCP answer and by later UDP answers.
const ANSWER_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 77);
const ANSWER_TTL: u32 = 60;
/// The DNS poll table grows past this reservation for the TCP descriptor.
const BRIDGE_CAPACITY: usize = 1;
/// Bound on re-armed completions, which makes the reported tick count exact.
const HEARTBEAT_TICKS: usize = 8;
const UDP_BUFFER_SIZE: usize = 65_535;
const UDP_POLL_TIMEOUT: Duration = Duration::from_millis(100);
const TCP_READ_TIMEOUT: Duration = Duration::from_millis(500);
const TCP_ACCEPT_POLL: Duration = Duration::from_millis(10);
const DRIVE_BUDGET: Duration = Duration::from_secs(10);
const COMPLETION_WAIT: Duration = Duration::from_millis(20);

type AnswerSlot = Rc<Cell<Option<(AresStatus, Result<DnsRecord, AresError>)>>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = liburing::ProactorConfig {
        entries: 64,
        staged_capacity: 256,
        max_cqe_batch: 64,
        ..liburing::ProactorConfig::default()
    };
    // A real shared-ring run is the point of this example; a host without
    // io_uring must fail rather than report a silent skip.
    let mut proactor =
        Proactor::new(config).map_err(|error| format!("proactor init failed: {error}"))?;

    let responder = DnsResponder::start()?;
    let options = ResolverOptions::builder()
        .tries(1)
        .timeout(Duration::from_secs(2))
        .query_cache_ttl(Duration::ZERO)
        .build()?;
    let dns_id = SubsystemId::new(DemoSubsystems::Dns.id()).ok_or("dns subsystem id")?;
    let heartbeat_id =
        SubsystemId::new(DemoSubsystems::Heartbeat.id()).ok_or("heartbeat subsystem id")?;
    let mut driver =
        ProactorResolver::new(dns_id, options, &responder.servers_csv(), BRIDGE_CAPACITY)?;

    // The caller retains the resolver while flush stages its socket interests
    // and retry deadline on the ring.
    let answer: AnswerSlot = Rc::new(Cell::new(None));
    let sink = Rc::clone(&answer);
    driver
        .resolver
        .submit_query(QUERY_NAME, DnsRecordType::A, move |_ctx, outcome| {
            let record = outcome
                .record
                .map(|record| record.to_owned_record())
                .unwrap_or_else(|| {
                    Err(AresError::invalid_record(
                        "completion carried no DNS record",
                    ))
                });
            sink.set(Some((outcome.status, record)));
        })?;
    driver.flush(&mut proactor)?;
    println!(
        "resolver deadline: ProactorResolver::flush arms the c-ares deadline on the shared ring \
         as an io_uring timeout on subsystem {}",
        dns_id.raw()
    );

    let ticks = Rc::new(Cell::new(0usize));
    let heartbeat_op = OperationId::pack(
        heartbeat_id,
        OperationPayload::new(1).ok_or("heartbeat payload")?,
    );
    let mut heartbeat = HeartbeatHandler {
        operation_id: heartbeat_op,
        ticks: Rc::clone(&ticks),
        target: HEARTBEAT_TICKS,
    };
    proactor.prepare_sqe_with(heartbeat_op, |sqe| {
        // SAFETY: The proactor provides exclusive zeroed SQE storage for this
        // call, and a NOP references no external memory.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;

    let mut completed = None;
    let drive_deadline = Instant::now() + DRIVE_BUDGET;
    while (completed.is_none() || ticks.get() < HEARTBEAT_TICKS) && Instant::now() < drive_deadline
    {
        let mut dispatch = |completion: Completion, submissions: &mut SubmissionContext<'_>| {
            if completion.operation_id.subsystem_id() == dns_id {
                driver.dispatch(completion, submissions)
            } else {
                heartbeat.dispatch(completion, submissions)
            }
        };
        proactor.wait_completions(1, Some(COMPLETION_WAIT), &mut dispatch)?;
        if completed.is_none() {
            completed = answer.take();
        }
    }

    if completed.is_none() {
        return Err(format!("dns query did not complete within {DRIVE_BUDGET:?}").into());
    }
    if ticks.get() != HEARTBEAT_TICKS {
        return Err(format!(
            "heartbeat stopped after {} of {HEARTBEAT_TICKS} completions",
            ticks.get()
        )
        .into());
    }
    let (status, record) = completed.take().ok_or("dns query produced no completion")?;
    if status != AresStatus::Success {
        return Err(format!("dns query finished with status {status:?}").into());
    }
    let address = record?.rr(DnsSection::Answer, 0)?.as_a()?.address;
    if address != ANSWER_ADDRESS {
        return Err(format!("unexpected answer address {address}").into());
    }

    let udp_queries = responder.udp_queries();
    let tcp_queries = responder.tcp_queries();
    if udp_queries < 1 || tcp_queries < 1 {
        return Err(format!(
            "expected UDP and TCP queries, saw udp={udp_queries} tcp={tcp_queries}"
        )
        .into());
    }
    let heartbeat_ticks = ticks.get();

    let mut dispatch = |completion: Completion, submissions: &mut SubmissionContext<'_>| {
        if completion.operation_id.subsystem_id() == dns_id {
            driver.dispatch(completion, submissions)
        } else {
            heartbeat.dispatch(completion, submissions)
        }
    };
    proactor.shutdown_with(&mut dispatch)?;
    drop(proactor);
    responder.stop();

    println!("answer={address}");
    println!("udp_queries={udp_queries}");
    println!("tcp_queries={tcp_queries}");
    println!("heartbeat_ticks={heartbeat_ticks}");
    println!(
        "bridge: capacity {BRIDGE_CAPACITY} grew to 2 descriptors across the UDP-to-TCP fallback"
    );
    Ok(())
}

/// Re-arms one NOP per completion until `target` completions have been seen.
///
/// The bound keeps the reported tick count exact; a busy NOP chain would
/// otherwise make it depend on how quickly the DNS query finishes.
struct HeartbeatHandler {
    operation_id: OperationId,
    ticks: Rc<Cell<usize>>,
    target: usize,
}

impl CompletionDispatcher for HeartbeatHandler {
    fn dispatch(
        &mut self,
        _completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        let next = self.ticks.get().saturating_add(1);
        self.ticks.set(next);
        if next >= self.target {
            return Ok(());
        }
        match submissions.prepare_sqe_with(self.operation_id, |sqe| {
            // SAFETY: The submission context provides exclusive zeroed SQE
            // storage for this call, and a NOP references no external memory.
            unsafe { liburing::ops::prep_nop(sqe) };
        }) {
            Ok(()) | Err(UringError::SqRingFull) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Counters shared by the responder workers and the ring-owning thread.
struct ResponderState {
    stop: AtomicBool,
    first_udp: AtomicBool,
    udp_queries: AtomicUsize,
    tcp_queries: AtomicUsize,
}

impl ResponderState {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

/// Deterministic UDP and TCP DNS responder bound to independent localhost ports.
struct DnsResponder {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    state: Arc<ResponderState>,
    udp_thread: Option<JoinHandle<()>>,
    tcp_thread: Option<JoinHandle<()>>,
}

impl DnsResponder {
    fn start() -> io::Result<Self> {
        let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp_socket.set_read_timeout(Some(UDP_POLL_TIMEOUT))?;
        tcp_listener.set_nonblocking(true)?;
        let udp_addr = udp_socket.local_addr()?;
        let tcp_addr = tcp_listener.local_addr()?;
        let state = Arc::new(ResponderState {
            stop: AtomicBool::new(false),
            first_udp: AtomicBool::new(true),
            udp_queries: AtomicUsize::new(0),
            tcp_queries: AtomicUsize::new(0),
        });
        let udp_thread = thread::Builder::new()
            .name(String::from("example-dns-udp"))
            .spawn({
                let state = Arc::clone(&state);
                move || udp_loop(udp_socket, state)
            })?;
        let tcp_thread = match thread::Builder::new()
            .name(String::from("example-dns-tcp"))
            .spawn({
                let state = Arc::clone(&state);
                move || tcp_loop(tcp_listener, state)
            }) {
            Ok(handle) => handle,
            Err(error) => {
                state.stop.store(true, Ordering::SeqCst);
                drop(udp_thread.join());
                return Err(error);
            }
        };
        Ok(Self {
            udp_addr,
            tcp_addr,
            state,
            udp_thread: Some(udp_thread),
            tcp_thread: Some(tcp_thread),
        })
    }

    /// The c-ares URI form, so TCP uses the responder's independent TCP port.
    fn servers_csv(&self) -> String {
        format!(
            "dns://127.0.0.1:{}?tcpport={}",
            self.udp_addr.port(),
            self.tcp_addr.port()
        )
    }

    fn udp_queries(&self) -> usize {
        self.state.udp_queries.load(Ordering::Acquire)
    }

    fn tcp_queries(&self) -> usize {
        self.state.tcp_queries.load(Ordering::Acquire)
    }

    /// Stops both workers and waits for them.
    fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        for handle in [self.udp_thread.take(), self.tcp_thread.take()]
            .into_iter()
            .flatten()
        {
            // A worker panic must not mask the driving thread's own result.
            drop(handle.join());
        }
    }
}

impl Drop for DnsResponder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn udp_loop(socket: UdpSocket, state: Arc<ResponderState>) {
    let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
    while !state.stopping() {
        let (length, peer) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if is_timeout(&error) => continue,
            Err(_) => return,
        };
        state.udp_queries.fetch_add(1, Ordering::Relaxed);
        let truncated = state.first_udp.swap(false, Ordering::AcqRel);
        let Some(response) = respond(&buffer[..length], truncated) else {
            continue;
        };
        if socket.send_to(&response, peer).is_err() {
            return;
        }
    }
}

fn tcp_loop(listener: TcpListener, state: Arc<ResponderState>) {
    while !state.stopping() {
        match listener.accept() {
            Ok((stream, _peer)) => serve_tcp(stream, &state),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                // The responder is a separate thread; the ring owner never waits here.
                thread::park_timeout(TCP_ACCEPT_POLL);
            }
            Err(_) => return,
        }
    }
}

fn serve_tcp(mut stream: TcpStream, state: &ResponderState) {
    if stream.set_nonblocking(false).is_err()
        || stream.set_read_timeout(Some(TCP_READ_TIMEOUT)).is_err()
    {
        return;
    }
    loop {
        if state.stopping() {
            return;
        }
        let mut prefix = [0u8; 2];
        // `read_exact` reassembles a prefix or body split across writes.
        match stream.read_exact(&mut prefix) {
            Ok(()) => {}
            Err(error) if is_timeout(&error) => continue,
            Err(_) => return,
        }
        let length = usize::from(u16::from_be_bytes(prefix));
        if length == 0 {
            return;
        }
        let mut message = vec![0u8; length];
        if stream.read_exact(&mut message).is_err() {
            return;
        }
        state.tcp_queries.fetch_add(1, Ordering::Relaxed);
        let Some(response) = respond(&message, false) else {
            continue;
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

/// Builds a response that echoes the query identifier and question.
///
/// The first UDP request gets `TC=1` and no answers, which is the signal that
/// makes c-ares retry over TCP. Every other response includes the `A` record.
fn respond(query_wire: &[u8], truncated: bool) -> Option<Vec<u8>> {
    let query = DnsRecord::parse_wire(query_wire).ok()?;
    if query.query_count() == 0 {
        return None;
    }
    let question = query.question(0).ok()?;
    let mut flags = DnsFlags::QR | DnsFlags::RD | DnsFlags::RA;
    if truncated {
        flags |= DnsFlags::TC;
    }
    let mut response = DnsRecord::builder()
        .id(query.id())
        .flags(flags)
        .opcode(DnsOpcode::Query)
        .rcode(DnsRcode::NoError)
        .question(question.name, question.record_type, question.class)
        .build()
        .ok()?;
    if !truncated {
        response
            .add_record(
                DnsSection::Answer,
                question.name,
                DnsClass::IN,
                ANSWER_TTL,
                &ARecord {
                    address: ANSWER_ADDRESS,
                },
            )
            .ok()?;
    }
    response.write_wire().ok()
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}
