//! Proves that `ProactorResolver` arms the c-ares deadline on the ring, so a
//! black-holed query times out instead of waiting forever.

use std::{
    cell::RefCell,
    error::Error,
    net::UdpSocket,
    rc::Rc,
    time::{Duration, Instant},
};

use cares::{
    ProactorResolver,
    error::{AresError, AresStatus},
    options::ResolverOptions,
    resolver::Resolver,
    socket_bridge::{ReadinessSink, SocketInterest},
    types::DnsRecordType,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn proactor_armed_timer_expires_a_blackholed_query() -> TestResult {
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
            return Ok(());
        }
        Err(error) => return Err(Box::<dyn Error>::from(format!("proactor init: {error}"))),
    };
    // Bound but never read: the query can only end through the c-ares timeout.
    let blackhole = UdpSocket::bind(("127.0.0.1", 0))?;
    let csv = format!("127.0.0.1:{}", blackhole.local_addr()?.port());
    let options = ResolverOptions::builder()
        .tries(1)
        .timeout(Duration::from_millis(100))
        .query_cache_ttl(Duration::ZERO)
        .build()?;
    let id = liburing::id::SubsystemId::new(1).ok_or("subsystem id")?;
    let mut driver = ProactorResolver::new(id, options, &csv, 1)?;
    let sink: Rc<RefCell<Option<AresStatus>>> = Rc::new(RefCell::new(None));
    let captured = Rc::clone(&sink);
    driver
        .resolver
        .submit_query("blackhole.test.", DnsRecordType::A, move |_, outcome| {
            *captured.borrow_mut() = Some(outcome.status);
        })?;
    driver.flush(&mut proactor)?;
    proactor.register_subsystem(id, driver)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while sink.borrow().is_none() && Instant::now() < deadline {
        proactor.wait_completions(8, Some(Duration::from_millis(20)), |_, _| Ok(()))?;
    }
    let status = sink.borrow_mut().take().ok_or("no timeout callback")?;
    assert_eq!(status, AresStatus::Timeout, "expected a c-ares timeout");
    proactor.shutdown()?;
    drop(proactor);
    drop(blackhole);
    Ok(())
}

struct PanickingSink;

impl ReadinessSink for PanickingSink {
    fn update_interest(&self, _fd: libc::c_int, _interest: SocketInterest) {
        panic!("readiness notification failed");
    }

    fn remove_interest(&self, _fd: libc::c_int) {}
}

#[test]
fn readiness_sink_panic_poison_gates_deadlines_and_channel_operations() -> TestResult {
    let blackhole = UdpSocket::bind(("127.0.0.1", 0))?;
    let mut resolver = Resolver::new(ResolverOptions::builder().build()?)?;
    resolver.set_servers_csv(&format!("127.0.0.1:{}", blackhole.local_addr()?.port()))?;
    resolver.install_readiness_sink(Rc::new(PanickingSink))?;
    assert!(matches!(
        resolver.submit_query("sink-panic.test.", DnsRecordType::A, |_, _| {}),
        Err(AresError::CallbackPanicked)
    ));
    assert!(resolver.is_poisoned());
    assert!(matches!(
        resolver.timer_deadline(),
        Err(AresError::CallbackPanicked)
    ));
    assert!(matches!(
        resolver.poll_completions(),
        Err(AresError::CallbackPanicked)
    ));
    assert!(matches!(
        resolver.servers_csv(),
        Err(AresError::CallbackPanicked)
    ));
    assert!(matches!(
        resolver.cancel(),
        Err(AresError::CallbackPanicked)
    ));
    assert!(matches!(
        resolver.submit_query("second.test.", DnsRecordType::A, |_, _| {}),
        Err(AresError::CallbackPanicked)
    ));
    Ok(())
}
