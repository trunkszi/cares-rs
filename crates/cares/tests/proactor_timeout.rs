//! Proves that `Resolver` arms the c-ares deadline on the ring, so a
//! black-holed query times out instead of waiting forever.

use std::{
    cell::Cell,
    error::Error,
    net::UdpSocket,
    rc::Rc,
    time::{Duration, Instant},
};

use cares::{
    Resolver,
    error::{AresError, AresStatus},
    options::ResolverOptions,
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
    let mut driver = Resolver::new(id, options, &csv, 1)?;
    let sink: Rc<Cell<Option<AresStatus>>> = Rc::new(Cell::new(None));
    let captured = Rc::clone(&sink);
    driver.submit_query("blackhole.test.", DnsRecordType::A, move |_, outcome| {
        captured.set(Some(outcome.status));
    })?;
    driver.flush(&mut proactor)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while sink.get().is_none() && Instant::now() < deadline {
        proactor.wait_completions(8, Some(Duration::from_millis(20)), &mut driver)?;
    }
    let status = sink.take().ok_or("no timeout callback")?;
    assert_eq!(status, AresStatus::Timeout, "expected a c-ares timeout");
    match driver.resolve(
        &mut proactor,
        "blackhole-caller-deadline.test.",
        DnsRecordType::A,
        Duration::from_millis(20),
    ) {
        Err(direct_err) => assert_eq!(direct_err.status(), Some(AresStatus::Timeout)),
        Ok(_) => return Err("caller-deadline resolve must time out".into()),
    }
    match driver.resolve(
        &mut proactor,
        "blackhole-resolve.test.",
        DnsRecordType::A,
        Duration::from_millis(250),
    ) {
        Err(direct_err) => assert_eq!(direct_err.status(), Some(AresStatus::Timeout)),
        Ok(_) => return Err("blackholed resolve must time out".into()),
    }
    assert_eq!(driver.active_queries(), 0);
    proactor.shutdown_with(&mut driver)?;
    drop(proactor);
    drop(blackhole);
    Ok(())
}

#[test]
fn resolver_constructors_validate_inputs_and_system_servers() -> TestResult {
    let id = liburing::id::SubsystemId::new(1).ok_or("subsystem id")?;
    assert!(Resolver::new(id, ResolverOptions::default(), "   ", 4).is_err());
    assert!(Resolver::new(id, ResolverOptions::default(), "127.0.0.1:53", 0).is_err());
    assert!(
        Resolver::new(
            liburing::id::SubsystemId::INTERNAL,
            ResolverOptions::default(),
            "127.0.0.1:53",
            4,
        )
        .is_err()
    );
    assert!(Resolver::from_system(id, ResolverOptions::default(), 0).is_err());
    let system = Resolver::from_system(id, ResolverOptions::default(), 4)?;
    assert!(!system.servers_csv()?.trim().is_empty());
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
    let id = liburing::id::SubsystemId::new(1).ok_or("subsystem id")?;
    let mut resolver = Resolver::new(
        id,
        ResolverOptions::builder().build()?,
        &format!("127.0.0.1:{}", blackhole.local_addr()?.port()),
        1,
    )?;
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
