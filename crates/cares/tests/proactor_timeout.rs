//! Proves that `ProactorResolver` arms the c-ares deadline on the ring, so a
//! black-holed query times out instead of waiting forever.

use std::{
    cell::RefCell,
    error::Error,
    net::UdpSocket,
    rc::Rc,
    time::{Duration, Instant},
};

use cares::{ProactorResolver, error::AresStatus, options::ResolverOptions, types::DnsRecordType};

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
