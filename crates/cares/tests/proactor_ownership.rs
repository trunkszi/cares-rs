//! Completion provenance must precede any DNS registration retirement.
use std::{error::Error, net::UdpSocket, time::Duration};

use cares::{DnsRecordType, Resolver, ResolverOptions};
use liburing::{
    CompletionDispatcher, OperationId, OperationPayload, Proactor, ProactorConfig, SubsystemId,
};

type TestResult = Result<(), Box<dyn Error>>;

fn staged_driver(ring: &mut Proactor) -> Result<(Resolver, UdpSocket), Box<dyn Error>> {
    let blackhole = UdpSocket::bind("127.0.0.1:0")?;
    let mut driver = Resolver::new(
        SubsystemId::new(1).ok_or("subsystem")?,
        ResolverOptions::builder()
            .tries(1)
            .timeout(Duration::from_secs(60))
            .build()?,
        &format!("127.0.0.1:{}", blackhole.local_addr()?.port()),
        1,
    )?;
    driver.submit_query("ownership.test.", DnsRecordType::A, |_, _| {})?;
    driver.flush(ring)?;
    Ok((driver, blackhole))
}

#[test]
fn foreign_completion_preserves_timeout_operand_and_completion_claim() -> TestResult {
    let mut owner = Proactor::new(ProactorConfig::default())?;
    let mut foreign = Proactor::new(ProactorConfig::default())?;
    let (mut driver, _blackhole) = staged_driver(&mut owner)?;
    let pending = driver.inflight_count();
    assert!(pending > 0);
    // The first registration is the timeout. Keep its owning SQE unpublished:
    // even a failing assertion must never expose a prematurely freed operand.
    let timer = OperationId::pack(
        SubsystemId::new(1).ok_or("subsystem")?,
        OperationPayload::new(1).ok_or("payload")?,
    );
    foreign.prepare_sqe_with(timer, |sqe| {
        // SAFETY: NOP references no external storage.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;
    let mut seen = false;
    foreign.wait_completions(
        1,
        Some(Duration::from_secs(1)),
        &mut |completion, context: &mut liburing::SubmissionContext<'_>| {
            assert!(driver.dispatch(completion, context).is_err());
            assert_eq!(
                driver.inflight_count(),
                pending,
                "foreign CQE retired the owner's operand"
            );
            context.claim_completion(completion)?;
            seen = true;
            Ok(())
        },
    )?;
    assert!(seen);
    assert_eq!(owner.operation_count(), pending);
    driver.shutdown(&mut owner)?;
    Ok(())
}

#[test]
fn foreign_flush_and_shutdown_reject_before_channel_or_ring_mutation() -> TestResult {
    let mut owner = Proactor::new(ProactorConfig::default())?;
    let mut foreign = Proactor::new(ProactorConfig::default())?;
    let (mut driver, _blackhole) = staged_driver(&mut owner)?;
    let pending = driver.inflight_count();
    assert!(driver.flush(&mut foreign).is_err());
    assert!(driver.begin_shutdown(&mut foreign).is_err());
    assert_eq!(driver.inflight_count(), pending);
    assert_eq!(foreign.operation_count(), 0);
    driver.submit_query("still-open.test.", DnsRecordType::A, |_, _| {})?;
    driver.shutdown(&mut owner)?;
    Ok(())
}
