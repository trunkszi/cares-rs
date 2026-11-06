//! Caller-owned DNS dispatch under bounded ring credit and terminal teardown.

use std::{
    cell::Cell,
    error::Error,
    net::{Ipv4Addr, UdpSocket},
    rc::Rc,
    time::{Duration, Instant},
};

use cares::{AresStatus, DnsRecordType, DnsSection, ProactorResolver, ResolverOptions};
use liburing::{CompletionDispatcher, Proactor, ProactorConfig, SubsystemId};

#[path = "mock_dns_server.rs"]
mod mock_dns_server;
use mock_dns_server::{Behavior, MockDnsServer, Zone};

/// Tiny staging and operation budgets preserve TCP fallback and reject forged CQEs.
#[test]
fn integration_scenario_bounded_dispatch() -> Result<(), Box<dyn Error>> {
    let server =
        MockDnsServer::start(Zone::new().a("bounded.test.", Ipv4Addr::new(192, 0, 2, 11)))?;
    server.set_behavior(Behavior::TruncateUdp);
    let mut ring = Proactor::new(ProactorConfig {
        entries: 2,
        staged_capacity: 2,
        operation_capacity: 3,
        ..ProactorConfig::default()
    })?;
    let mut dns = ProactorResolver::new(
        SubsystemId::new(1).ok_or("subsystem")?,
        ResolverOptions::builder()
            .tries(1)
            .timeout(Duration::from_secs(2))
            .build()?,
        &server.servers_csv_with_tcp(),
        1,
    )?;
    let output = Rc::new(Cell::new(None));
    let captured = Rc::clone(&output);
    dns.resolver
        .submit_query("bounded.test.", DnsRecordType::A, move |_, outcome| {
            captured.set(Some((
                outcome.status,
                outcome.record.and_then(|record| {
                    record
                        .rr(DnsSection::Answer, 0)
                        .ok()?
                        .as_a()
                        .ok()
                        .map(|value| value.address)
                }),
            )));
        })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut rejected = false;
    while output.get().is_none() && Instant::now() < deadline {
        dns.flush(&mut ring)?;
        let mut dispatch =
            |completion: liburing::Completion,
             submissions: &mut liburing::SubmissionContext<'_>| {
                if !rejected {
                    let forged = liburing::Completion {
                        flags: completion.flags ^ 1,
                        ..completion
                    };
                    assert!(dns.dispatch(forged, submissions).is_err());
                    rejected = true;
                }
                dns.dispatch(completion, submissions)
            };
        ring.wait_completions(1, Some(Duration::from_millis(20)), &mut dispatch)?;
    }
    assert!(rejected);
    assert_eq!(
        output.get(),
        Some((AresStatus::Success, Some(Ipv4Addr::new(192, 0, 2, 11))))
    );
    assert!(server.udp_queries() > 0 && server.tcp_queries() > 0);
    ring.shutdown_with(&mut dns)?;
    assert_eq!(ring.operation_count(), 0);
    assert!(dns.failure().is_none());
    drop(dns);
    server.stop();
    Ok(())
}

/// Canceling staged and submitted registrations retires each pending query once.
#[test]
fn integration_lifecycle_dns_shutdown() -> Result<(), Box<dyn Error>> {
    for publish in [false, true] {
        let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let mut ring = Proactor::new(ProactorConfig {
            entries: 4,
            staged_capacity: 4,
            ..ProactorConfig::default()
        })?;
        let csv = format!("127.0.0.1:{}", blackhole.local_addr()?.port());
        let mut dns = ProactorResolver::new(
            SubsystemId::new(1).ok_or("subsystem")?,
            ResolverOptions::builder()
                .timeout(Duration::from_secs(60))
                .build()?,
            &csv,
            1,
        )?;
        let destroyed = Rc::new(Cell::new(0));
        let captured = Rc::clone(&destroyed);
        dns.resolver
            .submit_query("shutdown.test.", DnsRecordType::A, move |_, outcome| {
                assert_eq!(outcome.status, AresStatus::Destruction);
                captured.set(captured.get() + 1);
            })?;
        dns.flush(&mut ring)?;
        assert!(ring.operation_count() >= 2);
        if publish {
            ring.submit()?;
        }
        ring.shutdown_with(&mut dns)?;
        assert_eq!(ring.operation_count(), 0);
        drop(dns);
        assert_eq!(destroyed.get(), 1);
    }
    Ok(())
}

/// DNS shutdown counts target and control CQEs without closing a peer's ring.
#[test]
fn integration_lifecycle_shared_shutdown() -> Result<(), Box<dyn Error>> {
    let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut ring = Proactor::new(ProactorConfig {
        entries: 8,
        staged_capacity: 8,
        operation_capacity: 8,
        ..ProactorConfig::default()
    })?;
    let dns_id = SubsystemId::new(1).ok_or("DNS subsystem")?;
    let peer_id = SubsystemId::new(2).ok_or("peer subsystem")?;
    let csv = format!("127.0.0.1:{}", blackhole.local_addr()?.port());
    let mut dns = ProactorResolver::new(
        dns_id,
        ResolverOptions::builder()
            .timeout(Duration::from_secs(60))
            .build()?,
        &csv,
        1,
    )?;
    let canceled = Rc::new(Cell::new(0));
    let captured = Rc::clone(&canceled);
    dns.resolver
        .submit_query("cancel.test.", DnsRecordType::A, move |ctx, outcome| {
            assert_eq!(outcome.status, AresStatus::Cancelled);
            captured.set(captured.get() + 1);
            assert!(
                ctx.submit_query("retry.test.", DnsRecordType::A, |_, _| {})
                    .is_err()
            );
        })?;
    dns.flush(&mut ring)?;
    assert_eq!(dns.inflight_count(), 2);
    let peer = liburing::OperationId::pack(
        peer_id,
        liburing::OperationPayload::new(1).ok_or("peer token")?,
    );
    ring.prepare_sqe_with(peer, |sqe| {
        // SAFETY: NOP references no external operands; SQE storage is exclusive.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;
    dns.begin_shutdown(&mut ring)?;
    assert_eq!(canceled.get(), 1);
    assert_eq!(dns.inflight_count(), 4);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut dns_completions = 0;
    let mut peer_completions = 0;
    while (dns.has_pending_io() || peer_completions == 0) && Instant::now() < deadline {
        dns.flush(&mut ring)?;
        let mut dispatch =
            |completion: liburing::Completion,
             submissions: &mut liburing::SubmissionContext<'_>| {
                if completion.operation_id.subsystem_id() == dns_id {
                    let before = dns.inflight_count();
                    dns.dispatch(completion, submissions)?;
                    assert_eq!(dns.inflight_count() + 1, before);
                    dns_completions += 1;
                    Ok(())
                } else {
                    peer_completions += 1;
                    Ok(())
                }
            };
        ring.wait_completions(1, Some(Duration::from_millis(20)), &mut dispatch)?;
    }
    assert!(!dns.has_pending_io());
    assert_eq!(dns.inflight_count(), 0);
    assert_eq!(dns_completions, 4);
    assert_eq!(peer_completions, 1);
    ring.prepare_sqe_with(peer, |sqe| {
        // SAFETY: The prior peer operation retired and NOP has no DMA operands.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;
    let mut peer_dispatch = |_: liburing::Completion, _: &mut liburing::SubmissionContext<'_>| {
        peer_completions += 1;
        Ok(())
    };
    ring.wait_completions(1, Some(Duration::from_secs(1)), &mut peer_dispatch)?;
    assert_eq!(peer_completions, 2);
    dns.shutdown(&mut ring)?;
    assert_eq!(canceled.get(), 1);
    ring.shutdown()?;
    Ok(())
}

/// An exhausted shutdown budget retains live state until shared-ring credit returns.
#[test]
fn integration_scenario_budget_retention() -> Result<(), Box<dyn Error>> {
    let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut ring = Proactor::new(ProactorConfig {
        entries: 4,
        staged_capacity: 4,
        operation_capacity: 3,
        ..ProactorConfig::default()
    })?;
    let dns_id = SubsystemId::new(1).ok_or("DNS subsystem")?;
    let peer_id = SubsystemId::new(2).ok_or("peer subsystem")?;
    let csv = format!("127.0.0.1:{}", blackhole.local_addr()?.port());
    let mut dns = ProactorResolver::new(
        dns_id,
        ResolverOptions::builder()
            .timeout(Duration::from_secs(60))
            .build()?,
        &csv,
        1,
    )?;
    dns.resolver
        .submit_query("budget.test.", DnsRecordType::A, |_, outcome| {
            assert_eq!(outcome.status, AresStatus::Cancelled);
        })?;
    dns.flush(&mut ring)?;
    let peer = liburing::OperationId::pack(
        peer_id,
        liburing::OperationPayload::new(1).ok_or("peer token")?,
    );
    ring.prepare_sqe_with(peer, |sqe| {
        // SAFETY: NOP references no external operands; SQE storage is exclusive.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;
    let Err(error) = dns.shutdown_within(&mut ring, Duration::ZERO) else {
        return Err("zero budget unexpectedly retired pending DNS I/O".into());
    };
    assert!(error.to_string().contains("budget exhausted"));
    assert!(dns.has_pending_io());
    assert_eq!(dns.inflight_count(), 2);
    let mut owner = (ring, dns);
    let deadline = Instant::now() + Duration::from_secs(5);
    while owner.1.has_pending_io() && Instant::now() < deadline {
        owner.1.flush(&mut owner.0)?;
        let mut dispatch =
            |completion: liburing::Completion,
             submissions: &mut liburing::SubmissionContext<'_>| {
                if completion.operation_id.subsystem_id() == dns_id {
                    owner.1.dispatch(completion, submissions)
                } else {
                    Ok(())
                }
            };
        owner
            .0
            .wait_completions(1, Some(Duration::from_millis(20)), &mut dispatch)?;
    }
    assert!(!owner.1.has_pending_io());
    assert_eq!(owner.1.inflight_count(), 0);
    owner.0.shutdown()?;
    Ok(())
}

#[test]
fn sqpoll_query_shutdown_retires_io() -> Result<(), Box<dyn Error>> {
    // SAFETY: A zeroed cpu_set_t is a valid empty CPU affinity mask.
    let mut allowed = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    // SAFETY: allowed is writable for its full size, and pid zero selects this thread.
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&allowed), &mut allowed) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: allowed is a fully initialized mask populated by sched_getaffinity.
    let allowed_cpus = unsafe { libc::CPU_COUNT(&allowed) };
    let cpu = (0..libc::CPU_SETSIZE as usize)
        .rev()
        .find(|&cpu| {
            // SAFETY: cpu is within CPU_SETSIZE and allowed is initialized.
            unsafe { libc::CPU_ISSET(cpu, &allowed) }
        })
        .ok_or("no allowed CPU for SQPOLL qualification")?;
    let polling = liburing::SqPollConfig::pinned(u32::try_from(cpu)?)
        .with_idle_ms(std::num::NonZeroU32::new(1).ok_or("SQPOLL idle interval")?);
    let mut ring = match Proactor::new(ProactorConfig {
        mode: liburing::ProactorMode::SqPoll(polling),
        entries: 8,
        ..ProactorConfig::default()
    }) {
        Ok(ring) => ring,
        Err(liburing::UringError::RingInit(errno))
            if matches!(
                errno.abs(),
                libc::EPERM | libc::EACCES | libc::ENOSYS | libc::EINVAL
            ) =>
        {
            eprintln!("SQPOLL qualification skipped: ring initialization errno {errno}");
            return Ok(());
        }
        Err(liburing::UringError::InvalidConfig(reason)) if allowed_cpus == 1 => {
            eprintln!("SQPOLL qualification skipped: {reason}");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let address = Ipv4Addr::new(192, 0, 2, 42);
    let server = MockDnsServer::start(Zone::new().a("sqpoll.test.", address))?;
    let mut dns = ProactorResolver::new(
        SubsystemId::new(1).ok_or("DNS subsystem")?,
        ResolverOptions::builder()
            .tries(1)
            .timeout(Duration::from_secs(60))
            .build()?,
        &server.servers_csv(),
        1,
    )?;
    let output = Rc::new(Cell::new(None));
    let captured = Rc::clone(&output);
    dns.resolver
        .submit_query("sqpoll.test.", DnsRecordType::A, move |_, outcome| {
            captured.set(Some((
                outcome.status,
                outcome.record.and_then(|record| {
                    record
                        .rr(DnsSection::Answer, 0)
                        .ok()?
                        .as_a()
                        .ok()
                        .map(|value| value.address)
                }),
            )));
        })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while output.get().is_none() && Instant::now() < deadline {
        dns.flush(&mut ring)?;
        ring.tick(&mut dns)?;
        std::hint::spin_loop();
    }
    assert_eq!(output.get(), Some((AresStatus::Success, Some(address))));
    server.set_behavior(Behavior::DropUdp(u32::MAX));
    let canceled = Rc::new(Cell::new(0));
    let captured = Rc::clone(&canceled);
    dns.resolver.submit_query(
        "pending.sqpoll.test.",
        DnsRecordType::A,
        move |_, outcome| {
            assert_eq!(outcome.status, AresStatus::Cancelled);
            captured.set(captured.get() + 1);
        },
    )?;
    dns.flush(&mut ring)?;
    ring.submit()?;
    assert!(dns.has_pending_io());
    dns.shutdown_within(&mut ring, Duration::from_secs(5))?;
    assert_eq!(canceled.get(), 1);
    assert!(!dns.has_pending_io());
    assert_eq!(dns.inflight_count(), 0);
    assert_eq!(ring.operation_count(), 0);
    assert_eq!(ring.stats().wait_calls, 0);
    ring.shutdown()?;
    drop(dns);
    server.stop();
    Ok(())
}
