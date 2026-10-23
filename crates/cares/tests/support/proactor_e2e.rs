use liburing::CompletionDispatcher;

use super::*;
type ProactorResult = Rc<Cell<Option<(AresStatus, Result<DnsRecord, AresError>)>>>;

struct NopSeen {
    seen: Rc<Cell<usize>>,
}

impl CompletionDispatcher for NopSeen {
    fn dispatch(
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
    // TC=1 forces a TCP fallback, so the bridge sees the UDP descriptor first
    // and then a second descriptor while the first is still registered.
    server.set_behavior(Behavior::TruncateUdp);
    let dns_id = liburing::id::SubsystemId::new(1).ok_or_else(|| failure("dns subsystem id"))?;
    let nop_id = liburing::id::SubsystemId::new(2).ok_or_else(|| failure("nop subsystem id"))?;
    let mut driver = ProactorResolver::new(
        dns_id,
        fast_options(1, Duration::from_secs(2))?,
        &server.servers_csv_with_tcp(),
        1,
    )?;
    let result: ProactorResult = Rc::new(Cell::new(None));
    let result_sink = Rc::clone(&result);
    driver
        .resolver
        .submit_query("proactor.test.", DnsRecordType::A, move |_ctx, outcome| {
            let record = outcome
                .record
                .map(|record| record.to_owned_record())
                .unwrap_or_else(|| Err(AresError::invalid_record("missing record")));
            result_sink.set(Some((outcome.status, record)));
        })?;
    driver.flush(&mut proactor)?;
    let nop_seen = Rc::new(Cell::new(0));
    let mut nop = NopSeen {
        seen: Rc::clone(&nop_seen),
    };
    let nop_op = liburing::id::OperationId::pack(
        nop_id,
        liburing::id::OperationPayload::new(1).ok_or_else(|| failure("nop token"))?,
    );
    proactor.prepare_sqe_with(nop_op, |sqe| {
        // SAFETY: The closure owns exclusive initialized SQE storage.
        unsafe { liburing::ops::prep_nop(sqe) };
    })?;
    let timer = liburing::ops::Timeout::new(Duration::from_millis(2))?;
    let timer_op = liburing::id::OperationId::pack(
        nop_id,
        liburing::id::OperationPayload::new(2).ok_or_else(|| failure("timer token"))?,
    );
    proactor.prepare_sqe_with(timer_op, |sqe| {
        // SAFETY: `timer` outlives its final CQE or ring shutdown.
        unsafe { timer.prepare(sqe) };
    })?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut answer = None;
    while answer.is_none() && Instant::now() < deadline {
        let mut dispatch =
            |completion: liburing::Completion,
             submissions: &mut liburing::SubmissionContext<'_>| {
                if completion.operation_id.subsystem_id() == dns_id {
                    driver.dispatch(completion, submissions)
                } else {
                    nop.dispatch(completion, submissions)
                }
            };
        proactor.wait_completions(8, Some(Duration::from_millis(20)), &mut dispatch)?;
        answer = result.take();
    }
    let (status, record) =
        answer.ok_or_else(|| failure("real proactor did not complete the DNS query"))?;
    assert_eq!(status, AresStatus::Success);
    let answer = record?.rr(DnsSection::Answer, 0)?.as_a()?.address;
    assert_eq!(answer, Ipv4Addr::new(192, 0, 2, 200));
    assert!(
        server.udp_queries() >= 1 && server.tcp_queries() >= 1,
        "the capacity-1 DNS poll table did not grow across the UDP and TCP descriptors"
    );
    assert!(nop_seen.get() >= 2, "saw {} completions", nop_seen.get());
    let mut dispatch = |completion: liburing::Completion,
                        submissions: &mut liburing::SubmissionContext<'_>| {
        if completion.operation_id.subsystem_id() == dns_id {
            driver.dispatch(completion, submissions)
        } else {
            nop.dispatch(completion, submissions)
        }
    };
    proactor.shutdown_with(&mut dispatch)?;
    drop(proactor);
    drop(timer);
    server.stop();
    Ok(())
}
