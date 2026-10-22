//! 10,000-query stress through a real `liburing::Proactor` and
//! `ProactorResolver`, chaining each completion into the next submission.

use std::{
    cell::Cell,
    error::Error,
    net::Ipv4Addr,
    rc::Rc,
    time::{Duration, Instant},
};

use cares::{
    ChannelCtx, ProactorResolver, error::AresStatus, options::ResolverOptions, types::DnsRecordType,
};
use mock_dns_server::{MockDnsServer, Zone};

#[path = "mock_dns_server.rs"]
mod mock_dns_server;

type TestResult = Result<(), Box<dyn Error>>;

const QUERIES: usize = 10_000;

#[derive(Default)]
struct State {
    completed: Cell<usize>,
    failed: Cell<usize>,
}

fn after_completion(ctx: &ChannelCtx<'_>, state: &Rc<State>, success: bool) {
    if success {
        state.completed.set(state.completed.get() + 1);
    } else {
        state.failed.set(state.failed.get() + 1);
    }
    if state.completed.get() + state.failed.get() < QUERIES {
        submit_next(ctx, state);
    }
}

fn submit_next(ctx: &ChannelCtx<'_>, state: &Rc<State>) {
    let next = Rc::clone(state);
    let result = ctx.submit_query("stress.test.", DnsRecordType::A, move |ctx, outcome| {
        after_completion(ctx, &next, outcome.status == AresStatus::Success);
    });
    if result.is_err() {
        state.failed.set(state.failed.get() + 1);
    }
}

#[test]
fn ten_thousand_queries_complete_through_the_proactor() -> TestResult {
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
    let server =
        MockDnsServer::start(Zone::new().a("stress.test.", Ipv4Addr::new(192, 0, 2, 210)))?;
    let options = ResolverOptions::builder()
        .tries(1)
        .timeout(Duration::from_secs(2))
        .query_cache_ttl(Duration::ZERO)
        .build()?;
    let id = liburing::id::SubsystemId::new(1).ok_or("subsystem id")?;
    let mut driver = ProactorResolver::new(id, options, &server.servers_csv(), 1)?;
    let state = Rc::new(State::default());
    let seed = Rc::clone(&state);
    driver
        .resolver
        .submit_query("stress.test.", DnsRecordType::A, move |ctx, outcome| {
            after_completion(ctx, &seed, outcome.status == AresStatus::Success);
        })?;
    driver.flush(&mut proactor)?;
    proactor.register_subsystem(id, driver)?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while state.completed.get() + state.failed.get() < QUERIES && Instant::now() < deadline {
        proactor.wait_completions(1, Some(Duration::from_millis(20)), |_, _| Ok(()))?;
    }
    assert_eq!(
        (state.completed.get(), state.failed.get()),
        (QUERIES, 0),
        "proactor stress completed {} and failed {} of {QUERIES}",
        state.completed.get(),
        state.failed.get()
    );
    proactor.shutdown()?;
    drop(proactor);
    server.stop();
    Ok(())
}
