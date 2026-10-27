//! Hot-path latency for query slots, socket interest, deadlines, and records.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    net::{Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use cares::{
    ARecord, AaaaRecord, DnsClass, DnsRecord, DnsRecordType, DnsSection, ProactorResolver,
    ResolverOptions, SrvRecord, TxtRecord, socket_bridge::SharedChannelState, timer::TimerState,
    types::DnsFlags,
};
use criterion::{Criterion, criterion_group};
use liburing::{Proactor, ProactorConfig, SubsystemId};

cares::cares_query_table! {
    enum Lookups {
        host_a { name: "a.example", rr_type: A, class: IN },
        host_aaaa { name: "aaaa.example", rr_type: AAAA, class: IN },
        host_srv { name: "srv.example", rr_type: SRV, class: IN },
        host_txt { name: "txt.example", rr_type: TXT, class: IN },
    }
}

struct CountingAllocator {
    allocations: AtomicUsize,
}

// SAFETY: Each method forwards to the system allocator and only increments an
// atomic counter. Pointers, alignment, and deallocation layouts remain those
// of `System`, so the `GlobalAlloc` contract is preserved.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocations.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies a valid layout for a fresh allocation.
        unsafe { System.alloc(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.allocations.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller retains the pointer previously returned by this allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller owns this allocation and passes its original layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator {
    allocations: AtomicUsize::new(0),
};

fn must<T, E: core::fmt::Debug>(value: Result<T, E>) -> T {
    match value {
        Ok(value) => value,
        Err(error) => panic!("dns hot-path benchmark failed: {error:?}"),
    }
}

fn assert_zero_alloc(label: &str, body: impl FnOnce()) {
    let before = ALLOCATOR.allocations.load(Ordering::Relaxed);
    body();
    let after = ALLOCATOR.allocations.load(Ordering::Relaxed);
    assert_eq!(before, after, "{label} allocated on the hot path");
}

fn preflight_queries() {
    let mut packet = [0u8; 96];
    assert_zero_alloc("query slot encode decode", || {
        let written = must(Lookups::HostA.encode(0x0010, &mut packet));
        let decoded = must(Lookups::decode(&packet[..written]));
        black_box((written, decoded.slot_name(), decoded.rr_type()));
    });
    assert_zero_alloc("query dispatch", || {
        let routes = Lookups::dispatch();
        black_box((routes.len(), routes[0].name, routes[3].rr_type));
    });
}

fn preflight_interest() {
    let state = SharedChannelState::new();
    let fd = must(state.open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0));
    state.on_socket_state(fd, true, false);
    assert_zero_alloc("socket interest unchanged", || {
        state.on_socket_state(fd, true, false);
    });
    state.on_socket_state(fd, false, true);
    must(state.close_socket(fd));
}

fn preflight_timer() {
    let timer = TimerState::new();
    let armed_at = Instant::now() + Duration::from_secs(30);
    let armed = match timer.refresh_from_deadline(Some(armed_at)) {
        Some(deadline) => deadline,
        None => panic!("dns hot-path benchmark failed: timer did not arm"),
    };
    assert_zero_alloc("timer generation stable", || {
        let again = timer.refresh_from_deadline(Some(armed_at + Duration::from_micros(200)));
        black_box(again.map(|deadline| deadline.generation));
    });
    assert_zero_alloc("timer generation transition", || {
        let moved = timer.refresh_from_deadline(Some(armed_at + Duration::from_secs(5)));
        let generation = match moved {
            Some(deadline) => deadline.generation,
            None => panic!("dns hot-path benchmark failed: timer lost its deadline"),
        };
        black_box(generation != armed.generation && timer.on_timer(generation));
    });
}

fn driver() -> (Proactor, ProactorResolver) {
    let proactor = must(Proactor::new(ProactorConfig {
        entries: 64,
        ..ProactorConfig::default()
    }));
    let subsystem = match SubsystemId::new(4) {
        Some(id) => id,
        None => panic!("dns hot-path benchmark failed: subsystem id was rejected"),
    };
    let resolver = must(ProactorResolver::new(
        subsystem,
        ResolverOptions::default(),
        "127.0.0.1:53",
        8,
    ));
    (proactor, resolver)
}

fn preflight_reconcile() {
    let (mut proactor, mut resolver) = driver();
    must(resolver.flush(&mut proactor));
    assert_zero_alloc("poll reconcile unchanged", || {
        must(resolver.flush(&mut proactor));
    });
    must(resolver.shutdown(&mut proactor));
}

fn sample_record() -> DnsRecord {
    let mut record = must(
        DnsRecord::builder()
            .id(0x1234)
            .flags(DnsFlags::QR | DnsFlags::RD | DnsFlags::RA)
            .question("www.example", DnsRecordType::A, DnsClass::IN)
            .build(),
    );
    must(record.add_record(
        DnsSection::Answer,
        "www.example",
        DnsClass::IN,
        60,
        &ARecord {
            address: Ipv4Addr::new(192, 0, 2, 10),
        },
    ));
    must(record.add_record(
        DnsSection::Answer,
        "www.example",
        DnsClass::IN,
        60,
        &AaaaRecord {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
        },
    ));
    must(record.add_record(
        DnsSection::Answer,
        "www.example",
        DnsClass::IN,
        60,
        &TxtRecord {
            chunks: vec![b"v=spf1".to_vec()],
        },
    ));
    must(record.add_record(
        DnsSection::Answer,
        "_sip._tcp.example",
        DnsClass::IN,
        60,
        &SrvRecord {
            priority: 10,
            weight: 20,
            port: 5060,
            target: "sip.example".to_owned(),
        },
    ));
    record
}

fn preflight_records() {
    let record = sample_record();
    assert_zero_alloc("a record extract", || {
        let parsed = must(must(record.rr(DnsSection::Answer, 0)).as_a());
        black_box(parsed.address);
    });
    assert_zero_alloc("aaaa record extract", || {
        let parsed = must(must(record.rr(DnsSection::Answer, 1)).as_aaaa());
        black_box(parsed.address);
    });
    let txt = must(must(record.rr(DnsSection::Answer, 2)).as_txt());
    let srv = must(must(record.rr(DnsSection::Answer, 3)).as_srv());
    assert_eq!(txt.chunks[0], b"v=spf1");
    assert_eq!(srv.port, 5060);
    assert_eq!(srv.target, "sip.example");
}

fn bench_queries(c: &mut Criterion) {
    let mut packet = [0u8; 96];
    c.bench_function("query_slot_encode_decode", |b| {
        b.iter(|| {
            let written = must(Lookups::HostSrv.encode(black_box(0x10), &mut packet));
            black_box(must(Lookups::decode(&packet[..written])));
        });
    });
    c.bench_function("query_dispatch", |b| {
        b.iter(|| {
            let routes = Lookups::dispatch();
            black_box((routes.len(), routes[black_box(2)].name));
        });
    });
}

fn bench_interest(c: &mut Criterion) {
    let state = SharedChannelState::new();
    let fd = must(state.open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0));
    state.on_socket_state(fd, true, false);
    c.bench_function("socket_interest_unchanged", |b| {
        b.iter(|| state.on_socket_state(black_box(fd), true, false));
    });
    c.bench_function("socket_interest_update", |b| {
        b.iter(|| {
            state.on_socket_state(fd, true, false);
            state.on_socket_state(fd, false, true);
        });
    });
    must(state.close_socket(fd));
}

fn bench_timer(c: &mut Criterion) {
    let timer = TimerState::new();
    let armed_at = Instant::now() + Duration::from_secs(60);
    c.bench_function("timer_generation_stable", |b| {
        b.iter(|| {
            black_box(timer.refresh_from_deadline(Some(armed_at + Duration::from_micros(100))));
        });
    });
    c.bench_function("timer_generation_rearm", |b| {
        b.iter(|| {
            let at = Instant::now() + Duration::from_secs(black_box(3));
            let deadline = timer.refresh_from_deadline(Some(at));
            black_box(timer.on_timer(deadline.map(|value| value.generation).unwrap_or(0)));
            black_box(deadline);
        });
    });
}

fn bench_reconcile(c: &mut Criterion) {
    let (mut proactor, mut resolver) = driver();
    must(resolver.flush(&mut proactor));
    c.bench_function("poll_reconcile_unchanged", |b| {
        b.iter(|| must(resolver.flush(&mut proactor)));
    });
    must(resolver.shutdown(&mut proactor));
}

fn bench_records(c: &mut Criterion) {
    let record = sample_record();
    c.bench_function("dns_record_a_aaaa", |b| {
        b.iter(|| {
            let v4 = must(must(record.rr(DnsSection::Answer, 0)).as_a());
            let v6 = must(must(record.rr(DnsSection::Answer, 1)).as_aaaa());
            black_box((v4.address, v6.address));
        });
    });
    c.bench_function("dns_record_srv_txt", |b| {
        b.iter(|| {
            let txt = must(must(record.rr(DnsSection::Answer, 2)).as_txt());
            let srv = must(must(record.rr(DnsSection::Answer, 3)).as_srv());
            black_box((txt.chunks.len(), srv.port));
        });
    });
}

fn preflight() {
    preflight_queries();
    preflight_interest();
    preflight_timer();
    preflight_reconcile();
    preflight_records();
}

criterion_group!(
    hotpath,
    bench_queries,
    bench_interest,
    bench_timer,
    bench_reconcile,
    bench_records
);

fn main() {
    preflight();
    hotpath();
}
