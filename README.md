# cares-rs

Safe, threadless, completion-driven Rust 2024 bindings for upstream [c-ares](https://github.com/c-ares/c-ares), built on [liburing-rs](https://github.com/trunkszi/liburing-rs). c-ares is compiled with `CARES_THREADS=OFF`; there is no executor runtime, background event thread, or readiness reactor.

## Why cares-rs?

Name resolution sits before the first connection, but it can also interrupt an
otherwise healthy client when a pool reconnects or an endpoint changes. A
hostname lookup through `getaddrinfo` or `std::net::ToSocketAddrs` can block the
calling thread. On a worker responsible for many live connections, that pause
holds up unrelated traffic as well as the connection being opened.

An asynchronous resolver avoids that blocking call, but changes how the client
must run. For example, [Hickory's Tokio integration](https://docs.rs/hickory-resolver/latest/hickory_resolver/)
drives lookups as futures on a runtime. Adopting that integration in a synchronous
client means propagating asynchronous signatures or bridging into an executor;
its task scheduling also becomes part of the connection's latency budget.
Thread-enabled c-ares builds offer another integration model, with channel
locking and optional event-thread processing. A worker that already owns its
I/O loop needs DNS progress to fit that loop instead.

`cares-rs` builds c-ares with `CARES_THREADS=OFF` and keeps each resolver on one
owner thread. In shared-ring applications, `ProactorResolver` submits socket
interests and retry timers to the caller's existing `liburing::Proactor`.
Answers, UDP-to-TCP fallback, timeouts, and follow-up queries advance through the
same completion dispatcher as the client's other I/O. There is no resolver
thread to synchronize with, and the caller keeps control of the timeout budget
and of how long shutdown may drain pending work.

That makes a failed lookup easier to inspect. A breakpoint can follow query
submission, socket or timer completion, and the callback on the same thread.
Borrowed DNS records are scoped to that callback, while `ChannelCtx` makes the
allowed follow-up operations explicit. Engineers and AI coding tools can reason
about these visible lifetimes without carrying resolver state across `.await`
boundaries or guessing when a background task will release it.

## Design

- **Threadless c-ares.** The native library is built with `CARES_THREADS=OFF` and `CARES_SHARED=OFF`; it contains no pthread mutexes, no event thread, and no `ARES_OPT_EVENT_THREAD`.
- **Single-thread resolver.** `Resolver` is `!Send + !Sync`. Socket readiness, retry deadlines, and user callbacks all run on the thread that owns it.
- **Two completion drivers.** Standalone mode uses `wait_completions`, `poll_completions`, or `resolve`. Shared-ring mode keeps `ProactorResolver` in caller-owned state and passes a static `CompletionDispatcher` to the pure Rust `liburing::Proactor`. DNS-specific POLL_ADD readiness handling stays inside cares; the ring holds no resolver or handler registry.
- **Safe callback boundary.** `DnsRecordRef<'cb>` cannot escape its callback. `ChannelCtx<'cb>` exposes only re-entrant-safe operations, and panics are caught at the FFI boundary and poison the resolver instead of unwinding into C.

Library initialization uses atomic first/last-reference transitions. Resolver handles
remain confined to their owner thread; socket progress does not wait on global
initialization state.

All callbacks run synchronously on the thread that drives the resolver. A callback may submit follow-up queries through `ChannelCtx`; it cannot recursively drive the resolver.

The workspace targets Linux `x86_64` and pins a nightly toolchain in `rust-toolchain.toml`.

## Crates

| Crate | Purpose |
| --- | --- |
| `cares-sys` | FFI bindings and the static c-ares build. |
| `cares-macros` | `DnsRecordExtract` and `cares_query_table!` proc macros. |
| `cares` | Safe resolver, record models, and the proactor driver. |

The crates are path dependencies in one Cargo workspace; `crates/cares/tests/` holds the integration suites.

## Quick Start

```rust
use std::time::Duration;

use cares::{DnsRecordType, DnsSection, Resolver, ResolverOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = ResolverOptions::builder()
        .tries(2)
        .timeout(Duration::from_secs(2))
        .build()?;
    let mut resolver = Resolver::new(options)?;
    resolver.set_servers_csv("1.1.1.1")?;
    // `resolve` drives the channel to completion or deadline.
    let record = resolver.resolve("example.com", DnsRecordType::A, Duration::from_secs(5))?;
    let address = record.rr(DnsSection::Answer, 0)?.as_a()?.address;
    println!("example.com -> {address}");
    Ok(())
}
```

Callbacks receive a `ChannelCtx` and a borrowed-or-owned record; use `submit_query` for completion-driven work.

## Examples

Three self-contained examples under `crates/cares/examples/` need no external network:

```bash
cargo run -p cares --example dns_packet_codec_and_edns
cargo run -p cares --example standalone_resolver_and_records
cargo run -p cares --example proactor_shared_ring_resolver
```

- `dns_packet_codec_and_edns` builds and parses wire messages with an EDNS0 `OPT` record and typed answers.
- `standalone_resolver_and_records` runs local UDP/TCP queries through `wait_completions`, including a re-entrant CNAME lookup.
- `proactor_shared_ring_resolver` drives `ProactorResolver` on a real `liburing::Proactor`; a truncated UDP answer forces TCP fallback and socket-bridge growth. It requires a kernel with io_uring and fails if the ring cannot be created.

The codec example is pure in-memory; the two resolver examples bind a deterministic `127.0.0.1:0` responder. Each prints a short summary and exits with status 0.

## Shared-Ring Shutdown

Call `driver.flush(&mut ring)` after submitting queries, then drive the shared
ring with `ring.wait_completions(min, timeout, &mut dispatcher)` in `EventDriven`
mode or `ring.tick(&mut dispatcher)` in `SqPoll` mode. Route the DNS
subsystem to `driver.dispatch(completion, submissions)`; the driver remains
owned by the caller throughout. Completion routing uses liburing `OperationId`
and `OperationPayload`; the completed identity is `Completion::operation_id`.

`driver.begin_shutdown(&mut ring)` rejects new queries and cancels existing
queries and registrations. Continue `flush` and caller-owned completion dispatch
within your remaining deadline until `driver.has_pending_io()` is false.
`inflight_count()` includes polls, timers, and explicit cancel acknowledgments;
a cancel ACK does not retire its target. No poll or timer is rearmed during
shutdown. If the deadline expires, retain the entire `(ring, driver)` owner for
later draining. Cancellation controls also need operation/staging credit; peer
completions can release it when the shared ring is full.

`driver.shutdown_within(&mut ring, budget)` and `driver.shutdown(&mut ring)`
(the latter has a five-second budget) drive a DNS-only dispatcher and leave the
ring open. Shared-ring applications use their worker dispatcher instead. Close
the ring only after every subsystem has retired its I/O. Dropping a driver early
retains pending timeout operands because their final CQEs have not proven reuse.

## Build and Test

Run every command from the workspace root. GitHub-hosted CI runs the Cargo checks directly.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```
