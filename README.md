# cares-rs

Safe, threadless, completion-driven Rust 2024 bindings for upstream [c-ares](https://github.com/c-ares/c-ares), built on [liburing-rs](https://github.com/trunkszi/liburing-rs). `cares-rs` compiles c-ares with `CARES_THREADS=OFF` and exposes a single-threaded resolver that shares one `io_uring` proactor with other protocol libraries on the same thread. There is no async runtime, no background event thread, and no readiness reactor.

## Why

- **Threadless c-ares.** The native library is built with `CARES_THREADS=OFF` and `CARES_SHARED=OFF`. It contains no pthread mutexes, no event thread, and no `ARES_OPT_EVENT_THREAD`, and `ares_threadsafety()` is checked before the first channel is created.
- **Run-to-completion, one thread.** `Resolver` is `!Send + !Sync`. Socket readiness, retry deadlines, and user callbacks all run on the thread that owns the resolver. There is no worker thread, channel, future executor, or waker.
- **One ring per thread.** DNS sockets and retry timers join the same `liburing::UringProactor` used by curl, gRPC, and nghttp2 on that thread. A DNS completion can trigger follow-up DNS work or another subsystem's I/O without a second ring or a thread hop.
- **No hidden locks.** Single-thread state uses `Rc`, `RefCell`, and `Cell`. Cross-thread use is a compile error rather than a runtime lock.
- **Safe callback boundary.** `DnsRecordRef<'cb>` cannot escape its callback. `ChannelCtx<'cb>` exposes only re-entrant-safe operations. Panics are caught at the FFI boundary and poison the resolver instead of unwinding into C.
- **Per-query cancellation.** `QueryHandle` identifies one lookup, so one cancellation does not abort unrelated queries sharing a UDP or TCP socket.

## Architecture

```text
application thread
│
├── cares::Resolver                         (!Send + !Sync)
│   ├── CallbackSlot<F> / CallbackState     callback registry and panic poison
│   ├── ChannelCtx<'cb>                     follow-up submission, logical cancel
│   ├── SharedChannelState                  10-hook socket vtable, readiness queue
│   └── TimerState                          ares_timeout deadline and generation
│
├── cares-sys ──────────────► static libcares.a
│                             CARES_THREADS=OFF, CARES_SHARED=OFF
│
└── liburing::UringProactor ─► one io_uring ring per thread
    UringSocketTable · TimerRegistry · SubsystemId
```

There are two ways to drive completion:

- **Shared-ring mode.** `ProactorResolver` binds the resolver's socket interest to a real `liburing::UringSocketBridge` and registers the driver as a `liburing::Proactor` subsystem. Socket poll completions are fed to `Resolver::on_cqe`, while `ops::timeout` drives interleaved timers. User callbacks run synchronously, so they can submit follow-up queries through `ChannelCtx`.
- **Standalone mode.** `wait_completions` polls the resolver's descriptors with a bounded `poll(2)` wait, processes events and `ares_timeout` deadlines, and returns when no query remains or the timeout expires. `poll_completions` performs the nonblocking half of that pass on events already buffered. `resolve` is the blocking-to-completion helper built on this path.

## Quick Start

Add the crate as a path dependency and run a blocking-to-completion lookup:

```rust
use std::time::Duration;

use cares::record_rr::ARecord;
use cares::{DnsRecordType, DnsSection, Resolver, ResolverOptions};

fn main() -> Result<(), cares::AresError> {
    let options = ResolverOptions::builder().tries(2).build()?;
    let mut resolver = Resolver::new(options)?;
    resolver.set_servers_csv("1.1.1.1,8.8.8.8:53")?;

    let record = resolver.resolve("example.com.", DnsRecordType::A, Duration::from_secs(5))?;
    for answer in record.records::<ARecord>(DnsSection::Answer)? {
        println!("{}", answer.address);
    }
    Ok(())
}
```

## Shared-Ring Callbacks

`submit_query` registers a completion closure and returns a `QueryHandle`. The closure runs on the resolver's thread. Its `ChannelCtx` can submit another query, and a record that must outlive the callback is duplicated explicitly:

```rust
use cares::{DnsRecordType, Resolver, ResolverCqe};

fn submit(resolver: &mut Resolver) -> cares::Result<()> {
    resolver.submit_query("www.example.com.", DnsRecordType::CNAME, |ctx, outcome| {
        if let Some(record) = outcome.record {
            // The borrowed record dies when this closure returns.
            let owned = record.to_owned_record();

            // A follow-up query is allowed from the callback context.
            let follow_up =
                ctx.submit_query("example.com.", DnsRecordType::A, |_ctx, _outcome| {});

            let _ = (owned, follow_up);
        }
    })?;
    Ok(())
}

fn on_socket_ready(resolver: &mut Resolver, socket_fd: i32) -> cares::Result<()> {
    resolver.on_cqe(ResolverCqe::Socket {
        fd: socket_fd,
        readable: true,
        writable: false,
    })
}

fn on_timer(resolver: &mut Resolver, generation: u64) -> cares::Result<()> {
    resolver.on_cqe(ResolverCqe::Timer { generation })
}
```

`ResolverCqe::Timer { generation }` carries the deadline generation reported by `TimerState`; a stale generation is ignored.

## API Surface

### Resolver

| Item | Purpose |
| --- | --- |
| `Resolver` | Owns the channel, callback state, socket table, and timer. `!Send + !Sync`. |
| `Resolver::new` | Creates a resolver from `ResolverOptions`. |
| `Resolver::submit_query` | Submits a DNS query with a completion closure. Returns a `QueryHandle`. |
| `Resolver::submit_record` | Sends a prebuilt `DnsRecord` through `ares_send_dnsrec`. |
| `Resolver::gethostbyname` / `gethostbyaddr` / `getnameinfo` | Host and name-info lookups with owned results. |
| `Resolver::on_cqe` | Feeds a shared-ring socket or timer completion and dispatches any resulting callbacks. |
| `Resolver::timer_deadline` | Reports the next c-ares deadline and generation for the proactor timeout operation. |
| `ProactorResolver` | Registers the resolver on a `liburing::Proactor` with a `UringSocketBridge` readiness sink. |
| `Resolver::poll_completions` / `wait_completions` | Nonblocking and blocking standalone completion drivers. `wait_completions` polls descriptors with `poll(2)`. |
| `Resolver::resolve` | Submits one query and waits for its owned result. |
| `Resolver::cancel` | Channel-wide `ares_cancel`; pending callbacks see `AresStatus::Cancelled`. |
| `Resolver::cancel_query` | Logical per-query cancellation of one `QueryHandle`. |
| `Resolver::reinit` | Re-reads system configuration; queries are requeued if their server disappears. |
| `Resolver::set_servers_csv` / `servers_csv` | Replaces or reads the server list. |
| `Resolver::set_server_state_callback` | Receives per-server success and transport notifications. |
| `Resolver::is_poisoned` / `active_queries` | Reports callback poisoning and the number of in-flight queries. |
| `LibraryGuard` | Reference-counted `ares_library_init` / `ares_library_cleanup`. |

### Callback Types

| Item | Purpose |
| --- | --- |
| `QueryHandle` | `(index, generation)` token for one in-flight lookup. |
| `ChannelCtx<'cb>` | Callback-scoped handle: `submit_query`, `submit_record`, `cancel`, `is_poisoned`. |
| `QueryOutcome<'cb>` | Status, timeout count, and an optional `DnsRecordRef<'cb>`. |
| `HostOutcome` / `NameInfoOutcome` | Owned host and name-info results. |
| `ServerStateEvent` | Server identity (when reported), success flag, and `ServerStateFlags` (UDP/TCP). |
| `ResolverCqe` | `Socket { fd, readable, writable }` or `Timer { generation }`. |
| `PollOutcome` | Whether work advanced and how many queries remain pending. |

### DNS Values

| Item | Purpose |
| --- | --- |
| `DnsRecord` | Owned, RAII DNS message with parse, write, question, and RR editing. |
| `DnsRecordRef<'cb>` | Immutable callback-scoped view; `to_owned_record` duplicates it. |
| `DnsRr` / `DnsRrMut` | Borrowed record views for reading and construction. |
| `ARecord`, `AaaaRecord`, `CnameRecord`, `MxRecord`, `TxtRecord`, `SrvRecord`, `PtrRecord`, `SoaRecord`, `NaptrRecord`, `UriRecord`, `CaaRecord`, `TlsaRecord`, `HttpsRecord`, `SvcbRecord`, `NsRecord`, `OptRecord` | Typed record models with `FromDnsRr` / `IntoDnsRr` (`cares::record_rr`). |
| `DnsRecordType`, `DnsClass`, `DnsSection`, `HostEntry`, `NameInfo` | DNS wire vocabulary re-exported at the crate root. |
| `DnsFlags`, `DnsOpcode`, `DnsRcode`, `ServerStateFlags`, `SocketAddress` | Additional wire and endpoint values in `cares::types`. |

### Configuration and Errors

| Item | Purpose |
| --- | --- |
| `ResolverOptions` / `ResolverBuilder` | Validated channel configuration with stable C storage. |
| `ResolverFlags` | Channel behavior flags such as `USE_TCP`, `PRIMARY`, `IGNORE_TRUNCATION`, `EDNS`, and `DNS0X20` (`cares::options`). |
| `LookupStrategy` | Host lookup order across DNS and the hosts file (`cares::options`). |
| `AresError` | `Status`, `InvalidInput`, `InvalidRecord`, `AllocationFailed`, `ReentrantDriveForbidden`, `ThreadSafetyEnabled`, and `CallbackPanicked`. |
| `AresStatus` | Exact c-ares status, including `Unknown(i32)` for unrecognized values. |
| `ErrorKind` | `Temporal` (retry may help) or `Fatal` (`cares::error`). |

## Semantics

### Cancellation

`Resolver::cancel_query(handle)` (or `ChannelCtx::cancel(handle)` from inside a callback) retires one callback slot: its closure is dropped without being invoked, and the slot is recycled once c-ares delivers the final callback for the underlying query. No other query, socket, or server connection is disturbed, and the channel is not cancelled. `Resolver::cancel` is the opposite scope: it calls `ares_cancel`, aborts every query pending at entry, and delivers `AresStatus::Cancelled` to their callbacks synchronously. Queries submitted from those callbacks are not cancelled.

A handle is only meaningful while its generation matches the live slot. A stale handle is rejected with `AresError::InvalidInput`; after the query completes, the handle no longer refers to an active lookup.

### Panic Poisoning

The C trampoline takes the closure out of its slot before invoking user code. If the closure unwinds, `catch_unwind` stores the first payload on the channel and marks it poisoned. Unwinding never crosses the C frame. Subsequent submissions, cancellations, and completion-driving calls return `AresError::CallbackPanicked`; `is_poisoned` reports the state. A panicked callback leaves the resolver in an unknown state, so drop it instead of resuming it.

### Drop Order

Dropping a `Resolver` clears its channel pointer and then runs `ares_destroy` while the callback trampolines are still valid. Pending callbacks receive `AresStatus::Destruction`; a callback that tries to submit a follow-up sees a not-initialized error because the channel pointer is already cleared. The resolver then shuts down residual sockets and disarms the timer. When a resolver shares a proactor with other subsystems, drop the resolver before the proactor.

### Record Lifetimes

`DnsRecord` owns a `ares_dns_record_t` and frees it on drop. `DnsRecordRef<'cb>` borrows the pointer that c-ares passes to a completion callback; c-ares frees that message as soon as the callback returns. Use `to_owned_record()` (`ares_dns_record_duplicate`) or decode into a `T: FromDnsRecord` to keep data beyond the callback.

### Channel Context

`ChannelCtx<'cb>` is valid only for the duration of its callback. It permits follow-up `submit_query` / `submit_record` calls and logical `cancel` of a `QueryHandle`. It does not expose `poll_completions`, `wait_completions`, `resolve`, `reinit`, or drop. Calling `Resolver::resolve` while a callback is driving the channel returns `AresError::ReentrantDriveForbidden`.

### Server CSV

`set_servers_csv` accepts the c-ares comma-separated format. A nameserver entry is `ip[:port][%iface]`; an IPv6 address with a port must be bracketed. The `dns://` URI form is also accepted. For example:

```text
1.1.1.1,8.8.8.8:53,[2606:4700:4700::1111]:53,dns://9.9.9.9?tcpport=1153
```

A port defaults to the configured UDP or TCP port, then to 53. `%iface` applies to IPv6 link-local addresses. The pinned c-ares 1.34.9 release defines `dns+tls://` and `dns+https://` schemes but does not implement their secure transports, so do not use them.

### Threading and Library Initialization

`Resolver` is `!Send + !Sync`, and so are its callback contexts and borrowed records. Create, drive, and drop a resolver on one thread. `LibraryGuard` reference-counts library initialization, so multiple resolvers can exist on the same thread and the last one releases the library.

## Testing

The suites are organized into four dimensions.

- **Integration test** — `record_and_options_tests.rs` covers DNS wire encoding and decoding, all fourteen typed RR models, extended RCODE/OPT validation, and option bounds. `socket_bridge_and_timer_tests.rs` covers the ten `ares_socket_functions_ex` hooks, the deferred re-entrancy queue, `TimerState` re-arm generations, and sink panic isolation.
- **Lifecycle test** — `resolver_lifecycle_and_framing.rs` covers `LibraryGuard`-serialized initialization, concurrent submissions, sibling cancellation on one shared socket, cross-resolver handle rejection, and dropping a resolver with a pending query (destruction callback plus per-cycle descriptor balance). `proactor_timeout.rs` covers timer-driven teardown through a real `liburing::Proactor`.
- **Scenario test** — `adversarial_e2e.rs` covers fourteen record families, `TC=1` fallback, timeout-driven failover, cancellation, re-entrant follow-up queries, and panic poisoning. `resolver_lifecycle_and_framing.rs` adds one-byte TCP prefix/body fragmentation, multi-frame coalescing, `ECONNREFUSED` failover, and single-server packet-loss retry.
- **E2E test** — `adversarial_e2e.rs` drives a real `liburing::Proactor` with `ProactorResolver` (initial bridge capacity 1, so the UDP and TCP descriptors force registration growth), NOP and timeout completions, and full-chain resolution through `MockDnsServer`. `proactor_timeout.rs` proves the proactor-armed c-ares timer expires a black-holed query. `proactor_stress.rs` chains 10,000 queries through the same ring, each completion submitting the next.

```bash
cargo test -p cares --test mock_dns_server
cargo test -p cares --test record_and_options_tests
cargo test -p cares --test socket_bridge_and_timer_tests
cargo test -p cares --test adversarial_e2e
cargo test -p cares --test resolver_lifecycle_and_framing
cargo test -p cares --test proactor_timeout
cargo test -p cares --test proactor_stress
```

The full workspace gate is:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

The io_uring E2E tests skip when ring creation reports `EPERM`, `EACCES`, or `ENOSYS`. All other suites run on any Linux x86_64 host.

## Features and Limitations

- **Toolchain.** Linux `x86_64`, Rust edition 2024, pinned nightly.
- **Build.** CMake, a C compiler, and `git`; offline builds set `CARES_DIR` to a c-ares CMake source tree. Without `CARES_DIR`, `cares-sys` clones the selected c-ares ref into the Cargo target directory.
- **c-ares versions.** `cares-sys` exposes two source features. The default `pre-release` feature tracks upstream `main`; `stable` pins `v1.34.9` and wins when both are enabled. Both builds use `CARES_THREADS=OFF`.
- **No async runtime.** There are no futures, executors, or wakers. Use the callback API with a shared proactor, or the standalone completion methods.
- **Thread affinity.** A resolver cannot move between threads. The type system enforces this.
- **Secure DNS schemes.** `dns+tls://` and `dns+https://` are parsed but not implemented by the pinned c-ares 1.34.9 release.
- **No pending-write callback.** `ares_set_pending_write_cb` is never installed; TCP short writes are handled by the socket bridge.

## License

Licensed under the MIT License. c-ares is also MIT licensed. liburing is distributed under the GNU Lesser General Public License, version 2.1; see the liburing-rs repository for its licensing details.
