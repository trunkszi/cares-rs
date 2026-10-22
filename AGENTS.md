# AGENTS.md

Operational contract for coding agents working in `cares-rs`. This file is the authoritative source for repository architecture, build and verification commands, and coding invariants. Read it before planning, reviewing, or editing any crate in this workspace.

## Project Overview

`cares-rs` is a safe, threadless, single-threaded, completion-driven Rust 2024 binding for upstream [c-ares](https://github.com/c-ares/c-ares), pinned to `v1.34.9` by the `stable` feature, built on [`liburing-rs`](../liburing-rs). There is no async runtime, no background event thread, no readiness reactor, and no hidden lock inside the library: `c-ares` sockets are real nonblocking descriptors whose readiness and completion events arrive through an `io_uring` proactor on the calling thread. `Resolver`, `ChannelCtx`, and the borrowed record views are `!Send + !Sync`.

`c-ares` is compiled from source with thread support disabled. A resolver therefore has one owner thread, and every completion callback runs synchronously on that thread, including callbacks triggered from inside `ares_query_dnsrec`, `ares_process_fds`, and `ares_destroy`.

## Workspace Layout

```text
cares-rs/
├── Cargo.toml                       # Workspace members, shared dependencies, lints, profiles
├── rust-toolchain.toml              # Pinned nightly toolchain and components
├── rustfmt.toml                     # Formatting configuration
├── AGENTS.md                        # This file
├── README.md                        # User-facing architecture and API documentation
├── crates/
│   ├── cares-sys/                   # L1: static c-ares build and raw FFI
│   │   ├── build.rs
│   │   ├── src/{lib,channel,consts,enums,types,socket_ex,dns_rec}.rs
│   │   └── tests/{abi_probe.c,abi_and_symbols.rs,support/abi_values.rs}
│   ├── cares-macros/                # L2: compile-time DNS procedural toolkit
│   └── cares/                       # L3: safe resolver and tests
│       ├── src/lib.rs
│       ├── src/error.rs
│       ├── src/types.rs
│       ├── src/record.rs
│       ├── src/record_rr.rs
│       ├── src/options.rs
│       ├── src/callbacks.rs
│       ├── src/socket_bridge.rs
│       ├── src/timer.rs
│       ├── src/resolver.rs
│       ├── examples/                 # dns_packet_codec_and_edns, standalone_resolver_and_records,
│       │                             # proactor_shared_ring_resolver
│       └── tests/{mock_dns_server,adversarial_e2e}.rs
└── .github/scripts/ci-incremental.sh # Full incremental gate in the integrated workspace
```

## Crate Layering

| Layer | Crate | Responsibilities and dependency boundaries |
| --- | --- | --- |
| L1 | `cares-sys` | Resolves or clones the upstream c-ares source tree, builds `libcares.a` with CMake, verifies the threadless configuration and modern header surface, and exposes raw `unsafe` FFI. Depends only on `libc` at runtime and `cmake` + `cc` at build time. Contains no `liburing` code. |
| L2 | `cares-macros` | Proc-macro crate for `#[derive(DnsRecord)]`, `#[derive(DnsBundle)]`, `dns_name!`, `dns_servers!`, `dns_query!`, and `#[cares_callback]`. Depends on `syn`, `quote`, and `proc-macro2`; it does not depend on `cares` or `cares-sys`. |
| L3 | `cares` | Depends on `cares-sys`, `cares-macros`, `liburing`, `liburing-macros`, `libc`, `bitflags`, and `thiserror`. Owns the safe API: errors, DNS types, owned records and callback-scoped views, typed RR models, options, callback slots and trampolines, the socket bridge, the timer state, and `Resolver`. |

Dependencies point downward only. `cares-sys` and `cares-macros` must never depend on `cares`; `cares` must never reach into `cares-sys` internals through a module path rather than its public re-exports.

### Module Responsibilities

| Module | Owner | Responsibility |
| --- | --- | --- |
| `cares-sys/src/lib.rs` | L1 | Re-exports the FFI modules and documents the raw contract. |
| `cares-sys/src/channel.rs` | L1 | Library initialization, channel creation and destruction, server configuration, event processing, and every query entry point. |
| `cares-sys/src/consts.rs` | L1 | Channel option masks and c-ares constants. |
| `cares-sys/src/enums.rs` | L1 | `#[repr(transparent)]` newtypes for every C enum, including unnamed wire values. |
| `cares-sys/src/types.rs` | L1 | C layouts, opaque handles, and callback function-pointer types. |
| `cares-sys/src/socket_ex.rs` | L1 | The 10-hook `ares_socket_functions_ex` vtable for ABI version 1. |
| `cares-sys/src/dns_rec.rs` | L1 | DNS record creation, query and RR access, wire parse/write, duplicate, and destroy. |
| `cares-macros/src/lib.rs` | L2 | Compile-time domain, server-list, and query validation; derive macros for record conversion and bundled queries. |
| `cares/src/error.rs` | L3 | `AresError`, `AresStatus`, `ErrorKind`, and `Result`. |
| `cares/src/types.rs` | L3 | `DnsRecordType`, `DnsClass`, `DnsSection`, `DnsOpcode`, `DnsRcode`, `DnsFlags`, `ServerStateFlags`, `HostEntry`, `NameInfo`, and `SocketAddress`. |
| `cares/src/record.rs` | L3 | Owned `DnsRecord`, callback-scoped `DnsRecordRef<'cb>`, `DnsRecordBuilder`, and the `FromDnsRecord` / `IntoDnsRecord` traits. |
| `cares/src/record_rr.rs` | L3 | Borrowed `DnsRr` / `DnsRrMut`, and the typed record models (`ARecord`, `AaaaRecord`, `CnameRecord`, `MxRecord`, `TxtRecord`, `SrvRecord`, `PtrRecord`, `SoaRecord`, `NaptrRecord`, `UriRecord`, `CaaRecord`, `TlsaRecord`, `HttpsRecord`, `SvcbRecord`, `NsRecord`, `OptRecord`). |
| `cares/src/options.rs` | L3 | `ResolverBuilder`, `ResolverOptions`, `ResolverFlags`, and `LookupStrategy`. |
| `cares/src/callbacks.rs` | L3 | `CallbackState`, per-query `CallbackSlot<F>`, and the DNS, host, and name-info C trampolines. |
| `cares/src/socket_bridge.rs` | L3 | `SharedChannelState`: the socket table, the 10-hook vtable installation, readiness coalescing, the sticky-error latch, and socket shutdown. |
| `cares/src/timer.rs` | L3 | `TimerState` and `TimerDeadline`: the `ares_timeout` deadline, generation, and expiry handshake. |
| `cares/src/resolver.rs` | L3 | `Resolver`, `ChannelCtx<'cb>`, completion and state callbacks, `ResolverCqe`, and `PollOutcome`. |
| `cares/src/lib.rs` | L3 | `LibraryGuard`, `QueryHandle`, public re-exports, and crate-level documentation. |
| `cares/tests/mock_dns_server.rs` | L3 | Deterministic localhost UDP/TCP DNS server used by the integration suite. |
| `cares/tests/adversarial_e2e.rs` | L3 | End-to-end resolver tests over real sockets, including failure and teardown paths. |

## Build, Lint, and Test Commands

Run every command from the workspace root. These are the commands to run; do not report them as passed unless they were actually executed in this checkout.

| Command | Purpose |
| --- | --- |
| `cargo fmt --all -- --check` | Check formatting across all workspace crates. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Strict lint gate for libraries, tests, examples, and benchmarks. |
| `cargo test --workspace` | Run unit, integration, and doc tests with the default `pre-release` feature. |
| `cargo test -p cares-sys --no-default-features --features stable` | Build and test against the pinned c-ares `v1.34.9` tag. |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | Build rustdoc with warnings denied. |
| `cargo test -p cares --test mock_dns_server` | Run the mock DNS server target on its own. |
| `cargo test -p cares --test adversarial_e2e` | Run the end-to-end resolver suite. |
| `cargo run -p cares --example dns_packet_codec_and_edns` | Run the DNS packet codec and EDNS example. |
| `cargo run -p cares --example standalone_resolver_and_records` | Run the standalone resolver and typed-record example. |
| `cargo run -p cares --example proactor_shared_ring_resolver` | Run the shared-ring proactor example. |
| `bash .github/scripts/ci-incremental.sh` | Full incremental gate in the integrated workspace. |

`.github/scripts/ci-incremental.sh` is added when the workspace is integrated and is not present in this worktree. When it is absent, run the equivalent commands in the table above; when it is present, run it before completing a change.

The workspace has three required example targets under `crates/cares/examples/`. Run each one before completing a change:

```bash
cargo run -p cares --example dns_packet_codec_and_edns
cargo run -p cares --example standalone_resolver_and_records
cargo run -p cares --example proactor_shared_ring_resolver
```

`dns_packet_codec_and_edns` exercises DNS message encoding, decoding, and `OPT`/EDNS handling. `standalone_resolver_and_records` resolves through the standalone completion driver and decodes typed records. `proactor_shared_ring_resolver` registers `ProactorResolver` on a real `liburing::Proactor` and drives completions from the shared ring.

## Hard Invariants

### Platform and Toolchain

- Linux `x86_64`, Rust edition `2024`, pinned nightly in `rust-toolchain.toml`.
- The workspace uses `resolver = "3"` and workspace-level lints. Member crates inherit with `[lints] workspace = true`.
- Shared dependencies are declared in the root `[workspace.dependencies]` and inherited with `{ workspace = true }`.
- Release builds use `panic = "abort"`. System boundaries return `Result`; do not abort a caller on a recoverable C status.

### Static, Threadless c-ares Build

- `cares-sys` never uses `pkg-config` and never links a system `libcares.so`.
- `build.rs` resolves the source tree in this order: `CARES_DIR` (must be a valid CMake source tree), then a cached clone under the Cargo target directory.
- CMake is invoked with `CARES_STATIC=ON`, `CARES_SHARED=OFF`, `CARES_THREADS=OFF`, `CARES_BUILD_TOOLS=OFF`, `CARES_BUILD_TESTS=OFF`, `CARES_STATIC_PIC=ON`, and `CARES_INSTALL=ON`.
- The build verifies that `ares_config.h` does not define `CARES_THREADS`, compiles a C header probe against the modern symbols, and asserts that `libcares.a` was installed.
- The default `pre-release` feature tracks upstream `main`. The `stable` feature selects the pinned `v1.34.9` tag, including when both features are enabled. Both builds disable thread support.
- Channel construction asserts `ares_threadsafety() == ARES_FALSE`. A linked library that reports thread safety returns `AresError::ThreadSafetyEnabled` instead of creating a channel.

### Socket Bridge and Completion Model

- Install `ares_socket_functions_ex` with `version = 1` and `flags = ARES_SOCKFUNC_FLAG_NONBLOCKING`. The table has ten hooks: `asocket`, `aclose`, `asetsockopt`, `aconnect`, `arecvfrom`, `asendto`, `agetsockname`, `abind`, `aif_nametoindex`, and `aif_indextoname`.
- Every socket returned by `asocket` is nonblocking and close-on-exec. `arecvfrom` must populate the peer address so c-ares can validate the UDP response source.
- Never install `ares_set_pending_write_cb`. TCP short writes are re-submitted by the socket bridge; c-ares consumes the byte count returned by `asendto`.
- Latch asynchronous socket errors (for example `ECONNREFUSED` and `ECONNRESET`) on the socket entry and return them from the next `arecvfrom` or `asendto` call. There is no `getsockopt(SO_ERROR)` hook in the vtable.
- In shared-ring mode, the caller feeds `ResolverCqe::Socket` and `ResolverCqe::Timer` events to `Resolver::on_cqe`. In standalone mode, the caller uses `Resolver::poll_completions` or `Resolver::wait_completions`. Do not introduce an epoll, `mio`, `polling`, `tokio`, or `async-std` path.
- `ProactorResolver` implements the shared-ring path on a real `liburing::Proactor`: it installs a `UringSocketBridge` readiness sink, stages bridge poll/control operations through the proactor, and drives `Resolver::on_cqe` from bridge completions. The caller registers the driver, flushes its initial registrations, and calls `Proactor::wait_completions`.
- Derive the next deadline from `ares_timeout` and deliver it through `TimerState`. A timer completion is valid only when its generation still matches the current deadline.
- Never use `std::thread::sleep` in library code or tests that drive the resolver. Waiting is expressed through proactor timers, `ares_timeout`, or the standalone completion methods.
- The library never spawns a thread. The mock DNS server test helper may spawn threads; that is test infrastructure, not the library's execution model.

### Re-entrancy, Callbacks, and Lifetimes

- Register a callback slot before calling `ares_query_dnsrec`, `ares_send_dnsrec`, `ares_gethostbyname`, `ares_gethostbyaddr`, or `ares_getnameinfo`. c-ares may invoke the callback synchronously on a cache hit or an immediate error.
- Pass `Rc<CallbackSlot<F>>` as the FFI `arg` with `Rc::into_raw`. The trampoline reconstructs it with `Rc::from_raw` and takes the closure before invoking user code, so a callback can submit follow-up queries without aliasing the slot registry.
- Track completion per slot with `CallbackSlot::is_completed`. Do not infer completion from a channel-wide flag; one slot completing says nothing about its siblings.
- Catch every unwind at the FFI boundary with `catch_unwind`; store the first payload on the channel. A panic poisons the resolver: subsequent submissions, cancellations, and completion-driving calls return `AresError::CallbackPanicked`, and the resolver must be dropped rather than resumed.
- `ChannelCtx<'cb>` is valid only for the callback. It permits follow-up submissions (`submit_query`, `submit_record`) and logical per-query cancellation. It forbids recursive driving, `reinit`, and destruction. `Resolver::resolve` returns `AresError::ReentrantDriveForbidden` when called while a callback is driving the channel; the other driving entry points are not reachable through `ChannelCtx`.
- `DnsRecordRef<'cb>` borrows a message that c-ares frees when the callback returns. It must not escape the callback. Copy it with `to_owned_record()` or decode it into an owned `T: FromDnsRecord` before returning.
- `Resolver::cancel_query` (or `ChannelCtx::cancel`) retires one callback slot: the closure is dropped without being invoked, and the slot is recycled after c-ares delivers the final callback for the underlying query. `Resolver::cancel` is the channel-wide `ares_cancel`: it aborts every query pending at entry and delivers `AresStatus::Cancelled` synchronously. Queries submitted from those callbacks are not cancelled.
- Dropping a resolver clears its channel pointer, runs `ares_destroy` while the callback trampolines are still valid, then shuts down residual sockets and disarms the timer. Pending callbacks observe `AresStatus::Destruction`; follow-up submissions from those callbacks fail with a not-initialized status.

### Safety, Documentation, and Style

- Every file must be at most 800 lines. Split a module or test by responsibility before reaching the limit.
- Every `unsafe` block needs a preceding `// SAFETY:` comment that states the pointer, lifetime, aliasing, or initialization invariant. Every `unsafe fn` needs a `# Safety` rustdoc section. Fallible public functions need `# Errors`; public functions with a panic path need `# Panics`.
- Do not use `unwrap`, `expect`, `panic!`, `todo`, or `unimplemented` in library code. Tests may use `expect` or `panic!` for assertions and setup.
- All repository text is English: source comments, rustdoc, error messages, CLI output, and documentation. There must be zero CJK characters.
- Comments explain constraints the code cannot express, not the history of the edit. Do not write conversation notes, review acknowledgements, or task identifiers into source.
- The workspace lints deny `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks`, `missing_safety_doc`, `missing_errors_doc`, `missing_panics_doc`, `todo`, and `unimplemented`, among others. Treat a new lint warning as a defect.

## Testing Map

`crates/cares/tests/mock_dns_server.rs` is a deterministic localhost DNS server. It binds UDP and TCP on `127.0.0.1:0`, publishes its CSV endpoint, and records query counts. `servers_csv` names the UDP endpoint; `servers_csv_with_tcp` uses the URI form `dns://127.0.0.1:<udp_port>?tcpport=<tcp_port>` when the transports bind different ports. Its `Zone` builder covers the typed record models used by the suite. Its `Behavior` switch injects `Normal`, `TruncateUdp`, `DropUdp`, `Delay`, `ServFail`, and `NxDomain`. TCP frames carry the standard two-byte big-endian length prefix. The helper is usable as a standalone test target and is included by `adversarial_e2e.rs` and `resolver_lifecycle_and_framing.rs` through `#[path = "mock_dns_server.rs"] mod mock_dns_server;`.

`crates/cares/tests/adversarial_e2e.rs` drives `Resolver` over real sockets. The suite is organized into seven groups:

1. **Record coverage** - resolve and decode fourteen RR types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `PTR`, `SOA`, `NAPTR`, `URI`, `CAA`, `TLSA`, `HTTPS`, and `SVCB`.
2. **TCP fallback** - a UDP response with `TC=1` falls back to TCP and preserves the answer; an explicit `USE_TCP` resolver sends no UDP query. The mock server's standalone tests cover the two-byte length prefix on the TCP path.
3. **Timeouts and failover** - a black-holed primary is abandoned and the query fails over to the next configured server within a bounded time; both failed and successful server-state events are reported.
4. **Cancellation** - `Resolver::cancel` delivers `AresStatus::Cancelled` to pending callbacks and leaves the channel usable; `Resolver::cancel_query` drops one closure uninvoked, leaves the channel usable, and does not poison it.
5. **Re-entrancy** - a `CNAME` callback submits an `A` follow-up through `ChannelCtx`; the outer `&mut Resolver` stays on the driving thread.
6. **Panics and resources** - a panicking callback poisons the resolver with `AresError::CallbackPanicked`; a 10,000-query stress run checks completion accounting, followed by a fresh-resolver teardown proxy that must still create sockets and resolve a new name.
7. **Real io_uring** - `io_uring_proactor_drives_resolver_against_mock` registers `ProactorResolver` (bridge capacity 1) and a NOP subsystem on a real `liburing::Proactor`, forces a `TC=1` UDP-to-TCP fallback so the second descriptor grows the bridge registration table, and resolves the mock A record through `UringSocketBridge` while both subsystems receive completions.

`crates/cares/tests/resolver_lifecycle_and_framing.rs` covers the scenario and lifecycle dimensions: one-byte TCP prefix/body fragmentation, multi-frame coalescing over one shared connection, `ECONNREFUSED` failover, single-server packet-loss retry, sibling cancellation on one shared socket, and dropping a resolver with a pending query (`AresStatus::Destruction` plus per-cycle socket-descriptor balance). `crates/cares/tests/proactor_timeout.rs` proves that `ProactorResolver` arms the c-ares deadline on the ring: a black-holed query completes with `AresStatus::Timeout` without standalone driving. `crates/cares/tests/proactor_stress.rs` chains 10,000 queries through the same ring, each completion submitting the next through `ChannelCtx`.

The single-thread contract is enforced by `!Send + !Sync` and by the library creating no threads. A process-wide `/proc/self/status` thread count is not attributable while the test harness runs tests in parallel, so the suite does not use one.

The `cares-sys` ABI test additionally asserts the C layouts, the modern symbol surface, `ares_threadsafety() == ARES_FALSE`, and the DNS record create/write/parse/duplicate lifecycle.

## Change Hygiene

- Inspect `git status` and `git diff` before and after edits. Keep the diff limited to the requested crate and behavior.
- Do not run `git commit`, `git add`, `git reset`, `git rebase`, or a destructive checkout unless the user explicitly asks.
- Update this file and `README.md` in the same change whenever crate names, paths, features, commands, or public API contracts change.
- When a change touches a wire-visible type, a callback signature, or the socket vtable, verify both the producer and the consumer paths in the same workspace.
