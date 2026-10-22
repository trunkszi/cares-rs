# cares-rs

Safe, threadless, completion-driven Rust 2024 bindings for upstream [c-ares](https://github.com/c-ares/c-ares), built on [liburing-rs](https://github.com/trunkszi/liburing-rs). c-ares is compiled with `CARES_THREADS=OFF`; there is no async runtime, background event thread, or readiness reactor.

## Design

- **Threadless c-ares.** The native library is built with `CARES_THREADS=OFF` and `CARES_SHARED=OFF`; it contains no pthread mutexes, no event thread, and no `ARES_OPT_EVENT_THREAD`.
- **Single-thread resolver.** `Resolver` is `!Send + !Sync`. Socket readiness, retry deadlines, and user callbacks all run on the thread that owns it.
- **Two completion drivers.** Standalone mode uses `wait_completions`, `poll_completions`, or `resolve`. Shared-ring mode uses `ProactorResolver` and `liburing::UringSocketBridge` on the caller's `liburing::Proactor`, alongside other `SubsystemId` handlers.
- **Safe callback boundary.** `DnsRecordRef<'cb>` cannot escape its callback. `ChannelCtx<'cb>` exposes only re-entrant-safe operations, and panics are caught at the FFI boundary and poison the resolver instead of unwinding into C.

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

## Build and Test

Run every command from the workspace root. The incremental gate also runs all three examples.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
bash .github/scripts/ci-incremental.sh
```

## License

MIT. c-ares is MIT licensed; liburing is distributed under LGPL-2.1. See the upstream projects for their full license texts.
