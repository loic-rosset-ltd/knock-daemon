# Contributing to knock-daemon

Thanks for looking. This daemon guards a firewall on machines people care about,
so the bar is "boring and provable" rather than clever.

## Build and test

```sh
cargo test                      # 64 tests, no root, no libpcap, no network
cargo run -- --demo             # two clients knocking one door, fully interleaved
cargo run -- --check --config knockd.toml
cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

Feature flags select the capture backend: `capture-afpacket` (pure Rust, Linux,
the shipped default for releases) and `capture-pcap` (libpcap). The default
`cargo test` build needs neither — the matcher is pure, so the core is testable
on macOS as well as Linux. CI runs the test suite across every feature
combination that has a code path on the OS it is running on.

Live capture and the nftables backend need Linux and
`CAP_NET_RAW`/`CAP_NET_ADMIN`. `ci/wire-test.sh` exercises the whole path against
a real socket and a real nftables set.

## What a good change looks like

- **The matcher stays pure.** `src/matcher.rs` takes a logical millisecond
  timestamp per event and never reads the clock. That is what makes the
  concurrency behaviour testable without sockets or sleeps. A change that makes
  the matcher call `Instant::now()` will be sent back.
- **New matching behaviour comes with a test that fails without it**, expressed
  as an event sequence. Interleaving, overlapping doors, timeout expiry and noise
  tolerance are the cases that matter; add to them rather than around them.
- **Capture and firewall work goes behind the existing traits** so backends stay
  swappable and the core stays portable.
- **No new inbound network surface** without discussing it first. The daemon
  currently observes packets and accepts no connections in its data path, which
  is why it can run on two capabilities instead of root. That property is a
  feature, not an accident.
- `cargo fmt` clean, `clippy -D warnings` clean.

## Reporting bugs

Use the issue templates. For anything with a security dimension, do **not** open
an issue — see [SECURITY.md](SECURITY.md).

A good bug report includes your config (redact hosts/ports if you like, but keep
the shape), what you knocked, what you expected, and what the firewall actually
did. `--check` output and the `[stats]` counters are usually enough to see where
a sequence died.

## Licence of contributions

The project is dual-licensed `MIT OR Apache-2.0`. By submitting a contribution
you agree it is licensed under both, matching the rest of the project. No CLA.
