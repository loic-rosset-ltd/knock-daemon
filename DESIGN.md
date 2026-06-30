# knock-daemon — design

A port-knocking daemon for Linux that replaces classic [`knockd`](https://www.zeroflux.org/projects/knock).
Its reason to exist is **correct concurrent sequence matching**: many clients
knocking at the same time — including the same door, fully interleaved — without
sequences corrupting one another.

## Why not just use knockd

`knockd` walks captured packets through a single, globally-shared set of
per-door state machines. When two clients knock simultaneously, or when doors
share ports, their progress interleaves into the same state and the matcher gets
confused — a real client's sequence can be derailed by an unrelated packet that
happens to land mid-sequence. It is also effectively single-threaded around
libpcap, offers little beyond the basic match→command behaviour, and its config
is showing its age.

The macOS Knock client already works around the *client*-side symptom: it
serialises knock sequences per resolved server IP so it never sends two
interleaved sequences to one host (`KnockService.performKnockQueued`). The daemon
fixes the *server* side properly, so correctness no longer depends on clients
being polite.

## Core idea: per-source isolation

In-flight matching state is partitioned **by source IP**. Within a source we keep
an independent in-flight *attempt* for every door. Consequences:

- **Concurrent clients never interfere** — each source IP owns its own bucket.
  Two clients knocking the same door, packet-for-packet interleaved, both succeed.
- **Overlapping doors both advance** — a packet matching the next step of several
  candidate attempts drives all of them forward.
- **Naturally shardable** — because sources are independent, the design scales by
  hashing source IP across worker shards with zero cross-shard coordination. This
  is realised by `ShardedMatcher` and the runtime's per-shard worker threads: the
  capture loop only hashes each packet to a shard (`matcher::shard_for`) and hands
  it off down a channel, so packet decoding never blocks on matching or firewall
  I/O, and a source always lands on the same shard so its isolation is preserved.

The matcher (`src/matcher.rs`) is **pure and deterministic**: each event carries a
logical millisecond timestamp instead of the matcher reading the clock, so the
whole thing is unit-testable without packets, sockets, or sleeps. The test suite
covers the defining cases — interleaved concurrent sources, overlapping doors,
timeout expiry, and noise-tolerance.

### Matching rules (MVP)

For each observed packet `(src, port, proto, t)`:

1. Reap this source's attempts whose `t - started > seq_timeout`.
2. Advance every in-flight attempt whose next expected step equals `(port, proto)`;
   an attempt that reaches the end of its door's sequence **completes**.
3. Open a fresh attempt for every door whose **first** step equals `(port, proto)`.
   (A stray opening-port hit starts a new candidate instead of corrupting an
   in-flight one — this is what makes retries and interleaving safe.)
4. Bound per-IP state at `MAX_ATTEMPTS_PER_IP` (drop oldest) so a hostile source
   can't grow daemon memory without limit.

Deliberate choice (the default **tolerant** mode): an out-of-sequence packet to
an **unrelated** port does *not* reset progress; correctness leans on
`seq_timeout` instead. This is more robust to background noise and concurrent
traffic than knockd's reset-on-stray behaviour. A **reset** mode is selectable
(`[matching] mode = "reset"`, the default for parsed knockd `.conf` files) for
knockd parity: there, a hit to one of a door's *own* sequence ports that isn't
the expected next step aborts that attempt, and a fresh hit to the first step
restarts it.

## Architecture

```
        ┌──────────┐   PacketEvent    ┌───────────┐   Completed    ┌────────────┐
  NIC → │ Capture  │ ───────────────▶ │  Matcher  │ ─────────────▶ │  Firewall  │
        │ (trait)  │  src,port,proto  │ (per-IP)  │   door, src    │  (trait)   │
        └──────────┘                  └───────────┘                └────────────┘
      afpacket | pcap | replay          pure core                  command | nftables
```

- **`capture/`** — `Capture` trait yielding normalised `PacketEvent`s. Frame
  decoding (Ethernet, 802.1Q/802.1ad VLAN incl. stacked QinQ, IPv4, IPv6 with a
  bounded extension-header walk, TCP-SYN, UDP) lives in the pure `capture::parse`
  module and is fully unit-tested against hand-built frames — every live backend
  shares it.
  - `afpacket` backend (feature `capture-afpacket`, Linux): pure-Rust `AF_PACKET`
    `SOCK_RAW` socket via `libc`, **no libpcap C dependency**. A hand-built kernel
    cBPF prefilter (`SO_ATTACH_FILTER`, from the union of door ports — see
    `capture::bpf`) drops irrelevant frames before they reach userspace, with the
    userspace decoder as the source-of-truth backstop. Preferred live backend when
    built in.
  - `pcap` backend (feature `capture-pcap`): libpcap + a kernel-side BPF filter
    built from the union of door ports.
  - `replay` backend: deterministic, used by `--demo` and tests.
  - `capture::open_live` picks the best backend compiled in (afpacket > pcap).
- **`matcher.rs`** — the concurrent core described above, plus `ShardedMatcher`
  (the per-IP partition that lets each shard run on its own worker thread).
- **`ratelimit.rs`** — an optional per-source token-bucket rate limiter, in the
  same clock-injected, fully-unit-tested spirit as the matcher. A source over its
  budget has packets dropped before they reach the matcher, so a flood can't drown
  out legitimate knocks or burn CPU. One limiter lives inside each shard, so it
  needs no cross-shard coordination either.
- **`stats.rs`** — process-wide atomic counters (packets observed/rate-limited,
  knocks accepted overall and per door, in-flight sources) exposed in Prometheus
  text format over a minimal HTTP `/metrics` endpoint (`[stats] listen`). The
  renderer is pure and unit-tested; the listener is thin glue.
- **`firewall/`** — `Firewall` trait with open/close side effects. The runtime
  hands each backend a per-door `Action` (open/close commands, nft set, timeout),
  so backends stay decoupled from config parsing.
  - `command` backend: substitute `%IP%` and run via the shell — a drop-in for
    existing knockd command setups. Expiry is a userspace timer that runs the
    close command after `cmd_timeout`.
  - `nftables` backend: add the source to a named allow-set as an element with a
    kernel-side timeout — `nft add element <family> <table> <set> { <ip> timeout
    <T> }`. One atomic call, no fork per knock, and the kernel reaps the element
    on its own, so the backend reports `auto_expires()` and the runtime skips the
    userspace close timer. (The argv builders are pure and unit-tested without
    `nft` present.)
- **`config.rs`** — native TOML config → validated runtime doors, plus the
  firewall-backend and matching-mode selectors.
- **`knockd.rs`** — compatibility parser for classic knockd `.conf` files,
  lowering them onto the same `Config`. Selected automatically by the `.conf`
  extension, so an existing knockd deployment migrates by pointing `--config` at
  its current file.
- **`main.rs`** — CLI (`--config`, `--check`, `--demo`), logging, and the
  capture→match→act wiring, including `cmd_timeout` auto-close timers.

## Decisions

- **Rust** over Go: this is a long-running, root-privileged network listener that
  touches the firewall. Memory safety with no GC, a small predictable footprint,
  and a single static binary are exactly what a security daemon wants. (Go was the
  faster-MVP alternative; the matcher's determinism and the privilege profile
  tipped it to Rust.)
- **Pure, clock-injected matcher** so the differentiating logic is fully tested
  without I/O.
- **Capture and firewall behind traits** so libpcap and the firewall mechanism are
  swappable and the core stays portable and testable.
- **knockd-compatible `command` firewall first** so existing deployments migrate
  with their existing open/close commands.

## Roadmap

1. **MVP (this scaffold):** concurrent matcher + tests, TOML config, libpcap
   capture (feature-gated), command firewall, `--demo`/`--check`.
2. ~~nftables firewall backend (allow-set element + kernel timeout).~~ **Done** —
   `nft_set` per door, kernel-side element timeout, no userspace close timer.
3. ~~Pure-Rust `AF_PACKET` capture; IPv6 + VLAN; kernel cBPF prefilter.~~ **Done** —
   `capture-afpacket` backend (libc, no libpcap), shared `capture::parse` decoder
   handling IPv4/IPv6/VLAN/QinQ, plus a hand-built `SO_ATTACH_FILTER` cBPF
   prefilter (`capture::bpf`, unit-tested with a software cBPF interpreter).
4. ~~knockd `.conf` compatibility parser; strict/reset matching mode.~~ **Done** —
   `knockd.rs` parser (auto-selected by extension) + `MatchMode::{Tolerant,Reset}`.
5. ~~Sharded multi-worker matching; per-source rate limiting; a stats/observability
   endpoint.~~ **Done** — `ShardedMatcher` + per-shard worker threads (one
   `mpsc` channel each, routed by `matcher::shard_for`), a clock-injected
   per-source token-bucket `RateLimiter` (`ratelimit.rs`), and a Prometheus
   `/metrics` endpoint (`stats.rs`).
6. ~~systemd unit + capability-based privilege (CAP_NET_RAW + CAP_NET_ADMIN)
   instead of full root.~~ **Done** — `packaging/systemd/knockd2.service`
   (DynamicUser + AmbientCapabilities + hardening).

## Privileges & threat model

Live capture needs `CAP_NET_RAW`; the nftables backend needs `CAP_NET_ADMIN`. The
daemon runs with exactly those two capabilities and no more — the shipped systemd
unit (`packaging/systemd/knockd2.service`) uses a `DynamicUser` plus
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` and a hardening sandbox instead of
running as root; the ambient grant is inherited by any `nft`/`iptables` child the
command backend execs. The daemon observes opening packets only and never
terminates connections, so it can't be tricked into dropping traffic. Per-IP
state is bounded (`MAX_ATTEMPTS_PER_IP`) to blunt state-exhaustion attempts, and
the optional per-source rate limiter (`[matching] rate_limit`) sheds a flood
before it reaches the matcher at all. The stats endpoint (`[stats] listen`) is a
plain TCP listener needing no extra capability; bind it to localhost (or a
trusted management interface) since it exposes operational counters, not secrets.
Knock secrecy is the usual port-knocking model — the sequence is the secret;
combine with `seq_timeout` and short `cmd_timeout` windows to limit replay value.
