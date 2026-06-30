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
  hashing source IP across worker shards with zero cross-shard coordination.
  (MVP runs single-threaded matching; the data model is the part that matters.)

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

Deliberate choice: an out-of-sequence packet to an **unrelated** port does *not*
reset progress; correctness leans on `seq_timeout` instead. This is more robust to
background noise and concurrent traffic than knockd's reset-on-stray behaviour.
A configurable strict/reset mode is a planned option for knockd parity.

## Architecture

```
        ┌──────────┐   PacketEvent    ┌───────────┐   Completed    ┌────────────┐
  NIC → │ Capture  │ ───────────────▶ │  Matcher  │ ─────────────▶ │  Firewall  │
        │ (trait)  │  src,port,proto  │ (per-IP)  │   door, src    │  (trait)   │
        └──────────┘                  └───────────┘                └────────────┘
         pcap | replay                  pure core                  command | nftables
```

- **`capture/`** — `Capture` trait yielding normalised `PacketEvent`s.
  - `pcap` backend (feature `capture-pcap`): libpcap + a kernel-side BPF filter
    built from the union of door ports; emits one event per inbound TCP SYN and
    per UDP datagram. *Planned:* pure-Rust `AF_PACKET`/eBPF backend to drop the
    libpcap C dependency, plus IPv6 and VLAN handling.
  - `replay` backend: deterministic, used by `--demo` and tests.
- **`matcher.rs`** — the concurrent core described above.
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
- **`config.rs`** — TOML config → validated runtime doors. A knockd-`.conf`
  compatibility parser is planned to ease migration.
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
3. Pure-Rust `AF_PACKET`/eBPF capture; IPv6 + VLAN.
4. knockd `.conf` compatibility parser; strict/reset matching mode.
5. Sharded multi-worker matching; per-source rate limiting; a stats/observability
   endpoint.
6. systemd unit + capability-based privilege (CAP_NET_RAW + CAP_NET_ADMIN) instead
   of full root.

## Privileges & threat model

Live capture needs `CAP_NET_RAW`; the nftables backend needs `CAP_NET_ADMIN`. The
daemon observes opening packets only and never terminates connections, so it can't
be tricked into dropping traffic. Per-IP state is bounded (`MAX_ATTEMPTS_PER_IP`)
to blunt state-exhaustion attempts; per-source rate limiting is on the roadmap.
Knock secrecy is the usual port-knocking model — the sequence is the secret;
combine with `seq_timeout` and short `cmd_timeout` windows to limit replay value.
