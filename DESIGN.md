# knock-daemon — design

A port-knocking daemon for Linux that replaces classic [`knockd`](https://github.com/jvinet/knock).
Its reason to exist is **correct concurrent sequence matching**: many clients
knocking at the same time — including the same door, fully interleaved — without
sequences corrupting one another.

## Why not just use knockd

`knockd` is not the strawman it is often made into, and it is worth being exact
about what it does — the audience for this daemon can read `knockd.c` in an
afternoon, and several of them will.

**It already partitions by source IP.** `knockd.c:103-113` says so verbatim
("we keep one list of knock attempts per IP address") and the lookup at
`knockd.c:1802` is a `strcmp` on the source address. Any claim that concurrent
clients collide in shared global state is false, and this document used to make
it.

What `knockd` does not do is tolerate the unexpected *within* one source's lane.
It keeps at most one in-flight attempt per source per door, and any packet that
is not the exact next step destroys it (`knockd.c:1812-1836`; `stage = -1` at
`:1829`) — including a re-hit of the door's own first port, because the
new-attempt branch only runs for a source with no attempt in flight. So a TCP
retransmit, a client that retries, or a second person behind the same NAT address
silently ends a knock in progress and starts nothing in its place.

That is the whole difference, and it is narrow. knock-daemon keeps a *set* of
candidate attempts per source and adds to it, so those three cases resolve
independently. `mode = "reset"` restores knockd's behaviour exactly.

### What knockd has that this does not

Being honest about the ledger in both directions:

| | `knockd` | `knock-daemon` |
|---|---|---|
| Per-source partitioning | yes | yes |
| Survives a retransmit / retry mid-sequence | no | yes |
| Concurrent clients behind one NAT address | collide | independent |
| `one_time_sequences` (replay protection) | **yes** | **no** — roadmap |
| Per-door `TARGET` | **yes** | **no** |
| `tcpflags` matching | **yes** | SYN only |
| IPv6 command variants (`start_command_6`) | **yes** | **no** |
| Reverse lookup, syslog integration | **yes** | no |
| nftables set elements with kernel-side timeout | no | yes |
| Prometheus metrics, per-source rate limiting | no | yes |
| Multi-threaded matching | no | yes |

`one_time_sequences` is the significant gap: it is replay protection this daemon
does not have, and replay is the technique's most practical weakness. It belongs
on the roadmap below, not in a footnote.

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
   (a dedicated `knockd2` system user + AmbientCapabilities + hardening; a
   static user rather than `DynamicUser=yes` because the config holds the door
   sequences and must not be world-readable).
7. ~~Release pipeline + distributable packages.~~ **Done** —
   `.github/workflows/release.yml` cross-builds `knockd2` for four Linux targets
   (`x86_64`/`aarch64`, glibc + static `musl`) via `cross`, always with
   `--features capture-afpacket` (no libpcap dependency, so the artifacts are
   self-contained). Each build is packaged as a `.tar.gz`; the glibc targets also
   emit `.deb` (`cargo deb`) and `.rpm` (`cargo generate-rpm`) from metadata in
   `Cargo.toml`. Everything is SHA256-summed and published to a GitHub Release on
   a `vX.Y.Z` tag. Dual-licensed **MIT OR Apache-2.0** for broad reuse and
   downstream distro packaging. *(Follow-up: publish to crates.io once the name
   is claimed and the repo is public.)*
8. **`one_time_sequences` — replay protection. Not built, and the largest gap
   against `knockd`.** A knock sequence travels in the clear, so an observer on
   the path can replay it verbatim; knockd answers this with single-use
   sequences consumed from a file. Until this exists, the honest statement is the
   one in `SECURITY.md`: replay is in scope for the *technique* and out of scope
   as a bug report. Anything built here has to survive a restart and a crash
   without either re-enabling a spent sequence or silently locking a user out,
   which is why it is not a weekend's work.
9. **Signed releases.** `SHA256SUMS` published beside the artifacts proves a
   download was not truncated; it says nothing about provenance. minisign or
   cosign, with the public key in this repository and in the release notes.

## Continuous integration

`.github/workflows/ci.yml` runs three jobs:

- **linux** / **macos** — `cargo fmt --check`, `clippy -D warnings`, and the test
  suite across every feature combo with a code path on that OS (Linux also
  compiles the `capture-afpacket` backend + cBPF prefilter, which never build on
  macOS). All pure cores — matcher, sharded routing, rate limiter, frame parser,
  the cBPF program (via its software interpreter), stats render/HTTP — are
  covered here.
- **integration** (`ci/wire-test.sh`, root) — the one slice unit tests can't
  reach: it runs the release daemon over a real `AF_PACKET` socket on `lo`,
  attaches the hand-emitted cBPF prefilter to a live kernel via
  `SO_ATTACH_FILTER`, drives an actual 3-step knock, and asserts the door opened
  two ways — the source IP landed in the nftables allow-set, and `/metrics`
  counted the accepted knock. This wire-tests the safety-critical prefilter
  invariant (the kernel *accepts* the program and does **not** drop real door
  frames) end to end through capture → parse → shard → match → nftables.

  It also asserts the prefilter's drop *efficiency*, using the AF_PACKET
  `PACKET_STATISTICS` counters the daemon now exposes
  (`knockd2_afpacket_kernel_packets_total` / `_drops_total`, sampled every ~250ms
  off the capture socket). `tp_packets` counts only frames that *passed* the
  filter, so a heavy flood of a non-door port leaves it flat — proving the kernel
  sheds those frames before the socket queue, not just that userspace ignores
  them. A successful knock then bumps the same counter, confirming door frames
  are delivered. This catches a silent prefilter regression the userspace-only
  "observed" check would miss.

  Finally it wire-tests the daemon's headline differentiator — **per-source
  isolation under concurrency**. Many clients (distinct `127.0.0.0/8` loopback
  source addresses, all local on Linux) knock at once with their sequences
  interleaved step-by-step, so every sequence is mid-flight simultaneously —
  exactly the load that a matcher keeping one attempt per source gets wrong, since
  every retry and retransmit in the mix would end a sequence rather than start one.
  The test asserts each client's door opened independently (every source landed
  in the allow-set) while one deliberately incomplete client stayed closed,
  proving state never leaks across the per-source boundary. This turns the
  unit-tested isolation guarantee into a live, end-to-end one.

## Privileges & threat model

Live capture needs `CAP_NET_RAW`; the nftables backend needs `CAP_NET_ADMIN`. The
daemon runs with exactly those two capabilities and no more — the shipped systemd
unit (`packaging/systemd/knockd2.service`) uses a dedicated `knockd2` system
user plus
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
