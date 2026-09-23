# knock-daemon

A concurrent port-knocking daemon for Linux — a [`knockd`](https://github.com/jvinet/knock)
replacement that keeps a knock alive when the unexpected happens.

Classic `knockd` already separates knock state per source IP. What it does not do
is tolerate anything unexpected *inside* a source's lane: it tracks at most one
in-flight attempt per source per door, and any packet that isn't the exact next
step destroys it — including a re-hit of the door's own first port. A TCP
retransmit, a client that retries, or a second person behind the same NAT address
silently kills a knock in progress, and nothing starts in its place.

knock-daemon keeps a *set* of candidate attempts per source and adds to it: every
hit on a door's first port opens a new candidate alongside the ones already
running. Retries, retransmits and shared source addresses stop being failure
modes. Set `mode = "reset"` if you want knockd's abort-on-stray behaviour back.

Part of the [Knock](https://github.com/loic-rosset-ltd) family: the
[macOS client](https://github.com/loic-rosset-ltd/knock-macos) is the knocking
front-end; this daemon is the server side it knocks against.

## Status

**v0.1.0 — first public release. No known production deployments, no external
users yet.** The matcher is heavily unit-tested and the packages are rehearsed on
fresh Debian and AlmaLinux systems, but nobody outside this repository has run
this against real traffic. It touches your firewall and it captures packets;
weigh that accordingly, and read [SECURITY.md](SECURITY.md) before you deploy it
in front of anything you care about.

The **concurrent matcher is real and unit-tested**. Live capture has two
backends — a pure-Rust `AF_PACKET` path (`capture-afpacket`, no libpcap) and a
libpcap path (`capture-pcap`) — sharing a unit-tested frame decoder
(IPv4/IPv6/VLAN/QinQ). Both firewall backends ship: `command` (knockd-style) and
`nftables` (allow-set element with a kernel-side timeout). The common subset of classic
knockd `.conf` files is parsed directly (see
[Migrating from knockd](#migrating-from-knockd) for what is and isn't covered),
and a systemd unit runs the daemon with `CAP_NET_RAW`/`CAP_NET_ADMIN` instead of
root. Matching shards across
worker threads by source IP, with an optional per-source rate limiter and a
Prometheus `/metrics` endpoint. See [DESIGN.md](DESIGN.md) for the architecture
and roadmap.

## When this is the wrong tool

If you can run WireGuard or Tailscale, run WireGuard or Tailscale. They authenticate; this
does not. Port knocking earns its place where you can't: an appliance or embedded client that
can only open a TCP connection, a network where you aren't allowed to install a VPN client, or
as one more thing in front of a service that already authenticates its users.

What it reliably buys you is that your SSH port stops appearing in scans and your auth log
stops filling with credential-stuffing attempts. Treat it as that, not as a lock. The sequence
travels in cleartext, so anyone on the path can record and replay it — [SECURITY.md](SECURITY.md)
sets out what is and isn't in scope, without hedging.

## Install

Prebuilt, self-contained binaries ship on every
[GitHub release](https://github.com/loic-rosset-ltd/knock-daemon/releases) for
`x86_64` and `aarch64` — glibc tarballs, fully static `musl` tarballs, plus
`.deb` and `.rpm` packages. Each build uses the pure-Rust AF_PACKET capture
backend, so there's no libpcap dependency to install.

Each release ships a `SHA256SUMS` file. Check your download against it — but note
what that does and does not prove: the checksums are published alongside the
artifacts they cover, so they catch a corrupted or truncated download, not a
compromised release. Signed releases are on the roadmap.

```sh
# Debian / Ubuntu
sudo dpkg -i knock-daemon_<version>_amd64.deb

# Fedora / RHEL
sudo rpm -i knock-daemon-<version>-x86_64-unknown-linux-gnu.rpm

# Any distro (static musl tarball)
tar xzf knock-daemon-<version>-x86_64-unknown-linux-musl.tar.gz
sudo install -Dm755 knock-daemon-*/knockd2 /usr/bin/knockd2
```

**Three names, one thing:** the package is `knock-daemon`, the binary and the
systemd service are both `knockd2`, and the config lives in
`/etc/knock-daemon/knockd.toml`. `systemctl status knock-daemon` will tell you
nothing exists; the unit is `knockd2`.

The packages install a hardened, **disabled** systemd unit and an example config
at `/etc/knock-daemon/knockd.toml`. Edit the config, then
`sudo systemctl enable --now knockd2`. See [Run as a service](#run-as-a-service).

To build from source instead, see [Run against live traffic](#run-against-live-traffic).

## Try it (no root, no libpcap)

```sh
knockd2 --demo
```

Replays one client whose opening packet arrives twice — a retry or a TCP
retransmit — alongside a second client knocking interleaved throughout. Both are
accepted. The duplicate is the interesting part: it is what ends an in-flight
knockd sequence without starting another.

Validate a config before you enable the service:

```sh
knockd2 --check --config /etc/knock-daemon/knockd.toml
```

(From a source checkout, both are `cargo run -- --demo` and
`cargo run -- --check --config knockd.toml`.)

## Run against live traffic

Live capture is behind a feature flag — pick a backend at build time:

```sh
# Pure-Rust AF_PACKET (Linux, no libpcap dependency) — recommended:
cargo build --release --features capture-afpacket

# …or libpcap-backed (Debian/Ubuntu: apt install libpcap-dev):
cargo build --release --features capture-pcap

sudo ./target/release/knockd2 --config /etc/knock-daemon/knockd.toml
```

If both features are built in, the AF_PACKET backend is preferred. Capture needs
`CAP_NET_RAW`; the nftables backend needs `CAP_NET_ADMIN` — see
[Run as a service](#run-as-a-service) to grant just those instead of root.

## Configuration

TOML — see [`knockd.toml`](knockd.toml). A door is an ordered port sequence that,
completed within `seq_timeout`, opens access for the source IP.

### First, the rule that makes a door mean anything

**Without a rule that blocks the port by default, knock-daemon changes nothing.** It only ever
adds a source to an allow-set; if nothing else is denying that port, the port was already open
and the knock bought you exactly nothing. Set the deny rule up first and confirm the port is
unreachable *before* you configure a single door.

A complete `nftables` ruleset that does this, with `knock_clients` as the set a door adds to:

```nft
table inet filter {
  set knock_clients {
    type ipv4_addr
    flags timeout
  }

  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept
    iif lo accept

    tcp dport 22 ip saddr @knock_clients accept
  }
}
```

Load it with `sudo nft -f <file>`, and persist it the way your distribution expects
(`/etc/nftables.conf` on Debian/Ubuntu).

> 🔴 **`policy drop` will lock you out of a remote machine** if you apply it without an accept
> rule matching how you are currently connected. Keep a second SSH session open while you test,
> or work from a console you cannot lose. The `ct state established,related` line keeps your
> *current* session alive; it does nothing for the next one.

The set is IPv4-only as written. For IPv6 clients add a second set
(`type ipv6_addr`) and a matching `tcp dport 22 ip6 saddr @... accept` rule.

### Then the doors

🔴 **Never use a sequence in ascending port order.** An ordinary ascending port
scan walks `7000, 8000, 9000` in exactly that order, and completes a door built
on them inside `seq_timeout` having known nothing — in `reset` mode as much as in
`tolerant`. The examples here are deliberately not monotonic. Pick your ports at
random, not by pattern, and keep them out of order.

With the default **`command`** backend a door runs `open_command` (with `%IP%`
substituted), optionally auto-undone by `close_command` after `cmd_timeout`:

```toml
[[door]]
name = "ssh"
sequence = ["41953/tcp", "8271/udp", "22986/tcp"]
seq_timeout = "10s"
open_command  = "nft add element inet filter knock_clients { %IP% }"
close_command = "nft delete element inet filter knock_clients { %IP% }"
cmd_timeout = "30s"
```

The **`nftables`** backend skips the shell and the userspace timer: it adds the
source to a named allow-set as an element with a **kernel-side timeout**, so the
add is atomic and the kernel expires it on its own. `cmd_timeout` becomes the
element timeout (omit it for a permanent element):

```toml
[firewall]
backend = "nftables"

[[door]]
name = "ssh"
sequence = ["41953/tcp", "8271/udp", "22986/tcp"]
seq_timeout = "10s"
nft_set = "inet filter knock_clients"   # "<family> <table> <set>"; family defaults to inet
cmd_timeout = "30s"                       # kernel-side element timeout
```

The set must already exist with a timeout flag, e.g.
`nft add set inet filter knock_clients '{ type ipv4_addr; flags timeout; }'`.

### Matching mode

By default an out-of-order packet to an **unrelated** port never derails an
in-flight sequence — correctness leans on `seq_timeout`, which is robust to
background noise and concurrent traffic. Set `[matching] mode = "reset"` for
classic knockd parity, where a hit to one of a door's own ports out of order
aborts the attempt:

```toml
[matching]
mode = "tolerant"   # default; or "reset" for knockd-style reset-on-stray
```

On Linux the AF_PACKET backend sets `PACKET_IGNORE_OUTGOING`, so the daemon never
sees this host's own outbound frames. That matters most in `reset` mode: on an
interface that observes its own traffic — `lo` above all — every frame is seen
twice, the second copy looks exactly like a stray hit to a monitored port, and
`reset` aborts on it, so the door never opens. On a kernel older than 4.20 the
option is unavailable and the daemon logs a warning at startup; prefer `tolerant`
there, or capture on a real interface.

**`reset` is not the more secure mode, and `tolerant` does not trade security for
robustness.** It is natural to assume otherwise. But `reset` also starts a fresh
attempt whenever a door's first port is hit, so an attacker who knows which three
ports a door uses opens it in either mode with the same short burst covering
every ordering. What `reset` buys is knockd parity; what `tolerant` buys is that
a retransmit doesn't cost you a knock. Neither changes what an attacker has to
guess — the ports, and their order.

### Scaling, rate limiting, and metrics

Matching is partitioned by source IP across worker threads, so concurrent clients
scale across cores with no cross-shard coordination. An optional per-source token
bucket sheds floods before they reach the matcher, and an HTTP endpoint exposes
Prometheus counters:

```toml
[matching]
shards = 1              # worker threads; 1 = single-threaded (default), 0 = auto-detect CPUs
rate_limit = "50/10s"   # per source IP: burst of 50, refilling 50 per 10s (omit = unlimited)

[stats]
listen = "127.0.0.1:9099"   # GET /metrics → Prometheus text; omit to disable
```

```sh
curl -s http://127.0.0.1:9099/metrics
# knockd2_packets_observed_total ...
# knockd2_packets_rate_limited_total ...
# knockd2_knocks_accepted_total ...
# knockd2_door_accepted_total{door="ssh"} ...
# knockd2_tracked_sources ...
```

## Migrating from knockd

Point `--config` at an existing knockd `.conf` and it's parsed in place (the
`.conf` extension selects the legacy format; anything else is TOML):

```sh
knockd2 --check --config /etc/knockd.conf
```

knockd's `command` / `start_command` / `stop_command` / `cmd_timeout` map onto
the `command` firewall backend, `port:proto` steps become `port/proto`, and the
matcher defaults to `reset` mode to mirror knockd's behaviour. See
[`examples/knockd.conf`](examples/knockd.conf).

**It is the common subset, not a drop-in.** `one_time_sequences`, a per-door
`TARGET`, the IPv6 `start_command_6` / `stop_command_6` variants and any
`tcpflags` other than `syn` are not supported — and a config using them is
**rejected at load rather than ignored**. That is deliberate: silently dropping
`one_time_sequences` would delete replay protection you currently have without
telling you. `--check` tells you before the service does.

## Run as a service

[`packaging/systemd/knockd2.service`](packaging/systemd/knockd2.service) runs the
daemon as a dedicated `knockd2` system user with only `CAP_NET_RAW` (capture) and
`CAP_NET_ADMIN` (firewall) — no root — plus a hardening sandbox. See
[`packaging/README.md`](packaging/README.md) for install and verification steps.

## Contributing & security

Bug reports and patches are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for
the build/test loop and the two rules that matter (the matcher stays pure; no new
inbound network surface).

**Security issues go through private vulnerability reporting, never a public
issue** — see [SECURITY.md](SECURITY.md), which also spells out what port
knocking does and does not protect against.

## Development

```sh
cargo test                              # matcher, frame parser, config + knockd tests
cargo check --features capture-pcap     # type-check the libpcap path
# The AF_PACKET backend is Linux-only; type-check it from any host with:
rustup target add x86_64-unknown-linux-gnu    # once
cargo check --target x86_64-unknown-linux-gnu --features capture-afpacket
```

The matcher (`src/matcher.rs`) takes a logical timestamp per event instead of
reading the clock, so it's fully deterministic and tested without sockets or
sleeps. See [DESIGN.md](DESIGN.md) for the architecture and rationale.

## Releasing

Push a `vX.Y.Z` tag (matching `Cargo.toml`'s `version`) and
[`.github/workflows/release.yml`](.github/workflows/release.yml) cross-builds all
four Linux targets, packages the tarballs / `.deb` / `.rpm`, checksums them, and
publishes a GitHub Release. `packaging/` metadata lives in `Cargo.toml`
(`[package.metadata.deb]` / `[package.metadata.generate-rpm]`).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution you intentionally submit for inclusion in this work,
as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
