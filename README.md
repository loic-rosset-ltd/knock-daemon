# knock-daemon

A concurrent port-knocking daemon for Linux — a [`knockd`](https://www.zeroflux.org/projects/knock)
replacement that handles **many simultaneous knock sequences without cross-talk**.

Classic `knockd` shares one global set of door state machines across all traffic,
so concurrent or interleaved sequences from different clients can corrupt each
other. knock-daemon partitions in-flight matching state **per source IP**, so any
number of clients can knock at once — even the same door, fully interleaved — and
each succeeds independently.

Part of the [Knock](https://github.com/loic-rosset-ltd) family: the
[macOS client](https://github.com/loic-rosset-ltd/knock-macos) is the knocking
front-end; this daemon is the server side it knocks against.

## Status

The **concurrent matcher is real and unit-tested**. Live capture has two
backends — a pure-Rust `AF_PACKET` path (`capture-afpacket`, no libpcap) and a
libpcap path (`capture-pcap`) — sharing a unit-tested frame decoder
(IPv4/IPv6/VLAN/QinQ). Both firewall backends ship: `command` (knockd-style) and
`nftables` (allow-set element with a kernel-side timeout). Classic knockd
`.conf` files are parsed for drop-in migration, and a systemd unit runs the
daemon with `CAP_NET_RAW`/`CAP_NET_ADMIN` instead of root. See
[DESIGN.md](DESIGN.md) for the architecture and roadmap.

## Try it (no root, no libpcap)

```sh
cargo run -- --demo
```

Replays two clients knocking the same door with fully interleaved packets and
shows both accepted independently — the exact case classic knockd mishandles.

Validate a config:

```sh
cargo run -- --check --config knockd.toml
```

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

With the default **`command`** backend a door runs `open_command` (with `%IP%`
substituted), optionally auto-undone by `close_command` after `cmd_timeout`:

```toml
[[door]]
name = "ssh"
sequence = ["7000/tcp", "8000/udp", "9000/tcp"]
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
sequence = ["7000/tcp", "8000/udp", "9000/tcp"]
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

## Run as a service

[`packaging/systemd/knockd2.service`](packaging/systemd/knockd2.service) runs the
daemon under a `DynamicUser` with only `CAP_NET_RAW` (capture) and
`CAP_NET_ADMIN` (firewall) — no root — plus a hardening sandbox. See
[`packaging/README.md`](packaging/README.md) for install and verification steps.

## Development

```sh
cargo test                              # matcher, frame parser, config + knockd tests
cargo check --features capture-pcap     # type-check the libpcap path
# The AF_PACKET backend is Linux-only; type-check it from any host with:
cargo check --target x86_64-unknown-linux-gnu --features capture-afpacket
```

The matcher (`src/matcher.rs`) takes a logical timestamp per event instead of
reading the clock, so it's fully deterministic and tested without sockets or
sleeps. See [DESIGN.md](DESIGN.md) for the architecture and rationale.
