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

Early scaffold. The **concurrent matcher is real and unit-tested**; live capture
(libpcap) and both firewall backends — `command` and `nftables` (allow-set
element with a kernel-side timeout) — are wired up. A pure-Rust capture path and
knockd `.conf` compatibility are on the roadmap — see [DESIGN.md](DESIGN.md).

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

Live capture is behind the `capture-pcap` feature (needs libpcap):

```sh
# Debian/Ubuntu: apt install libpcap-dev
cargo build --release --features capture-pcap
sudo ./target/release/knockd2 --config /etc/knock-daemon/knockd.toml
```

Capture needs `CAP_NET_RAW`; the nftables backend needs `CAP_NET_ADMIN`.

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

## Development

```sh
cargo test                          # pure matcher + config tests, no privileges needed
cargo check --features capture-pcap # type-check the live capture path
```

The matcher (`src/matcher.rs`) takes a logical timestamp per event instead of
reading the clock, so it's fully deterministic and tested without sockets or
sleeps. See [DESIGN.md](DESIGN.md) for the architecture and rationale.
