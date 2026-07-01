#!/usr/bin/env bash
#
# End-to-end wire-test for the Linux live path, exercised by CI as root.
#
# This is the one slice the unit tests can't reach: a real AF_PACKET socket, the
# hand-emitted cBPF prefilter attached to a live kernel via SO_ATTACH_FILTER, the
# frame parser fed by genuine loopback traffic, the sharded matcher, and the
# nftables backend issuing a real `nft add element`. We drive an actual knock and
# assert the door opened two independent ways: the nftables set gained the source
# IP, and /metrics counted the accepted knock.
#
# What this proves about the cBPF prefilter: the kernel *accepted* the program
# (log line "attached cBPF prefilter", and no "attach failed" warning), and — the
# safety-critical invariant — it does NOT drop real door frames (the knock
# completes end to end). It intentionally does not assert kernel-side drop
# *efficiency* (tp_drops for non-door frames): that would need the daemon to
# expose AF_PACKET PACKET_STATISTICS, which it doesn't yet — noted, not silently
# skipped. See DESIGN.md "Continuous integration".
set -euo pipefail

BIN=./target/release/knockd2
IFACE=lo
STATS_ADDR=127.0.0.1:9099
NFT_FAMILY=inet
NFT_TABLE=knockd_ci
NFT_SET=knock_clients
CFG=/tmp/knockd-ci.toml
LOG=/tmp/knockd-ci.log
DOOR_PORTS=(7000 8000 9000)
NON_DOOR_PORT=55555

fail() { echo "WIRE-TEST FAIL: $*" >&2; exit 1; }

metric() { # metric <name> -> the counter value (0 if absent)
  curl -s "http://$STATS_ADDR/metrics" | awk -v k="$1" '$1 == k {print $2; f=1} END {if (!f) print 0}'
}

knock_port() { # send a single TCP SYN to 127.0.0.1:<port> (closed port → RST, SYN still emitted on lo)
  timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null || true
}

[ -x "$BIN" ] || fail "daemon binary $BIN not found (build with --features capture-afpacket)"

# --- nftables scaffolding the daemon adds elements to -------------------------
nft add table "$NFT_FAMILY" "$NFT_TABLE"
nft add set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET" '{ type ipv4_addr; flags timeout; }'

cleanup() {
  [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true
  echo "----- daemon log -----"
  cat "$LOG" 2>/dev/null || true
  nft delete table "$NFT_FAMILY" "$NFT_TABLE" 2>/dev/null || true
}
trap cleanup EXIT

# --- config: nftables backend, stats endpoint, 3-step door on loopback --------
cat >"$CFG" <<EOF
interface = "$IFACE"

[firewall]
backend = "nftables"

[matching]
mode = "tolerant"
shards = 4

[stats]
listen = "$STATS_ADDR"

[[door]]
name = "ssh"
sequence = ["7000/tcp", "8000/tcp", "9000/tcp"]
seq_timeout = "15s"
nft_set = "$NFT_FAMILY $NFT_TABLE $NFT_SET"
cmd_timeout = "30s"
EOF

# --- start the daemon (debug log so we can confirm the prefilter attach) ------
RUST_LOG=knockd2=debug "$BIN" --config "$CFG" >"$LOG" 2>&1 &
PID=$!

# Wait until the socket is bound AND the cBPF prefilter attach has run. That log
# line is emitted right before the recv loop, so it's our "capture is live" gate.
for _ in $(seq 1 100); do
  kill -0 "$PID" 2>/dev/null || fail "daemon exited early"
  grep -q "attached cBPF prefilter" "$LOG" && break
  sleep 0.1
done
grep -q "attached cBPF prefilter" "$LOG" || fail "kernel did not accept the cBPF prefilter (no attach log line)"
grep -q "attaching cBPF prefilter failed" "$LOG" && fail "SO_ATTACH_FILTER was rejected by the kernel"

# Wait for the stats endpoint to answer.
for _ in $(seq 1 50); do
  curl -sf "http://$STATS_ADDR/metrics" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "http://$STATS_ADDR/metrics" >/dev/null 2>&1 || fail "stats endpoint never came up"

echo "== daemon up, cBPF prefilter attached to the live kernel socket =="

# --- negative check: non-door SYNs never reach the matcher --------------------
observed_before=$(metric knockd2_packets_observed_total)
for _ in $(seq 1 20); do knock_port "$NON_DOOR_PORT"; done
sleep 0.5
observed_after_noise=$(metric knockd2_packets_observed_total)
[ "$observed_after_noise" -eq "$observed_before" ] \
  || fail "non-door frames reached the matcher (observed $observed_before -> $observed_after_noise); door-port filtering is broken"
echo "== non-door SYNs correctly filtered (observed stayed at $observed_before) =="

# --- the knock: SYN each door port in order -----------------------------------
for p in "${DOOR_PORTS[@]}"; do
  knock_port "$p"
  sleep 0.2
done

# --- wait for acceptance, then assert both signals ----------------------------
for _ in $(seq 1 50); do
  [ "$(metric knockd2_knocks_accepted_total)" -ge 1 ] && break
  sleep 0.2
done

echo "----- /metrics -----"
curl -s "http://$STATS_ADDR/metrics"
echo "--------------------"

accepted=$(metric knockd2_knocks_accepted_total)
[ "$accepted" -ge 1 ] || fail "knock was never accepted (afpacket capture or matcher did not see the door frames)"

door_accepted=$(curl -s "http://$STATS_ADDR/metrics" \
  | awk -F' ' '/^knockd2_door_accepted_total\{door="ssh"\}/ {print $2}')
[ "${door_accepted:-0}" -ge 1 ] || fail "per-door counter did not register the ssh knock"

# The nftables backend must have added the loopback source (127.0.0.1) to the set.
nft list set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET"
nft list set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET" | grep -q "127.0.0.1" \
  || fail "source IP was not added to the nftables allow-set"

echo "WIRE-TEST PASS: knock accepted end-to-end (afpacket + cBPF prefilter + matcher + nftables + /metrics)"
