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
# What this proves about the cBPF prefilter:
#   1. the kernel *accepted* the program (log line "attached cBPF prefilter", no
#      "attach failed" warning);
#   2. the safety-critical invariant — it does NOT drop real door frames (the
#      knock completes end to end, and the kernel's PACKET_STATISTICS shows it
#      delivered the door frames);
#   3. drop *efficiency* — it DOES drop non-door frames in the kernel: a heavy
#      flood of a non-door port leaves the kernel-delivered counter
#      (PACKET_STATISTICS tp_packets, now exposed on /metrics) flat, because the
#      prefilter rejects those frames before they reach the socket queue. This
#      catches a silent prefilter regression that the userspace-only "observed"
#      check cannot: if the filter stopped working, userspace would still drop
#      the frames by port, but tp_packets would jump.
#
# It then wire-tests the daemon's headline differentiator over classic knockd:
#   4. per-source isolation under concurrency — many clients (distinct loopback
#      source IPs) knock at once with their sequences fully interleaved, and each
#      door still opens for exactly the clients that completed it. A global-state
#      matcher (knockd's classic weakness) mishandles this; the per-source shards
#      here don't. An extra client with an incomplete sequence must stay closed,
#      proving state never leaks across the source boundary.
# See DESIGN.md "Continuous integration".
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

# --- negative check + prefilter drop-efficiency -------------------------------
# Flood a non-door port. Two invariants must hold:
#   - userspace never sees the frames (observed unchanged), and
#   - the KERNEL never even delivers them: PACKET_STATISTICS' tp_packets counts
#     only frames that PASSED the cBPF filter, so a working prefilter keeps the
#     exposed kernel counter flat here even under a heavy flood. (If the prefilter
#     regressed, these frames would be delivered and tp_packets would jump, while
#     the observed-only check would still pass — hence this stronger assertion.)
FLOOD=300
observed_before=$(metric knockd2_packets_observed_total)
kpkts_before=$(metric knockd2_afpacket_kernel_packets_total)
for _ in $(seq 1 "$FLOOD"); do knock_port "$NON_DOOR_PORT"; done
sleep 1  # let the daemon's ~250ms PACKET_STATISTICS poll run at least once

observed_after_noise=$(metric knockd2_packets_observed_total)
[ "$observed_after_noise" -eq "$observed_before" ] \
  || fail "non-door frames reached the matcher (observed $observed_before -> $observed_after_noise); door-port filtering is broken"

kpkts_after_noise=$(metric knockd2_afpacket_kernel_packets_total)
kdelta=$((kpkts_after_noise - kpkts_before))
[ "$kdelta" -le 5 ] \
  || fail "kernel delivered $kdelta frames during a ${FLOOD}-connect non-door flood; the cBPF prefilter is not shedding them (expected ~0)"
echo "== non-door flood shed by the kernel: observed stayed at $observed_before, kernel tp_packets +$kdelta over $FLOOD connects =="

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

# The kernel must have DELIVERED the door frames it let through — the positive
# side of the prefilter story, and proof the PACKET_STATISTICS metric is wired
# and not stuck at zero. Retry: the counter only advances on the daemon's ~250ms
# poll, which may lag the accept.
for _ in $(seq 1 20); do
  kpkts_final=$(metric knockd2_afpacket_kernel_packets_total)
  [ "${kpkts_final:-0}" -ge 1 ] && break
  sleep 0.2
done
[ "${kpkts_final:-0}" -ge 1 ] \
  || fail "kernel packet counter never moved even after a successful knock (PACKET_STATISTICS not wired?)"
echo "== kernel delivered the door frames: knockd2_afpacket_kernel_packets_total=$kpkts_final =="

# The nftables backend must have added the loopback source (127.0.0.1) to the set.
nft list set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET"
nft list set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET" | grep -q "127.0.0.1" \
  || fail "source IP was not added to the nftables allow-set"

# --- concurrent per-source isolation (the daemon's differentiator) ------------
# Classic knockd tracks knock progress essentially globally and buckles when
# several clients knock at once with interleaved sequences. knock-daemon keeps
# per-source-IP state, sharded by source, so simultaneous interleaved knocks each
# resolve independently. That property is unit-tested; here we prove it live over
# the wire, driving many clients through one AF_PACKET socket at the same time.
#
# Trick: on Linux the whole 127.0.0.0/8 is local, so each 127.0.0.N is an
# independent client source IP we can bind and knock from — genuinely distinct
# source addresses on the wire, routed across the matcher's shards.
#
# We interleave step by step (every client sends door step 1, THEN every client
# sends step 2, ...), so at each moment all sequences are simultaneously in
# flight — exactly the concurrency a global-state matcher gets wrong. One extra
# "bad" client sends step 1 then step 3, skipping step 2: it must NEVER open, and
# the burst of step-3 hits from the good clients must not leak into its state.
GOOD_SRCS=(127.0.0.11 127.0.0.12 127.0.0.13 127.0.0.14 127.0.0.15 127.0.0.16 127.0.0.17 127.0.0.18)
BAD_SRC=127.0.0.30
N_GOOD=${#GOOD_SRCS[@]}

accepted_before_concurrent=$(metric knockd2_knocks_accepted_total)

DST=127.0.0.1 GOOD="${GOOD_SRCS[*]}" BAD="$BAD_SRC" PORTS="${DOOR_PORTS[*]}" python3 - <<'PY'
import os, socket
dst   = os.environ["DST"]
good  = os.environ["GOOD"].split()
bad   = os.environ["BAD"]
ports = [int(p) for p in os.environ["PORTS"].split()]

def syn(src, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((src, 0))          # any 127.x is a local loopback address on Linux
        s.settimeout(0.3)
        s.connect((dst, port))    # closed port -> RST, but the SYN is on the wire
    except OSError:
        pass                      # ConnectionRefused/timeout expected; SYN already sent
    finally:
        s.close()

# Step-major interleave: all clients advance one step together, so every
# sequence is mid-flight at the same time.
for i, port in enumerate(ports):
    for src in good:
        syn(src, port)
    if i != 1:                    # bad client hits step 1 and step 3, never step 2
        syn(bad, port)
PY

# Wait for all good clients' knocks to be accepted (the ~250ms poll + matcher lag).
want=$((accepted_before_concurrent + N_GOOD))
for _ in $(seq 1 50); do
  [ "$(metric knockd2_knocks_accepted_total)" -ge "$want" ] && break
  sleep 0.2
done
accepted_now=$(metric knockd2_knocks_accepted_total)
[ "$accepted_now" -ge "$want" ] \
  || fail "only $((accepted_now - accepted_before_concurrent))/$N_GOOD interleaved knocks accepted; per-source concurrency is broken"

# Exact-match membership against the allow-set's IPs (avoids 127.0.0.1 matching
# 127.0.0.11 as a substring). Every good client must be present; the bad one must not.
set_ips=$(nft list set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET" \
  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
for src in "${GOOD_SRCS[@]}"; do
  grep -qxF "$src" <<<"$set_ips" \
    || fail "interleaved client $src completed its knock but was not added to the allow-set"
done
if grep -qxF "$BAD_SRC" <<<"$set_ips"; then
  fail "incomplete client $BAD_SRC was opened; per-source isolation leaked across sources"
fi
echo "== concurrent isolation: all $N_GOOD interleaved clients opened independently; incomplete client stayed closed =="

echo "WIRE-TEST PASS: knock accepted end-to-end (afpacket + cBPF prefilter + matcher + nftables + /metrics)"
