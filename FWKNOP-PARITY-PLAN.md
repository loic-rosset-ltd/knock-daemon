# Plan — full fwknop capability parity for knock-daemon, improved

<!-- Tracked in the repository on purpose: this plan was drafted in a session
     scratchpad, and the write-through rule says nothing of value may exist only
     there. Phases 0-3 are DONE (commit 4df5f70); Phases 4-9 are NOT committed
     work, they are a proposal whose cost is assessed in
     ../marketing/business-model.md §8. Read that before starting Phase 4. -->

> **Status, 2026-09-24:** Phases 0-3 shipped in `4df5f70`. **Phases 4-9 are not
> authorised work** — they are ~2-3 months, and `marketing/business-model.md` §8
> records the decision about whether to spend it. This file is the *how*, not the
> *whether*.


## Context

`knock-daemon` ships a knockd-compatible port-knock daemon. A competitive teardown
(`marketing/competitive-landscape.md`) established that **fwknop wins the security axis**:
its SPA packet is encrypted, authenticated and non-replayable, while a knock sequence is a
cleartext, on-path-observable, replayable secret.

An **SPA core** was then written (`src/spa/`, 51 tests) with better primitives than fwknop —
XChaCha20-Poly1305 instead of hand-assembled AES-CBC+HMAC, Argon2id instead of PBKDF1,
X25519+Ed25519 instead of GnuPG, and replay protection bounded by the timestamp window
instead of an unbounded on-disk cache. **It is inert: nothing calls it.**

You asked to implement everything fwknop has that we do not, improve it, and cover
**platform breadth as well as capabilities**. You also asked, twice, for a recommendation
rather than a choice: *what is the best strategy for fwknop users*, and *what client will
actually get used*. Both are answered in §1 — they turn out to be the same answer.

**Intended outcome:** an fwknop-superset daemon — everything fwknop can do, with modern
primitives, that fwknop's own existing clients (including its Android and iPhone apps) can
talk to unmodified.

---

## 1. The two strategy answers

### 1.1 fwknop compatibility: implement the **strong subset**, loudly

**Recommendation: yes to compatibility — but accept only the configurations that are
actually safe, and reject the rest with a message naming the reason.**

Full wire compat sounds like it means inheriting fwknop's worst parts. It does not, because
fwknop permits a *range* of settings and most deployments use the good end. We accept:

| fwknop setting | We accept | We refuse, with a named reason |
|---|---|---|
| `ENCRYPTION_MODE` | `CBC` | `ECB`, `CFB`, `OFB`, `PCBC`, `legacy` (pre-2.5 IV) |
| HMAC | **required** — `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_512` | **no HMAC at all**, `md5`, `sha1` |
| `DIGEST_TYPE` | sha256 and above | `md5`, `sha1` |
| GPG mode | signed, with `GPG_REMOTE_ID`/`GPG_FINGERPRINT_ID` pinning | `GPG_DISABLE_SIG`, `GPG_IGNORE_SIG_VERIFY_ERROR` |

**This is the same "reject, don't ignore" philosophy already shipped** for `knockd.conf`
parsing (`README.md:282`), and it is strictly safer than fwknop, which still permits ECB,
MD5 and no-HMAC today. The pitch is precise and true: *"your fwknop clients work unchanged;
we refuse the settings that were never safe, and tell you which."*

**The decisive bonus, and why this is also the breadth answer:** compatibility gives us
fwknop's **Android client, iPhone client, existing CLI, and Perl/Python/Erlang bindings for
free**. Porting those ourselves is months; accepting their packets is Phase 3.

### 1.2 The client that will actually get used

**Recommendation, in priority order:**

1. **fwknop's own clients (Phase 3).** The most-used client is the one already installed.
2. **A single static `knock` binary** (Phase 2) — Linux/macOS/Windows, zero dependencies,
   one file to download. Plus an rc-file of named stanzas (`knock ssh-prod`), which is the
   feature that makes fwknop's CLI tolerable and is cheap to copy.
3. **`knock-macos` SPA support (Phase 9)** — the GUI, last, because a fleet of sporadic
   VPSes is driven from a terminal.

Not a `knockd2` subcommand: the client runs on your laptop, and asking people to install a
*daemon* to send a packet is a bad first impression.

---

## 2. What the exploration found — four real blockers

Verified firsthand, not assumed:

| # | Blocker | Evidence |
|---|---|---|
| **B1** | **The capture layer cannot deliver a UDP payload.** `parse_l4` reads only `l4[2],l4[3],l4[13]` — never the body. `PacketEvent` is `Copy` with no byte field and crosses an `mpsc` channel. | `src/capture/parse.rs:127-160`, `src/matcher.rs:57-64` |
| **B2** | **`at_ms` is per-process monotonic, not unix time.** `SpaVerifier::verify` needs `now_secs`. | `src/capture/afpacket.rs` (`start.elapsed()`) |
| **B3** | **The firewall trait has no per-request duration.** `open(&Action, IpAddr)`; `timeout_ms` is baked into `Action` at config load. SPA carries `duration_secs` per request. | `src/firewall/mod.rs:69-77` |
| **B4** | **The SPA port must join the `ports` union** or the kernel cBPF prefilter drops the frame before userspace. | `src/main.rs:129-132`, `src/capture/bpf.rs:88` |

Two more worth knowing: there is **no signal handling or shutdown path** at all, and config
has **no `deny_unknown_fields`**, so a typo'd `[spa]` section would be silently ignored.

---

## 3. Phases

Each phase ends green (`cargo fmt`, `clippy -D warnings`, `cargo test`) and is independently
shippable. **Effort is a working estimate, not a commitment.**

### Phase 0 — Unblock the pipeline `~2-3 d`
Files: `src/capture/parse.rs`, `src/capture/mod.rs`, `src/capture/afpacket.rs`,
`src/capture/pcap_backend.rs`, `src/main.rs`

- Add a **second event type** rather than making `PacketEvent` non-`Copy`: keep the knock
  hot path allocation-free, and route SPA separately.
  ```rust
  pub enum Captured { Knock(PacketEvent), Spa(SpaDatagram) }
  pub struct SpaDatagram { src: IpAddr, dst: IpAddr, payload: Vec<u8>, at_ms: u64, at_unix: u64 }
  ```
- `parse_l4`: when UDP **and** dst port is in the configured SPA port set, copy `l4[8..]`
  (bounded by `spa::packet::MAX_PACKET_LEN`) out of the reused recv buffer.
- Stamp `at_unix` once per recv batch, not per packet (B2).
- Add the SPA port to the `ports` union feeding cBPF (B4).
- **Tests:** extend `capture/parse.rs`'s hand-built-frame helpers — a UDP frame on the SPA
  port yields the exact payload; on another port yields `Knock`; a truncated frame yields
  `None`; an oversize payload is bounded not panicking.

### Phase 1 — Wire native SPA end to end `~3-4 d`
Files: `src/config.rs`, `src/main.rs`, `src/firewall/*`, `src/stats.rs`, `ci/wire-test.sh`

- `[spa]` config: `enabled`, `port`, `psk`/`salt`, `static_key_file`, `authorized_keys`,
  `window_secs`, `default_duration`, `max_duration`, `allow_explicit_addr`.
- Add `deny_unknown_fields` across config structs — a typo must be an error, not silence.
- **B3:** add `fn open_for(&self, action: &Action, src: IpAddr, duration: Option<Duration>)`
  to the `Firewall` trait with a default impl delegating to `open`, so both backends keep
  working and nftables gains a genuine per-request kernel timeout.
- Dedicated SPA worker thread; reuse `ratelimit::RateLimiter` (do **not** write a second one).
- `stats.rs`: SPA counters **by rejection reason** — extend `Snapshot` and `render` together,
  with `render`'s existing tests.
- **Acceptance:** `ci/wire-test.sh` gains an SPA case proving a real packet opens a real nft
  set entry, and that a replay of the same packet does not.

### Phase 2 — The `knock` client + key management `~4-5 d`
New: `src/bin/knock.rs` (second bin target), `src/spa/client.rs`

- `knock --door ssh --to host.example` ; `knock ssh-prod` via rc-file stanzas.
- `knock keygen` (X25519 static + Ed25519 identity), `knockd2 spa-keygen` server-side.
- **Improvement over fwknop's `-R`:** fwknop resolves your external IP by fetching a URL
  over HTTP(S) via `wget` — a third-party dependency and a privacy leak. We default to the
  observed-source model (already the SPA default) and make external resolution explicit,
  opt-in, and HTTPS-only with no `--resolve-http-only` equivalent.
- Cross-platform release builds in `.github/workflows/release.yml`.

### Phase 3 — fwknop compatibility, strong subset `~5-7 d`
New: `src/fwknop/` (feature `compat-fwknop`, **off by default**)

- Decode fwknop SPA: base64 → Rijndael-CBC → **HMAC verified before decrypt**.
- Message types: `FKO_ACCESS_MSG`, `FKO_NAT_ACCESS_MSG`, `FKO_CLIENT_TIMEOUT_*`,
  `FKO_LOCAL_NAT_ACCESS_MSG`, `FKO_COMMAND_MSG`.
- Refuse the weak set from §1.1 with a named reason in the log.
- GPG mode: **shell out to `gpg`** as fwknop does, feature-gated. `sequoia-openpgp` is a
  very large dependency tree for a compatibility path.
- Map the fwknop payload onto our `Authorized`, so the rest of the daemon is unchanged.
- **Acceptance:** build the real fwknop client in CI and knock our daemon with it.

### Phase 4 — Access-control model `~4-5 d`
- Stanzas with **first-match-wins** ordering (load-bearing in fwknop, easy to get wrong).
- `SOURCE`/`DESTINATION` CIDR restrictions; `ACCESS_EXPIRE` / `_EPOCH`; `MAX_FW_TIMEOUT`.
- **Improvement:** fwknop lets a client name arbitrary ports and then filters them with
  `OPEN_PORTS`/`RESTRICT_PORTS`. Our payload names a **door**, and the door defines the
  ports — a client can never request a port at all. Keep that; add the restriction
  directives only as a second belt for compat-mode packets.
- `REQUIRE_USERNAME` → superseded by the Ed25519 identity; accept it in compat mode only.

### Phase 5 — NAT / forwarding `~4-6 d`
- nftables-native DNAT/SNAT/masquerade with **kernel-expiring** rules (fwknop shells out to
  iptables and reaps rules by parsing comment strings — we keep atomicity and the timeout).
- `FORCE_NAT`, `FORCE_SNAT`, `FORCE_MASQUERADE`, `DISABLE_DNAT`, `FORWARD_ALL`, `--nat-local`,
  `--nat-rand-port`.

### Phase 6 — Command execution, made safe `~2-3 d`
- fwknop runs arbitrary payload commands via shell, with setuid/sudo options.
- **Improvement: no shell, ever.** Explicit `argv`, an allow-list of permitted commands, and
  `$IP` vs `$PKT_SRC` kept distinct (payload-claimed vs real sender). Drops shell injection
  as a category rather than escaping it.
- `cmd_cycle` open/close equivalent, including `CLOSE = NONE` (indefinite) as an explicit opt-in.

### Phase 7 — Persistence & operations `~4-5 d`
- **Replay-cache persistence across restart.** Closes both the known SPA gap
  (`SPA-DESIGN.md` §4) and `DESIGN.md` roadmap item 8, which already names the hard
  requirement: survive restart *and* crash without re-enabling a spent token or locking a
  user out. Append-only journal + atomic rotation, fsync on the accept path only.
- Signals: SIGTERM graceful drain, SIGHUP reload. There is **no shutdown path today**.
- `--fw-list`, `--fw-flush`, `--status`, `--kill`, `--test`, `--packet-limit`,
  `--rotate-digest-cache`.

### Phase 8 — Alternative transports `~4-6 d`
- SPA over **TCP**, **ICMP**, **HTTP** (fwknop's `-P`), and client port randomisation.
- ⚠️ **`ENABLE_UDP_SERVER` is deliberately excluded** — binding a port is the one thing we
  do not do, and it is our cleanest win over fwknop. `CONTRIBUTING.md` pins "no new inbound
  network surface"; AF_PACKET capture of TCP/ICMP/HTTP-shaped SPA keeps that intact.
- ⚠️ `ENABLE_X_FORWARDED_FOR` and `ENABLE_PCAP_ANY_DIRECTION`: implement, **off by default**,
  documented as attacker-controllable / transit-authorising respectively.

### Phase 9 — Platform breadth `~3-4 w`
- `pf`, `ipfw`, `ipf` firewall backends behind the existing `Firewall` trait.
- macOS/BSD daemon support (AF_PACKET is Linux-only → BPF device path for BSD).
- `knock-macos` SPA support.
- Bindings: publish a stable packet-format spec + a small C ABI rather than maintaining four
  language bindings.

---

## 4. Files that change most

- `src/capture/parse.rs`, `src/capture/mod.rs`, `src/capture/afpacket.rs` — payload delivery (B1)
- `src/main.rs` — a second worker path, signals, lifecycle
- `src/config.rs` — `[spa]`, stanzas, `deny_unknown_fields`
- `src/firewall/mod.rs` + `nftables.rs` — `open_for`, NAT
- `src/stats.rs` — SPA counters (extend `Snapshot` **and** `render` **and** its tests)
- New: `src/bin/knock.rs`, `src/spa/client.rs`, `src/fwknop/`, `src/access/`

Reuse rather than rewrite: `ratelimit::RateLimiter`, `stats::Stats`, `firewall::NftSet::parse`,
`config::parse_duration_ms`, `capture::bpf::build_filter`, and the `spa::*` core as-is.

---

## 5. Verification

- **Unit:** in-file `#[cfg(test)] mod tests`, local builders, **clock injected everywhere** —
  the invariant `CONTRIBUTING.md` pins. No test sleeps.
- **Integration:** extend `ci/wire-test.sh` (root, real nft sets, real packets on `lo`) with
  an SPA case and a replay case. It already verifies two-sided — nft set *and* `/metrics`.
- **Compat:** CI job that builds the genuine fwknop client and knocks our daemon.
- **CI:** `.github/workflows/ci.yml` gains the new feature combos; clippy is `-D warnings`,
  so each phase must land wired, not dangling.
- **Manual:** `knockd2 --check` on every new config; `knockd2 --demo` extended to show an SPA
  exchange.

---

## 6. Honest notes

- **This is months, not weeks** — roughly 5-7 weeks for Phases 0-8 and another 3-4 for
  Phase 9. Every phase boundary is a clean stopping point, and Phases 0-2 deliver the whole
  security story on their own.
- **No external cryptographic review exists.** Compat mode means implementing older
  primitives; that code needs review more than the native path does.
- **`business-model.md`'s stop criteria still apply.** This is justified as craft and as a
  portfolio artefact — which that document names as legitimate — not by a revenue case.
- Documentation to update as we go, not after: `SPA-DESIGN.md` §7 (the "not done" list),
  `DESIGN.md` roadmap items 8-9, `README.md`, `SECURITY.md` (the replay statement changes),
  and `marketing/competitive-landscape.md` §1.3 once parity actually ships.
