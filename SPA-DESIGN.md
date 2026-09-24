# Single Packet Authorization — design

**Status: core implemented and tested (51 tests). NOT yet wired into the running
daemon.** See §7 for exactly what is and is not done — the distinction matters and
is not blurred anywhere below.

SPA closes the one gap `SECURITY.md` is candid about: **a port-knock sequence is a
cleartext secret.** Anyone on the path sees the destination ports and can replay
them. An SPA packet is encrypted, authenticated and non-replayable.

**Sequences are not deprecated.** SPA is an additional door type. The
knockd-compatible matcher is what lets existing deployments migrate and it is
unchanged.

---

## 1. Why not just reimplement fwknop

`fwknop` got the *concept* right in 2011 and it is still the reference. The
concept is not what is being improved — the primitives and the operational shape
are. Each change below removes a class of mistake; none is change for its own sake.

| | `fwknop` | here | why it matters |
|---|---|---|---|
| Cipher | AES-256-CBC + HMAC-SHA256, encrypt-then-MAC **assembled by hand** | **XChaCha20-Poly1305** (one AEAD) | No MAC to assemble ⇒ no MAC-assembly bug, no padding oracle, no verify-before-decrypt ordering to get wrong. fwknop had to *add* "HMAC before decryption" deliberately; with an AEAD it is not a choice, it is the API. |
| Passphrase KDF | **PBKDF1** | **Argon2id** (64 MiB, 3 passes) | PBKDF1 is obsolete and cheap to attack offline. Derived **once at startup** from a config salt — never per packet, so it is not a DoS vector. |
| Asymmetric | **GnuPG** (keyring, agent, huge dependency) | **X25519 + Ed25519** | No GnuPG anywhere. Same shape as SSH `authorized_keys`, which operators already understand. |
| Nonce | 64-bit space needing care | **192-bit XChaCha nonce** | Random nonces are safe with no counter state — which a stateless single packet needs. |
| Replay store | digest cache **on disk, unbounded**, pruning is the operator's problem | **in-memory, bounded by the timestamp window** | See §4. Memory tracks the window, not uptime. No I/O on the packet path. |
| Capture | libpcap, **or `bind()`s a real UDP socket** in its no-libpcap mode (`server/udp_server.c:106`) | **`AF_PACKET`, binds an interface not a port** | fwknop's no-libpcap mode trades away the stealth the tool exists to provide. **We have no bound port in any mode.** |
| Privilege | shipped unit runs as **root**, no sandbox | dedicated user, `CAP_NET_RAW`+`CAP_NET_ADMIN`, ~20 hardening directives | Unchanged from the existing daemon. |
| Memory safety | ~33 000 lines of C parsing hostile packets | Rust | The highest-risk shape in systems programming, removed. |

> ⚠️ **Where fwknop is still ahead, stated plainly:** fifteen years of production
> exposure, five native firewall backends, NAT access, command execution, *BSD and
> macOS servers, mobile clients, and language bindings. **A new implementation of a
> well-understood idea is not automatically better than a battle-tested one, and
> this design has been run by nobody.** See `../marketing/competitive-landscape.md`.

---

## 2. The topology this is actually designed for

The motivating case, from the operator: **several sporadic VPSes, physical servers,
VMs and containers, in different locations, all at once.** That shape is the reason
public-key mode exists and is the recommended mode.

**Why a mesh VPN gets hectic here, honestly:** WireGuard is peer-to-peer with static
key distribution. Every node needs every peer's public key and an `AllowedIPs`
entry, you must allocate a unique private address per node, and for hosts that live
for three days you are constantly allocating and reclaiming. It is genuinely real
toil, and it is precisely the problem Tailscale exists to solve — at the price of a
third-party control plane holding your device authorisation and ACLs.

**Knocking scales differently because there is no mesh.** Each server independently
decides to open a port. No shared fabric, no address allocation, no peer registry,
nothing to clean up when a node disappears. Adding a host is installing a daemon and
a config; removing one is deleting it. **There is no N² problem because there are no
pairs.**

Public-key mode sharpens that into the `authorized_keys` model:

> **One client identity. N servers, each holding that client's public key.**
> Add a server → drop the public key in. Revoke → remove it. **No per-pair state,
> no shared secret to rotate everywhere, and a stolen server config authorises
> nothing** — it contains public keys only.

That last clause is the important one, and it is what PSK mode cannot give you: with
a shared passphrase, compromising any one host compromises the knock for all of them.
**For a fleet, use public-key mode. PSK mode is for a single host or a quick start.**

⚠️ **This does not make knocking better than a VPN**, and it is not an argument that
it is. It is a statement about which shape fits: a VPN gives you a network, SPA gives
you a conditional firewall opening on hosts that keep their own addresses.
**Knocking to open the WireGuard port is a better deployment than either alone.**

---

## 3. Wire format

```text
header (6 bytes — authenticated as AAD, never encrypted)
  magic    4  b"KSPA"
  version  1  = 1
  mode     1  1 = PSK, 2 = public key

body, mode 1                     body, mode 2
  nonce   24                       eph_pub 32   X25519 ephemeral public key
  sealed  ..  ct || tag(16)        nonce   24
                                   sealed  ..  ct || tag(16)

inner payload (encrypted)
  packet_id   16  random — the replay token
  timestamp    8  u64 BE, unix seconds
  duration     4  u32 BE, seconds requested (0 = server default)
  addr_kind    1  0 = use observed source, 4 = IPv4, 6 = IPv6
  addr      0/4/16
  door_len     1
  door   door_len  UTF-8
  -- mode 2 only --
  client_pub  32  Ed25519 identity
  signature   64  Ed25519 over every preceding payload byte
```

**The header is authenticated but not encrypted.** A tampered `mode` or `version`
byte changes the AAD and the tag fails, so **downgrade attempts are rejected by the
AEAD rather than by hand-written checks** (`flipping_the_mode_byte_cannot_downgrade_the_packet`).

**The ephemeral public key is inside the AAD** so it cannot be substituted
(`ephemeral_key_is_covered_by_the_aad`), and **the signature covers the client's own
public key** so a valid signature cannot be re-attached to a different identity
(`signed_region_covers_the_client_public_key`).

---

## 4. Replay protection, and why there is no cache file

fwknop remembers every digest it has ever accepted, on disk, forever.

**The timestamp window already does that work.** A packet is only acceptable inside
a bounded skew window, so nothing older can be replayed successfully, so nothing
older needs remembering. Therefore:

- **memory is bounded by `accept rate × window`, not by uptime**
  (`memory_is_bounded_by_the_window_not_by_uptime`: 10 000 accepted packets, ≤12 retained)
- **no I/O on the packet path**
- a **hard entry cap** on top, so a same-instant flood cannot grow it
  (`hard_cap_bounds_memory_under_a_same_instant_flood`)

⚠️ **The honest trade: state is lost on restart.** Within one window after a restart
a packet could in principle be replayed. fwknop's on-disk cache does not have this
gap. Mitigations considered and **not** implemented: persisting the window across
restarts, or refusing packets for one window after start. **Recorded as a known
limitation, not solved.**

Signed arithmetic throughout — a sender whose clock is ahead produces a negative
age, and computing that in `u64` would wrap and silently turn a future packet into
an ancient one (`rejects_a_future_packet_without_integer_wraparound`).

---

## 5. Verification order

Cheapest and least-trusting first, so a flood costs the attacker more than us, and
so **no attacker-controlled byte is interpreted before it is authenticated**:

1. framing — magic, version, mode, lengths
2. **AEAD open** — tag verified before any plaintext is released
3. payload parse, fully bounds-checked (`every_truncation_is_an_error_not_a_panic`)
4. timestamp window
5. replay guard
6. public-key mode: Ed25519 signature, **then** the authorised-key set

**The daemon answers nothing, ever.** Failure reasons go to logs and metrics, never
to the sender — a prober must not learn whether the key was wrong or the packet
malformed. `SpaError::Open` deliberately covers both.

---

## 6. Defaults, and why

| Default | Value | Why |
|---|---|---|
| Explicit address in payload | **ignored** | The server authorises the source it *observed*, so a stolen packet cannot open a door for the thief. Opt-in via `allow_explicit_addr` because a client behind unpredictable NAT sometimes needs it. |
| Empty authorised-key set | **authorises nothing** | Fail closed, never open (`an_empty_authorized_set_fails_closed`). |
| Unconfigured verifier | **accepts nothing** | `an_unconfigured_verifier_accepts_nothing`. |
| Duration | default 30 s, capped 3600 s | A payload cannot request an unbounded opening. |
| Argon2id | 64 MiB / 3 passes / 1 lane | Startup only. Documented cost, not a per-packet one. |

---

## 7. What is done, and what is not

**Done — 51 tests, all passing (120 total in the crate):**
- `spa/packet.rs` — wire format, AAD binding, runt/oversize/truncation rejection
- `spa/payload.rs` — inner payload, bounds-checked reader, signature region
- `spa/crypto.rs` — Argon2id, XChaCha20-Poly1305, X25519 (low-order point rejected),
  Ed25519; every single-bit flip in the ciphertext is tested as rejected
- `spa/replay.rs` — bounded, clock-injected replay guard
- `spa/mod.rs` — `SpaVerifier`, the full accept path, end-to-end tests in both modes

**Not done — do not describe SPA as shipped:**
- ❌ **Not wired into the running daemon.** Nothing calls `SpaVerifier` yet; the
  capture path does not route UDP payloads to it. This is why the crate emits
  dead-code warnings.
- ❌ **No config plumbing** — no `[spa]` section, no key loading, no `authorized_keys` file.
- ❌ **No client.** Nothing generates packets except the tests.
- ❌ **No key-generation tooling** (`knockd2 spa-keygen`).
- ❌ **No `knock-macos` support.**
- ❌ **No interoperability with fwknop**, by design — different format, different primitives.
- ❌ **No external cryptographic review.** *The primitives are standard and the
  composition is conservative, but it has been reviewed by nobody. Do not present it
  as audited.*

---

## 8. Remaining fwknop capabilities, assessed

Not silently dropped. In the order they are worth doing:

| Capability | Verdict |
|---|---|
| **Wire SPA into the daemon + config + client** | **The only thing that matters next.** Everything above is inert until this exists. |
| **NAT access** (open a forward to an internal host) | Worth doing, after wiring. Fits the stated topology well. |
| **Command execution on knock** | Already present via the `command` firewall backend. No new work. |
| **More firewall backends** (pf, ipfw, ipf) | Only with a real *BSD user asking. nftables + command already cover Linux. |
| **`--enable-udp-server` equivalent** | **Deliberately never.** Binding a port is the thing we do not do. |
| **Mobile clients, language bindings** | No. No evidence of demand at this category size. |

⚠️ **`business-model.md`'s stop criteria still apply.** This work is justified as
craft and as a portfolio artefact — which that document explicitly names as a
legitimate reason — **not** by a revenue case, which remains absent. **Building more
of it is a time-budget decision, and the measured payback on effort here is still
decades.**
