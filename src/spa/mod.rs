//! Single Packet Authorization.
//!
//! One encrypted, authenticated, non-replayable UDP datagram replaces a knock
//! sequence. This closes the gap `SECURITY.md` is candid about: a port-knock
//! sequence is a cleartext secret, visible to anyone on the path and trivially
//! replayable. An SPA packet is neither.
//!
//! **Sequences are not going away.** SPA is an additional door type, not a
//! replacement — the knockd-compatible sequence matcher is what lets existing
//! deployments migrate, and it still works exactly as before.
//!
//! # What this keeps from the daemon's existing design
//!
//! - **No bound port, in any mode.** SPA packets arrive through the same
//!   `AF_PACKET` capture path as knock packets, so the host still has nothing
//!   listening. fwknop either needs libpcap or `bind()`s a real UDP socket in
//!   its no-libpcap mode (`server/udp_server.c`), which gives away the
//!   stealth the tool exists to provide. We give up nothing.
//! - **Clock injection.** `SpaVerifier::verify` takes `now_secs`; it never
//!   reads the clock. Every expiry, skew and replay path is deterministically
//!   testable, the same invariant `matcher` holds and `CONTRIBUTING.md` pins.
//! - **No new inbound surface.** Still a packet decoder and nothing else.
//!
//! # Verification order
//!
//! Cheapest and least trusting first, so a flood costs the attacker more than
//! it costs us, and so no attacker-controlled byte is *interpreted* before it
//! has been authenticated:
//!
//! 1. framing — magic, version, mode, lengths (`packet::parse`)
//! 2. **AEAD open** — the tag is verified before any plaintext is released
//! 3. payload parse, fully bounds-checked
//! 4. timestamp window
//! 5. replay guard
//! 6. public-key mode: Ed25519 signature, then the authorised-key set
//!
//! Step 2 before step 3 is the property fwknop had to add deliberately as
//! "HMAC before decryption". With an AEAD it is not a choice, it is the API.

pub mod crypto;
pub mod packet;
pub mod payload;
pub mod replay;

use std::collections::HashSet;
use std::net::IpAddr;

pub use packet::Mode;
pub use payload::SpaPayload;
pub use replay::{PacketId, ReplayGuard, ReplayVerdict};

/// Every way an SPA packet can be refused.
///
/// These are deliberately *not* surfaced to the sender — the daemon answers
/// nothing, ever. They exist for logs and metrics.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SpaError {
    TooShort(usize),
    TooLong(usize),
    BadMagic,
    BadVersion(u8),
    UnknownMode(u8),
    Truncated,
    TrailingBytes(usize),
    BadAddrKind(u8),
    BadDoorName,
    MissingSignature,
    SaltTooShort(usize),
    KeyDerivation,
    Seal,
    /// Wrong key or tampered packet. Deliberately indistinguishable.
    Open,
    WeakKeyExchange,
    BadClientKey,
    BadSignature,
    /// Signature valid, but the identity is not authorised for this server.
    UnauthorizedClient,
    /// Replay guard refused it.
    Replay(ReplayVerdict),
    /// Public-key mode packet arrived but no static secret is configured.
    NoStaticKey,
    /// PSK mode packet arrived but no pre-shared key is configured.
    NoPsk,
}

impl std::fmt::Display for SpaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpaError::TooShort(n) => write!(f, "packet too short ({n} bytes)"),
            SpaError::TooLong(n) => write!(f, "packet too long ({n} bytes)"),
            SpaError::BadMagic => write!(f, "not an SPA packet"),
            SpaError::BadVersion(v) => write!(f, "unsupported SPA version {v}"),
            SpaError::UnknownMode(m) => write!(f, "unknown SPA mode {m}"),
            SpaError::Truncated => write!(f, "payload truncated"),
            SpaError::TrailingBytes(n) => write!(f, "{n} trailing bytes after payload"),
            SpaError::BadAddrKind(k) => write!(f, "unknown address kind {k}"),
            SpaError::BadDoorName => write!(f, "invalid door name"),
            SpaError::MissingSignature => write!(f, "signature required but absent"),
            SpaError::SaltTooShort(n) => write!(f, "salt too short ({n} bytes, need 8+)"),
            SpaError::KeyDerivation => write!(f, "key derivation failed"),
            SpaError::Seal => write!(f, "encryption failed"),
            SpaError::Open => write!(f, "authentication failed"),
            SpaError::WeakKeyExchange => write!(f, "non-contributory key exchange rejected"),
            SpaError::BadClientKey => write!(f, "malformed client public key"),
            SpaError::BadSignature => write!(f, "signature verification failed"),
            SpaError::UnauthorizedClient => write!(f, "client key not authorised"),
            SpaError::Replay(v) => write!(f, "replay check failed: {v:?}"),
            SpaError::NoStaticKey => write!(f, "public-key mode packet but no static key set"),
            SpaError::NoPsk => write!(f, "PSK mode packet but no pre-shared key set"),
        }
    }
}

impl std::error::Error for SpaError {}

/// An authorised request. Producing one of these means every check passed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Authorized {
    pub door: String,
    /// Address to open for — already resolved against the observed source.
    pub addr: IpAddr,
    pub duration_secs: u32,
    /// Ed25519 identity that authorised it, in public-key mode.
    pub client_pub: Option<[u8; 32]>,
}

/// Server-side SPA configuration and state.
pub struct SpaVerifier {
    psk: Option<crypto::SymKey>,
    static_secret: Option<[u8; 32]>,
    static_public: Option<[u8; 32]>,
    /// The `authorized_keys` set. Empty in public-key mode means nothing is
    /// authorised — fail closed, never open.
    authorized: HashSet<[u8; 32]>,
    replay: ReplayGuard,
    default_duration_secs: u32,
    max_duration_secs: u32,
    /// Whether a payload may name an address other than the observed source.
    allow_explicit_addr: bool,
}

impl SpaVerifier {
    pub fn new(window_secs: u64, max_replay_entries: usize) -> Self {
        Self {
            psk: None,
            static_secret: None,
            static_public: None,
            authorized: HashSet::new(),
            replay: ReplayGuard::new(window_secs, max_replay_entries),
            default_duration_secs: 30,
            max_duration_secs: 3600,
            allow_explicit_addr: false,
        }
    }

    pub fn with_psk(mut self, key: crypto::SymKey) -> Self {
        self.psk = Some(key);
        self
    }

    pub fn with_static_secret(mut self, secret: [u8; 32]) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};
        let sk = StaticSecret::from(secret);
        self.static_public = Some(*PublicKey::from(&sk).as_bytes());
        self.static_secret = Some(secret);
        self
    }

    pub fn authorize(mut self, client_pub: [u8; 32]) -> Self {
        self.authorized.insert(client_pub);
        self
    }

    pub fn with_durations(mut self, default_secs: u32, max_secs: u32) -> Self {
        self.default_duration_secs = default_secs;
        self.max_duration_secs = max_secs;
        self
    }

    /// Allow a payload to request an address other than the one observed.
    /// Off by default: it widens what a stolen packet can do.
    pub fn allow_explicit_addr(mut self, allow: bool) -> Self {
        self.allow_explicit_addr = allow;
        self
    }

    pub fn static_public(&self) -> Option<[u8; 32]> {
        self.static_public
    }

    pub fn tracked_replays(&self) -> usize {
        self.replay.tracked()
    }

    /// The full accept path. `observed_src` is the source address the capture
    /// layer actually saw; `now_secs` is the server clock, passed in rather
    /// than read.
    pub fn verify(
        &mut self,
        buf: &[u8],
        observed_src: IpAddr,
        now_secs: u64,
    ) -> Result<Authorized, SpaError> {
        // 1. framing
        let pkt = packet::parse(buf)?;

        // 2. authenticate, then decrypt — never the other way round
        let key = match pkt.mode {
            Mode::Psk => self.psk.clone().ok_or(SpaError::NoPsk)?,
            Mode::PublicKey => {
                let secret = self.static_secret.ok_or(SpaError::NoStaticKey)?;
                let eph = pkt.eph_pub.ok_or(SpaError::Truncated)?;
                let shared = crypto::x25519_shared(&secret, &eph)?;
                let static_pub = self.static_public.ok_or(SpaError::NoStaticKey)?;
                crypto::derive_from_x25519(&shared, &eph, &static_pub)
            }
        };
        let plaintext = crypto::open(&key, &pkt.nonce, pkt.aad, pkt.sealed)?;

        // 3. parse the now-authenticated payload
        let signed = matches!(pkt.mode, Mode::PublicKey);
        let p = SpaPayload::decode(&plaintext, signed)?;

        // 4 + 5. timestamp window and replay, in one guarded step
        match self.replay.check(p.packet_id, p.timestamp, now_secs) {
            ReplayVerdict::Fresh => {}
            other => return Err(SpaError::Replay(other)),
        }

        // 6. identity
        let client_pub = if signed {
            let pk = p.client_pub.ok_or(SpaError::MissingSignature)?;
            let sig = p.signature.ok_or(SpaError::MissingSignature)?;
            crypto::verify_signature(&pk, &p.signed_region()?, &sig)?;
            if !self.authorized.contains(&pk) {
                return Err(SpaError::UnauthorizedClient);
            }
            Some(pk)
        } else {
            None
        };

        let addr = match p.addr {
            None => observed_src,
            Some(a) if self.allow_explicit_addr => a,
            Some(_) => observed_src,
        };

        let duration = if p.duration_secs == 0 {
            self.default_duration_secs
        } else {
            p.duration_secs.min(self.max_duration_secs)
        };

        Ok(Authorized {
            door: p.door,
            addr,
            duration_secs: duration,
            client_pub,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use x25519_dalek::{PublicKey, StaticSecret};

    const WINDOW: u64 = 30;
    const NOW: u64 = 1_700_000_000;

    fn src() -> IpAddr {
        "203.0.113.10".parse().unwrap()
    }

    /// Argon2id at 64 MiB is intentionally expensive, and the real daemon runs
    /// it exactly once at config load. Tests do the same, or a loop below would
    /// take minutes and would be testing the KDF rather than the verifier.
    fn psk_key() -> crypto::SymKey {
        static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        let bytes = KEY.get_or_init(|| {
            *crypto::derive_psk(b"a test passphrase", b"unit-test-salt").unwrap()
        });
        zeroize::Zeroizing::new(*bytes)
    }

    fn wrong_psk_key() -> crypto::SymKey {
        static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        let bytes = KEY.get_or_init(|| {
            *crypto::derive_psk(b"not the passphrase", b"unit-test-salt").unwrap()
        });
        zeroize::Zeroizing::new(*bytes)
    }

    fn payload(id: u8, stamp: u64) -> SpaPayload {
        SpaPayload {
            packet_id: [id; 16],
            timestamp: stamp,
            duration_secs: 0,
            addr: None,
            door: "ssh".into(),
            client_pub: None,
            signature: None,
        }
    }

    fn build_psk(key: &crypto::SymKey, p: &SpaPayload, nonce: u8) -> Vec<u8> {
        let aad = packet::aad_for(Mode::Psk, None);
        let n = [nonce; packet::NONCE_LEN];
        let sealed = crypto::seal(key, &n, &aad, &p.encode().unwrap()).unwrap();
        packet::serialise(Mode::Psk, None, &n, &sealed)
    }

    fn psk_verifier() -> SpaVerifier {
        SpaVerifier::new(WINDOW, 4096).with_psk(psk_key())
    }

    #[test]
    fn accepts_a_valid_psk_packet_and_opens_for_the_observed_source() {
        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &payload(1, NOW), 1);
        let a = v.verify(&buf, src(), NOW).unwrap();
        assert_eq!(a.door, "ssh");
        assert_eq!(a.addr, src());
        assert_eq!(a.duration_secs, 30);
        assert_eq!(a.client_pub, None);
    }

    /// The headline property fwknop has and knock sequences cannot: capturing
    /// the packet and sending it again achieves nothing.
    #[test]
    fn a_captured_packet_replayed_verbatim_is_refused() {
        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &payload(1, NOW), 1);
        assert!(v.verify(&buf, src(), NOW).is_ok());
        assert_eq!(
            v.verify(&buf, src(), NOW),
            Err(SpaError::Replay(ReplayVerdict::Replayed))
        );
        // Still refused later, and from a different source address.
        let other: IpAddr = "198.51.100.5".parse().unwrap();
        assert!(v.verify(&buf, other, NOW + 5).is_err());
    }

    #[test]
    fn a_packet_held_and_replayed_after_the_window_is_refused_on_age() {
        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &payload(1, NOW), 1);
        assert!(matches!(
            v.verify(&buf, src(), NOW + WINDOW + 1),
            Err(SpaError::Replay(ReplayVerdict::TooOld { .. }))
        ));
    }

    #[test]
    fn a_packet_from_the_future_is_refused() {
        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &payload(1, NOW + 600), 1);
        assert!(matches!(
            v.verify(&buf, src(), NOW),
            Err(SpaError::Replay(ReplayVerdict::TooNew { .. }))
        ));
    }

    #[test]
    fn a_packet_sealed_with_the_wrong_passphrase_is_refused() {
        let wrong = wrong_psk_key();
        let mut v = psk_verifier();
        let buf = build_psk(&wrong, &payload(1, NOW), 1);
        assert_eq!(v.verify(&buf, src(), NOW), Err(SpaError::Open));
    }

    /// Flipping the mode byte must not downgrade a public-key packet into a PSK
    /// one, because the header is inside the AAD.
    #[test]
    fn flipping_the_mode_byte_cannot_downgrade_the_packet() {
        let mut v = psk_verifier();
        let mut buf = build_psk(&psk_key(), &payload(1, NOW), 1);
        buf[5] = Mode::PublicKey.to_byte();
        // Rejected -- it can never be accepted as a valid PSK packet.
        assert!(v.verify(&buf, src(), NOW).is_err());
    }

    #[test]
    fn noise_and_unrelated_traffic_are_cheaply_rejected() {
        let mut v = psk_verifier();
        // Length is checked before magic -- the cheaper test first -- so short
        // noise is refused on size and never reaches a comparison.
        assert_eq!(v.verify(b"", src(), NOW), Err(SpaError::TooShort(0)));
        assert_eq!(
            v.verify(b"GET / HTTP/1.1\r\n\r\n", src(), NOW),
            Err(SpaError::TooShort(18))
        );
        // Long enough to reach the magic check, and still not ours.
        assert_eq!(v.verify(&[0u8; 64], src(), NOW), Err(SpaError::BadMagic));
        let http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        assert!(http.len() > packet::MIN_PACKET_LEN);
        assert_eq!(v.verify(http, src(), NOW), Err(SpaError::BadMagic));
        // A DNS-shaped payload, i.e. plausible real background traffic.
        assert_eq!(v.verify(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01][..].repeat(9).as_slice(), src(), NOW), Err(SpaError::BadMagic));
    }

    // ---- public-key mode -------------------------------------------------

    fn build_pubkey(
        server_pub: &[u8; 32],
        signing: &SigningKey,
        p: &SpaPayload,
        eph_seed: u8,
    ) -> Vec<u8> {
        let eph_sk = StaticSecret::from([eph_seed; 32]);
        let eph_pk = *PublicKey::from(&eph_sk).as_bytes();
        let shared = eph_sk.diffie_hellman(&PublicKey::from(*server_pub));
        let key = crypto::derive_from_x25519(shared.as_bytes(), &eph_pk, server_pub);

        let mut p = p.clone();
        p.client_pub = Some(*signing.verifying_key().as_bytes());
        let sig = signing.sign(&p.signed_region().unwrap());
        p.signature = Some(sig.to_bytes());

        let aad = packet::aad_for(Mode::PublicKey, Some(&eph_pk));
        let n = [eph_seed; packet::NONCE_LEN];
        let sealed = crypto::seal(&key, &n, &aad, &p.encode().unwrap()).unwrap();
        packet::serialise(Mode::PublicKey, Some(&eph_pk), &n, &sealed)
    }

    #[test]
    fn accepts_an_authorised_public_key_client() {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let client_pub = *signing.verifying_key().as_bytes();
        let mut v = SpaVerifier::new(WINDOW, 4096)
            .with_static_secret([5u8; 32])
            .authorize(client_pub);
        let server_pub = v.static_public().unwrap();

        let buf = build_pubkey(&server_pub, &signing, &payload(2, NOW), 9);
        let a = v.verify(&buf, src(), NOW).unwrap();
        assert_eq!(a.door, "ssh");
        assert_eq!(a.client_pub, Some(client_pub));
    }

    /// A correctly signed packet from a key that is not in `authorized_keys`
    /// must be refused. This is the fleet story: add a server, drop in the
    /// public key; revoke by removing it.
    #[test]
    fn refuses_a_valid_signature_from_an_unauthorised_key() {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let mut v = SpaVerifier::new(WINDOW, 4096).with_static_secret([5u8; 32]);
        let server_pub = v.static_public().unwrap();
        let buf = build_pubkey(&server_pub, &signing, &payload(2, NOW), 9);
        assert_eq!(
            v.verify(&buf, src(), NOW),
            Err(SpaError::UnauthorizedClient)
        );
    }

    /// An empty authorised set must authorise nothing at all.
    #[test]
    fn an_empty_authorized_set_fails_closed() {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let mut v = SpaVerifier::new(WINDOW, 4096).with_static_secret([5u8; 32]);
        let server_pub = v.static_public().unwrap();
        for seed in 1..5u8 {
            let buf = build_pubkey(&server_pub, &signing, &payload(seed, NOW), seed);
            assert!(v.verify(&buf, src(), NOW).is_err());
        }
    }

    /// A packet encrypted to a *different* server's static key must not open,
    /// which is what keeps one compromised host from authorising the fleet.
    #[test]
    fn a_packet_for_another_server_does_not_open_here() {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let client_pub = *signing.verifying_key().as_bytes();
        let mut v = SpaVerifier::new(WINDOW, 4096)
            .with_static_secret([5u8; 32])
            .authorize(client_pub);

        let other_sk = StaticSecret::from([6u8; 32]);
        let other_pub = *PublicKey::from(&other_sk).as_bytes();
        let buf = build_pubkey(&other_pub, &signing, &payload(2, NOW), 9);
        assert_eq!(v.verify(&buf, src(), NOW), Err(SpaError::Open));
    }

    #[test]
    fn a_public_key_packet_is_not_replayable_either() {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let client_pub = *signing.verifying_key().as_bytes();
        let mut v = SpaVerifier::new(WINDOW, 4096)
            .with_static_secret([5u8; 32])
            .authorize(client_pub);
        let server_pub = v.static_public().unwrap();
        let buf = build_pubkey(&server_pub, &signing, &payload(2, NOW), 9);
        assert!(v.verify(&buf, src(), NOW).is_ok());
        assert_eq!(
            v.verify(&buf, src(), NOW),
            Err(SpaError::Replay(ReplayVerdict::Replayed))
        );
    }

    // ---- policy ----------------------------------------------------------

    /// By default an explicit address in the payload is ignored in favour of
    /// the observed source, so a stolen packet cannot open a door for the
    /// thief's address.
    #[test]
    fn an_explicit_address_is_ignored_unless_enabled() {
        let claimed: IpAddr = "198.51.100.99".parse().unwrap();
        let p = SpaPayload { addr: Some(claimed), ..payload(1, NOW) };

        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &p, 1);
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().addr, src());

        let mut v = psk_verifier().allow_explicit_addr(true);
        let buf = build_psk(&psk_key(), &p, 2);
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().addr, claimed);
    }

    #[test]
    fn duration_defaults_and_is_capped() {
        let mut v = psk_verifier().with_durations(45, 600);

        let buf = build_psk(&psk_key(), &payload(1, NOW), 1);
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().duration_secs, 45);

        let p = SpaPayload { duration_secs: 99_999, ..payload(2, NOW) };
        let buf = build_psk(&psk_key(), &p, 2);
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().duration_secs, 600);

        let p = SpaPayload { duration_secs: 120, ..payload(3, NOW) };
        let buf = build_psk(&psk_key(), &p, 3);
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().duration_secs, 120);
    }

    /// A verifier with no keys configured must accept nothing.
    #[test]
    fn an_unconfigured_verifier_accepts_nothing() {
        let mut v = SpaVerifier::new(WINDOW, 4096);
        let buf = build_psk(&psk_key(), &payload(1, NOW), 1);
        assert_eq!(v.verify(&buf, src(), NOW), Err(SpaError::NoPsk));
    }

    /// Memory must not grow with traffic, only with the window.
    #[test]
    fn sustained_traffic_does_not_grow_replay_memory_without_bound() {
        let mut v = SpaVerifier::new(5, 100_000).with_psk(psk_key());
        for t in 0..2_000u64 {
            let p = payload((t % 251) as u8, NOW + t);
            let buf = build_psk(&psk_key(), &p, (t % 251) as u8);
            let _ = v.verify(&buf, src(), NOW + t);
        }
        assert!(
            v.tracked_replays() <= 12,
            "replay memory unbounded: {}",
            v.tracked_replays()
        );
    }
}
