//! SPA packet construction — the sending half of [`SpaVerifier`].
//!
//! Everything here is pure: key material, a request and a timestamp go in,
//! bytes come out. No socket, no clock, no filesystem — `bin/knock.rs` owns all
//! of that. **The clock is a parameter**, as it is in `verify`, `ReplayGuard`
//! and `matcher`: `CONTRIBUTING.md` pins that invariant, and it is what lets the
//! timestamp tests below run without sleeping.
//!
//! These two builders are the production form of the `build_psk` and
//! `build_pubkey` helpers in the `spa` test module. They are kept honest by the
//! round-trip tests at the bottom, which push each built packet through a real
//! [`SpaVerifier`] — the only check that can catch the whole class of bug where
//! the builder and the verifier drift apart and every packet is silently
//! dropped by a daemon that, by design, answers nothing.

#![allow(dead_code)]

use std::net::IpAddr;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use super::crypto::{self, SymKey};
use super::packet::{self, Mode, EPH_PUB_LEN, NONCE_LEN};
use super::payload::SpaPayload;
use super::SpaError;

/// What the client is asking for. Deliberately not the payload type: a caller
/// must not be able to set `packet_id`, `timestamp` or `signature` by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub door: String,
    /// Seconds of access. `0` means "use the server's default" — the payload
    /// carries a literal zero rather than the client guessing server policy.
    pub duration_secs: u32,
    /// `None` is both the default and the safe answer: the server authorises
    /// the source address it observed, so a captured packet cannot open a door
    /// for the captor. A default-configured server ignores an explicit address
    /// anyway (`allow_explicit_addr`), so setting this is rarely right.
    pub addr: Option<IpAddr>,
}

impl Request {
    /// A request for `door` with server-default duration and no explicit
    /// address — the shape that should be used unless there is a reason not to.
    pub fn new(door: impl Into<String>) -> Self {
        Self {
            door: door.into(),
            duration_secs: 0,
            addr: None,
        }
    }

    pub fn with_duration(mut self, secs: u32) -> Self {
        self.duration_secs = secs;
        self
    }

    pub fn with_addr(mut self, addr: Option<IpAddr>) -> Self {
        self.addr = addr;
        self
    }
}

/// Build a PSK-mode packet.
///
/// `key` is the Argon2id output of [`crypto::derive_psk`] over the passphrase
/// and the server's configured salt. Deriving it is expensive by design and is
/// the caller's job, once, so that sending N packets does not cost N × 64 MiB.
pub fn build_psk(key: &SymKey, req: &Request, now_secs: u64) -> Result<Vec<u8>, SpaError> {
    let payload = fresh_payload(req, now_secs);
    let nonce = random_bytes::<NONCE_LEN>();
    let aad = packet::aad_for(Mode::Psk, None);
    let sealed = crypto::seal(key, &nonce, &aad, &payload.encode()?)?;
    Ok(packet::serialise(Mode::Psk, None, &nonce, &sealed))
}

/// Build a public-key-mode packet: encrypted to the server's X25519 static
/// public key, signed by the client's Ed25519 identity.
///
/// This is the `authorized_keys` shape `SPA-DESIGN.md` §2 recommends for more
/// than one host — the same identity addresses N servers, and a stolen server
/// config authorises nothing because it holds public keys only.
pub fn build_public_key(
    server_static_pub: &[u8; EPH_PUB_LEN],
    signing: &SigningKey,
    req: &Request,
    now_secs: u64,
) -> Result<Vec<u8>, SpaError> {
    // A fresh ephemeral key per packet, so the AEAD key is never reused and the
    // random nonce needs no counter state to be safe.
    let eph_secret = StaticSecret::from(random_bytes::<32>());
    let eph_pub = *PublicKey::from(&eph_secret).as_bytes();
    let shared = eph_secret.diffie_hellman(&PublicKey::from(*server_static_pub));
    // The server refuses a non-contributory exchange. Refuse to *send* one too:
    // a packet built against a low-order "public key" can only ever be dropped,
    // and silently emitting it would look like a network fault to the operator.
    if !shared.was_contributory() {
        return Err(SpaError::WeakKeyExchange);
    }
    let key = crypto::derive_from_x25519(shared.as_bytes(), &eph_pub, server_static_pub);

    let mut payload = fresh_payload(req, now_secs);
    payload.client_pub = Some(*signing.verifying_key().as_bytes());
    // Signed before sealing, over a region that includes the identity itself,
    // so a valid signature cannot be re-attached to a different client key.
    payload.signature = Some(signing.sign(&payload.signed_region()?).to_bytes());

    let nonce = random_bytes::<NONCE_LEN>();
    let aad = packet::aad_for(Mode::PublicKey, Some(&eph_pub));
    let sealed = crypto::seal(&key, &nonce, &aad, &payload.encode()?)?;
    Ok(packet::serialise(
        Mode::PublicKey,
        Some(&eph_pub),
        &nonce,
        &sealed,
    ))
}

/// Generate an X25519 static keypair for a server, as `(secret, public)`.
pub fn generate_static_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::from(random_bytes::<32>());
    let public = *PublicKey::from(&secret).as_bytes();
    (secret.to_bytes(), public)
}

/// Generate an Ed25519 client identity, as `(secret, public)`.
pub fn generate_identity() -> ([u8; 32], [u8; 32]) {
    let signing = SigningKey::from_bytes(&random_bytes::<32>());
    (signing.to_bytes(), *signing.verifying_key().as_bytes())
}

/// The per-packet unique material: a random id for the replay guard and the
/// caller's timestamp. The id is 128 random bits, so two clients that have
/// never met still do not collide.
fn fresh_payload(req: &Request, now_secs: u64) -> SpaPayload {
    SpaPayload {
        packet_id: random_bytes::<16>(),
        timestamp: now_secs,
        duration_secs: req.duration_secs,
        addr: req.addr,
        door: req.door.clone(),
        client_pub: None,
        signature: None,
    }
}

/// Panics rather than returning an error if the OS has no entropy. There is no
/// safe degraded mode: a predictable nonce or packet id is worse than no packet
/// at all, and a caller given an error would have nothing useful to do with it.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::super::{ReplayVerdict, SpaVerifier};
    use super::*;

    const WINDOW: u64 = 30;
    const NOW: u64 = 1_700_000_000;
    const SALT: &[u8] = b"client-test-salt";

    fn src() -> IpAddr {
        "203.0.113.10".parse().unwrap()
    }

    /// Argon2id at 64 MiB is intentionally expensive. Derive once for the whole
    /// test binary, exactly as `spa::tests::psk_key` does, or these tests spend
    /// minutes benchmarking the KDF instead of testing the client.
    fn psk_key() -> SymKey {
        static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        let bytes = KEY.get_or_init(|| *crypto::derive_psk(b"a test passphrase", SALT).unwrap());
        zeroize::Zeroizing::new(*bytes)
    }

    fn psk_verifier() -> SpaVerifier {
        SpaVerifier::new(WINDOW, 4096).with_psk(psk_key())
    }

    /// A server and a client that already know about each other, as
    /// `(verifier, server_public_key, client_signing_key)`.
    fn paired_public_key() -> (SpaVerifier, [u8; 32], SigningKey) {
        let (secret, _) = generate_static_keypair();
        let (id_secret, id_public) = generate_identity();
        let v = SpaVerifier::new(WINDOW, 4096)
            .with_static_secret(secret)
            .authorize(id_public);
        let server_pub = v.static_public().unwrap();
        (v, server_pub, SigningKey::from_bytes(&id_secret))
    }

    /// The test this whole module exists for. If the client and the verifier
    /// ever disagree by one byte, the daemon drops every packet in silence and
    /// the operator has nothing to debug with.
    #[test]
    fn a_psk_packet_built_by_the_client_verifies() {
        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &Request::new("ssh"), NOW).unwrap();
        let a = v.verify(&buf, src(), NOW).unwrap();
        assert_eq!(a.door, "ssh");
        assert_eq!(a.addr, src());
        assert_eq!(a.client_pub, None);
    }

    #[test]
    fn a_public_key_packet_built_by_the_client_verifies() {
        let (mut v, server_pub, signing) = paired_public_key();
        let buf = build_public_key(&server_pub, &signing, &Request::new("ssh"), NOW).unwrap();
        let a = v.verify(&buf, src(), NOW).unwrap();
        assert_eq!(a.door, "ssh");
        assert_eq!(a.client_pub, Some(*signing.verifying_key().as_bytes()));
    }

    /// A packet names exactly one door. Opening "web" must never be a way to
    /// reach "ssh", in either mode.
    #[test]
    fn a_packet_built_for_one_door_does_not_authorise_another() {
        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &Request::new("web"), NOW).unwrap();
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().door, "web");

        let (mut v, server_pub, signing) = paired_public_key();
        let buf = build_public_key(&server_pub, &signing, &Request::new("web"), NOW).unwrap();
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().door, "web");
    }

    /// The property a knock sequence cannot have: capturing what the client
    /// sent and sending it again achieves nothing.
    #[test]
    fn a_built_packet_replayed_verbatim_is_refused() {
        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &Request::new("ssh"), NOW).unwrap();
        assert!(v.verify(&buf, src(), NOW).is_ok());
        assert_eq!(
            v.verify(&buf, src(), NOW),
            Err(SpaError::Replay(ReplayVerdict::Replayed))
        );

        let (mut v, server_pub, signing) = paired_public_key();
        let buf = build_public_key(&server_pub, &signing, &Request::new("ssh"), NOW).unwrap();
        assert!(v.verify(&buf, src(), NOW).is_ok());
        assert_eq!(
            v.verify(&buf, src(), NOW),
            Err(SpaError::Replay(ReplayVerdict::Replayed))
        );
    }

    /// Two packets for the same request must differ in every random field, or
    /// the second one is refused as a replay of the first. A builder that
    /// reused either value would still pass the single-packet tests above.
    #[test]
    fn two_packets_for_the_same_request_are_both_accepted() {
        let mut v = psk_verifier();
        let req = Request::new("ssh");
        let a = build_psk(&psk_key(), &req, NOW).unwrap();
        let b = build_psk(&psk_key(), &req, NOW).unwrap();
        assert_ne!(a, b, "two packets must not be byte-identical");
        assert!(v.verify(&a, src(), NOW).is_ok());
        assert!(v.verify(&b, src(), NOW).is_ok(), "second packet refused");
    }

    /// The timestamp is the caller's, not the machine's: a packet built with a
    /// stale clock is refused on age, and one built ahead is refused as future.
    #[test]
    fn the_timestamp_comes_from_the_caller_not_the_clock() {
        let mut v = psk_verifier();

        let old = build_psk(&psk_key(), &Request::new("ssh"), NOW - WINDOW - 1).unwrap();
        assert!(matches!(
            v.verify(&old, src(), NOW),
            Err(SpaError::Replay(ReplayVerdict::TooOld { .. }))
        ));

        let ahead = build_psk(&psk_key(), &Request::new("ssh"), NOW + WINDOW + 1).unwrap();
        assert!(matches!(
            v.verify(&ahead, src(), NOW),
            Err(SpaError::Replay(ReplayVerdict::TooNew { .. }))
        ));
    }

    #[test]
    fn a_requested_duration_reaches_the_server_and_zero_means_default() {
        let mut v = psk_verifier().with_durations(30, 600);

        let buf = build_psk(&psk_key(), &Request::new("ssh").with_duration(120), NOW).unwrap();
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().duration_secs, 120);

        let buf = build_psk(&psk_key(), &Request::new("ssh"), NOW).unwrap();
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().duration_secs, 30);
    }

    /// An explicit address is carried, and a default server still ignores it.
    /// Both halves matter: the client must not silently drop what the operator
    /// asked for, and the server must not honour it unless configured to.
    #[test]
    fn an_explicit_address_is_carried_but_ignored_by_default() {
        let claimed: IpAddr = "198.51.100.99".parse().unwrap();
        let req = Request::new("ssh").with_addr(Some(claimed));

        let mut v = psk_verifier();
        let buf = build_psk(&psk_key(), &req, NOW).unwrap();
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().addr, src());

        let mut v = psk_verifier().allow_explicit_addr(true);
        let buf = build_psk(&psk_key(), &req, NOW).unwrap();
        assert_eq!(v.verify(&buf, src(), NOW).unwrap().addr, claimed);
    }

    /// The fleet story in reverse: a packet built for one server's static key
    /// must not open on another, so one compromised host authorises nothing
    /// elsewhere.
    #[test]
    fn a_packet_built_for_one_server_does_not_open_on_another() {
        let (mut v, _, signing) = paired_public_key();
        let (_, other_pub) = generate_static_keypair();
        let buf = build_public_key(&other_pub, &signing, &Request::new("ssh"), NOW).unwrap();
        assert_eq!(v.verify(&buf, src(), NOW), Err(SpaError::Open));
    }

    /// An identity the server has not authorised is refused even though the
    /// signature is perfectly valid.
    #[test]
    fn an_unauthorised_identity_is_refused() {
        let (mut v, server_pub, _) = paired_public_key();
        let (stranger, _) = generate_identity();
        let signing = SigningKey::from_bytes(&stranger);
        let buf = build_public_key(&server_pub, &signing, &Request::new("ssh"), NOW).unwrap();
        assert_eq!(
            v.verify(&buf, src(), NOW),
            Err(SpaError::UnauthorizedClient)
        );
    }

    /// A low-order "server public key" is caught at build time rather than
    /// producing a packet that can only be dropped.
    #[test]
    fn refuses_to_build_against_a_low_order_server_key() {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        assert_eq!(
            build_public_key(&[0u8; 32], &signing, &Request::new("ssh"), NOW),
            Err(SpaError::WeakKeyExchange)
        );
    }

    /// A door name the payload encoder rejects must fail here, not produce a
    /// malformed packet.
    #[test]
    fn rejects_an_unencodable_door_name() {
        let req = Request::new("");
        assert_eq!(build_psk(&psk_key(), &req, NOW), Err(SpaError::BadDoorName));
    }

    #[test]
    fn generated_keypairs_are_distinct_and_self_consistent() {
        let (s1, p1) = generate_static_keypair();
        let (s2, p2) = generate_static_keypair();
        assert_ne!(s1, s2);
        assert_ne!(p1, p2);
        assert_eq!(*PublicKey::from(&StaticSecret::from(s1)).as_bytes(), p1);

        let (i1, v1) = generate_identity();
        let (i2, _) = generate_identity();
        assert_ne!(i1, i2);
        assert_eq!(*SigningKey::from_bytes(&i1).verifying_key().as_bytes(), v1);
    }
}
