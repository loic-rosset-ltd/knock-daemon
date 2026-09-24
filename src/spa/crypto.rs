//! Key derivation, sealing and opening.
//!
//! Deliberate departures from fwknop, each because the modern primitive removes
//! a class of mistake rather than because it is newer:
//!
//! | fwknop | here | why |
//! |---|---|---|
//! | AES-256-CBC + HMAC-SHA256, encrypt-then-MAC assembled by hand | **XChaCha20-Poly1305** | One AEAD call. There is no MAC to assemble, so there is no MAC-assembly bug, no padding oracle, and no "verify before decrypt" ordering to get right — the tag is checked before any plaintext is released. |
//! | **PBKDF1** for passphrase keys | **Argon2id** | PBKDF1 is obsolete and cheap to attack offline. Argon2id is memory-hard. Derived **once at startup** from a config salt, never per packet, so it is not a DoS vector. |
//! | GPG for asymmetric mode | **X25519 + Ed25519** | No GnuPG dependency, no keyring, no agent. Same shape as SSH's `authorized_keys`, which is what operators already know. |
//! | 64-bit nonce space needing care | **192-bit XChaCha nonce** | Random nonces are safe without any counter state, which a stateless single packet needs. |
//!
//! The AEAD key is never derived from attacker-controlled input on the packet
//! path. Per packet the server does one X25519 (public-key mode only) and one
//! AEAD open, both constant-time and cheap.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::packet::{Mode, EPH_PUB_LEN, NONCE_LEN};
use super::SpaError;

/// A symmetric AEAD key. Wrapped so it is wiped when dropped.
pub type SymKey = Zeroizing<[u8; 32]>;

/// Derive the shared key from a passphrase.
///
/// Called **once, at config load** — never per packet. The salt lives in the
/// config rather than on the wire precisely so that a flood of packets cannot
/// force the server to run a memory-hard function.
pub fn derive_psk(passphrase: &[u8], salt: &[u8]) -> Result<SymKey, SpaError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    if salt.len() < 8 {
        return Err(SpaError::SaltTooShort(salt.len()));
    }
    let mut out: SymKey = Zeroizing::new([0u8; 32]);
    // 64 MiB, 3 passes, 1 lane: a deliberate, documented cost. Startup only.
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| SpaError::KeyDerivation)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| SpaError::KeyDerivation)?;
    Ok(out)
}

/// Derive the AEAD key for public-key mode from an X25519 shared secret.
///
/// The ephemeral and static public keys are folded into the hash so the key is
/// bound to *this* pair. Without that binding a shared secret could be reused
/// across contexts.
pub fn derive_from_x25519(shared: &[u8; 32], eph_pub: &[u8; 32], static_pub: &[u8; 32]) -> SymKey {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let mut h = Blake2bVar::new(32).expect("32 is a valid Blake2b output length");
    h.update(b"knock-daemon spa v1 x25519");
    h.update(shared);
    h.update(eph_pub);
    h.update(static_pub);
    let mut out: SymKey = Zeroizing::new([0u8; 32]);
    h.finalize_variable(out.as_mut())
        .expect("output length matches the configured length");
    out
}

/// Encrypt `plaintext`, binding `aad` (the packet header, and the ephemeral key
/// in public-key mode) to the ciphertext.
pub fn seal(
    key: &SymKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SpaError> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| SpaError::Seal)
}

/// Verify and decrypt. A failure here is indistinguishable between "wrong key"
/// and "tampered packet", which is intended: the server must not tell a prober
/// which it was.
pub fn open(
    key: &SymKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, SpaError> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map_err(|_| SpaError::Open)
}

/// Compute the X25519 shared secret for an inbound packet.
pub fn x25519_shared(
    static_secret: &[u8; 32],
    eph_pub: &[u8; EPH_PUB_LEN],
) -> Result<[u8; 32], SpaError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk = StaticSecret::from(*static_secret);
    let pk = PublicKey::from(*eph_pub);
    let shared = sk.diffie_hellman(&pk);
    // Reject the all-zero shared secret produced by low-order points.
    if !shared.was_contributory() {
        return Err(SpaError::WeakKeyExchange);
    }
    Ok(*shared.as_bytes())
}

/// Verify an Ed25519 signature over the payload's signed region.
pub fn verify_signature(
    client_pub: &[u8; 32],
    signed_region: &[u8],
    signature: &[u8; 64],
) -> Result<(), SpaError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vk = VerifyingKey::from_bytes(client_pub).map_err(|_| SpaError::BadClientKey)?;
    let sig = Signature::from_bytes(signature);
    vk.verify(signed_region, &sig)
        .map_err(|_| SpaError::BadSignature)
}

/// Which mode a given key material implies. Small helper so callers do not
/// re-derive the mapping and get it inconsistent.
pub fn mode_for_static_key(has_static: bool) -> Mode {
    if has_static {
        Mode::PublicKey
    } else {
        Mode::Psk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SymKey {
        Zeroizing::new([b; 32])
    }

    #[test]
    fn seals_and_opens_a_round_trip() {
        let k = key(1);
        let n = [2u8; NONCE_LEN];
        let aad = b"header";
        let sealed = seal(&k, &n, aad, b"hello").unwrap();
        assert_eq!(open(&k, &n, aad, &sealed).unwrap(), b"hello");
    }

    #[test]
    fn the_tag_makes_the_ciphertext_longer_than_the_plaintext() {
        let sealed = seal(&key(1), &[0u8; NONCE_LEN], b"", b"hello").unwrap();
        assert_eq!(sealed.len(), 5 + 16);
    }

    #[test]
    fn a_wrong_key_fails_to_open() {
        let n = [2u8; NONCE_LEN];
        let sealed = seal(&key(1), &n, b"h", b"x").unwrap();
        assert!(matches!(open(&key(2), &n, b"h", &sealed), Err(SpaError::Open)));
    }

    /// The AAD carries the header and the ephemeral key. If a changed AAD still
    /// opened, downgrade and key-substitution attacks would both be possible.
    #[test]
    fn tampering_with_the_aad_fails_to_open() {
        let k = key(1);
        let n = [2u8; NONCE_LEN];
        let sealed = seal(&k, &n, b"header-A", b"payload").unwrap();
        assert!(open(&k, &n, b"header-B", &sealed).is_err());
    }

    /// Every single-bit flip anywhere in the ciphertext or tag must be caught.
    #[test]
    fn every_single_bit_flip_in_the_ciphertext_is_rejected() {
        let k = key(1);
        let n = [2u8; NONCE_LEN];
        let sealed = seal(&k, &n, b"h", b"a secret request").unwrap();
        for byte in 0..sealed.len() {
            for bit in 0..8 {
                let mut bad = sealed.clone();
                bad[byte] ^= 1 << bit;
                assert!(
                    open(&k, &n, b"h", &bad).is_err(),
                    "flip at byte {byte} bit {bit} was not detected"
                );
            }
        }
    }

    #[test]
    fn a_wrong_nonce_fails_to_open() {
        let k = key(1);
        let sealed = seal(&k, &[2u8; NONCE_LEN], b"h", b"x").unwrap();
        assert!(open(&k, &[3u8; NONCE_LEN], b"h", &sealed).is_err());
    }

    #[test]
    fn argon2_is_deterministic_and_salt_dependent() {
        let a = derive_psk(b"correct horse", b"saltsaltsalt").unwrap();
        let b = derive_psk(b"correct horse", b"saltsaltsalt").unwrap();
        let c = derive_psk(b"correct horse", b"different123").unwrap();
        let d = derive_psk(b"wrong horse", b"saltsaltsalt").unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), c.as_ref());
        assert_ne!(a.as_ref(), d.as_ref());
    }

    #[test]
    fn rejects_a_short_salt() {
        assert!(matches!(
            derive_psk(b"pw", b"short"),
            Err(SpaError::SaltTooShort(5))
        ));
    }

    /// Both sides must land on the same key, and it must depend on all three
    /// inputs, or the binding is not doing its job.
    #[test]
    fn x25519_agreement_matches_and_is_context_bound() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let server_sk = StaticSecret::from([7u8; 32]);
        let server_pk = PublicKey::from(&server_sk);
        let eph_sk = StaticSecret::from([9u8; 32]);
        let eph_pk = PublicKey::from(&eph_sk);

        let server_shared =
            x25519_shared(server_sk.as_bytes(), eph_pk.as_bytes()).unwrap();
        let client_shared = eph_sk.diffie_hellman(&server_pk);
        assert_eq!(&server_shared, client_shared.as_bytes());

        let k1 = derive_from_x25519(&server_shared, eph_pk.as_bytes(), server_pk.as_bytes());
        let k2 = derive_from_x25519(&server_shared, eph_pk.as_bytes(), server_pk.as_bytes());
        assert_eq!(k1.as_ref(), k2.as_ref());

        let k3 = derive_from_x25519(&server_shared, &[0u8; 32], server_pk.as_bytes());
        assert_ne!(k1.as_ref(), k3.as_ref(), "key must bind the ephemeral key");
    }

    /// A low-order point yields an all-zero shared secret. Accepting it would
    /// let anyone force a key both sides can compute without the private key.
    #[test]
    fn rejects_a_low_order_ephemeral_key() {
        let sk = [7u8; 32];
        assert!(matches!(
            x25519_shared(&sk, &[0u8; 32]),
            Err(SpaError::WeakKeyExchange)
        ));
    }

    #[test]
    fn verifies_a_good_signature_and_rejects_a_bad_one() {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let msg = b"the signed region";
        let sig = sk.sign(msg);

        assert!(verify_signature(vk.as_bytes(), msg, &sig.to_bytes()).is_ok());
        assert!(matches!(
            verify_signature(vk.as_bytes(), b"a different region", &sig.to_bytes()),
            Err(SpaError::BadSignature)
        ));

        let other = SigningKey::from_bytes(&[43u8; 32]).verifying_key();
        assert!(matches!(
            verify_signature(other.as_bytes(), msg, &sig.to_bytes()),
            Err(SpaError::BadSignature)
        ));
    }
}
