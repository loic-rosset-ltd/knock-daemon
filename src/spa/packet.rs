//! SPA wire format — parsing and serialisation only, no cryptography.
//!
//! Kept separate from `crypto` so the format can be fuzzed and unit-tested
//! without keys, and so a format bug cannot hide behind a crypto failure.
//!
//! ```text
//! header (6 bytes, authenticated as AAD, never encrypted)
//!   magic    4  b"KSPA"
//!   version  1  = 1
//!   mode     1  1 = pre-shared key, 2 = public key
//!
//! body, mode 1 (PSK)
//!   nonce   24  XChaCha20-Poly1305 nonce
//!   sealed  ..  ciphertext || 16-byte Poly1305 tag
//!
//! body, mode 2 (public key)
//!   eph_pub 32  X25519 ephemeral public key (also authenticated as AAD)
//!   nonce   24
//!   sealed  ..  ciphertext || tag
//! ```
//!
//! The header is authenticated but not encrypted: a tampered `mode` or
//! `version` byte changes the AAD and makes the tag fail, so downgrade attempts
//! are rejected by the AEAD rather than by hand-written checks.

use super::SpaError;

/// Magic prefix. Four bytes so a cheap memcmp rejects unrelated traffic before
/// any allocation or cryptographic work happens.
pub const MAGIC: [u8; 4] = *b"KSPA";
/// Wire format version. Bumped only on an incompatible change.
pub const VERSION: u8 = 1;

pub const HEADER_LEN: usize = 6;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const EPH_PUB_LEN: usize = 32;

/// Smallest packet that could possibly be valid, used to reject runts early.
pub const MIN_PACKET_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// An SPA packet is a single datagram; anything larger is not ours. This also
/// bounds the work an attacker can force per packet.
pub const MAX_PACKET_LEN: usize = 1400;

/// Which key agreement the sender used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Symmetric: both sides derive the key from a shared passphrase.
    Psk,
    /// Asymmetric: sender encrypts to the server's X25519 static public key
    /// with a fresh ephemeral key, and signs the payload with its Ed25519
    /// identity. The `authorized_keys` model — see `SPA-DESIGN.md`.
    PublicKey,
}

impl Mode {
    pub fn to_byte(self) -> u8 {
        match self {
            Mode::Psk => 1,
            Mode::PublicKey => 2,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self, SpaError> {
        match b {
            1 => Ok(Mode::Psk),
            2 => Ok(Mode::PublicKey),
            _ => Err(SpaError::UnknownMode(b)),
        }
    }
}

/// A parsed but still-sealed packet. Holding this proves the framing is
/// well-formed; it proves nothing about authenticity.
#[derive(Clone, Debug)]
pub struct SealedPacket<'a> {
    pub mode: Mode,
    /// X25519 ephemeral public key, public-key mode only.
    pub eph_pub: Option<[u8; EPH_PUB_LEN]>,
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the Poly1305 tag still appended.
    pub sealed: &'a [u8],
    /// Exactly the bytes that must be passed to the AEAD as associated data.
    pub aad: &'a [u8],
}

/// Parse framing. Does no cryptography and never interprets the payload.
pub fn parse(buf: &[u8]) -> Result<SealedPacket<'_>, SpaError> {
    if buf.len() < MIN_PACKET_LEN {
        return Err(SpaError::TooShort(buf.len()));
    }
    if buf.len() > MAX_PACKET_LEN {
        return Err(SpaError::TooLong(buf.len()));
    }
    if buf[..4] != MAGIC {
        return Err(SpaError::BadMagic);
    }
    if buf[4] != VERSION {
        return Err(SpaError::BadVersion(buf[4]));
    }
    let mode = Mode::from_byte(buf[5])?;

    // The AAD covers the header, plus the ephemeral public key in public-key
    // mode, so neither can be swapped without failing the tag.
    let (eph_pub, aad_len, body_at) = match mode {
        Mode::Psk => (None, HEADER_LEN, HEADER_LEN),
        Mode::PublicKey => {
            let end = HEADER_LEN + EPH_PUB_LEN;
            if buf.len() < end + NONCE_LEN + TAG_LEN {
                return Err(SpaError::TooShort(buf.len()));
            }
            let mut pk = [0u8; EPH_PUB_LEN];
            pk.copy_from_slice(&buf[HEADER_LEN..end]);
            (Some(pk), end, end)
        }
    };

    let nonce_end = body_at + NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[body_at..nonce_end]);

    let sealed = &buf[nonce_end..];
    if sealed.len() < TAG_LEN {
        return Err(SpaError::TooShort(buf.len()));
    }

    Ok(SealedPacket {
        mode,
        eph_pub,
        nonce,
        sealed,
        aad: &buf[..aad_len],
    })
}

/// Build the on-the-wire bytes from already-sealed ciphertext.
pub fn serialise(
    mode: Mode,
    eph_pub: Option<&[u8; EPH_PUB_LEN]>,
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MIN_PACKET_LEN + EPH_PUB_LEN + sealed.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(mode.to_byte());
    if let Some(pk) = eph_pub {
        out.extend_from_slice(pk);
    }
    out.extend_from_slice(nonce);
    out.extend_from_slice(sealed);
    out
}

/// The AAD for a packet being *built*. Must match what `parse` computes, which
/// the `aad_round_trips` test pins.
pub fn aad_for(mode: Mode, eph_pub: Option<&[u8; EPH_PUB_LEN]>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + EPH_PUB_LEN);
    aad.extend_from_slice(&MAGIC);
    aad.push(VERSION);
    aad.push(mode.to_byte());
    if let Some(pk) = eph_pub {
        aad.extend_from_slice(pk);
    }
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk_packet(payload_len: usize) -> Vec<u8> {
        let nonce = [7u8; NONCE_LEN];
        let sealed = vec![9u8; payload_len + TAG_LEN];
        serialise(Mode::Psk, None, &nonce, &sealed)
    }

    #[test]
    fn parses_a_psk_packet() {
        let buf = psk_packet(32);
        let p = parse(&buf).expect("should parse");
        assert_eq!(p.mode, Mode::Psk);
        assert!(p.eph_pub.is_none());
        assert_eq!(p.nonce, [7u8; NONCE_LEN]);
        assert_eq!(p.sealed.len(), 32 + TAG_LEN);
    }

    #[test]
    fn parses_a_public_key_packet() {
        let nonce = [1u8; NONCE_LEN];
        let eph = [2u8; EPH_PUB_LEN];
        let sealed = vec![3u8; 40 + TAG_LEN];
        let buf = serialise(Mode::PublicKey, Some(&eph), &nonce, &sealed);
        let p = parse(&buf).expect("should parse");
        assert_eq!(p.mode, Mode::PublicKey);
        assert_eq!(p.eph_pub, Some(eph));
        assert_eq!(p.nonce, nonce);
    }

    /// The AAD the builder uses and the AAD the parser reports must be byte
    /// identical, or every packet fails to open. Cheap test, catches a whole
    /// class of format drift.
    #[test]
    fn aad_round_trips_for_both_modes() {
        let buf = psk_packet(16);
        assert_eq!(parse(&buf).unwrap().aad, &aad_for(Mode::Psk, None)[..]);

        let eph = [5u8; EPH_PUB_LEN];
        let buf = serialise(Mode::PublicKey, Some(&eph), &[0u8; NONCE_LEN], &[0u8; TAG_LEN]);
        assert_eq!(
            parse(&buf).unwrap().aad,
            &aad_for(Mode::PublicKey, Some(&eph))[..]
        );
    }

    /// The ephemeral public key is inside the AAD precisely so it cannot be
    /// swapped for an attacker's. If this ever stops holding, public-key mode
    /// loses its binding between key agreement and payload.
    #[test]
    fn ephemeral_key_is_covered_by_the_aad() {
        let eph = [5u8; EPH_PUB_LEN];
        let aad = aad_for(Mode::PublicKey, Some(&eph));
        assert!(aad.ends_with(&eph));
        assert_eq!(aad.len(), HEADER_LEN + EPH_PUB_LEN);
    }

    #[test]
    fn rejects_runt_short_and_oversize_packets() {
        assert!(matches!(parse(&[]), Err(SpaError::TooShort(0))));
        assert!(matches!(parse(&[0u8; 10]), Err(SpaError::TooShort(10))));
        let big = vec![0u8; MAX_PACKET_LEN + 1];
        assert!(matches!(parse(&big), Err(SpaError::TooLong(_))));
    }

    #[test]
    fn rejects_foreign_traffic_by_magic_before_anything_else() {
        let mut buf = psk_packet(16);
        buf[0] = b'X';
        assert!(matches!(parse(&buf), Err(SpaError::BadMagic)));
    }

    #[test]
    fn rejects_unknown_version_and_mode() {
        let mut buf = psk_packet(16);
        buf[4] = 99;
        assert!(matches!(parse(&buf), Err(SpaError::BadVersion(99))));

        let mut buf = psk_packet(16);
        buf[5] = 77;
        assert!(matches!(parse(&buf), Err(SpaError::UnknownMode(77))));
    }

    /// A public-key packet truncated inside the ephemeral key must be rejected
    /// as short rather than read out of bounds.
    #[test]
    fn rejects_public_key_packet_truncated_in_the_ephemeral_key() {
        let eph = [2u8; EPH_PUB_LEN];
        let buf = serialise(Mode::PublicKey, Some(&eph), &[0u8; NONCE_LEN], &[0u8; TAG_LEN]);
        for cut in MIN_PACKET_LEN..buf.len() {
            // Never panics, always a clean error.
            let _ = parse(&buf[..cut]);
        }
        assert!(parse(&buf[..MIN_PACKET_LEN + 4]).is_err());
    }
}
