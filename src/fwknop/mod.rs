//! fwknop wire compatibility — **read only**, and only fwknop's strong subset.
//!
//! # Why this exists
//!
//! fwknop has the users. It ships an Android app and an iPhone app, it is in
//! Debian, and the people who already run SPA are running it. Asking them to
//! change clients to try this daemon is asking too much, so this module lets a
//! **genuine, unmodified fwknop client** — including those phone apps — talk to
//! `knockd2` with no change at all on their side.
//!
//! It is a decoder and nothing else. There is no code here that produces an
//! fwknop packet, and there will not be: the native SPA format in `src/spa` is
//! what this daemon emits, and offering a second way to *generate* obsolete
//! crypto would undo the point of having a modern format.
//!
//! The whole module is behind the off-by-default `compat-fwknop` feature, so
//! the default build does not link AES, CBC, MD5 or any of the rest of it.
//!
//! # The rule: accept the strong subset, refuse the rest by name
//!
//! fwknop's options range from sound to actively dangerous, and the dangerous
//! ones are not deprecated — they are just settings. This module implements the
//! sound subset and refuses everything else **with a distinct, logged reason**.
//! That is the same philosophy the `knockd.conf` importer already ships:
//! reject, do not ignore. A silently downgraded knock is worse than a refused
//! one, because the operator believes they have protection they do not have.
//!
//! | Setting | Accepted | Refused |
//! |---|---|---|
//! | Encryption mode | `CBC` | `ECB`, `CFB`, `OFB`, `PCBC`, `CTR`, pre-2.5 `legacy` IV → [`FwknopError::WeakEncryptionMode`] |
//! | HMAC | mandatory: SHA-256/384/512, SHA3-256/512 | **absent** → [`FwknopError::HmacAbsent`]; MD5, SHA-1 → [`FwknopError::WeakHmac`] |
//! | Inner digest | SHA-256/384/512 | MD5, SHA-1 → [`FwknopError::WeakDigest`] |
//!
//! Two of those deserve their reasoning spelled out:
//!
//! * **ECB is not a mode, it is a bug with a name.** fwknop offers it, and an
//!   fwknop server will happily be configured to accept it. Identical plaintext
//!   blocks produce identical ciphertext blocks, which for a format whose first
//!   field is a fixed-length random value and whose remaining fields are highly
//!   structured is a real leak. The other stream-like modes (CFB, OFB, CTR)
//!   are refused for a different reason: without an authenticated mode they are
//!   trivially malleable bit-by-bit, and fwknop's HMAC is optional.
//! * **An absent HMAC is refused outright.** fwknop permits it, and with it the
//!   packet is unauthenticated ciphertext that the server must decrypt and then
//!   *parse* before it learns anything is wrong. That is a decryption oracle
//!   and a parser reachable by anyone who can send a UDP datagram. We require
//!   an HMAC and verify it **before decryption**, always.
//!
//! # Verification order
//!
//! 1. settings — refuse a weak configuration before a packet byte is touched
//! 2. framing — length and alphabet
//! 3. **HMAC**, constant-time, over the base64 text *as transmitted*
//! 4. base64 decode, `Salted__` header, key/IV derivation
//! 5. AES-256-CBC decrypt, strict PKCS#7
//! 6. inner digest
//! 7. field parsing
//! 8. freshness — [`FwknopRequest::check_timestamp`], clock injected by the caller
//!
//! Step 3 before step 5 is the property fwknop had to add deliberately, and
//! which it still lets an operator turn off. Here it is not optional.
//!
//! # Not in this phase
//!
//! * **GPG / asymmetric mode.** `// Phase 3b:` — fwknop's `FKO_ENCRYPTION_GPG`
//!   needs an OpenPGP implementation and a keyring, and it is a much larger
//!   attack surface than a packet decoder. A GPG packet does not carry the
//!   `Salted__` header and is refused by [`FwknopError::NotRijndaelPacket`].
//! * **SHA3 HMAC and SHA3 digests.** They are in fwknop's strong set and are
//!   accepted by [`FwknopSettings::validate`], but computing one needs a SHA3
//!   implementation this crate does not depend on; see
//!   [`FwknopError::HmacAlgorithmUnavailable`].
//!
//! # Wire format, for the reader who has to maintain this
//!
//! ```text
//! packet   = base64(Salted__ || salt8 || AES-256-CBC(plaintext))   -- '=' stripped,
//!            with the constant leading "U2FsdGVkX1" removed        -- lib/fko_funcs.c
//!         || base64(HMAC(key, "U2FsdGVkX1" || the above))          -- '=' stripped
//!
//! plaintext = <encoded message> ":" base64(digest(<encoded message>))
//! ```
//!
//! The HMAC covers the base64 text *with* the `U2FsdGVkX1` prefix restored,
//! because that is the buffer fwknop happens to hold when it computes it
//! (`lib/fko_hmac.c` calls `add_salted_str` first). It is an accident of
//! implementation, not a design, and it is the single easiest thing to get
//! wrong when reading this format.

// Nothing calls this module yet: wiring it into the SPA dispatch path is a
// separate change. Until then the decoder's public surface has no non-test
// consumer, which is not a defect of the decoder.
#![allow(dead_code, unused_imports)]

mod crypto;
mod message;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

pub use message::{AccessProto, FwknopRequest, MessageType, NatTarget, ProtoPort, RAND_VAL_LEN};

/// The constant base64 prefix fwknop strips before transmitting and that must
/// be restored before either hashing or decoding (`B64_RIJNDAEL_SALT`).
const B64_RIJNDAEL_SALT: &str = "U2FsdGVkX1";

/// `MIN_SPA_ENCODED_MSG_SIZE` — fwknop's own floor, described in its source as
/// "somewhat arbitrary". Kept identical so nothing real is refused here that
/// fwknop would accept.
const MIN_SPA_DATA: usize = 36;

/// `MAX_SPA_ENCRYPTED_SIZE`. Also, conveniently, a bound on how much work one
/// datagram can cost us.
const MAX_SPA_DATA: usize = 1500;

/// fwknop's symmetric encryption modes (`fko_encryption_mode_t`).
///
/// All of them are named, including the ones we refuse: an operator migrating
/// a working fwknop deployment needs to be told *which* setting is the problem,
/// not that "the packet failed".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncryptionMode {
    /// The only mode accepted. fwknop's default since 2.5.
    Cbc,
    Ecb,
    Cfb,
    Pcbc,
    Ofb,
    Ctr,
    /// Pre-2.5 zero-padded-key IV derivation. fwknop's own source calls it
    /// "not recommended" and says it will be removed.
    CbcLegacyIv,
}

impl std::fmt::Display for EncryptionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EncryptionMode::Cbc => "CBC",
            EncryptionMode::Ecb => "ECB",
            EncryptionMode::Cfb => "CFB",
            EncryptionMode::Pcbc => "PCBC",
            EncryptionMode::Ofb => "OFB",
            EncryptionMode::Ctr => "CTR",
            EncryptionMode::CbcLegacyIv => "legacy (pre-2.5 IV)",
        };
        f.write_str(s)
    }
}

/// fwknop's HMAC types (`fko_hmac_type_t`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HmacType {
    /// fwknop's `FKO_HMAC_UNKNOWN`: no HMAC on the packet at all.
    None,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl std::fmt::Display for HmacType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HmacType::None => "none",
            HmacType::Md5 => "md5",
            HmacType::Sha1 => "sha1",
            HmacType::Sha256 => "sha256",
            HmacType::Sha384 => "sha384",
            HmacType::Sha512 => "sha512",
            HmacType::Sha3_256 => "sha3-256",
            HmacType::Sha3_512 => "sha3-512",
        };
        f.write_str(s)
    }
}

/// The digest carried *inside* the encrypted message.
///
/// Unlike the HMAC and the cipher mode, this one is not configuration: the
/// client chooses it and its length is all that identifies it on the wire, so
/// a weak choice is a property of the packet and is refused as such.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DigestType {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl std::fmt::Display for DigestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DigestType::Md5 => "md5",
            DigestType::Sha1 => "sha1",
            DigestType::Sha256 => "sha256",
            DigestType::Sha384 => "sha384",
            DigestType::Sha512 => "sha512",
        };
        f.write_str(s)
    }
}

/// What the server must be told in order to read a given client's packets.
///
/// This mirrors one fwknop `access.conf` stanza: `KEY`/`KEY_BASE64`,
/// `HMAC_KEY`/`HMAC_KEY_BASE64`, `ENCRYPTION_MODE` and `HMAC_DIGEST_TYPE`.
/// Keys are raw bytes; decoding whatever base64 the operator wrote in a config
/// file is the config layer's job, not this one's.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FwknopSettings {
    pub enc_key: Vec<u8>,
    pub enc_mode: EncryptionMode,
    pub hmac_type: HmacType,
    pub hmac_key: Vec<u8>,
}

impl FwknopSettings {
    /// Check the configuration before any packet is looked at.
    ///
    /// Calling this early is the whole design: a deployment configured for ECB
    /// or for no HMAC should fail loudly at load time, not quietly accept
    /// datagrams it cannot safely authenticate. [`decode`] calls it on every
    /// packet as well, because a cheap check that cannot be forgotten is worth
    /// more than a cheaper one that can.
    pub fn validate(&self) -> Result<(), FwknopError> {
        if self.enc_mode != EncryptionMode::Cbc {
            return Err(FwknopError::WeakEncryptionMode(self.enc_mode));
        }
        match self.hmac_type {
            HmacType::None => return Err(FwknopError::HmacAbsent),
            HmacType::Md5 | HmacType::Sha1 => return Err(FwknopError::WeakHmac(self.hmac_type)),
            HmacType::Sha256 | HmacType::Sha384 | HmacType::Sha512 => {}
            // Accepted as strong, but not computable without a SHA3
            // dependency. The failure surfaces at verification time with its
            // own variant so it can never be mistaken for a bad HMAC.
            HmacType::Sha3_256 | HmacType::Sha3_512 => {}
        }
        if self.enc_key.is_empty() {
            return Err(FwknopError::EncKeyEmpty);
        }
        if self.enc_key.len() > crypto::MAX_ENC_KEY_LEN {
            return Err(FwknopError::EncKeyTooLong(self.enc_key.len()));
        }
        if self.hmac_key.is_empty() {
            return Err(FwknopError::HmacKeyEmpty);
        }
        if self.hmac_key.len() > crypto::MAX_HMAC_KEY_LEN {
            return Err(FwknopError::HmacKeyTooLong(self.hmac_key.len()));
        }
        Ok(())
    }
}

/// Every way an fwknop packet, or the settings for reading one, can be refused.
///
/// Each weak setting gets its own variant on purpose. A log line that says
/// "ECB refused" tells an operator what to change; one that says "bad packet"
/// sends them looking for a network problem that is not there.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FwknopError {
    // --- configuration ------------------------------------------------------
    /// A cipher mode outside the accepted subset.
    WeakEncryptionMode(EncryptionMode),
    /// The configuration asks for no HMAC. fwknop permits this; we do not.
    HmacAbsent,
    /// MD5 or SHA-1 HMAC.
    WeakHmac(HmacType),
    /// SHA3 is strong but this build has no SHA3 implementation. Needs the
    /// `sha3` crate added to the `compat-fwknop` feature; see the module docs.
    HmacAlgorithmUnavailable(HmacType),
    EncKeyEmpty,
    EncKeyTooLong(usize),
    HmacKeyEmpty,
    HmacKeyTooLong(usize),

    // --- framing ------------------------------------------------------------
    PacketTooShort(usize),
    PacketTooLong(usize),
    /// Not base64 text at all.
    NotBase64,
    /// The packet already carries the `U2FsdGVkX1` prefix that a genuine client
    /// strips. fwknop's server refuses these too (`server/incoming_spa.c`):
    /// tacking a prefix onto a previously seen packet is an attempt to slip a
    /// replay past a digest-based replay cache.
    PrefixStuffed,

    // --- authentication and decryption -------------------------------------
    /// Wrong HMAC key, or the packet was altered. Deliberately one variant:
    /// distinguishing them would hand an attacker an oracle.
    HmacVerificationFailed,
    CiphertextNotBlockAligned(usize),
    /// No `Salted__` header. A GPG-mode packet lands here.
    NotRijndaelPacket,
    /// PKCS#7 padding did not verify after decryption.
    BadPadding,
    /// Decrypted to something that is not an fwknop message — in practice, the
    /// wrong encryption key.
    DecryptionFailed,

    // --- inner digest -------------------------------------------------------
    WeakDigest(DigestType),
    BadDigestLength(usize),
    /// The digest did not match. Note that a packet using a SHA3 *digest* also
    /// lands here: SHA3-256 and SHA-256 produce the same base64 length, so
    /// without a SHA3 implementation the two are indistinguishable and the
    /// comparison simply fails.
    DigestVerificationFailed,

    // --- message fields -----------------------------------------------------
    NonPrintableMessage,
    TooFewFields(usize),
    TooManyFields {
        message_type: MessageType,
        found: usize,
    },
    MissingField(&'static str),
    FieldTooLong(&'static str),
    FieldNotBase64(&'static str),
    FieldNotUtf8(&'static str),
    BadRandValue,
    BadTimestamp(String),
    BadMessageType(String),
    UnknownMessageType(u8),
    BadUsername,
    BadAccessMessage,
    BadCommandMessage,
    BadProtoPort(String),
    BadAllowIp(String),
    BadNatAccess(String),
    BadClientTimeout(String),
    MissingClientTimeout,

    // --- freshness ----------------------------------------------------------
    TimestampOutOfWindow {
        timestamp: u64,
        now: u64,
        max_skew: u64,
    },
}

impl std::fmt::Display for FwknopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use FwknopError::*;
        match self {
            WeakEncryptionMode(m) => write!(
                f,
                "fwknop encryption mode {m} refused: only CBC is accepted"
            ),
            HmacAbsent => write!(
                f,
                "fwknop stanza has no HMAC: an unauthenticated SPA packet is refused"
            ),
            WeakHmac(t) => write!(
                f,
                "fwknop HMAC type {t} refused: sha256 or stronger required"
            ),
            HmacAlgorithmUnavailable(t) => write!(
                f,
                "fwknop HMAC type {t} is not compiled in (needs a SHA3 implementation)"
            ),
            EncKeyEmpty => write!(f, "fwknop encryption key is empty"),
            EncKeyTooLong(n) => write!(f, "fwknop encryption key too long ({n} bytes, max 32)"),
            HmacKeyEmpty => write!(f, "fwknop HMAC key is empty"),
            HmacKeyTooLong(n) => write!(f, "fwknop HMAC key too long ({n} bytes, max 136)"),
            PacketTooShort(n) => write!(f, "fwknop packet too short ({n} bytes)"),
            PacketTooLong(n) => write!(f, "fwknop packet too long ({n} bytes)"),
            NotBase64 => write!(f, "fwknop packet is not base64"),
            PrefixStuffed => write!(f, "fwknop packet carries a stuffed Salted__ prefix"),
            HmacVerificationFailed => write!(f, "fwknop HMAC verification failed"),
            CiphertextNotBlockAligned(n) => {
                write!(f, "fwknop ciphertext is {n} bytes, not a multiple of 16")
            }
            NotRijndaelPacket => write!(
                f,
                "fwknop packet has no Salted__ header (GPG mode is not supported)"
            ),
            BadPadding => write!(f, "fwknop plaintext has invalid PKCS#7 padding"),
            DecryptionFailed => write!(f, "fwknop decryption produced no valid message"),
            WeakDigest(d) => write!(
                f,
                "fwknop message digest {d} refused: sha256 or stronger required"
            ),
            BadDigestLength(n) => write!(f, "fwknop message digest has unknown length {n}"),
            DigestVerificationFailed => write!(f, "fwknop message digest did not match"),
            NonPrintableMessage => write!(f, "fwknop message contains non-printable bytes"),
            TooFewFields(n) => write!(f, "fwknop message has only {n} fields"),
            TooManyFields {
                message_type,
                found,
            } => write!(
                f,
                "fwknop message type {message_type:?} cannot carry {found} trailing fields"
            ),
            MissingField(w) => write!(f, "fwknop message is missing its {w} field"),
            FieldTooLong(w) => write!(f, "fwknop {w} field is too long"),
            FieldNotBase64(w) => write!(f, "fwknop {w} field is not base64"),
            FieldNotUtf8(w) => write!(f, "fwknop {w} field is not valid UTF-8"),
            BadRandValue => write!(f, "fwknop random value is not 16 digits"),
            BadTimestamp(s) => write!(f, "fwknop timestamp {s:?} is not a number"),
            BadMessageType(s) => write!(f, "fwknop message type {s:?} is not a number"),
            UnknownMessageType(v) => write!(f, "fwknop message type {v} is unknown"),
            BadUsername => write!(f, "fwknop username is not acceptable"),
            BadAccessMessage => write!(f, "fwknop access message is malformed"),
            BadCommandMessage => write!(f, "fwknop command message is malformed"),
            BadProtoPort(s) => write!(f, "fwknop proto/port spec {s:?} is malformed"),
            BadAllowIp(s) => write!(f, "fwknop allow address {s:?} is not a dotted-quad IPv4"),
            BadNatAccess(s) => write!(f, "fwknop NAT access spec {s:?} is malformed"),
            BadClientTimeout(s) => write!(f, "fwknop client timeout {s:?} is malformed"),
            MissingClientTimeout => {
                write!(
                    f,
                    "fwknop message type requires a client timeout but has none"
                )
            }
            TimestampOutOfWindow {
                timestamp,
                now,
                max_skew,
            } => write!(
                f,
                "fwknop timestamp {timestamp} is outside ±{max_skew}s of {now}"
            ),
        }
    }
}

impl std::error::Error for FwknopError {}

/// Decode one SPA datagram from a genuine fwknop client.
///
/// `wire` is the UDP payload, exactly as it arrived — no trimming, no
/// normalisation. Returning `Ok` means the HMAC verified, the packet decrypted
/// under `settings.enc_key`, the inner digest matched and every field parsed
/// inside fwknop's own limits.
///
/// It does **not** mean the request is fresh or should be granted. This
/// function never reads the clock; call [`FwknopRequest::check_timestamp`] with
/// an injected `now_secs`, then apply replay and access policy.
pub fn decode(wire: &[u8], settings: &FwknopSettings) -> Result<FwknopRequest, FwknopError> {
    settings.validate()?;

    if wire.len() < MIN_SPA_DATA {
        return Err(FwknopError::PacketTooShort(wire.len()));
    }
    if wire.len() > MAX_SPA_DATA {
        return Err(FwknopError::PacketTooLong(wire.len()));
    }

    // The whole packet is base64 text. Anything else — a stray newline, an
    // HTTP request, binary — is refused here rather than deeper in.
    let wire = std::str::from_utf8(wire).map_err(|_| FwknopError::NotBase64)?;
    if !wire
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(FwknopError::NotBase64);
    }
    if wire.starts_with(B64_RIJNDAEL_SALT) {
        return Err(FwknopError::PrefixStuffed);
    }

    // --- 1. HMAC, before anything is decrypted ------------------------------
    let hmac_len = crypto::hmac_b64_len(settings.hmac_type);
    if wire.len() < hmac_len + MIN_SPA_DATA {
        return Err(FwknopError::PacketTooShort(wire.len()));
    }
    let (body, transmitted_hmac) = wire.split_at(wire.len() - hmac_len);

    // The prefix fwknop stripped has to go back on: it is part of what was
    // hashed, and part of what must be base64-decoded.
    let mut restored = String::with_capacity(B64_RIJNDAEL_SALT.len() + body.len());
    restored.push_str(B64_RIJNDAEL_SALT);
    restored.push_str(body);

    let computed = crypto::hmac_b64(settings.hmac_type, &settings.hmac_key, restored.as_bytes())?;
    if !crypto::hmac_matches(&computed, transmitted_hmac.as_bytes()) {
        return Err(FwknopError::HmacVerificationFailed);
    }

    // --- 2. Decode and decrypt ---------------------------------------------
    let cipher = STANDARD_NO_PAD
        .decode(&restored)
        .map_err(|_| FwknopError::NotBase64)?;
    if cipher.len() < crypto::SALTED_HEADER_LEN + crypto::IV_LEN
        || cipher.len() % crypto::IV_LEN != 0
    {
        return Err(FwknopError::CiphertextNotBlockAligned(cipher.len()));
    }
    if &cipher[..8] != b"Salted__" {
        return Err(FwknopError::NotRijndaelPacket);
    }

    let (key, iv) = crypto::derive_key_iv(&settings.enc_key, &cipher[8..crypto::SALTED_HEADER_LEN]);
    let plaintext = crypto::aes256_cbc_decrypt(&key, &iv, &cipher[crypto::SALTED_HEADER_LEN..])?;
    let plaintext = String::from_utf8(plaintext).map_err(|_| FwknopError::DecryptionFailed)?;

    // fwknop's own wrong-key detector: the message must open with 16 decimal
    // digits and a colon (`lib/fko_encryption.c:_rijndael_decrypt`). Under the
    // wrong key this fails essentially always, which is why it runs before the
    // message is picked apart.
    if plaintext.len() <= RAND_VAL_LEN
        || !plaintext.as_bytes()[..RAND_VAL_LEN]
            .iter()
            .all(u8::is_ascii_digit)
        || plaintext.as_bytes()[RAND_VAL_LEN] != b':'
    {
        return Err(FwknopError::DecryptionFailed);
    }

    // --- 3. Inner digest ----------------------------------------------------
    let total_colons = plaintext.matches(':').count();
    let split = plaintext
        .rfind(':')
        .ok_or(FwknopError::TooFewFields(total_colons))?;
    let (body_with_colon, digest_field) = plaintext.split_at(split);
    let digest_field = &digest_field[1..];

    let digest_type = digest_type_for_len(digest_field.len())?;
    match digest_type {
        DigestType::Md5 | DigestType::Sha1 => return Err(FwknopError::WeakDigest(digest_type)),
        DigestType::Sha256 | DigestType::Sha384 | DigestType::Sha512 => {}
    }

    let expected = match digest_type {
        DigestType::Sha256 => STANDARD_NO_PAD.encode(Sha256::digest(body_with_colon.as_bytes())),
        DigestType::Sha384 => STANDARD_NO_PAD.encode(Sha384::digest(body_with_colon.as_bytes())),
        DigestType::Sha512 => STANDARD_NO_PAD.encode(Sha512::digest(body_with_colon.as_bytes())),
        DigestType::Md5 | DigestType::Sha1 => unreachable!("refused above"),
    };
    let matched: bool = expected.as_bytes().ct_eq(digest_field.as_bytes()).into();
    if !matched {
        return Err(FwknopError::DigestVerificationFailed);
    }

    // --- 4. Fields ----------------------------------------------------------
    message::parse_encoded(body_with_colon, total_colons)
}

/// fwknop identifies the inner digest by its base64 length alone
/// (`lib/fko_decode.c:is_valid_digest_len`). SHA3-256 and SHA-256 share a
/// length, as do SHA3-512 and SHA-512; the collision is resolved there by
/// trying both, and here by trying the SHA-2 one and letting a SHA3 packet fail
/// the comparison.
fn digest_type_for_len(len: usize) -> Result<DigestType, FwknopError> {
    Ok(match len {
        22 => DigestType::Md5,
        27 => DigestType::Sha1,
        43 => DigestType::Sha256,
        64 => DigestType::Sha384,
        86 => DigestType::Sha512,
        other => return Err(FwknopError::BadDigestLength(other)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ---------------------------------------------------------------------
    // Fixtures
    //
    // **CAPTURED, not reconstructed.** Every `.b64` file under `fixtures/` is
    // the byte-for-byte output of the genuine, unmodified fwknop 2.6.11
    // client's `--save-packet`, which writes exactly the payload it would have
    // put in the UDP datagram. Not one line of the C was edited.
    //
    // The build host had no autoconf, so `./autogen.sh && ./configure` was not
    // available and the sources were compiled directly with the HAVE_* macros
    // `configure` would have set, from a clean checkout of fwknop 2.6.11:
    //
    //   CF='-O1 -w -Ilib -Icommon -Iclient -DHAVE_STDINT_H=1 -DSTDC_HEADERS=1
    //       -DHAVE_UNISTD_H=1 -DHAVE_CTYPE_H=1 -DHAVE_SYS_TIME_H=1
    //       -DHAVE_STRNLEN=1 -DHAVE_BZERO=1 -DHAVE_MEMSET=1 -DHAVE_STRINGS_H=1
    //       -DHAVE_TIME_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1
    //       -DHAVE_STRLCAT=1 -DHAVE_STRLCPY=1 -DHAVE_SYS_SOCKET_H=1
    //       -DHAVE_NETDB_H=1 -DHAVE_ARPA_INET_H=1 -DHAVE_NETINET_IN_H=1
    //       -DHAVE_SYS_WAIT_H=1 -DHAVE_ERRNO_H=1 -DHAVE_FCNTL_H=1
    //       -DHAVE_SYS_STAT_H=1 -DHAVE_LOCALE_H=1 -DHAVE_TERMIOS_H=1
    //       -DHAVE_GETLINE=1 -DVERSION=\"2.6.11\"'
    //   cc $CF -o fwknop lib/*.c common/fko_util.c client/*.c   # minus
    //       # lib/gpgme_funcs.c, lib/fko_utests.c, client/fwknop_utests.c
    //
    // The resulting binary self-reports "fwknop client 2.6.11, FKO protocol
    // version 3.0.0", which is the version string the fixtures carry.
    //
    // Reproduce each fixture with:
    //
    //   fwknop --no-rc-file --no-save-args -T -D 127.0.0.1 -U testuser \
    //     --key-base64-rijndael=a25vY2stZGFlbW9uLWZ3a25vcC10ZXN0LWtleS0wMDE= \
    //     --key-base64-hmac=a25vY2stZGFlbW9uLWZ3a25vcC10ZXN0LWhtYWMtMDE= \
    //     --use-hmac -B <fixture> <per-fixture args>
    //
    // The per-fixture args are recorded at each use below. `-B` appends a
    // trailing newline, which `packet()` strips; nothing else is touched.
    // ---------------------------------------------------------------------

    /// The `--key-base64-rijndael` value above, decoded.
    const ENC_KEY: &[u8] = b"knock-daemon-fwknop-test-key-001";
    /// The `--key-base64-hmac` value above, decoded.
    const HMAC_KEY: &[u8] = b"knock-daemon-fwknop-test-hmac-01";

    fn settings(hmac_type: HmacType) -> FwknopSettings {
        FwknopSettings {
            enc_key: ENC_KEY.to_vec(),
            enc_mode: EncryptionMode::Cbc,
            hmac_type,
            hmac_key: HMAC_KEY.to_vec(),
        }
    }

    fn sha256_settings() -> FwknopSettings {
        settings(HmacType::Sha256)
    }

    fn packet(raw: &str) -> Vec<u8> {
        raw.trim_end().as_bytes().to_vec()
    }

    // `-A tcp/22 -a 192.168.1.50`
    const ACCESS: &str = include_str!("fixtures/access.b64");
    // `-A "tcp/22,udp/53,tcp/8080" -a 10.0.0.7`
    const ACCESS_MULTI: &str = include_str!("fixtures/access_multi.b64");
    // `-A tcp/22 -a 192.168.1.50 -f 120`
    const TIMEOUT_ACCESS: &str = include_str!("fixtures/timeout_access.b64");
    // `-A tcp/22 -a 192.168.1.50 -N 192.168.10.5:2222`
    const NAT_ACCESS: &str = include_str!("fixtures/nat_access.b64");
    // `-A tcp/22 -a 192.168.1.50 -N 192.168.10.5:2222 -f 90`
    const TIMEOUT_NAT: &str = include_str!("fixtures/timeout_nat.b64");
    // `-A tcp/22 -a 192.168.1.50 -N 192.168.10.5:2222 --nat-local`
    const LOCAL_NAT: &str = include_str!("fixtures/local_nat.b64");
    // `-A tcp/22 -a 192.168.1.50 -N 192.168.10.5:2222 --nat-local -f 45`
    const TIMEOUT_LOCAL_NAT: &str = include_str!("fixtures/timeout_local_nat.b64");
    // `-C "/bin/echo hello" -a 192.168.1.50`
    const COMMAND: &str = include_str!("fixtures/command.b64");
    // `-A tcp/22 -a 192.168.1.50 --hmac-digest-type sha512 -m sha512`
    const HMAC_SHA512: &str = include_str!("fixtures/hmac_sha512.b64");
    // `-A tcp/22 -a 192.168.1.50 --hmac-digest-type sha384 -m sha384`
    const HMAC_SHA384: &str = include_str!("fixtures/hmac_sha384.b64");
    // `-A tcp/22 -a 192.168.1.50 -m sha384`
    const DIGEST_SHA384: &str = include_str!("fixtures/digest_sha384.b64");
    // `-A tcp/22 -a 192.168.1.50 -m md5`
    const WEAK_DIGEST_MD5: &str = include_str!("fixtures/weak_digest_md5.b64");
    // `-A tcp/22 -a 192.168.1.50 -m sha1`
    const WEAK_DIGEST_SHA1: &str = include_str!("fixtures/weak_digest_sha1.b64");
    // `-A tcp/22 -a 192.168.1.50 --hmac-digest-type md5`
    const WEAK_HMAC_MD5: &str = include_str!("fixtures/weak_hmac_md5.b64");
    // `-A tcp/22 -a 192.168.1.50 --hmac-digest-type sha1`
    const WEAK_HMAC_SHA1: &str = include_str!("fixtures/weak_hmac_sha1.b64");
    // `-A tcp/22 -a 192.168.1.50 -M ecb`
    const MODE_ECB: &str = include_str!("fixtures/mode_ecb.b64");
    // `-A tcp/22 -a 192.168.1.50 -M cfb`
    const MODE_CFB: &str = include_str!("fixtures/mode_cfb.b64");
    // `-A tcp/22 -a 192.168.1.50` with `--use-hmac` omitted entirely.
    const NO_HMAC: &str = include_str!("fixtures/no_hmac.b64");

    // ---------------------------------------------------------------------
    // The headline test: real client output decodes.
    // ---------------------------------------------------------------------

    #[test]
    fn decodes_a_real_fwknop_access_packet() {
        let r = decode(&packet(ACCESS), &sha256_settings()).unwrap();
        assert_eq!(r.message_type, MessageType::Access);
        // The FKO protocol version, which fwknop 2.6.11 reports as 3.0.0.
        assert_eq!(r.version, "3.0.0");
        assert_eq!(r.username, "testuser");
        assert_eq!(r.allow_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(
            r.ports,
            vec![ProtoPort {
                proto: AccessProto::Tcp,
                port: 22
            }]
        );
        assert_eq!(r.rand_value.len(), RAND_VAL_LEN);
        // These two are pinned from libfko's *own* decoder run over these same
        // bytes (`fko_new_with_data` + the `fko_get_*` accessors), not from
        // what this implementation happened to produce. That independence is
        // the point: it is the only assertion here that could catch this
        // decoder and its author being wrong in the same direction.
        assert_eq!(r.rand_value, "1060666733364027");
        assert_eq!(r.timestamp, 1_790_258_911);
        assert_eq!(r.client_timeout, None);
        assert_eq!(r.nat, None);
        assert_eq!(r.command, None);
    }

    #[test]
    fn decodes_a_multi_port_access_request() {
        let r = decode(&packet(ACCESS_MULTI), &sha256_settings()).unwrap();
        assert_eq!(r.allow_ip, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(
            r.ports,
            vec![
                ProtoPort {
                    proto: AccessProto::Tcp,
                    port: 22
                },
                ProtoPort {
                    proto: AccessProto::Udp,
                    port: 53
                },
                ProtoPort {
                    proto: AccessProto::Tcp,
                    port: 8080
                },
            ]
        );
        assert_eq!(r.access, "10.0.0.7,tcp/22,udp/53,tcp/8080");
    }

    /// Every message type the client can produce, decoded from a real packet.
    /// The tail-field ambiguity between `server_auth` and `client_timeout`
    /// only bites on the timeout-bearing types, which is why all four appear.
    #[test]
    fn every_message_type_round_trips() {
        let s = sha256_settings();

        let r = decode(&packet(TIMEOUT_ACCESS), &s).unwrap();
        assert_eq!(r.message_type, MessageType::ClientTimeoutAccess);
        assert_eq!(r.client_timeout, Some(120));

        let r = decode(&packet(NAT_ACCESS), &s).unwrap();
        assert_eq!(r.message_type, MessageType::NatAccess);
        assert_eq!(
            r.nat,
            Some(NatTarget {
                host: "192.168.10.5".to_string(),
                port: 2222
            })
        );
        assert_eq!(r.client_timeout, None);

        let r = decode(&packet(TIMEOUT_NAT), &s).unwrap();
        assert_eq!(r.message_type, MessageType::ClientTimeoutNatAccess);
        assert_eq!(r.client_timeout, Some(90));
        assert!(r.nat.is_some());

        let r = decode(&packet(LOCAL_NAT), &s).unwrap();
        assert_eq!(r.message_type, MessageType::LocalNatAccess);
        assert!(r.nat.is_some());

        let r = decode(&packet(TIMEOUT_LOCAL_NAT), &s).unwrap();
        assert_eq!(r.message_type, MessageType::ClientTimeoutLocalNatAccess);
        assert_eq!(r.client_timeout, Some(45));

        let r = decode(&packet(COMMAND), &s).unwrap();
        assert_eq!(r.message_type, MessageType::Command);
        assert_eq!(r.command.as_deref(), Some("/bin/echo hello"));
        assert_eq!(r.allow_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert!(r.ports.is_empty());
    }

    #[test]
    fn stronger_hmac_and_digest_choices_decode() {
        let r = decode(&packet(HMAC_SHA512), &settings(HmacType::Sha512)).unwrap();
        assert_eq!(r.allow_ip, Ipv4Addr::new(192, 168, 1, 50));

        let r = decode(&packet(HMAC_SHA384), &settings(HmacType::Sha384)).unwrap();
        assert_eq!(r.allow_ip, Ipv4Addr::new(192, 168, 1, 50));

        // SHA-384 inner digest with the default SHA-256 HMAC.
        let r = decode(&packet(DIGEST_SHA384), &sha256_settings()).unwrap();
        assert_eq!(r.allow_ip, Ipv4Addr::new(192, 168, 1, 50));
    }

    // ---------------------------------------------------------------------
    // The refusals. Each weak setting, by name.
    // ---------------------------------------------------------------------

    /// The cipher mode is not carried on the wire — an ECB packet is
    /// structurally identical to a CBC one — so it is refused as a setting,
    /// before the packet is looked at. That is why these fixtures exist: to
    /// show that a real client *will* produce them and that we never get as
    /// far as trying.
    #[test]
    fn weak_encryption_modes_are_refused_by_name() {
        for (mode, fixture) in [
            (EncryptionMode::Ecb, MODE_ECB),
            (EncryptionMode::Cfb, MODE_CFB),
            (EncryptionMode::Ofb, MODE_ECB),
            (EncryptionMode::Pcbc, MODE_ECB),
            (EncryptionMode::Ctr, MODE_ECB),
            (EncryptionMode::CbcLegacyIv, MODE_ECB),
        ] {
            let s = FwknopSettings {
                enc_mode: mode,
                ..sha256_settings()
            };
            assert_eq!(s.validate(), Err(FwknopError::WeakEncryptionMode(mode)));
            assert_eq!(
                decode(&packet(fixture), &s),
                Err(FwknopError::WeakEncryptionMode(mode))
            );
        }
    }

    #[test]
    fn absent_hmac_is_refused_outright() {
        let s = FwknopSettings {
            hmac_type: HmacType::None,
            ..sha256_settings()
        };
        assert_eq!(s.validate(), Err(FwknopError::HmacAbsent));
        // And the packet a client produces without `--use-hmac` is refused too.
        assert_eq!(decode(&packet(NO_HMAC), &s), Err(FwknopError::HmacAbsent));
    }

    /// A packet sent with no HMAC, against a correctly configured server, must
    /// fail authentication rather than be read. It is shorter than a real
    /// packet by the HMAC's length, so the trailing 43 characters we strip are
    /// ciphertext, and the check fails — which is the fail-closed outcome.
    #[test]
    fn unauthenticated_packet_does_not_authenticate() {
        assert_eq!(
            decode(&packet(NO_HMAC), &sha256_settings()),
            Err(FwknopError::HmacVerificationFailed)
        );
    }

    #[test]
    fn weak_hmac_types_are_refused_by_name() {
        for (t, fixture) in [
            (HmacType::Md5, WEAK_HMAC_MD5),
            (HmacType::Sha1, WEAK_HMAC_SHA1),
        ] {
            let s = settings(t);
            assert_eq!(s.validate(), Err(FwknopError::WeakHmac(t)));
            assert_eq!(decode(&packet(fixture), &s), Err(FwknopError::WeakHmac(t)));
        }
    }

    /// The inner digest *is* on the wire, so this refusal is a property of the
    /// packet: a client configured with `-m md5` is turned away with the reason
    /// named, after its HMAC has verified.
    #[test]
    fn weak_inner_digests_are_refused_by_name() {
        assert_eq!(
            decode(&packet(WEAK_DIGEST_MD5), &sha256_settings()),
            Err(FwknopError::WeakDigest(DigestType::Md5))
        );
        assert_eq!(
            decode(&packet(WEAK_DIGEST_SHA1), &sha256_settings()),
            Err(FwknopError::WeakDigest(DigestType::Sha1))
        );
    }

    #[test]
    fn sha3_hmac_is_accepted_as_strong_and_actually_verifies() {
        // Previously this asserted SHA-3 was accepted by `validate()` and then
        // refused at decode as unavailable -- an accept-list entry that could
        // never succeed. The `sha3` dependency was added instead, so the two
        // halves now agree: if we say we accept it, it has to work.
        for t in [HmacType::Sha3_256, HmacType::Sha3_512] {
            let s = settings(t);
            assert_eq!(s.validate(), Ok(()));
            // The fixtures are SHA-256-HMAC packets, so a SHA-3 setting must now
            // fail on the *HMAC comparison* -- a real verification that did not
            // match -- rather than on the algorithm being missing.
            assert_eq!(
                decode(&packet(ACCESS), &s),
                Err(FwknopError::HmacVerificationFailed),
                "{t:?} should verify and mismatch, not report unavailable"
            );
        }
    }

    #[test]
    fn malformed_keys_are_refused() {
        let s = FwknopSettings {
            enc_key: Vec::new(),
            ..sha256_settings()
        };
        assert_eq!(s.validate(), Err(FwknopError::EncKeyEmpty));

        let s = FwknopSettings {
            enc_key: vec![0u8; 33],
            ..sha256_settings()
        };
        assert_eq!(s.validate(), Err(FwknopError::EncKeyTooLong(33)));

        let s = FwknopSettings {
            hmac_key: Vec::new(),
            ..sha256_settings()
        };
        assert_eq!(s.validate(), Err(FwknopError::HmacKeyEmpty));

        let s = FwknopSettings {
            hmac_key: vec![0u8; 137],
            ..sha256_settings()
        };
        assert_eq!(s.validate(), Err(FwknopError::HmacKeyTooLong(137)));
    }

    // ---------------------------------------------------------------------
    // Tampering, wrong keys, truncation.
    // ---------------------------------------------------------------------

    /// Flip one character anywhere in the ciphertext body and the HMAC must
    /// catch it — before a single block is decrypted.
    #[test]
    fn tampered_ciphertext_fails_the_hmac() {
        let good = packet(ACCESS);
        let hmac_len = crypto::hmac_b64_len(HmacType::Sha256);
        let body_len = good.len() - hmac_len;
        // Sample across the body rather than every byte: the property is
        // positional, and 16 probes cover every cipher block.
        for i in (0..body_len).step_by(body_len / 16) {
            let mut bad = good.clone();
            bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
            assert_eq!(
                decode(&bad, &sha256_settings()),
                Err(FwknopError::HmacVerificationFailed),
                "byte {i} was not caught"
            );
        }
    }

    #[test]
    fn tampered_hmac_fails() {
        let mut bad = packet(ACCESS);
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            decode(&bad, &sha256_settings()),
            Err(FwknopError::HmacVerificationFailed)
        );
    }

    #[test]
    fn wrong_hmac_key_fails_before_decryption() {
        let s = FwknopSettings {
            hmac_key: b"a completely different hmac key".to_vec(),
            ..sha256_settings()
        };
        assert_eq!(
            decode(&packet(ACCESS), &s),
            Err(FwknopError::HmacVerificationFailed)
        );
    }

    /// A correct HMAC key with the wrong encryption key gets past step 3 and
    /// must then fail cleanly — never panic, never return a half-parsed
    /// request. Padding is checked before content, so either outcome is
    /// acceptable; what matters is that it is one of them.
    #[test]
    fn wrong_encryption_key_fails_cleanly() {
        let s = FwknopSettings {
            enc_key: b"a completely different enc key".to_vec(),
            ..sha256_settings()
        };
        let err = decode(&packet(ACCESS), &s).unwrap_err();
        assert!(
            matches!(
                err,
                FwknopError::BadPadding
                    | FwknopError::DecryptionFailed
                    | FwknopError::NonPrintableMessage
            ),
            "unexpected error {err:?}"
        );
    }

    /// Every truncation of a real packet must produce an error, not a panic.
    /// This is the cheapest possible fuzz and it covers the boundary
    /// arithmetic around the HMAC split and the `Salted__` header.
    #[test]
    fn every_truncation_errors_without_panicking() {
        let good = packet(ACCESS);
        for cut in 0..good.len() {
            let err = decode(&good[..cut], &sha256_settings()).unwrap_err();
            // A truncated packet can never authenticate.
            assert_ne!(err, FwknopError::DigestVerificationFailed);
        }
        assert!(decode(&good, &sha256_settings()).is_ok());
    }

    /// And every single-byte extension, for the same reason: the HMAC split is
    /// computed from the end of the buffer.
    #[test]
    fn trailing_junk_is_refused() {
        for extra in [b'A', b'=', b'\n', 0x00, 0xff] {
            let mut bad = packet(ACCESS);
            bad.push(extra);
            assert!(decode(&bad, &sha256_settings()).is_err());
        }
    }

    #[test]
    fn oversized_and_undersized_packets_are_refused() {
        assert_eq!(
            decode(&[b'A'; 10], &sha256_settings()),
            Err(FwknopError::PacketTooShort(10))
        );
        assert_eq!(
            decode(&[b'A'; 1501], &sha256_settings()),
            Err(FwknopError::PacketTooLong(1501))
        );
    }

    #[test]
    fn non_base64_input_is_refused() {
        let mut bad = packet(ACCESS);
        bad[0] = b'!';
        assert_eq!(
            decode(&bad, &sha256_settings()),
            Err(FwknopError::NotBase64)
        );
        // Invalid UTF-8 too.
        let mut bad = packet(ACCESS);
        bad[0] = 0x80;
        assert_eq!(
            decode(&bad, &sha256_settings()),
            Err(FwknopError::NotBase64)
        );
    }

    /// fwknop's server refuses a packet that arrives with the `Salted__`
    /// prefix already on it, because appending one to a captured packet is a
    /// way to change its digest without changing what it decrypts to. We do
    /// the same.
    #[test]
    fn prefix_stuffed_packet_is_refused() {
        let mut bad = B64_RIJNDAEL_SALT.as_bytes().to_vec();
        bad.extend_from_slice(&packet(ACCESS));
        assert_eq!(
            decode(&bad, &sha256_settings()),
            Err(FwknopError::PrefixStuffed)
        );
    }

    /// The clock never comes from inside the decoder. `decode` returns a
    /// request regardless of age; freshness is a separate, injected decision.
    #[test]
    fn freshness_is_a_separate_injected_decision() {
        let r = decode(&packet(ACCESS), &sha256_settings()).unwrap();
        assert!(r.check_timestamp(r.timestamp, 0).is_ok());
        assert!(r.check_timestamp(r.timestamp + 30, 60).is_ok());
        assert!(matches!(
            r.check_timestamp(r.timestamp + 61, 60),
            Err(FwknopError::TimestampOutOfWindow { .. })
        ));
    }

    #[test]
    fn digest_length_table_matches_fwknop() {
        assert_eq!(digest_type_for_len(22), Ok(DigestType::Md5));
        assert_eq!(digest_type_for_len(27), Ok(DigestType::Sha1));
        assert_eq!(digest_type_for_len(43), Ok(DigestType::Sha256));
        assert_eq!(digest_type_for_len(64), Ok(DigestType::Sha384));
        assert_eq!(digest_type_for_len(86), Ok(DigestType::Sha512));
        assert_eq!(
            digest_type_for_len(44),
            Err(FwknopError::BadDigestLength(44))
        );
    }
}
