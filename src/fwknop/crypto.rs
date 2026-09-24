//! The cryptographic primitives a genuine fwknop packet is built from.
//!
//! Every choice here is dictated by fwknop's wire format, not by preference.
//! Where fwknop offers a weaker option, this module does not implement it at
//! all — the refusal happens one level up in [`super::FwknopSettings::validate`],
//! and the code to do the weak thing simply does not exist.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use md5::Digest as _;
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};
use subtle::ConstantTimeEq;

use super::{FwknopError, HmacType};

/// MD5, via the `md-5` crate.
///
/// Used *only* inside fwknop's `EVP_BytesToKey` key derivation, which is
/// hard-wired to MD5 and cannot be changed without breaking compatibility. It is not
/// used for authentication anywhere: the HMAC is verified first, with SHA-2 or
/// SHA-3, before this is ever reached.
fn md5(data: &[u8]) -> [u8; 16] {
    md5::Md5::digest(data).into()
}

/// AES-256 in CBC mode, decrypt direction. The only cipher we implement.
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// fwknop's salt is the 8 bytes following the literal `Salted__`.
pub const SALT_LEN: usize = 8;
/// `Salted__` plus the salt: the OpenSSL header fwknop borrows.
pub const SALTED_HEADER_LEN: usize = 16;
/// AES-256 key length.
pub const KEY_LEN: usize = 32;
/// AES block / CBC IV length.
pub const IV_LEN: usize = 16;

/// fwknop refuses a Rijndael key longer than the AES-256 key size
/// (`RIJNDAEL_MAX_KEYSIZE`, `lib/rijndael.h`). Longer keys are silently
/// truncated by OpenSSL-compatible tooling, so refusing is the honest answer.
pub const MAX_ENC_KEY_LEN: usize = 32;

/// fwknop's `MAX_DIGEST_BLOCK_LEN` (`lib/hmac.h`): the SHA3-256 block length,
/// which is the longest block of any HMAC it supports.
pub const MAX_HMAC_KEY_LEN: usize = 136;

/// Derive the AES key and IV the way fwknop does.
///
/// This is OpenSSL's `EVP_BytesToKey` with **MD5 and a single iteration** — a
/// PBKDF1-shaped construction that is obsolete as a password KDF and is used
/// here only because the format demands it:
///
/// ```text
/// D_1 = MD5(password || salt)
/// D_i = MD5(D_{i-1} || password || salt)
/// key = (D_1 || D_2 || D_3)[0..32]
/// iv  = (D_1 || D_2 || D_3)[32..48]
/// ```
///
/// Source: `lib/cipher_funcs.c:rij_salt_and_iv`. Three MD5 blocks are exactly
/// enough for a 32-byte key plus a 16-byte IV, which is why the loop is fixed.
///
/// **This is not a password-strengthening function.** It is one MD5 per 16
/// bytes of output and offers no work factor. It is why `SECURITY.md` says
/// fwknop-compatible mode is for interoperating with existing deployments,
/// not the mode to choose for a new one.
pub fn derive_key_iv(password: &[u8], salt: &[u8]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
    debug_assert_eq!(salt.len(), SALT_LEN);

    let mut kiv = [0u8; KEY_LEN + IV_LEN];
    let mut prev = [0u8; 16];
    let mut filled = 0usize;

    while filled < kiv.len() {
        let mut buf = Vec::with_capacity(16 + password.len() + salt.len());
        if filled > 0 {
            buf.extend_from_slice(&prev);
        }
        buf.extend_from_slice(password);
        buf.extend_from_slice(salt);
        prev = md5(&buf);
        kiv[filled..filled + 16].copy_from_slice(&prev);
        filled += 16;
    }

    let mut key = [0u8; KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    key.copy_from_slice(&kiv[..KEY_LEN]);
    iv.copy_from_slice(&kiv[KEY_LEN..]);
    (key, iv)
}

/// Decrypt the body of a `Salted__` blob with AES-256-CBC and strip PKCS#7.
///
/// `body` is everything after the 16-byte `Salted__` + salt header.
///
/// **Departure from fwknop, deliberate:** `lib/cipher_funcs.c:rij_decrypt`
/// treats a malformed pad as "no padding" and keeps the bytes. We refuse. By
/// the time this runs the HMAC has already been verified, so the ciphertext is
/// authentic; a pad that does not verify therefore means a corrupt or
/// adversarially-constructed packet, and silently keeping trailing junk in
/// something we are about to parse as an authorisation request is not a
/// behaviour worth being bug-compatible with.
pub fn aes256_cbc_decrypt(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    body: &[u8],
) -> Result<Vec<u8>, FwknopError> {
    if body.is_empty() || body.len() % IV_LEN != 0 {
        return Err(FwknopError::CiphertextNotBlockAligned(body.len()));
    }
    let mut buf = body.to_vec();
    let plaintext = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| FwknopError::BadPadding)?;
    Ok(plaintext.to_vec())
}

/// Number of base64 characters an HMAC of this type occupies on the wire.
///
/// fwknop base64-encodes the digest and then truncates at the first `=`
/// (`lib/base64.c:strip_b64_eq`), so the transmitted length is the unpadded
/// one. These are fwknop's own `*_B64_LEN` constants.
pub fn hmac_b64_len(t: HmacType) -> usize {
    match t {
        HmacType::Md5 => 22,
        HmacType::Sha1 => 27,
        HmacType::Sha256 | HmacType::Sha3_256 => 43,
        HmacType::Sha384 => 64,
        HmacType::Sha512 | HmacType::Sha3_512 => 86,
        HmacType::None => 0,
    }
}

/// Compute the HMAC over the SPA data exactly as fwknop transmits it, and
/// return it base64-encoded with padding stripped — the form that appears on
/// the wire.
///
/// Only the strong subset is implemented. The weak types have no arm here:
/// they are rejected by [`super::FwknopSettings::validate`] before any packet
/// byte is touched, and SHA3 needs a dependency the crate does not carry (see
/// [`FwknopError::HmacAlgorithmUnavailable`]).
pub fn hmac_b64(t: HmacType, key: &[u8], msg: &[u8]) -> Result<String, FwknopError> {
    /// The `Mac` trait's `new_from_slice` cannot fail for these algorithms —
    /// they accept keys of any length — but the signature is fallible, so the
    /// impossible case is mapped rather than unwrapped.
    macro_rules! mac {
        ($alg:ty) => {{
            let mut m = <Hmac<$alg>>::new_from_slice(key)
                .map_err(|_| FwknopError::HmacKeyTooLong(key.len()))?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }

    let digest = match t {
        HmacType::Sha256 => mac!(Sha256),
        HmacType::Sha384 => mac!(Sha384),
        HmacType::Sha512 => mac!(Sha512),
        HmacType::Sha3_256 => mac!(Sha3_256),
        HmacType::Sha3_512 => mac!(Sha3_512),
        // Exhaustive on purpose: no catch-all. If fwknop ever grows another
        // HMAC type, this must fail to compile rather than silently take a
        // default branch and decide on its own whether it is safe.
        HmacType::Md5 | HmacType::Sha1 | HmacType::None => return Err(FwknopError::WeakHmac(t)),
    };

    Ok(STANDARD_NO_PAD.encode(digest))
}

/// Constant-time comparison of the computed HMAC against the transmitted one.
///
/// Length is compared first and in the clear: it is a function of the HMAC
/// type, which is configuration, not a secret. The bytes themselves go through
/// `subtle` so that a partial match cannot be timed out one character at a
/// time — the attack fwknop's own `constant_runtime_cmp` exists to stop.
pub fn hmac_matches(computed: &str, transmitted: &[u8]) -> bool {
    if computed.len() != transmitted.len() {
        return false;
    }
    computed.as_bytes().ct_eq(transmitted).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anchored against OpenSSL's own `EVP_BytesToKey(EVP_aes_256_cbc(),
    /// EVP_md5(), salt, "password", 8, 1, key, iv)`, i.e. what
    /// `openssl enc -aes-256-cbc -md md5 -P -S 0102030405060708 -k password`
    /// prints. If this test fails, no genuine fwknop packet will decrypt.
    #[test]
    fn evp_bytes_to_key_md5_matches_openssl() {
        let salt = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let (key, iv) = derive_key_iv(b"password", &salt);
        assert_eq!(
            hex(&key),
            "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce02"
        );
        assert_eq!(hex(&iv), "8d450e2ed75a84a923d4eac9fe49226b");
    }

    /// The derivation chains: block 2 folds in block 1. A truncated loop or a
    /// missing `prev` would still produce a plausible-looking key, so the
    /// relationship is asserted directly.
    #[test]
    fn key_blocks_chain() {
        let salt = [9u8; 8];
        let (key, iv) = derive_key_iv(b"k", &salt);
        let d1 = md5(&[b"k".as_slice(), &salt].concat());
        let d2 = md5(&[d1.as_slice(), b"k", &salt].concat());
        let d3 = md5(&[d2.as_slice(), b"k", &salt].concat());
        assert_eq!(&key[..16], &d1[..]);
        assert_eq!(&key[16..], &d2[..]);
        assert_eq!(&iv[..], &d3[..]);
    }

    /// RFC 4231 test case 2, the one with a short ASCII key, in the base64 form
    /// fwknop puts on the wire.
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let got = hmac_b64(HmacType::Sha256, b"Jefe", b"what do ya want for nothing?").unwrap();
        // RFC 4231: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
        assert_eq!(
            STANDARD_NO_PAD.decode(&got).unwrap(),
            hexdec("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_eq!(got.len(), hmac_b64_len(HmacType::Sha256));
    }

    #[test]
    fn hmac_sha384_and_sha512_rfc4231_case2() {
        let sha384 = hmac_b64(HmacType::Sha384, b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(
            STANDARD_NO_PAD.decode(&sha384).unwrap(),
            hexdec(
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                 8e2240ca5e69e2c78b3239ecfab21649"
            )
        );
        assert_eq!(sha384.len(), hmac_b64_len(HmacType::Sha384));

        let sha512 = hmac_b64(HmacType::Sha512, b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(
            STANDARD_NO_PAD.decode(&sha512).unwrap(),
            hexdec(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                 9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            )
        );
        assert_eq!(sha512.len(), hmac_b64_len(HmacType::Sha512));
    }

    /// The weak types must not be computable at all, even by an internal
    /// caller that forgot to validate its settings first.
    #[test]
    fn weak_hmac_types_are_not_implemented() {
        for t in [HmacType::Md5, HmacType::Sha1, HmacType::None] {
            assert!(matches!(
                hmac_b64(t, b"k", b"m"),
                Err(FwknopError::WeakHmac(_))
            ));
        }
    }

    /// SHA3 is in fwknop's strong set but needs a hash this crate does not
    /// depend on. That gap must announce itself, not masquerade as a bad HMAC.
    #[test]
    fn sha3_hmac_now_verifies_rather_than_reporting_unavailable() {
        // This test previously asserted SHA-3 was *unavailable*, which was true
        // only because the crate had no `sha3` dependency. The dependency was
        // added rather than leaving an accept-list entry that could never
        // verify, so the expectation flips: SHA-3 must produce a real HMAC.
        for t in [HmacType::Sha3_256, HmacType::Sha3_512] {
            let got = hmac_b64(t, b"k", b"m").expect("sha3 must verify now");
            assert_eq!(got.len(), hmac_b64_len(t), "wrong length for {t:?}");
        }
        // And the two lengths must differ, or the length check cannot tell them
        // apart on the wire.
        assert_ne!(
            hmac_b64_len(HmacType::Sha3_256),
            hmac_b64_len(HmacType::Sha3_512)
        );
    }

    #[test]
    fn hmac_comparison_rejects_length_and_content_mismatch() {
        assert!(hmac_matches("abcdef", b"abcdef"));
        assert!(!hmac_matches("abcdef", b"abcde"));
        assert!(!hmac_matches("abcdef", b"abcdeg"));
    }

    #[test]
    fn misaligned_ciphertext_is_refused_not_panicked() {
        let key = [0u8; KEY_LEN];
        let iv = [0u8; IV_LEN];
        for len in [0usize, 1, 15, 17, 31] {
            assert!(matches!(
                aes256_cbc_decrypt(&key, &iv, &vec![0u8; len]),
                Err(FwknopError::CiphertextNotBlockAligned(_))
            ));
        }
    }

    #[test]
    fn invalid_padding_is_refused() {
        // A block of zeroes decrypts to something whose last byte is almost
        // certainly not a valid PKCS#7 length; assert we surface that rather
        // than returning trailing junk as fwknop would.
        let key = [7u8; KEY_LEN];
        let iv = [3u8; IV_LEN];
        let res = aes256_cbc_decrypt(&key, &iv, &[0u8; 16]);
        assert!(matches!(res, Err(FwknopError::BadPadding)));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hexdec(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }
}
