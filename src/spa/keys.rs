//! Loading SPA key material from disk, server side.
//!
//! The formats here are the exact counterpart of what `knock keygen` writes, so
//! the two halves interoperate without a translation step. Tags are checked, not
//! guessed: feeding a private key where a public one belongs is rejected rather
//! than silently producing a daemon nobody can knock.
//!
//! ```text
//! knock-x25519        <64 hex>            server static public  (given to clients)
//! knock-x25519-secret <64 hex>            server static secret  (stays here)
//! knock-ed25519       <64 hex> <comment>  a client identity, authorized_keys style
//! knock-ed25519-secret <64 hex>           a client secret       (never on a server)
//! ```
//!
//! The `authorized_keys` shape is deliberate: it is the model operators already
//! understand from SSH, and it is what makes a fleet cheap — one client identity,
//! N servers each holding its public key, nothing per-pair, and a stolen server
//! config authorises nothing because it contains only public keys.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

pub const TAG_ID_PUB: &str = "knock-ed25519";
pub const TAG_ID_SECRET: &str = "knock-ed25519-secret";
pub const TAG_SRV_PUB: &str = "knock-x25519";
pub const TAG_SRV_SECRET: &str = "knock-x25519-secret";

/// One entry from an `authorized_keys` file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedKey {
    pub public: [u8; 32],
    /// Free-text trailing comment, used only in logs so an accepted knock can be
    /// attributed to a person rather than to 32 bytes of hex.
    pub comment: String,
}

pub fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        bail!("expected 64 hex characters, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("invalid hex at character {}", i * 2))?;
    }
    Ok(out)
}

pub fn encode_hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse a single tagged key line. A wrong tag is an error, which is what stops
/// a secret being pasted where a public key was meant.
fn parse_tagged(line: &str, want: &str) -> Result<([u8; 32], String)> {
    let mut parts = line.split_whitespace();
    let tag = parts.next().ok_or_else(|| anyhow!("empty key line"))?;
    if tag != want {
        // Installing a *secret* where a public key belongs is the dangerous
        // direction of this mistake, so name it explicitly rather than leaving
        // the operator to compare two similar-looking tags.
        if tag == TAG_ID_SECRET || tag == TAG_SRV_SECRET {
            bail!(
                "expected a `{want}` line but found `{tag}`, which is a PRIVATE key. \
                 Publish the matching public key instead; a private key must never \
                 be copied to a server."
            );
        }
        bail!("expected a `{want}` line, found `{tag}`");
    }
    let hex = parts
        .next()
        .ok_or_else(|| anyhow!("`{want}` line has no key"))?;
    let key = decode_hex32(hex).with_context(|| format!("in `{want}` line"))?;
    let comment = parts.collect::<Vec<_>>().join(" ");
    Ok((key, comment))
}

/// Skip blank lines and `#` comments; yield the rest.
fn significant_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Read the server's X25519 static secret.
pub fn load_static_secret(path: &Path) -> Result<[u8; 32]> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading SPA static key {}", path.display()))?;
    let (line_no, line) = significant_lines(&text)
        .next()
        .ok_or_else(|| anyhow!("{} contains no key", path.display()))?;
    let (key, _) = parse_tagged(line, TAG_SRV_SECRET)
        .with_context(|| format!("{}:{}", path.display(), line_no))?;
    Ok(key)
}

/// Read an `authorized_keys` file of client identities.
///
/// An empty or all-comment file is *not* an error here — it is a valid "nobody
/// is authorised yet" state, and `SpaVerifier` fails closed on it. Refusing to
/// start would be worse: it would push operators toward leaving public-key mode
/// off entirely.
pub fn load_authorized_keys(path: &Path) -> Result<Vec<AuthorizedKey>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading SPA authorized_keys {}", path.display()))?;
    let mut out = Vec::new();
    for (line_no, line) in significant_lines(&text) {
        let (public, comment) = parse_tagged(line, TAG_ID_PUB)
            .with_context(|| format!("{}:{}", path.display(), line_no))?;
        if out.iter().any(|k: &AuthorizedKey| k.public == public) {
            tracing::warn!(
                file = %path.display(),
                line = line_no,
                "duplicate authorized key ignored"
            );
            continue;
        }
        out.push(AuthorizedKey { public, comment });
    }
    Ok(out)
}

/// Read a passphrase for PSK mode. The whole file minus a trailing newline is
/// the passphrase, so a passphrase may contain spaces; only the final newline
/// that every editor adds is stripped.
pub fn load_passphrase(path: &Path) -> Result<Vec<u8>> {
    let raw =
        fs::read(path).with_context(|| format!("reading SPA passphrase {}", path.display()))?;
    let trimmed = raw
        .strip_suffix(b"\n")
        .unwrap_or(&raw)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| raw.strip_suffix(b"\n").unwrap_or(&raw));
    if trimmed.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(trimmed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write a temp file in the scratch dir cargo gives each test run.
    fn tmp(name: &str, contents: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("knockd2-keys-test-{name}"));
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        p
    }

    const HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    #[test]
    fn hex_round_trips() {
        let k = [7u8; 32];
        assert_eq!(encode_hex32(&k), HEX);
        assert_eq!(decode_hex32(HEX).unwrap(), k);
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        assert!(decode_hex32("abcd").is_err());
        assert!(decode_hex32(&"z".repeat(64)).is_err());
    }

    /// The tag check is the thing that stops a secret being installed where a
    /// public key belongs, so it gets its own test.
    #[test]
    fn a_secret_is_refused_where_a_public_key_is_expected() {
        let line = format!("{TAG_ID_SECRET} {HEX}");
        let err = parse_tagged(&line, TAG_ID_PUB).unwrap_err().to_string();
        assert!(err.contains(TAG_ID_PUB), "unhelpful error: {err}");
        assert!(err.contains(TAG_ID_SECRET), "unhelpful error: {err}");
    }

    #[test]
    fn loads_authorized_keys_with_comments_and_blank_lines() {
        let p = tmp(
            "authorized",
            &format!(
                "# fleet keys\n\n{TAG_ID_PUB} {HEX} laptop\n{TAG_ID_PUB} {} phone\n",
                encode_hex32(&[9u8; 32])
            ),
        );
        let keys = load_authorized_keys(&p).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].public, [7u8; 32]);
        assert_eq!(keys[0].comment, "laptop");
        assert_eq!(keys[1].comment, "phone");
    }

    /// Fail closed, but start: an empty file means nobody is authorised, which
    /// `SpaVerifier` already treats as authorising nothing.
    #[test]
    fn an_empty_authorized_keys_file_is_not_an_error() {
        let p = tmp("empty", "# nothing yet\n\n");
        assert!(load_authorized_keys(&p).unwrap().is_empty());
    }

    #[test]
    fn a_bad_line_names_the_file_and_line_number() {
        let p = tmp("bad", &format!("{TAG_ID_PUB} {HEX} ok\nnonsense here\n"));
        let err = format!("{:#}", load_authorized_keys(&p).unwrap_err());
        assert!(err.contains(":2"), "error should name line 2: {err}");
    }

    #[test]
    fn loads_the_static_secret_and_refuses_the_public_half() {
        let p = tmp("secret", &format!("{TAG_SRV_SECRET} {HEX}\n"));
        assert_eq!(load_static_secret(&p).unwrap(), [7u8; 32]);

        let p = tmp("pubhalf", &format!("{TAG_SRV_PUB} {HEX}\n"));
        assert!(load_static_secret(&p).is_err());
    }

    #[test]
    fn passphrase_keeps_spaces_and_strips_one_trailing_newline() {
        let p = tmp("pass", "correct horse battery staple\n");
        assert_eq!(
            load_passphrase(&p).unwrap(),
            b"correct horse battery staple".to_vec()
        );
        let p = tmp("pass2", "no-newline");
        assert_eq!(load_passphrase(&p).unwrap(), b"no-newline".to_vec());
        let p = tmp("pass3", "\n");
        assert!(load_passphrase(&p).is_err());
    }

    #[test]
    fn duplicate_authorized_keys_are_deduplicated() {
        let p = tmp(
            "dupes",
            &format!("{TAG_ID_PUB} {HEX} a\n{TAG_ID_PUB} {HEX} b\n"),
        );
        assert_eq!(load_authorized_keys(&p).unwrap().len(), 1);
    }
}
