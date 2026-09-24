//! The inner, encrypted payload: what the client is actually asking for.
//!
//! ```text
//!   packet_id   16  random, the replay token
//!   timestamp    8  u64 BE, unix seconds
//!   duration     4  u32 BE, seconds of access requested (0 = server default)
//!   addr_kind    1  0 = "use the source address you observed", 4 = IPv4, 6 = IPv6
//!   addr      0/4/16
//!   door_len     1
//!   door   door_len  UTF-8 door name
//!   -- public-key mode only --
//!   client_pub  32  Ed25519 identity of the sender
//!   signature   64  Ed25519 over every preceding byte of this payload
//! ```
//!
//! `addr_kind = 0` is the default and the safest option: the server authorises
//! the source address it actually saw, so a captured packet cannot be used to
//! open a door for somebody else's address. An explicit address is supported
//! because a client behind a NAT it cannot predict sometimes needs it, and
//! because fwknop supports it — but it widens what a stolen packet can do, so
//! `SPA-DESIGN.md` records it as opt-in.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{replay::PacketId, SpaError};

/// Hard limit on a door name. Keeps a hostile payload from forcing a large
/// allocation, and no real door name approaches it.
pub const MAX_DOOR_LEN: usize = 64;

const SIG_LEN: usize = 64;
const PUB_LEN: usize = 32;

/// A decrypted, structurally valid request. Still unauthorised: the caller must
/// check the replay guard and, in public-key mode, the signature and the
/// authorised-key set.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpaPayload {
    pub packet_id: PacketId,
    pub timestamp: u64,
    pub duration_secs: u32,
    /// `None` means "authorise the observed source address".
    pub addr: Option<IpAddr>,
    pub door: String,
    /// Present in public-key mode only.
    pub client_pub: Option<[u8; PUB_LEN]>,
    /// Present in public-key mode only.
    pub signature: Option<[u8; SIG_LEN]>,
}

impl SpaPayload {
    /// The bytes an Ed25519 signature covers: everything before the signature
    /// itself, including the client's own public key.
    pub fn signed_region(&self) -> Result<Vec<u8>, SpaError> {
        let mut out = self.encode_unsigned()?;
        if let Some(pk) = self.client_pub {
            out.extend_from_slice(&pk);
        }
        Ok(out)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, SpaError> {
        let door = self.door.as_bytes();
        if door.is_empty() || door.len() > MAX_DOOR_LEN {
            return Err(SpaError::BadDoorName);
        }
        let mut out = Vec::with_capacity(32 + door.len());
        out.extend_from_slice(&self.packet_id);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.duration_secs.to_be_bytes());
        match self.addr {
            None => out.push(0),
            Some(IpAddr::V4(v4)) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            Some(IpAddr::V6(v6)) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.push(door.len() as u8);
        out.extend_from_slice(door);
        Ok(out)
    }

    /// Serialise for sealing. `signature` must already be set in public-key mode.
    pub fn encode(&self) -> Result<Vec<u8>, SpaError> {
        let mut out = self.signed_region()?;
        if self.client_pub.is_some() {
            let sig = self.signature.ok_or(SpaError::MissingSignature)?;
            out.extend_from_slice(&sig);
        }
        Ok(out)
    }

    /// Parse a decrypted payload. `expect_signed` comes from the packet mode,
    /// which is authenticated as AAD, so it cannot be flipped by an attacker.
    pub fn decode(buf: &[u8], expect_signed: bool) -> Result<Self, SpaError> {
        let mut r = Reader { buf, at: 0 };

        let packet_id: PacketId = r.array::<16>()?;
        let timestamp = u64::from_be_bytes(r.array::<8>()?);
        let duration_secs = u32::from_be_bytes(r.array::<4>()?);

        let addr = match r.byte()? {
            0 => None,
            4 => Some(IpAddr::V4(Ipv4Addr::from(r.array::<4>()?))),
            6 => Some(IpAddr::V6(Ipv6Addr::from(r.array::<16>()?))),
            other => return Err(SpaError::BadAddrKind(other)),
        };

        let door_len = r.byte()? as usize;
        if door_len == 0 || door_len > MAX_DOOR_LEN {
            return Err(SpaError::BadDoorName);
        }
        let door = std::str::from_utf8(r.take(door_len)?)
            .map_err(|_| SpaError::BadDoorName)?
            .to_string();

        let (client_pub, signature) = if expect_signed {
            let pk: [u8; PUB_LEN] = r.array::<PUB_LEN>()?;
            let sig: [u8; SIG_LEN] = r.array::<SIG_LEN>()?;
            (Some(pk), Some(sig))
        } else {
            (None, None)
        };

        if !r.is_empty() {
            return Err(SpaError::TrailingBytes(r.remaining()));
        }

        Ok(SpaPayload {
            packet_id,
            timestamp,
            duration_secs,
            addr,
            door,
            client_pub,
            signature,
        })
    }
}

/// Bounds-checked cursor. Every read goes through this so a truncated payload
/// is an error rather than a panic.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SpaError> {
        let end = self.at.checked_add(n).ok_or(SpaError::Truncated)?;
        if end > self.buf.len() {
            return Err(SpaError::Truncated);
        }
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SpaError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    fn byte(&mut self) -> Result<u8, SpaError> {
        Ok(self.take(1)?[0])
    }

    fn is_empty(&self) -> bool {
        self.at >= self.buf.len()
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SpaPayload {
        SpaPayload {
            packet_id: [3u8; 16],
            timestamp: 1_700_000_000,
            duration_secs: 30,
            addr: None,
            door: "ssh".to_string(),
            client_pub: None,
            signature: None,
        }
    }

    #[test]
    fn round_trips_an_unsigned_payload() {
        let p = base();
        let enc = p.encode().unwrap();
        assert_eq!(SpaPayload::decode(&enc, false).unwrap(), p);
    }

    #[test]
    fn round_trips_both_address_families_and_the_default() {
        for addr in [
            None,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            Some("2001:db8::1".parse::<IpAddr>().unwrap()),
        ] {
            let p = SpaPayload { addr, ..base() };
            let enc = p.encode().unwrap();
            assert_eq!(SpaPayload::decode(&enc, false).unwrap(), p, "addr {addr:?}");
        }
    }

    #[test]
    fn round_trips_a_signed_payload() {
        let p = SpaPayload {
            client_pub: Some([9u8; 32]),
            signature: Some([1u8; 64]),
            ..base()
        };
        let enc = p.encode().unwrap();
        assert_eq!(SpaPayload::decode(&enc, true).unwrap(), p);
    }

    /// The signature must cover the client's public key, otherwise an attacker
    /// could keep a valid signature and substitute their own identity.
    #[test]
    fn signed_region_covers_the_client_public_key() {
        let p = SpaPayload {
            client_pub: Some([9u8; 32]),
            signature: Some([1u8; 64]),
            ..base()
        };
        let region = p.signed_region().unwrap();
        assert!(region.ends_with(&[9u8; 32]));

        let other = SpaPayload {
            client_pub: Some([8u8; 32]),
            ..p.clone()
        };
        assert_ne!(region, other.signed_region().unwrap());
    }

    /// The signature itself must NOT be inside the region it signs.
    #[test]
    fn signed_region_excludes_the_signature() {
        let p = SpaPayload {
            client_pub: Some([9u8; 32]),
            signature: Some([1u8; 64]),
            ..base()
        };
        assert_eq!(p.encode().unwrap().len(), p.signed_region().unwrap().len() + 64);
    }

    /// Truncation at every possible offset must produce an error, never a panic
    /// and never a partly-populated request.
    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let p = SpaPayload {
            client_pub: Some([9u8; 32]),
            signature: Some([1u8; 64]),
            ..base()
        };
        let enc = p.encode().unwrap();
        for cut in 0..enc.len() {
            assert!(
                SpaPayload::decode(&enc[..cut], true).is_err(),
                "truncation at {cut} should not decode"
            );
        }
        assert!(SpaPayload::decode(&enc, true).is_ok());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut enc = base().encode().unwrap();
        enc.push(0);
        assert!(matches!(
            SpaPayload::decode(&enc, false),
            Err(SpaError::TrailingBytes(1))
        ));
    }

    #[test]
    fn rejects_empty_oversized_and_non_utf8_door_names() {
        let p = SpaPayload { door: String::new(), ..base() };
        assert!(matches!(p.encode(), Err(SpaError::BadDoorName)));

        let p = SpaPayload { door: "x".repeat(MAX_DOOR_LEN + 1), ..base() };
        assert!(matches!(p.encode(), Err(SpaError::BadDoorName)));

        // Hand-build a payload whose door bytes are not valid UTF-8.
        let mut enc = base().encode().unwrap();
        let n = enc.len();
        enc[n - 3..].copy_from_slice(&[0xff, 0xfe, 0xfd]);
        assert!(matches!(
            SpaPayload::decode(&enc, false),
            Err(SpaError::BadDoorName)
        ));
    }

    #[test]
    fn rejects_an_unknown_address_kind() {
        let mut enc = base().encode().unwrap();
        enc[28] = 7; // the addr_kind byte
        assert!(matches!(
            SpaPayload::decode(&enc, false),
            Err(SpaError::BadAddrKind(7))
        ));
    }
}
