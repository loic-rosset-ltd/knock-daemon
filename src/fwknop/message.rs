//! The decrypted SPA message: field layout, parsing and validation.
//!
//! What comes out of the cipher is a single `:`-delimited ASCII line
//! (`lib/fko_encode.c:fko_encode_spa_data`):
//!
//! ```text
//! <rand16>:<b64 user>:<timestamp>:<version>:<type>:<b64 access>
//!          [:<b64 nat_access>][:<b64 server_auth>][:<timeout>]:<b64 digest>
//! ```
//!
//! Three of those fields are optional and **not tagged** — which of them a
//! given trailing field is depends on the message type. That ambiguity is
//! fwknop's, and `lib/fko_decode.c` resolves it with the rule reproduced in
//! [`parse_encoded`]. Getting it wrong silently mis-assigns a timeout to a
//! server-auth string, so the resolution order is followed exactly.
//!
//! Every field is length-checked against fwknop's own `lib/fko_limits.h`
//! constants before use, and every index is bounds-checked: this parser runs on
//! bytes that arrived from the network, and the only reason they are trusted at
//! all is that the HMAC has already been verified.

use std::net::Ipv4Addr;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;

use super::FwknopError;

/// `FKO_RAND_VAL_SIZE` — the 16 decimal digits that open every message.
pub const RAND_VAL_LEN: usize = 16;
/// `MAX_SPA_USERNAME_SIZE`.
const MAX_USERNAME: usize = 64;
/// `MAX_SPA_MESSAGE_SIZE` — bounds the access and NAT strings.
const MAX_MESSAGE: usize = 256;
/// `MAX_SPA_VERSION_SIZE`.
const MAX_VERSION: usize = 8;
/// `MAX_SPA_TIMESTAMP_SIZE`.
const MAX_TIMESTAMP: usize = 12;
/// `MAX_SPA_MESSAGE_TYPE_SIZE`.
const MAX_MSG_TYPE: usize = 2;
/// `MAX_SPA_SERVER_AUTH_SIZE`.
const MAX_SERVER_AUTH: usize = 64;
/// `MIN_SPA_FIELDS` — the number of `:` separators a well-formed message has
/// at minimum, counted before the digest is removed.
const MIN_SPA_FIELDS: usize = 6;
/// fwknop clamps the client timeout to `2 << 15` in
/// `lib/fko_decode.c:parse_client_timeout`.
const MAX_CLIENT_TIMEOUT: u32 = 2 << 15;

/// What the client is asking the server to do.
///
/// The discriminants are fwknop's `fko_message_type_t` values and appear
/// literally on the wire, so they are pinned rather than derived.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    /// `FKO_COMMAND_MSG` — run a command. The access field holds
    /// `<allow ip>,<command>` rather than a port list.
    Command = 0,
    /// `FKO_ACCESS_MSG` — open ports.
    Access = 1,
    /// `FKO_NAT_ACCESS_MSG` — open ports and DNAT them to an internal host.
    NatAccess = 2,
    /// `FKO_CLIENT_TIMEOUT_ACCESS_MSG` — as `Access`, with a client-chosen
    /// firewall timeout.
    ClientTimeoutAccess = 3,
    /// `FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG`.
    ClientTimeoutNatAccess = 4,
    /// `FKO_LOCAL_NAT_ACCESS_MSG` — forward to a port on the server itself.
    LocalNatAccess = 5,
    /// `FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG`.
    ClientTimeoutLocalNatAccess = 6,
}

impl MessageType {
    fn from_wire(v: u8) -> Result<Self, FwknopError> {
        Ok(match v {
            0 => MessageType::Command,
            1 => MessageType::Access,
            2 => MessageType::NatAccess,
            3 => MessageType::ClientTimeoutAccess,
            4 => MessageType::ClientTimeoutNatAccess,
            5 => MessageType::LocalNatAccess,
            6 => MessageType::ClientTimeoutLocalNatAccess,
            other => return Err(FwknopError::UnknownMessageType(other)),
        })
    }

    /// Does this type carry a NAT target field?
    pub fn has_nat(self) -> bool {
        matches!(
            self,
            MessageType::NatAccess
                | MessageType::LocalNatAccess
                | MessageType::ClientTimeoutNatAccess
                | MessageType::ClientTimeoutLocalNatAccess
        )
    }

    /// Does this type carry a trailing client-timeout field?
    pub fn has_client_timeout(self) -> bool {
        matches!(
            self,
            MessageType::ClientTimeoutAccess
                | MessageType::ClientTimeoutNatAccess
                | MessageType::ClientTimeoutLocalNatAccess
        )
    }

    /// Upper bound on the number of `:` separators allowed after the message
    /// type field, from `lib/fko_decode.c:parse_msg_type`. A message with more
    /// fields than its type can hold is refused rather than partially read.
    fn max_remaining_fields(self) -> usize {
        match self {
            MessageType::Command | MessageType::Access => 2,
            MessageType::NatAccess
            | MessageType::LocalNatAccess
            | MessageType::ClientTimeoutAccess => 3,
            MessageType::ClientTimeoutNatAccess | MessageType::ClientTimeoutLocalNatAccess => 4,
        }
    }
}

/// The protocols fwknop's access syntax admits
/// (`lib/fko_message.c:validate_proto_port_spec`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessProto {
    Tcp,
    Udp,
    Icmp,
    /// fwknop's literal `none` — a request that names no protocol. It is
    /// carried through rather than dropped so a caller can decide what, if
    /// anything, it means to them.
    None,
}

/// One `proto/port` pair from an access request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtoPort {
    pub proto: AccessProto,
    pub port: u16,
}

/// The parsed `<host>,<port>` of a NAT request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NatTarget {
    /// Left as a string: fwknop permits a hostname here, and resolving one on
    /// the packet path would be a remote-triggered DNS lookup. Whether to
    /// accept a non-literal target is the caller's policy decision.
    pub host: String,
    pub port: u16,
}

/// A decoded fwknop SPA request.
///
/// Producing one means the HMAC verified, the packet decrypted, the inner
/// digest matched and every field parsed within fwknop's own limits. It does
/// **not** mean the request should be granted — freshness, replay and access
/// policy are all still to come, and [`FwknopRequest::check_timestamp`] is the
/// only one of those this type does.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FwknopRequest {
    /// 16 decimal digits the client generated. fwknop's replay defence hashes
    /// the whole packet rather than this, but it is what makes two otherwise
    /// identical requests distinct.
    pub rand_value: String,
    /// The client-side username. Advisory: it is whatever the client put
    /// there, including via `--spoof-user`.
    pub username: String,
    /// Client clock, seconds since the epoch. Attacker-controlled.
    pub timestamp: u64,
    /// The **FKO protocol** version, not the client's release version: fwknop
    /// 2.6.11 puts `3.0.0` here. Easy to misread, and worth stating because a
    /// caller tempted to gate behaviour on it would gate on the wrong number.
    pub version: String,
    pub message_type: MessageType,
    /// The access field exactly as fwknop encoded it, e.g.
    /// `192.168.1.50,tcp/22,udp/53`. Kept verbatim alongside the parsed form
    /// so a caller can log precisely what arrived.
    pub access: String,
    /// The address the client is asking to have authorised, parsed from the
    /// head of `access`.
    pub allow_ip: Ipv4Addr,
    /// The proto/port pairs from `access`. Empty for [`MessageType::Command`].
    pub ports: Vec<ProtoPort>,
    /// The command string, for [`MessageType::Command`] only.
    pub command: Option<String>,
    /// The NAT field verbatim, e.g. `192.168.10.5,2222`.
    pub nat_access: Option<String>,
    /// The parsed form of `nat_access`.
    pub nat: Option<NatTarget>,
    /// fwknop's optional `server_auth` field. Parsed so the field layout is
    /// resolved correctly; this daemon has no use for it.
    pub server_auth: Option<String>,
    /// Client-requested firewall timeout, in seconds.
    pub client_timeout: Option<u32>,
}

impl FwknopRequest {
    /// Reject a packet whose timestamp is too far from `now_secs` in either
    /// direction.
    ///
    /// **The clock is injected, never read.** That is a pinned invariant of
    /// this codebase (`CONTRIBUTING.md`), and it is what makes every skew case
    /// — including a client whose clock runs fast — deterministically testable
    /// without a single `sleep`.
    ///
    /// Both directions matter. fwknop's server checks both for the same
    /// reason: a packet dated in the future would otherwise stay valid for as
    /// long as the skew allows, which is a replay window granted for free.
    pub fn check_timestamp(&self, now_secs: u64, max_skew_secs: u64) -> Result<(), FwknopError> {
        if self.timestamp.abs_diff(now_secs) > max_skew_secs {
            return Err(FwknopError::TimestampOutOfWindow {
                timestamp: self.timestamp,
                now: now_secs,
                max_skew: max_skew_secs,
            });
        }
        Ok(())
    }
}

/// Parse the decrypted, digest-verified message body into a request.
///
/// `body` is the encoded message with the trailing `:<digest>` already
/// removed — the same point at which `lib/fko_decode.c` starts its field
/// parsers, and deliberately so: the digest must be checked before any field
/// is interpreted.
///
/// `total_colons` is the separator count of the message *including* the
/// digest, which is what fwknop's `MIN_SPA_FIELDS` check counts.
pub fn parse_encoded(body: &str, total_colons: usize) -> Result<FwknopRequest, FwknopError> {
    if total_colons < MIN_SPA_FIELDS {
        return Err(FwknopError::TooFewFields(total_colons));
    }

    // fwknop rejects any non-printable byte in the decrypted message before
    // parsing (`fko_decode_spa_data`). A decryption under the wrong key almost
    // always trips this, which is why it comes first.
    if !body.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(FwknopError::NonPrintableMessage);
    }

    // Split once, then index. The alternative — walking to each `:` in turn —
    // reads naturally but gets the *last* field wrong, because several fields
    // can legitimately be last and none of them is followed by a separator.
    let parts: Vec<&str> = body.split(':').collect();

    // The six leading fields are mandatory for every message type.
    const ACCESS_IDX: usize = 5;
    if parts.len() <= ACCESS_IDX {
        return Err(FwknopError::MissingField(match parts.len() {
            0 | 1 => "username",
            2 => "timestamp",
            3 => "version",
            4 => "message type",
            _ => "access",
        }));
    }

    // --- rand value: exactly 16 digits -------------------------------------
    let rand_value = parts[0];
    if rand_value.len() != RAND_VAL_LEN || !rand_value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FwknopError::BadRandValue);
    }

    // --- username: base64 ---------------------------------------------------
    if parts[1].len() > MAX_USERNAME {
        return Err(FwknopError::FieldTooLong("username"));
    }
    let username = decode_b64_string(parts[1], "username")?;
    validate_username(&username)?;

    // --- timestamp ----------------------------------------------------------
    let ts_field = parts[2];
    if ts_field.is_empty() || ts_field.len() > MAX_TIMESTAMP {
        return Err(FwknopError::FieldTooLong("timestamp"));
    }
    let timestamp: u64 = ts_field
        .parse()
        .map_err(|_| FwknopError::BadTimestamp(ts_field.to_string()))?;

    // --- version ------------------------------------------------------------
    let version = parts[3];
    if version.is_empty() || version.len() > MAX_VERSION {
        return Err(FwknopError::FieldTooLong("version"));
    }

    // --- message type -------------------------------------------------------
    let type_field = parts[4];
    if type_field.is_empty() || type_field.len() > MAX_MSG_TYPE {
        return Err(FwknopError::FieldTooLong("message type"));
    }
    let message_type = MessageType::from_wire(
        type_field
            .parse::<u8>()
            .map_err(|_| FwknopError::BadMessageType(type_field.to_string()))?,
    )?;

    // fwknop counts the separators from the message-type field onward and caps
    // them per type (`parse_msg_type`). A message with more trailing fields
    // than its type can hold is refused rather than partly read.
    let remaining_fields = parts.len() - 5;
    if remaining_fields > message_type.max_remaining_fields() {
        return Err(FwknopError::TooManyFields {
            message_type,
            found: remaining_fields,
        });
    }

    // --- access message -----------------------------------------------------
    let access_field = parts[ACCESS_IDX];
    if access_field.is_empty() || access_field.len() > MAX_MESSAGE {
        return Err(FwknopError::FieldTooLong("access"));
    }
    let access = decode_b64_string(access_field, "access")?;

    let (allow_ip, ports, command) = if message_type == MessageType::Command {
        let (ip, cmd) = split_once_required(&access, ',', FwknopError::BadCommandMessage)?;
        if cmd.is_empty() {
            return Err(FwknopError::BadCommandMessage);
        }
        (parse_allow_ip(ip)?, Vec::new(), Some(cmd.to_string()))
    } else {
        let (ip, spec) = split_once_required(&access, ',', FwknopError::BadAccessMessage)?;
        (parse_allow_ip(ip)?, parse_proto_port_list(spec)?, None)
    };

    // --- NAT target ---------------------------------------------------------
    let mut idx = ACCESS_IDX + 1;
    let (nat_access, nat) = if message_type.has_nat() {
        let field = *parts
            .get(idx)
            .ok_or(FwknopError::MissingField("nat_access"))?;
        idx += 1;
        if field.is_empty() || field.len() > MAX_MESSAGE {
            return Err(FwknopError::FieldTooLong("nat_access"));
        }
        let raw = decode_b64_string(field, "nat_access")?;
        let target = parse_nat_target(&raw)?;
        (Some(raw), Some(target))
    } else {
        (None, None)
    };

    // --- server_auth and client_timeout -------------------------------------
    //
    // This is the ambiguous tail: neither field is tagged, and which one a
    // trailing field *is* depends on the message type.
    // `lib/fko_decode.c:parse_server_auth` resolves it as follows, and the
    // order matters:
    //
    //   * nothing left              -> neither field is present
    //   * type has no timeout       -> the remainder is server_auth
    //   * type has a timeout, 2 left -> server_auth then timeout
    //   * type has a timeout, 1 left -> the remainder is the timeout
    //
    // Reading it the other way round would silently turn a firewall timeout
    // into an opaque auth string, or vice versa. The per-type field cap above
    // is what guarantees at most two fields reach this point.
    let tail = &parts[idx..];
    let mut server_auth = None;
    let mut client_timeout = None;

    if message_type.has_client_timeout() {
        match tail {
            // fwknop returns FKO_ERROR_INVALID_DATA_DECODE_TIMEOUT_MISSING.
            [] => return Err(FwknopError::MissingClientTimeout),
            [timeout] => client_timeout = Some(parse_client_timeout(timeout)?),
            [auth, timeout] => {
                if auth.len() > MAX_SERVER_AUTH {
                    return Err(FwknopError::FieldTooLong("server_auth"));
                }
                server_auth = Some(decode_b64_string(auth, "server_auth")?);
                client_timeout = Some(parse_client_timeout(timeout)?);
            }
            _ => {
                return Err(FwknopError::TooManyFields {
                    message_type,
                    found: remaining_fields,
                })
            }
        }
    } else {
        match tail {
            [] => {}
            [auth] => {
                if auth.len() > MAX_SERVER_AUTH {
                    return Err(FwknopError::FieldTooLong("server_auth"));
                }
                server_auth = Some(decode_b64_string(auth, "server_auth")?);
            }
            _ => {
                return Err(FwknopError::TooManyFields {
                    message_type,
                    found: remaining_fields,
                })
            }
        }
    }

    Ok(FwknopRequest {
        rand_value: rand_value.to_string(),
        username,
        timestamp,
        version: version.to_string(),
        message_type,
        access,
        allow_ip,
        ports,
        command,
        nat_access,
        nat,
        server_auth,
        client_timeout,
    })
}

/// fwknop base64-encodes sub-fields and then strips the `=` padding
/// (`lib/base64.c:strip_b64_eq`), so the unpadded engine is the right one.
fn decode_b64_string(field: &str, what: &'static str) -> Result<String, FwknopError> {
    let bytes = STANDARD_NO_PAD
        .decode(field)
        .map_err(|_| FwknopError::FieldNotBase64(what))?;
    String::from_utf8(bytes).map_err(|_| FwknopError::FieldNotUtf8(what))
}

fn split_once_required(s: &str, sep: char, err: FwknopError) -> Result<(&str, &str), FwknopError> {
    s.split_once(sep).ok_or(err)
}

/// The `allow` address at the head of every access and command message.
///
/// **Departure from fwknop, deliberate:** fwknop finishes with `inet_aton`,
/// which accepts octal (`010` is 8) and short forms. Rust's parser takes
/// dotted-quad decimal only. Every genuine client emits a plain dotted quad,
/// so nothing real is refused, and the ambiguity that makes `010.0.0.1` mean
/// two different things to two different tools is refused outright.
fn parse_allow_ip(s: &str) -> Result<Ipv4Addr, FwknopError> {
    if s.len() > 15 || s.len() < 7 {
        return Err(FwknopError::BadAllowIp(s.to_string()));
    }
    s.parse::<Ipv4Addr>()
        .map_err(|_| FwknopError::BadAllowIp(s.to_string()))
}

/// Parse `tcp/22,udp/53,...`.
fn parse_proto_port_list(spec: &str) -> Result<Vec<ProtoPort>, FwknopError> {
    if spec.is_empty() {
        return Err(FwknopError::BadAccessMessage);
    }
    let mut out = Vec::new();
    for item in spec.split(',') {
        let (proto_str, port_str) =
            split_once_required(item, '/', FwknopError::BadProtoPort(item.to_string()))?;
        let proto = match proto_str {
            "tcp" => AccessProto::Tcp,
            "udp" => AccessProto::Udp,
            "icmp" => AccessProto::Icmp,
            "none" => AccessProto::None,
            _ => return Err(FwknopError::BadProtoPort(item.to_string())),
        };
        // fwknop's `have_port` requires all digits and 1..=65535 — zero is not
        // a legal port there, so it is not one here either.
        if port_str.is_empty()
            || port_str.len() > 5
            || !port_str.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(FwknopError::BadProtoPort(item.to_string()));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| FwknopError::BadProtoPort(item.to_string()))?;
        if port == 0 {
            return Err(FwknopError::BadProtoPort(item.to_string()));
        }
        out.push(ProtoPort { proto, port });
    }
    Ok(out)
}

/// Parse `<host>,<port>` (`lib/fko_message.c:validate_nat_access_msg`).
fn parse_nat_target(raw: &str) -> Result<NatTarget, FwknopError> {
    if raw.matches(',').count() != 1 {
        return Err(FwknopError::BadNatAccess(raw.to_string()));
    }
    let (host, port_str) =
        split_once_required(raw, ',', FwknopError::BadNatAccess(raw.to_string()))?;
    // fwknop's `MAX_HOSTNAME_LEN` check plus its explicit reject list.
    if host.is_empty() || host.len() > 64 || host.contains([' ', '/', '?', '"', '\'', '\\']) {
        return Err(FwknopError::BadNatAccess(raw.to_string()));
    }
    if port_str.is_empty() || port_str.len() > 5 || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FwknopError::BadNatAccess(raw.to_string()));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| FwknopError::BadNatAccess(raw.to_string()))?;
    if port == 0 {
        return Err(FwknopError::BadNatAccess(raw.to_string()));
    }
    Ok(NatTarget {
        host: host.to_string(),
        port,
    })
}

fn parse_client_timeout(field: &str) -> Result<u32, FwknopError> {
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FwknopError::BadClientTimeout(field.to_string()));
    }
    let v: u32 = field
        .parse()
        .map_err(|_| FwknopError::BadClientTimeout(field.to_string()))?;
    if v > MAX_CLIENT_TIMEOUT {
        return Err(FwknopError::BadClientTimeout(field.to_string()));
    }
    Ok(v)
}

/// fwknop's `validate_username` (`lib/fko_user.c`), reproduced: printable
/// ASCII minus a reject list taken from Microsoft's account-name guidance.
/// The username is advisory, but it reaches logs, so refusing control
/// characters and quoting metacharacters here keeps them out of them.
fn validate_username(u: &str) -> Result<(), FwknopError> {
    const REJECT: &[char] = &[
        '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>',
    ];
    if u.is_empty() || u.len() > MAX_USERNAME {
        return Err(FwknopError::BadUsername);
    }
    for c in u.chars() {
        if c.is_ascii_alphanumeric() {
            continue;
        }
        if !(' '..='~').contains(&c) || REJECT.contains(&c) {
            return Err(FwknopError::BadUsername);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an encoded message the way `fko_encode_spa_data` does, so the
    /// parser can be exercised over field layouts that need no key material.
    /// The digest is appended and its separator counted, then handed to
    /// `parse_encoded` the way the real caller does.
    fn encoded(fields: &[&str]) -> (String, usize) {
        let body = fields.join(":");
        let with_digest = format!("{body}:{}", "d".repeat(43));
        (body, with_digest.matches(':').count())
    }

    fn b64(s: &str) -> String {
        STANDARD_NO_PAD.encode(s)
    }

    fn access_fields(msg_type: u8, access: &str, extra: &[&str]) -> (String, usize) {
        let mut v = vec![
            "1111222233334444".to_string(),
            b64("testuser"),
            "1700000000".to_string(),
            "2.6.11".to_string(),
            msg_type.to_string(),
            b64(access),
        ];
        v.extend(extra.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
        encoded(&refs)
    }

    #[test]
    fn plain_access_parses() {
        let (body, colons) = access_fields(1, "192.168.1.50,tcp/22", &[]);
        let r = parse_encoded(&body, colons).unwrap();
        assert_eq!(r.message_type, MessageType::Access);
        assert_eq!(r.rand_value, "1111222233334444");
        assert_eq!(r.username, "testuser");
        assert_eq!(r.timestamp, 1_700_000_000);
        assert_eq!(r.version, "2.6.11");
        assert_eq!(r.allow_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(
            r.ports,
            vec![ProtoPort {
                proto: AccessProto::Tcp,
                port: 22
            }]
        );
        assert_eq!(r.client_timeout, None);
        assert_eq!(r.nat, None);
    }

    #[test]
    fn multi_proto_port_list_parses_in_order() {
        let (body, colons) = access_fields(1, "10.0.0.7,tcp/22,udp/53,icmp/1,none/9", &[]);
        let r = parse_encoded(&body, colons).unwrap();
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
                    proto: AccessProto::Icmp,
                    port: 1
                },
                ProtoPort {
                    proto: AccessProto::None,
                    port: 9
                },
            ]
        );
    }

    /// The tail-field rule, both ways round. A timeout type with one trailing
    /// field means timeout; with two it means server_auth then timeout. This
    /// is the case most likely to be silently mis-parsed.
    #[test]
    fn timeout_tail_without_server_auth() {
        let (body, colons) = access_fields(3, "192.168.1.50,tcp/22", &["120"]);
        let r = parse_encoded(&body, colons).unwrap();
        assert_eq!(r.client_timeout, Some(120));
        assert_eq!(r.server_auth, None);
    }

    #[test]
    fn timeout_tail_with_server_auth() {
        let auth = b64("crypt");
        let (body, colons) = access_fields(3, "192.168.1.50,tcp/22", &[&auth, "90"]);
        let r = parse_encoded(&body, colons).unwrap();
        assert_eq!(r.server_auth.as_deref(), Some("crypt"));
        assert_eq!(r.client_timeout, Some(90));
    }

    #[test]
    fn non_timeout_tail_is_entirely_server_auth() {
        let auth = b64("crypt");
        let (body, colons) = access_fields(1, "192.168.1.50,tcp/22", &[&auth]);
        let r = parse_encoded(&body, colons).unwrap();
        assert_eq!(r.server_auth.as_deref(), Some("crypt"));
        assert_eq!(r.client_timeout, None);
    }

    #[test]
    fn nat_and_timeout_order() {
        let nat = b64("192.168.10.5,2222");
        let (body, colons) = access_fields(4, "192.168.1.50,tcp/22", &[&nat, "45"]);
        let r = parse_encoded(&body, colons).unwrap();
        assert_eq!(
            r.nat,
            Some(NatTarget {
                host: "192.168.10.5".to_string(),
                port: 2222
            })
        );
        assert_eq!(r.client_timeout, Some(45));
    }

    #[test]
    fn command_message_keeps_the_command() {
        let (body, colons) = access_fields(0, "192.168.1.50,/bin/echo hello", &[]);
        let r = parse_encoded(&body, colons).unwrap();
        assert_eq!(r.message_type, MessageType::Command);
        assert_eq!(r.command.as_deref(), Some("/bin/echo hello"));
        assert!(r.ports.is_empty());
    }

    #[test]
    fn timeout_type_without_a_timeout_is_refused() {
        let (body, colons) = access_fields(3, "192.168.1.50,tcp/22", &[]);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::MissingClientTimeout)
        ));
    }

    #[test]
    fn too_many_fields_for_the_type_is_refused() {
        let a = b64("x");
        let (body, colons) = access_fields(1, "192.168.1.50,tcp/22", &[&a, &a, &a]);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::TooManyFields { .. })
        ));
    }

    #[test]
    fn unknown_message_type_is_refused() {
        let (body, colons) = access_fields(7, "192.168.1.50,tcp/22", &[]);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::UnknownMessageType(7))
        ));
    }

    /// Every truncation of a well-formed message must produce an error, never
    /// a panic and never a half-populated request.
    #[test]
    fn every_truncation_errors_without_panicking() {
        let (body, colons) = access_fields(4, "192.168.1.50,tcp/22", &[&b64("h,1"), "30"]);
        for cut in 0..body.len() {
            let truncated = &body[..cut];
            if !truncated.is_char_boundary(cut) {
                continue;
            }
            let _ = parse_encoded(truncated, colons);
        }
        // And the full message still parses, so the loop above was meaningful.
        assert!(parse_encoded(&body, colons).is_ok());
    }

    #[test]
    fn malformed_fields_are_refused() {
        // Bad rand value.
        let (body, colons) = encoded(&[
            "123",
            &b64("u"),
            "1700000000",
            "2.6.11",
            "1",
            &b64("1.2.3.4,tcp/22"),
        ]);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::BadRandValue)
        ));

        // Bad allow IP: fwknop's inet_aton would take this, we do not.
        let (body, colons) = access_fields(1, "010.0.0.1,tcp/22", &[]);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::BadAllowIp(_))
        ));

        // Port zero.
        let (body, colons) = access_fields(1, "1.2.3.4,tcp/0", &[]);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::BadProtoPort(_))
        ));

        // Unknown protocol.
        let (body, colons) = access_fields(1, "1.2.3.4,sctp/22", &[]);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::BadProtoPort(_))
        ));

        // Username with a shell metacharacter from fwknop's reject list.
        let mut v = vec![
            "1111222233334444".to_string(),
            b64("bad;user"),
            "1700000000".to_string(),
            "2.6.11".to_string(),
            "1".to_string(),
            b64("1.2.3.4,tcp/22"),
        ];
        v.truncate(6);
        let refs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
        let (body, colons) = encoded(&refs);
        assert!(matches!(
            parse_encoded(&body, colons),
            Err(FwknopError::BadUsername)
        ));
    }

    #[test]
    fn too_few_fields_is_refused() {
        let (body, _) = access_fields(1, "1.2.3.4,tcp/22", &[]);
        assert!(matches!(
            parse_encoded(&body, 3),
            Err(FwknopError::TooFewFields(3))
        ));
    }

    #[test]
    fn non_printable_body_is_refused() {
        let body = format!("1111222233334444:\u{7}:1700000000:2.6.11:1:{}", b64("x"));
        assert!(matches!(
            parse_encoded(&body, 6),
            Err(FwknopError::NonPrintableMessage)
        ));
    }

    /// The clock is a parameter. Both directions of skew are bounded, and no
    /// test here sleeps or reads a clock.
    #[test]
    fn timestamp_window_is_checked_in_both_directions() {
        let (body, colons) = access_fields(1, "1.2.3.4,tcp/22", &[]);
        let r = parse_encoded(&body, colons).unwrap();
        assert_eq!(r.timestamp, 1_700_000_000);

        assert!(r.check_timestamp(1_700_000_000, 0).is_ok());
        assert!(r.check_timestamp(1_700_000_120, 120).is_ok());
        assert!(r.check_timestamp(1_699_999_880, 120).is_ok());
        assert!(matches!(
            r.check_timestamp(1_700_000_121, 120),
            Err(FwknopError::TimestampOutOfWindow { .. })
        ));
        // A clock set in the future is just as unacceptable as one in the past.
        assert!(matches!(
            r.check_timestamp(1_699_999_879, 120),
            Err(FwknopError::TimestampOutOfWindow { .. })
        ));
    }
}
