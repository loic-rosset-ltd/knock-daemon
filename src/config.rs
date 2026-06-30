//! TOML configuration and conversion into runtime types.
//!
//! A knockd-compatible `.conf` parser is planned (see DESIGN.md); for now the
//! native format is TOML, which maps cleanly onto serde.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::firewall::{Action, FirewallKind, NftSet};
use crate::matcher::{DoorSpec, PortSpec, Proto};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Network interface to capture on, e.g. "eth0". `None` = capture-layer default.
    pub interface: Option<String>,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(rename = "door", default)]
    pub doors: Vec<DoorConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct FirewallConfig {
    /// "command" (knockd-compatible, default) or "nftables" (planned).
    #[serde(default = "default_backend")]
    pub backend: String,
}

fn default_backend() -> String {
    "command".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DoorConfig {
    pub name: String,
    /// Steps like "7000/tcp", "8000/udp". Bare numbers default to tcp.
    pub sequence: Vec<String>,
    /// Whole-sequence timeout, e.g. "10s", "500ms". Defaults to 15s.
    #[serde(default = "default_seq_timeout")]
    pub seq_timeout: String,
    /// `command` backend: shell command run on a successful knock; `%IP%` is
    /// replaced with the source. Required when the firewall backend is `command`.
    pub open_command: Option<String>,
    /// `command` backend: optional command to undo the open (run after
    /// `cmd_timeout`, if set).
    pub close_command: Option<String>,
    /// `nftables` backend: the allow-set the source is added to, e.g.
    /// "inet filter knock_clients". Required when the backend is `nftables`.
    pub nft_set: Option<String>,
    /// Optional auto-close delay, e.g. "30s". For `command` this schedules
    /// `close_command`; for `nftables` it becomes the element's kernel timeout.
    pub cmd_timeout: Option<String>,
}

fn default_seq_timeout() -> String {
    "15s".to_string()
}

/// A door plus its resolved action, ready for the runtime to wire up.
#[derive(Debug, Clone)]
pub struct ResolvedDoor {
    pub spec: DoorSpec,
    pub action: Action,
}

impl Config {
    pub fn firewall_kind(&self) -> Result<FirewallKind> {
        match self.firewall.backend.as_str() {
            "command" => Ok(FirewallKind::Command),
            "nftables" => Ok(FirewallKind::Nftables),
            other => bail!("unknown firewall backend {other:?} (expected \"command\" or \"nftables\")"),
        }
    }

    /// Validate and lower the parsed config into runtime doors, checking that
    /// each door carries the fields the active firewall backend needs.
    pub fn resolve(&self, kind: FirewallKind) -> Result<Vec<ResolvedDoor>> {
        if self.doors.is_empty() {
            bail!("config defines no [[door]] sections");
        }
        self.doors.iter().map(|d| d.resolve(kind)).collect()
    }
}

impl DoorConfig {
    fn resolve(&self, kind: FirewallKind) -> Result<ResolvedDoor> {
        if self.sequence.is_empty() {
            bail!("door {:?} has an empty sequence", self.name);
        }
        let sequence = self
            .sequence
            .iter()
            .map(|s| parse_port_spec(s))
            .collect::<Result<Vec<_>>>()
            .with_context(|| format!("door {:?}", self.name))?;

        let timeout_ms = self
            .cmd_timeout
            .as_deref()
            .map(parse_duration_ms)
            .transpose()
            .with_context(|| format!("door {:?} cmd_timeout", self.name))?;

        let nft_set = self
            .nft_set
            .as_deref()
            .map(NftSet::parse)
            .transpose()
            .with_context(|| format!("door {:?}", self.name))?;

        // Backend-specific requirements: a door must carry what its backend acts on.
        match kind {
            FirewallKind::Command if self.open_command.is_none() => {
                bail!("door {:?}: command backend requires open_command", self.name)
            }
            FirewallKind::Nftables if nft_set.is_none() => {
                bail!("door {:?}: nftables backend requires nft_set", self.name)
            }
            _ => {}
        }

        Ok(ResolvedDoor {
            spec: DoorSpec {
                name: self.name.clone(),
                sequence,
                seq_timeout_ms: parse_duration_ms(&self.seq_timeout)
                    .with_context(|| format!("door {:?} seq_timeout", self.name))?,
            },
            action: Action {
                open_command: self.open_command.clone(),
                close_command: self.close_command.clone(),
                nft_set,
                timeout_ms,
            },
        })
    }
}

/// Parse "7000/tcp", "8000/udp", or bare "7000" (defaults to tcp).
fn parse_port_spec(s: &str) -> Result<PortSpec> {
    let (port_str, proto) = match s.split_once('/') {
        Some((p, "tcp")) => (p, Proto::Tcp),
        Some((p, "udp")) => (p, Proto::Udp),
        Some((_, other)) => bail!("invalid protocol {other:?} in step {s:?} (use tcp or udp)"),
        None => (s, Proto::Tcp),
    };
    let port: u16 = port_str
        .trim()
        .parse()
        .with_context(|| format!("invalid port in step {s:?}"))?;
    if port == 0 {
        bail!("port 0 is not valid in step {s:?}");
    }
    Ok(PortSpec { port, proto })
}

/// Parse a tiny duration grammar: "<n>ms", "<n>s", "<n>m", or bare "<n>" (seconds).
fn parse_duration_ms(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else {
        (s, 1_000)
    };
    let value: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid duration {s:?}"))?;
    Ok(value * mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port_specs() {
        assert_eq!(parse_port_spec("7000").unwrap(), PortSpec { port: 7000, proto: Proto::Tcp });
        assert_eq!(parse_port_spec("80/tcp").unwrap(), PortSpec { port: 80, proto: Proto::Tcp });
        assert_eq!(parse_port_spec("53/udp").unwrap(), PortSpec { port: 53, proto: Proto::Udp });
        assert!(parse_port_spec("0").is_err());
        assert!(parse_port_spec("99/sctp").is_err());
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration_ms("500ms").unwrap(), 500);
        assert_eq!(parse_duration_ms("10s").unwrap(), 10_000);
        assert_eq!(parse_duration_ms("2m").unwrap(), 120_000);
        assert_eq!(parse_duration_ms("15").unwrap(), 15_000);
        assert!(parse_duration_ms("soon").is_err());
    }

    #[test]
    fn resolves_a_full_config() {
        let toml = r#"
            interface = "eth0"
            [firewall]
            backend = "command"
            [[door]]
            name = "ssh"
            sequence = ["7000/tcp", "8000/udp", "9000/tcp"]
            seq_timeout = "10s"
            open_command = "nft add element inet filter knock { %IP% }"
            cmd_timeout = "30s"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let kind = cfg.firewall_kind().unwrap();
        let doors = cfg.resolve(kind).unwrap();
        assert_eq!(doors.len(), 1);
        assert_eq!(doors[0].spec.sequence.len(), 3);
        assert_eq!(doors[0].spec.seq_timeout_ms, 10_000);
        assert_eq!(doors[0].action.timeout_ms, Some(30_000));
        assert_eq!(doors[0].spec.sequence[1].proto, Proto::Udp);
    }

    #[test]
    fn nftables_door_resolves_with_an_nft_set() {
        let toml = r#"
            [firewall]
            backend = "nftables"
            [[door]]
            name = "ssh"
            sequence = ["7000/tcp", "8000/tcp"]
            nft_set = "inet filter knock_clients"
            cmd_timeout = "30s"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let kind = cfg.firewall_kind().unwrap();
        let doors = cfg.resolve(kind).unwrap();
        let set = doors[0].action.nft_set.as_ref().unwrap();
        assert_eq!(set.set, "knock_clients");
        assert_eq!(doors[0].action.timeout_ms, Some(30_000));
    }

    #[test]
    fn backend_specific_fields_are_required() {
        // command backend without open_command
        let toml = r#"
            [[door]]
            name = "ssh"
            sequence = ["7000/tcp"]
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.resolve(FirewallKind::Command).is_err());

        // nftables backend without nft_set
        let toml = r#"
            [firewall]
            backend = "nftables"
            [[door]]
            name = "ssh"
            sequence = ["7000/tcp"]
            open_command = "true"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.resolve(FirewallKind::Nftables).is_err());
    }
}
