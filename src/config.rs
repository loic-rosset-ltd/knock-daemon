//! TOML configuration and conversion into runtime types.
//!
//! This is the native format (TOML, mapped onto serde). The legacy knockd
//! `.conf` format is handled by [`crate::knockd`], which lowers onto the same
//! [`Config`]/[`DoorConfig`] types resolved here.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::firewall::{Action, FirewallKind, NftSet};
use crate::matcher::{DoorSpec, MatchMode, PortSpec, Proto};
use crate::ratelimit::RateLimiter;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Network interface to capture on, e.g. "eth0". `None` = capture-layer default.
    pub interface: Option<String>,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub matching: MatchingConfig,
    #[serde(default)]
    pub stats: StatsConfig,
    #[serde(rename = "door", default)]
    pub doors: Vec<DoorConfig>,
}

#[derive(Debug, Deserialize)]
pub struct MatchingConfig {
    /// "tolerant" (default) or "reset" (knockd parity). See [`MatchMode`].
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Number of matcher worker shards. 1 (default) = single-threaded; `0` =
    /// auto-detect from available CPUs. Sources are partitioned by IP across
    /// shards, each driven by its own worker thread.
    #[serde(default = "default_shards")]
    pub shards: usize,
    /// Optional per-source rate limit, `"<count>/<duration>"` (e.g. `"50/10s"` =
    /// a burst of 50 packets per source, refilling at 50 per 10s). `None` =
    /// unlimited. Packets over budget are dropped before matching.
    pub rate_limit: Option<String>,
}

fn default_mode() -> String {
    "tolerant".to_string()
}

fn default_shards() -> usize {
    1
}

impl Default for MatchingConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            shards: default_shards(),
            rate_limit: None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct StatsConfig {
    /// Optional `host:port` to serve Prometheus metrics on (e.g.
    /// `"127.0.0.1:9099"`). `None` disables the endpoint.
    pub listen: Option<String>,
}

/// A parsed rate-limit spec, ready to build a [`RateLimiter`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateSpec {
    /// Burst size (tokens) per source.
    pub capacity: f64,
    /// Sustained refill rate in tokens per millisecond.
    pub refill_per_ms: f64,
}

impl RateSpec {
    /// Build a limiter for this spec, bounding tracked sources at `max_tracked`.
    pub fn build(&self, max_tracked: usize) -> RateLimiter {
        RateLimiter::new(self.capacity, self.refill_per_ms, max_tracked)
    }
}

#[derive(Debug, Deserialize)]
pub struct FirewallConfig {
    /// "command" (knockd-compatible, default) or "nftables".
    #[serde(default = "default_backend")]
    pub backend: String,
}

fn default_backend() -> String {
    "command".to_string()
}

impl Default for FirewallConfig {
    // Hand-written rather than derived so an omitted `[firewall]` section
    // defaults `backend` to "command" — a derived Default would leave it the
    // empty string (serde's field default only fills a missing field of a
    // *present* table, not a missing whole section).
    fn default() -> Self {
        Self {
            backend: default_backend(),
        }
    }
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
            other => {
                bail!("unknown firewall backend {other:?} (expected \"command\" or \"nftables\")")
            }
        }
    }

    pub fn match_mode(&self) -> Result<MatchMode> {
        match self.matching.mode.as_str() {
            "tolerant" => Ok(MatchMode::Tolerant),
            "reset" | "strict" => Ok(MatchMode::Reset),
            other => bail!("unknown matching mode {other:?} (expected \"tolerant\" or \"reset\")"),
        }
    }

    /// Resolve the worker-shard count: the configured value, or — when `0` —
    /// auto-detected from available CPUs. Always at least 1.
    pub fn shard_count(&self) -> usize {
        match self.matching.shards {
            0 => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            n => n,
        }
    }

    /// Parse the optional `[matching] rate_limit` spec into a [`RateSpec`].
    pub fn rate_limit(&self) -> Result<Option<RateSpec>> {
        let Some(raw) = self.matching.rate_limit.as_deref() else {
            return Ok(None);
        };
        Ok(Some(parse_rate(raw).with_context(|| {
            format!("invalid rate_limit {raw:?} (expected \"<count>/<duration>\", e.g. \"50/10s\")")
        })?))
    }

    /// The configured stats endpoint address, if any.
    pub fn stats_listen(&self) -> Option<&str> {
        self.stats.listen.as_deref()
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
                bail!(
                    "door {:?}: command backend requires open_command",
                    self.name
                )
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

/// Parse a `"<count>/<duration>"` rate spec into a [`RateSpec`]. The count is the
/// per-source burst capacity; the sustained refill rate is `count / duration`.
fn parse_rate(s: &str) -> Result<RateSpec> {
    let (count_str, dur_str) = s
        .split_once('/')
        .with_context(|| format!("rate {s:?} is missing the '/' separator"))?;
    let count: u32 = count_str
        .trim()
        .parse()
        .with_context(|| format!("invalid count in rate {s:?}"))?;
    if count == 0 {
        bail!("rate count must be at least 1 in {s:?}");
    }
    let dur_ms = parse_duration_ms(dur_str)?;
    if dur_ms == 0 {
        bail!("rate duration must be non-zero in {s:?}");
    }
    Ok(RateSpec {
        capacity: count as f64,
        refill_per_ms: count as f64 / dur_ms as f64,
    })
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
        assert_eq!(
            parse_port_spec("7000").unwrap(),
            PortSpec {
                port: 7000,
                proto: Proto::Tcp
            }
        );
        assert_eq!(
            parse_port_spec("80/tcp").unwrap(),
            PortSpec {
                port: 80,
                proto: Proto::Tcp
            }
        );
        assert_eq!(
            parse_port_spec("53/udp").unwrap(),
            PortSpec {
                port: 53,
                proto: Proto::Udp
            }
        );
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
    fn parses_rate_limit_spec() {
        // "50/10s" = burst 50, refill 50 tokens / 10000 ms = 0.005 tokens/ms.
        let spec = parse_rate("50/10s").unwrap();
        assert_eq!(spec.capacity, 50.0);
        assert!((spec.refill_per_ms - 0.005).abs() < 1e-9);
        // Bad forms are rejected.
        assert!(parse_rate("50").is_err()); // no separator
        assert!(parse_rate("0/10s").is_err()); // zero count
        assert!(parse_rate("10/soon").is_err()); // bad duration
    }

    #[test]
    fn matching_section_defaults_and_overrides() {
        // Defaults: 1 shard, no rate limit, no stats endpoint.
        let cfg: Config = toml::from_str("interface = \"eth0\"").unwrap();
        assert_eq!(cfg.shard_count(), 1);
        assert!(cfg.rate_limit().unwrap().is_none());
        assert!(cfg.stats_listen().is_none());

        // Explicit overrides round-trip through the accessors.
        let toml = r#"
            [matching]
            shards = 4
            rate_limit = "20/1s"
            [stats]
            listen = "127.0.0.1:9099"
            [[door]]
            name = "ssh"
            sequence = ["7000/tcp"]
            open_command = "true"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.shard_count(), 4);
        let spec = cfg.rate_limit().unwrap().unwrap();
        assert_eq!(spec.capacity, 20.0);
        assert_eq!(cfg.stats_listen(), Some("127.0.0.1:9099"));
    }

    #[test]
    fn omitted_firewall_section_defaults_to_command() {
        // A config with no [firewall] section must still resolve to the command
        // backend, not an empty backend string.
        let toml = r#"
            [[door]]
            name = "ssh"
            sequence = ["7000/tcp"]
            open_command = "true"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.firewall_kind().unwrap(), FirewallKind::Command);
    }

    #[test]
    fn zero_shards_means_auto_detect() {
        let toml = r#"
            [matching]
            shards = 0
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        // Auto-detect resolves to at least one shard on any host.
        assert!(cfg.shard_count() >= 1);
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
