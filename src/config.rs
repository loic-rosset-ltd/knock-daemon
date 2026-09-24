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
    #[serde(default)]
    pub spa: SpaConfig,
    #[serde(rename = "door", default)]
    pub doors: Vec<DoorConfig>,
}

/// Single Packet Authorization. Off by default: it is strictly additional to
/// sequence knocking, and a daemon that was not asked for it should not start
/// deriving keys or watching a new port.
///
/// A door is still a door — an SPA packet names one by name, and the door's
/// config decides what opens. The client never names a port, which is why there
/// is no equivalent of fwknop's `OPEN_PORTS`/`RESTRICT_PORTS` here: a request
/// for an arbitrary port is not something the format can express.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaConfig {
    #[serde(default)]
    pub enabled: bool,
    /// UDP port SPA packets are *observed* on. Nothing is bound: the capture
    /// layer watches for it, so the host still has no listening socket.
    #[serde(default = "default_spa_port")]
    pub port: u16,
    /// PSK mode: file holding the shared passphrase, and a salt that must be the
    /// same on both sides. Argon2id runs once at startup, never per packet.
    pub passphrase_file: Option<String>,
    pub salt: Option<String>,
    /// Public-key mode: this server's X25519 static secret, and the
    /// `authorized_keys` file of client Ed25519 identities.
    pub static_key_file: Option<String>,
    pub authorized_keys: Option<String>,
    /// How far either side of our clock a packet timestamp may sit. Also bounds
    /// replay memory, since nothing outside the window can be replayed anyway.
    #[serde(default = "default_spa_window")]
    pub window: String,
    #[serde(default = "default_spa_duration")]
    pub default_duration: String,
    /// Hard ceiling on what a packet may request, so a client cannot grant
    /// itself unbounded access. fwknop's `MAX_FW_TIMEOUT`.
    #[serde(default = "default_spa_max_duration")]
    pub max_duration: String,
    /// Allow a payload to name an address other than the one observed. Off by
    /// default: it widens what a stolen packet can do.
    #[serde(default)]
    pub allow_explicit_addr: bool,
    #[serde(default = "default_spa_replay_entries")]
    pub max_replay_entries: usize,
}

impl Default for SpaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_spa_port(),
            passphrase_file: None,
            salt: None,
            static_key_file: None,
            authorized_keys: None,
            window: default_spa_window(),
            default_duration: default_spa_duration(),
            max_duration: default_spa_max_duration(),
            allow_explicit_addr: false,
            max_replay_entries: default_spa_replay_entries(),
        }
    }
}

fn default_spa_port() -> u16 {
    62201
}
fn default_spa_window() -> String {
    "30s".to_string()
}
fn default_spa_duration() -> String {
    "30s".to_string()
}
fn default_spa_max_duration() -> String {
    "1h".to_string()
}
fn default_spa_replay_entries() -> usize {
    65_536
}

/// Validated SPA settings, with durations already in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSpa {
    pub port: u16,
    pub window_secs: u64,
    pub default_duration_secs: u32,
    pub max_duration_secs: u32,
    pub allow_explicit_addr: bool,
    pub max_replay_entries: usize,
    pub passphrase_file: Option<String>,
    pub salt: Option<String>,
    pub static_key_file: Option<String>,
    pub authorized_keys: Option<String>,
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
    /// Validate the `[spa]` table. `Ok(None)` means SPA is switched off, which
    /// is a normal state, not a failure.
    ///
    /// Everything is checked here rather than at first packet, so `--check`
    /// catches a broken SPA setup before the service does. A daemon that starts
    /// and then silently refuses every knock is the worst of both worlds.
    pub fn resolve_spa(&self) -> Result<Option<ResolvedSpa>> {
        let c = &self.spa;
        if !c.enabled {
            return Ok(None);
        }
        if c.port == 0 {
            bail!("[spa] port must not be 0");
        }

        let has_psk = c.passphrase_file.is_some();
        let has_pubkey = c.static_key_file.is_some();
        if !has_psk && !has_pubkey {
            bail!(
                "[spa] is enabled but no key material is configured; set \
                 passphrase_file (+ salt) for PSK mode, or static_key_file \
                 (+ authorized_keys) for public-key mode"
            );
        }
        // A passphrase without a salt is a silent interoperability failure: the
        // daemon derives one key, every client derives another, and nothing ever
        // opens. Refuse it at load instead.
        if has_psk && c.salt.is_none() {
            bail!(
                "[spa] passphrase_file is set but salt is not; both sides must use the same salt"
            );
        }
        if let Some(salt) = &c.salt {
            if salt.len() < 8 {
                bail!(
                    "[spa] salt must be at least 8 characters (got {})",
                    salt.len()
                );
            }
        }
        // Public-key mode without an authorized_keys file authorises nobody. That
        // is safe, but it is almost certainly a mistake, so say so loudly rather
        // than running a daemon that can never accept a packet.
        if has_pubkey && c.authorized_keys.is_none() {
            bail!("[spa] static_key_file is set but authorized_keys is not; no client could be authorised");
        }

        let window_secs = parse_duration_ms(&c.window).context("[spa] window")? / 1000;
        if window_secs == 0 {
            bail!("[spa] window must be at least 1s");
        }
        let default_duration_secs = duration_secs(&c.default_duration, "[spa] default_duration")?;
        let max_duration_secs = duration_secs(&c.max_duration, "[spa] max_duration")?;
        if default_duration_secs > max_duration_secs {
            bail!(
                "[spa] default_duration ({default_duration_secs}s) exceeds max_duration ({max_duration_secs}s)"
            );
        }
        if c.max_replay_entries == 0 {
            bail!("[spa] max_replay_entries must be greater than 0");
        }

        Ok(Some(ResolvedSpa {
            port: c.port,
            window_secs,
            default_duration_secs,
            max_duration_secs,
            allow_explicit_addr: c.allow_explicit_addr,
            max_replay_entries: c.max_replay_entries,
            passphrase_file: c.passphrase_file.clone(),
            salt: c.salt.clone(),
            static_key_file: c.static_key_file.clone(),
            authorized_keys: c.authorized_keys.clone(),
        }))
    }

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
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else {
        (s, 1_000)
    };
    let value: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid duration {s:?}"))?;
    Ok(value * mult)
}

/// Parse a duration into whole seconds, rejecting zero and anything that would
/// not fit the `u32` the SPA payload carries.
fn duration_secs(text: &str, what: &str) -> Result<u32> {
    let ms = parse_duration_ms(text).with_context(|| what.to_string())?;
    let secs = ms / 1000;
    if secs == 0 {
        bail!("{what} must be at least 1s");
    }
    u32::try_from(secs).map_err(|_| anyhow::anyhow!("{what} is too large ({secs}s)"))
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

    /// Hours exist because `[spa] max_duration` defaults to "1h". The first
    /// version of that default did not parse, and every happy-path test set an
    /// explicit duration, so nothing caught it until a deliberately-invalid
    /// config was tried. Pin the whole grammar, not just the case that broke.
    #[test]
    fn duration_grammar_covers_every_suffix() {
        for (text, want_ms) in [
            ("250ms", 250u64),
            ("30s", 30_000),
            ("5m", 300_000),
            ("1h", 3_600_000),
            ("2h", 7_200_000),
            ("45", 45_000), // bare = seconds
        ] {
            assert_eq!(parse_duration_ms(text).unwrap(), want_ms, "parsing {text}");
        }
        assert!(parse_duration_ms("abc").is_err());
        assert!(parse_duration_ms("1d").is_err());
    }

    /// Every default in `[spa]` must actually parse. A default that does not is
    /// a landmine for anyone who omits the field.
    #[test]
    fn every_spa_default_parses() {
        let c = SpaConfig::default();
        assert!(
            parse_duration_ms(&c.window).is_ok(),
            "window {:?}",
            c.window
        );
        assert!(parse_duration_ms(&c.default_duration).is_ok());
        assert!(parse_duration_ms(&c.max_duration).is_ok());

        // And the whole table resolves once key material is supplied.
        let cfg: Config = toml::from_str(
            "[[door]]\nname = \"ssh\"\nsequence = [\"1/tcp\"]\nopen_command = \"x\"\n\n\
             [spa]\nenabled = true\nstatic_key_file = \"k\"\nauthorized_keys = \"a\"\n",
        )
        .unwrap();
        let sp = cfg.resolve_spa().unwrap().expect("spa enabled");
        assert_eq!(sp.max_duration_secs, 3600);
        assert_eq!(sp.default_duration_secs, 30);
        assert_eq!(sp.window_secs, 30);
    }
}
