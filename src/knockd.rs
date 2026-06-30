//! Compatibility parser for classic `knockd` `.conf` files.
//!
//! Lets existing knockd deployments point knock-daemon at their current config
//! unchanged. The legacy format is an INI-ish file: an optional `[options]`
//! section followed by one section per door. We translate it into our native
//! [`Config`], mapping knockd's `command` / `start_command` / `stop_command` /
//! `cmd_timeout` onto the `command` firewall backend, and converting `port:proto`
//! steps to our `port/proto` form.
//!
//! Because knockd resets a client's progress on any out-of-order hit, a parsed
//! `.conf` defaults to [`MatchMode::Reset`](crate::matcher::MatchMode) for true
//! behavioural parity; switch to the tolerant matcher in the TOML format if you
//! want knock-daemon's noise-robust behaviour instead.

use anyhow::{bail, Context, Result};

use crate::config::{Config, DoorConfig, FirewallConfig, MatchingConfig, StatsConfig};

/// Parse the text of a knockd `.conf` file into a native [`Config`].
pub fn parse_conf(text: &str) -> Result<Config> {
    let mut interface: Option<String> = None;
    let mut doors: Vec<DoorConfig> = Vec::new();
    let mut current: Option<DoorBuilder> = None;
    let mut in_options = false;

    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let ctx = || format!("knockd .conf line {}", lineno + 1);

        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // New section: flush the door we were building.
            if let Some(b) = current.take() {
                doors.push(b.finish().with_context(ctx)?);
            }
            let section = section.trim();
            if section.eq_ignore_ascii_case("options") {
                in_options = true;
            } else {
                in_options = false;
                current = Some(DoorBuilder::new(section));
            }
            continue;
        }

        // key = value, or a bare boolean flag like `UseSyslog`.
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (line, ""),
        };

        if in_options {
            if key.eq_ignore_ascii_case("interface") {
                interface = Some(value.to_string());
            }
            // Other options (UseSyslog, LogFile, PidFile, …) don't map onto this
            // daemon; ignore them rather than fail a otherwise-valid config.
            continue;
        }

        let Some(b) = current.as_mut() else {
            bail!("{}: directive {key:?} outside any [section]", ctx());
        };
        b.set(key, value).with_context(ctx)?;
    }

    if let Some(b) = current.take() {
        doors.push(b.finish()?);
    }
    if doors.is_empty() {
        bail!("knockd .conf defines no door sections");
    }

    Ok(Config {
        interface,
        firewall: FirewallConfig {
            backend: "command".to_string(),
        },
        // knockd resets on any out-of-order hit; match that for parity. Sharding,
        // rate limiting, and the stats endpoint are knockd2 extensions with no
        // legacy equivalent, so they take their native defaults.
        matching: MatchingConfig {
            mode: "reset".to_string(),
            ..MatchingConfig::default()
        },
        stats: StatsConfig::default(),
        doors,
    })
}

/// Drop a trailing `#`-comment. We only honour `#` at the start of (trimmed)
/// lines plus whitespace-preceded `#` elsewhere, so a `#` inside a command isn't
/// mistaken for a comment.
fn strip_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return "";
    }
    match line.find(" #") {
        Some(i) => &line[..i],
        None => line,
    }
}

#[derive(Default)]
struct DoorBuilder {
    name: String,
    sequence: Option<String>,
    seq_timeout: Option<String>,
    command: Option<String>,
    start_command: Option<String>,
    stop_command: Option<String>,
    cmd_timeout: Option<String>,
}

impl DoorBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let value = value.to_string();
        match key.to_ascii_lowercase().as_str() {
            "sequence" => self.sequence = Some(value),
            "seq_timeout" => self.seq_timeout = Some(value),
            "command" => self.command = Some(value),
            "start_command" => self.start_command = Some(value),
            "stop_command" | "cmd_stop_command" => self.stop_command = Some(value),
            "cmd_timeout" => self.cmd_timeout = Some(value),
            // knockd matches SYN by default and we only ever count SYN openers, so
            // `tcpflags = syn` is the no-op common case; reject anything else loudly.
            "tcpflags" => {
                if !value
                    .split(',')
                    .all(|f| f.trim().eq_ignore_ascii_case("syn"))
                {
                    bail!(
                        "door {:?}: only `tcpflags = syn` is supported (got {value:?})",
                        self.name
                    );
                }
            }
            other => bail!(
                "door {:?}: unsupported knockd directive {other:?}",
                self.name
            ),
        }
        Ok(())
    }

    fn finish(self) -> Result<DoorConfig> {
        let Some(sequence) = self.sequence else {
            bail!("door {:?} has no sequence", self.name);
        };
        let sequence = sequence
            .split(',')
            .map(convert_step)
            .collect::<Result<Vec<_>>>()
            .with_context(|| format!("door {:?} sequence", self.name))?;

        // `start_command` pairs with `stop_command`; a lone `command` is open-only.
        let open_command = self.start_command.or(self.command);
        let Some(open_command) = open_command else {
            bail!("door {:?} has no command / start_command", self.name);
        };

        Ok(DoorConfig {
            name: self.name,
            sequence,
            seq_timeout: seconds_to_duration(self.seq_timeout.as_deref()),
            open_command: Some(open_command),
            close_command: self.stop_command,
            nft_set: None,
            cmd_timeout: self.cmd_timeout.as_deref().map(to_seconds_literal),
        })
    }
}

/// Convert a knockd step (`7000`, `7000:tcp`, `8000:udp`) to our `port/proto` form.
fn convert_step(step: &str) -> Result<String> {
    let step = step.trim();
    match step.split_once(':') {
        Some((port, proto)) => {
            let proto = proto.trim().to_ascii_lowercase();
            if proto != "tcp" && proto != "udp" {
                bail!("invalid protocol in step {step:?} (use tcp or udp)");
            }
            Ok(format!("{}/{}", port.trim(), proto))
        }
        None => Ok(step.to_string()),
    }
}

/// knockd durations are bare integer seconds; tag them so our duration parser
/// reads them as seconds rather than its bare-number fallback (which is also
/// seconds, but being explicit keeps `--check` output unambiguous).
fn seconds_to_duration(raw: Option<&str>) -> String {
    match raw {
        Some(s) => to_seconds_literal(s),
        None => "15s".to_string(),
    }
}

fn to_seconds_literal(s: &str) -> String {
    let s = s.trim();
    // Already carries a unit (someone hand-edited): pass it through.
    if s.ends_with(|c: char| c.is_ascii_alphabetic()) {
        s.to_string()
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallKind;
    use crate::matcher::{MatchMode, Proto};

    #[test]
    fn parses_a_classic_knockd_conf() {
        let conf = "\
[options]
\tUseSyslog
\tInterface = eth0

[openSSH]
\tsequence    = 7000,8000,9000
\tseq_timeout = 5
\ttcpflags    = syn
\tcommand     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
";
        let cfg = parse_conf(conf).unwrap();
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.firewall_kind().unwrap(), FirewallKind::Command);
        // knockd parity → reset matching.
        assert_eq!(cfg.match_mode().unwrap(), MatchMode::Reset);

        let doors = cfg.resolve(FirewallKind::Command).unwrap();
        assert_eq!(doors.len(), 1);
        assert_eq!(doors[0].spec.name, "openSSH");
        assert_eq!(doors[0].spec.sequence.len(), 3);
        assert_eq!(doors[0].spec.seq_timeout_ms, 5_000);
        assert!(doors[0]
            .action
            .open_command
            .as_deref()
            .unwrap()
            .contains("--dport 22"));
        assert!(doors[0].action.close_command.is_none());
    }

    #[test]
    fn parses_open_close_with_cmd_timeout_and_udp_steps() {
        let conf = "\
[opencloseSSH]
\tsequence      = 2222:udp,3333:tcp,4444:udp
\tseq_timeout   = 15
\ttcpflags      = syn
\tstart_command = /usr/sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
\tcmd_timeout   = 10
\tstop_command  = /usr/sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
";
        let cfg = parse_conf(conf).unwrap();
        let doors = cfg.resolve(FirewallKind::Command).unwrap();
        let d = &doors[0];
        assert_eq!(d.spec.sequence[0].proto, Proto::Udp);
        assert_eq!(d.spec.sequence[1].proto, Proto::Tcp);
        assert_eq!(d.spec.sequence[2].proto, Proto::Udp);
        assert_eq!(d.action.timeout_ms, Some(10_000));
        assert!(d
            .action
            .open_command
            .as_deref()
            .unwrap()
            .contains("-A INPUT"));
        assert!(d
            .action
            .close_command
            .as_deref()
            .unwrap()
            .contains("-D INPUT"));
    }

    #[test]
    fn rejects_non_syn_tcpflags_and_empty_files() {
        let bad = "[d]\nsequence = 1,2\ntcpflags = syn,ack\ncommand = true\n";
        assert!(parse_conf(bad).is_err());
        assert!(parse_conf("# just a comment\n").is_err());
    }

    #[test]
    fn comments_are_stripped_but_not_inside_commands() {
        let conf = "\
# a leading comment
[d]
sequence = 100,200   # trailing comment
command = echo done   # and here
";
        let cfg = parse_conf(conf).unwrap();
        let doors = cfg.resolve(FirewallKind::Command).unwrap();
        assert_eq!(doors[0].spec.sequence.len(), 2);
        assert_eq!(doors[0].action.open_command.as_deref(), Some("echo done"));
    }
}
