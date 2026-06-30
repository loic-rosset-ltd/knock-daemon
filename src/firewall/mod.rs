//! Firewall backends — what actually happens when a door opens.
//!
//! Two backends ship:
//!
//! - `command` — run a configured shell command with `%IP%` substituted, exactly
//!   like knockd, so existing knockd setups port over unchanged. Expiry is driven
//!   by a userspace timer that runs the close command after `cmd_timeout`.
//! - `nftables` — add the source IP to a named allow-set as an element with a
//!   kernel-side timeout. No fork per knock beyond the one `nft` call, the add is
//!   atomic, and the kernel auto-expires the element, so no userspace close timer
//!   is needed.

use std::net::IpAddr;

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallKind {
    Command,
    Nftables,
}

/// Everything a door needs to act, for whichever backend is active. Built by the
/// config layer so the firewall backends stay decoupled from config parsing.
#[derive(Debug, Clone, Default)]
pub struct Action {
    /// Shell command run on open (`command` backend). `%IP%` → source address.
    pub open_command: Option<String>,
    /// Shell command run on close (`command` backend), if any.
    pub close_command: Option<String>,
    /// Allow-set the source is added to / removed from (`nftables` backend).
    pub nft_set: Option<NftSet>,
    /// Auto-close delay. The `command` backend uses it for a userspace close
    /// timer; the `nftables` backend uses it as the element's kernel timeout.
    pub timeout_ms: Option<u64>,
}

/// A reference to an nftables set, e.g. `inet filter knock_clients`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftSet {
    pub family: String,
    pub table: String,
    pub set: String,
}

impl NftSet {
    /// Parse `"<family> <table> <set>"` or `"<table> <set>"` (family defaults to
    /// `inet`, which covers both IPv4 and IPv6 in a single set).
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        let (family, table, set) = match parts.as_slice() {
            [family, table, set] => (*family, *table, *set),
            [table, set] => ("inet", *table, *set),
            _ => bail!(
                "invalid nft_set {s:?}: expected \"<family> <table> <set>\" \
                 or \"<table> <set>\" (e.g. \"inet filter knock_clients\")"
            ),
        };
        Ok(NftSet {
            family: family.to_string(),
            table: table.to_string(),
            set: set.to_string(),
        })
    }
}

/// Executes the open/close side effects of a knock for a given source IP.
pub trait Firewall: Send {
    fn open(&self, action: &Action, src: IpAddr) -> Result<()>;
    fn close(&self, action: &Action, src: IpAddr) -> Result<()>;

    /// Whether opened access expires on its own without a userspace close.
    ///
    /// `true` for backends like nftables that hand the timeout to the kernel:
    /// the runtime then skips the userspace close timer. `false` backends rely
    /// on the runtime to call [`Firewall::close`] after `cmd_timeout`.
    fn auto_expires(&self) -> bool {
        false
    }
}

mod command;
mod nftables;
pub use command::CommandFirewall;
pub use nftables::NftablesFirewall;
