//! Firewall backends — what actually happens when a door opens.
//!
//! The MVP ships the `command` backend: run a configured shell command with
//! `%IP%` substituted, exactly like knockd, so existing knockd setups port over
//! unchanged. An `nftables` backend (manipulate an allow-set element with a
//! kernel-side timeout, no fork per knock) is planned (see DESIGN.md).

use anyhow::Result;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallKind {
    Command,
    Nftables,
}

/// Executes the open/close side effects of a knock for a given source IP.
pub trait Firewall: Send {
    fn open(&self, command: &str, src: IpAddr) -> Result<()>;
    fn close(&self, command: &str, src: IpAddr) -> Result<()>;
}

mod command;
pub use command::CommandFirewall;
