//! nftables backend: add the source IP to a named allow-set as an element with a
//! kernel-side timeout.
//!
//! This is the differentiator over the `command` backend: instead of forking a
//! shell per knock and running a userspace timer to undo it, we issue a single
//! atomic `nft add element ... { <ip> timeout <T> }`. The kernel then expires the
//! element on its own, so no close timer is needed. A matching `nft delete
//! element` is still provided for explicit/early close.
//!
//! The argv builders are pure so the exact `nft` invocations are unit-tested
//! without nftables (or root) present; only [`run`] actually shells out.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::{Action, Firewall, NftSet};

pub struct NftablesFirewall {
    /// Path to the `nft` binary; overridable for tests/packaging.
    nft: String,
}

impl Default for NftablesFirewall {
    fn default() -> Self {
        Self {
            nft: "nft".to_string(),
        }
    }
}

impl NftablesFirewall {
    fn run(&self, args: &[String]) -> Result<()> {
        tracing::info!(cmd = %format!("{} {}", self.nft, args.join(" ")), "running nft");
        let status = Command::new(&self.nft)
            .args(args)
            .status()
            .with_context(|| format!("spawning {:?}", self.nft))?;
        if !status.success() {
            bail!("nft exited with {status}: {} {}", self.nft, args.join(" "));
        }
        Ok(())
    }

    fn set(action: &Action) -> Result<&NftSet> {
        action
            .nft_set
            .as_ref()
            .context("nftables backend: door has no nft_set")
    }
}

impl Firewall for NftablesFirewall {
    fn open(&self, action: &Action, src: IpAddr) -> Result<()> {
        self.run(&add_element_args(
            Self::set(action)?,
            src,
            action.timeout_ms,
        ))
    }

    fn close(&self, action: &Action, src: IpAddr) -> Result<()> {
        self.run(&delete_element_args(Self::set(action)?, src))
    }

    fn auto_expires(&self) -> bool {
        // The element carries a kernel timeout; the kernel reaps it. The runtime
        // need not (and must not, with no close command) schedule a userspace close.
        true
    }
}

/// `nft add element <family> <table> <set> { <ip>[ timeout <T>] }`
fn add_element_args(set: &NftSet, src: IpAddr, timeout_ms: Option<u64>) -> Vec<String> {
    let element = match timeout_ms {
        Some(ms) => format!("{} timeout {}", src, format_timeout(ms)),
        None => src.to_string(),
    };
    element_args("add", set, element)
}

/// `nft delete element <family> <table> <set> { <ip> }`
fn delete_element_args(set: &NftSet, src: IpAddr) -> Vec<String> {
    element_args("delete", set, src.to_string())
}

fn element_args(verb: &str, set: &NftSet, element: String) -> Vec<String> {
    vec![
        verb.to_string(),
        "element".to_string(),
        set.family.clone(),
        set.table.clone(),
        set.set.clone(),
        "{".to_string(),
        element,
        "}".to_string(),
    ]
}

/// Render a millisecond duration as an nft timeout literal. nft accepts `ms` and
/// `s`; we prefer whole seconds for readability and fall back to milliseconds.
fn format_timeout(ms: u64) -> String {
    if ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{}ms", ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn set() -> NftSet {
        NftSet::parse("inet filter knock_clients").unwrap()
    }

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
    }

    #[test]
    fn add_with_timeout_carries_kernel_expiry() {
        let args = add_element_args(&set(), ip(), Some(30_000));
        assert_eq!(
            args.join(" "),
            "add element inet filter knock_clients { 203.0.113.10 timeout 30s }"
        );
    }

    #[test]
    fn add_without_timeout_is_permanent() {
        let args = add_element_args(&set(), ip(), None);
        assert_eq!(
            args.join(" "),
            "add element inet filter knock_clients { 203.0.113.10 }"
        );
    }

    #[test]
    fn delete_removes_the_element() {
        let args = delete_element_args(&set(), ip());
        assert_eq!(
            args.join(" "),
            "delete element inet filter knock_clients { 203.0.113.10 }"
        );
    }

    #[test]
    fn sub_second_timeout_uses_milliseconds() {
        assert_eq!(format_timeout(1500), "1500ms");
        assert_eq!(format_timeout(45_000), "45s");
        assert_eq!(format_timeout(1000), "1s");
    }

    #[test]
    fn set_parse_defaults_family_to_inet() {
        assert_eq!(
            NftSet::parse("filter knock").unwrap(),
            set_named("inet", "filter", "knock")
        );
        assert_eq!(
            NftSet::parse("ip6 myt knock").unwrap(),
            set_named("ip6", "myt", "knock")
        );
        assert!(NftSet::parse("justone").is_err());
        assert!(NftSet::parse("a b c d").is_err());
    }

    fn set_named(family: &str, table: &str, set: &str) -> NftSet {
        NftSet {
            family: family.to_string(),
            table: table.to_string(),
            set: set.to_string(),
        }
    }
}
