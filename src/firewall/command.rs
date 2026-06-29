//! knockd-compatible command backend: substitute `%IP%` and run via the shell.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{bail, Result};

use super::Firewall;

pub struct CommandFirewall;

impl CommandFirewall {
    fn run(&self, command: &str, src: IpAddr) -> Result<()> {
        let rendered = command.replace("%IP%", &src.to_string());
        tracing::info!(command = %rendered, "running firewall command");
        let status = Command::new("sh").arg("-c").arg(&rendered).status()?;
        if !status.success() {
            bail!("firewall command exited with {status}: {rendered}");
        }
        Ok(())
    }
}

impl Firewall for CommandFirewall {
    fn open(&self, command: &str, src: IpAddr) -> Result<()> {
        self.run(command, src)
    }

    fn close(&self, command: &str, src: IpAddr) -> Result<()> {
        self.run(command, src)
    }
}
