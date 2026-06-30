//! knockd-compatible command backend: substitute `%IP%` and run via the shell.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{bail, Result};

use super::{Action, Firewall};

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
    fn open(&self, action: &Action, src: IpAddr) -> Result<()> {
        let Some(command) = action.open_command.as_deref() else {
            bail!("command backend: door has no open_command");
        };
        self.run(command, src)
    }

    fn close(&self, action: &Action, src: IpAddr) -> Result<()> {
        let Some(command) = action.close_command.as_deref() else {
            // No close command configured: nothing to undo.
            return Ok(());
        };
        self.run(command, src)
    }
}
