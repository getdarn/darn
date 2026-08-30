pub mod apt;
pub mod detect;
mod linux;
pub mod mikrotik;
pub mod os_release;
pub mod redhat;

use crate::db::Patch;
use crate::errors::DarnError;
use crate::ssh::SshSession;

pub use apt::AptHandler;
pub use mikrotik::MikrotikHandler;
pub use redhat::RedHatHandler;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reboot {
    Yes,
    No,
    Unknown,
}

impl Reboot {
    pub fn as_str(self) -> &'static str {
        match self {
            Reboot::Yes => "yes",
            Reboot::No => "no",
            Reboot::Unknown => "unknown",
        }
    }
}

/// What a host needs restarted to finish applying its installed changes.
///
/// `reboot` is yes, no or unknown — never a boolean, because on both Linux
/// families the tool that gives the authoritative answer may simply not be
/// installed, and an absent marker is not proof of an absent reboot.
///
/// `services` names the systemd units running against upgraded libraries. It
/// is a separate axis from `reboot`: a container never needs a reboot but may
/// well have stale services, and a host needing a reboot does not need its
/// services bounced first.
#[derive(Clone, Debug, PartialEq)]
pub struct RestartCheck {
    pub reboot: Reboot,
    pub reboot_detail: Option<String>,
    pub services: Vec<String>,
}

impl RestartCheck {
    pub fn new(reboot: Reboot, reboot_detail: Option<&str>) -> Self {
        RestartCheck {
            reboot,
            reboot_detail: reboot_detail.map(str::to_string),
            services: Vec::new(),
        }
    }

    /// The same check with `services` attached — the list is parsed once per
    /// probe while the verdict comes from whichever indicator answered first.
    pub fn with_services(mut self, services: Vec<String>) -> Self {
        self.services = services;
        self
    }
}

/// Reject the flag combination no handler can honour. Both Linux families
/// enforced this separately, word for word.
pub fn check_upgrade_flags(security: bool, non_security: bool) -> Result<(), DarnError> {
    if security && non_security {
        return Err(DarnError::Other(
            "security and non_security are mutually exclusive".to_string(),
        ));
    }
    Ok(())
}

/// The packages among the known patches flagged security — what `--security`
/// installs and `--non-security` excludes.
pub fn security_packages(known_patches: &[Patch]) -> Vec<&str> {
    known_patches
        .iter()
        .filter(|p| p.is_security)
        .map(|p| p.package.as_str())
        .collect()
}

pub trait HostHandler: Sync {
    fn type_name(&self) -> &'static str;
    fn matches(&self, session: &mut SshSession<'_>) -> Result<bool, DarnError>;
    /// Return a human-readable distribution name and version.
    fn identify(&self, session: &mut SshSession<'_>) -> Result<String, DarnError>;
    fn discover(&self, session: &mut SshSession<'_>) -> Result<Vec<Patch>, DarnError>;
    fn upgrade(
        &self,
        session: &mut SshSession<'_>,
        security: bool,
        non_security: bool,
        known_patches: &[Patch],
    ) -> Result<(), DarnError>;
    /// Report what the host needs restarted to apply its installed changes.
    fn check_restarts(&self, session: &mut SshSession<'_>) -> Result<RestartCheck, DarnError>;
    /// Reboot the host. May return before the host has actually gone down.
    fn reboot(&self, session: &mut SshSession<'_>) -> Result<(), DarnError>;
    /// Restart the units running against upgraded libraries.
    ///
    /// `force` bypasses whatever local policy would otherwise decline to
    /// restart a unit, and restarts it directly.
    fn restart_services(
        &self,
        session: &mut SshSession<'_>,
        services: &[String],
        force: bool,
    ) -> Result<(), DarnError>;
}

/// Detection order matters: Apt, RedHat, Mikrotik.
pub static ALL_HANDLERS: [&dyn HostHandler; 3] = [&AptHandler, &RedHatHandler, &MikrotikHandler];

pub fn get_handler(type_name: &str) -> Result<&'static dyn HostHandler, DarnError> {
    ALL_HANDLERS
        .iter()
        .find(|h| h.type_name() == type_name)
        .copied()
        .ok_or_else(|| DarnError::Other(format!("unknown host type: {type_name}")))
}

#[cfg(test)]
mod quoting_parity_tests {
    // One-off parity check against Python shlex.quote output; reads the
    // fixture produced in the scratchpad. Skipped when the file is absent.
    // Lives here rather than with sh_quote so the probes it quotes are the
    // handlers' real ones.
    #[test]
    fn sudo_quoting_matches_python() {
        let path = std::env::var("DARN_PY_QUOTED").unwrap_or_default();
        if path.is_empty() {
            return;
        }
        let expected = std::fs::read_to_string(path).unwrap();
        let apt = super::apt::reboot_probe();
        let rh = super::redhat::reboot_probe();
        let cmds = [
            apt.to_string(),
            rh.replace("{pm}", "dnf"),
            rh.replace("{pm}", "yum"),
            "systemctl restart 'cron.service' 'postfix@-.service'".to_string(),
            "DEBIAN_FRONTEND=noninteractive apt-get update -qq".to_string(),
        ];
        let mut actual = String::new();
        for cmd in &cmds {
            let quoted = crate::quote::sh_quote(cmd);
            actual.push_str(&format!("sudo -n -- sh -c {quoted}\n=====\n"));
        }
        if let Ok(dump) = std::env::var("DARN_DUMP") {
            std::fs::write(dump, &actual).unwrap();
        }
        assert_eq!(expected, actual);
    }
}
