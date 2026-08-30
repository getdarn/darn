pub mod apt;
pub mod detect;
pub mod mikrotik;
pub mod os_release;
pub mod redhat;

use std::collections::HashMap;

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

/// Restart units directly, in one call so a failure is reported not skipped.
pub fn systemctl_restart(
    session: &mut SshSession<'_>,
    services: &[String],
) -> Result<(), DarnError> {
    if services.is_empty() {
        return Ok(());
    }
    let units = services
        .iter()
        .map(|unit| crate::quote::sh_quote(unit))
        .collect::<Vec<_>>()
        .join(" ");
    session.run(&format!("systemctl restart {units}"), true, true)?;
    Ok(())
}

/// Trigger a reboot on a Linux host without waiting for it to go down.
///
/// The command is detached and its output redirected so that the SSH exec
/// returns cleanly instead of hanging until the connection dies; if the
/// connection drops anyway, that is the expected outcome, not a failure.
pub fn reboot_linux(session: &mut SshSession<'_>) -> Result<(), DarnError> {
    match session.run(
        "(sleep 2; systemctl reboot || shutdown -r now || reboot) >/dev/null 2>&1 </dev/null &",
        true,
        false,
    ) {
        Ok(_) | Err(DarnError::Ssh(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

// Containers see their host's kernel via uname but own neither it nor /boot,
// so every kernel-based indicator is meaningless inside one.
pub const CONTAINER_PROBE: &str = "systemd-detect-virt --container 2>/dev/null \
|| cat /run/systemd/container 2>/dev/null || true";

/// Verdict for a containerised host, or None if this is not a container.
///
/// needrestart omits its kernel verdict entirely inside a container, and the
/// kernel comparison would pit the *host's* running kernel against whatever
/// happens to be in the container's /boot — so neither may be consulted here.
pub fn container_reboot_check(container: &str) -> Option<RestartCheck> {
    let value = container
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or("");
    if value.is_empty() || value == "none" {
        return None;
    }
    Some(RestartCheck::new(
        Reboot::No,
        Some(&format!("{value} container: kernel belongs to the host")),
    ))
}

/// Fall-back verdict from the running kernel versus the newest installed one.
///
/// Coarser than the distribution's own tooling — it cannot see a glibc or
/// systemd update — so callers should only reach for it when that tooling is
/// absent.
pub fn kernel_reboot_check(running: &str, newest: &str) -> RestartCheck {
    let running = running.trim();
    let newest = newest.trim();
    if running.is_empty() || newest.is_empty() {
        return RestartCheck::new(Reboot::Unknown, Some("no reboot indicator available"));
    }
    if running != newest {
        return RestartCheck::new(Reboot::Yes, Some(&format!("kernel {running} → {newest}")));
    }
    RestartCheck::new(Reboot::No, None)
}

/// Split `### NAME`-delimited probe output into a section → body mapping.
pub fn parse_probe_sections(output: &str) -> HashMap<String, String> {
    let mut sections: HashMap<String, Vec<&str>> = HashMap::new();
    let mut current: Option<String> = None;
    for raw in output.lines() {
        let line = raw.trim_end();
        if let Some(name) = line.strip_prefix("### ") {
            let name = name.trim().to_string();
            sections.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        if let Some(name) = &current {
            sections.get_mut(name).unwrap().push(line);
        }
    }
    sections
        .into_iter()
        .map(|(k, v)| (k, v.join("\n").trim().to_string()))
        .collect()
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
