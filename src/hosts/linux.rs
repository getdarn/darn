//! What the two Linux families share: systemd restarts, the detached reboot,
//! probe-section parsing, and the container/kernel fallback verdict. RouterOS
//! uses none of this.

use std::collections::HashMap;

use crate::errors::DarnError;
use crate::hosts::{Reboot, RestartCheck};
use crate::ssh::SshSession;

/// Restart units directly, in one call so a failure is reported not skipped.
pub(super) fn systemctl_restart(
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
pub(super) fn reboot_linux(session: &mut SshSession<'_>) -> Result<(), DarnError> {
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
pub(super) const CONTAINER_PROBE: &str = "systemd-detect-virt --container 2>/dev/null \
|| cat /run/systemd/container 2>/dev/null || true";

/// The fallback verdict both Linux probes end on when the distribution's own
/// tooling gave no answer: the container verdict when in one, else the
/// running-versus-newest kernel comparison.
pub(super) fn fallback_reboot_check(container: &str, running: &str, newest: &str) -> RestartCheck {
    container_reboot_check(container).unwrap_or_else(|| kernel_reboot_check(running, newest))
}

/// Verdict for a containerised host, or None if this is not a container.
///
/// needrestart omits its kernel verdict entirely inside a container, and the
/// kernel comparison would pit the *host's* running kernel against whatever
/// happens to be in the container's /boot — so neither may be consulted here.
fn container_reboot_check(container: &str) -> Option<RestartCheck> {
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
fn kernel_reboot_check(running: &str, newest: &str) -> RestartCheck {
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
pub(super) fn parse_probe_sections(output: &str) -> HashMap<String, String> {
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
