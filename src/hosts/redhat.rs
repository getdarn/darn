use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::db::Patch;
use crate::errors::DarnError;
use crate::hosts::os_release::{identify_from_os_release, parse_os_release};
use crate::hosts::{
    container_reboot_check, kernel_reboot_check, parse_probe_sections, reboot_linux,
    systemctl_restart, HostHandler, Reboot, RestartCheck, CONTAINER_PROBE,
};
use crate::ssh::SshSession;

const REDHAT_IDS: [&str; 7] = [
    "rhel",
    "centos",
    "fedora",
    "rocky",
    "almalinux",
    "ol",
    "amzn",
];

// `needs-restarting` ships in dnf-plugins-core / yum-utils and is absent on
// minimal images, so its own output has to be inspected rather than trusted.
// `{pm}` is substituted with the detected package manager before running.
static REBOOT_PROBE: LazyLock<String> = LazyLock::new(|| {
    r#"export LC_ALL=C
echo '### NEEDS_RESTARTING'
{pm} needs-restarting -r 2>&1
echo "EXIT=$?"
echo '### SERVICES'
{pm} needs-restarting -s 2>/dev/null || true
echo '### CONTAINER'
{container}
echo '### RUNNING'
uname -r
echo '### NEWEST'
rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -1
"#
    .replace("{container}", CONTAINER_PROBE)
});

const MISSING_PLUGIN_MARKERS: [&str; 6] = [
    "no such command",
    "unknown command",
    "unknown argument",
    "not found", // covers both bash's "command not found" and dash's "not found"
    "no module named",
    "invalid choice",
];

static NVR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<name>[A-Za-z0-9._+-]+?)-\d[\w.+~:-]*\.(?:noarch|x86_64|i686|aarch64|armv7hl|ppc64le|s390x)$",
    )
    .unwrap()
});

pub struct RedHatHandler;

impl RedHatHandler {
    fn pm(&self, session: &mut SshSession<'_>) -> Result<String, DarnError> {
        let res = session.probe(
            "command -v dnf >/dev/null 2>&1 && echo dnf || echo yum",
            false,
            false,
        )?;
        let pm = res.stdout.trim();
        Ok(if pm.is_empty() {
            "yum".to_string()
        } else {
            pm.to_string()
        })
    }
}

impl HostHandler for RedHatHandler {
    fn type_name(&self) -> &'static str {
        "redhat"
    }

    fn matches(&self, session: &mut SshSession<'_>) -> Result<bool, DarnError> {
        let res = session.probe("cat /etc/os-release 2>/dev/null || true", false, false)?;
        if res.exit_code != 0 || res.stdout.is_empty() {
            return Ok(false);
        }
        let fields = parse_os_release(&res.stdout);
        let id = fields.get("ID").map(String::as_str).unwrap_or("");
        let id_like = fields.get("ID_LIKE").map(String::as_str).unwrap_or("");
        Ok(std::iter::once(id)
            .chain(id_like.split_whitespace())
            .any(|i| REDHAT_IDS.contains(&i)))
    }

    fn identify(&self, session: &mut SshSession<'_>) -> Result<String, DarnError> {
        let res = session.probe("cat /etc/os-release 2>/dev/null || true", false, false)?;
        Ok(identify_from_os_release(&res.stdout, "RedHat-based"))
    }

    fn discover(&self, session: &mut SshSession<'_>) -> Result<Vec<Patch>, DarnError> {
        let pm = self.pm(session)?;
        // check-update exits 100 when updates are available, 0 when none, >0 on error.
        let check = session.probe(&format!("LC_ALL=C {pm} -q check-update"), false, false)?;
        if check.exit_code != 0 && check.exit_code != 100 {
            return Err(DarnError::Ssh(format!(
                "{pm} check-update failed ({}): {}",
                check.exit_code, check.stderr
            )));
        }
        let all_patches = parse_dnf_check_update(&check.stdout);

        let sec = session.probe(
            &format!("LC_ALL=C {pm} -q updateinfo list --security 2>/dev/null || true"),
            false,
            false,
        )?;
        let security_pkgs = parse_dnf_updateinfo_security(&sec.stdout);

        Ok(all_patches
            .into_iter()
            .map(|p| {
                let is_security = security_pkgs.contains(&p.package);
                Patch { is_security, ..p }
            })
            .collect())
    }

    fn upgrade(
        &self,
        session: &mut SshSession<'_>,
        security: bool,
        non_security: bool,
        known_patches: &[Patch],
    ) -> Result<(), DarnError> {
        if security && non_security {
            return Err(DarnError::Other(
                "security and non_security are mutually exclusive".to_string(),
            ));
        }
        let pm = self.pm(session)?;

        if security {
            session.run(&format!("{pm} upgrade -y --security"), true, true)?;
        } else if non_security {
            let excludes: Vec<&str> = known_patches
                .iter()
                .filter(|p| p.is_security)
                .map(|p| p.package.as_str())
                .collect();
            if !excludes.is_empty() {
                let exc = excludes
                    .iter()
                    .map(|p| crate::quote::sh_quote(p))
                    .collect::<Vec<_>>()
                    .join(",");
                session.run(&format!("{pm} upgrade -y --exclude={exc}"), true, true)?;
            } else {
                session.run(&format!("{pm} upgrade -y"), true, true)?;
            }
        } else {
            session.run(&format!("{pm} upgrade -y"), true, true)?;
        }
        Ok(())
    }

    fn check_restarts(&self, session: &mut SshSession<'_>) -> Result<RestartCheck, DarnError> {
        let pm = self.pm(session)?;
        let probe = REBOOT_PROBE.replace("{pm}", &pm);
        let res = session.probe(&probe, true, false)?;
        Ok(parse_redhat_restarts(&res.stdout))
    }

    fn reboot(&self, session: &mut SshSession<'_>) -> Result<(), DarnError> {
        reboot_linux(session)
    }

    /// Restart the named units.
    ///
    /// RedHat has no equivalent of needrestart's policy-aware automatic mode,
    /// so the units are always bounced directly and `force` changes nothing.
    fn restart_services(
        &self,
        session: &mut SshSession<'_>,
        services: &[String],
        _force: bool,
    ) -> Result<(), DarnError> {
        systemctl_restart(session, services)
    }
}

/// Parse `dnf check-update` output.
///
/// Output format (after a blank line separating headers, per package):
///     <name>.<arch>    <version>    <repo>
///
/// Lines starting with 'Obsoleting Packages' and below are ignored.
/// Empty lines and header lines are skipped.
pub fn parse_dnf_check_update(output: &str) -> Vec<Patch> {
    let mut patches = Vec::new();
    let mut seen_blank = false;
    for raw in output.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            seen_blank = true;
            continue;
        }
        if line.starts_with("Obsoleting Packages") {
            break;
        }
        if !seen_blank {
            // Pre-blank lines are metadata (e.g. "Last metadata expiration ...").
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let (name_arch, version) = (parts[0], parts[1]);
        let package = match name_arch.rsplit_once('.') {
            Some((name, _arch)) => name,
            None => name_arch,
        };
        patches.push(Patch {
            package: package.to_string(),
            version: Some(version.to_string()),
            is_security: false,
        });
    }
    patches
}

/// Turn the reboot probe output into a restart verdict.
///
/// `needs-restarting -r` exits 1 both when a reboot is required and when the
/// subcommand does not exist, so the text is checked for a missing-plugin
/// complaint *before* the exit status is believed.
pub fn parse_redhat_restarts(output: &str) -> RestartCheck {
    let sections = parse_probe_sections(output);
    let get = |name: &str| sections.get(name).map(String::as_str).unwrap_or("");
    let body = get("NEEDS_RESTARTING");
    let services = parse_needs_restarting_services(get("SERVICES"));

    let mut exit_code: Option<i32> = None;
    let mut message_lines: Vec<&str> = Vec::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("EXIT=") {
            exit_code = rest.trim().parse().ok();
            continue;
        }
        if !line.trim().is_empty() {
            message_lines.push(line.trim());
        }
    }
    let message = message_lines.join(" ");
    let lowered = message.to_lowercase();

    let plugin_missing = MISSING_PLUGIN_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker));
    if !plugin_missing {
        if exit_code == Some(0) {
            let mut check = RestartCheck::new(Reboot::No, None);
            check.services = services;
            return check;
        }
        if exit_code == Some(1) {
            let detail = if message.is_empty() {
                "needs-restarting reports a reboot".to_string()
            } else {
                message
            };
            let mut check = RestartCheck::new(Reboot::Yes, Some(&detail));
            check.services = services;
            return check;
        }
    }

    let mut verdict = container_reboot_check(get("CONTAINER"))
        .unwrap_or_else(|| kernel_reboot_check(get("RUNNING"), get("NEWEST")));
    verdict.services = services;
    verdict
}

/// Extract unit names from `needs-restarting -s` output.
///
/// One unit per line; anything without a systemd suffix is a diagnostic and is
/// ignored, which also drops the missing-plugin complaint.
pub fn parse_needs_restarting_services(output: &str) -> Vec<String> {
    const SUFFIXES: [&str; 6] = [
        ".service", ".socket", ".target", ".timer", ".path", ".mount",
    ];
    let mut seen = HashSet::new();
    let mut units = Vec::new();
    for raw in output.lines() {
        let unit = raw.trim();
        if SUFFIXES.iter().any(|s| unit.ends_with(s)) && seen.insert(unit.to_string()) {
            units.push(unit.to_string());
        }
    }
    units
}

/// Extract package names from `dnf updateinfo list --security`.
///
/// Output format per row:
///     FEDORA-2024-abc123  Important/Sec.  curl-8.0.1-1.fc39.x86_64
pub fn parse_dnf_updateinfo_security(output: &str) -> HashSet<String> {
    let mut pkgs = HashSet::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let candidate = parts[parts.len() - 1];
        if let Some(m) = NVR_RE.captures(candidate) {
            pkgs.insert(m["name"].to_string());
        }
    }
    pkgs
}

#[cfg(test)]
pub(super) fn reboot_probe() -> &'static str {
    &REBOOT_PROBE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_update_basic() {
        let output = "\
Last metadata expiration check: 0:05:12 ago on Mon 21 Apr 2026 10:00:00 AM UTC.

curl.x86_64                 8.0.1-1.fc39           updates
openssl-libs.x86_64         1:3.0.9-2.fc39         updates
kernel.x86_64               6.6.7-100.fc39         updates

Obsoleting Packages
old-thing.noarch            1.0-1.fc39             updates
";
        let patches = parse_dnf_check_update(output);
        let names: Vec<&str> = patches.iter().map(|p| p.package.as_str()).collect();
        assert_eq!(names, ["curl", "openssl-libs", "kernel"]);
        assert_eq!(patches[0].version.as_deref(), Some("8.0.1-1.fc39"));
    }

    #[test]
    fn check_update_empty() {
        let output = "Last metadata expiration check: 0:00:01 ago on ...\n";
        assert!(parse_dnf_check_update(output).is_empty());
    }

    #[test]
    fn updateinfo_security_extracts_names() {
        let output = "\
FEDORA-2026-abc Important/Sec. curl-8.0.1-1.fc39.x86_64
FEDORA-2026-def Moderate/Sec.  openssl-libs-1:3.0.9-2.fc39.x86_64
FEDORA-2026-ghi Low/Sec.       kernel-6.6.7-100.fc39.x86_64
";
        let pkgs = parse_dnf_updateinfo_security(output);
        let expected: HashSet<String> = ["curl", "openssl-libs", "kernel"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(pkgs, expected);
    }

    fn probe(
        needs_restarting: &str,
        container: &str,
        running: &str,
        newest: &str,
        services: &str,
    ) -> String {
        format!(
            "### NEEDS_RESTARTING\n{needs_restarting}\n### SERVICES\n{services}\n\
### CONTAINER\n{container}\n### RUNNING\n{running}\n### NEWEST\n{newest}\n"
        )
    }

    #[test]
    fn restarts_not_needed() {
        let check = parse_redhat_restarts(&probe(
            "Reboot should not be necessary.\nEXIT=0",
            "none",
            "",
            "",
            "",
        ));
        assert_eq!(check.reboot, Reboot::No);
    }

    #[test]
    fn restarts_needed() {
        let check = parse_redhat_restarts(&probe(
            "Core libraries or services have been updated since boot-up:\n  \
* kernel\nReboot is required to fully utilize these updates.\nEXIT=1",
            "none",
            "",
            "",
            "",
        ));
        assert_eq!(check.reboot, Reboot::Yes);
        assert!(check.reboot_detail.unwrap().contains("Core libraries"));
    }

    #[test]
    fn restarts_missing_plugin_is_not_a_reboot() {
        // dnf exits 1 for an unknown subcommand too — the text has to break the tie.
        let check = parse_redhat_restarts(&probe(
            "No such command: needs-restarting. Please use /usr/bin/dnf --help\nEXIT=1",
            "none",
            "5.14.0-427.el9.x86_64",
            "5.14.0-427.el9.x86_64",
            "",
        ));
        assert_eq!(check.reboot, Reboot::No);

        let unknown = parse_redhat_restarts(&probe(
            "No such command: needs-restarting.\nEXIT=1",
            "none",
            "",
            "",
            "",
        ));
        assert_eq!(unknown.reboot, Reboot::Unknown);
    }

    #[test]
    fn restarts_falls_back_to_kernel_comparison() {
        let check = parse_redhat_restarts(&probe(
            "sh: line 1: dnf: command not found\nEXIT=127",
            "none",
            "5.14.0-427.el9.x86_64",
            "5.14.0-503.el9.x86_64",
            "",
        ));
        assert_eq!(check.reboot, Reboot::Yes);
        assert_eq!(
            check.reboot_detail.as_deref(),
            Some("kernel 5.14.0-427.el9.x86_64 → 5.14.0-503.el9.x86_64")
        );
    }

    #[test]
    fn restarts_container_skips_kernel_comparison() {
        let check = parse_redhat_restarts(&probe(
            "No such command: needs-restarting.\nEXIT=1",
            "podman",
            "5.14.0-427.el9.x86_64",
            "",
            "",
        ));
        assert_eq!(check.reboot, Reboot::No);
        assert_eq!(
            check.reboot_detail.as_deref(),
            Some("podman container: kernel belongs to the host")
        );
    }

    #[test]
    fn restarts_collects_service_units() {
        let check = parse_redhat_restarts(&probe(
            "Reboot should not be necessary.\nEXIT=0",
            "none",
            "",
            "",
            "crond.service\nsshd.service\nchronyd.service\n",
        ));
        assert_eq!(check.reboot, Reboot::No);
        assert_eq!(
            check.services,
            ["crond.service", "sshd.service", "chronyd.service"]
        );
    }

    #[test]
    fn needs_restarting_services_ignores_noise() {
        let output = "\
No such command: needs-restarting. Please use /usr/bin/dnf --help
crond.service
crond.service
";
        assert_eq!(parse_needs_restarting_services(output), ["crond.service"]);
    }
}
