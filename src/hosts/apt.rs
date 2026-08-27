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

// Matches simulated apt output lines like:
//   Inst curl [7.81.0-1ubuntu1.14] (7.81.0-1ubuntu1.16 Ubuntu:22.04/jammy-security [amd64])
static INST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^Inst\s+(?P<pkg>\S+)\s+(?:\[(?P<old>[^\]]+)\]\s+)?\((?P<new>\S+)\s+(?P<archives>[^)]*)\)",
    )
    .unwrap()
});

// Gathers every reboot indicator in one round trip. The marker file and the
// kernel comparison need no privileges; needrestart does, hence sudo.
static REBOOT_PROBE: LazyLock<String> = LazyLock::new(|| {
    r"export LC_ALL=C
echo '### MARKER'
[ -e /var/run/reboot-required ] && echo present || echo absent
echo '### PKGS'
cat /var/run/reboot-required.pkgs 2>/dev/null || true
echo '### NOTIFIER'
dpkg-query -W -f='${Status}' update-notifier-common 2>/dev/null || true
echo
echo '### NEEDRESTART'
command -v needrestart >/dev/null 2>&1 && needrestart -b -r l 2>/dev/null || true
echo '### CONTAINER'
{container}
echo '### RUNNING'
uname -r
echo '### NEWEST'
ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|.*/vmlinuz-||' | sort -V | tail -1
"
    .replace("{container}", CONTAINER_PROBE)
});

static KSTA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^NEEDRESTART-KSTA:\s*(\d+)").unwrap());
static KCUR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^NEEDRESTART-KCUR:\s*(\S+)").unwrap());
static KEXP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^NEEDRESTART-KEXP:\s*(\S+)").unwrap());
static SVC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^NEEDRESTART-SVC:\s*(\S+)").unwrap());

pub struct AptHandler;

impl AptHandler {
    fn apt_update(&self, session: &mut SshSession<'_>) -> Result<(), DarnError> {
        session.run(
            "DEBIAN_FRONTEND=noninteractive apt-get update -qq",
            true,
            true,
        )?;
        Ok(())
    }
}

const BASE: &str = "DEBIAN_FRONTEND=noninteractive apt-get -y \
-o Dpkg::Options::=--force-confold \
-o Dpkg::Options::=--force-confdef";

impl HostHandler for AptHandler {
    fn type_name(&self) -> &'static str {
        "debian"
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
            .any(|i| i == "ubuntu" || i == "debian"))
    }

    fn identify(&self, session: &mut SshSession<'_>) -> Result<String, DarnError> {
        let res = session.probe("cat /etc/os-release 2>/dev/null || true", false, false)?;
        Ok(identify_from_os_release(&res.stdout, "Debian-based"))
    }

    fn discover(&self, session: &mut SshSession<'_>) -> Result<Vec<Patch>, DarnError> {
        self.apt_update(session)?;
        let res = session.probe(
            "LC_ALL=C apt-get -s -o Debug::NoLocking=true dist-upgrade",
            true,
            true,
        )?;
        Ok(parse_apt_simulate(&res.stdout))
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

        self.apt_update(session)?;

        if security {
            let packages: Vec<&str> = known_patches
                .iter()
                .filter(|p| p.is_security)
                .map(|p| p.package.as_str())
                .collect();
            if packages.is_empty() {
                return Ok(());
            }
            let quoted = quote_all(&packages);
            session.run(
                &format!("{BASE} install --only-upgrade {quoted}"),
                true,
                true,
            )?;
        } else if non_security {
            let excludes: Vec<&str> = known_patches
                .iter()
                .filter(|p| p.is_security)
                .map(|p| p.package.as_str())
                .collect();
            if !excludes.is_empty() {
                // Using apt-mark hold is more robust than APT::Get::Hold.
                let mark = quote_all(&excludes);
                session.run(&format!("apt-mark hold {mark}"), true, true)?;
                let result = session.run(&format!("{BASE} dist-upgrade"), true, true);
                // The unhold must run even when the upgrade failed.
                let _ = session.run(&format!("apt-mark unhold {mark}"), true, false);
                result?;
            } else {
                session.run(&format!("{BASE} dist-upgrade"), true, true)?;
            }
        } else {
            session.run(&format!("{BASE} dist-upgrade"), true, true)?;
        }
        Ok(())
    }

    fn check_restarts(&self, session: &mut SshSession<'_>) -> Result<RestartCheck, DarnError> {
        let res = session.probe(&REBOOT_PROBE, true, false)?;
        Ok(parse_debian_restarts(&res.stdout))
    }

    fn reboot(&self, session: &mut SshSession<'_>) -> Result<(), DarnError> {
        reboot_linux(session)
    }

    /// Hand the job to needrestart, which produced the list in the first place.
    ///
    /// Its automatic mode honours the local restart policy in
    /// /etc/needrestart/needrestart.conf and conf.d — so units marked too
    /// disruptive to bounce (dbus, systemd-logind, display managers, and
    /// whatever the distribution or admin has added) stay untouched, which a
    /// bare `systemctl restart` would not respect. `force` is exactly that
    /// bare restart, for units the policy has declined.
    fn restart_services(
        &self,
        session: &mut SshSession<'_>,
        services: &[String],
        force: bool,
    ) -> Result<(), DarnError> {
        if services.is_empty() {
            return Ok(());
        }
        if force {
            return systemctl_restart(session, services);
        }
        session.run("needrestart -b -r a", true, true)?;
        Ok(())
    }
}

fn quote_all(items: &[&str]) -> String {
    items
        .iter()
        .map(|p| crate::quote::sh_quote(p))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse `apt-get -s dist-upgrade` output into Patch records.
///
/// A package is flagged security iff any archive listed in the parentheses
/// ends in `-security` (e.g. `jammy-security`, `bookworm-security`).
pub fn parse_apt_simulate(output: &str) -> Vec<Patch> {
    let mut patches = Vec::new();
    for line in output.lines() {
        let Some(m) = INST_RE.captures(line.trim()) else {
            continue;
        };
        let archives = m.name("archives").map(|a| a.as_str()).unwrap_or("");
        patches.push(Patch {
            package: m["pkg"].to_string(),
            version: Some(m["new"].to_string()),
            is_security: archives_are_security(archives),
        });
    }
    patches
}

/// Turn the reboot probe output into a restart verdict.
///
/// The marker file outranks needrestart because needrestart only judges the
/// kernel, whereas `/var/run/reboot-required` is also written for userland
/// packages such as dbus or libc. When neither indicator is installed, fall
/// back to comparing the running kernel with the newest one in /boot.
pub fn parse_debian_restarts(output: &str) -> RestartCheck {
    let sections = parse_probe_sections(output);
    let get = |name: &str| sections.get(name).map(String::as_str).unwrap_or("");
    let marker = get("MARKER").trim();
    let needrestart = get("NEEDRESTART");
    let services: Vec<String> = SVC_RE
        .captures_iter(needrestart)
        .map(|c| c[1].to_string())
        .collect();

    if marker == "present" {
        let pkgs: Vec<&str> = get("PKGS")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let detail = if pkgs.is_empty() {
            "/var/run/reboot-required exists".to_string()
        } else {
            pkgs.join(", ")
        };
        let mut check = RestartCheck::new(Reboot::Yes, Some(&detail));
        check.services = services;
        return check;
    }

    if let Some(m) = KSTA_RE.captures(needrestart) {
        let ksta = &m[1];
        if ksta == "3" {
            let kcur = KCUR_RE.captures(needrestart);
            let kexp = KEXP_RE.captures(needrestart);
            let detail = match (kcur, kexp) {
                (Some(c), Some(e)) => format!("kernel {} → {}", &c[1], &e[1]),
                _ => "needrestart reports an upgraded kernel".to_string(),
            };
            let mut check = RestartCheck::new(Reboot::Yes, Some(&detail));
            check.services = services;
            return check;
        }
        if ksta == "2" {
            let mut check = RestartCheck::new(Reboot::No, Some("ABI-compatible livepatch loaded"));
            check.services = services;
            return check;
        }
        if ksta == "1" {
            let mut check = RestartCheck::new(Reboot::No, None);
            check.services = services;
            return check;
        }
        // KSTA 0 means needrestart could not tell; keep looking.
    }

    // An absent marker only means "no reboot" if something is there to write it.
    if marker == "absent" && get("NOTIFIER").contains("install ok installed") {
        let mut check = RestartCheck::new(Reboot::No, None);
        check.services = services;
        return check;
    }

    let mut verdict = container_reboot_check(get("CONTAINER"))
        .unwrap_or_else(|| kernel_reboot_check(get("RUNNING"), get("NEWEST")));
    verdict.services = services;
    verdict
}

fn archives_are_security(archives_blob: &str) -> bool {
    // The archives blob looks like: "Ubuntu:22.04/jammy-security,Ubuntu:22.04/jammy-updates [amd64]"
    // or "jammy-security [amd64]". We scan every token.
    let blob = archives_blob.replace(',', " ");
    blob.split_whitespace()
        .any(|token| token.trim_end_matches(',').contains("-security"))
}

#[cfg(test)]
pub fn reboot_probe() -> &'static str {
    &REBOOT_PROBE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::os_release::identify_from_os_release;

    #[test]
    fn parse_apt_simulate_mixed_archives() {
        let output = "\
Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages will be upgraded:
  curl openssl vim
3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst curl [7.81.0-1ubuntu1.14] (7.81.0-1ubuntu1.16 Ubuntu:22.04/jammy-security, Ubuntu:22.04/jammy-updates [amd64])
Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])
Inst vim [2:8.2.3995-1ubuntu2.12] (2:8.2.3995-1ubuntu2.13 Ubuntu:22.04/jammy-updates [amd64])
Conf curl (7.81.0-1ubuntu1.16 Ubuntu:22.04/jammy-security [amd64])
";
        let patches = parse_apt_simulate(output);
        let by_pkg: std::collections::HashMap<&str, &Patch> =
            patches.iter().map(|p| (p.package.as_str(), p)).collect();
        let mut names: Vec<&&str> = by_pkg.keys().collect();
        names.sort();
        assert_eq!(names, [&"curl", &"openssl", &"vim"]);
        assert!(by_pkg["curl"].is_security);
        assert!(by_pkg["openssl"].is_security);
        assert!(!by_pkg["vim"].is_security);
        assert_eq!(
            by_pkg["curl"].version.as_deref(),
            Some("7.81.0-1ubuntu1.16")
        );
    }

    #[test]
    fn parse_apt_simulate_no_updates() {
        let output = "\
Reading package lists...
Building dependency tree...
Calculating upgrade...
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
";
        assert!(parse_apt_simulate(output).is_empty());
    }

    #[test]
    fn parse_apt_simulate_without_old_version() {
        // Newly-pulled-in dependencies have no [old] field.
        let output = "Inst libssl3 (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])";
        let patches = parse_apt_simulate(output);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].package, "libssl3");
        assert_eq!(patches[0].version.as_deref(), Some("3.0.2-0ubuntu1.15"));
        assert!(patches[0].is_security);
    }

    #[test]
    fn identify_prefers_pretty_name() {
        let content = "\
NAME=\"Ubuntu\"
VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"
ID=ubuntu
PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"
VERSION_ID=\"22.04\"
";
        assert_eq!(identify_from_os_release(content, "?"), "Ubuntu 22.04.3 LTS");
    }

    #[test]
    fn identify_falls_back_to_name_and_version() {
        let content = "\
NAME=\"Debian GNU/Linux\"
VERSION=\"12 (bookworm)\"
ID=debian
";
        assert_eq!(
            identify_from_os_release(content, "Debian-based"),
            "Debian GNU/Linux 12 (bookworm)"
        );
    }

    #[test]
    fn identify_uses_fallback_when_empty() {
        assert_eq!(identify_from_os_release("", "Debian-based"), "Debian-based");
    }

    struct Probe<'a> {
        marker: &'a str,
        pkgs: &'a str,
        notifier: &'a str,
        needrestart: &'a str,
        container: &'a str,
        running: &'a str,
        newest: &'a str,
    }

    impl Default for Probe<'_> {
        fn default() -> Self {
            Probe {
                marker: "absent",
                pkgs: "",
                notifier: "",
                needrestart: "",
                container: "none",
                running: "",
                newest: "",
            }
        }
    }

    fn probe(p: Probe) -> String {
        format!(
            "### MARKER\n{}\n### PKGS\n{}\n### NOTIFIER\n{}\n### NEEDRESTART\n{}\n\
### CONTAINER\n{}\n### RUNNING\n{}\n### NEWEST\n{}\n",
            p.marker, p.pkgs, p.notifier, p.needrestart, p.container, p.running, p.newest
        )
    }

    #[test]
    fn restarts_marker_lists_packages() {
        let check = parse_debian_restarts(&probe(Probe {
            marker: "present",
            pkgs: "linux-image-6.8.0-52-generic\nlibssl3\n",
            notifier: "install ok installed",
            needrestart: "NEEDRESTART-KSTA: 1",
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::Yes);
        assert_eq!(
            check.reboot_detail.as_deref(),
            Some("linux-image-6.8.0-52-generic, libssl3")
        );
    }

    #[test]
    fn restarts_marker_without_pkgs_file() {
        let check = parse_debian_restarts(&probe(Probe {
            marker: "present",
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::Yes);
        assert!(check.reboot_detail.unwrap().contains("reboot-required"));
    }

    #[test]
    fn restarts_notifier_installed_and_no_marker() {
        let check = parse_debian_restarts(&probe(Probe {
            marker: "absent",
            notifier: "install ok installed",
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::No);
    }

    #[test]
    fn restarts_needrestart_kernel_upgraded() {
        let needrestart = "\
NEEDRESTART-VER: 3.5
NEEDRESTART-KCUR: 6.8.0-45-generic
NEEDRESTART-KEXP: 6.8.0-52-generic
NEEDRESTART-KSTA: 3
NEEDRESTART-SVC: cron.service
";
        let check = parse_debian_restarts(&probe(Probe {
            needrestart,
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::Yes);
        assert_eq!(
            check.reboot_detail.as_deref(),
            Some("kernel 6.8.0-45-generic → 6.8.0-52-generic")
        );
    }

    #[test]
    fn restarts_livepatch_does_not_need_reboot() {
        let needrestart = "NEEDRESTART-KCUR: 6.8.0-45-generic\nNEEDRESTART-KSTA: 2\n";
        // Kernels differ, but the livepatch verdict must win over the fallback.
        let check = parse_debian_restarts(&probe(Probe {
            needrestart,
            running: "6.8.0-45-generic",
            newest: "6.8.0-52-generic",
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::No);
        assert!(check.reboot_detail.unwrap().contains("livepatch"));
    }

    #[test]
    fn restarts_falls_back_to_kernel_comparison() {
        let check = parse_debian_restarts(&probe(Probe {
            running: "6.8.0-45-generic",
            newest: "6.8.0-52-generic",
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::Yes);
        assert_eq!(
            check.reboot_detail.as_deref(),
            Some("kernel 6.8.0-45-generic → 6.8.0-52-generic")
        );

        let same = parse_debian_restarts(&probe(Probe {
            running: "6.8.0-52-generic",
            newest: "6.8.0-52-generic",
            ..Default::default()
        }));
        assert_eq!(same.reboot, Reboot::No);
    }

    #[test]
    fn restarts_unknown_when_nothing_reports() {
        // Minimal image: no marker hooks, no needrestart, no /boot listing.
        assert_eq!(
            parse_debian_restarts(&probe(Probe::default())).reboot,
            Reboot::Unknown
        );
        assert_eq!(parse_debian_restarts("").reboot, Reboot::Unknown);
    }

    #[test]
    fn restarts_lxc_container_never_needs_one() {
        // Recorded from an Ubuntu LXC guest on Proxmox: needrestart runs but omits
        // its kernel verdict, uname reports the *host's* kernel, and /boot is empty.
        let output = "\
### MARKER
absent
### PKGS
### NOTIFIER

### NEEDRESTART
NEEDRESTART-VER: 3.6
NEEDRESTART-SVC: cron.service
NEEDRESTART-SVC: dbus.service
NEEDRESTART-SESS: martin @ user manager service
### CONTAINER
lxc
### RUNNING
7.0.14-11-pve
### NEWEST
";
        let check = parse_debian_restarts(output);
        assert_eq!(check.reboot, Reboot::No);
        assert_eq!(
            check.reboot_detail.as_deref(),
            Some("lxc container: kernel belongs to the host")
        );
    }

    #[test]
    fn restarts_container_marker_still_wins() {
        let check = parse_debian_restarts(&probe(Probe {
            marker: "present",
            pkgs: "libssl3",
            container: "lxc",
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::Yes);
        assert_eq!(check.reboot_detail.as_deref(), Some("libssl3"));
    }

    #[test]
    fn restarts_container_probe_absent_or_none() {
        // systemd-detect-virt missing (empty) or reporting a real machine ("none")
        // must both leave the kernel comparison in charge.
        for container in ["", "none"] {
            let check = parse_debian_restarts(&probe(Probe {
                container,
                running: "6.8.0-45-generic",
                newest: "6.8.0-52-generic",
                ..Default::default()
            }));
            assert_eq!(check.reboot, Reboot::Yes, "container={container:?}");
        }
    }

    #[test]
    fn restarts_collects_service_units() {
        let needrestart = "\
NEEDRESTART-VER: 3.6
NEEDRESTART-SVC: cron.service
NEEDRESTART-SVC: dbus.service
NEEDRESTART-SVC: postfix@-.service
NEEDRESTART-SESS: martin @ user manager service
NEEDRESTART-KSTA: 1
";
        let check = parse_debian_restarts(&probe(Probe {
            needrestart,
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::No);
        // Sessions are not units and cannot be restarted, so they must not appear.
        assert_eq!(
            check.services,
            ["cron.service", "dbus.service", "postfix@-.service"]
        );
    }

    #[test]
    fn restarts_reports_services_alongside_a_reboot() {
        let needrestart = "NEEDRESTART-SVC: cron.service\nNEEDRESTART-KSTA: 3\n";
        let check = parse_debian_restarts(&probe(Probe {
            marker: "present",
            needrestart,
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::Yes);
        assert_eq!(check.services, ["cron.service"]);
    }

    #[test]
    fn restarts_services_survive_the_container_verdict() {
        // The exact shape seen on an LXC guest: no KSTA, but plenty of stale units.
        let needrestart = "NEEDRESTART-VER: 3.6\nNEEDRESTART-SVC: cron.service\n";
        let check = parse_debian_restarts(&probe(Probe {
            needrestart,
            container: "lxc",
            ..Default::default()
        }));
        assert_eq!(check.reboot, Reboot::No);
        assert_eq!(check.services, ["cron.service"]);
    }
}
