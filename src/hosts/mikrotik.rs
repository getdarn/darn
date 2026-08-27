use std::collections::HashMap;

use crate::db::Patch;
use crate::errors::DarnError;
use crate::hosts::{HostHandler, Reboot, RestartCheck};
use crate::ssh::SshSession;

pub struct MikrotikHandler;

impl HostHandler for MikrotikHandler {
    fn type_name(&self) -> &'static str {
        "mikrotik"
    }

    fn matches(&self, session: &mut SshSession<'_>) -> Result<bool, DarnError> {
        let res = session.probe("/system resource print", false, false)?;
        if res.exit_code != 0 {
            return Ok(false);
        }
        Ok(res.stdout.contains("RouterOS") || res.stdout.to_lowercase().contains("platform:"))
    }

    fn identify(&self, session: &mut SshSession<'_>) -> Result<String, DarnError> {
        let res = session.probe("/system resource print", false, false)?;
        Ok(parse_mikrotik_identity(&res.stdout))
    }

    fn discover(&self, session: &mut SshSession<'_>) -> Result<Vec<Patch>, DarnError> {
        let res = session.probe("/system package update check-for-updates", false, true)?;
        Ok(parse_mikrotik_check(&res.stdout))
    }

    fn upgrade(
        &self,
        session: &mut SshSession<'_>,
        security: bool,
        non_security: bool,
        _known_patches: &[Patch],
    ) -> Result<(), DarnError> {
        if security || non_security {
            return Err(DarnError::Unsupported(
                "Mikrotik RouterOS does not distinguish security patches; \
run without --security / --non-security"
                    .to_string(),
            ));
        }
        // Triggers a reboot to apply the downloaded firmware.
        session.run("/system package update install", false, true)?;
        Ok(())
    }

    fn check_restarts(&self, _session: &mut SshSession<'_>) -> Result<RestartCheck, DarnError> {
        // RouterOS reboots as part of installing an update, so an update can
        // never be sitting installed-but-not-applied, and it has no notion of
        // individually restartable services running against stale libraries.
        Ok(RestartCheck::new(Reboot::No, None))
    }

    fn reboot(&self, session: &mut SshSession<'_>) -> Result<(), DarnError> {
        match session.run("/system reboot", false, false) {
            // The connection dropping as the router goes down is expected.
            Ok(_) | Err(DarnError::Ssh(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn restart_services(
        &self,
        _session: &mut SshSession<'_>,
        _services: &[String],
        _force: bool,
    ) -> Result<(), DarnError> {
        Err(DarnError::Unsupported(
            "Mikrotik RouterOS has no individually restartable services; \
reboot the router instead"
                .to_string(),
        ))
    }
}

fn parse_colon_fields(output: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for raw in output.lines() {
        let line = raw.trim();
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        fields.insert(k.trim().to_lowercase(), v.trim().to_string());
    }
    fields
}

/// Parse `/system package update check-for-updates` output.
///
/// Example relevant fields in output:
///     installed-version: 7.14.1
///     latest-version: 7.14.3
///     status: New version is available
pub fn parse_mikrotik_check(output: &str) -> Vec<Patch> {
    let fields = parse_colon_fields(output);
    let status = fields
        .get("status")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let latest = fields
        .get("latest-version")
        .or_else(|| fields.get("latest"))
        .filter(|s| !s.is_empty());
    if status.contains("new version is available") {
        if let Some(latest) = latest {
            return vec![Patch {
                package: "routeros".to_string(),
                version: Some(latest.clone()),
                is_security: false,
            }];
        }
    }
    Vec::new()
}

/// Pull the RouterOS version from `/system resource print` output.
pub fn parse_mikrotik_identity(output: &str) -> String {
    let fields = parse_colon_fields(output);
    match fields.get("version").filter(|s| !s.is_empty()) {
        Some(version) => format!("RouterOS {version}"),
        None => "RouterOS".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_version_available() {
        let output = "\
                 channel: stable
       installed-version: 7.14.1
          latest-version: 7.14.3
                  status: New version is available
";
        let patches = parse_mikrotik_check(output);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].package, "routeros");
        assert_eq!(patches[0].version.as_deref(), Some("7.14.3"));
        assert!(!patches[0].is_security);
    }

    #[test]
    fn up_to_date() {
        let output = "\
                 channel: stable
       installed-version: 7.14.3
                  status: System is already up to date
";
        assert!(parse_mikrotik_check(output).is_empty());
    }

    #[test]
    fn identity() {
        let output = "\
               uptime: 1w2d3h
              version: 7.14.1 (stable)
           build-time: May/15/2024 08:00:00
             platform: MikroTik
                board: RB4011iGS+5HacQ2HnD
";
        assert_eq!(parse_mikrotik_identity(output), "RouterOS 7.14.1 (stable)");
    }

    #[test]
    fn identity_falls_back_when_missing() {
        assert_eq!(parse_mikrotik_identity(""), "RouterOS");
    }
}
