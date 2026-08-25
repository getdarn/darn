//! The YAML file behind `darn server export` and `darn server import`.
//!
//! What goes in the file is configuration — what you told darn about a host —
//! and nothing else. Pending patches, reboot verdicts and the last-update
//! timestamp are discovered state owned by `darn update`, so exporting them
//! would produce a file that goes stale the moment it is written and an
//! import that quietly asserted things about hosts it never contacted.
//!
//! Everything here is pure: parsing, validating and rendering, no database and
//! no filesystem. The commands in `commands::server` do the I/O around it.

use serde::{Deserialize, Serialize};

use crate::db::Server;
use crate::errors::DarnError;
use crate::hosts::{get_handler, ALL_HANDLERS};

/// The only format version we write, and the only one we read.
///
/// A version that is not this one is an error rather than a best effort: a
/// file from a future darn may mean something different by a field we think we
/// understand, and silently importing it would be worse than refusing.
const VERSION: u32 = 1;

fn default_version() -> u32 {
    VERSION
}

fn default_port() -> u16 {
    22
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerFile {
    #[serde(default = "default_version")]
    pub version: u32,
    pub servers: Vec<ServerEntry>,
}

/// One host, as the file spells it.
///
/// The defaults are what make a file worth hand-writing: `hostname` and
/// `host_type` are the only fields that must be there, and the rest fall back
/// to the same values `darn server add` would have used. An export writes them
/// all out anyway, so a round trip loses nothing.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerEntry {
    pub hostname: String,
    #[serde(default = "crate::target::current_user")]
    pub ssh_user: String,
    #[serde(default = "default_port")]
    pub ssh_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_path: Option<String>,
    pub host_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
    #[serde(default)]
    pub no_all: bool,
}

impl From<&Server> for ServerEntry {
    fn from(s: &Server) -> Self {
        ServerEntry {
            hostname: s.hostname.clone(),
            ssh_user: s.ssh_user.clone(),
            ssh_port: s.ssh_port,
            ssh_key_path: s.ssh_key_path.clone(),
            host_type: s.host_type.clone(),
            distribution: s.distribution.clone(),
            no_all: s.no_all,
        }
    }
}

/// Render the managed servers as the file's YAML.
///
/// Callers pass `db::list_servers`, which is ordered by hostname, so a
/// re-export of an unchanged fleet is byte-identical and diffs cleanly.
pub fn to_yaml(servers: &[Server]) -> Result<String, DarnError> {
    let file = ServerFile {
        version: VERSION,
        servers: servers.iter().map(ServerEntry::from).collect(),
    };
    serde_norway::to_string(&file)
        .map_err(|e| DarnError::Other(format!("cannot render server file: {e}")))
}

/// Parse and validate a server file, returning its entries.
///
/// Validation is all-or-nothing and happens before any caller touches the
/// database, so a file with one bad host imports nothing rather than half a
/// fleet.
pub fn from_yaml(text: &str) -> Result<Vec<ServerEntry>, DarnError> {
    let file: ServerFile = serde_norway::from_str(text)
        .map_err(|e| DarnError::Other(format!("invalid server file: {e}")))?;
    if file.version != VERSION {
        return Err(DarnError::Other(format!(
            "invalid server file: version {} is not supported (this darn writes and reads version {VERSION})",
            file.version
        )));
    }

    let mut seen: Vec<&str> = Vec::with_capacity(file.servers.len());
    for entry in &file.servers {
        if entry.hostname.trim().is_empty() {
            return Err(DarnError::Other(
                "invalid server file: a server has an empty hostname".to_string(),
            ));
        }
        if entry.hostname.trim() != entry.hostname {
            return Err(DarnError::Other(format!(
                "invalid server file: hostname '{}' has leading or trailing whitespace",
                entry.hostname
            )));
        }
        if entry.ssh_user.is_empty() {
            return Err(DarnError::Other(format!(
                "invalid server file: {} has an empty ssh_user",
                entry.hostname
            )));
        }
        // Reuse the handler registry so the accepted types cannot drift from
        // the ones darn can actually drive.
        if get_handler(&entry.host_type).is_err() {
            let known: Vec<&str> = ALL_HANDLERS.iter().map(|h| h.type_name()).collect();
            return Err(DarnError::Other(format!(
                "invalid server file: {} has unknown host_type '{}' (expected one of: {})",
                entry.hostname,
                entry.host_type,
                known.join(", ")
            )));
        }
        if seen.contains(&entry.hostname.as_str()) {
            return Err(DarnError::Other(format!(
                "invalid server file: {} appears more than once",
                entry.hostname
            )));
        }
        seen.push(&entry.hostname);
    }

    Ok(file.servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(hostname: &str) -> Server {
        Server {
            hostname: hostname.to_string(),
            ssh_user: "admin".to_string(),
            ssh_port: 2222,
            ssh_key_path: Some("~/.ssh/id_ed25519".to_string()),
            host_type: "debian".to_string(),
            distribution: Some("Ubuntu 24.04".to_string()),
            last_update_at: Some("2026-08-25T10:00:00+00:00".to_string()),
            last_update_ok: Some(1),
            reboot_required: Some("yes".to_string()),
            reboot_detail: Some("kernel updated".to_string()),
            no_all: true,
        }
    }

    #[test]
    fn every_configured_field_survives_a_round_trip() {
        let yaml = to_yaml(&[server("web-01")]).unwrap();
        let entries = from_yaml(&yaml).unwrap();
        assert_eq!(entries, vec![ServerEntry::from(&server("web-01"))]);
    }

    #[test]
    fn discovered_state_is_not_exported() {
        let yaml = to_yaml(&[server("web-01")]).unwrap();
        for field in [
            "last_update_at",
            "last_update_ok",
            "reboot_required",
            "reboot_detail",
        ] {
            assert!(!yaml.contains(field), "{field} leaked into {yaml}");
        }
    }

    #[test]
    fn an_empty_fleet_still_writes_a_readable_file() {
        let yaml = to_yaml(&[]).unwrap();
        assert!(from_yaml(&yaml).unwrap().is_empty());
    }

    #[test]
    fn absent_fields_fall_back_to_what_server_add_would_have_used() {
        let entries = from_yaml(
            "version: 1
servers:
  - hostname: web-01
    host_type: debian
",
        )
        .unwrap();
        assert_eq!(entries[0].ssh_user, crate::target::current_user());
        assert_eq!(entries[0].ssh_port, 22);
        assert_eq!(entries[0].ssh_key_path, None);
        assert_eq!(entries[0].distribution, None);
        assert!(!entries[0].no_all);
    }

    #[test]
    fn nulls_are_accepted_where_the_value_is_optional() {
        let entries = from_yaml(
            "version: 1
servers:
  - hostname: web-01
    host_type: debian
    ssh_key_path: null
    distribution: null
",
        )
        .unwrap();
        assert_eq!(entries[0].ssh_key_path, None);
    }

    #[test]
    fn an_omitted_version_is_taken_as_the_current_one() {
        let entries = from_yaml(
            "servers:
  - hostname: web-01
    host_type: debian
",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
    }

    fn error(text: &str) -> String {
        from_yaml(text).unwrap_err().to_string()
    }

    #[test]
    fn a_misspelt_field_is_refused_rather_than_dropped() {
        let msg = error(
            "version: 1
servers:
  - hostname: web-01
    host_type: debian
    hostame: web-02
",
        );
        assert!(msg.contains("hostame"), "{msg}");
    }

    #[test]
    fn an_unknown_host_type_names_the_ones_that_work() {
        let msg = error(
            "version: 1
servers:
  - hostname: web-01
    host_type: windows
",
        );
        assert!(msg.contains("windows") && msg.contains("debian"), "{msg}");
    }

    #[test]
    fn a_duplicated_hostname_is_refused() {
        let msg = error(
            "version: 1
servers:
  - hostname: web-01
    host_type: debian
  - hostname: web-01
    host_type: redhat
",
        );
        assert!(msg.contains("more than once"), "{msg}");
    }

    #[test]
    fn an_empty_hostname_is_refused() {
        let msg = error(
            "version: 1
servers:
  - hostname: ''
    host_type: debian
",
        );
        assert!(msg.contains("empty hostname"), "{msg}");
    }

    #[test]
    fn a_future_version_is_refused() {
        let msg = error(
            "version: 2
servers: []
",
        );
        assert!(msg.contains("version 2"), "{msg}");
    }

    #[test]
    fn a_file_that_is_not_this_format_is_refused() {
        assert!(error("just a string").contains("invalid server file"));
    }
}
