use std::collections::HashMap;

use crate::errors::DarnError;
use crate::ssh::SshSession;

/// Whether the host's os-release names one of the family's IDs, in ID or
/// ID_LIKE. The predicate is the only thing that differs between the two
/// Linux handlers' `matches`.
pub fn matches_os_release(
    session: &mut SshSession<'_>,
    is_family_id: impl Fn(&str) -> bool,
) -> Result<bool, DarnError> {
    let res = session.probe("cat /etc/os-release 2>/dev/null || true", false, false)?;
    if res.exit_code != 0 || res.stdout.is_empty() {
        return Ok(false);
    }
    let fields = parse_os_release(&res.stdout);
    let id = fields.get("ID").map(String::as_str).unwrap_or("");
    let id_like = fields.get("ID_LIKE").map(String::as_str).unwrap_or("");
    Ok(std::iter::once(id)
        .chain(id_like.split_whitespace())
        .any(is_family_id))
}

pub fn parse_os_release(content: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (k, v) = line.split_once('=').unwrap();
        let v = v.trim().trim_matches('"').trim_matches('\'');
        fields.insert(k.trim().to_string(), v.to_string());
    }
    fields
}

pub fn identify_from_os_release(content: &str, fallback: &str) -> String {
    let fields = parse_os_release(content);
    if let Some(pretty) = fields.get("PRETTY_NAME").filter(|s| !s.is_empty()) {
        return pretty.clone();
    }
    let name = fields
        .get("NAME")
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .unwrap_or(fallback);
    let version = fields
        .get("VERSION")
        .filter(|s| !s.is_empty())
        .or_else(|| fields.get("VERSION_ID").filter(|s| !s.is_empty()))
        .map(String::as_str)
        .unwrap_or("");
    format!("{name} {version}").trim().to_string()
}
