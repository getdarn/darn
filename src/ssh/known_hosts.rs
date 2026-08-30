//! Reading known_hosts: which files to consult, matching entries to a host
//! (hashed, globbed and bracketed forms included), and steering libssh2's
//! host key negotiation towards a key we can verify.

use std::path::PathBuf;

use ssh2::{CheckResult, KnownHostFileKind, Session};

use super::ConnectErr;

pub(crate) fn known_hosts_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(home) = dirs::home_dir() {
        files.push(home.join(".ssh").join("known_hosts"));
    }
    files.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    files
}

/// Host key algorithms in OpenSSH's own order of preference.
const SUPPORTED_HOSTKEY_ALGORITHMS: [&str; 8] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
];

/// The host key algorithms to offer, with the types already stored in
/// known_hosts for this host first — mirroring OpenSSH's behaviour so the
/// server presents a key we can actually verify.
pub(super) fn preferred_hostkey_algorithms(hostname: &str, port: u16) -> Option<String> {
    let mut stored_types: Vec<String> = Vec::new();
    for file in known_hosts_files() {
        let Ok(content) = std::fs::read_to_string(&file) else {
            continue;
        };
        for key_type in stored_key_types(&content, hostname, port) {
            if !stored_types.contains(&key_type) {
                stored_types.push(key_type);
            }
        }
    }
    if stored_types.is_empty() {
        // First contact, so there is no stored type to match. Ask in
        // OpenSSH's order anyway: the key darn then shows and records is the
        // one `ssh` would have shown for the same host, which is what makes
        // comparing the two fingerprints meaningful.
        return Some(SUPPORTED_HOSTKEY_ALGORITHMS.join(","));
    }
    let algs = expand_and_order(&stored_types);
    if algs.is_empty() {
        None
    } else {
        Some(algs)
    }
}

/// Build the negotiation list: the stored key types first (an ssh-rsa key
/// verifies the rsa-sha2-* signature variants too), then the remaining
/// algorithms libssh2 supports as fallbacks, so an unknown host still
/// handshakes and then fails the known-hosts check with a useful message.
fn expand_and_order(stored_types: &[String]) -> String {
    const SUPPORTED: [&str; 8] = SUPPORTED_HOSTKEY_ALGORITHMS;
    let mut algs: Vec<&str> = Vec::new();
    for key_type in stored_types {
        let expanded: &[&str] = match key_type.as_str() {
            "ssh-rsa" => &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
            other => match SUPPORTED.iter().find(|a| **a == other) {
                Some(alg) => std::slice::from_ref(alg),
                None => &[],
            },
        };
        for alg in expanded {
            if !algs.contains(alg) {
                algs.push(alg);
            }
        }
    }
    if algs.is_empty() {
        return String::new();
    }
    for alg in SUPPORTED {
        if !algs.contains(&alg) {
            algs.push(alg);
        }
    }
    algs.join(",")
}

/// Key types of known_hosts entries matching `hostname`/`port`, in file order.
pub(super) fn stored_key_types(content: &str, hostname: &str, port: u16) -> Vec<String> {
    // A bare hostname entry means port 22; other ports only match the
    // bracketed form, as in OpenSSH.
    let bracketed = format!("[{hostname}]:{port}");
    let mut candidates = vec![bracketed];
    if port == 22 {
        candidates.push(hostname.to_string());
    }
    let mut types = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut patterns = fields.next().unwrap_or("");
        // Skip marker lines (@cert-authority, @revoked): not plain host keys.
        if patterns.starts_with('@') {
            continue;
        }
        let Some(key_type) = fields.next() else {
            continue;
        };
        if !key_type.starts_with("ssh-") && !key_type.starts_with("ecdsa-") {
            continue; // e.g. legacy "1024 35 ..." RSA1 lines
        }
        if patterns.starts_with("|1|") {
            if candidates.iter().any(|c| hashed_entry_matches(patterns, c)) {
                types.push(key_type.to_string());
            }
            continue;
        }
        // Comma-separated glob patterns; negations exclude the whole line.
        let mut matched = false;
        let mut negated = false;
        loop {
            let (pattern, rest) = match patterns.split_once(',') {
                Some((p, r)) => (p, Some(r)),
                None => (patterns, None),
            };
            let (pattern, negate) = match pattern.strip_prefix('!') {
                Some(p) => (p, true),
                None => (pattern, false),
            };
            if candidates.iter().any(|c| glob_match(pattern, c)) {
                if negate {
                    negated = true;
                } else {
                    matched = true;
                }
            }
            match rest {
                Some(r) => patterns = r,
                None => break,
            }
        }
        if matched && !negated {
            types.push(key_type.to_string());
        }
    }
    types
}

/// Match a hashed `|1|salt|hash` known_hosts pattern: HMAC-SHA1(salt, host).
fn hashed_entry_matches(pattern: &str, hostname: &str) -> bool {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let mut parts = pattern.splitn(4, '|');
    let (_, magic, salt_b64, hash_b64) = (parts.next(), parts.next(), parts.next(), parts.next());
    if magic != Some("1") {
        return false;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let (Some(salt), Some(hash)) = (
        salt_b64.and_then(|s| engine.decode(s).ok()),
        hash_b64.and_then(|s| engine.decode(s).ok()),
    ) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha1::Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(hostname.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

/// OpenSSH-style host pattern match: `*` and `?` wildcards, case-insensitive.
pub(crate) fn glob_match(pattern: &str, host: &str) -> bool {
    fn inner(p: &[u8], h: &[u8]) -> bool {
        match (p.first(), h.first()) {
            (None, None) => true,
            (Some(b'*'), _) => inner(&p[1..], h) || (!h.is_empty() && inner(p, &h[1..])),
            (Some(b'?'), Some(_)) => inner(&p[1..], &h[1..]),
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b) && inner(&p[1..], &h[1..]),
            _ => false,
        }
    }
    inner(pattern.as_bytes(), host.as_bytes())
}

pub(super) fn check_known_hosts(
    sess: &Session,
    hostname: &str,
    port: u16,
) -> Result<(), ConnectErr> {
    let mut kh = sess
        .known_hosts()
        .map_err(|e| ConnectErr::Other(e.to_string()))?;
    for file in known_hosts_files() {
        // Missing files are fine; paramiko's load_system_host_keys ignores them too.
        let _ = kh.read_file(&file, KnownHostFileKind::OpenSSH);
    }

    let (key, _key_type) = sess
        .host_key()
        .ok_or_else(|| ConnectErr::Other("server presented no host key".to_string()))?;
    match kh.check_port(hostname, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err(ConnectErr::Other(format!(
            "host key mismatch for '{hostname}' (possible MITM); fix ~/.ssh/known_hosts"
        ))),
        CheckResult::NotFound => Err(ConnectErr::UnknownHostKey(format!(
            "server '{hostname}' not found in known_hosts; connect once with ssh to accept its key"
        ))),
        // Not a first contact: libssh2 could not perform the comparison at
        // all, and offering to record a key would paper over that.
        CheckResult::Failure => Err(ConnectErr::Other(format!(
            "could not check the host key for '{hostname}' against known_hosts"
        ))),
    }
}

#[cfg(test)]
mod known_hosts_tests {
    use super::*;

    #[test]
    fn plain_entries_match_by_name_and_port() {
        let content = "\
example.com ssh-ed25519 AAAAkey1 comment
other.com ssh-rsa AAAAkey2
[example.com]:2222 ecdsa-sha2-nistp256 AAAAkey3
";
        assert_eq!(
            stored_key_types(content, "example.com", 22),
            ["ssh-ed25519"]
        );
        assert_eq!(
            stored_key_types(content, "example.com", 2222),
            ["ecdsa-sha2-nistp256"]
        );
        assert!(stored_key_types(content, "nowhere.com", 22).is_empty());
    }

    #[test]
    fn comma_lists_globs_and_negations() {
        let content = "\
web-*,!web-03 ssh-ed25519 AAAAkey
?db.example.com ecdsa-sha2-nistp384 AAAAkey
";
        assert_eq!(stored_key_types(content, "web-01", 22), ["ssh-ed25519"]);
        assert!(stored_key_types(content, "web-03", 22).is_empty());
        assert_eq!(
            stored_key_types(content, "adb.example.com", 22),
            ["ecdsa-sha2-nistp384"]
        );
    }

    #[test]
    fn markers_comments_and_legacy_lines_are_skipped() {
        let content = "\
# a comment
@cert-authority example.com ssh-rsa AAAAca
@revoked example.com ssh-ed25519 AAAAbad
example.com 1024 35 1234567890
";
        assert!(stored_key_types(content, "example.com", 22).is_empty());
    }

    #[test]
    fn hashed_entries_match_via_hmac() {
        // Vectors: HMAC-SHA1 with salt 0x00..0x13 over the hostname.
        let content = "\
|1|AAECAwQFBgcICQoLDA0ODxAREhM=|nnUK16ANsXd3hL31YfAkGOluSjU= ssh-ed25519 AAAAkey
|1|AAECAwQFBgcICQoLDA0ODxAREhM=|Wgcx+Fm+LmaWwC7rQ80eIf2uHe0= ssh-rsa AAAAkey2
";
        assert_eq!(
            stored_key_types(content, "example.com", 22),
            ["ssh-ed25519"]
        );
        assert_eq!(stored_key_types(content, "example.com", 2222), ["ssh-rsa"]);
        assert!(stored_key_types(content, "other.com", 22).is_empty());
    }

    #[test]
    fn rsa_expands_to_sha2_signature_variants() {
        // Exercise the expansion logic through a temp known_hosts? The file
        // list is fixed, so test the pure pieces instead.
        let types = stored_key_types("h ssh-rsa AAAAkey\n", "h", 22);
        assert_eq!(types, ["ssh-rsa"]);
        // Expansion itself is covered by preferred order construction below.
        let algs = super::expand_and_order(&types);
        assert!(algs.starts_with("rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-ed25519"));
    }

    #[test]
    fn stored_type_leads_the_preference_list() {
        let algs = super::expand_and_order(&["ssh-ed25519".to_string()]);
        assert!(algs.starts_with("ssh-ed25519,"));
        assert!(algs.contains("rsa-sha2-512"));
    }
}
