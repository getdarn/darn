use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ssh2::{CheckResult, KnownHostFileKind, Session};

use crate::errors::DarnError;

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct CommandResult {
    #[allow(dead_code)] // mirrors the darn3 CommandResult shape
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    #[allow(dead_code)]
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }
}

/// Called with (command, stdout, stderr, exit_code) after every executed
/// command; the hostname is captured by the closure.
pub type Recorder<'a> = Box<dyn Fn(&str, &str, &str, i64) + 'a>;

/// SSH session that logs every command via a recorder callback.
///
/// Not thread-safe; create one per worker thread. Authentication never
/// prompts: explicit key file, then the SSH agent, then the default
/// ~/.ssh/id_* keys. Unknown or mismatched host keys are rejected.
pub struct SshSession<'a> {
    pub hostname: String,
    user: String,
    recorder: Option<Recorder<'a>>,
    sess: Session,
}

impl<'a> SshSession<'a> {
    pub fn connect(
        hostname: &str,
        user: &str,
        port: u16,
        key_path: Option<&str>,
        recorder: Option<Recorder<'a>>,
        connect_timeout: Duration,
    ) -> Result<Self, DarnError> {
        let sess = Self::connect_inner(hostname, user, port, key_path, connect_timeout)
            .map_err(|e| DarnError::Ssh(format!("failed to connect to {hostname}: {e}")))?;
        Ok(SshSession {
            hostname: hostname.to_string(),
            user: user.to_string(),
            recorder,
            sess,
        })
    }

    fn connect_inner(
        hostname: &str,
        user: &str,
        port: u16,
        key_path: Option<&str>,
        connect_timeout: Duration,
    ) -> Result<Session, String> {
        let addrs = (hostname, port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?;
        let mut stream = None;
        let mut last_err = "no addresses resolved".to_string();
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, connect_timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last_err = e.to_string(),
            }
        }
        let stream = stream.ok_or(last_err)?;

        let mut sess = Session::new().map_err(|e| e.to_string())?;
        sess.set_timeout(connect_timeout.as_millis() as u32);
        // Prefer the host key types our known_hosts already stores for this
        // host, as OpenSSH does. Without this, libssh2 may negotiate a key
        // type different from the stored one, and the later comparison would
        // wrongly report a mismatch.
        if let Some(prefs) = preferred_hostkey_algorithms(hostname, port) {
            let _ = sess.method_pref(ssh2::MethodType::HostKey, &prefs);
        }
        sess.set_tcp_stream(stream);
        sess.handshake().map_err(|e| e.to_string())?;

        check_known_hosts(&sess, hostname, port)?;
        authenticate(&sess, user, key_path)?;

        // From here on, blocking calls are bounded by the command timeout.
        sess.set_timeout(COMMAND_TIMEOUT.as_millis() as u32);
        Ok(sess)
    }

    pub fn run(&mut self, command: &str, sudo: bool, check: bool) -> Result<CommandResult, DarnError> {
        let full_cmd = if sudo { self.with_sudo(command) } else { command.to_string() };

        let exec = || -> Result<(String, String, i32), String> {
            let mut ch = self.sess.channel_session().map_err(|e| e.to_string())?;
            ch.exec(&full_cmd).map_err(|e| e.to_string())?;
            let _ = ch.send_eof();
            // libssh2 buffers the stream not currently being read, so full
            // sequential reads cannot deadlock the way raw pipes would.
            let mut out_raw = Vec::new();
            let mut err_raw = Vec::new();
            ch.read_to_end(&mut out_raw).map_err(|e| e.to_string())?;
            ch.stderr()
                .read_to_end(&mut err_raw)
                .map_err(|e| e.to_string())?;
            let _ = ch.close();
            let _ = ch.wait_close();
            let code = ch.exit_status().map_err(|e| e.to_string())?;
            Ok((
                String::from_utf8_lossy(&out_raw).into_owned(),
                String::from_utf8_lossy(&err_raw).into_owned(),
                code,
            ))
        };
        let (stdout, stderr, exit_code) = exec()
            .map_err(|e| DarnError::Ssh(format!("command failed to execute: {e}")))?;

        if let Some(recorder) = &self.recorder {
            recorder(&full_cmd, &stdout, &stderr, exit_code as i64);
        }

        if check && exit_code != 0 {
            return Err(DarnError::Ssh(format!(
                "{}: command exited {exit_code}: {full_cmd}\n{stderr}",
                self.hostname
            )));
        }
        Ok(CommandResult {
            command: full_cmd,
            exit_code,
            stdout,
            stderr,
        })
    }

    fn with_sudo(&self, command: &str) -> String {
        if self.user == "root" {
            return command.to_string();
        }
        format!("sudo -n -- sh -c {}", crate::quote::sh_quote(command))
    }
}

// Dropping the ssh2 Session sends a disconnect and swallows errors, which is
// what we want: the peer may already be gone — e.g. we just rebooted it.

pub(crate) fn known_hosts_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(home) = dirs::home_dir() {
        files.push(home.join(".ssh").join("known_hosts"));
    }
    files.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    files
}

/// The host key algorithms to offer, with the types already stored in
/// known_hosts for this host first — mirroring OpenSSH's behaviour so the
/// server presents a key we can actually verify. None when nothing matched.
fn preferred_hostkey_algorithms(hostname: &str, port: u16) -> Option<String> {
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
        return None;
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
    const SUPPORTED: [&str; 8] = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        "ssh-dss",
    ];
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
fn stored_key_types(content: &str, hostname: &str, port: u16) -> Vec<String> {
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
    let (_, magic, salt_b64, hash_b64) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    );
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

fn check_known_hosts(sess: &Session, hostname: &str, port: u16) -> Result<(), String> {
    let mut kh = sess.known_hosts().map_err(|e| e.to_string())?;
    for file in known_hosts_files() {
        // Missing files are fine; paramiko's load_system_host_keys ignores them too.
        let _ = kh.read_file(&file, KnownHostFileKind::OpenSSH);
    }

    let (key, _key_type) = sess
        .host_key()
        .ok_or_else(|| "server presented no host key".to_string())?;
    match kh.check_port(hostname, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err(format!(
            "host key mismatch for '{hostname}' (possible MITM); fix ~/.ssh/known_hosts"
        )),
        CheckResult::NotFound | CheckResult::Failure => Err(format!(
            "server '{hostname}' not found in known_hosts; connect once with ssh to accept its key"
        )),
    }
}

fn authenticate(sess: &Session, user: &str, key_path: Option<&str>) -> Result<(), String> {
    // Explicit key first, then the agent, then the default keys — paramiko's order.
    if let Some(key) = key_path {
        let path = expand_tilde(key);
        sess.userauth_pubkey_file(user, None, &path, None)
            .map_err(|e| format!("authentication with key {key} failed: {e}"))?;
        if sess.authenticated() {
            return Ok(());
        }
    }

    if let Ok(mut agent) = sess.agent() {
        if agent.connect().is_ok() && agent.list_identities().is_ok() {
            if let Ok(identities) = agent.identities() {
                for identity in identities {
                    if agent.userauth(user, &identity).is_ok() && sess.authenticated() {
                        return Ok(());
                    }
                }
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        for name in ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"] {
            let path = home.join(".ssh").join(name);
            if path.exists()
                && sess.userauth_pubkey_file(user, None, &path, None).is_ok()
                && sess.authenticated()
            {
                return Ok(());
            }
        }
    }

    if sess.authenticated() {
        Ok(())
    } else {
        Err("Authentication failed.".to_string())
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    Path::new(path).to_path_buf()
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
        assert_eq!(stored_key_types(content, "example.com", 22), ["ssh-ed25519"]);
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
        assert_eq!(stored_key_types(content, "example.com", 22), ["ssh-ed25519"]);
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

#[cfg(test)]
mod quoting_parity_tests {
    // One-off parity check against Python shlex.quote output; reads the
    // fixture produced in the scratchpad. Skipped when the file is absent.
    #[test]
    fn sudo_quoting_matches_python() {
        let path = std::env::var("DARN_PY_QUOTED").unwrap_or_default();
        if path.is_empty() {
            return;
        }
        let expected = std::fs::read_to_string(path).unwrap();
        let apt = crate::hosts::apt::reboot_probe();
        let rh = crate::hosts::redhat::reboot_probe();
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
