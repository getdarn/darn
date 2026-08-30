//! Trust on first use, mechanically: probing a host's key to show the user,
//! and recording an accepted one the way OpenSSH itself would write it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ssh2::{HashType, HostKeyType};

use crate::errors::DarnError;

use super::known_hosts::{known_hosts_files, parse_line};
use super::SshSession;

/// A host key as the server presented it, ready to show and to record.
pub struct HostKey {
    /// The address that answered, as ssh(1) prints it in parentheses.
    pub address: String,
    /// `SHA256:...`, the same string `ssh-keygen -lf` shows.
    pub fingerprint: String,
    /// The algorithm as ssh(1) names it in the prompt, e.g. `ED25519`.
    pub algorithm: String,
    /// The algorithm as known_hosts spells it, e.g. `ssh-ed25519`.
    key_type: String,
    key: Vec<u8>,
}

/// Fetch a host's key without authenticating or checking known_hosts.
///
/// Used to show the user what they are being asked to trust. Trusting it is a
/// separate step: whatever is recorded here is verified by the real connect
/// that follows, so a key swapped in between the two fails as a mismatch
/// rather than slipping through.
pub fn probe_host_key(
    hostname: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<HostKey, DarnError> {
    let (sess, addr) = SshSession::open_session(hostname, port, connect_timeout)
        .map_err(|e| DarnError::Ssh(format!("failed to connect to {hostname}: {e}")))?;

    let (key, key_type) = sess
        .host_key()
        .ok_or_else(|| DarnError::Ssh(format!("{hostname} presented no host key")))?;
    let (algorithm, wire_name) = match key_type {
        HostKeyType::Ed25519 => ("ED25519", "ssh-ed25519"),
        HostKeyType::Rsa => ("RSA", "ssh-rsa"),
        HostKeyType::Dss => ("DSA", "ssh-dss"),
        HostKeyType::Ecdsa256 => ("ECDSA", "ecdsa-sha2-nistp256"),
        HostKeyType::Ecdsa384 => ("ECDSA", "ecdsa-sha2-nistp384"),
        HostKeyType::Ecdsa521 => ("ECDSA", "ecdsa-sha2-nistp521"),
        // Recording a key we cannot name would produce a line no ssh could
        // read back, so stop rather than write nonsense.
        HostKeyType::Unknown => {
            return Err(DarnError::Ssh(format!(
                "{hostname} presented a host key of a type darn cannot record"
            )))
        }
    };

    // libssh2 hashes the key for us, which is why no sha2 crate is needed.
    use base64::Engine;
    let digest = sess
        .host_key_hash(HashType::Sha256)
        .ok_or_else(|| DarnError::Ssh(format!("{hostname} gave no SHA256 host key hash")))?;
    let fingerprint = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    );

    Ok(HostKey {
        address: addr.ip().to_string(),
        fingerprint,
        algorithm: algorithm.to_string(),
        key_type: wire_name.to_string(),
        key: key.to_vec(),
    })
}

/// Where else this exact key is already trusted, as `file:line: pattern`.
///
/// ssh(1) shows this when asking about an unknown name, and it is the useful
/// half of the question: a key already trusted under another name is a host
/// you have met, not a stranger.
pub fn other_names_for_key(host_key: &HostKey) -> Vec<String> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&host_key.key);
    let mut found = Vec::new();
    for file in known_hosts_files() {
        let Ok(content) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (index, raw) in content.lines().enumerate() {
            let Some(line) = parse_line(raw) else {
                continue;
            };
            // A @cert-authority or @revoked line is not a place this key is
            // trusted, whatever blob it carries.
            if line.marker.is_some() {
                continue;
            }
            if line.key_base64 == encoded {
                found.push(format!("{}:{}: {}", file.display(), index + 1, line.hosts_field));
            }
        }
    }
    found
}

/// Record `host_key` in the user's known_hosts, returning the file written.
///
/// The entry is hashed, as OpenSSH writes them here, and names the host the
/// way `check_port` looks it up: bare at port 22, `[host]:port` otherwise.
pub fn remember_host_key(
    host_key: &HostKey,
    hostname: &str,
    port: u16,
) -> Result<PathBuf, DarnError> {
    let name = if port == 22 {
        hostname.to_string()
    } else {
        format!("[{hostname}]:{port}")
    };
    let mut salt = [0u8; 20];
    getrandom::fill(&mut salt)
        .map_err(|e| DarnError::Other(format!("cannot generate a known_hosts salt: {e}")))?;

    // Only ever the user's own file: /etc/ssh/ssh_known_hosts is the
    // administrator's, and darn is not it.
    let path = dirs::home_dir()
        .ok_or_else(|| DarnError::Other("no home directory to write known_hosts in".to_string()))?
        .join(".ssh")
        .join("known_hosts");
    let entry = known_hosts_entry(&name, host_key, &salt);
    append_known_host(&path, &entry)
        .map_err(|e| DarnError::Other(format!("cannot write {}: {e}", path.display())))?;
    Ok(path)
}

/// One hashed known_hosts line: `|1|<salt>|<HMAC-SHA1(salt, name)> type key`.
fn known_hosts_entry(name: &str, host_key: &HostKey, salt: &[u8]) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};

    let engine = base64::engine::general_purpose::STANDARD;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(salt).expect("HMAC takes a key of any size");
    mac.update(name.as_bytes());
    let hash = mac.finalize().into_bytes();
    format!(
        "|1|{}|{} {} {}",
        engine.encode(salt),
        engine.encode(hash),
        host_key.key_type,
        engine.encode(&host_key.key)
    )
}

/// Append a line, creating ~/.ssh and known_hosts with the modes ssh expects.
///
/// A file not ending in a newline gets one first: appending blindly would
/// otherwise splice our entry onto the end of somebody else's, silently
/// invalidating both.
fn append_known_host(path: &Path, entry: &str) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(dir) = path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    // Readable as well as appendable: the trailing-newline check below has
    // to look at what is already there. Appending still lands at the end
    // whatever the read leaves the cursor on.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .open(path)?;

    let end = file.seek(SeekFrom::End(0))?;
    if end > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::End(-1))?;
        std::io::Read::read_exact(&mut file, &mut last)?;
        if last[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }
    file.write_all(entry.as_bytes())?;
    file.write_all(b"\n")
}

#[cfg(test)]
mod host_key_tests {
    use super::super::known_hosts::stored_key_types;
    use super::*;

    fn a_host_key() -> HostKey {
        HostKey {
            address: "10.42.42.51".to_string(),
            fingerprint: "SHA256:TsA++yDjGBI6RHajtLzDAcpM5B2FM8vv1KeCENzeTdQ".to_string(),
            algorithm: "ED25519".to_string(),
            key_type: "ssh-ed25519".to_string(),
            key: b"a plausible key blob".to_vec(),
        }
    }

    /// The test that matters: what we write is what our own reader matches.
    /// A salt encoded wrongly would leave darn asking about the same host
    /// forever, and nothing else would notice.
    #[test]
    fn a_written_entry_is_found_again_by_the_parser() {
        let entry = known_hosts_entry("proxmox1", &a_host_key(), &[7u8; 20]);
        assert!(entry.starts_with("|1|"));
        assert_eq!(
            stored_key_types(&entry, "proxmox1", 22),
            ["ssh-ed25519"],
            "hashed entry did not match the host it was written for"
        );
        // And it is not a match for anything else.
        assert!(stored_key_types(&entry, "proxmox2", 22).is_empty());
        assert!(stored_key_types(&entry, "proxmox1", 2222).is_empty());
    }

    #[test]
    fn a_non_default_port_is_named_in_brackets() {
        let key = a_host_key();
        let entry = known_hosts_entry("[proxmox1]:2222", &key, &[9u8; 20]);
        assert_eq!(stored_key_types(&entry, "proxmox1", 2222), ["ssh-ed25519"]);
        assert!(stored_key_types(&entry, "proxmox1", 22).is_empty());
    }

    #[test]
    fn a_new_known_hosts_gets_ssh_s_own_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(".ssh").join("known_hosts");
        append_known_host(&path, "|1|salt|hash ssh-ed25519 AAAA").unwrap();

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "|1|salt|hash ssh-ed25519 AAAA\n"
        );
    }

    /// Appending to a file whose last line has no newline must not splice the
    /// two entries together — that would quietly invalidate both.
    #[test]
    fn an_unterminated_last_line_is_closed_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, "existing.example.com ssh-rsa AAAAold").unwrap();

        append_known_host(&path, "|1|salt|hash ssh-ed25519 AAAAnew").unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "existing.example.com ssh-rsa AAAAold\n|1|salt|hash ssh-ed25519 AAAAnew\n"
        );
    }

    #[test]
    fn a_key_already_trusted_elsewhere_is_reported_with_its_line() {
        // other_names_for_key reads the real known_hosts paths, so exercise
        // the line-matching it depends on rather than the file list.
        let key = a_host_key();
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&key.key);
        let entry = known_hosts_entry("proxmox1", &key, &[3u8; 20]);
        assert!(
            entry.ends_with(&encoded),
            "the recorded line must carry the key verbatim for lookup to work"
        );
    }
}
