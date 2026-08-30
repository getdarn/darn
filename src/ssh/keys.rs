//! Local key discovery and the remote shell one-liners built around keys and
//! sudo. Nothing here opens a connection; these are strings and paths.

use std::path::PathBuf;

use super::auth::expand_tilde;
use super::DEFAULT_KEY_NAMES;

/// The public key to install on a host that accepts none of ours, following
/// the order `authenticate` tries private keys in. An explicit `--key` names
/// its own `.pub` sibling.
///
/// None when there is nothing to install — no `~/.ssh/id_*.pub` at all, or a
/// named key whose public half is missing.
pub fn default_public_key(key_path: Option<&str>) -> Option<PathBuf> {
    if let Some(key) = key_path {
        let path = expand_tilde(key);
        let public = if path.extension().is_some_and(|ext| ext == "pub") {
            path
        } else {
            let mut name = path.file_name()?.to_os_string();
            name.push(".pub");
            path.with_file_name(name)
        };
        return public.exists().then_some(public);
    }
    let ssh_dir = dirs::home_dir()?.join(".ssh");
    DEFAULT_KEY_NAMES
        .iter()
        .map(|name| ssh_dir.join(format!("{name}.pub")))
        .find(|path| path.exists())
}

/// The remote command that appends `public_key` to the user's
/// authorized_keys, creating ~/.ssh at 700 and the file at 600 if needed.
///
/// Written to be safe to run twice: an identical line already present is left
/// alone. `restorecon` matches what ssh-copy-id does, so the file is usable
/// on an SELinux host; hosts without it skip that step.
pub fn install_authorized_key_command(public_key: &str) -> String {
    let key = crate::quote::sh_quote(public_key);
    format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && \
{{ grep -qxF {key} ~/.ssh/authorized_keys || printf '%s\\n' {key} >> ~/.ssh/authorized_keys; }} && \
{{ command -v restorecon >/dev/null 2>&1 && restorecon -F ~/.ssh ~/.ssh/authorized_keys >/dev/null 2>&1; true; }}"
    )
}

/// Wrap `command` in a sudo that takes its password on stdin.
///
/// The counterpart to `with_sudo`'s `sudo -n`, for the one moment darn has a
/// password to spend: `-S` reads it from stdin rather than a tty, and `-p ''`
/// keeps sudo's prompt out of the stderr we report. The password stays out of
/// the command string, and so out of the command log.
pub fn sudo_password_command(command: &str) -> String {
    format!("sudo -S -p '' -- sh -c {}", crate::quote::sh_quote(command))
}

#[cfg(test)]
mod key_install_tests {
    use super::*;

    #[test]
    fn the_key_is_quoted_and_written_once() {
        let cmd = install_authorized_key_command("ssh-ed25519 AAAAC3Nz martin@laptop");
        // Quoted, so a comment containing spaces cannot split the command.
        assert!(cmd.contains(
            "printf '%s\\n' 'ssh-ed25519 AAAAC3Nz martin@laptop' >> ~/.ssh/authorized_keys"
        ));
        // Appended only when not already there, so re-adding a host is a no-op.
        assert!(cmd
            .contains("grep -qxF 'ssh-ed25519 AAAAC3Nz martin@laptop' ~/.ssh/authorized_keys ||"));
        // The directory and file exist with private permissions first.
        assert!(cmd.starts_with("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys &&"));
    }

    /// Run the command the way the remote shell will, against a throwaway
    /// HOME. Nothing else executes this string locally, so a syntax slip or a
    /// wrong mode would otherwise only show up on someone's server.
    #[test]
    fn the_command_writes_a_private_authorized_keys_and_repeats_cleanly() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let home = tempfile::tempdir().unwrap();
        let key = "ssh-ed25519 AAAAC3Nz martin@laptop";
        let cmd = install_authorized_key_command(key);

        // Twice: adding a host again must not pile up duplicate lines.
        for run in 1..=2 {
            let status = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .env("HOME", home.path())
                .status()
                .unwrap();
            assert!(status.success(), "run {run} of the install command failed");
        }

        let ssh_dir = home.path().join(".ssh");
        let authorized = ssh_dir.join("authorized_keys");
        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            format!("{key}\n")
        );
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        // sshd ignores an authorized_keys file that others can read.
        assert_eq!(mode(&ssh_dir), 0o700);
        assert_eq!(mode(&authorized), 0o600);
    }

    #[test]
    fn keys_already_on_the_host_are_kept() {
        use std::process::Command;

        let home = tempfile::tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        let authorized = ssh_dir.join("authorized_keys");
        std::fs::write(&authorized, "ssh-rsa AAAAsomeoneelse colleague@laptop\n").unwrap();

        let status = Command::new("sh")
            .arg("-c")
            .arg(install_authorized_key_command(
                "ssh-ed25519 AAAAmine martin@laptop",
            ))
            .env("HOME", home.path())
            .status()
            .unwrap();
        assert!(status.success());

        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            "ssh-rsa AAAAsomeoneelse colleague@laptop\nssh-ed25519 AAAAmine martin@laptop\n"
        );
    }

    #[test]
    fn an_explicit_key_names_its_public_half() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("deploy_key");
        std::fs::write(&private, "private").unwrap();

        // No .pub beside it: nothing to install, and no guessing.
        assert_eq!(default_public_key(Some(private.to_str().unwrap())), None);

        let public = dir.path().join("deploy_key.pub");
        std::fs::write(&public, "ssh-ed25519 AAAA").unwrap();
        assert_eq!(
            default_public_key(Some(private.to_str().unwrap())),
            Some(public.clone())
        );
        // Naming the public half directly works too.
        assert_eq!(
            default_public_key(Some(public.to_str().unwrap())),
            Some(public)
        );
    }
}
