//! The remote script that gives a host an account darn can escalate with.
//!
//! Every darn command escalates with `sudo -n`, so a host whose admin account
//! wants a password for sudo is unusable until something is done about it.
//! What is done is here: a dedicated `darn` user, a NOPASSWD rule, and the
//! operator's public key — built as one shell script rather than run
//! step-by-step, because sudo caches credentials per tty and an `ssh` exec has
//! no tty. Each extra `sudo` would be another password round trip; one script
//! spends the password once.
//!
//! The script is a string so it can be inspected in tests. It cannot be run
//! locally — it needs root, `useradd` and `visudo` — so the tests check its
//! shape and hand it to `sh -n`.

use crate::quote::sh_quote;

/// The account darn creates and thereafter connects as.
pub const DARN_USER: &str = "darn";

/// The sudoers rule that account gets.
const SUDOERS_RULE: &str = "darn ALL=(ALL) NOPASSWD: ALL";

/// The drop-in path. Deliberately extension-less: sudo ignores any file in
/// sudoers.d whose name contains a dot.
const SUDOERS_DROPIN: &str = "/etc/sudoers.d/darn";

/// Build the script that creates the `darn` user, grants it passwordless
/// sudo, and — when `public_key` is given — authorises that key for it.
///
/// Safe to run again on a host that already has all three: the user is only
/// created if missing, the rule only added if absent, the key only appended if
/// it is not already a line of the file. That matters because `darn server
/// add` is how an existing host is re-added.
pub fn create_user_command(public_key: Option<&str>) -> String {
    let user = DARN_USER;
    let rule = sh_quote(SUDOERS_RULE);
    let mut script = format!(
        // Every step is load-bearing, so stop at the first one that fails
        // rather than reporting success for a half-provisioned host.
        "set -e
umask 077
# No password is set, so the account can only be reached by key.
id -u {user} >/dev/null 2>&1 || \
useradd --create-home --shell \"$(command -v bash || echo /bin/sh)\" \
--comment 'darn fleet patching' {user}
tmp=$(mktemp)
trap 'rm -f \"$tmp\"' EXIT INT TERM
if grep -Eq '^[[:space:]]*[#@]include(dir)?[[:space:]]+/etc/sudoers\\.d[[:space:]]*$' /etc/sudoers; then
    # Drop-ins are read: leave the distribution's own file alone.
    printf '%s\\n' {rule} > \"$tmp\"
    visudo -c -f \"$tmp\" >/dev/null
    install -o root -g root -m 0440 \"$tmp\" {dropin}
else
    # No includedir, so the rule has to go in the main file. It is checked
    # as a copy and only then installed over the live one, because an
    # unparseable /etc/sudoers locks everyone out of sudo.
    if ! grep -qxF {rule} /etc/sudoers; then
        cat /etc/sudoers > \"$tmp\"
        printf '%s\\n' {rule} >> \"$tmp\"
        visudo -c -f \"$tmp\" >/dev/null
        install -o root -g root -m 0440 \"$tmp\" /etc/sudoers
    fi
fi
",
        dropin = SUDOERS_DROPIN,
    );

    if let Some(public_key) = public_key {
        let key = sh_quote(public_key);
        // Root is writing into someone else's home, so ownership and modes
        // are set explicitly rather than inherited from the umask.
        script.push_str(&format!(
            "home=$(getent passwd {user} | cut -d: -f6)
mkdir -p \"$home/.ssh\"
touch \"$home/.ssh/authorized_keys\"
grep -qxF {key} \"$home/.ssh/authorized_keys\" || \
printf '%s\\n' {key} >> \"$home/.ssh/authorized_keys\"
chown -R {user}: \"$home/.ssh\"
chmod 700 \"$home/.ssh\"
chmod 600 \"$home/.ssh/authorized_keys\"
{{ command -v restorecon >/dev/null 2>&1 && \
restorecon -F \"$home/.ssh\" \"$home/.ssh/authorized_keys\" >/dev/null 2>&1; true; }}
"
        ));
    }
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3Nz martin@laptop";

    /// The script never runs locally, so a syntax slip would otherwise only
    /// show up on someone's server, under sudo, half way through.
    fn assert_valid_shell(script: &str) {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut sh = Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        sh.stdin
            .as_mut()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(sh.wait().unwrap().success(), "sh -n rejected:\n{script}");
    }

    #[test]
    fn the_script_is_valid_shell_with_and_without_a_key() {
        assert_valid_shell(&create_user_command(None));
        assert_valid_shell(&create_user_command(Some(KEY)));
    }

    #[test]
    fn the_user_is_created_only_when_missing() {
        let script = create_user_command(None);
        assert!(script.contains("id -u darn >/dev/null 2>&1 || useradd --create-home"));
        // A shell it can actually run commands with, and a home to hold the key.
        assert!(script.contains("--shell \"$(command -v bash || echo /bin/sh)\""));
    }

    #[test]
    fn both_sudoers_paths_are_checked_by_visudo_before_installing() {
        let script = create_user_command(None);
        // Drop-in branch: check the candidate, then install it.
        let dropin = script.find("install -o root -g root -m 0440 \"$tmp\" /etc/sudoers.d/darn");
        let dropin_check = script.find("visudo -c -f \"$tmp\"");
        assert!(dropin_check.unwrap() < dropin.unwrap());
        // Fallback branch: the same, over the live /etc/sudoers.
        let live = script
            .find("install -o root -g root -m 0440 \"$tmp\" /etc/sudoers\n")
            .unwrap();
        let live_check = script.rfind("visudo -c -f \"$tmp\"").unwrap();
        assert!(live_check < live);
        assert!(script.contains("'darn ALL=(ALL) NOPASSWD: ALL'"));
    }

    #[test]
    fn the_key_is_quoted_and_appended_only_when_absent() {
        let script = create_user_command(Some(KEY));
        // Quoted, so a comment containing spaces cannot split the command.
        assert!(script.contains(
            "grep -qxF 'ssh-ed25519 AAAAC3Nz martin@laptop' \"$home/.ssh/authorized_keys\" || \
printf '%s\\n' 'ssh-ed25519 AAAAC3Nz martin@laptop' >> \"$home/.ssh/authorized_keys\""
        ));
        // Root wrote them, so they have to be handed over explicitly.
        assert!(script.contains("chown -R darn: \"$home/.ssh\""));
        assert!(script.contains("chmod 700 \"$home/.ssh\""));
        assert!(script.contains("chmod 600 \"$home/.ssh/authorized_keys\""));
    }

    #[test]
    fn no_key_means_no_authorized_keys_step() {
        let script = create_user_command(None);
        assert!(!script.contains("authorized_keys"));
    }
}
