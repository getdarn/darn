//! Trust on first use: showing an unknown host key and recording it only
//! when the user says so, in ssh(1)'s own words.

use std::io::Write;

use crate::errors::DarnError;
use crate::password::stdin_is_terminal;
use crate::render::{bold, yellow};
use crate::ssh::{self, DEFAULT_CONNECT_TIMEOUT};

use super::ANSWER_ATTEMPTS;

/// Show an unknown host's key and record it if the user says to.
///
/// This is trust on first use, and the wording is ssh(1)'s because that is
/// the text a sysadmin already knows how to weigh. What gets recorded is
/// verified by the connect that follows, so a key substituted between the
/// question and the answer fails as a mismatch instead of being trusted.
pub(super) fn accept_host_key(hostname: &str, port: u16, why: &str) -> Result<(), DarnError> {
    if !stdin_is_terminal() {
        return Err(DarnError::SshHostKeyUnknown(format!(
            "{why}\nOr run `darn server add` from a terminal to be shown the key \
             and asked about it here."
        )));
    }

    let host_key = ssh::probe_host_key(hostname, port, DEFAULT_CONNECT_TIMEOUT)?;
    println!(
        "The authenticity of host '{hostname} ({})' can't be established.",
        host_key.address
    );
    println!(
        "{} key fingerprint is {}.",
        host_key.algorithm,
        bold(&host_key.fingerprint)
    );
    let other_names = ssh::other_names_for_key(&host_key);
    if other_names.is_empty() {
        println!("This key is not known by any other names.");
    } else {
        println!("This host key is known by the following other names/addresses:");
        for name in other_names {
            println!("    {name}");
        }
    }

    if !confirm_fingerprint(&host_key.fingerprint)? {
        return Err(DarnError::SshHostKeyUnknown(format!(
            "host key not accepted; {hostname} was not added"
        )));
    }

    let file = ssh::remember_host_key(&host_key, hostname, port)?;
    println!(
        "{} Permanently added '{hostname}' ({}) to {}.",
        yellow("Warning:"),
        host_key.algorithm,
        file.display()
    );
    Ok(())
}

/// Ask ssh(1)'s question, accepting `yes` or the fingerprint pasted back.
///
/// A bare `y` is not enough: this is the one answer in darn that decides who
/// you are talking to, and ssh makes you spell it out for that reason.
fn confirm_fingerprint(fingerprint: &str) -> Result<bool, DarnError> {
    let bare = fingerprint.strip_prefix("SHA256:").unwrap_or(fingerprint);
    for _ in 0..ANSWER_ATTEMPTS {
        print!("Are you sure you want to continue connecting (yes/no/[fingerprint])? ");
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() || answer.is_empty() {
            return Ok(false); // EOF: no answer is not a yes.
        }
        let answer = answer.trim();
        if answer.eq_ignore_ascii_case("yes") || answer == fingerprint || answer == bare {
            return Ok(true);
        }
        if answer.eq_ignore_ascii_case("no") {
            return Ok(false);
        }
        println!(
            "{}",
            yellow("Please type 'yes', 'no' or the fingerprint shown above.")
        );
    }
    Ok(false)
}
