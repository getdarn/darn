//! Getting into a host being added, and making sure darn can escalate once
//! there: key installation against a password, and the offer of a dedicated
//! `darn` user when the account itself cannot sudo.

use std::path::Path;

use rusqlite::Connection;

use crate::commands::confirm;
use crate::errors::DarnError;
use crate::password::{read_password, stdin_is_terminal};
use crate::provision::{self, DARN_USER};
use crate::render::{bold, green, yellow};
use crate::ssh::{self, SshSession, DEFAULT_CONNECT_TIMEOUT};

use super::add::{recorder, FirstContact, NewHost};
use super::PASSWORD_ATTEMPTS;

/// Where a public key was searched for, for messages about not finding one.
fn where_key_was_sought(key_path: Option<&str>) -> String {
    match key_path {
        Some(key) => format!("for --key {key}"),
        None => "in ~/.ssh".to_string(),
    }
}

/// Read a public key file, trimmed to the single line authorized_keys wants.
fn read_public_key(path: &Path) -> Result<String, DarnError> {
    Ok(std::fs::read_to_string(path)
        .map_err(|e| DarnError::Other(format!("cannot read {}: {e}", path.display())))?
        .trim()
        .to_string())
}

/// Ask for a password up to PASSWORD_ATTEMPTS times, handing each one to
/// `accept`. A `Some` from `accept` ends the loop with that value; a `None`
/// prints `retry_message` and asks again. `Ok(None)` means every attempt was
/// refused, and the caller says what giving up means. An empty entry raises
/// `empty_error`: silence at a password prompt is a cancel, not an attempt.
fn prompt_password_loop<T>(
    prompt: &str,
    empty_error: impl Fn() -> DarnError,
    retry_message: &str,
    mut accept: impl FnMut(&str) -> Result<Option<T>, DarnError>,
) -> Result<Option<T>, DarnError> {
    for attempt in 1..=PASSWORD_ATTEMPTS {
        let password = read_password(prompt)
            .map_err(|e| DarnError::Other(format!("cannot read password: {e}")))?;
        if password.is_empty() {
            return Err(empty_error());
        }
        if let Some(accepted) = accept(&password)? {
            return Ok(Some(accepted));
        }
        if attempt < PASSWORD_ATTEMPTS {
            println!("{}", yellow(retry_message));
        }
    }
    Ok(None)
}

/// Install the local public key on a host that accepts no key of ours, using
/// a password typed at the prompt, and return that password.
///
/// Says which key is going where before asking, since a password prompt from
/// a tool that has never wanted one needs to account for itself. The password
/// is returned so that the sudo step, if it comes, does not ask for the same
/// secret a second time; it is held in memory for the rest of the command and
/// is neither stored nor logged. What goes in the command log is the
/// authorized_keys command, whose only secret-shaped content is a public key.
pub(super) fn install_public_key(
    conn: &Connection,
    host: &NewHost<'_>,
    session_id: &str,
    why: &str,
) -> Result<String, DarnError> {
    let Some(public_key_path) = ssh::default_public_key(host.key_path) else {
        return Err(DarnError::SshAuth(format!(
            "{why}\nNo public key found {} to install; \
             create one with `ssh-keygen -t ed25519` and try again.",
            where_key_was_sought(host.key_path)
        )));
    };
    let public_key = read_public_key(&public_key_path)?;

    // Nothing to prompt with, so leave the original failure to stand rather
    // than hanging a cron run on a question nobody will answer.
    if !stdin_is_terminal() {
        return Err(DarnError::SshAuth(format!(
            "{why}\nInstall {} on the host (`ssh-copy-id`), or run `darn server add` \
             from a terminal to be offered the same thing here.",
            public_key_path.display()
        )));
    }

    let account = format!("{}@{}", host.ssh_user, host.hostname);
    println!("{}", yellow(&format!("No SSH key works for {account}.")));
    // The prompt below names the same account, which is what says whose
    // password is wanted; spelling that out again only buries it.
    println!(
        "Enter password to copy public key from {} to authorized_keys on server, \
         or ctrl-c to cancel.",
        bold(&public_key_path.display().to_string())
    );

    // Keep why the server said no: after the last try it is the useful half
    // of the message, and it may not be "wrong password" at all — a host
    // offering neither password method says so here.
    let mut refusal = None;
    let opened = prompt_password_loop(
        &format!("{account}'s password: "),
        || DarnError::SshAuth(format!("no password entered; {account} was not added")),
        "Permission denied, please try again.",
        |password| match SshSession::connect_with_password(
            host.hostname,
            host.ssh_user,
            host.port,
            password,
            Some(recorder(conn, host.hostname, session_id)),
            DEFAULT_CONNECT_TIMEOUT,
        ) {
            Ok(open) => Ok(Some((open, password.to_string()))),
            Err(DarnError::SshAuth(refused)) => {
                refusal = Some(refused);
                Ok(None)
            }
            Err(e) => Err(e),
        },
    )?;
    let Some((mut session, accepted)) = opened else {
        let refusal = refusal.unwrap_or_else(|| format!("could not authenticate to {account}"));
        return Err(DarnError::SshAuth(format!(
            "{refusal}; giving up after {PASSWORD_ATTEMPTS} attempts"
        )));
    };

    session
        .run(
            &ssh::install_authorized_key_command(&public_key),
            false,
            true,
        )
        .map_err(|e| {
            DarnError::Ssh(format!(
                "{e}\nCould not write ~/.ssh/authorized_keys on {}. A host whose \
                 shell is not POSIX — RouterOS, for one — needs its keys installed with \
                 its own tooling.",
                host.hostname
            ))
        })?;
    println!(
        "{} {} on {account}",
        green("Installed"),
        public_key_path.display()
    );
    Ok(accepted)
}

/// Make sure darn will be able to escalate on a host it is about to manage,
/// offering a dedicated `darn` user when the account being added cannot.
///
/// Returns a session as that new user when one was created and is reachable,
/// and `None` when nothing was needed or the offer was declined — declining
/// leaves the host to be added under the account that was asked for, because
/// a host darn cannot fully manage is still worth having on the list.
pub(super) fn ensure_privileges<'a>(
    conn: &'a Connection,
    session: &mut SshSession<'_>,
    host: &NewHost<'a>,
    session_id: &'a str,
    contact: &FirstContact,
) -> Result<Option<SshSession<'a>>, DarnError> {
    if has_passwordless_sudo(session)? {
        return Ok(None);
    }

    let hostname = host.hostname;
    let account = format!("{}@{hostname}", host.ssh_user);
    println!(
        "{}",
        yellow(&format!(
            "{account} doesn't allow passwordless sudo, which darn requires."
        ))
    );

    if !stdin_is_terminal() {
        println!(
            "{}",
            yellow(&format!(
                "Give {account} passwordless sudo, or run `darn server add` from a \
                 terminal to be offered a `{DARN_USER}` user here."
            ))
        );
        return Ok(None);
    }

    // An account nothing can log in to would be worse than no account, so the
    // key that will authorise it is found before anything is offered.
    let Some(public_key_path) = ssh::default_public_key(host.key_path) else {
        println!(
            "{}",
            yellow(&format!(
                "No public key found {} to authorise for a `{DARN_USER}` user; \
                 create one with `ssh-keygen -t ed25519` and add {hostname} again.",
                where_key_was_sought(host.key_path)
            ))
        );
        return Ok(None);
    };
    let public_key = read_public_key(&public_key_path)?;

    if !confirm(&format!(
        "Create user '{DARN_USER}' with passwordless sudo on {hostname}?"
    )) {
        println!(
            "{}",
            yellow(&format!(
                "Not created; {hostname} is being added as {account}, and commands \
                 needing root will fail."
            ))
        );
        return Ok(None);
    }

    // Permission to put this key on this host has already been given if a key
    // was installed to get in at all; asking again would be asking twice.
    let install_key = contact.key_installed
        || confirm(&format!(
            "Copy {} to {DARN_USER}'s authorized_keys on {hostname}?",
            public_key_path.display()
        ));

    let password = match &contact.password {
        // The SSH password is usually the sudo password too, but not always —
        // so it is offered to sudo rather than assumed to work.
        Some(known) if sudo_password_works(session, known)? => known.clone(),
        _ => ask_sudo_password(session, &account)?,
    };

    session
        .run_with_stdin(
            &ssh::sudo_password_command(&provision::create_user_command(
                install_key.then_some(public_key.as_str()),
            )),
            &format!("{password}\n"),
            true,
        )
        .map_err(|e| {
            DarnError::Ssh(format!(
                "{e}\nCould not create the {DARN_USER} user on {hostname}; \
                 nothing was changed unless the error above says otherwise."
            ))
        })?;
    println!(
        "{} user {DARN_USER} with passwordless sudo on {hostname}",
        green("Created")
    );

    if !install_key {
        println!(
            "{}",
            yellow(&format!(
                "No key was installed for {DARN_USER}, so {hostname} is being added as \
                 {account}. Authorise a key for {DARN_USER} and add the host again to \
                 use it."
            ))
        );
        return Ok(None);
    }
    println!(
        "{} {} on {DARN_USER}@{hostname}",
        green("Installed"),
        public_key_path.display()
    );

    // Prove the new account is usable before the database is told to trust
    // it: a `darn` user that cannot be reached, or that still cannot sudo,
    // would turn every later command into a puzzle.
    let mut darn_session = SshSession::connect(
        hostname,
        DARN_USER,
        host.port,
        host.key_path,
        Some(recorder(conn, hostname, session_id)),
        DEFAULT_CONNECT_TIMEOUT,
    )?;
    if !has_passwordless_sudo(&mut darn_session)? {
        return Err(DarnError::Other(format!(
            "{DARN_USER}@{hostname} was created but still cannot run sudo without a \
             password; {hostname} was not added"
        )));
    }
    Ok(Some(darn_session))
}

/// Whether this session can already do what darn needs of it.
///
/// `id -u` first, because root needs no sudo at all and may not even have it
/// installed — and because the account being added is not always called
/// `root` when it is root.
fn has_passwordless_sudo(session: &mut SshSession<'_>) -> Result<bool, DarnError> {
    if session.probe("id -u", false, false)?.stdout.trim() == "0" {
        return Ok(true);
    }
    Ok(session.probe("sudo -n true", false, false)?.exit_code == 0)
}

/// Ask for a password until sudo accepts one, as sudo itself asks.
fn ask_sudo_password(session: &mut SshSession<'_>, account: &str) -> Result<String, DarnError> {
    let accepted = prompt_password_loop(
        &format!("[sudo] password for {account}: "),
        || {
            DarnError::Other(format!(
                "no password entered; the {DARN_USER} user was not created"
            ))
        },
        "Sorry, try again.",
        |password| Ok(sudo_password_works(session, password)?.then(|| password.to_string())),
    )?;
    accepted.ok_or_else(|| {
        DarnError::Other(format!(
            "sudo did not accept a password for {account} after {PASSWORD_ATTEMPTS} attempts; \
             the {DARN_USER} user was not created. Answer 'n' when asked about it to add the \
             host as {account} instead."
        ))
    })
}

/// Spend a password on `sudo -v` alone, so a wrong one costs nothing.
///
/// A refusal that is not about the password — the account not being a sudoer
/// at all, or sudo wanting a tty — is an error rather than a retry: asking
/// for the same password twice more would not change any of those answers.
fn sudo_password_works(session: &mut SshSession<'_>, password: &str) -> Result<bool, DarnError> {
    let result = session.run_with_stdin("sudo -S -p '' -v", &format!("{password}\n"), false)?;
    if result.exit_code == 0 {
        return Ok(true);
    }
    // sudo's own words for "the password is not the problem here": the
    // account is no sudoer (`sudo -v` says "may not run sudo", a command says
    // "is not in the sudoers file"), or sudo wants a tty an ssh exec has not
    // got. A wrong password says "Sorry, try again" and matches none of them.
    let stderr = result.stderr.to_lowercase();
    let unrelated = [
        "may not run sudo",
        "not allowed to run sudo",
        "not in the sudoers",
        "must have a tty",
    ]
    .iter()
    .any(|hint| stderr.contains(hint));
    if unrelated {
        return Err(DarnError::Other(format!(
            "sudo on {} refused: {}\nAnswer 'n' when asked about the {DARN_USER} user to \
             add the host as it is.",
            session.hostname,
            result.stderr.trim()
        )));
    }
    Ok(false)
}
