use std::io::Write;
use std::path::Path;

use rusqlite::Connection;

use crate::commands::session_id;
use crate::db;
use crate::errors::DarnError;
use crate::hosts::detect::detect_type;
use crate::hosts::get_handler;
use crate::password::{read_password, stdin_is_terminal};
use crate::render::{bold, dim, green, render_server_list, yellow};
use crate::ssh::{self, Recorder, SshSession, DEFAULT_CONNECT_TIMEOUT};
use crate::target::parse_target;

/// How many times to re-ask for a mistyped password, as sshd itself allows.
const PASSWORD_ATTEMPTS: usize = 3;

/// How many times to re-ask an unanswered yes/no, before treating the
/// silence as a no.
const ANSWER_ATTEMPTS: usize = 3;

#[allow(clippy::too_many_arguments)]
pub fn add(
    db_path: Option<&Path>,
    target: &str,
    port: Option<u16>,
    key_path: Option<&str>,
    no_all: Option<bool>,
) -> Result<i32, DarnError> {
    let (ssh_user, hostname, target_port) = parse_target(target)?;
    if let (Some(tp), Some(p)) = (target_port, port) {
        if tp != p {
            return Err(DarnError::Usage(format!(
                "--port {p} conflicts with the port in '{target}'"
            )));
        }
    }
    let port = target_port.or(port).unwrap_or(22);
    let conn = db::open_db(db_path)?;
    let session_id = session_id();

    let (host_type, distribution) = {
        let mut session =
            connect_to_new_host(&conn, &hostname, &ssh_user, port, key_path, &session_id)?;
        let host_type = detect_type(&mut session)?;
        let distribution = get_handler(host_type)?.identify(&mut session)?;
        (host_type, distribution)
    };

    db::add_server(
        &conn,
        &hostname,
        &ssh_user,
        port,
        key_path,
        host_type,
        Some(&distribution),
        no_all,
    )?;
    let stored = db::get_server(&conn, &hostname)?;
    let suffix = if stored.is_some_and(|s| s.no_all) {
        format!(" {}", dim("· no-all"))
    } else {
        String::new()
    };
    println!(
        "{} {hostname} (type: {host_type}, distribution: {distribution}){suffix}",
        green("Added")
    );
    Ok(0)
}

/// Connect to a host being added, offering to settle what an unseen host
/// still needs settled: its key recorded, and one of ours installed.
///
/// Each is offered once. A brand-new host needs both, in this order, because
/// that is the order SSH raises them — there is no point discussing
/// credentials with a server whose identity is still unestablished.
fn connect_to_new_host<'a>(
    conn: &'a Connection,
    hostname: &'a str,
    ssh_user: &str,
    port: u16,
    key_path: Option<&str>,
    session_id: &'a str,
) -> Result<SshSession<'a>, DarnError> {
    let mut asked_about_key = false;
    let mut installed_key = false;
    loop {
        let attempt = SshSession::connect(
            hostname,
            ssh_user,
            port,
            key_path,
            Some(recorder(conn, hostname, session_id)),
            DEFAULT_CONNECT_TIMEOUT,
        );
        match attempt {
            Ok(session) => return Ok(session),
            // Never seen this host before. Ask, the way ssh(1) asks.
            Err(DarnError::SshHostKeyUnknown(why)) if !asked_about_key => {
                asked_about_key = true;
                accept_host_key(hostname, port, &why)?;
            }
            // The host is reachable and its key is known; we simply have
            // nothing it accepts. Offer to put a key there rather than
            // sending the user off to ssh-copy-id and back.
            Err(DarnError::SshAuth(why)) if !installed_key => {
                installed_key = true;
                install_public_key(conn, hostname, ssh_user, port, key_path, session_id, &why)?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Show an unknown host's key and record it if the user says to.
///
/// This is trust on first use, and the wording is ssh(1)'s because that is
/// the text a sysadmin already knows how to weigh. What gets recorded is
/// verified by the connect that follows, so a key substituted between the
/// question and the answer fails as a mismatch instead of being trusted.
fn accept_host_key(hostname: &str, port: u16, why: &str) -> Result<(), DarnError> {
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

/// Log every command run while adding a host, so `darn log` shows the type
/// detection — and any key install — alongside later sessions.
fn recorder<'a>(conn: &'a Connection, hostname: &'a str, session_id: &'a str) -> Recorder<'a> {
    Box::new(move |command, stdout, stderr, exit_code| {
        let _ = db::record_command(
            conn,
            hostname,
            session_id,
            command,
            Some(stdout),
            Some(stderr),
            Some(exit_code),
        );
    })
}

/// Install the local public key on a host that accepts no key of ours, using
/// a password typed at the prompt.
///
/// Says which key is going where before asking, since a password prompt from
/// a tool that has never wanted one needs to account for itself. The password
/// authenticates one connection and is neither stored nor logged: what goes
/// in the command log is the authorized_keys command, whose only
/// secret-shaped content is a public key.
#[allow(clippy::too_many_arguments)]
fn install_public_key(
    conn: &Connection,
    hostname: &str,
    ssh_user: &str,
    port: u16,
    key_path: Option<&str>,
    session_id: &str,
    why: &str,
) -> Result<(), DarnError> {
    let where_looked = match key_path {
        Some(key) => format!("for --key {key}"),
        None => "in ~/.ssh".to_string(),
    };
    let Some(public_key_path) = ssh::default_public_key(key_path) else {
        return Err(DarnError::SshAuth(format!(
            "{why}\nNo public key found {where_looked} to install; \
             create one with `ssh-keygen -t ed25519` and try again."
        )));
    };
    let public_key = std::fs::read_to_string(&public_key_path)
        .map_err(|e| DarnError::Other(format!("cannot read {}: {e}", public_key_path.display())))?
        .trim()
        .to_string();

    // Nothing to prompt with, so leave the original failure to stand rather
    // than hanging a cron run on a question nobody will answer.
    if !stdin_is_terminal() {
        return Err(DarnError::SshAuth(format!(
            "{why}\nInstall {} on the host (`ssh-copy-id`), or run `darn server add` \
             from a terminal to be offered the same thing here.",
            public_key_path.display()
        )));
    }

    let account = format!("{ssh_user}@{hostname}");
    println!("{}", yellow(&format!("No SSH key works for {account}.")));
    // The prompt below names the same account, which is what says whose
    // password is wanted; spelling that out again only buries it.
    println!(
        "Enter password to copy public key from {} to authorized_keys on server, \
         or ctrl-c to cancel.",
        bold(&public_key_path.display().to_string())
    );

    let mut session = None;
    let mut refusal = None;
    for attempt in 1..=PASSWORD_ATTEMPTS {
        let password = read_password(&format!("{account}'s password: "))
            .map_err(|e| DarnError::Other(format!("cannot read password: {e}")))?;
        if password.is_empty() {
            return Err(DarnError::SshAuth(format!(
                "no password entered; {account} was not added"
            )));
        }
        match SshSession::connect_with_password(
            hostname,
            ssh_user,
            port,
            &password,
            Some(recorder(conn, hostname, session_id)),
            DEFAULT_CONNECT_TIMEOUT,
        ) {
            Ok(open) => {
                session = Some(open);
                break;
            }
            // Keep why the server said no: after the last try it is the
            // useful half of the message, and it may not be "wrong password"
            // at all — a host offering neither password method says so here.
            Err(DarnError::SshAuth(refused)) => {
                refusal = Some(refused);
                if attempt < PASSWORD_ATTEMPTS {
                    println!("{}", yellow("Permission denied, please try again."));
                }
            }
            Err(e) => return Err(e),
        }
    }
    let Some(mut session) = session else {
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
                "{e}\nCould not write ~/.ssh/authorized_keys on {hostname}. A host whose \
                 shell is not POSIX — RouterOS, for one — needs its keys installed with \
                 its own tooling."
            ))
        })?;
    println!(
        "{} {} on {account}",
        green("Installed"),
        public_key_path.display()
    );
    Ok(())
}

pub fn remove(db_path: Option<&Path>, hostname: &str) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    if db::remove_server(&conn, hostname)? {
        println!("{} {hostname}", green("Removed"));
        Ok(0)
    } else {
        Err(DarnError::Other(format!("no such server: {hostname}")))
    }
}

pub fn set(db_path: Option<&Path>, hostname: &str, no_all: Option<bool>) -> Result<i32, DarnError> {
    let Some(no_all) = no_all else {
        return Err(DarnError::Usage(
            "nothing to set: pass --no-all or --all".to_string(),
        ));
    };
    let conn = db::open_db(db_path)?;
    if !db::set_no_all(&conn, hostname, no_all)? {
        return Err(DarnError::Other(format!("no such server: {hostname}")));
    }
    if no_all {
        println!("{} is now excluded from 'all' targets", green(hostname));
    } else {
        println!("{} is now included in 'all' targets", green(hostname));
    }
    Ok(0)
}

pub fn list(db_path: Option<&Path>) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let servers = db::list_servers(&conn)?;
    if servers.is_empty() {
        println!(
            "{}",
            yellow("No servers configured. Use `darn server add`.")
        );
        return Ok(0);
    }
    render_server_list(&servers);
    Ok(0)
}
