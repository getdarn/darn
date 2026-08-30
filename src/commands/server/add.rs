//! First contact with a host being added: connect, detect what it is, and
//! record it — settling host key and credentials along the way.

use std::path::Path;

use rusqlite::Connection;

use crate::commands::session_id;
use crate::db;
use crate::errors::DarnError;
use crate::hosts::detect::detect_type;
use crate::hosts::{get_handler, MikrotikHandler};
use crate::orchestrator::command_recorder;
use crate::provision::DARN_USER;
use crate::render::{dim, green};
use crate::ssh::{SshSession, DEFAULT_CONNECT_TIMEOUT};
use crate::target::parse_target;

use super::access::{ensure_privileges, install_public_key};
use super::trust::accept_host_key;

/// The host being added, as the user asked for it.
pub(super) struct NewHost<'a> {
    pub(super) hostname: &'a str,
    pub(super) ssh_user: &'a str,
    pub(super) port: u16,
    pub(super) key_path: Option<&'a str>,
}

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
    let host = NewHost {
        hostname: &hostname,
        ssh_user: &ssh_user,
        port,
        key_path,
    };

    let (host_type, distribution, stored_user) = {
        let (mut session, contact) = connect_to_new_host(&conn, &host, &session_id)?;
        let host_type = detect_type(&mut session)?;

        // RouterOS has neither sudo nor useradd, and darn never escalates on
        // it; asking about a `darn` user there would be asking nonsense.
        let mut stored_user = ssh_user.clone();
        if host_type != MikrotikHandler::TYPE {
            let provisioned = ensure_privileges(&conn, &mut session, &host, &session_id, &contact)?;
            if let Some(darn_session) = provisioned {
                session = darn_session;
                stored_user = DARN_USER.to_string();
            }
        }

        let distribution = get_handler(host_type)?.identify(&mut session)?;
        (host_type, distribution, stored_user)
    };

    db::add_server(
        &conn,
        &hostname,
        &stored_user,
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
    // The user is named only when it is not the one asked for, since that is
    // the case where what was added differs from what was typed.
    let added = if stored_user == ssh_user {
        hostname.clone()
    } else {
        format!("{stored_user}@{hostname}")
    };
    println!(
        "{} {added} (type: {host_type}, distribution: {distribution}){suffix}",
        green("Added")
    );
    Ok(0)
}

/// What settling first contact left behind, for the sudo step that follows.
///
/// Both fields exist to keep `server add` from asking twice for something the
/// user has already given: the remote password, and permission to put a key
/// on this host.
pub(super) struct FirstContact {
    pub(super) password: Option<String>,
    pub(super) key_installed: bool,
}

/// Connect to a host being added, offering to settle what an unseen host
/// still needs settled: its key recorded, and one of ours installed.
///
/// Each is offered once. A brand-new host needs both, in this order, because
/// that is the order SSH raises them — there is no point discussing
/// credentials with a server whose identity is still unestablished.
fn connect_to_new_host<'a>(
    conn: &'a Connection,
    host: &NewHost<'a>,
    session_id: &'a str,
) -> Result<(SshSession<'a>, FirstContact), DarnError> {
    let mut asked_about_key = false;
    let mut contact = FirstContact {
        password: None,
        key_installed: false,
    };
    loop {
        let attempt = SshSession::connect(
            host.hostname,
            host.ssh_user,
            host.port,
            host.key_path,
            Some(command_recorder(conn, host.hostname, session_id)),
            DEFAULT_CONNECT_TIMEOUT,
        );
        match attempt {
            Ok(session) => return Ok((session, contact)),
            // Never seen this host before. Ask, the way ssh(1) asks.
            Err(DarnError::SshHostKeyUnknown(why)) if !asked_about_key => {
                asked_about_key = true;
                accept_host_key(host.hostname, host.port, &why)?;
            }
            // The host is reachable and its key is known; we simply have
            // nothing it accepts. Offer to put a key there rather than
            // sending the user off to ssh-copy-id and back.
            Err(DarnError::SshAuth(why)) if !contact.key_installed => {
                contact.key_installed = true;
                contact.password = Some(install_public_key(conn, host, session_id, &why)?);
            }
            Err(e) => return Err(e),
        }
    }
}
