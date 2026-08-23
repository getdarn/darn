use std::path::Path;

use crate::commands::session_id;
use crate::db;
use crate::errors::DarnError;
use crate::hosts::detect::detect_type;
use crate::hosts::get_handler;
use crate::render::{dim, green, render_server_list, yellow};
use crate::ssh::{Recorder, SshSession, DEFAULT_CONNECT_TIMEOUT};
use crate::target::parse_target;

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
        let recorder: Recorder<'_> = Box::new(|command, stdout, stderr, exit_code| {
            let _ = db::record_command(
                &conn,
                &hostname,
                &session_id,
                command,
                Some(stdout),
                Some(stderr),
                Some(exit_code),
            );
        });
        let mut session = SshSession::connect(
            &hostname,
            &ssh_user,
            port,
            key_path,
            Some(recorder),
            DEFAULT_CONNECT_TIMEOUT,
        )?;
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
