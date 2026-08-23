use std::path::Path;

use crate::commands::{
    batch_exit_code, no_targets_message, record_restart_state, servers_for_all, session_id,
};
use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::get_handler;
use crate::orchestrator::{run_parallel, HostResult};
use crate::render::{render_results, restart_suffix};
use crate::ssh::SshSession;

#[allow(clippy::too_many_arguments)]
pub fn run(
    db_path: Option<&Path>,
    target: &str,
    mut jobs: usize,
    security: bool,
    non_security: bool,
    include_no_all: bool,
) -> Result<i32, DarnError> {
    if security && non_security {
        return Err(DarnError::Usage(
            "--security and --non-security are mutually exclusive".to_string(),
        ));
    }
    let conn = db::open_db(db_path)?;

    let (servers, description) = if target == "all" {
        let servers = servers_for_all(&conn, include_no_all)?;
        if let Some(empty) = no_targets_message(&conn, &servers)? {
            println!("{empty}");
            return Ok(0);
        }
        (servers, "Applying patches".to_string())
    } else {
        let Some(single) = db::get_server(&conn, target)? else {
            return Err(DarnError::Other(format!("no such server: {target}")));
        };
        jobs = 1;
        (vec![single], format!("Upgrading {target}"))
    };

    let session_id = session_id();

    let work = |server: &Server,
                session: &mut SshSession<'_>,
                thread_conn: &rusqlite::Connection|
     -> HostResult {
        let mut attempt = || -> Result<String, DarnError> {
            let handler = get_handler(&server.host_type)?;
            let known = db::get_pending_patches(thread_conn, &server.hostname)?;
            handler.upgrade(session, security, non_security, &known)?;
            match handler.discover(session) {
                Ok(patches) => {
                    db::replace_pending_patches(thread_conn, &server.hostname, &patches, true)?;
                }
                Err(_) => {
                    db::clear_pending_patches(thread_conn, &server.hostname)?;
                }
            }
            let restarts = record_restart_state(thread_conn, server, handler, session)?;
            Ok(format!(
                "upgraded{}",
                restart_suffix(
                    thread_conn,
                    &server.hostname,
                    Some(restarts.reboot.as_str())
                )
            ))
        };
        match attempt() {
            Ok(message) => HostResult {
                hostname: server.hostname.clone(),
                ok: true,
                message,
            },
            Err(e) => HostResult {
                hostname: server.hostname.clone(),
                ok: false,
                message: e.to_string(),
            },
        }
    };

    let results = run_parallel(&servers, work, &session_id, jobs, db_path, &description);
    let title = if target == "all" {
        "upgrade all results".to_string()
    } else {
        format!("upgrade {target}")
    };
    render_results(&title, &results);
    Ok(batch_exit_code(&results))
}
