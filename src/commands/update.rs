use std::path::Path;

use crate::commands::batch::{batch_exit_code, host_result, record_restart_state};
use crate::commands::session_id;
use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::get_handler;
use crate::orchestrator::{run_parallel, HostResult};
use crate::render::{green, red, render_results, restart_suffix, yellow};
use crate::ssh::SshSession;

pub fn run(db_path: Option<&Path>, jobs: usize) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let servers = db::list_servers(&conn)?;
    if servers.is_empty() {
        println!("{}", yellow("No servers configured."));
        return Ok(0);
    }
    let session_id = session_id();

    let work = |server: &Server,
                session: &mut SshSession<'_>,
                thread_conn: &rusqlite::Connection|
     -> HostResult {
        let mut attempt = || -> Result<String, DarnError> {
            let handler = get_handler(&server.host_type)?;
            if let Ok(distribution) = handler.identify(session) {
                let _ = db::set_distribution(thread_conn, &server.hostname, Some(&distribution));
            }
            let patches = handler.discover(session)?;
            db::replace_pending_patches(thread_conn, &server.hostname, &patches, true)?;
            let restarts = record_restart_state(thread_conn, server, handler, session)?;
            let security_count = patches.iter().filter(|p| p.is_security).count();
            let body = format!("{} pending ({security_count} security)", patches.len());
            let coloured = if security_count > 0 {
                red(&body)
            } else if !patches.is_empty() {
                yellow(&body)
            } else {
                green(&body)
            };
            let (actionable, deferred) =
                db::count_pending_services(thread_conn, &server.hostname).unwrap_or((0, 0));
            Ok(coloured + &restart_suffix(Some(restarts.reboot.as_str()), actionable, deferred))
        };
        let outcome = attempt();
        if outcome.is_err() {
            let _ = db::replace_pending_patches(thread_conn, &server.hostname, &[], false);
        }
        host_result(&server.hostname, outcome)
    };

    let results = run_parallel(
        &servers,
        work,
        &session_id,
        jobs,
        db_path,
        Some("Discovering patches"),
    );
    render_results("update results", &results);
    Ok(batch_exit_code(&results))
}
