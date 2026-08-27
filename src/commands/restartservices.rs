use std::path::Path;

use rusqlite::Connection;

use crate::commands::{
    batch_exit_code, confirm, no_targets_message, record_restart_state, servers_for_all, session_id,
};
use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::get_handler;
use crate::orchestrator::{run_parallel, HostResult};
use crate::render::{bold, dim, green, red, render_plan, render_results, yellow};
use crate::ssh::SshSession;

pub fn run(
    db_path: Option<&Path>,
    target: &str,
    jobs: usize,
    yes: bool,
    force: bool,
    include_no_all: bool,
    dry_run: bool,
) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;

    let selectable = |conn: &Connection, hostname: &str| -> Result<i64, DarnError> {
        let (actionable, deferred) = db::count_pending_services(conn, hostname)?;
        Ok(if force {
            actionable + deferred
        } else {
            actionable
        })
    };

    let (servers, description) = if target == "all" {
        let candidates = servers_for_all(&conn, include_no_all)?;
        if let Some(empty) = no_targets_message(&conn, &candidates)? {
            println!("{empty}");
            return Ok(0);
        }
        let mut servers = Vec::new();
        for s in candidates {
            if selectable(&conn, &s.hostname)? > 0 {
                servers.push(s);
            }
        }
        if servers.is_empty() {
            println!("{}", green("No hosts have services awaiting a restart."));
            return Ok(0);
        }
        (servers, "Restarting services".to_string())
    } else {
        let Some(single) = db::get_server(&conn, target)? else {
            return Err(DarnError::Other(format!("no such server: {target}")));
        };
        if selectable(&conn, target)? == 0 {
            let (_, deferred) = db::count_pending_services(&conn, target)?;
            if deferred > 0 {
                return Err(DarnError::Other(format!(
                    "{target}: all {deferred} stale service(s) are deferred — the \
host's own restart policy declined them; pass --force to restart them anyway"
                )));
            }
            return Err(DarnError::Other(format!(
                "{target} has no services awaiting a restart; run `darn update` first"
            )));
        }
        (vec![single], format!("Restarting services on {target}"))
    };

    let units_for = |conn: &Connection, hostname: &str| -> Result<Vec<String>, DarnError> {
        db::get_pending_services(conn, hostname, if force { None } else { Some(false) })
    };

    if !yes && !dry_run {
        println!("About to restart:");
        for s in &servers {
            println!(
                "  {} — {}",
                bold(&s.hostname),
                units_for(&conn, &s.hostname)?.join(", ")
            );
        }
        if force {
            println!(
                "{}",
                red(
                    "--force bypasses the host's own restart policy; units such as \
dbus and systemd-logind are excluded by that policy because \
bouncing them disrupts running sessions."
                )
            );
        }
        if !confirm(&format!("Restart services on {} host(s)?", servers.len())) {
            println!("{}", yellow("Aborted."));
            return Ok(0);
        }
    }

    let session_id = session_id();

    let work = |server: &Server,
                session: &mut SshSession<'_>,
                thread_conn: &rusqlite::Connection|
     -> HostResult {
        session.set_dry_run(dry_run);
        let mut attempt = || -> Result<String, DarnError> {
            let handler = get_handler(&server.host_type)?;
            let units = units_for(thread_conn, &server.hostname)?;
            handler.restart_services(session, &units, force)?;
            if dry_run {
                // Re-probing would find every unit still stale and mark the
                // lot deferred, which is a lie about a restart never attempted.
                return Ok(session.take_plan().join("\n"));
            }
            // Re-probe rather than assuming: local policy may have declined some.
            let restarts = record_restart_state(thread_conn, server, handler, session)?;
            let declined: Vec<String> = units
                .iter()
                .filter(|unit| restarts.services.contains(unit))
                .cloned()
                .collect();
            db::mark_services_deferred(thread_conn, &server.hostname, &declined)?;
            let mut message = format!(
                "restarted {} of {} service(s)",
                units.len() - declined.len(),
                units.len()
            );
            if !declined.is_empty() {
                message.push(' ');
                message.push_str(&dim(&format!(
                    "· {} deferred by host policy",
                    declined.len()
                )));
            }
            Ok(message)
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

    let results = run_parallel(
        &servers,
        work,
        &session_id,
        jobs,
        db_path,
        Some(&description),
    );
    let title = if target == "all" {
        "restartservices all results".to_string()
    } else {
        format!("restartservices {target}")
    };
    if dry_run {
        render_plan(&format!("{title} — dry run"), &results);
    } else {
        render_results(&title, &results);
    }
    Ok(batch_exit_code(&results))
}
