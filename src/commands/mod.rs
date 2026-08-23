pub mod completions;
pub mod log;
pub mod man;
pub mod reboot;
pub mod restartservices;
pub mod server;
pub mod shell;
pub mod status;
pub mod update;
pub mod upgrade;

use std::io::Write;

use rusqlite::Connection;

use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::{HostHandler, Reboot, RestartCheck};
use crate::render::yellow;
use crate::ssh::SshSession;

pub fn session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Probe and store what a host needs restarted, tolerating probe failure.
pub fn record_restart_state(
    conn: &Connection,
    server: &Server,
    handler: &dyn HostHandler,
    session: &mut SshSession<'_>,
) -> Result<RestartCheck, DarnError> {
    let check = match handler.check_restarts(session) {
        Ok(check) => check,
        Err(e) => RestartCheck::new(Reboot::Unknown, Some(&format!("restart check failed: {e}"))),
    };
    db::set_reboot_state(
        conn,
        &server.hostname,
        Some(check.reboot.as_str()),
        check.reboot_detail.as_deref(),
    )?;
    db::replace_pending_services(conn, &server.hostname, &check.services)?;
    Ok(check)
}

/// Resolve the literal target 'all', honouring the per-host --no-all mark.
pub fn servers_for_all(conn: &Connection, include_no_all: bool) -> Result<Vec<Server>, DarnError> {
    let servers = db::list_servers(conn)?;
    Ok(if include_no_all {
        servers
    } else {
        servers.into_iter().filter(|s| !s.no_all).collect()
    })
}

/// Explain an empty 'all' selection: nothing configured, or all held back.
pub fn no_targets_message(
    conn: &Connection,
    selected: &[Server],
) -> Result<Option<String>, DarnError> {
    if !selected.is_empty() {
        return Ok(None);
    }
    if !db::list_servers(conn)?.is_empty() {
        return Ok(Some(yellow(
            "Every host is marked --no-all; name one explicitly or pass --include-no-all.",
        )));
    }
    Ok(Some(yellow("No servers configured.")))
}

/// Ask a yes/no question defaulting to no, like click.confirm.
pub fn confirm(prompt: &str) -> bool {
    print!("{prompt} [y/N]: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Exit code for a batch: 1 if any host failed, else 0.
pub fn batch_exit_code(results: &[crate::orchestrator::HostResult]) -> i32 {
    if results.iter().any(|r| !r.ok) {
        1
    } else {
        0
    }
}
