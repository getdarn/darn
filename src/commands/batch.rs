//! Shared plumbing for the batch commands (update, upgrade, reboot,
//! restartservices): target selection, restart-state bookkeeping, and the
//! result mapping and presentation they all share.

use rusqlite::Connection;

use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::{HostHandler, Reboot, RestartCheck};
use crate::orchestrator::HostResult;
use crate::render::{green, render_plan, render_results, yellow};
use crate::ssh::SshSession;

/// Look up a named server, or fail with the canonical "no such server" error.
pub fn require_server(conn: &Connection, hostname: &str) -> Result<Server, DarnError> {
    db::get_server(conn, hostname)?
        .ok_or_else(|| DarnError::Other(format!("no such server: {hostname}")))
}

/// Resolve the literal target 'all': honour the per-host --no-all mark, apply
/// the command's own `keep` filter, and explain an empty selection.
///
/// `Ok(None)` means the explanation was printed and the command should exit 0;
/// `none_selected` is the line for "servers exist but none passed the filter".
pub fn select_all_targets(
    conn: &Connection,
    include_no_all: bool,
    mut keep: impl FnMut(&Server) -> Result<bool, DarnError>,
    none_selected: &str,
) -> Result<Option<Vec<Server>>, DarnError> {
    let candidates = servers_for_all(conn, include_no_all)?;
    if let Some(empty) = no_targets_message(conn, &candidates)? {
        println!("{empty}");
        return Ok(None);
    }
    let mut servers = Vec::new();
    for s in candidates {
        if keep(&s)? {
            servers.push(s);
        }
    }
    if servers.is_empty() {
        println!("{}", green(none_selected));
        return Ok(None);
    }
    Ok(Some(servers))
}

/// Resolve the literal target 'all', honouring the per-host --no-all mark.
fn servers_for_all(conn: &Connection, include_no_all: bool) -> Result<Vec<Server>, DarnError> {
    let servers = db::list_servers(conn)?;
    Ok(if include_no_all {
        servers
    } else {
        servers.into_iter().filter(|s| !s.no_all).collect()
    })
}

/// Explain an empty 'all' selection: nothing configured, or all held back.
fn no_targets_message(conn: &Connection, selected: &[Server]) -> Result<Option<String>, DarnError> {
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

/// Store a host's probed restart needs: the reboot flag and the stale services.
pub fn store_restart_state(
    conn: &Connection,
    hostname: &str,
    check: &RestartCheck,
) -> Result<(), DarnError> {
    db::set_reboot_state(
        conn,
        hostname,
        Some(check.reboot.as_str()),
        check.reboot_detail.as_deref(),
    )?;
    db::replace_pending_services(conn, hostname, &check.services)?;
    Ok(())
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
    store_restart_state(conn, &server.hostname, &check)?;
    Ok(check)
}

/// The Ok/Err → HostResult mapping every work closure ends with.
///
/// Purely a conversion: a command with error side-effects (clearing stale
/// state, say) runs them at the call site before converting.
pub fn host_result(hostname: &str, outcome: Result<String, DarnError>) -> HostResult {
    match outcome {
        Ok(message) => HostResult {
            hostname: hostname.to_string(),
            ok: true,
            message,
        },
        Err(e) => HostResult {
            hostname: hostname.to_string(),
            ok: false,
            message: e.to_string(),
        },
    }
}

/// Title the batch, render it (as a plan under --dry-run), and report its
/// exit code.
pub fn finish_batch(command: &str, target: &str, dry_run: bool, results: &[HostResult]) -> i32 {
    let title = if target == "all" {
        format!("{command} all results")
    } else {
        format!("{command} {target}")
    };
    if dry_run {
        render_plan(&format!("{title} — dry run"), results);
    } else {
        render_results(&title, results);
    }
    batch_exit_code(results)
}

/// Exit code for a batch: 1 if any host failed, else 0.
pub fn batch_exit_code(results: &[HostResult]) -> i32 {
    if results.iter().any(|r| !r.ok) {
        1
    } else {
        0
    }
}
