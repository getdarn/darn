use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::commands::batch::{
    finish_batch, host_result, require_server, select_all_targets, store_restart_state,
};
use crate::commands::{confirm, session_id};
use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::{get_handler, Reboot, RestartCheck};
use crate::orchestrator::{command_recorder, run_parallel, HostResult};
use crate::render::{bold, restart_suffix, yellow};
use crate::ssh::SshSession;

pub const BOOT_ID_CMD: &str = "cat /proc/sys/kernel/random/boot_id 2>/dev/null || true";
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const POLL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll until the host is back up, and re-probe its reboot state.
///
/// A changed boot id proves the host actually rebooted rather than never
/// having gone down. Hosts that cannot report one (RouterOS) fall back to
/// "the connection dropped and then came back".
fn wait_for_reboot(
    server: &Server,
    conn: &Connection,
    session_id: &str,
    previous_boot_id: &str,
    timeout: f64,
) -> Result<(f64, RestartCheck), DarnError> {
    let started = Instant::now();
    let deadline = Duration::from_secs_f64(timeout.max(0.0));
    let mut saw_down = false;
    while started.elapsed() < deadline {
        std::thread::sleep(POLL_INTERVAL);
        let poll = || -> Result<Option<(f64, RestartCheck)>, DarnError> {
            let recorder = command_recorder(conn, &server.hostname, session_id);
            let mut session = SshSession::connect(
                &server.hostname,
                &server.ssh_user,
                server.ssh_port,
                server.ssh_key_path.as_deref(),
                Some(recorder),
                POLL_CONNECT_TIMEOUT,
            )?;
            let boot_id = session
                .probe(BOOT_ID_CMD, false, false)?
                .stdout
                .trim()
                .to_string();
            let rebooted = if !boot_id.is_empty() && !previous_boot_id.is_empty() {
                boot_id != previous_boot_id
            } else {
                saw_down
            };
            if !rebooted {
                return Ok(None);
            }
            let check = match get_handler(&server.host_type)
                .and_then(|h| h.check_restarts(&mut session))
            {
                Ok(check) => check,
                // The host is back, which is what matters here.
                Err(e) => {
                    RestartCheck::new(Reboot::Unknown, Some(&format!("restart check failed: {e}")))
                }
            };
            Ok(Some((started.elapsed().as_secs_f64(), check)))
        };
        match poll() {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => continue,
            Err(_) => {
                // Unreachable is the expected state while the host is down.
                saw_down = true;
            }
        }
    }
    Err(DarnError::Timeout(format!(
        "did not come back within {timeout:.0}s"
    )))
}

/// Everything `darn reboot` was invoked with, minus the shared --db.
pub struct Options {
    pub target: String,
    pub jobs: usize,
    pub yes: bool,
    pub force: bool,
    pub wait: bool,
    pub timeout: f64,
    pub include_no_all: bool,
    pub dry_run: bool,
}

pub fn run(db_path: Option<&Path>, options: Options) -> Result<i32, DarnError> {
    let Options {
        target,
        mut jobs,
        yes,
        force,
        wait,
        timeout,
        include_no_all,
        dry_run,
    } = options;
    let target = target.as_str();
    let conn = db::open_db(db_path)?;

    let (servers, description) = if target == "all" {
        let Some(servers) = select_all_targets(
            &conn,
            include_no_all,
            |s| {
                let flag = s.reboot_required.as_deref().and_then(Reboot::parse);
                Ok(if force {
                    flag != Some(Reboot::No)
                } else {
                    flag == Some(Reboot::Yes)
                })
            },
            "No hosts are waiting on a reboot.",
        )?
        else {
            return Ok(0);
        };
        (servers, "Rebooting".to_string())
    } else {
        let single = require_server(&conn, target)?;
        if !force && single.reboot_required.as_deref().and_then(Reboot::parse) != Some(Reboot::Yes)
        {
            let state = single
                .reboot_required
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "not yet checked".to_string());
            return Err(DarnError::Other(format!(
                "{target} is not flagged as needing a reboot ({state}); \
run `darn update` first, or pass --force"
            )));
        }
        jobs = 1;
        (vec![single], format!("Rebooting {target}"))
    };

    if !yes && !dry_run {
        println!("About to reboot:");
        for s in &servers {
            let reason = s
                .reboot_detail
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| s.reboot_required.clone().filter(|s| !s.is_empty()))
                .unwrap_or_else(|| "not checked".to_string());
            println!("  {} — {reason}", bold(&s.hostname));
        }
        if !confirm(&format!("Reboot {} host(s)?", servers.len())) {
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
            let previous_boot_id = session
                .probe(BOOT_ID_CMD, false, false)?
                .stdout
                .trim()
                .to_string();
            handler.reboot(session)?;
            if dry_run {
                // Nothing went down, so there is nothing to wait for and no
                // reboot flag to clear.
                return Ok(session.take_plan().join("\n"));
            }
            if !wait {
                // State is unknowable until it is back; do not leave a stale flag.
                db::set_reboot_state(thread_conn, &server.hostname, None, None)?;
                return Ok("reboot issued".to_string());
            }
            let (elapsed, check) =
                wait_for_reboot(server, thread_conn, &session_id, &previous_boot_id, timeout)?;
            store_restart_state(thread_conn, &server.hostname, &check)?;
            let (actionable, deferred) =
                db::count_pending_services(thread_conn, &server.hostname).unwrap_or((0, 0));
            Ok(format!(
                "rebooted (up in {elapsed:.0}s){}",
                restart_suffix(Some(check.reboot.as_str()), actionable, deferred)
            ))
        };
        let outcome = attempt();
        if let Err(DarnError::Timeout(_)) = &outcome {
            let _ = db::set_reboot_state(thread_conn, &server.hostname, None, None);
        }
        host_result(&server.hostname, outcome)
    };

    let results = run_parallel(
        &servers,
        work,
        &session_id,
        jobs,
        db_path,
        Some(&description),
    );
    Ok(finish_batch("reboot", target, dry_run, &results))
}
