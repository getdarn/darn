use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::commands::{batch_exit_code, confirm, no_targets_message, servers_for_all, session_id};
use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::{get_handler, Reboot, RestartCheck};
use crate::orchestrator::{run_parallel, HostResult};
use crate::render::{bold, green, render_results, restart_suffix, yellow};
use crate::ssh::{Recorder, SshSession};

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
            let recorder: Recorder<'_> = Box::new(|command, stdout, stderr, exit_code| {
                let _ = db::record_command(
                    conn,
                    &server.hostname,
                    session_id,
                    command,
                    Some(stdout),
                    Some(stderr),
                    Some(exit_code),
                );
            });
            let mut session = SshSession::connect(
                &server.hostname,
                &server.ssh_user,
                server.ssh_port,
                server.ssh_key_path.as_deref(),
                Some(recorder),
                POLL_CONNECT_TIMEOUT,
            )?;
            let boot_id = session
                .run(BOOT_ID_CMD, false, false)?
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

#[allow(clippy::too_many_arguments)]
pub fn run(
    db_path: Option<&Path>,
    target: &str,
    mut jobs: usize,
    yes: bool,
    force: bool,
    wait: bool,
    timeout: f64,
    include_no_all: bool,
) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;

    let (servers, description) = if target == "all" {
        let candidates = servers_for_all(&conn, include_no_all)?;
        if let Some(empty) = no_targets_message(&conn, &candidates)? {
            println!("{empty}");
            return Ok(0);
        }
        let servers: Vec<Server> = if force {
            candidates
                .into_iter()
                .filter(|s| s.reboot_required.as_deref() != Some("no"))
                .collect()
        } else {
            candidates
                .into_iter()
                .filter(|s| s.reboot_required.as_deref() == Some("yes"))
                .collect()
        };
        if servers.is_empty() {
            println!("{}", green("No hosts are waiting on a reboot."));
            return Ok(0);
        }
        (servers, "Rebooting".to_string())
    } else {
        let Some(single) = db::get_server(&conn, target)? else {
            return Err(DarnError::Other(format!("no such server: {target}")));
        };
        if !force && single.reboot_required.as_deref() != Some("yes") {
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

    if !yes {
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
        let mut attempt = || -> Result<String, DarnError> {
            let handler = get_handler(&server.host_type)?;
            let previous_boot_id = session
                .run(BOOT_ID_CMD, false, false)?
                .stdout
                .trim()
                .to_string();
            handler.reboot(session)?;
            if !wait {
                // State is unknowable until it is back; do not leave a stale flag.
                db::set_reboot_state(thread_conn, &server.hostname, None, None)?;
                return Ok("reboot issued".to_string());
            }
            let (elapsed, check) =
                wait_for_reboot(server, thread_conn, &session_id, &previous_boot_id, timeout)?;
            db::set_reboot_state(
                thread_conn,
                &server.hostname,
                Some(check.reboot.as_str()),
                check.reboot_detail.as_deref(),
            )?;
            db::replace_pending_services(thread_conn, &server.hostname, &check.services)?;
            Ok(format!(
                "rebooted (up in {elapsed:.0}s){}",
                restart_suffix(thread_conn, &server.hostname, Some(check.reboot.as_str()))
            ))
        };
        match attempt() {
            Ok(message) => HostResult {
                hostname: server.hostname.clone(),
                ok: true,
                message,
            },
            Err(e) => {
                if matches!(e, DarnError::Timeout(_)) {
                    let _ = db::set_reboot_state(thread_conn, &server.hostname, None, None);
                }
                HostResult {
                    hostname: server.hostname.clone(),
                    ok: false,
                    message: e.to_string(),
                }
            }
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
        "reboot all results".to_string()
    } else {
        format!("reboot {target}")
    };
    render_results(&title, &results);
    Ok(batch_exit_code(&results))
}
