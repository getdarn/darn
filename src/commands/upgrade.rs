use std::path::Path;

use crate::commands::batch::{
    finish_batch, host_result, record_restart_state, require_server, select_all_targets,
};
use crate::commands::session_id;
use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::hosts::get_handler;
use crate::orchestrator::{run_parallel, HostResult};
use crate::render::{restart_suffix, stream_to_terminal};
use crate::ssh::SshSession;

/// How many patches this run would actually install on a host.
///
/// What counts depends on the flags, so that `--security` does not drag in a
/// host whose only pending patches are ordinary ones.
fn selectable(
    conn: &rusqlite::Connection,
    hostname: &str,
    security: bool,
    non_security: bool,
) -> Result<i64, DarnError> {
    let (total, sec, non_sec) = db::count_pending_patches(conn, hostname)?;
    Ok(if security {
        sec
    } else if non_security {
        non_sec
    } else {
        total
    })
}

/// Everything `darn upgrade` was invoked with, minus the shared --db.
pub struct Options {
    pub target: String,
    pub jobs: usize,
    pub security: bool,
    pub non_security: bool,
    pub include_no_all: bool,
    pub dry_run: bool,
}

pub fn run(db_path: Option<&Path>, options: Options) -> Result<i32, DarnError> {
    let Options {
        target,
        mut jobs,
        security,
        non_security,
        include_no_all,
        dry_run,
    } = options;
    let target = target.as_str();
    if security && non_security {
        return Err(DarnError::Usage(
            "--security and --non-security are mutually exclusive".to_string(),
        ));
    }
    let conn = db::open_db(db_path)?;

    let (servers, description) = if target == "all" {
        let kind = if security {
            "security patches"
        } else if non_security {
            "non-security patches"
        } else {
            "patches"
        };
        // Selection comes from the last discovery, as it does for `reboot all`
        // and `restartservices all`: a host with nothing pending would only be
        // connected to, updated and left alone.
        let Some(servers) = select_all_targets(
            &conn,
            include_no_all,
            |s| Ok(selectable(&conn, &s.hostname, security, non_security)? > 0),
            &format!("No hosts have {kind} pending."),
        )?
        else {
            return Ok(0);
        };
        (servers, "Applying patches".to_string())
    } else {
        let single = require_server(&conn, target)?;
        jobs = 1;
        (vec![single], format!("Upgrading {target}"))
    };

    // One named host has the terminal to itself, so there is no reason to
    // withhold what it prints until the end. Under 'all' the hosts would be
    // interleaving, and the progress bar is the more readable summary.
    // A dry run has nothing of its own to stream, and letting the probes it
    // runs print would bury the plan in their output.
    let stream = target != "all" && !dry_run;
    let session_id = session_id();

    let work = |server: &Server,
                session: &mut SshSession<'_>,
                thread_conn: &rusqlite::Connection|
     -> HostResult {
        if stream {
            session.set_output_sink(Some(stream_to_terminal()));
        }
        session.set_dry_run(dry_run);
        let mut attempt = || -> Result<String, DarnError> {
            let handler = get_handler(&server.host_type)?;
            let known = db::get_pending_patches(thread_conn, &server.hostname)?;
            handler.upgrade(session, security, non_security, &known)?;
            if dry_run {
                // Stop here: re-discovering and recording would overwrite what
                // the database says about a host nothing has been done to.
                return Ok(session.take_plan().join("\n"));
            }
            match handler.discover(session) {
                Ok(patches) => {
                    db::replace_pending_patches(thread_conn, &server.hostname, &patches, true)?;
                }
                Err(_) => {
                    db::clear_pending_patches(thread_conn, &server.hostname)?;
                }
            }
            let restarts = record_restart_state(thread_conn, server, handler, session)?;
            let (actionable, deferred) =
                db::count_pending_services(thread_conn, &server.hostname).unwrap_or((0, 0));
            Ok(format!(
                "upgraded{}",
                restart_suffix(Some(restarts.reboot.as_str()), actionable, deferred)
            ))
        };
        host_result(&server.hostname, attempt())
    };

    let progress = (!stream).then_some(description.as_str());
    let results = run_parallel(&servers, work, &session_id, jobs, db_path, progress);
    Ok(finish_batch("upgrade", target, dry_run, &results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn the_flags_decide_which_pending_patches_make_a_host_worth_visiting() {
        let dir = TempDir::new().unwrap();
        let conn = db::open_db(Some(&dir.path().join("t.db"))).unwrap();
        let patch = |package: &str, is_security: bool| db::Patch::new(package, "1.0", is_security);
        for (host, patches) in [
            ("sec-only", vec![patch("openssl", true)]),
            ("nonsec-only", vec![patch("vim", false)]),
            ("both", vec![patch("openssl", true), patch("vim", false)]),
            ("nothing", vec![]),
        ] {
            db::add_server(&conn, host, "nobody", 22, None, "debian", None, None).unwrap();
            db::replace_pending_patches(&conn, host, &patches, true).unwrap();
        }

        let count =
            |host, security, non_security| selectable(&conn, host, security, non_security).unwrap();
        // (host, plain, --security, --non-security)
        for (host, plain, sec, non_sec) in [
            ("sec-only", 1, 1, 0),
            ("nonsec-only", 1, 0, 1),
            ("both", 2, 1, 1),
            ("nothing", 0, 0, 0),
        ] {
            assert_eq!(count(host, false, false), plain, "{host} plain");
            assert_eq!(count(host, true, false), sec, "{host} --security");
            assert_eq!(count(host, false, true), non_sec, "{host} --non-security");
        }
    }
}
