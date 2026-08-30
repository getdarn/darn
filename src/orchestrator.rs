use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::Connection;

use crate::db::{self, Server};
use crate::ssh::{Recorder, SshSession, DEFAULT_CONNECT_TIMEOUT};

#[derive(Clone, Debug)]
pub struct HostResult {
    pub hostname: String,
    pub ok: bool,
    pub message: String,
}

/// A Recorder that logs every command to the command_log under `session_id`.
pub fn command_recorder<'a>(
    conn: &'a Connection,
    hostname: &'a str,
    session_id: &'a str,
) -> Recorder<'a> {
    Box::new(move |command, stdout, stderr, exit_code| {
        let _ = db::record_command(
            conn,
            hostname,
            session_id,
            command,
            Some(stdout),
            Some(stderr),
            Some(exit_code),
        );
    })
}

/// Run `work` against every server, at most `jobs` hosts at a time.
///
/// Each task gets its own DB connections (SQLite connections are not Sync;
/// WAL plus the 30s busy timeout absorbs writer contention) and its own SSH
/// session wired to a recorder that logs every command under `session_id`.
/// Connect failures become failed results rather than aborting the batch.
///
/// `progress` is the message for the progress bar, or None for no bar at all —
/// which is what a caller streaming a host's output live wants, since the two
/// would otherwise be redrawing over each other.
pub fn run_parallel<F>(
    servers: &[Server],
    work: F,
    session_id: &str,
    jobs: usize,
    db_path: Option<&Path>,
    progress: Option<&str>,
) -> Vec<HostResult>
where
    F: Fn(&Server, &mut SshSession<'_>, &Connection) -> HostResult + Sync,
{
    if servers.is_empty() {
        return Vec::new();
    }

    let bar = progress.map(|description| {
        let bar = ProgressBar::new(servers.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner} {msg} {bar:40} {pos}/{len} {percent:>3}% {elapsed}",
            )
            .unwrap(),
        );
        bar.set_message(description.to_string());
        bar.enable_steady_tick(Duration::from_millis(100));
        bar
    });

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<HostResult>> = Mutex::new(Vec::with_capacity(servers.len()));
    let workers = jobs.max(1).min(servers.len());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= servers.len() {
                    break;
                }
                let result = run_one(&servers[i], &work, session_id, db_path);
                results.lock().unwrap().push(result);
                if let Some(bar) = &bar {
                    bar.inc(1);
                }
            });
        }
    });
    if let Some(bar) = &bar {
        bar.finish_and_clear();
    }

    let mut results = results.into_inner().unwrap();
    results.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    results
}

fn run_one<F>(server: &Server, work: &F, session_id: &str, db_path: Option<&Path>) -> HostResult
where
    F: Fn(&Server, &mut SshSession<'_>, &Connection) -> HostResult + Sync,
{
    let fail = |message: String| HostResult {
        hostname: server.hostname.clone(),
        ok: false,
        message,
    };

    let recorder_conn = match db::open_db(db_path) {
        Ok(conn) => conn,
        Err(e) => return fail(e.to_string()),
    };
    let work_conn = match db::open_db(db_path) {
        Ok(conn) => conn,
        Err(e) => return fail(e.to_string()),
    };

    let recorder = command_recorder(&recorder_conn, &server.hostname, session_id);

    // Bound to a local so the session (which borrows recorder_conn through
    // its recorder) is dropped before the connection, not at the fn's end.
    let connected = SshSession::connect(
        &server.hostname,
        &server.ssh_user,
        server.ssh_port,
        server.ssh_key_path.as_deref(),
        Some(recorder),
        DEFAULT_CONNECT_TIMEOUT,
    );
    match connected {
        Ok(mut session) => work(server, &mut session, &work_conn),
        Err(e) => fail(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn server(hostname: &str) -> Server {
        Server {
            hostname: hostname.to_string(),
            ssh_user: "nobody".to_string(),
            // A port in the reserved range that nothing listens on, so the
            // connect fails fast without touching the network.
            ssh_port: 1,
            ssh_key_path: None,
            host_type: "debian".to_string(),
            distribution: None,
            last_update_at: None,
            last_update_ok: None,
            reboot_required: None,
            reboot_detail: None,
            no_all: false,
        }
    }

    #[test]
    fn empty_server_list_returns_no_results() {
        let results = run_parallel(
            &[],
            |_, _, _| unreachable!(),
            "sid",
            4,
            None,
            Some("Working"),
        );
        assert!(results.is_empty());
    }

    #[test]
    fn no_progress_message_means_no_bar_but_the_same_results() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t.db");
        let servers = vec![server("127.0.0.1")];
        let results = run_parallel(
            &servers,
            |_, _, _| unreachable!(),
            "sid",
            1,
            Some(&path),
            None,
        );
        assert_eq!(results.len(), 1);
        assert!(!results[0].ok);
    }

    #[test]
    fn connect_failures_become_failed_results_sorted_by_hostname() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t.db");
        let servers = vec![server("127.0.0.2"), server("127.0.0.1")];
        let results = run_parallel(
            &servers,
            |_, _, _| unreachable!("work must not run when connect fails"),
            "sid",
            4,
            Some(&path),
            Some("Working"),
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].hostname, "127.0.0.1");
        assert_eq!(results[1].hostname, "127.0.0.2");
        for r in &results {
            assert!(!r.ok);
            assert!(r.message.contains("failed to connect"), "{}", r.message);
        }
    }
}
