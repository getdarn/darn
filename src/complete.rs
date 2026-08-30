//! Candidates for dynamic shell completion.
//!
//! Everything here runs inside a tab-press, in a short-lived process the shell
//! spawned behind the user's cursor. So: never create or migrate a database,
//! never write to stdout or stderr, never panic, and swallow every error into
//! an empty list — a completion that finds nothing is a non-event, while one
//! that hangs, prints, or leaves files behind is a bug the user sees.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap_complete::CompletionCandidate;
use rusqlite::{Connection, OpenFlags};

use crate::db;
use crate::ssh::known_hosts::{glob_match, known_hosts_files, parse_line, plain_names};

/// How long to wait on a database another darn is writing. Long enough to
/// ride out a single commit, short enough that the shell never feels stuck.
const BUSY_TIMEOUT: Duration = Duration::from_millis(250);

/// Targets for upgrade/reboot/restartservices: the literal 'all', then hosts.
pub fn targets() -> Vec<CompletionCandidate> {
    // The engine sorts on display order with None first, so 'all' leads only
    // if every hostname is pushed explicitly behind it.
    let mut candidates = vec![CompletionCandidate::new("all")
        .help(Some("every managed host".into()))
        .display_order(Some(0))];
    candidates.extend(
        hostnames()
            .into_iter()
            .map(|candidate| candidate.display_order(Some(1))),
    );
    candidates
}

/// Hosts darn already manages.
pub fn hostnames() -> Vec<CompletionCandidate> {
    managed_hosts()
        .into_iter()
        .map(|(hostname, host_type)| {
            CompletionCandidate::new(hostname).help(host_type.map(Into::into))
        })
        .collect()
}

/// Targets for `server add`: managed hosts (re-adding refreshes them) plus
/// names ssh already knows about, which is where a first-time add comes from.
pub fn new_targets() -> Vec<CompletionCandidate> {
    let managed = managed_hosts();
    let mut candidates: Vec<CompletionCandidate> = managed
        .iter()
        .map(|(hostname, host_type)| {
            CompletionCandidate::new(hostname).help(host_type.clone().map(Into::into))
        })
        .collect();
    for (name, source) in ssh_known_names() {
        if managed.iter().any(|(hostname, _)| *hostname == name) {
            continue;
        }
        candidates.push(CompletionCandidate::new(name).help(Some(source.into())));
    }
    candidates
}

/// Hostname and host type of every server in the darn database, or nothing at
/// all if it is missing, locked or unreadable.
fn managed_hosts() -> Vec<(String, Option<String>)> {
    let path = db_path().unwrap_or_else(db::default_db_path);
    hostnames_from(&path)
}

/// The database this completion is about: the `--db` on the line being
/// completed, else darn's default path.
fn db_path() -> Option<PathBuf> {
    db_path_from_args(&std::env::args_os().collect::<Vec<_>>())
}

/// Find `--db` in a completion callback's argv.
///
/// The shell hands us `darn -- <the words on the command line>`, so the words
/// to search are the ones after the first `--`; a bare `darn` with no escape
/// is the registration call, which has no line to inspect.
fn db_path_from_args(args: &[OsString]) -> Option<PathBuf> {
    let escape = args.iter().position(|arg| arg == "--")?;
    let mut words = args[escape + 1..].iter();
    while let Some(word) = words.next() {
        let word = word.to_string_lossy();
        if let Some(value) = word.strip_prefix("--db=") {
            return Some(PathBuf::from(value));
        }
        if word == "--db" {
            // The value may be the word the cursor is still sitting on, which
            // is empty and means "not chosen yet" rather than "the empty path".
            let value = words.next()?;
            if value.is_empty() {
                return None;
            }
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// Read the server list straight out of the database file.
///
/// Deliberately not [`db::open_db`]: that creates the parent directory and the
/// database itself, switches journal mode, applies the schema and migrations,
/// and retries a locked database for five seconds — all wrong for a tab-press.
fn hostnames_from(path: &Path) -> Vec<(String, Option<String>)> {
    if !path.exists() {
        return Vec::new();
    }
    // A read-only connection to a WAL database needs the -shm file to already
    // exist, so try read-write first (without CREATE, so we still never make a
    // database) and keep read-only as the fallback for a file we may not own.
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .or_else(|_| Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY));
    let Ok(conn) = conn else {
        return Vec::new();
    };
    if conn.busy_timeout(BUSY_TIMEOUT).is_err() {
        return Vec::new();
    }
    // A darn3 database that has not been migrated yet may predate some
    // columns, so fall back to the one column that has always been there.
    query_hosts(
        &conn,
        "SELECT hostname, host_type FROM servers ORDER BY hostname",
    )
    .or_else(|_| {
        query_hosts(
            &conn,
            "SELECT hostname, NULL FROM servers ORDER BY hostname",
        )
    })
    .unwrap_or_default()
}

fn query_hosts(
    conn: &Connection,
    sql: &str,
) -> Result<Vec<(String, Option<String>)>, rusqlite::Error> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

/// Host names ssh knows, each with the file it came from, for `server add`.
fn ssh_known_names() -> Vec<(String, &'static str)> {
    let mut names: Vec<(String, &'static str)> = Vec::new();
    let mut push = |name: String, source: &'static str| {
        if !names.iter().any(|(seen, _)| *seen == name) {
            names.push((name, source));
        }
    };

    if let Some(config) = ssh_config_path() {
        if let Ok(content) = std::fs::read_to_string(&config) {
            for name in ssh_config_hosts(&content, config.parent()) {
                push(name, "~/.ssh/config");
            }
        }
    }
    for file in known_hosts_files() {
        if let Ok(content) = std::fs::read_to_string(&file) {
            for name in known_hosts_names(&content) {
                push(name, "known_hosts");
            }
        }
    }
    names
}

fn ssh_config_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".ssh").join("config"))
}

/// Literal host names from an ssh_config, following `Include` one level deep.
///
/// Patterns (`*`, `?`, negations) name no single host, so they are no use as
/// completions and are skipped. `Match` blocks have no host list at all.
fn ssh_config_hosts(content: &str, dir: Option<&Path>) -> Vec<String> {
    collect_hosts(content, dir, true)
}

fn collect_hosts(content: &str, dir: Option<&Path>, follow_includes: bool) -> Vec<String> {
    let mut names = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // ssh_config allows `Keyword value` and `Keyword=value`.
        let (keyword, rest) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((keyword, rest)) => (keyword, rest.trim_start_matches(['=', ' ', '\t'])),
            None => continue,
        };
        if keyword.eq_ignore_ascii_case("host") {
            for name in rest.split_whitespace() {
                if name.starts_with('!') || name.contains('*') || name.contains('?') {
                    continue;
                }
                names.push(name.to_string());
            }
        } else if keyword.eq_ignore_ascii_case("include") && follow_includes {
            for pattern in rest.split_whitespace() {
                for path in include_paths(pattern, dir) {
                    if let Ok(included) = std::fs::read_to_string(&path) {
                        // One level only: an Include inside an Include is rare,
                        // and not recursing means a cycle cannot hang the shell.
                        names.extend(collect_hosts(&included, path.parent(), false));
                    }
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Expand one `Include` argument: `~`, paths relative to ~/.ssh, and a glob in
/// the final component (`config.d/*.conf`), which is how it is nearly always
/// written.
fn include_paths(pattern: &str, dir: Option<&Path>) -> Vec<PathBuf> {
    let resolved = if let Some(rest) = pattern.strip_prefix("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(rest),
            None => return Vec::new(),
        }
    } else if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        match dir {
            Some(dir) => dir.join(pattern),
            None => return Vec::new(),
        }
    };

    let Some(file_name) = resolved
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
    else {
        return Vec::new();
    };
    if !file_name.contains('*') && !file_name.contains('?') {
        return vec![resolved];
    }
    let Some(parent) = resolved.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut matched: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| glob_match(&file_name, &entry.file_name().to_string_lossy()))
        .map(|entry| entry.path())
        .collect();
    matched.sort();
    matched
}

/// Plain host names from a known_hosts file.
///
/// Hashed entries (`|1|salt|hash`) cannot be reversed into a name, and pattern
/// entries name no single host, so both are skipped.
fn known_hosts_names(content: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for raw in content.lines() {
        // Marker lines (@cert-authority, @revoked) still name hosts worth
        // completing; darn stores the host bare, so `[host]:port` entries
        // complete to the name alone.
        let Some(line) = parse_line(raw) else {
            continue;
        };
        names.extend(plain_names(&line).map(str::to_string));
    }
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn db_flag_is_found_in_either_form() {
        let split = args(&["darn", "--", "darn", "--db", "/tmp/a.db", "upgrade", ""]);
        assert_eq!(db_path_from_args(&split), Some(PathBuf::from("/tmp/a.db")));
        let joined = args(&["darn", "--", "darn", "--db=/tmp/b.db", "upgrade", ""]);
        assert_eq!(db_path_from_args(&joined), Some(PathBuf::from("/tmp/b.db")));
    }

    #[test]
    fn db_flag_is_found_after_the_subcommand_too() {
        // --db is global, so it may follow the subcommand.
        let words = args(&["darn", "--", "darn", "upgrade", "--db", "/tmp/c.db", ""]);
        assert_eq!(db_path_from_args(&words), Some(PathBuf::from("/tmp/c.db")));
    }

    #[test]
    fn no_db_flag_means_the_default_database() {
        assert_eq!(db_path_from_args(&args(&["darn", "--", "darn", ""])), None);
        // Only the registration call, with no command line to inspect.
        assert_eq!(db_path_from_args(&args(&["darn"])), None);
    }

    #[test]
    fn words_before_the_escape_are_not_searched() {
        let words = args(&["darn", "--db", "/tmp/ours.db", "--", "darn", "upgrade", ""]);
        assert_eq!(db_path_from_args(&words), None);
    }

    #[test]
    fn an_unfinished_db_value_is_not_a_path() {
        let words = args(&["darn", "--", "darn", "--db", ""]);
        assert_eq!(db_path_from_args(&words), None);
    }

    #[test]
    fn hosts_come_back_sorted_with_their_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("darn.db");
        let conn = db::open_db(Some(&path)).unwrap();
        db::add_server(&conn, "web-02", "root", 22, None, "apt", None, None).unwrap();
        db::add_server(&conn, "web-01", "root", 22, None, "redhat", None, None).unwrap();
        drop(conn);

        assert_eq!(
            hostnames_from(&path),
            vec![
                ("web-01".to_string(), Some("redhat".to_string())),
                ("web-02".to_string(), Some("apt".to_string())),
            ]
        );
    }

    #[test]
    fn a_missing_database_yields_nothing_and_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("darn.db");
        assert!(hostnames_from(&path).is_empty());
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn a_file_that_is_not_a_database_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("darn.db");
        std::fs::write(&path, b"not a database").unwrap();
        assert!(hostnames_from(&path).is_empty());
    }

    #[test]
    fn ssh_config_host_lines_are_read_and_patterns_skipped() {
        let content = "
# a comment
Host web-01 web-02
    User admin
Host *.example.com !bad ??-test
    User nobody
Host=router
Match host anything
    User someone
";
        assert_eq!(
            ssh_config_hosts(content, None),
            vec!["router", "web-01", "web-02"]
        );
    }

    #[test]
    fn ssh_config_include_is_followed_one_level() {
        let dir = tempfile::tempdir().unwrap();
        let included = dir.path().join("config.d");
        std::fs::create_dir(&included).unwrap();
        std::fs::write(included.join("hosts.conf"), "Host from-include\n").unwrap();
        std::fs::write(included.join("ignored.txt"), "Host not-matched\n").unwrap();
        let content = "Include config.d/*.conf\nHost direct\n";

        assert_eq!(
            ssh_config_hosts(content, Some(dir.path())),
            vec!["direct", "from-include"]
        );
    }

    #[test]
    fn known_hosts_names_skip_hashed_and_pattern_entries() {
        let content = "
# comment
web-01,192.0.2.10 ssh-ed25519 AAAA...
[web-02]:2222 ssh-rsa AAAA...
|1|c2FsdA==|aGFzaA== ssh-ed25519 AAAA...
*.example.com ssh-ed25519 AAAA...
@cert-authority ca-host ssh-ed25519 AAAA...
";
        assert_eq!(
            known_hosts_names(content),
            vec!["192.0.2.10", "ca-host", "web-01", "web-02"]
        );
    }
}
