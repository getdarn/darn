use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::errors::DarnError;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS servers (
    hostname        TEXT PRIMARY KEY,
    ssh_user        TEXT NOT NULL,
    ssh_port        INTEGER NOT NULL DEFAULT 22,
    ssh_key_path    TEXT,
    host_type       TEXT NOT NULL,
    distribution    TEXT,
    no_all          INTEGER NOT NULL DEFAULT 0,
    last_update_at  TIMESTAMP,
    last_update_ok  INTEGER,
    reboot_required TEXT,
    reboot_detail   TEXT
);

CREATE TABLE IF NOT EXISTS pending_patches (
    hostname       TEXT NOT NULL,
    package        TEXT NOT NULL,
    version        TEXT,
    is_security    INTEGER NOT NULL DEFAULT 0,
    discovered_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (hostname, package),
    FOREIGN KEY (hostname) REFERENCES servers(hostname) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pending_services (
    hostname       TEXT NOT NULL,
    service        TEXT NOT NULL,
    deferred       INTEGER NOT NULL DEFAULT 0,
    discovered_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (hostname, service),
    FOREIGN KEY (hostname) REFERENCES servers(hostname) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS command_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname    TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    command     TEXT NOT NULL,
    stdout      TEXT,
    stderr      TEXT,
    exit_code   INTEGER,
    run_at      TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_command_log_host_session
    ON command_log (hostname, session_id, id);
";

#[derive(Clone, Debug, PartialEq)]
pub struct Server {
    pub hostname: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub ssh_key_path: Option<String>,
    pub host_type: String,
    pub distribution: Option<String>,
    pub last_update_at: Option<String>,
    pub last_update_ok: Option<i64>,
    pub reboot_required: Option<String>,
    pub reboot_detail: Option<String>,
    pub no_all: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Patch {
    pub package: String,
    pub version: Option<String>,
    pub is_security: bool,
}

#[cfg(test)]
impl Patch {
    pub fn new(package: &str, version: &str, is_security: bool) -> Self {
        Patch {
            package: package.to_string(),
            version: Some(version.to_string()),
            is_security,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LoggedCommand {
    pub command: String,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i64>,
    pub run_at: String,
}

pub fn default_db_path() -> PathBuf {
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(xdg) if !xdg.is_empty() => PathBuf::from(xdg),
        _ => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local")
            .join("share"),
    };
    base.join("darn").join("darn.db")
}

pub fn open_db(path: Option<&Path>) -> Result<Connection, DarnError> {
    let target = match path {
        Some(p) => p.to_path_buf(),
        None => default_db_path(),
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| DarnError::Other(format!("cannot create {}: {e}", parent.display())))?;
    }
    let conn = Connection::open(&target)?;
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // Switching journal mode takes an exclusive lock that bypasses the busy
    // handler, so concurrent opens of a fresh database race here; retry.
    let mut attempts = 0;
    loop {
        let result: Result<String, _> =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0));
        match result {
            Ok(_) => break,
            Err(e) => {
                attempts += 1;
                if attempts >= 50 {
                    return Err(e.into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    conn.execute_batch(SCHEMA)?;
    migrate(&conn)?;
    Ok(conn)
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, DarnError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let cols = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(cols)
}

fn migrate(conn: &Connection) -> Result<(), DarnError> {
    let cols = table_columns(conn, "servers")?;
    for column in ["distribution", "reboot_required", "reboot_detail"] {
        if !cols.iter().any(|c| c == column) {
            conn.execute_batch(&format!("ALTER TABLE servers ADD COLUMN {column} TEXT"))?;
        }
    }
    if !cols.is_empty() && !cols.iter().any(|c| c == "no_all") {
        conn.execute_batch("ALTER TABLE servers ADD COLUMN no_all INTEGER NOT NULL DEFAULT 0")?;
    }

    let service_cols = table_columns(conn, "pending_services")?;
    if !service_cols.is_empty() && !service_cols.iter().any(|c| c == "deferred") {
        conn.execute_batch(
            "ALTER TABLE pending_services ADD COLUMN deferred INTEGER NOT NULL DEFAULT 0",
        )?;
    }
    Ok(())
}

pub fn utcnow() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, false)
}

/// Add or refresh a server record.
///
/// `no_all` left as None keeps whatever a re-added host already had: the flag
/// records a standing decision about the host, not a property of this add.
#[allow(clippy::too_many_arguments)]
pub fn add_server(
    conn: &Connection,
    hostname: &str,
    ssh_user: &str,
    ssh_port: u16,
    ssh_key_path: Option<&str>,
    host_type: &str,
    distribution: Option<&str>,
    no_all: Option<bool>,
) -> Result<(), DarnError> {
    let flag = no_all.map(|b| b as i64);
    conn.execute(
        "
        INSERT INTO servers
            (hostname, ssh_user, ssh_port, ssh_key_path, host_type, distribution, no_all)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, COALESCE(?7, 0))
        ON CONFLICT(hostname) DO UPDATE SET
            ssh_user      = excluded.ssh_user,
            ssh_port      = excluded.ssh_port,
            ssh_key_path  = excluded.ssh_key_path,
            host_type     = excluded.host_type,
            distribution  = excluded.distribution,
            no_all        = COALESCE(?7, servers.no_all)
        ",
        params![hostname, ssh_user, ssh_port, ssh_key_path, host_type, distribution, flag],
    )?;
    Ok(())
}

/// Record whether a host is left out of 'all' targets.
pub fn set_no_all(conn: &Connection, hostname: &str, no_all: bool) -> Result<bool, DarnError> {
    let n = conn.execute(
        "UPDATE servers SET no_all = ?1 WHERE hostname = ?2",
        params![no_all as i64, hostname],
    )?;
    Ok(n > 0)
}

pub fn set_distribution(
    conn: &Connection,
    hostname: &str,
    distribution: Option<&str>,
) -> Result<(), DarnError> {
    conn.execute(
        "UPDATE servers SET distribution = ?1 WHERE hostname = ?2",
        params![distribution, hostname],
    )?;
    Ok(())
}

/// Record whether a host needs rebooting ("yes" / "no" / "unknown").
pub fn set_reboot_state(
    conn: &Connection,
    hostname: &str,
    required: Option<&str>,
    detail: Option<&str>,
) -> Result<(), DarnError> {
    conn.execute(
        "UPDATE servers SET reboot_required = ?1, reboot_detail = ?2 WHERE hostname = ?3",
        params![required, detail, hostname],
    )?;
    Ok(())
}

pub fn remove_server(conn: &Connection, hostname: &str) -> Result<bool, DarnError> {
    let n = conn.execute("DELETE FROM servers WHERE hostname = ?1", params![hostname])?;
    Ok(n > 0)
}

pub fn get_server(conn: &Connection, hostname: &str) -> Result<Option<Server>, DarnError> {
    let server = conn
        .query_row(
            "SELECT hostname, ssh_user, ssh_port, ssh_key_path, host_type, distribution,
                    last_update_at, last_update_ok, reboot_required, reboot_detail, no_all
               FROM servers WHERE hostname = ?1",
            params![hostname],
            row_to_server,
        )
        .optional()?;
    Ok(server)
}

pub fn list_servers(conn: &Connection) -> Result<Vec<Server>, DarnError> {
    let mut stmt = conn.prepare(
        "SELECT hostname, ssh_user, ssh_port, ssh_key_path, host_type, distribution,
                last_update_at, last_update_ok, reboot_required, reboot_detail, no_all
           FROM servers ORDER BY hostname",
    )?;
    let servers = stmt
        .query_map([], row_to_server)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(servers)
}

fn row_to_server(row: &rusqlite::Row<'_>) -> rusqlite::Result<Server> {
    Ok(Server {
        hostname: row.get(0)?,
        ssh_user: row.get(1)?,
        ssh_port: row.get(2)?,
        ssh_key_path: row.get(3)?,
        host_type: row.get(4)?,
        distribution: row.get(5)?,
        last_update_at: row.get(6)?,
        last_update_ok: row.get(7)?,
        reboot_required: row.get(8)?,
        reboot_detail: row.get(9)?,
        no_all: row.get::<_, i64>(10)? != 0,
    })
}

pub fn replace_pending_patches(
    conn: &Connection,
    hostname: &str,
    patches: &[Patch],
    success: bool,
) -> Result<(), DarnError> {
    let now = utcnow();
    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<(), DarnError> {
        conn.execute(
            "DELETE FROM pending_patches WHERE hostname = ?1",
            params![hostname],
        )?;
        let mut stmt = conn.prepare(
            "INSERT INTO pending_patches (hostname, package, version, is_security, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for p in patches {
            stmt.execute(params![
                hostname,
                p.package,
                p.version,
                p.is_security as i64,
                now
            ])?;
        }
        conn.execute(
            "UPDATE servers SET last_update_at = ?1, last_update_ok = ?2 WHERE hostname = ?3",
            params![now, success as i64, hostname],
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(_) => conn.execute_batch("ROLLBACK")?,
    }
    result
}

pub fn clear_pending_patches(conn: &Connection, hostname: &str) -> Result<(), DarnError> {
    conn.execute(
        "DELETE FROM pending_patches WHERE hostname = ?1",
        params![hostname],
    )?;
    Ok(())
}

pub fn get_pending_patches(conn: &Connection, hostname: &str) -> Result<Vec<Patch>, DarnError> {
    let mut stmt = conn.prepare(
        "SELECT package, version, is_security FROM pending_patches
          WHERE hostname = ?1 ORDER BY package",
    )?;
    let patches = stmt
        .query_map(params![hostname], |row| {
            Ok(Patch {
                package: row.get(0)?,
                version: row.get(1)?,
                is_security: row.get::<_, i64>(2)? != 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(patches)
}

/// Return (total, security, non_security) for a host.
#[allow(dead_code)] // part of the darn3 DB API; currently only tests use it
pub fn count_pending_patches(
    conn: &Connection,
    hostname: &str,
) -> Result<(i64, i64, i64), DarnError> {
    let counts = conn.query_row(
        "SELECT
            COUNT(*)                                                       AS total,
            COALESCE(SUM(is_security), 0)                                  AS security,
            COALESCE(SUM(CASE WHEN is_security = 0 THEN 1 ELSE 0 END), 0)  AS non_security
           FROM pending_patches
          WHERE hostname = ?1",
        params![hostname],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok(counts)
}

/// Replace the list of units awaiting a restart on a host.
///
/// The `deferred` mark survives for units that are still stale: it records the
/// host's own restart policy, which a fresh discovery run does not change.
pub fn replace_pending_services(
    conn: &Connection,
    hostname: &str,
    services: &[String],
) -> Result<(), DarnError> {
    let now = utcnow();
    let deferred = get_pending_services(conn, hostname, Some(true))?;
    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<(), DarnError> {
        conn.execute(
            "DELETE FROM pending_services WHERE hostname = ?1",
            params![hostname],
        )?;
        let mut stmt = conn.prepare(
            "INSERT INTO pending_services (hostname, service, deferred, discovered_at)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for service in services {
            let flag = deferred.contains(service) as i64;
            stmt.execute(params![hostname, service, flag, now])?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(_) => conn.execute_batch("ROLLBACK")?,
    }
    result
}

/// Record that the host's own policy declined to restart these units.
pub fn mark_services_deferred(
    conn: &Connection,
    hostname: &str,
    services: &[String],
) -> Result<(), DarnError> {
    let mut stmt = conn.prepare(
        "UPDATE pending_services SET deferred = 1 WHERE hostname = ?1 AND service = ?2",
    )?;
    for service in services {
        stmt.execute(params![hostname, service])?;
    }
    Ok(())
}

/// List units awaiting a restart: all of them, or only the (non-)deferred.
pub fn get_pending_services(
    conn: &Connection,
    hostname: &str,
    deferred: Option<bool>,
) -> Result<Vec<String>, DarnError> {
    match deferred {
        None => {
            let mut stmt = conn.prepare(
                "SELECT service FROM pending_services WHERE hostname = ?1 ORDER BY service",
            )?;
            let services = stmt
                .query_map(params![hostname], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(services)
        }
        Some(flag) => {
            let mut stmt = conn.prepare(
                "SELECT service FROM pending_services
                  WHERE hostname = ?1 AND deferred = ?2 ORDER BY service",
            )?;
            let services = stmt
                .query_map(params![hostname, flag as i64], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(services)
        }
    }
}

/// Return (actionable, deferred) counts for a host.
pub fn count_pending_services(
    conn: &Connection,
    hostname: &str,
) -> Result<(i64, i64), DarnError> {
    let counts = conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN deferred = 0 THEN 1 ELSE 0 END), 0) AS actionable,
            COALESCE(SUM(deferred), 0)                                 AS deferred
           FROM pending_services
          WHERE hostname = ?1",
        params![hostname],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(counts)
}

pub fn record_command(
    conn: &Connection,
    hostname: &str,
    session_id: &str,
    command: &str,
    stdout: Option<&str>,
    stderr: Option<&str>,
    exit_code: Option<i64>,
) -> Result<(), DarnError> {
    conn.execute(
        "INSERT INTO command_log
            (hostname, session_id, command, stdout, stderr, exit_code, run_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![hostname, session_id, command, stdout, stderr, exit_code, utcnow()],
    )?;
    Ok(())
}

pub fn get_last_session_commands(
    conn: &Connection,
    hostname: &str,
) -> Result<Vec<LoggedCommand>, DarnError> {
    let last: Option<String> = conn
        .query_row(
            "SELECT session_id FROM command_log
              WHERE hostname = ?1 ORDER BY id DESC LIMIT 1",
            params![hostname],
            |row| row.get(0),
        )
        .optional()?;
    let Some(session_id) = last else {
        return Ok(Vec::new());
    };
    let mut stmt = conn.prepare(
        "SELECT command, stdout, stderr, exit_code, run_at
           FROM command_log
          WHERE hostname = ?1 AND session_id = ?2
          ORDER BY id",
    )?;
    let commands = stmt
        .query_map(params![hostname, session_id], |row| {
            Ok(LoggedCommand {
                command: row.get(0)?,
                stdout: row.get(1)?,
                stderr: row.get(2)?,
                exit_code: row.get(3)?,
                run_at: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_tmp() -> (TempDir, Connection) {
        let dir = TempDir::new().unwrap();
        let conn = open_db(Some(&dir.path().join("test.db"))).unwrap();
        (dir, conn)
    }

    fn add(conn: &Connection, hostname: &str) {
        add_with(conn, hostname, "debian", "ubuntu", Some("Ubuntu 22.04"));
    }

    fn add_with(
        conn: &Connection,
        hostname: &str,
        host_type: &str,
        user: &str,
        distribution: Option<&str>,
    ) {
        add_server(conn, hostname, user, 22, None, host_type, distribution, None).unwrap();
    }

    fn svc(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn schema_creates_on_open() {
        let (_dir, conn) = open_tmp();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for expected in ["servers", "pending_patches", "command_log"] {
            assert!(names.iter().any(|n| n == expected), "missing {expected}");
        }
    }

    #[test]
    fn add_list_remove_roundtrip() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        add_with(&conn, "beta", "redhat", "ubuntu", Some("Ubuntu 22.04"));
        let servers = list_servers(&conn).unwrap();
        let names: Vec<&str> = servers.iter().map(|s| s.hostname.as_str()).collect();
        assert_eq!(names, ["alpha", "beta"]);
        assert_eq!(get_server(&conn, "alpha").unwrap().unwrap().host_type, "debian");
        assert!(remove_server(&conn, "alpha").unwrap());
        assert!(!remove_server(&conn, "alpha").unwrap());
        let names: Vec<String> = list_servers(&conn)
            .unwrap()
            .into_iter()
            .map(|s| s.hostname)
            .collect();
        assert_eq!(names, ["beta"]);
    }

    #[test]
    fn add_is_idempotent() {
        let (_dir, conn) = open_tmp();
        add_with(&conn, "alpha", "debian", "root", Some("Ubuntu 22.04"));
        add_with(&conn, "alpha", "debian", "ubuntu", Some("Ubuntu 22.04"));
        assert_eq!(get_server(&conn, "alpha").unwrap().unwrap().ssh_user, "ubuntu");
    }

    #[test]
    fn distribution_round_trips_and_updates() {
        let (_dir, conn) = open_tmp();
        add_with(&conn, "alpha", "debian", "ubuntu", Some("Ubuntu 22.04 LTS"));
        assert_eq!(
            get_server(&conn, "alpha").unwrap().unwrap().distribution.as_deref(),
            Some("Ubuntu 22.04 LTS")
        );
        set_distribution(&conn, "alpha", Some("Ubuntu 24.04 LTS")).unwrap();
        assert_eq!(
            get_server(&conn, "alpha").unwrap().unwrap().distribution.as_deref(),
            Some("Ubuntu 24.04 LTS")
        );
    }

    #[test]
    fn migration_adds_distribution_column() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("legacy.db");
        {
            let legacy = Connection::open(&path).unwrap();
            legacy
                .execute_batch(
                    "CREATE TABLE servers (
                        hostname TEXT PRIMARY KEY,
                        ssh_user TEXT NOT NULL,
                        ssh_port INTEGER NOT NULL DEFAULT 22,
                        ssh_key_path TEXT,
                        host_type TEXT NOT NULL,
                        last_update_at TIMESTAMP,
                        last_update_ok INTEGER
                    );
                    INSERT INTO servers (hostname, ssh_user, host_type)
                    VALUES ('oldbox', 'root', 'debian');",
                )
                .unwrap();
        }
        let conn = open_db(Some(&path)).unwrap();
        let server = get_server(&conn, "oldbox").unwrap().unwrap();
        assert_eq!(server.distribution, None);
    }

    #[test]
    fn pending_patches_and_counts() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        let patches = vec![
            Patch::new("openssl", "1.1.1f-1ubuntu2.20", true),
            Patch::new("vim", "2:8.2.3995-1ubuntu2.13", false),
            Patch::new("curl", "7.81.0-1ubuntu1.16", true),
        ];
        replace_pending_patches(&conn, "alpha", &patches, true).unwrap();

        let stored = get_pending_patches(&conn, "alpha").unwrap();
        let names: Vec<&str> = stored.iter().map(|p| p.package.as_str()).collect();
        assert_eq!(names, ["curl", "openssl", "vim"]);
        assert_eq!(count_pending_patches(&conn, "alpha").unwrap(), (3, 2, 1));

        // Replace wipes previous rows.
        replace_pending_patches(&conn, "alpha", &[Patch::new("foo", "1.0", false)], true).unwrap();
        let names: Vec<String> = get_pending_patches(&conn, "alpha")
            .unwrap()
            .into_iter()
            .map(|p| p.package)
            .collect();
        assert_eq!(names, ["foo"]);
    }

    #[test]
    fn remove_server_cascades() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        replace_pending_patches(&conn, "alpha", &[Patch::new("curl", "1", true)], true).unwrap();
        record_command(&conn, "alpha", "s1", "echo hi", Some("hi"), Some(""), Some(0)).unwrap();
        remove_server(&conn, "alpha").unwrap();
        assert!(get_pending_patches(&conn, "alpha").unwrap().is_empty());
        // command_log has no FK (intentionally kept for audit); removal must not error.
    }

    #[test]
    fn last_session_commands() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        for (cmd, sid) in [("a", "s1"), ("b", "s1"), ("c", "s2"), ("d", "s2")] {
            record_command(&conn, "alpha", sid, cmd, Some(""), Some(""), Some(0)).unwrap();
        }
        let last = get_last_session_commands(&conn, "alpha").unwrap();
        let cmds: Vec<&str> = last.iter().map(|c| c.command.as_str()).collect();
        assert_eq!(cmds, ["c", "d"]);
    }

    #[test]
    fn default_db_path_respects_xdg() {
        // Env mutation: keep this the only test touching XDG_DATA_HOME.
        let dir = TempDir::new().unwrap();
        let xdg = dir.path().join("xdg");
        std::env::set_var("XDG_DATA_HOME", &xdg);
        let path = default_db_path();
        std::env::remove_var("XDG_DATA_HOME");
        assert_eq!(path, xdg.join("darn").join("darn.db"));
    }

    #[test]
    fn reboot_state_round_trips() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        assert_eq!(get_server(&conn, "alpha").unwrap().unwrap().reboot_required, None);
        set_reboot_state(&conn, "alpha", Some("yes"), Some("linux-image-generic")).unwrap();
        let server = get_server(&conn, "alpha").unwrap().unwrap();
        assert_eq!(server.reboot_required.as_deref(), Some("yes"));
        assert_eq!(server.reboot_detail.as_deref(), Some("linux-image-generic"));
        set_reboot_state(&conn, "alpha", None, None).unwrap();
        assert_eq!(get_server(&conn, "alpha").unwrap().unwrap().reboot_required, None);
    }

    #[test]
    fn migrate_adds_reboot_columns_to_old_db() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.db");
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE servers (
                    hostname        TEXT PRIMARY KEY,
                    ssh_user        TEXT NOT NULL,
                    ssh_port        INTEGER NOT NULL DEFAULT 22,
                    ssh_key_path    TEXT,
                    host_type       TEXT NOT NULL,
                    last_update_at  TIMESTAMP,
                    last_update_ok  INTEGER
                );
                INSERT INTO servers (hostname, ssh_user, host_type)
                VALUES ('old-01', 'ubuntu', 'debian');",
            )
            .unwrap();
        }
        let conn = open_db(Some(&path)).unwrap();
        let server = get_server(&conn, "old-01").unwrap().unwrap();
        assert_eq!(server.distribution, None);
        assert_eq!(server.reboot_required, None);
        set_reboot_state(&conn, "old-01", Some("unknown"), None).unwrap();
        assert_eq!(
            get_server(&conn, "old-01").unwrap().unwrap().reboot_required.as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn pending_services_round_trip_and_replace() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        assert!(get_pending_services(&conn, "alpha", None).unwrap().is_empty());
        replace_pending_services(&conn, "alpha", &svc(&["dbus.service", "cron.service"])).unwrap();
        assert_eq!(
            get_pending_services(&conn, "alpha", None).unwrap(),
            svc(&["cron.service", "dbus.service"])
        );
        assert_eq!(count_pending_services(&conn, "alpha").unwrap(), (2, 0));
        replace_pending_services(&conn, "alpha", &svc(&["cron.service"])).unwrap();
        assert_eq!(
            get_pending_services(&conn, "alpha", None).unwrap(),
            svc(&["cron.service"])
        );
        replace_pending_services(&conn, "alpha", &[]).unwrap();
        assert_eq!(count_pending_services(&conn, "alpha").unwrap(), (0, 0));
    }

    #[test]
    fn removing_a_server_cascades_to_pending_services() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        replace_pending_services(&conn, "alpha", &svc(&["cron.service"])).unwrap();
        remove_server(&conn, "alpha").unwrap();
        assert!(get_pending_services(&conn, "alpha", None).unwrap().is_empty());
    }

    #[test]
    fn deferred_mark_survives_rediscovery() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        replace_pending_services(&conn, "alpha", &svc(&["dbus.service", "cron.service"])).unwrap();
        mark_services_deferred(&conn, "alpha", &svc(&["dbus.service"])).unwrap();
        assert_eq!(count_pending_services(&conn, "alpha").unwrap(), (1, 1));
        assert_eq!(
            get_pending_services(&conn, "alpha", Some(false)).unwrap(),
            svc(&["cron.service"])
        );
        assert_eq!(
            get_pending_services(&conn, "alpha", Some(true)).unwrap(),
            svc(&["dbus.service"])
        );

        // A later discovery must not resurrect it as outstanding work: the host's
        // restart policy has not changed just because we probed again.
        replace_pending_services(&conn, "alpha", &svc(&["dbus.service", "sshd.service"])).unwrap();
        assert_eq!(count_pending_services(&conn, "alpha").unwrap(), (1, 1));
        assert_eq!(
            get_pending_services(&conn, "alpha", Some(true)).unwrap(),
            svc(&["dbus.service"])
        );

        // But once it stops being stale, the mark goes with it.
        replace_pending_services(&conn, "alpha", &svc(&["sshd.service"])).unwrap();
        assert_eq!(count_pending_services(&conn, "alpha").unwrap(), (1, 0));
    }

    #[test]
    fn migrate_adds_deferred_column_to_old_pending_services() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.db");
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE servers (
                    hostname TEXT PRIMARY KEY, ssh_user TEXT NOT NULL,
                    ssh_port INTEGER NOT NULL DEFAULT 22, ssh_key_path TEXT,
                    host_type TEXT NOT NULL, last_update_at TIMESTAMP, last_update_ok INTEGER
                );
                CREATE TABLE pending_services (
                    hostname TEXT NOT NULL, service TEXT NOT NULL,
                    discovered_at TIMESTAMP NOT NULL, PRIMARY KEY (hostname, service)
                );
                INSERT INTO servers (hostname, ssh_user, host_type)
                VALUES ('old-01','ubuntu','debian');
                INSERT INTO pending_services
                VALUES ('old-01','dbus.service','2026-08-19T00:00:00+00:00');",
            )
            .unwrap();
        }
        let conn = open_db(Some(&path)).unwrap();
        assert_eq!(count_pending_services(&conn, "old-01").unwrap(), (1, 0));
        mark_services_deferred(&conn, "old-01", &svc(&["dbus.service"])).unwrap();
        assert_eq!(count_pending_services(&conn, "old-01").unwrap(), (0, 1));
    }

    #[test]
    fn no_all_defaults_off_and_round_trips() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        assert!(!get_server(&conn, "alpha").unwrap().unwrap().no_all);
        assert!(set_no_all(&conn, "alpha", true).unwrap());
        assert!(get_server(&conn, "alpha").unwrap().unwrap().no_all);
        assert!(set_no_all(&conn, "alpha", false).unwrap());
        assert!(!get_server(&conn, "alpha").unwrap().unwrap().no_all);
        assert!(!set_no_all(&conn, "nosuch", true).unwrap());
    }

    #[test]
    fn add_server_preserves_no_all_unless_told_otherwise() {
        let (_dir, conn) = open_tmp();
        add(&conn, "alpha");
        set_no_all(&conn, "alpha", true).unwrap();

        // A plain re-add refreshes the connection details without disturbing the mark.
        add_with(&conn, "alpha", "debian", "root", Some("Ubuntu 22.04"));
        let server = get_server(&conn, "alpha").unwrap().unwrap();
        assert_eq!(server.ssh_user, "root");
        assert!(server.no_all);

        add_server(&conn, "alpha", "root", 22, None, "debian", None, Some(false)).unwrap();
        assert!(!get_server(&conn, "alpha").unwrap().unwrap().no_all);
    }

    #[test]
    fn add_server_can_set_no_all_on_a_new_host() {
        let (_dir, conn) = open_tmp();
        add_server(&conn, "router", "admin", 22, None, "mikrotik", None, Some(true)).unwrap();
        assert!(get_server(&conn, "router").unwrap().unwrap().no_all);
    }

    #[test]
    fn migrate_adds_no_all_column_to_old_servers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.db");
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE servers (
                    hostname TEXT PRIMARY KEY, ssh_user TEXT NOT NULL,
                    ssh_port INTEGER NOT NULL DEFAULT 22, ssh_key_path TEXT,
                    host_type TEXT NOT NULL, last_update_at TIMESTAMP, last_update_ok INTEGER
                );
                INSERT INTO servers (hostname, ssh_user, host_type)
                VALUES ('old-01','ubuntu','debian');",
            )
            .unwrap();
        }
        let conn = open_db(Some(&path)).unwrap();
        // Existing hosts stay in 'all' — the upgrade must not hide anything.
        assert!(!get_server(&conn, "old-01").unwrap().unwrap().no_all);
        set_no_all(&conn, "old-01", true).unwrap();
        assert!(get_server(&conn, "old-01").unwrap().unwrap().no_all);
    }
}
