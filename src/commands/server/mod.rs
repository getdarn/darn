//! The `darn server` family. Everything interactive about adding a host
//! lives in the submodules: `add` drives the flow, `trust` settles the host
//! key, `access` settles login and sudo, `transfer` moves the list to and
//! from YAML. What remains here is the plain database CRUD.

mod access;
mod add;
mod transfer;
mod trust;

pub use add::add;
pub use transfer::{export, import};

use std::path::Path;

use crate::commands::confirm;
use crate::db;
use crate::errors::DarnError;
use crate::render::{bold, green, render_server_list, yellow};

/// How many times to re-ask for a mistyped password, as sshd itself allows.
const PASSWORD_ATTEMPTS: usize = 3;

/// How many times to re-ask an unanswered yes/no, before treating the
/// silence as a no.
const ANSWER_ATTEMPTS: usize = 3;

pub fn remove(db_path: Option<&Path>, hostname: &str) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    if db::remove_server(&conn, hostname)? {
        println!("{} {hostname}", green("Removed"));
        Ok(0)
    } else {
        Err(DarnError::Other(format!("no such server: {hostname}")))
    }
}

pub fn set(db_path: Option<&Path>, hostname: &str, no_all: Option<bool>) -> Result<i32, DarnError> {
    let Some(no_all) = no_all else {
        return Err(DarnError::Usage(
            "nothing to set: pass --no-all or --all".to_string(),
        ));
    };
    let conn = db::open_db(db_path)?;
    if !db::set_no_all(&conn, hostname, no_all)? {
        return Err(DarnError::Other(format!("no such server: {hostname}")));
    }
    if no_all {
        println!("{} is now excluded from 'all' targets", green(hostname));
    } else {
        println!("{} is now included in 'all' targets", green(hostname));
    }
    Ok(0)
}

/// Clear the configured servers list.
///
/// The command log survives: it is an audit trail of what darn ran, and it
/// stays readable with `darn log` for a host that has been removed.
pub fn reset(db_path: Option<&Path>, yes: bool) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let servers = db::list_servers(&conn)?;
    if servers.is_empty() {
        println!("{}", yellow("No servers configured; nothing to reset."));
        return Ok(0);
    }

    if !yes {
        println!("About to remove, along with their recorded patch and reboot state:");
        for s in &servers {
            println!("  {}", bold(&s.hostname));
        }
        // confirm() reads false at EOF, so a script that forgot --yes aborts
        // here rather than hanging or clearing the list unasked.
        if !confirm(&format!("Remove {} server(s)?", servers.len())) {
            println!("{}", yellow("Aborted."));
            return Ok(0);
        }
    }

    let removed = db::clear_servers(&conn)?;
    println!("{} {removed} server(s)", green("Removed"));
    Ok(0)
}

pub fn list(db_path: Option<&Path>) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let servers = db::list_servers(&conn)?;
    if servers.is_empty() {
        println!(
            "{}",
            yellow("No servers configured. Use `darn server add`.")
        );
        return Ok(0);
    }
    render_server_list(&servers);
    Ok(0)
}
