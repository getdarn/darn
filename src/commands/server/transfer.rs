//! Moving the server list to and from YAML, without contacting any host.

use std::path::Path;

use crate::commands::confirm;
use crate::db;
use crate::errors::DarnError;
use crate::render::{bold, dim, green, yellow};
use crate::serverfile;

/// Write the managed servers to a YAML file, or to stdout for `-`.
pub fn export(db_path: Option<&Path>, file: &Path) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let servers = db::list_servers(&conn)?;
    let yaml = serverfile::to_yaml(&servers)?;

    if is_stdio(file) {
        print!("{yaml}");
        return Ok(0);
    }

    std::fs::write(file, &yaml)
        .map_err(|e| DarnError::Other(format!("cannot write {}: {e}", file.display())))?;
    if servers.is_empty() {
        println!(
            "{}",
            yellow(&format!(
                "No servers configured; wrote an empty list to {}.",
                file.display()
            ))
        );
    } else {
        println!(
            "{} {} server(s) to {}",
            green("Exported"),
            servers.len(),
            file.display()
        );
    }
    Ok(0)
}

/// Read servers back from a YAML file, without contacting any of them.
///
/// The file is parsed and validated in full before the database is opened, and
/// every write happens in one transaction, so a bad file changes nothing.
pub fn import(
    db_path: Option<&Path>,
    file: &Path,
    replace: bool,
    yes: bool,
) -> Result<i32, DarnError> {
    let text = if is_stdio(file) {
        std::io::read_to_string(std::io::stdin())
            .map_err(|e| DarnError::Other(format!("cannot read standard input: {e}")))?
    } else {
        std::fs::read_to_string(file)
            .map_err(|e| DarnError::Other(format!("cannot read {}: {e}", file.display())))?
    };
    let entries = serverfile::from_yaml(&text)?;

    let mut conn = db::open_db(db_path)?;

    // Ask before the transaction opens, so the prompt is not holding a write
    // lock on the database while it waits for an answer.
    let obsolete: Vec<String> = if replace {
        db::list_servers(&conn)?
            .into_iter()
            .map(|s| s.hostname)
            .filter(|h| !entries.iter().any(|e| &e.hostname == h))
            .collect()
    } else {
        Vec::new()
    };
    if !obsolete.is_empty() && !yes {
        println!("About to remove, along with their recorded patch and reboot state:");
        for hostname in &obsolete {
            println!("  {}", bold(hostname));
        }
        if !confirm(&format!("Remove {} server(s)?", obsolete.len())) {
            println!("{}", yellow("Aborted."));
            return Ok(0);
        }
    }

    let tx = conn.transaction()?;
    let mut added = 0;
    let mut updated = 0;
    for entry in &entries {
        if db::get_server(&tx, &entry.hostname)?.is_some() {
            updated += 1;
        } else {
            added += 1;
        }
        // no_all is passed as Some: for a host it names, the file is what the
        // setting now is, not a suggestion to be merged with the stored one.
        db::add_server(
            &tx,
            &entry.hostname,
            &entry.ssh_user,
            entry.ssh_port,
            entry.ssh_key_path.as_deref(),
            &entry.host_type,
            entry.distribution.as_deref(),
            Some(entry.no_all),
        )?;
    }
    for hostname in &obsolete {
        db::remove_server(&tx, hostname)?;
    }
    tx.commit()?;

    if entries.is_empty() && obsolete.is_empty() {
        println!(
            "{}",
            yellow("Nothing to import: the file lists no servers.")
        );
        return Ok(0);
    }
    println!(
        "{} {} server(s) ({added} added, {updated} updated{})",
        green("Imported"),
        entries.len(),
        if obsolete.is_empty() {
            String::new()
        } else {
            format!(", {} removed", obsolete.len())
        }
    );
    if added > 0 {
        println!(
            "{}",
            dim("Run `darn update` to discover their patches and reboot state.")
        );
    }
    Ok(0)
}

/// `-` means stdout or stdin, as it does for most tools that take a filename.
fn is_stdio(file: &Path) -> bool {
    file.as_os_str() == "-"
}
