use std::path::Path;

use crate::db::{self, Server};
use crate::errors::DarnError;
use crate::render::render_status;

/// Describe a host with nothing outstanding, for `status --plain --all`.
fn idle_state(server: &Server) -> &'static str {
    if server.last_update_at.is_none() {
        return "not yet checked";
    }
    if server.last_update_ok == Some(0) {
        return "discovery failed";
    }
    "up to date"
}

pub fn run(db_path: Option<&Path>, plain: bool, show_all: bool) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let servers = db::list_servers(&conn)?;
    if !plain {
        render_status(&conn, &servers, show_all);
        return Ok(0);
    }
    for s in &servers {
        let patches = db::get_pending_patches(&conn, &s.hostname)?;
        let needs_reboot = s.reboot_required.as_deref() == Some("yes");
        let services = db::get_pending_services(&conn, &s.hostname, Some(false))?;
        let deferred = db::get_pending_services(&conn, &s.hostname, Some(true))?;
        if patches.is_empty() && !needs_reboot && services.is_empty() && deferred.is_empty() {
            if show_all {
                println!("{}: {}", s.hostname, idle_state(s));
            }
            continue;
        }
        if !patches.is_empty() {
            let security_count = patches.iter().filter(|p| p.is_security).count();
            let other_count = patches.len() - security_count;
            println!(
                "{}: {security_count} security (*), {other_count} other",
                s.hostname
            );
            let pkgs = patches
                .iter()
                .map(|p| {
                    if p.is_security {
                        format!("{}*", p.package)
                    } else {
                        p.package.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            println!("   {pkgs}");
        }
        if needs_reboot {
            let detail = match s.reboot_detail.as_deref() {
                Some(d) if !d.is_empty() => format!(" ({d})"),
                _ => String::new(),
            };
            println!("{}: reboot required{detail}", s.hostname);
        }
        if !services.is_empty() {
            println!("{}: {} services need restart", s.hostname, services.len());
            println!("   {}", services.join(" "));
        }
        if !deferred.is_empty() {
            println!(
                "{}: {} services deferred by host policy",
                s.hostname,
                deferred.len()
            );
            println!("   {}", deferred.join(" "));
        }
    }
    Ok(0)
}
