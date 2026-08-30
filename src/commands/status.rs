use std::path::Path;

use crate::db;
use crate::errors::DarnError;
use crate::hosts::Reboot;
use crate::render::{idle_fragment, patch_list, render_status};

pub fn run(db_path: Option<&Path>, plain: bool, show_all: bool) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let servers = db::list_servers(&conn)?;
    if !plain {
        render_status(&conn, &servers, show_all);
        return Ok(0);
    }
    for s in &servers {
        let patches = db::get_pending_patches(&conn, &s.hostname)?;
        let needs_reboot =
            s.reboot_required.as_deref().and_then(Reboot::parse) == Some(Reboot::Yes);
        let services = db::get_pending_services(&conn, &s.hostname, Some(false))?;
        let deferred = db::get_pending_services(&conn, &s.hostname, Some(true))?;
        if patches.is_empty() && !needs_reboot && services.is_empty() && deferred.is_empty() {
            if show_all {
                println!("{}: {}", s.hostname, idle_fragment(s).1);
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
            println!("   {}", patch_list(&patches));
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
