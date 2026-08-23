use chrono::{DateTime, Local};
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table, TableComponent};
use console::style;
use rusqlite::Connection;

use crate::db::{self, LoggedCommand, Server};
use crate::orchestrator::HostResult;
use crate::target::current_user;

pub fn red(s: &str) -> String {
    style(s).red().to_string()
}

pub fn yellow(s: &str) -> String {
    style(s).yellow().to_string()
}

pub fn green(s: &str) -> String {
    style(s).green().to_string()
}

pub fn dim(s: &str) -> String {
    style(s).dim().to_string()
}

pub fn bold(s: &str) -> String {
    style(s).bold().to_string()
}

pub fn cyan(s: &str) -> String {
    style(s).cyan().to_string()
}

fn paint(colour: &str, s: &str) -> String {
    match colour {
        "red" => red(s),
        "yellow" => yellow(s),
        "green" => green(s),
        "dim" => dim(s),
        _ => s.to_string(),
    }
}

/// Convert a stored ISO-8601 UTC timestamp to a locally-formatted local time.
pub fn format_local_datetime(iso_utc: Option<&str>) -> String {
    let Some(iso_utc) = iso_utc.filter(|s| !s.is_empty()) else {
        return "—".to_string();
    };
    match DateTime::parse_from_rfc3339(iso_utc) {
        Ok(dt) => dt
            .with_timezone(&Local)
            .format("%b %d %H:%M:%S")
            .to_string(),
        Err(_) => iso_utc.to_string(),
    }
}

pub fn format_host(server: &Server, current_user: &str) -> String {
    let prefix = if server.ssh_user != current_user {
        format!("{}@", server.ssh_user)
    } else {
        String::new()
    };
    let suffix = if server.ssh_port != 22 {
        format!(":{}", server.ssh_port)
    } else {
        String::new()
    };
    format!("{prefix}{}{suffix}", server.hostname)
}

/// The pending reboot and service restarts, as (colour, text) fragments.
fn restart_parts(
    conn: &Connection,
    hostname: &str,
    reboot: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut parts = Vec::new();
    if reboot == Some("yes") {
        parts.push(("red", "reboot required".to_string()));
    } else if reboot == Some("unknown") {
        parts.push(("yellow", "reboot unknown".to_string()));
    }
    let (actionable, deferred) = db::count_pending_services(conn, hostname).unwrap_or((0, 0));
    if actionable > 0 {
        parts.push(("yellow", format!("{actionable} services")));
    }
    if deferred > 0 {
        // Declined by the host's own restart policy: shown, but not outstanding.
        parts.push(("dim", format!("{deferred} deferred")));
    }
    parts
}

/// Annotate a status cell with pending reboot and service restarts.
pub fn restart_suffix(conn: &Connection, hostname: &str, reboot: Option<&str>) -> String {
    restart_parts(conn, hostname, reboot)
        .iter()
        .map(|(colour, text)| format!(" {}", paint(colour, &format!("· {text}"))))
        .collect()
}

fn new_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);
    // No separator lines between rows, like rich's default table.
    table.remove_style(TableComponent::HorizontalLines);
    table.remove_style(TableComponent::MiddleIntersections);
    table.remove_style(TableComponent::LeftBorderIntersections);
    table.remove_style(TableComponent::RightBorderIntersections);
    table
}

/// List the fleet and how each host is configured.
///
/// Deliberately says nothing about pending work — that is `darn status`.
pub fn render_server_list(servers: &[Server]) {
    let mut table = new_table();
    table.set_header(["Host", "Distribution", "Flags"]);
    let user = current_user();
    for s in servers {
        let flags = if s.no_all { "no-all" } else { "—" };
        table.add_row([
            bold(&format_host(s, &user)),
            s.distribution.clone().unwrap_or_else(|| "—".to_string()),
            flags.to_string(),
        ]);
    }
    println!("{table}");
}

/// How a host with no outstanding work reports itself under --all.
fn idle_fragment(server: &Server) -> (&'static str, String) {
    if server.last_update_at.is_none() {
        return ("dim", "not yet checked".to_string());
    }
    if server.last_update_ok == Some(0) {
        return ("red", "discovery failed".to_string());
    }
    ("green", "up to date".to_string())
}

/// Show outstanding work per host, in the same shape as `update` results.
///
/// Hosts with nothing outstanding are left out, as in the plain output, so a
/// fully patched fleet renders as a single all-clear line; `show_all` keeps
/// them in, each reporting that it has nothing to do.
pub fn render_status(conn: &Connection, servers: &[Server], show_all: bool) {
    let mut table = new_table();
    table.set_header(["Hostname", "Status", "Checked", "Message"]);

    let user = current_user();
    let mut shown = 0;
    for s in servers {
        let patches = db::get_pending_patches(conn, &s.hostname).unwrap_or_default();
        let needs_reboot = s.reboot_required.as_deref() == Some("yes");
        let services = db::get_pending_services(conn, &s.hostname, Some(false)).unwrap_or_default();
        if patches.is_empty() && !needs_reboot && services.is_empty() && !show_all {
            continue;
        }
        shown += 1;

        let mut fragments: Vec<(&'static str, String)> = Vec::new();
        if !patches.is_empty() {
            let security = patches.iter().filter(|p| p.is_security).count();
            let colour = if security > 0 { "red" } else { "yellow" };
            fragments.push((
                colour,
                format!("{} pending ({security} security)", patches.len()),
            ));
        }
        fragments.extend(restart_parts(
            conn,
            &s.hostname,
            s.reboot_required.as_deref(),
        ));
        if fragments.is_empty() {
            // Only reachable under show_all: say why there is nothing to report.
            fragments.push(idle_fragment(s));
        }
        // Every fragment after the first is bulleted, as in the `update` table.
        let mut lines = vec![fragments
            .iter()
            .enumerate()
            .map(|(i, (colour, text))| {
                let bullet = if i == 0 { "" } else { "· " };
                paint(colour, &format!("{bullet}{text}"))
            })
            .collect::<Vec<_>>()
            .join(" ")];
        if !patches.is_empty() {
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
            lines.push(dim(&pkgs));
        }
        if needs_reboot {
            if let Some(detail) = &s.reboot_detail {
                lines.push(dim(detail));
            }
        }
        if !services.is_empty() {
            lines.push(dim(&services.join(" ")));
        }

        let state = if s.last_update_at.is_some() && s.last_update_ok == Some(0) {
            red("failed")
        } else if s.last_update_at.is_some() {
            green("ok")
        } else {
            yellow("unknown")
        };
        // When discovery last ran, successfully or not: old data reads the same
        // as good news otherwise.
        table.add_row([
            bold(&format_host(s, &user)),
            state,
            format_local_datetime(s.last_update_at.as_deref()),
            lines.join("\n"),
        ]);
    }

    if servers.is_empty() {
        println!("{}", yellow("No servers configured."));
        return;
    }
    if shown == 0 {
        println!("{}", green("Nothing pending."));
        return;
    }
    println!("{}", center_title("status", &table));
    println!("{table}");
}

pub fn render_results(title: &str, results: &[HostResult]) {
    let mut table = new_table();
    table.set_header(["Hostname", "Status", "Message"]);
    for r in results {
        let status = if r.ok { green("ok") } else { red("failed") };
        table.add_row([bold(&r.hostname), status, r.message.clone()]);
    }
    println!("{}", center_title(title, &table));
    println!("{table}");
}

/// Centre a table title over the rendered table, as rich does.
fn center_title(title: &str, table: &Table) -> String {
    let width = table
        .to_string()
        .lines()
        .map(console::measure_text_width)
        .max()
        .unwrap_or(0);
    if title.len() >= width {
        return title.to_string();
    }
    let pad = (width - title.len()) / 2;
    format!("{}{title}", " ".repeat(pad))
}

pub fn render_log(hostname: &str, commands: &[LoggedCommand]) {
    if commands.is_empty() {
        println!("{}", yellow(&format!("No logged commands for {hostname}.")));
        return;
    }
    let width = terminal_width();
    rule(&format!("Last session for {hostname}"), width);
    for cmd in commands {
        let header = format!(
            "{}  exit={}  at {}",
            bold(&cmd.command),
            cmd.exit_code.map_or("None".to_string(), |c| c.to_string()),
            format_local_datetime(Some(&cmd.run_at)),
        );
        let mut body_parts: Vec<String> = Vec::new();
        if let Some(stdout) = cmd.stdout.as_deref().filter(|s| !s.is_empty()) {
            body_parts.push(format!("{}:\n{}", green("stdout"), stdout.trim_end()));
        }
        if let Some(stderr) = cmd.stderr.as_deref().filter(|s| !s.is_empty()) {
            body_parts.push(format!("{}:\n{}", red("stderr"), stderr.trim_end()));
        }
        let body = if body_parts.is_empty() {
            "(no output)".to_string()
        } else {
            body_parts.join("\n\n")
        };
        panel(&header, &body, width);
    }
}

fn terminal_width() -> usize {
    let (_rows, cols) = console::Term::stdout().size();
    if cols == 0 {
        80
    } else {
        cols as usize
    }
}

/// A horizontal rule with a centred title, like rich's Console.rule.
fn rule(title: &str, width: usize) {
    let text_width = console::measure_text_width(title) + 2;
    if text_width >= width {
        println!("{title}");
        return;
    }
    let left = (width - text_width) / 2;
    let right = width - text_width - left;
    println!(
        "{} {} {}",
        cyan(&"─".repeat(left)),
        bold(title),
        cyan(&"─".repeat(right)),
    );
}

/// A rounded box with the header in the top border, like rich's Panel.
fn panel(header: &str, body: &str, width: usize) {
    let inner = width.saturating_sub(4).max(20);
    let top_header: String = if console::measure_text_width(header) > inner.saturating_sub(2) {
        console::truncate_str(header, inner.saturating_sub(3), "…").into_owned()
    } else {
        header.to_string()
    };
    let header_width = console::measure_text_width(&top_header);
    let dashes = inner.saturating_sub(header_width + 1);
    println!(
        "{} {} {}{}",
        cyan("╭─"),
        top_header,
        cyan(&"─".repeat(dashes)),
        cyan("╮"),
    );
    for raw in body.lines() {
        let mut line = raw.to_string();
        loop {
            let visible = console::measure_text_width(&line);
            if visible <= inner {
                let pad = inner - visible;
                println!("{} {}{} {}", cyan("│"), line, " ".repeat(pad), cyan("│"));
                break;
            }
            let head = console::truncate_str(&line, inner, "").into_owned();
            let taken = head.len();
            println!("{} {} {}", cyan("│"), head, cyan("│"));
            line = line[taken..].to_string();
        }
    }
    println!("{}{}{}", cyan("╰"), cyan(&"─".repeat(inner + 2)), cyan("╯"));
}
