use chrono::{DateTime, Local};
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table, TableComponent};
use console::style;
use rusqlite::Connection;

use crate::db::{self, LoggedCommand, Patch, Server};
use crate::hosts::Reboot;
use crate::orchestrator::HostResult;
use crate::ssh::{OutEvent, OutputSink};
use crate::target::current_user;

/// A sink that puts a remote command's output on the local terminal as it
/// arrives, so watching a remote run looks like watching a local one.
///
/// Chunks are written as raw bytes rather than through a `String`: a read can
/// land mid-way through a UTF-8 sequence, and passing the bytes straight out
/// is both correct and exactly what running the command locally would do.
///
/// The `$ command` header goes to stderr, for the same reason a shell prompt
/// is not part of a piped command's stdout: redirecting stdout then gets the
/// remote output unpunctuated by darn's own framing.
pub fn stream_to_terminal() -> OutputSink<'static> {
    Box::new(|event| {
        write_event(
            event,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        );
    })
}

/// The command as a single prompt line.
///
/// Some of what an upgrade runs is a multi-line probe script; spilling all of
/// it between two commands' output would bury the output it introduces. The
/// first line plus an ellipsis reads as a prompt, and `darn log` still holds
/// the command in full.
fn command_header(command: &str) -> String {
    match command.split_once('\n') {
        Some((first, _)) => format!("$ {}…", first.trim_end()),
        None => format!("$ {command}"),
    }
}

/// Put one output event on `out`/`err`, flushing so it lands immediately.
///
/// Write errors are dropped: a closed pipe must not turn a successful upgrade
/// into a failed one.
fn write_event(event: OutEvent<'_>, out: &mut impl std::io::Write, err: &mut impl std::io::Write) {
    let (sink, bytes): (&mut dyn std::io::Write, &[u8]) = match event {
        OutEvent::Command(command) => {
            let _ = writeln!(err, "{}", dim(&command_header(command)));
            let _ = err.flush();
            return;
        }
        OutEvent::Stdout(bytes) => (out, bytes),
        OutEvent::Stderr(bytes) => (err, bytes),
    };
    let _ = sink.write_all(bytes);
    let _ = sink.flush();
}

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
///
/// `(actionable, deferred)` are the pending-service counts, fetched by the
/// caller — a formatter is not the place to run queries.
fn restart_parts(
    reboot: Option<&str>,
    actionable: i64,
    deferred: i64,
) -> Vec<(&'static str, String)> {
    let mut parts = Vec::new();
    match reboot.and_then(Reboot::parse) {
        Some(Reboot::Yes) => parts.push(("red", "reboot required".to_string())),
        Some(Reboot::Unknown) => parts.push(("yellow", "reboot unknown".to_string())),
        _ => {}
    }
    if actionable > 0 {
        parts.push(("yellow", format!("{actionable} services")));
    }
    if deferred > 0 {
        // Declined by the host's own restart policy: still stale, so still
        // worth showing, but not work `restartservices` will pick up unbidden.
        parts.push(("dim", format!("{deferred} deferred")));
    }
    parts
}

/// Annotate a status cell with pending reboot and service restarts.
pub fn restart_suffix(reboot: Option<&str>, actionable: i64, deferred: i64) -> String {
    restart_parts(reboot, actionable, deferred)
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

/// How a host with no outstanding work reports itself under --all, as a
/// (colour, text) fragment. `status --plain` prints the text alone.
pub fn idle_fragment(server: &Server) -> (&'static str, String) {
    if server.last_update_at.is_none() {
        return ("dim", "not yet checked".to_string());
    }
    if server.last_update_ok == Some(0) {
        return ("red", "discovery failed".to_string());
    }
    ("green", "up to date".to_string())
}

/// Every pending package on one line, the security ones starred.
pub fn patch_list(patches: &[Patch]) -> String {
    patches
        .iter()
        .map(|p| {
            if p.is_security {
                format!("{}*", p.package)
            } else {
                p.package.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
        let needs_reboot =
            s.reboot_required.as_deref().and_then(Reboot::parse) == Some(Reboot::Yes);
        let services = db::get_pending_services(conn, &s.hostname, Some(false)).unwrap_or_default();
        let deferred = db::get_pending_services(conn, &s.hostname, Some(true)).unwrap_or_default();
        if patches.is_empty()
            && !needs_reboot
            && services.is_empty()
            && deferred.is_empty()
            && !show_all
        {
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
        let (actionable, deferred_count) =
            db::count_pending_services(conn, &s.hostname).unwrap_or((0, 0));
        fragments.extend(restart_parts(
            s.reboot_required.as_deref(),
            actionable,
            deferred_count,
        ));
        if fragments.is_empty() {
            // Only reachable under show_all: say why there is nothing to report.
            fragments.push(idle_fragment(s));
        }
        // Every fragment after the first is bulleted, as in the `update` table.
        let mut summary = fragments
            .iter()
            .enumerate()
            .map(|(i, (colour, text))| {
                let bullet = if i == 0 { "" } else { "· " };
                paint(colour, &format!("{bullet}{text}"))
            })
            .collect::<Vec<_>>()
            .join(" ");
        // Unbulleted and greyed: not outstanding work, just a note that 'all'
        // will pass this host by.
        if s.no_all {
            summary.push(' ');
            summary.push_str(&dim("no-all"));
        }
        let mut lines = vec![summary];
        if !patches.is_empty() {
            lines.push(dim(&patch_list(&patches)));
        }
        if needs_reboot {
            if let Some(detail) = &s.reboot_detail {
                lines.push(dim(detail));
            }
        }
        if !services.is_empty() {
            lines.push(dim(&services.join(" ")));
        }
        if !deferred.is_empty() {
            // Labelled, so two runs of unit names cannot be read as one list.
            lines.push(dim(&format!("deferred: {}", deferred.join(" "))));
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

/// Show what a dry run would have issued, per host.
///
/// Not a table: a sudo-wrapped `sh -c '...'` is long enough that a cell would
/// wrap it into something you could not copy, paste or read, and the point of
/// the output is that you can check it line by line against what you expected.
/// `message` carries one command per line, as the work closure assembled it.
pub fn render_plan(title: &str, results: &[HostResult]) {
    println!("{}", bold(title));
    for r in results {
        println!();
        if !r.ok {
            println!("{} {}", bold(&r.hostname), red("— no plan"));
            for line in r.message.lines() {
                println!("  {}", red(line));
            }
            continue;
        }
        println!("{}", bold(&r.hostname));
        if r.message.trim().is_empty() {
            println!("  {}", dim("nothing to do"));
            continue;
        }
        for line in r.message.lines() {
            println!("  {} {line}", dim("$"));
        }
    }
    println!();
    println!(
        "{}",
        yellow("Dry run: nothing above was issued. Read-only probes were run.")
    );
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

pub fn render_log(server: &Server, commands: &[LoggedCommand]) {
    if commands.is_empty() {
        println!(
            "{}",
            yellow(&format!("No logged commands for {}.", server.hostname))
        );
        return;
    }
    print!("{}", log_transcript(server, commands));
}

/// The recorded session as a shell transcript: a prompt line per command,
/// followed by that command's output as the command itself printed it.
///
/// No framing around the output. A box would have to wrap long lines to keep
/// its right-hand border straight, and the whole point of this view is to show
/// what the remote command actually said — including where it chose to break
/// its own lines — in a form that survives being piped or copied.
///
/// stdout is printed before stderr because that is all the ordering the log
/// preserves: the two streams go to separate columns, so their true
/// interleaving is gone by the time it is read back.
fn log_transcript(server: &Server, commands: &[LoggedCommand]) -> String {
    let mut out = String::new();
    for (i, cmd) in commands.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        // A non-zero exit is worth saying out loud; a zero one is what the
        // absence of an error already means.
        let exit = match cmd.exit_code {
            Some(code) if code != 0 => format!(", exit {code}"),
            _ => String::new(),
        };
        let header = format!(
            "{}@{} # {} (at {}{exit})",
            server.ssh_user,
            server.hostname,
            cmd.command.trim_end(),
            format_local_datetime(Some(&cmd.run_at)),
        );
        // Bold per line, for the reason the stderr below is coloured per line:
        // a multi-line command's prompt is several lines, and each has to
        // close what it opened.
        for line in header.lines() {
            out.push_str(&bold(line));
            out.push('\n');
        }
        if let Some(stdout) = cmd.stdout.as_deref().filter(|s| !s.trim_end().is_empty()) {
            for line in stdout.trim_end().lines() {
                out.push_str(line);
                out.push('\n');
            }
        }
        if let Some(stderr) = cmd.stderr.as_deref().filter(|s| !s.trim_end().is_empty()) {
            // Coloured line by line rather than as a block: the reset then
            // lands before each newline, which is what keeps the colour from
            // bleeding across lines in a pager.
            for line in stderr.trim_end().lines() {
                out.push_str(&red(line));
                out.push('\n');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(events: Vec<OutEvent<'_>>) -> (String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        for event in events {
            write_event(event, &mut out, &mut err);
        }
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn each_stream_keeps_its_own_channel() {
        let (out, err) = capture(vec![
            OutEvent::Stdout(b"Reading package lists...\n"),
            OutEvent::Stderr(b"W: some warning\n"),
        ]);
        assert_eq!(out, "Reading package lists...\n");
        assert!(err.contains("W: some warning"), "{err:?}");
        assert!(!out.contains("warning"), "{out:?}");
    }

    #[test]
    fn the_command_header_stays_out_of_stdout() {
        let (out, err) = capture(vec![
            OutEvent::Command("sudo -n -- sh -c 'apt-get update'"),
            OutEvent::Stdout(b"Hit:1 http://deb.debian.org\n"),
        ]);
        // Framing must not interleave itself into the captured output.
        assert_eq!(out, "Hit:1 http://deb.debian.org\n");
        assert!(
            err.contains("$ sudo -n -- sh -c 'apt-get update'"),
            "{err:?}"
        );
    }

    #[test]
    fn a_multi_line_command_is_elided_to_one_prompt_line() {
        let (_, err) = capture(vec![OutEvent::Command(
            "sudo -n -- sh -c 'export LC_ALL=C\necho \"### MARKER\"\nuname -r\n'",
        )]);
        assert_eq!(err.lines().count(), 1, "{err:?}");
        assert!(
            err.contains("$ sudo -n -- sh -c 'export LC_ALL=C…"),
            "{err:?}"
        );
    }

    #[test]
    fn chunks_are_passed_through_byte_for_byte() {
        // A read can land mid-way through a UTF-8 sequence, so the two halves
        // must arrive unaltered and rejoin into the original text.
        let text = "é×日\n".as_bytes();
        let (first, second) = text.split_at(3);
        let (out, _) = capture(vec![OutEvent::Stdout(first), OutEvent::Stdout(second)]);
        assert_eq!(out, "é×日\n");
    }

    fn server() -> Server {
        Server {
            hostname: "web-01".to_string(),
            ssh_user: "admin".to_string(),
            ssh_port: 22,
            ssh_key_path: None,
            host_type: "apt".to_string(),
            distribution: None,
            last_update_at: None,
            last_update_ok: None,
            reboot_required: None,
            reboot_detail: None,
            no_all: false,
        }
    }

    fn logged(command: &str, stdout: &str, stderr: &str, exit_code: i64) -> LoggedCommand {
        LoggedCommand {
            command: command.to_string(),
            stdout: Some(stdout.to_string()),
            stderr: Some(stderr.to_string()),
            exit_code: Some(exit_code),
            run_at: "2026-08-27T13:05:31+00:00".to_string(),
        }
    }

    #[test]
    fn a_command_reads_as_a_prompt_line_over_its_own_output() {
        let out = log_transcript(
            &server(),
            &[logged(
                "apt-get update",
                "Hit:1 http://deb.debian.org\n",
                "",
                0,
            )],
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[0].contains("admin@web-01 # apt-get update (at "),
            "{out:?}"
        );
        assert_eq!(lines[1], "Hit:1 http://deb.debian.org");
        // Nothing is framed any more, and a clean run says nothing about exit.
        assert!(!out.contains('│') && !out.contains('╭'), "{out:?}");
        assert!(!out.contains("exit"), "{out:?}");
    }

    #[test]
    fn a_failure_carries_its_exit_code_and_its_stderr_last() {
        let out = log_transcript(
            &server(),
            &[logged(
                "apt-get upgrade",
                "Reading package lists...\n",
                "E: Could not get lock\n",
                100,
            )],
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains(", exit 100)"), "{out:?}");
        assert!(lines[1].contains("Reading package lists..."), "{out:?}");
        assert!(lines[2].contains("E: Could not get lock"), "{out:?}");
    }

    #[test]
    fn multi_line_stderr_stays_one_line_per_line() {
        // Each line is styled separately, so each must still arrive as its own
        // line — the colouring must not fold or drop any of them.
        let out = log_transcript(&server(), &[logged("probe", "", "one\ntwo\n", 1)]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out:?}");
        assert!(lines[1].contains("one"), "{out:?}");
        assert!(lines[2].contains("two"), "{out:?}");
    }

    #[test]
    fn a_multi_line_command_is_kept_whole() {
        // The opposite of the streaming sink: this is the archival view, so
        // the whole script is there to be read.
        let script = "sudo -n -- sh -c 'export LC_ALL=C\necho \"### MARKER\"\nuname -r'";
        let out = log_transcript(&server(), &[logged(script, "6.1.0-18-amd64\n", "", 0)]);
        assert!(out.contains("### MARKER"), "{out:?}");
        assert!(out.contains("uname -r'"), "{out:?}");
    }

    #[test]
    fn commands_are_separated_by_a_blank_line_and_empty_output_is_just_a_prompt() {
        let out = log_transcript(
            &server(),
            &[logged("true", "", "", 0), logged("false", "", "", 1)],
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out:?}");
        assert!(lines[0].contains("# true"), "{out:?}");
        assert_eq!(lines[1], "");
        assert!(lines[2].contains("# false"), "{out:?}");
    }
}
