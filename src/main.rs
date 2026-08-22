mod commands;
mod complete;
mod db;
mod errors;
mod hosts;
mod orchestrator;
mod quote;
mod render;
mod ssh;
mod target;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::engine::{ArgValueCandidates, ArgValueCompleter, PathCompleter};

use crate::errors::DarnError;

/// darn — SSH-based fleet patching CLI.
#[derive(Parser)]
#[command(name = "darn", version, about = "darn — SSH-based fleet patching CLI.")]
struct Cli {
    /// Override SQLite database path.
    #[arg(
        long = "db",
        value_name = "PATH",
        global = true,
        add = ArgValueCompleter::new(PathCompleter::file())
    )]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the list of servers.
    #[command(subcommand)]
    Server(ServerCommand),

    /// Discover which hosts need patching (runs in parallel).
    Update {
        /// Maximum number of hosts to work on in parallel.
        #[arg(short, long, default_value_t = 10)]
        jobs: usize,
    },

    /// Apply patches to TARGET (a hostname, or the literal 'all').
    ///
    /// 'all' skips hosts marked --no-all unless --include-no-all is given;
    /// naming such a host directly always works.
    Upgrade {
        #[arg(add = ArgValueCandidates::new(complete::targets))]
        target: String,
        /// Maximum number of hosts to work on in parallel.
        #[arg(short, long, default_value_t = 10)]
        jobs: usize,
        /// Apply only security patches.
        #[arg(long)]
        security: bool,
        /// Apply only non-security patches.
        #[arg(long)]
        non_security: bool,
        /// Also include hosts marked --no-all.
        #[arg(long)]
        include_no_all: bool,
    },

    /// Reboot TARGET (a hostname, or the literal 'all').
    ///
    /// 'all' selects only the hosts that the last `darn update` or `darn
    /// upgrade` flagged as needing a reboot; --force widens that to hosts
    /// whose state could not be determined. Hosts marked --no-all are left
    /// out unless --include-no-all is given; naming one directly always works.
    Reboot {
        #[arg(add = ArgValueCandidates::new(complete::targets))]
        target: String,
        /// Maximum number of hosts to reboot concurrently.
        #[arg(short, long, default_value_t = 1)]
        jobs: usize,
        /// Do not ask for confirmation.
        #[arg(short, long)]
        yes: bool,
        /// Include hosts darn has not flagged as needing a reboot.
        #[arg(long)]
        force: bool,
        /// Wait for each host to come back up before reporting success.
        #[arg(long, default_value_t = true, overrides_with = "no_wait", action = clap::ArgAction::SetTrue)]
        wait: bool,
        /// Do not wait for hosts to come back up.
        #[arg(long = "no-wait", overrides_with = "wait")]
        no_wait: bool,
        /// How long to wait for a host to come back up.
        #[arg(long, value_name = "SECONDS", default_value_t = 300.0)]
        timeout: f64,
        /// Also include hosts marked --no-all.
        #[arg(long)]
        include_no_all: bool,
    },

    /// Restart stale services on TARGET (a hostname, or the literal 'all').
    ///
    /// Services are those the last `darn update` or `darn upgrade` found
    /// running against upgraded libraries. Units that policy declines to
    /// restart are marked deferred and stop being counted as outstanding
    /// work — pass --force to restart them directly anyway.
    Restartservices {
        #[arg(add = ArgValueCandidates::new(complete::targets))]
        target: String,
        /// Maximum number of hosts to work on in parallel.
        #[arg(short, long, default_value_t = 10)]
        jobs: usize,
        /// Do not ask for confirmation.
        #[arg(short, long)]
        yes: bool,
        /// Also restart units the host's own policy declined, bypassing it.
        #[arg(long)]
        force: bool,
        /// Also include hosts marked --no-all.
        #[arg(long)]
        include_no_all: bool,
    },

    /// Show the output of the last commands run on a host.
    Log {
        #[arg(add = ArgValueCandidates::new(complete::hostnames))]
        hostname: String,
    },

    /// Show pending patches, reboots and service restarts.
    ///
    /// Built from what the last discovery stored rather than by contacting
    /// any host. Only hosts with something outstanding are listed unless
    /// --all is given.
    Status {
        /// Print plain text with no colour or tables, for scripts and cron.
        #[arg(long)]
        plain: bool,
        /// Also list hosts with nothing outstanding.
        #[arg(long = "all")]
        show_all: bool,
    },

    /// Print the shell completion script for SHELL.
    ///
    /// Either source it directly — `source <(darn completions bash)` — or save
    /// it where your shell looks for completions. `COMPLETE=bash darn` prints
    /// the same script. Regenerate it after upgrading darn.
    Completions {
        #[arg(value_name = "SHELL", value_parser = shell_values())]
        shell: String,
    },

    /// Print the roff man page, for packaging to capture as darn.1.
    #[command(hide = true)]
    Man,
}

/// The shells the completion engine can register with, taken from the engine
/// itself so the accepted values cannot drift from what it supports.
fn shell_values() -> clap::builder::PossibleValuesParser {
    let shells = clap_complete::env::Shells::builtins();
    clap::builder::PossibleValuesParser::new(shells.names().collect::<Vec<_>>())
}

#[derive(Subcommand)]
enum ServerCommand {
    /// Add a server, auto-detecting its host type.
    ///
    /// TARGET is `user@hostname`, `hostname`, or either of those with a
    /// `:port` suffix — without a user the current local user is used, and
    /// without a port 22 is used.
    Add {
        #[arg(
            value_name = "[USER@]HOSTNAME[:PORT]",
            add = ArgValueCandidates::new(complete::new_targets)
        )]
        target: String,
        /// SSH port on the managed host.  [default: 22]
        #[arg(short, long)]
        port: Option<u16>,
        /// Path to an SSH private key. Defaults to agent / ~/.ssh/id_*.
        #[arg(
            long = "key",
            value_name = "PATH",
            add = ArgValueCompleter::new(PathCompleter::file())
        )]
        key_path: Option<String>,
        #[command(flatten)]
        no_all: NoAllFlag,
    },
    /// Remove a server from the managed list.
    Remove {
        #[arg(add = ArgValueCandidates::new(complete::hostnames))]
        hostname: String,
    },
    /// Change the settings of an already-added server.
    Set {
        #[arg(add = ArgValueCandidates::new(complete::hostnames))]
        hostname: String,
        #[command(flatten)]
        no_all: NoAllFlag,
    },
    /// List all managed servers.
    List,
}

/// The tri-state --no-all/--all pair: unset keeps the stored value.
#[derive(Args)]
struct NoAllFlag {
    /// Leave this host out of 'all' targets, so it must be named explicitly.
    #[arg(long = "no-all", overrides_with = "all")]
    no_all: bool,
    /// Include this host in 'all' targets again.
    #[arg(long = "all", overrides_with = "no_all")]
    all: bool,
}

impl NoAllFlag {
    fn value(&self) -> Option<bool> {
        if self.no_all {
            Some(true)
        } else if self.all {
            Some(false)
        } else {
            None
        }
    }
}

fn run(cli: Cli) -> Result<i32, DarnError> {
    let db = cli.db.as_deref();
    match cli.command {
        Command::Server(cmd) => match cmd {
            ServerCommand::Add {
                target,
                port,
                key_path,
                no_all,
            } => commands::server::add(db, &target, port, key_path.as_deref(), no_all.value()),
            ServerCommand::Remove { hostname } => commands::server::remove(db, &hostname),
            ServerCommand::Set { hostname, no_all } => {
                commands::server::set(db, &hostname, no_all.value())
            }
            ServerCommand::List => commands::server::list(db),
        },
        Command::Update { jobs } => commands::update::run(db, jobs),
        Command::Upgrade {
            target,
            jobs,
            security,
            non_security,
            include_no_all,
        } => commands::upgrade::run(db, &target, jobs, security, non_security, include_no_all),
        Command::Reboot {
            target,
            jobs,
            yes,
            force,
            wait: _,
            no_wait,
            timeout,
            include_no_all,
        } => commands::reboot::run(
            db,
            &target,
            jobs,
            yes,
            force,
            !no_wait,
            timeout,
            include_no_all,
        ),
        Command::Restartservices {
            target,
            jobs,
            yes,
            force,
            include_no_all,
        } => commands::restartservices::run(db, &target, jobs, yes, force, include_no_all),
        Command::Log { hostname } => commands::log::run(db, &hostname),
        Command::Status { plain, show_all } => commands::status::run(db, plain, show_all),
        Command::Completions { shell } => commands::completions::run(&shell),
        Command::Man => commands::man::run(Cli::command()),
    }
}

fn main() -> ExitCode {
    // Answers the shell's completion callback and exits; a no-op otherwise.
    // Must come before anything that could write to stdout.
    clap_complete::CompleteEnv::with_factory(Cli::command).complete();

    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(DarnError::Usage(msg)) => {
            eprintln!("Error: {msg}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(1)
        }
    }
}
