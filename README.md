# darn

SSH-based fleet patching CLI — a Rust port of [darn3](https://github.com/mmaisey/darn3).

darn keeps a list of hosts in a local SQLite database, connects to them in
parallel over SSH with your own credentials, discovers pending package
updates, applies them, reboots hosts that need it, and restarts services left
running against upgraded libraries. Every remote command's stdout, stderr and
exit code is logged to the database.

Supported host types: Debian/Ubuntu (`apt`), RedHat-family (`dnf`/`yum`), and
Mikrotik RouterOS.

## Building

```sh
cargo build --release
# binary at target/release/darn
```

The build vendors libssh2, OpenSSL and SQLite, so no development headers are
needed.

## Quick start

```sh
darn server add admin@web-01          # auto-detects the host type
darn server add '[2001:db8::1]:2222'  # bracketed IPv6 with a port
darn update                           # discover pending patches (parallel)
darn status                           # what the last discovery found
darn upgrade all                      # apply patches everywhere
darn reboot all                       # reboot the hosts flagged as needing it
darn restartservices all              # bounce services running stale libraries
darn log web-01                       # full output of the last session
```

## Commands

- `darn server add [USER@]HOSTNAME[:PORT] [--port N] [--key PATH] [--no-all|--all]`
  — add or refresh a host. `--no-all` holds it back from `all` targets;
  re-adding without either flag keeps the current setting.
- `darn server remove|set|list`
- `darn update [-j N]` — probe every host (including `--no-all` ones) and
  record pending patches, reboot state, and stale services.
- `darn upgrade TARGET [--security|--non-security] [-j N] [--include-no-all]`
  — apply patches to a hostname or the literal `all`.
- `darn reboot TARGET [-y] [--force] [--no-wait] [--timeout SECONDS] [-j N] [--include-no-all]`
  — reboot hosts flagged as needing it; waits for each host to come back
  (verified by a changed boot id) unless `--no-wait`.
- `darn restartservices TARGET [-y] [--force] [-j N] [--include-no-all]`
  — restart stale services. On Debian this is delegated to needrestart so the
  host's own restart policy is honoured; declined units are marked deferred,
  and `--force` bypasses the policy.
- `darn log HOSTNAME` — the recorded commands from the most recent session.
- `darn status [--plain] [--all]` — offline view of pending work; `--plain`
  is stable, script-friendly text.

Exit codes: 0 on success, 1 when a command or any host failed, 2 on usage
errors.

## SSH behaviour

darn never prompts for a password. Authentication tries the explicit `--key`
file, then the SSH agent, then `~/.ssh/id_*`. Unknown or mismatched host keys
are rejected — connect once with plain `ssh` to accept a new host key.
Privilege escalation uses passwordless `sudo -n` (skipped when the SSH user
is `root`).

## Database

The database lives at `$XDG_DATA_HOME/darn/darn.db` (default
`~/.local/share/darn/darn.db`). The schema is identical to darn3's, including
its migrations, so an existing darn3 database works as-is:

```sh
darn --db ~/.local/share/darn3/darn3.db status
```

darn does not migrate the default darn3 path automatically; copy the file or
pass `--db` if you want to keep using it.

## Development

```sh
cargo test     # DB, parser, target-parsing and orchestrator tests
cargo clippy
```

The parsers (apt simulate output, needrestart, dnf check-update /
updateinfo, RouterOS) and the restart-verdict precedence ladders are pure
functions with the darn3 test suite ported alongside them.
