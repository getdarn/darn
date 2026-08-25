# darn

SSH-based fleet patching CLI.

darn keeps a list of hosts in a local SQLite database, connects to them in
parallel over SSH with your own credentials, discovers pending package
updates, applies them, reboots hosts that need it, and restarts services left
running against upgraded libraries. Every remote command's stdout, stderr and
exit code is logged to the database.

Supported host types: Debian/Ubuntu (`apt`), RedHat-family (`dnf`/`yum`), and
Mikrotik RouterOS.

## Installing

### Debian, Ubuntu and derivatives

```sh
curl -1sLf https://dl.cloudsmith.io/public/getdarn/darn/setup.deb.sh | sudo -E bash
sudo apt install darn
```

### RHEL, Alma, Rocky, Fedora

```sh
curl -1sLf https://dl.cloudsmith.io/public/getdarn/darn/setup.rpm.sh | sudo -E bash
sudo dnf install darn
```

Packages are built against glibc 2.28, so they work on RHEL-family 8 and
later, Debian 11 and later, and Ubuntu 20.04 and later.

### Static tarball

Needs no glibc at all — useful for older or unusual distributions.

```sh
curl -LO https://github.com/getdarn/darn/releases/latest/download/darn-0.1.0-x86_64-linux-musl.tar.gz
tar xzf darn-0.1.0-x86_64-linux-musl.tar.gz
sudo install -m755 darn-0.1.0-x86_64-linux-musl/darn /usr/local/bin/darn
```

Every release also ships `SHA256SUMS` and build provenance attestations, so a
download can be verified with `sha256sum -c` and `gh attestation verify`.

### Docker

```sh
docker run --rm -it \
  -v ~/.ssh:/home/darn/.ssh:ro \
  -v ~/.local/share/darn:/home/darn/.local/share/darn \
  -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \
  -e USER="$USER" \
  ghcr.io/getdarn/darn:latest status
```

Three of those flags are load-bearing. `-t` keeps the progress bars working.
`USER` is what darn uses as the SSH username for targets added without an
explicit `user@`, and it defaults to `root` when unset. Mounting the data
directory is what makes the database survive the container.

The image is Alpine-based and includes `ssh`, so you can accept a new host key
from inside it, and `bash`, so `docker exec -it <container> bash` gets working
tab-completion.

### Building from source

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
darn shell web-01                     # interactive SSH session on a managed host
```

## Shell completion

Completion covers subcommands and flags, and completes hostnames from your own
database — so `darn upgrade <TAB>` offers `all` plus the hosts you manage, and
`darn server add <TAB>` also offers the hosts in `~/.ssh/config` and
`~/.ssh/known_hosts`. Add one line to your shell's startup file:

```sh
# ~/.bashrc
source <(COMPLETE=bash darn)

# ~/.zshrc
source <(COMPLETE=zsh darn)

# ~/.config/fish/config.fish
COMPLETE=fish darn | source
```

`darn completions SHELL` prints the same script if you would rather install it
as a file (`bash`, `elvish`, `fish`, `powershell`, `zsh`):

```sh
darn completions bash > /etc/bash_completion.d/darn
darn completions fish > ~/.config/fish/completions/darn.fish
```

The script calls darn itself to work out the candidates, so regenerate a saved
copy after upgrading darn. Completion reads the database without creating or
modifying it, and stays silent if there is no database yet.

## Commands

- `darn server add [USER@]HOSTNAME[:PORT] [--port N] [--key PATH] [--no-all|--all]`
  — add or refresh a host. `--no-all` holds it back from `all` targets;
  re-adding without either flag keeps the current setting. Offers to record an
  unknown host key, and to install your public key where none works
  (see [SSH behaviour](#ssh-behaviour)).
- `darn server remove|set|list`
- `darn server export FILE` — write the server list to FILE as YAML, or to
  standard output for `-`. See [the server file](#the-server-file).
- `darn server import FILE [--replace] [-y]` — read a server list back, adding
  hosts that are new and refreshing ones already there. Hosts the file does not
  mention are left alone unless `--replace` is given, which makes the list match
  the file exactly and asks before removing anything. FILE may be `-` for
  standard input.
- `darn server reset [-y]` — clear the server list. Asks first unless `-y` is
  given.
- `darn update [-j N]` — probe every host (including `--no-all` ones) and
  record pending patches, reboot state, and stale services.
- `darn upgrade TARGET [--security|--non-security] [-j N] [--include-no-all]`
  — apply patches to a hostname or the literal `all`. `all` selects only the
  hosts the last discovery found patches on (narrowed by `--security` /
  `--non-security`), the way `reboot all` and `restartservices all` select
  theirs; naming a host directly upgrades it regardless. Naming a single host
  streams that host's output to your terminal as it happens, as if you had run
  the package manager there yourself; `all` shows a progress bar instead,
  because concurrent hosts interleaving would be unreadable. Either way the
  summary table is printed at the end and the full output is recorded, to be
  read back with `darn log`.
- `darn reboot TARGET [-y] [--force] [--no-wait] [--timeout SECONDS] [-j N] [--include-no-all]`
  — reboot hosts flagged as needing it; waits for each host to come back
  (verified by a changed boot id) unless `--no-wait`.
- `darn restartservices TARGET [-y] [--force] [-j N] [--include-no-all]`
  — restart stale services. On Debian this is delegated to needrestart so the
  host's own restart policy is honoured; declined units are marked deferred,
  and `--force` bypasses the policy.
- `darn log HOSTNAME` — the recorded commands from the most recent session.
- `darn shell HOSTNAME` — drop into an interactive session on a managed host,
  using the stored user, port and key. This one hands the terminal to `ssh(1)`,
  so ssh must be on PATH and your `~/.ssh/config` applies; the session is not
  recorded.
- `darn status [--plain] [--all]` — offline view of pending work; `--plain`
  is stable, script-friendly text.
- `darn completions SHELL` — print the shell completion script (see above).

Exit codes: 0 on success, 1 when a command or any host failed, 2 on usage
errors.

## SSH behaviour

Authentication tries the explicit `--key` file, then the SSH agent, then
`~/.ssh/id_*`. Unknown or mismatched host keys are rejected. Privilege
escalation uses passwordless `sudo -n` (skipped when the SSH user is `root`).

`darn server add` is the one command that will ask you about either, so that
adding a host you have never touched takes one command rather than a detour
through `ssh` and `ssh-copy-id`. Both questions are asked only when stdin is a
terminal — `cron` runs fail as before rather than hang — and Ctrl+C cancels.

- **An unknown host key** is shown with its `SHA256` fingerprint, in ssh(1)'s
  own wording, and recorded in `~/.ssh/known_hosts` if you type `yes` (or paste
  the fingerprint back). Entries are written hashed, as OpenSSH writes them
  here, and the file is created 600 in a 700 `~/.ssh` if it does not exist. A
  *mismatched* key is never offered this way: that is a changed key, not a new
  one, and stays a hard error everywhere.
- **No usable key** prompts for the password of the **remote** account — the
  one on the host being added, not your local login — and uses it once to
  append your public key (`--key`'s `.pub` sibling, else the first of
  `~/.ssh/id_*.pub`) to `~/.ssh/authorized_keys` there. Every later connection
  uses the key. Hosts without a POSIX shell, such as RouterOS, need their keys
  installed with their own tools.

Every other command still rejects a host that is not already in `known_hosts`;
`darn server add` is where a host is vouched for.

## Database

The database lives at `$XDG_DATA_HOME/darn/darn.db` (default
`~/.local/share/darn/darn.db`). The schema is identical to darn3's, including
its migrations, so an existing darn3 database works as-is:

```sh
darn --db ~/.local/share/darn3/darn3.db status
```

darn does not migrate the default darn3 path automatically; copy the file or
pass `--db` if you want to keep using it.

## The server file

`darn server export` and `darn server import` move the server list in and out
of a YAML file, so it can be backed up, reviewed in a diff, kept in version
control, or copied to another machine:

```yaml
version: 1
servers:
- hostname: web-01
  ssh_user: admin
  ssh_port: 2222
  ssh_key_path: ~/.ssh/id_ed25519
  host_type: debian
  distribution: Ubuntu 24.04
  no_all: false
```

The file holds configuration only — what you told darn about a host. Pending
patches, reboot verdicts and the command log stay in the database, because they
are discovered state rather than something you decided. Nothing secret is in
there either: a private key's path, never its contents.

Only `hostname` and `host_type` are required, so a file can be written by hand.
`ssh_user` defaults to the current local user, `ssh_port` to 22, and `no_all` to
false — the same defaults `darn server add` uses. `host_type` must be one darn
supports (`debian`, `redhat` or `mikrotik`). Hosts are written in hostname
order, so re-exporting an unchanged fleet gives a byte-identical file.

Importing is entirely offline: it never connects to the hosts, and believes
what the file says about them. Run `darn update` afterwards to find out what
they actually need. A file that does not parse, names an unknown host type, or
lists a host twice is refused as a whole and changes nothing.

To replace one machine's list with another's exactly:

```sh
darn server export fleet.yaml            # on the machine that has the list
darn server import --replace fleet.yaml  # on the machine that wants it
```

## Development

```sh
cargo test     # DB, parser, target-parsing and orchestrator tests
cargo clippy
```

The parsers (apt simulate output, needrestart, dnf check-update /
updateinfo, RouterOS) and the restart-verdict precedence ladders are pure
functions with the darn3 test suite ported alongside them.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE.txt](LICENSE.txt).
