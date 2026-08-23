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
- `darn completions SHELL` — print the shell completion script (see above).

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

## License

Licensed under the Apache License, Version 2.0. See [LICENSE.txt](LICENSE.txt).
