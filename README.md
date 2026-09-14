# darn

SSH-based bulk patching CLI.

darn provides easy, fast centralised patching designed for up to a few tens of
hosts, for people who would otherwise do it manually. Installation,
registration of a few hosts and a first patching run should take less than five
minutes. It works in parallel across all of your hosts, so makes ongoing
patching much faster.

Debian/Ubuntu, RedHat family and (with limited functionality) Mikrotik hosts are
currently supported.

It is command line based and builds on SSH for authentication and remote host
access, enabling rapid setup. Command line completion makes it quick to use. As
well as parallel patching, changes can be applied individually for fine grained
control. It also looks after service restarts and host reboots (tracking which
are complete) in a similar way. 

It can be run directly on your laptop, any management server or from a locked
down host. The latter is particularly recommended as the user it runs under must
have SSH public keys authorised for passwordless sudo on all managed hosts.
While this sounds scary, the alternative for most users is ssh'ing from the same
machine they use to browse the web, which is the same or worse. 

## Installing

### Debian (11+), Ubuntu (Ubuntu 20.04+) and derivatives

```sh
curl -1sLf https://dl.cloudsmith.io/public/getdarn/darn/setup.deb.sh | sudo -E bash
sudo apt install darn
```

### RHEL, Alma, Rocky, Fedora (8+)

```sh
curl -1sLf https://dl.cloudsmith.io/public/getdarn/darn/setup.rpm.sh | sudo -E bash
sudo dnf install darn
```

### Static tarball

```sh
curl -LO https://github.com/getdarn/darn/releases/latest/download/darn-0.3.2-x86_64-linux-musl.tar.gz
tar xzf darn-0.3.2-x86_64-linux-musl.tar.gz
sudo install -m755 darn-0.3.2-x86_64-linux-musl/darn /usr/local/bin/darn
```

Every release also ships `SHA256SUMS` and build provenance attestations, so a
download can be verified with `sha256sum -c` and `gh attestation verify`.

### Building from source

See the [developer guide](https://github.com/getdarn/darn/blob/main/docs/Developers.md)
for setting up a build environment, building, and running the tests.

## Quick start

```sh
darn server add admin@web-01          # Prompts to install keys + passwordless sudo if needed
darn server add '[2001:db8::1]:2222'  # bracketed IPv6 with a port, current user
darn update                           # discover pending patches (parallel)
darn status                           # pending actions
darn upgrade all                      # apply patches (parallel)
darn reboot all                       # reboot the hosts where required (parallel)
darn restartservices all              # bounce services running stale libraries (parallel)
darn log web-01                       # full output of the last session
darn shell web-01                     # interactive SSH session on a managed host
```

## Shell completion

Completion covers subcommands and flags, and completes registered hostnames.

```sh
# ~/.bashrc
source <(COMPLETE=bash darn)

# ~/.zshrc
source <(COMPLETE=zsh darn)

# ~/.config/fish/config.fish
COMPLETE=fish darn | source
```

## Commands

- `darn server add [USER@]HOSTNAME[:PORT] [--port N] [--key PATH] [--no-all|--all]`
  — add or refresh a host. `--no-all` holds it back from `all` targets.
  Prompts to add to known hosts if required and (with a password) to install 
  your public key on the host to allow passwordless ssh. If the remote user 
  does not have passwordless sudo, it will also offer to create a separate 
  'darn' user which does.
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
- `darn update [TARGET] [-j N]` — probe a single host or all in parallel
  and record pending patches, reboot state, and stale services.
- `darn upgrade TARGET [--security|--non-security] [-j N] [--include-no-all]`
  — apply outstanding patches to an individual host or the literal `all` 
  (excluding hosts flagged as no-all, which must be patched individually).
  For a single host, output is streamed as if the package manager has been 
  run directly. `all` applies outstanding patches in parallel. All patch 
  output is available with `darn log`.
- `darn reboot TARGET [-y] [--force] [--no-wait] [--timeout SECONDS] [-j N] [--include-no-all]`
  — reboot hosts flagged as needing it; waits for each host to come back
  unless `--no-wait`.
- `darn restartservices TARGET [-y] [--force] [-j N] [--include-no-all]`
  — restart stale services. On Debian this is delegated to needrestart so the
  host's own restart policy is honoured; declined units are marked deferred.
  `--force` bypasses the policy.
- `darn log HOSTNAME` — the recorded commands from the most recent session.
- `darn shell HOSTNAME` — drop into an interactive session on a managed host,
  using the stored user, port and key. Unlike other commands, requires 'ssh' 
  to be on the path.
- `darn status [--plain] [--all]` — displays pending patches, service restarts
  and reboots required.
- `darn completions SHELL` — print the shell completion script (see above).

Exit codes: 0 on success, 1 when a command or any host failed, 2 on usage
errors.

## Database

Darn stores state in a SQLite database The database lives at 
`$XDG_DATA_HOME/darn/darn.db` (default`~/.local/share/darn/darn.db`).

## Server export/import

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

The following allows allows darn to be run from a new machine:

```sh
darn server export hosts.yaml            # on the existing machine
darn server import --replace hosts.yaml  # on the new machine
darn update                              # on the new machine
```

If known_hosts doesn't contain the relevant hosts or authorized_keys on each
host doesn't include the new users keys, darn will report errors. These can
be fixed by running "darn update" for each host individually.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE.txt](LICENSE.txt).
