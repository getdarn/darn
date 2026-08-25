#!/usr/bin/env bash
#
# Create and start the LXD test containers used for darn development.
#
# Existing containers are left alone (started if stopped), so this is safe to
# re-run. Failures are reported per container rather than aborting the run.

set -uo pipefail

if ! lxc list >/dev/null 2>&1; then
    echo "Cannot talk to the LXD daemon. Is lxd running, and are you in the 'lxd' group?" >&2
    echo "  sudo usermod -aG lxd \"$USER\"" >&2
    echo "Group changes only apply to newly created processes. On WSL, closing the" >&2
    echo "terminal is not enough - run 'wsl --shutdown' from Windows and reopen, or" >&2
    echo "use 'newgrp lxd' / 'sg lxd -c ./$(basename "$0")' in the current shell." >&2
    exit 1
fi

# name:image
CONTAINERS=(
    "dplex:ubuntu:24.04"
    "dhomeassistant:ubuntu:22.04"
    "dproxmox:images:debian/11"
    "dportainer:images:rockylinux/9"
)

failed=()

for entry in "${CONTAINERS[@]}"; do
    name="${entry%%:*}"
    image="${entry#*:}"

    if lxc info "$name" >/dev/null 2>&1; then
        status=$(lxc list "^${name}$" --format csv --columns s)
        if [ "$status" = "RUNNING" ]; then
            echo "== $name already exists and is running"
        else
            echo "== $name already exists ($status), starting"
            lxc start "$name" || failed+=("$name")
        fi
        continue
    fi

    echo "== Launching $name from $image"
    if ! lxc launch "$image" "$name"; then
        echo "!! Failed to launch $name from $image" >&2
        failed+=("$name")
    fi
done

echo
lxc list "^(dplex|dhomeassistant|dproxmox|dportainer)$"

if [ ${#failed[@]} -gt 0 ]; then
    echo >&2
    echo "Failed: ${failed[*]}" >&2
    exit 1
fi
