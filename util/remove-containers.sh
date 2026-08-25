#!/usr/bin/env bash
#
# Stop and remove the LXD test containers created by create-containers.sh.
#
# Containers that do not exist are skipped, so this is safe to re-run.

set -uo pipefail

if ! lxc list >/dev/null 2>&1; then
    echo "Cannot talk to the LXD daemon. Is lxd running, and are you in the 'lxd' group?" >&2
    echo "  sudo usermod -aG lxd \"$USER\"" >&2
    echo "Group changes only apply to newly created processes. On WSL, closing the" >&2
    echo "terminal is not enough - run 'wsl --shutdown' from Windows and reopen, or" >&2
    echo "use 'newgrp lxd' / 'sg lxd -c ./$(basename "$0")' in the current shell." >&2
    exit 1
fi

CONTAINERS=(dplex dhomeassistant dproxmox dportainer)

failed=()

for name in "${CONTAINERS[@]}"; do
    if ! lxc info "$name" >/dev/null 2>&1; then
        echo "== $name does not exist, skipping"
        continue
    fi

    echo "== Deleting $name"
    if ! lxc delete --force "$name"; then
        echo "!! Failed to delete $name" >&2
        failed+=("$name")
    fi
done

if [ ${#failed[@]} -gt 0 ]; then
    echo >&2
    echo "Failed: ${failed[*]}" >&2
    exit 1
fi
