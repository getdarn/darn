#!/bin/sh
# Generate the man page and completion scripts that the packages ship.
#
# clap_complete's dynamic engine bakes the path of the *generating* binary into
# the script (src/commands/completions.rs uses current_exe()), so the binary has
# to be installed at its final location before we run it. Generating straight
# out of target/release would ship scripts pointing at this build directory:
# they would install cleanly, source without error, and silently complete
# nothing.
#
# Usage: ci/gen-dist.sh [install-path] [output-dir]
set -eu

BIN=${1:-/usr/bin/darn}
OUT=${2:-dist}

install -D -m755 target/release/darn "$BIN"

mkdir -p "$OUT/completions" "$OUT/completions-portable"
"$BIN" man > "$OUT/darn.1"
"$BIN" completions bash > "$OUT/completions/darn.bash"
"$BIN" completions zsh  > "$OUT/completions/_darn"
"$BIN" completions fish > "$OUT/completions/darn.fish"

# The tarball can be unpacked anywhere, so it gets a variant that resolves darn
# through PATH instead of the packaged install path.
for f in darn.bash _darn darn.fish; do
    sed "s#$BIN#darn#g" "$OUT/completions/$f" > "$OUT/completions-portable/$f"
done

# Fail loudly if a build path ever leaks into something we ship.
if grep -rq 'target/release' "$OUT/completions" "$OUT/completions-portable"; then
    echo "error: build path leaked into completion scripts" >&2
    exit 1
fi
if grep -rq "$BIN" "$OUT/completions-portable"; then
    echo "error: install path left in portable completion scripts" >&2
    exit 1
fi

echo "generated $OUT/darn.1 and completions referencing $BIN"
