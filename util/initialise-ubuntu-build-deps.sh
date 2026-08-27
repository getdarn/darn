#!/usr/bin/env bash
#
# Install everything a fresh Ubuntu box needs to `cargo build --release` darn.
#
# darn vendors libssh2, OpenSSL, SQLite and zlib and builds them from source, so
# beyond a Rust toolchain the only requirements are a C compiler, make and perl
# (OpenSSL's Configure is a perl script). Ubuntu's `perl` package already carries
# the IPC::Cmd and Time::Piece modules that Configure needs, so unlike the
# RHEL-family build (see .github/workflows/release.yml) nothing extra is pulled
# in for them.
#
# Once the toolchain is in place it runs `cargo build --release` and links the
# resulting binary into ~/.cargo/bin/darn (same PATH entry as cargo itself).
#
# Pass --musl to also set up the fully static x86_64-unknown-linux-musl build
# used for the release tarballs and the container image.
#
# Every step checks before acting, so this is safe to re-run.

set -uo pipefail

want_musl=0
for arg in "$@"; do
    case "$arg" in
        --musl) want_musl=1 ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-} ${ID_LIKE:-}" in
        *ubuntu*|*debian*) ;;
        *) echo "!! This script targets Ubuntu; ${PRETTY_NAME:-this system} may need different packages." >&2 ;;
    esac
fi

if [ "$(id -u)" -eq 0 ]; then
    sudo=""
elif command -v sudo >/dev/null 2>&1; then
    sudo="sudo"
else
    echo "Need root to install apt packages, and sudo is not available." >&2
    exit 1
fi

apt_packages=(build-essential curl ca-certificates git pkg-config perl)
if [ "$want_musl" -eq 1 ]; then
    apt_packages+=(musl-tools musl-dev)
fi

missing=()
for pkg in "${apt_packages[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        missing+=("$pkg")
    fi
done

if [ ${#missing[@]} -gt 0 ]; then
    echo "== Installing apt packages: ${missing[*]}"
    $sudo apt-get update -qq || exit 1
    $sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}" || exit 1
else
    echo "== apt packages already present: ${apt_packages[*]}"
fi

# Rust. Prefer an existing toolchain (rustup, a distro package, or one a CI
# image baked in); only reach for rustup.rs when there is no cargo at all.
if command -v cargo >/dev/null 2>&1; then
    echo "== Rust already installed: $(cargo --version)"
else
    echo "== Installing Rust via rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable || exit 1
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

# 1.88 is darn's MSRV (see rust-version in Cargo.toml). Warn rather than fail:
# the user may be pinning an older toolchain deliberately, and `rustup update`
# is their call to make.
if command -v rustc >/dev/null 2>&1; then
    rustc_ver=$(rustc --version | awk '{print $2}')
    if [ "$(printf '%s\n1.88.0\n' "$rustc_ver" | sort -V | head -1)" != "1.88.0" ]; then
        echo "!! rustc $rustc_ver is below darn's MSRV of 1.88; run 'rustup update stable'." >&2
    fi
fi

if [ "$want_musl" -eq 1 ]; then
    if command -v rustup >/dev/null 2>&1; then
        if rustup target list --installed 2>/dev/null | grep -qx x86_64-unknown-linux-musl; then
            echo "== musl target already installed"
        else
            echo "== Adding x86_64-unknown-linux-musl target"
            rustup target add x86_64-unknown-linux-musl || exit 1
        fi
    else
        echo "!! rustup not found; install the x86_64-unknown-linux-musl std yourself." >&2
    fi
fi

repo_root=$(cd "$(dirname "$0")/.." && pwd)

echo "== Building darn (cargo build --release)"
( cd "$repo_root" && cargo build --release ) || exit 1

# Symlink rather than `cargo install`: the link tracks every subsequent
# `cargo build --release` with no reinstall step. ~/.cargo/bin is already on
# PATH wherever cargo is (rustup wires it into the shell profile), so no extra
# PATH setup is needed here.
link_dir="${CARGO_HOME:-$HOME/.cargo}/bin"
link="$link_dir/darn"
mkdir -p "$link_dir"
ln -sfn "$repo_root/target/release/darn" "$link"
echo "== Linked $link -> $repo_root/target/release/darn"

case ":$PATH:" in
    *":$link_dir:"*) ;;
    *) echo "!! $link_dir is not on PATH in this shell; open a new shell or run '. \"$link_dir/../env\"'." >&2 ;;
esac

echo
if [ "$want_musl" -eq 1 ]; then
    echo "Static build:"
    echo "  CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --target x86_64-unknown-linux-musl"
fi
echo "Done. Run 'darn --version' to check the link resolves."
