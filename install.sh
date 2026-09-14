#!/usr/bin/env bash
# darn installer:
#
#   curl -fsSL https://raw.githubusercontent.com/getdarn/darn/main/install.sh | sudo bash
#   wget -qO- https://raw.githubusercontent.com/getdarn/darn/main/install.sh | sudo bash
#
# On apt and dnf/yum systems it adds the getdarn/darn Cloudsmith repository and
# installs the darn package from it.
# Otherwise, or when given --tarball, it installs the static x86_64 binary
# from the latest GitHub Release into /usr/local, after checking it against the
# release's SHA256SUMS:
#
#   curl -fsSL https://raw.githubusercontent.com/getdarn/darn/main/install.sh | sudo bash -s -- --tarball

set -euo pipefail

REPO_URL=https://dl.cloudsmith.io/public/getdarn/darn
RELEASES_URL=https://github.com/getdarn/darn/releases
PREFIX=/usr/local

say() { printf '==> %s\n' "$*"; }
die() { printf 'darn install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# fetch URL FILE, with whichever of curl or wget is present.
fetch() {
    if have curl; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif have wget; then
        wget -q -O "$2" "$1"
    else
        die "need curl or wget to download $1"
    fi
}

# Cloudsmith's need curl, so install it on wget-only systems
ensure_curl() {
    have curl && return
    say "Installing curl, which the repository setup needs"
    case $1 in
        apt) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ;;
        *)   "$1" install -y -q curl ;;
    esac
}

install_apt() {
    ensure_curl apt
    say "Adding the getdarn/darn apt repository"
    fetch "$REPO_URL/setup.deb.sh" "$tmp/setup.sh"
    bash "$tmp/setup.sh"
    say "Installing darn"
    DEBIAN_FRONTEND=noninteractive apt-get install -y darn
}

install_rpm() {  # $1: dnf or yum
    ensure_curl "$1"
    say "Adding the getdarn/darn $1 repository"
    fetch "$REPO_URL/setup.rpm.sh" "$tmp/setup.sh"
    bash "$tmp/setup.sh"
    # Cloudsmith's generated config pins sslcacert to
    # /etc/pki/tls/certs/ca-bundle.crt, which Fedora 44 no longer ships, and dnf
    # then cannot reach the repository at all. Without the line dnf uses the
    # system trust store, so drop it wherever the file it names is missing.
    local repo=/etc/yum.repos.d/getdarn-darn.repo ca
    for ca in $(sed -n 's/^sslcacert=//p' "$repo" | sort -u); do
        [ -e "$ca" ] || sed -i "\\|^sslcacert=$ca\$|d" "$repo"
    done
    say "Installing darn"
    "$1" install -y darn
}

install_tarball() {
    [ "$(uname -m)" = x86_64 ] ||
        die "there is no prebuilt binary for $(uname -m); to build from source, see https://github.com/getdarn/darn/blob/main/docs/Developers.md"

    say "Finding the latest release"
    fetch "$RELEASES_URL/latest/download/SHA256SUMS" "$tmp/SHA256SUMS"
    # The tarball's name carries the version, so read it from the checksum
    # list rather than asking the GitHub API which release is the latest.
    local name version
    name=$(sed -n 's/^[0-9a-f]\{64\}  \(darn-.*-x86_64-linux-musl\)\.tar\.gz$/\1/p' "$tmp/SHA256SUMS")
    [ -n "$name" ] || die "the latest release's SHA256SUMS lists no x86_64 tarball"
    version=${name#darn-}
    version=${version%-x86_64-linux-musl}

    # Fetched by tag, not from latest/, so a release published in between
    # cannot swap the file out from under the checksum.
    say "Downloading darn $version"
    fetch "$RELEASES_URL/download/v$version/$name.tar.gz" "$tmp/$name.tar.gz"
    (cd "$tmp" && grep "  $name\.tar\.gz\$" SHA256SUMS | sha256sum -c - >/dev/null) ||
        die "$name.tar.gz does not match the release's SHA256SUMS"
    tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

    say "Installing into $PREFIX"
    local src="$tmp/$name"
    install -Dm755 "$src/darn"                  "$PREFIX/bin/darn"
    install -Dm644 "$src/darn.1"                "$PREFIX/share/man/man1/darn.1"
    install -Dm644 "$src/completions/darn.bash" "$PREFIX/share/bash-completion/completions/darn"
    install -Dm644 "$src/completions/_darn"     "$PREFIX/share/zsh/site-functions/_darn"
    install -Dm644 "$src/completions/darn.fish" "$PREFIX/share/fish/vendor_completions.d/darn.fish"
}

main() {
    local method=auto
    case ${1:-} in
        '')        ;;
        --tarball) method=tarball ;;
        *)         die "unknown option: $1 (the only option is --tarball)" ;;
    esac

    [ "$(id -u)" -eq 0 ] || die "must run as root; pipe it to 'sudo bash' rather than 'bash'"

    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    if [ "$method" = auto ]; then
        if have apt-get; then method=apt
        elif have dnf;   then method=dnf
        elif have yum;   then method=yum
        else                  method=tarball
        fi
    fi

    case $method in
        apt)     install_apt;           bin=/usr/bin/darn ;;
        dnf|yum) install_rpm "$method"; bin=/usr/bin/darn ;;
        tarball) install_tarball;       bin=$PREFIX/bin/darn ;;
    esac

    say "Installed $("$bin" --version)"
}

main "$@"
