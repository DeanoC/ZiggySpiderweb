#!/bin/bash
#
# Quick update script - rebuild and restart
# Run as root or with sudo
#

set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-spiderweb}"
BASE_DIR="${SPIDERWEB_BASE_DIR:-${BASE_DIR:-}}"
if [ -n "$BASE_DIR" ]; then
    INSTALL_DIR_DEFAULT="$BASE_DIR/opt/spiderweb"
else
    INSTALL_DIR_DEFAULT="/opt/spiderweb"
fi
INSTALL_DIR="${INSTALL_DIR:-$INSTALL_DIR_DEFAULT}"
BINARIES=(spiderweb spiderweb-config spiderweb-control spiderweb-fs-mount)

log_info() {
    echo -e "\033[0;32m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root or with sudo"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

log_info "Stopping service..."
systemctl stop "$SERVICE_NAME" || true

log_info "Building..."
rm -rf zig-out .zig-cache
zig build -Doptimize=ReleaseSafe

log_info "Installing binaries..."
if [ ! -d "$INSTALL_DIR/bin" ]; then
    log_error "Install directory not found: $INSTALL_DIR/bin"
    exit 1
fi

for bin in "${BINARIES[@]}"; do
    if [ ! -x "zig-out/bin/$bin" ]; then
        log_error "Missing build artifact: zig-out/bin/$bin"
        exit 1
    fi
    cp "zig-out/bin/$bin" "$INSTALL_DIR/bin/"
    ln -sf "$INSTALL_DIR/bin/$bin" "/usr/local/bin/$bin"
done

log_info "Restarting service..."
systemctl start "$SERVICE_NAME"

log_info "Done! Status:"
systemctl status "$SERVICE_NAME" --no-pager
