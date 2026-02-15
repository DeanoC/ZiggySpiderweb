#!/bin/bash
#
# Quick update script - rebuild and restart
# Run as root or with sudo
#

set -e

SERVICE_NAME="${SERVICE_NAME:-spiderweb}"

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
cp zig-out/bin/spiderweb /opt/spiderweb/bin/
cp zig-out/bin/spiderweb-config /opt/spiderweb/bin/

log_info "Restarting service..."
systemctl start "$SERVICE_NAME"

log_info "Done! Status:"
systemctl status "$SERVICE_NAME" --no-pager
