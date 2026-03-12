#!/bin/bash
#
# Spiderweb Uninstall Script
# Run as root or with sudo
#

set -euo pipefail

INSTALL_USER="${INSTALL_USER:-spiderweb}"
SERVICE_NAME="${SERVICE_NAME:-spiderweb}"
BASE_DIR="${SPIDERWEB_BASE_DIR:-${BASE_DIR:-}}"
if [ -n "$BASE_DIR" ]; then
    INSTALL_DIR_DEFAULT="$BASE_DIR/opt/spiderweb"
    CONFIG_DIR_DEFAULT="$BASE_DIR/etc/spiderweb"
    DATA_DIR_DEFAULT="$BASE_DIR/var/lib/spiderweb"
    LOG_DIR_DEFAULT="$BASE_DIR/var/log/spiderweb"
else
    INSTALL_DIR_DEFAULT="/opt/spiderweb"
    CONFIG_DIR_DEFAULT="/etc/spiderweb"
    DATA_DIR_DEFAULT="/var/lib/spiderweb"
    LOG_DIR_DEFAULT="/var/log/spiderweb"
fi
INSTALL_DIR="${INSTALL_DIR:-$INSTALL_DIR_DEFAULT}"
CONFIG_DIR="${CONFIG_DIR:-$CONFIG_DIR_DEFAULT}"
DATA_DIR="${DATA_DIR:-$DATA_DIR_DEFAULT}"
LOG_DIR="${LOG_DIR:-$LOG_DIR_DEFAULT}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root or with sudo"
        exit 1
    fi
}

read_confirm() {
    echo "This will completely remove Spiderweb from your system."
    echo ""
    echo "The following will be DELETED:"
    echo "  - Service: $SERVICE_NAME"
    echo "  - User: $INSTALL_USER"
    echo "  - Directory: $INSTALL_DIR"
    echo "  - Config: $CONFIG_DIR"
    echo "  - Logs: $LOG_DIR"
    echo "  - Data: $DATA_DIR"
    echo ""
    read -p "Are you sure? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstall cancelled"
        exit 0
    fi
}

stop_service() {
    log_info "Stopping service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
}

remove_service() {
    log_info "Removing systemd service..."
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
}

remove_files() {
    log_info "Removing files..."
    
    # Binaries
    rm -rf "$INSTALL_DIR"
    rm -f /usr/local/bin/spiderweb
    rm -f /usr/local/bin/spiderweb-config
    rm -f /usr/local/bin/spiderweb-control
    rm -f /usr/local/bin/spiderweb-fs-mount
    
    # Config (backup first if exists)
    if [ -d "$CONFIG_DIR" ]; then
        BACKUP_DIR="/root/spiderweb-config-backup-$(date +%Y%m%d-%H%M%S)"
        cp -r "$CONFIG_DIR" "$BACKUP_DIR" 2>/dev/null || true
        log_info "Config backed up to: $BACKUP_DIR"
        rm -rf "$CONFIG_DIR"
    fi
    
    # Logs and data
    rm -rf "$LOG_DIR"
    rm -rf "$DATA_DIR"
}

remove_user() {
    if id "$INSTALL_USER" &>/dev/null; then
        log_info "Removing user: $INSTALL_USER"
        userdel "$INSTALL_USER" 2>/dev/null || true
    else
        log_warn "User '$INSTALL_USER' does not exist"
    fi
}

main() {
    echo "========================================"
    echo "  Spiderweb Uninstaller"
    echo "========================================"
    echo ""
    
    check_root
    read_confirm
    stop_service
    remove_service
    remove_files
    remove_user
    
    log_info "Spiderweb has been uninstalled"
}

main "$@"
