#!/bin/bash
#
# ZiggySpiderWeb Uninstall Script
# Run as root or with sudo
#

set -e

INSTALL_USER="${INSTALL_USER:-spiderweb}"
INSTALL_DIR="${INSTALL_DIR:-/opt/spiderweb}"
CONFIG_DIR="${CONFIG_DIR:-/etc/spiderweb}"
SERVICE_NAME="${SERVICE_NAME:-spiderweb}"

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
    echo "This will completely remove ZiggySpiderWeb from your system."
    echo ""
    echo "The following will be DELETED:"
    echo "  - Service: $SERVICE_NAME"
    echo "  - User: $INSTALL_USER"
    echo "  - Directory: $INSTALL_DIR"
    echo "  - Config: $CONFIG_DIR"
    echo "  - Logs: /var/log/spiderweb"
    echo "  - Data: /var/lib/spiderweb"
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
    
    # Config (backup first if exists)
    if [ -d "$CONFIG_DIR" ]; then
        BACKUP_DIR="/root/spiderweb-config-backup-$(date +%Y%m%d-%H%M%S)"
        cp -r "$CONFIG_DIR" "$BACKUP_DIR" 2>/dev/null || true
        log_info "Config backed up to: $BACKUP_DIR"
        rm -rf "$CONFIG_DIR"
    fi
    
    # Logs and data
    rm -rf /var/log/spiderweb
    rm -rf /var/lib/spiderweb
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
    echo "  ZiggySpiderWeb Uninstaller"
    echo "========================================"
    echo ""
    
    check_root
    read_confirm
    stop_service
    remove_service
    remove_files
    remove_user
    
    log_info "ZiggySpiderWeb has been uninstalled"
}

main "$@"
