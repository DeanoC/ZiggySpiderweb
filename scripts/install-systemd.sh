#!/bin/bash
#
# Spiderweb SystemD Install Script
# Run as root or with sudo.
#

set -euo pipefail

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

INSTALL_USER="${INSTALL_USER:-spiderweb}"
INSTALL_DIR="${INSTALL_DIR:-$INSTALL_DIR_DEFAULT}"
CONFIG_DIR="${CONFIG_DIR:-$CONFIG_DIR_DEFAULT}"
DATA_DIR="${DATA_DIR:-$DATA_DIR_DEFAULT}"
LOG_DIR="${LOG_DIR:-$LOG_DIR_DEFAULT}"
SERVICE_NAME="${SERVICE_NAME:-spiderweb}"
PORT="${PORT:-18790}"
BIND_ADDR="${BIND_ADDR:-0.0.0.0}"
SPIDER_WEB_ROOT="${SPIDER_WEB_ROOT:-}"
OVERWRITE_CONFIG="${OVERWRITE_CONFIG:-0}"

SERVICE_USER_HOME=""

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

check_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        log_error "systemctl not found. This script requires systemd."
        exit 1
    fi
    log_info "systemd detected ✓"
}

check_zig() {
    if ! command -v zig >/dev/null 2>&1; then
        log_error "Zig compiler not found. Please install Zig first."
        log_info "Visit: https://ziglang.org/download/"
        exit 1
    fi
    log_info "Zig version: $(zig version)"
}

build_project() {
    log_info "Building Spiderweb..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

    cd "$PROJECT_DIR"
    rm -rf zig-out .zig-cache
    zig build -Doptimize=ReleaseSafe

    if [ ! -f "zig-out/bin/spiderweb" ]; then
        log_error "Build failed: spiderweb binary not found"
        exit 1
    fi

    log_info "Build successful ✓"
}

create_user() {
    if id "$INSTALL_USER" >/dev/null 2>&1; then
        log_warn "User '$INSTALL_USER' already exists"
    else
        log_info "Creating user: $INSTALL_USER"
        useradd --system --create-home --shell /usr/sbin/nologin "$INSTALL_USER"
    fi

    SERVICE_USER_HOME="$(getent passwd "$INSTALL_USER" | cut -d: -f6)"
    if [ -z "$SERVICE_USER_HOME" ] || [ "$SERVICE_USER_HOME" = "/" ]; then
        log_error "Could not determine home directory for user '$INSTALL_USER'"
        exit 1
    fi

    mkdir -p "$SERVICE_USER_HOME/.config/spiderweb"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME"
    chmod 700 "$SERVICE_USER_HOME"
}

install_files() {
    log_info "Installing files to $INSTALL_DIR..."

    mkdir -p "$INSTALL_DIR/bin"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/mounts"
    mkdir -p "$DATA_DIR/rootfs/base"
    mkdir -p "$DATA_DIR/rootfs/overlays"
    mkdir -p "$DATA_DIR/rootfs/snapshots"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

    cp "$PROJECT_DIR/zig-out/bin/spiderweb" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-config" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-fs-mount" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-control" "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/"*

    ln -sf "$INSTALL_DIR/bin/spiderweb" /usr/local/bin/spiderweb
    ln -sf "$INSTALL_DIR/bin/spiderweb-config" /usr/local/bin/spiderweb-config
    ln -sf "$INSTALL_DIR/bin/spiderweb-control" /usr/local/bin/spiderweb-control

    log_info "Binaries installed ✓"
}

install_config() {
    log_info "Setting up configuration..."

    CONFIG_FILE="$CONFIG_DIR/config.json"

    if [ -f "$CONFIG_FILE" ] && [ "$OVERWRITE_CONFIG" != "1" ]; then
        log_warn "Config already exists at $CONFIG_FILE; preserving existing file (set OVERWRITE_CONFIG=1 to replace)"
    else
        if [ -f "$CONFIG_FILE" ]; then
            log_warn "Config already exists at $CONFIG_FILE"
            log_info "Backing up to $CONFIG_FILE.bak"
            cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
        fi
        cat > "$CONFIG_FILE" <<EOF
{
  "server": {
    "bind": "$BIND_ADDR",
    "port": $PORT
  },
  "log": {
    "level": "info"
  },
  "runtime": {
    "spider_web_root": "$SPIDER_WEB_ROOT",
    "ltm_directory": "$DATA_DIR/.spiderweb-ltm",
    "ltm_filename": "runtime-memory.db",
    "sandbox_mounts_root": "$DATA_DIR/mounts",
    "sandbox_rootfs_base_ref": "debian:bookworm-slim",
    "sandbox_rootfs_store_root": "$DATA_DIR/rootfs/base",
    "sandbox_overlay_root": "$DATA_DIR/rootfs/overlays",
    "sandbox_snapshot_root": "$DATA_DIR/rootfs/snapshots",
    "sandbox_fs_mount_bin": "$INSTALL_DIR/bin/spiderweb-fs-mount"
  }
}
EOF
    fi

    chmod 644 "$CONFIG_FILE"

    mkdir -p "$SERVICE_USER_HOME/.config/spiderweb"
    cp "$CONFIG_FILE" "$SERVICE_USER_HOME/.config/spiderweb/config.json"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME/.config"
    chmod 755 "$SERVICE_USER_HOME/.config"
    chmod 755 "$SERVICE_USER_HOME/.config/spiderweb"
    chmod 644 "$SERVICE_USER_HOME/.config/spiderweb/config.json"

    log_info "Config installed at $CONFIG_FILE"
    log_info "Edit with: spiderweb-config config"
}

install_systemd_service() {
    log_info "Installing systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Spiderweb Workspace Host
Documentation=https://github.com/DeanoC/Spiderweb
After=network.target
Wants=network.target

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER
Environment="SPIDERWEB_CONFIG=$CONFIG_DIR/config.json"
Environment="HOME=$SERVICE_USER_HOME"
WorkingDirectory=$DATA_DIR
ExecStart=$INSTALL_DIR/bin/spiderweb
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
StartLimitInterval=60s
StartLimitBurst=3
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$DATA_DIR $LOG_DIR $SERVICE_USER_HOME/.config
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=false
RestrictRealtime=true
RestrictNamespaces=false
LockPersonality=true
MemoryDenyWriteExecute=true
LimitNOFILE=65536
LimitNPROC=4096
StandardOutput=journal
StandardError=journal
SyslogIdentifier=spiderweb

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service installed: $SERVICE_NAME.service"
}

set_permissions() {
    log_info "Setting permissions..."

    chown -R root:root "$INSTALL_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$LOG_DIR"
    chown root:"$INSTALL_USER" "$CONFIG_DIR"
    chown root:"$INSTALL_USER" "$CONFIG_DIR/config.json"
    chmod 755 "$CONFIG_DIR"
    chmod 644 "$CONFIG_DIR/config.json"

    if [ -d "$SERVICE_USER_HOME/.config" ]; then
        chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME/.config"
    fi

    log_info "Permissions set ✓"
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "  Spiderweb Installation Complete!"
    echo "=========================================="
    echo ""
    echo "Service:     $SERVICE_NAME"
    echo "User:        $INSTALL_USER"
    echo "Install:     $INSTALL_DIR"
    echo "Config:      $CONFIG_DIR/config.json"
    echo "Logs:        $LOG_DIR/"
    echo "Data:        $DATA_DIR/"
    echo "Port:        $PORT"
    echo "Bind:        $BIND_ADDR"
    echo "System Root: $SPIDER_WEB_ROOT"
    echo ""
    echo "Commands:"
    echo "  Start:     sudo systemctl start $SERVICE_NAME"
    echo "  Stop:      sudo systemctl stop $SERVICE_NAME"
    echo "  Status:    sudo systemctl status $SERVICE_NAME"
    echo "  Logs:      sudo journalctl -u $SERVICE_NAME -f"
    echo "  Config:    sudo spiderweb-config config"
    echo ""
    echo "Notes:"
    echo "  - Spiderweb now runs as a workspace host only."
    echo "  - Create and mount workspaces with spiderweb-control and spiderweb-fs-mount."
    echo "  - External workers such as Spider Monkey own model/provider credentials."
    echo ""
}

main() {
    echo "========================================"
    echo "  Spiderweb SystemD Installer"
    echo "========================================"
    echo ""

    check_root
    check_systemd
    check_zig
    build_project
    create_user
    install_files
    install_config
    install_systemd_service
    set_permissions
    print_summary

    log_info "Installation complete!"
    log_info "Start with: sudo systemctl start $SERVICE_NAME"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
