#!/bin/bash
#
# ZiggySpiderWeb SystemD Install Script
# Run as root or with sudo
#

set -e

INSTALL_USER="${INSTALL_USER:-spiderweb}"
INSTALL_DIR="${INSTALL_DIR:-/opt/spiderweb}"
CONFIG_DIR="${CONFIG_DIR:-/etc/spiderweb}"
SERVICE_NAME="${SERVICE_NAME:-spiderweb}"
PORT="${PORT:-18790}"
BIND_ADDR="${BIND_ADDR:-0.0.0.0}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
    if ! command -v systemctl &> /dev/null; then
        log_error "systemctl not found. This script requires systemd."
        exit 1
    fi
    log_info "systemd detected ✓"
}

check_zig() {
    if ! command -v zig &> /dev/null; then
        log_error "Zig compiler not found. Please install Zig first."
        log_info "Visit: https://ziglang.org/download/"
        exit 1
    fi
    log_info "Zig version: $(zig version)"
}

build_project() {
    log_info "Building ZiggySpiderWeb..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    cd "$PROJECT_DIR"
    
    # Clean and build
    rm -rf zig-out .zig-cache
    zig build -Doptimize=ReleaseSafe
    
    if [ ! -f "zig-out/bin/spiderweb" ]; then
        log_error "Build failed: spiderweb binary not found"
        exit 1
    fi
    
    log_info "Build successful ✓"
}

create_user() {
    if id "$INSTALL_USER" &>/dev/null; then
        log_warn "User '$INSTALL_USER' already exists"
    else
        log_info "Creating user: $INSTALL_USER"
        useradd --system --create-home --shell /usr/sbin/nologin "$INSTALL_USER"
    fi
    
    # Ensure home directory exists and has correct permissions
    USER_HOME=$(getent passwd "$INSTALL_USER" | cut -d: -f6)
    if [ -n "$USER_HOME" ] && [ "$USER_HOME" != "/" ]; then
        mkdir -p "$USER_HOME/.config/spiderweb"
        chown -R "$INSTALL_USER:$INSTALL_USER" "$USER_HOME"
        chmod 700 "$USER_HOME"
    fi
}

install_files() {
    log_info "Installing files to $INSTALL_DIR..."
    
    # Create directories
    mkdir -p "$INSTALL_DIR/bin"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "/var/log/spiderweb"
    mkdir -p "/var/lib/spiderweb"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    # Copy binaries
    cp "$PROJECT_DIR/zig-out/bin/spiderweb" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-config" "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/"*
    
    # Create symlink in /usr/local/bin
    ln -sf "$INSTALL_DIR/bin/spiderweb" /usr/local/bin/spiderweb
    ln -sf "$INSTALL_DIR/bin/spiderweb-config" /usr/local/bin/spiderweb-config
    
    log_info "Binaries installed ✓"
}

install_config() {
    log_info "Setting up configuration..."
    
    CONFIG_FILE="$CONFIG_DIR/config.json"
    
    if [ -f "$CONFIG_FILE" ]; then
        log_warn "Config already exists at $CONFIG_FILE"
        log_info "Backing up to $CONFIG_FILE.bak"
        cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
    fi
    
    # Generate default config
    cat > "$CONFIG_FILE" <<EOF
{
  "server": {
    "bind": "$BIND_ADDR",
    "port": $PORT
  },
  "provider": {
    "name": "openai",
    "model": "gpt-4o-mini"
  },
  "log": {
    "level": "info"
  }
}
EOF
    
    chmod 644 "$CONFIG_FILE"
    
    # Also copy to user's home directory where spiderweb looks for it
    USER_HOME=$(getent passwd "$INSTALL_USER" | cut -d: -f6)
    if [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
        mkdir -p "$USER_HOME/.config/spiderweb"
        cp "$CONFIG_FILE" "$USER_HOME/.config/spiderweb/config.json"
        chown -R "$INSTALL_USER:$INSTALL_USER" "$USER_HOME/.config"
        chmod 755 "$USER_HOME/.config"
        chmod 755 "$USER_HOME/.config/spiderweb"
        chmod 644 "$USER_HOME/.config/spiderweb/config.json"
    fi
    
    log_info "Config installed at $CONFIG_FILE"
    log_info "Edit with: spiderweb-config config"
}

install_systemd_service() {
    log_info "Installing systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=ZiggySpiderWeb Pi AI Gateway
Documentation=https://github.com/DeanoC/ZiggySpiderweb
After=network.target
Wants=network.target

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER

# Environment
Environment="SPIDERWEB_CONFIG=$CONFIG_DIR/config.json"
Environment="RUST_LOG=info"

# Working directory
WorkingDirectory=/var/lib/spiderweb

# Binary
ExecStart=$INSTALL_DIR/bin/spiderweb
ExecReload=/bin/kill -HUP \$MAINPID

# Restart policy
Restart=on-failure
RestartSec=5
StartLimitInterval=60s
StartLimitBurst=3

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/spiderweb /var/log/spiderweb /home/$INSTALL_USER/.config
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Logging
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
    chown -R "$INSTALL_USER:$INSTALL_USER" "/var/lib/spiderweb"
    chown -R "$INSTALL_USER:$INSTALL_USER" "/var/log/spiderweb"
    chown root:"$INSTALL_USER" "$CONFIG_DIR"
    chown root:"$INSTALL_USER" "$CONFIG_DIR/config.json"
    chmod 755 "$CONFIG_DIR"
    chmod 644 "$CONFIG_DIR/config.json"
    
    # Set permissions on user's home config
    USER_HOME=$(getent passwd "$INSTALL_USER" | cut -d: -f6)
    if [ -n "$USER_HOME" ] && [ -d "$USER_HOME/.config" ]; then
        chown -R "$INSTALL_USER:$INSTALL_USER" "$USER_HOME/.config"
    fi
    
    log_info "Permissions set ✓"
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "  ZiggySpiderWeb Installation Complete!"
    echo "=========================================="
    echo ""
    echo "Service:     $SERVICE_NAME"
    echo "User:        $INSTALL_USER"
    echo "Install:     $INSTALL_DIR"
    echo "Config:      $CONFIG_DIR/config.json"
    echo "Logs:        /var/log/spiderweb/"
    echo "Data:        /var/lib/spiderweb/"
    echo "Port:        $PORT"
    echo "Bind:        $BIND_ADDR"
    echo ""
    echo "Commands:"
    echo "  Start:     sudo systemctl start $SERVICE_NAME"
    echo "  Stop:      sudo systemctl stop $SERVICE_NAME"
    echo "  Status:    sudo systemctl status $SERVICE_NAME"
    echo "  Logs:      sudo journalctl -u $SERVICE_NAME -f"
    echo "  Config:    sudo spiderweb-config config"
    echo ""
    echo "Don't forget to set your API key:"
    echo "  export OPENAI_API_KEY='your-key-here'"
    echo "  # Or use spiderweb-config set-key"
    echo ""
}

main() {
    echo "========================================"
    echo "  ZiggySpiderWeb SystemD Installer"
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

# Allow sourcing for testing, or run main
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
