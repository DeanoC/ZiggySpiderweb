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
PROVIDER_NAME="${PROVIDER_NAME:-}"
PROVIDER_MODEL="${PROVIDER_MODEL:-}"
SPIDER_WEB_ROOT="${SPIDER_WEB_ROOT:-/}"
OVERWRITE_CONFIG="${OVERWRITE_CONFIG:-0}"
SERVICE_ENV_FILE="${SERVICE_ENV_FILE:-$CONFIG_DIR/service.env}"

SERVICE_USER_HOME=""
CREDENTIAL_STATUS="not configured"

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

require_provider_selection() {
    local config_file="$CONFIG_DIR/config.json"

    # When preserving an existing config, provider/model should come from that file.
    if [ -f "$config_file" ] && [ "$OVERWRITE_CONFIG" != "1" ]; then
        if command -v jq &> /dev/null; then
            detected_provider="$(jq -r '.provider.name // empty' "$config_file" 2>/dev/null || true)"
            detected_model="$(jq -r '.provider.model // empty' "$config_file" 2>/dev/null || true)"
            if [ -n "$detected_provider" ] && [ -n "$detected_model" ]; then
                if [ -n "$PROVIDER_NAME" ] || [ -n "$PROVIDER_MODEL" ]; then
                    log_warn "Preserving existing config at $config_file; ignoring PROVIDER_NAME/PROVIDER_MODEL overrides"
                fi
                PROVIDER_NAME="$detected_provider"
                PROVIDER_MODEL="$detected_model"
                log_info "Using provider from existing config: $PROVIDER_NAME/$PROVIDER_MODEL"
                return 0
            fi
        fi

        # Existing config path but provider data unavailable/parsing failed.
        if [ -z "$PROVIDER_NAME" ] || [ -z "$PROVIDER_MODEL" ]; then
            log_error "Provider is not configured in $config_file and no explicit values were provided."
            log_error "Set PROVIDER_NAME and PROVIDER_MODEL, or install jq so the script can read config values."
            log_info "Example:"
            log_info "  sudo PROVIDER_NAME=openai-codex PROVIDER_MODEL=gpt-5.3-codex ./scripts/install-systemd.sh"
            exit 1
        fi
        return 0
    fi

    # New config or overwrite: require explicit provider/model.
    if [ -z "$PROVIDER_NAME" ] || [ -z "$PROVIDER_MODEL" ]; then
        log_error "Missing required provider configuration."
        log_error "Set both PROVIDER_NAME and PROVIDER_MODEL."
        log_info "Examples:"
        log_info "  sudo PROVIDER_NAME=openai-codex PROVIDER_MODEL=gpt-5.3-codex ./scripts/install-systemd.sh"
        log_info "  sudo PROVIDER_NAME=openai PROVIDER_MODEL=gpt-4.1 ./scripts/install-systemd.sh"
        exit 1
    fi
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
    SERVICE_USER_HOME=$(getent passwd "$INSTALL_USER" | cut -d: -f6)
    if [ -n "$SERVICE_USER_HOME" ] && [ "$SERVICE_USER_HOME" != "/" ]; then
        mkdir -p "$SERVICE_USER_HOME/.config/spiderweb"
        mkdir -p "$SERVICE_USER_HOME/.pi/agent"
        mkdir -p "$SERVICE_USER_HOME/.codex"
        chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME"
        chmod 700 "$SERVICE_USER_HOME"
    else
        log_error "Could not determine home directory for user '$INSTALL_USER'"
        exit 1
    fi
}

install_files() {
    log_info "Installing files to $INSTALL_DIR..."
    
    # Create directories
    mkdir -p "$INSTALL_DIR/bin"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "/var/log/spiderweb"
    mkdir -p "/var/lib/spiderweb"
    mkdir -p "/var/lib/spiderweb/mounts"
    mkdir -p "/var/lib/spiderweb/runtime"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    # Copy binaries
    cp "$PROJECT_DIR/zig-out/bin/spiderweb" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-config" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-agent-runtime" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-fs-mount" "$INSTALL_DIR/bin/"
    cp "$PROJECT_DIR/zig-out/bin/spiderweb-control" "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/"*
    
    # Create symlink in /usr/local/bin
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
    elif [ -f "$CONFIG_FILE" ]; then
        log_warn "Config already exists at $CONFIG_FILE"
        log_info "Backing up to $CONFIG_FILE.bak"
        cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
        # Generate config from explicit provider/model selection
        cat > "$CONFIG_FILE" <<EOF
{
  "server": {
    "bind": "$BIND_ADDR",
    "port": $PORT
  },
  "provider": {
    "name": "$PROVIDER_NAME",
    "model": "$PROVIDER_MODEL"
  },
  "log": {
    "level": "info"
  },
  "runtime": {
    "spider_web_root": "$SPIDER_WEB_ROOT",
    "ltm_directory": "/var/lib/spiderweb/.spiderweb-ltm",
    "ltm_filename": "runtime-memory.db",
    "sandbox_enabled": true,
    "sandbox_mounts_root": "/var/lib/spiderweb/mounts",
    "sandbox_runtime_root": "/var/lib/spiderweb/runtime",
    "sandbox_fs_mount_bin": "$INSTALL_DIR/bin/spiderweb-fs-mount",
    "sandbox_agent_runtime_bin": "$INSTALL_DIR/bin/spiderweb-agent-runtime"
  }
}
EOF
    else
        # Generate config from explicit provider/model selection
        cat > "$CONFIG_FILE" <<EOF
{
  "server": {
    "bind": "$BIND_ADDR",
    "port": $PORT
  },
  "provider": {
    "name": "$PROVIDER_NAME",
    "model": "$PROVIDER_MODEL"
  },
  "log": {
    "level": "info"
  },
  "runtime": {
    "spider_web_root": "$SPIDER_WEB_ROOT",
    "ltm_directory": "/var/lib/spiderweb/.spiderweb-ltm",
    "ltm_filename": "runtime-memory.db",
    "sandbox_enabled": true,
    "sandbox_mounts_root": "/var/lib/spiderweb/mounts",
    "sandbox_runtime_root": "/var/lib/spiderweb/runtime",
    "sandbox_fs_mount_bin": "$INSTALL_DIR/bin/spiderweb-fs-mount",
    "sandbox_agent_runtime_bin": "$INSTALL_DIR/bin/spiderweb-agent-runtime"
  }
}
EOF
    fi
    
    chmod 644 "$CONFIG_FILE"
    
    # Also copy to user's home directory where spiderweb looks for it
    if [ -n "$SERVICE_USER_HOME" ] && [ -d "$SERVICE_USER_HOME" ]; then
        mkdir -p "$SERVICE_USER_HOME/.config/spiderweb"
        cp "$CONFIG_FILE" "$SERVICE_USER_HOME/.config/spiderweb/config.json"
        chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME/.config"
        chmod 755 "$SERVICE_USER_HOME/.config"
        chmod 755 "$SERVICE_USER_HOME/.config/spiderweb"
        chmod 644 "$SERVICE_USER_HOME/.config/spiderweb/config.json"
    fi
    
    # Always derive provider/model from effective config so credential bootstrap matches runtime.
    if command -v jq &> /dev/null; then
        detected_provider="$(jq -r '.provider.name // empty' "$CONFIG_FILE" 2>/dev/null || true)"
        detected_model="$(jq -r '.provider.model // empty' "$CONFIG_FILE" 2>/dev/null || true)"
        if [ -n "$detected_provider" ]; then
            PROVIDER_NAME="$detected_provider"
        fi
        if [ -n "$detected_model" ]; then
            PROVIDER_MODEL="$detected_model"
        fi
    fi

    log_info "Config installed at $CONFIG_FILE"
    log_info "Edit with: spiderweb-config config"
}

configure_service_credentials() {
    log_info "Configuring provider credentials for service account..."

    # Start fresh; this file is optional and loaded via EnvironmentFile=-...
    rm -f "$SERVICE_ENV_FILE"
    install -m 640 -o root -g "$INSTALL_USER" /dev/null "$SERVICE_ENV_FILE"

    if [[ "$PROVIDER_NAME" == openai-codex* ]]; then
        if [ -n "${OPENAI_CODEX_API_KEY:-}" ]; then
            printf 'OPENAI_CODEX_API_KEY=%s\n' "${OPENAI_CODEX_API_KEY}" >> "$SERVICE_ENV_FILE"
            CREDENTIAL_STATUS="service env key: OPENAI_CODEX_API_KEY"
        elif [ -n "${OPENAI_API_KEY:-}" ]; then
            printf 'OPENAI_API_KEY=%s\n' "${OPENAI_API_KEY}" >> "$SERVICE_ENV_FILE"
            CREDENTIAL_STATUS="service env key: OPENAI_API_KEY"
        else
            source_home=""
            if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
                source_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
            fi

            if [ -n "$source_home" ] && [ -f "$source_home/.codex/auth.json" ]; then
                mkdir -p "$SERVICE_USER_HOME/.codex"
                cp "$source_home/.codex/auth.json" "$SERVICE_USER_HOME/.codex/auth.json"
                chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME/.codex"
                chmod 700 "$SERVICE_USER_HOME/.codex"
                chmod 600 "$SERVICE_USER_HOME/.codex/auth.json"
                CREDENTIAL_STATUS="imported Codex OAuth tokens to $SERVICE_USER_HOME/.codex/auth.json"
            else
                if [ -t 0 ]; then
                    log_warn "No Codex credentials found for service user '$INSTALL_USER'."
                    read -r -p "Run OAuth login now for '$INSTALL_USER'? [Y/n]: " oauth_confirm
                    if [ -z "$oauth_confirm" ] || [[ ! "$oauth_confirm" =~ ^[Nn]$ ]]; then
                        mkdir -p "$SERVICE_USER_HOME/.pi/agent"
                        chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME/.pi"
                        chmod 700 "$SERVICE_USER_HOME/.pi"
                        chmod 700 "$SERVICE_USER_HOME/.pi/agent"

                        if command -v runuser &> /dev/null; then
                            if runuser -u "$INSTALL_USER" -- env HOME="$SERVICE_USER_HOME" SPIDERWEB_CONFIG="$CONFIG_DIR/config.json" "$INSTALL_DIR/bin/spiderweb-config" oauth login openai-codex --no-set-provider; then
                                CREDENTIAL_STATUS="completed interactive OAuth login for openai-codex"
                            else
                                CREDENTIAL_STATUS="oauth login failed; set OPENAI_CODEX_API_KEY or provide $SERVICE_USER_HOME/.codex/auth.json"
                            fi
                        elif command -v sudo &> /dev/null; then
                            if sudo -u "$INSTALL_USER" HOME="$SERVICE_USER_HOME" SPIDERWEB_CONFIG="$CONFIG_DIR/config.json" "$INSTALL_DIR/bin/spiderweb-config" oauth login openai-codex --no-set-provider; then
                                CREDENTIAL_STATUS="completed interactive OAuth login for openai-codex"
                            else
                                CREDENTIAL_STATUS="oauth login failed; set OPENAI_CODEX_API_KEY or provide $SERVICE_USER_HOME/.codex/auth.json"
                            fi
                        else
                            CREDENTIAL_STATUS="cannot run oauth login automatically (missing runuser/sudo); set OPENAI_CODEX_API_KEY or provide $SERVICE_USER_HOME/.codex/auth.json"
                        fi
                    else
                        CREDENTIAL_STATUS="missing codex credentials (set OPENAI_CODEX_API_KEY or place $SERVICE_USER_HOME/.codex/auth.json)"
                    fi
                else
                    CREDENTIAL_STATUS="missing codex credentials (set OPENAI_CODEX_API_KEY or place $SERVICE_USER_HOME/.codex/auth.json)"
                fi
            fi
        fi
    elif [ "$PROVIDER_NAME" = "openai" ]; then
        if [ -n "${OPENAI_API_KEY:-}" ]; then
            printf 'OPENAI_API_KEY=%s\n' "${OPENAI_API_KEY}" >> "$SERVICE_ENV_FILE"
            CREDENTIAL_STATUS="service env key: OPENAI_API_KEY"
        else
            CREDENTIAL_STATUS="missing OPENAI_API_KEY"
        fi
    else
        CREDENTIAL_STATUS="provider-specific bootstrap not automated for '$PROVIDER_NAME'"
    fi

    if [ ! -s "$SERVICE_ENV_FILE" ]; then
        rm -f "$SERVICE_ENV_FILE"
    else
        chown root:"$INSTALL_USER" "$SERVICE_ENV_FILE"
        chmod 640 "$SERVICE_ENV_FILE"
    fi
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
Environment="HOME=$SERVICE_USER_HOME"
Environment="RUST_LOG=info"
EnvironmentFile=-$SERVICE_ENV_FILE

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
# FUSE mount helpers (fusermount3) require setuid transitions.
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/spiderweb /var/log/spiderweb $SERVICE_USER_HOME/.config $SERVICE_USER_HOME/.codex $SERVICE_USER_HOME/.pi
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=false
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

    if [ -f "$SERVICE_ENV_FILE" ]; then
        chown root:"$INSTALL_USER" "$SERVICE_ENV_FILE"
        chmod 640 "$SERVICE_ENV_FILE"
    fi
    
    # Set permissions on user's home config
    if [ -n "$SERVICE_USER_HOME" ] && [ -d "$SERVICE_USER_HOME/.config" ]; then
        chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME/.config"
    fi
    if [ -n "$SERVICE_USER_HOME" ] && [ -d "$SERVICE_USER_HOME/.pi" ]; then
        chown -R "$INSTALL_USER:$INSTALL_USER" "$SERVICE_USER_HOME/.pi"
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
    if [ -f "$SERVICE_ENV_FILE" ]; then
        echo "Env file:    $SERVICE_ENV_FILE"
    fi
    echo "Logs:        /var/log/spiderweb/"
    echo "Data:        /var/lib/spiderweb/"
    echo "Port:        $PORT"
    echo "Bind:        $BIND_ADDR"
    echo "Provider:    $PROVIDER_NAME/$PROVIDER_MODEL"
    echo "Credentials: $CREDENTIAL_STATUS"
    echo ""
    echo "Commands:"
    echo "  Start:     sudo systemctl start $SERVICE_NAME"
    echo "  Stop:      sudo systemctl stop $SERVICE_NAME"
    echo "  Status:    sudo systemctl status $SERVICE_NAME"
    echo "  Logs:      sudo journalctl -u $SERVICE_NAME -f"
    echo "  Config:    sudo spiderweb-config config"
    echo ""
    echo "Credential notes:"
    echo "  - For system services, keys must be available to user '$INSTALL_USER'."
    echo "  - Provider/model selection is required for new/overwrite installs (no defaults)."
    echo "  - OpenAI/OpenAI Codex keys can be supplied via environment at install time:"
    echo "      sudo OPENAI_API_KEY=... PROVIDER_NAME=openai PROVIDER_MODEL=gpt-4.1 ./scripts/install-systemd.sh"
    echo "      sudo OPENAI_CODEX_API_KEY=... PROVIDER_NAME=openai-codex PROVIDER_MODEL=gpt-5.3-codex ./scripts/install-systemd.sh"
    echo "  - For Codex OAuth, place auth at: $SERVICE_USER_HOME/.codex/auth.json"
    echo "  - Or run OAuth login as service user:"
    echo "      sudo -u $INSTALL_USER HOME=$SERVICE_USER_HOME SPIDERWEB_CONFIG=$CONFIG_DIR/config.json $INSTALL_DIR/bin/spiderweb-config oauth login openai-codex --no-set-provider"
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
    require_provider_selection
    build_project
    create_user
    install_files
    install_config
    configure_service_credentials
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
