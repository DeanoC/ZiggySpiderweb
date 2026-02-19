#!/bin/bash
# ZiggySpiderweb Install Script
#
# RECOMMENDED (interactive):
#   curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh -o /tmp/install.sh
#   bash /tmp/install.sh
#
# PIPED (non-interactive, uses defaults):
#   curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh | bash
#
# NON-INTERACTIVE with options:
#   curl ... | SPIDERWEB_PROVIDER=openai-codex SPIDERWEB_AGENT=ziggy bash

set -euo pipefail

# Error handler
cleanup_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        echo "[ERROR] Installation failed (exit code: $exit_code)"
        echo ""
        echo "Try running with --non-interactive or install dependencies:"
        echo "  sudo apt-get install curl jq git libsecret-tools sqlite3 build-essential"
        echo ""
    fi
    exit $exit_code
}
trap 'cleanup_on_error' ERR

# Colors
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# Detect if we're being piped
if [[ ! -t 0 ]]; then
    echo ""
    log_warn "Running via pipe (curl | bash)"
    echo ""
    echo "For interactive setup, use:"
    echo "  curl -fsSL .../install.sh -o /tmp/install.sh"
    echo "  bash /tmp/install.sh"
    echo ""
    echo "Using non-interactive mode with defaults..."
    echo ""
    export SPIDERWEB_NON_INTERACTIVE=1
fi

# Check OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This installer only supports Linux"
    exit 1
fi

# Check dependencies
log_info "Checking dependencies..."

DEPS_MISSING=()
for cmd in curl jq git; do
    if ! command -v "$cmd" &> /dev/null; then
        DEPS_MISSING+=("$cmd")
    fi
done

if ! command -v zig &> /dev/null; then
    DEPS_MISSING+=("zig")
fi

if [[ ${#DEPS_MISSING[@]} -gt 0 ]]; then
    log_info "Installing dependencies: ${DEPS_MISSING[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y -qq curl jq git libsecret-tools sqlite3 build-essential
fi

# Clone and build
REPO_DIR="${HOME}/.local/share/ziggy-spiderweb"
INSTALL_DIR="${HOME}/.local/bin"

# Check if spiderweb is running and offer to stop it first
SPIDERWEB_RUNNING=false
if pgrep spiderweb > /dev/null 2>&1; then
    SPIDERWEB_RUNNING=true
    if [[ -t 0 ]]; then
        echo ""
        read -rp "Spiderweb is currently running. Stop it to allow update? [Y/n]: " stop_confirm
        if [[ ! "$stop_confirm" =~ ^[Nn]$ ]] || [[ -z "$stop_confirm" ]]; then
            log_info "Stopping spiderweb..."
            # Try graceful stop first
            if systemctl --user is-active spiderweb >/dev/null 2>&1; then
                systemctl --user stop spiderweb || true
            elif sudo systemctl is-active spiderweb >/dev/null 2>&1; then
                sudo systemctl stop spiderweb || true
            fi
            # Kill any remaining processes
            pkill spiderweb 2>/dev/null || sudo pkill spiderweb 2>/dev/null || true
            sleep 2
            pkill -9 spiderweb 2>/dev/null || sudo pkill -9 spiderweb 2>/dev/null || true
            sleep 1
        fi
    fi
fi

if [[ -d "$REPO_DIR" ]]; then
    if [[ -t 0 ]]; then
        # Interactive - ask user
        echo ""
        read -rp "Remove existing install and re-clone? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "$REPO_DIR"
        fi
    else
        # Non-interactive - just use existing
        log_info "Using existing installation at ${REPO_DIR}"
    fi
fi

if [[ ! -d "$REPO_DIR" ]]; then
    log_info "Cloning ZiggySpiderweb..."
    mkdir -p "$(dirname "$REPO_DIR")"
    git clone -q https://github.com/DeanoC/ZiggySpiderweb.git "$REPO_DIR"
fi

cd "$REPO_DIR"

log_info "Building ZiggySpiderweb..."
zig build -Doptimize=ReleaseSafe

log_info "Installing binaries..."
mkdir -p "$INSTALL_DIR"

# Copy binaries (spiderweb should be stopped by now)
if ! cp zig-out/bin/spiderweb "$INSTALL_DIR/" 2>/dev/null; then
    log_info "Need elevated permissions to update binary..."
    sudo cp zig-out/bin/spiderweb "$INSTALL_DIR/"
    sudo cp zig-out/bin/spiderweb-config "$INSTALL_DIR/"
else
    cp zig-out/bin/spiderweb "$INSTALL_DIR/"
    cp zig-out/bin/spiderweb-config "$INSTALL_DIR/"
fi

log_success "Build complete!"

# Ask about installing ZiggyStarSpider client
INSTALL_ZSS=false
if [[ -t 0 ]]; then
    echo ""
    read -rp "Also install ZiggyStarSpider client (zss)? [Y/n]: " zss_confirm
    if [[ ! "$zss_confirm" =~ ^[Nn]$ ]] || [[ -z "$zss_confirm" ]]; then
        INSTALL_ZSS=true
    fi
fi

if [[ "$INSTALL_ZSS" == "true" ]]; then
    ZSS_REPO="${HOME}/.local/share/ziggy-starspider"
    
    if [[ -d "$ZSS_REPO" ]]; then
        log_info "ZiggyStarSpider already exists, updating..."
        cd "$ZSS_REPO"
        git pull -q
    else
        log_info "Cloning ZiggyStarSpider..."
        mkdir -p "$(dirname "$ZSS_REPO")"
        git clone -q https://github.com/DeanoC/ZiggyStarSpider.git "$ZSS_REPO"
        cd "$ZSS_REPO"
    fi
    
    log_info "Building ZiggyStarSpider CLI..."
    zig build cli -Doptimize=ReleaseSafe -Dtarget=native
    
    log_info "Building ZiggyStarSpider TUI..."
    zig build tui -Doptimize=ReleaseSafe -Dtarget=native
    
    log_info "Installing zss binaries..."
    cp zig-out/bin/zss "$INSTALL_DIR/" 2>/dev/null || true
    cp zig-out/bin/zss-tui "$INSTALL_DIR/" 2>/dev/null || true
    
    log_success "ZiggyStarSpider installed!"
    
    log_success "ZiggyStarSpider installed!"
fi

# Ask about systemd service
INSTALL_SYSTEMD=false
SYSTEMD_SCOPE="user"

# Check for existing systemd services
SYSTEMD_EXISTS=false
EXISTING_SCOPE=""
if [[ -f /etc/systemd/system/spiderweb.service ]]; then
    SYSTEMD_EXISTS=true
    EXISTING_SCOPE="system"
elif [[ -f "$HOME/.config/systemd/user/spiderweb.service" ]]; then
    SYSTEMD_EXISTS=true
    EXISTING_SCOPE="user"
fi

if [[ "$SYSTEMD_EXISTS" == "true" ]]; then
    log_info "Systemd service already exists ($EXISTING_SCOPE scope)"
    INSTALL_SYSTEMD=false
elif [[ -t 0 ]]; then
    echo ""
    read -rp "Install systemd service? [Y/n]: " systemd_confirm
    if [[ ! "$systemd_confirm" =~ ^[Nn]$ ]] || [[ -z "$systemd_confirm" ]]; then
        INSTALL_SYSTEMD=true
        echo ""
        read -rp "User or system service? [user/system]: " scope_choice
        if [[ "$scope_choice" =~ ^[Ss]ystem$ ]]; then
            SYSTEMD_SCOPE="system"
        fi
    fi
fi

if [[ "$INSTALL_SYSTEMD" == "true" ]]; then
    log_info "Installing systemd service..."
    
    # Get current user for system service
    CURRENT_USER=$(whoami)
    
    # Create service file content
    if [[ "$SYSTEMD_SCOPE" == "system" ]]; then
        SERVICE_FILE="[Unit]
Description=ZiggySpiderweb AI Agent Gateway
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
ExecStart=$INSTALL_DIR/spiderweb
WorkingDirectory=%h
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target"
        
        echo "$SERVICE_FILE" | sudo tee /etc/systemd/system/spiderweb.service > /dev/null
        sudo systemctl daemon-reload
        sudo systemctl enable --now spiderweb
        log_success "System service installed and started"
    else
        SERVICE_FILE="[Unit]
Description=ZiggySpiderweb AI Agent Gateway
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/spiderweb
WorkingDirectory=%h
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target"
        
        mkdir -p "$HOME/.config/systemd/user"
        echo "$SERVICE_FILE" > "$HOME/.config/systemd/user/spiderweb.service"
        systemctl --user daemon-reload
        systemctl --user enable --now spiderweb
        log_success "User service installed and started"
    fi
fi

# Ask about remote access
BIND_ADDRESS="127.0.0.1"
CURRENT_PORT="18790"
if [[ -t 0 ]]; then
    echo ""
    read -rp "Allow remote connections (Tailscale/VPN)? [y/N]: " remote_confirm
    if [[ "$remote_confirm" =~ ^[Yy]$ ]]; then
        BIND_ADDRESS="0.0.0.0"
        log_info "Server will bind to all interfaces (0.0.0.0)"
    else
        log_info "Server will bind to localhost only (127.0.0.1)"
    fi
fi

# Run first-run wizard
echo ""
log_info "Starting first-time setup..."
echo ""

if [[ -n "${SPIDERWEB_NON_INTERACTIVE:-}" ]]; then
    # Non-interactive mode - skip first-run, user should run manually
    log_info "Skipping interactive first-time setup (non-interactive mode)"
    log_info "Run 'spiderweb-config first-run' manually to configure your agent"
else
    # Clear any leftover input before running first-run
    while IFS= read -r -t 0.1 dummy 2>/dev/null; do : ; done
    spiderweb-config first-run
fi

# Only configure bind address in interactive mode (when we asked the user)
if [[ -t 0 ]]; then
    log_info "Configuring bind address (${BIND_ADDRESS})..."
    
    # Get current port from config - spiderweb-config outputs "Bind: <host>:<port>"
    # Extract port from format like "Bind: 127.0.0.1:18790"
    DETECTED_PORT=$(spiderweb-config config 2>/dev/null | grep -oP 'Bind: [^:]+:\K\d+' || echo "18790")
    if [[ -n "$DETECTED_PORT" ]]; then
        CURRENT_PORT="$DETECTED_PORT"
    fi
    
    spiderweb-config config set-server --bind "$BIND_ADDRESS" --port "$CURRENT_PORT"
    
    # Restart service if running to apply new bind address
    if [[ "$INSTALL_SYSTEMD" == "true" ]] || [[ "$SYSTEMD_EXISTS" == "true" ]]; then
        if systemctl --user is-active spiderweb >/dev/null 2>&1 || sudo systemctl is-active spiderweb >/dev/null 2>&1; then
            log_info "Restarting service with new bind address..."
            if [[ "$SYSTEMD_SCOPE" == "system" ]] || [[ "$EXISTING_SCOPE" == "system" ]]; then
                sudo systemctl restart spiderweb 2>/dev/null || true
            else
                systemctl --user restart spiderweb 2>/dev/null || true
            fi
        fi
    else
        # No systemd - check if spiderweb is running directly and restart it
        if pgrep -x spiderweb > /dev/null 2>&1; then
            log_info "Restarting spiderweb with new bind address..."
            pkill -x spiderweb 2>/dev/null || true
            sleep 1
            # spiderweb-config first-run will have started it, or user can start manually
            spiderweb &
        fi
    fi
fi

# Post-install summary
echo ""
log_success "Installation complete!"
echo ""
echo "Binaries installed to:"
echo "  $INSTALL_DIR/spiderweb"
echo "  $INSTALL_DIR/spiderweb-config"
if [[ "$INSTALL_ZSS" == "true" ]]; then
    echo "  $INSTALL_DIR/zss"
    echo "  $INSTALL_DIR/zss-tui"
fi
echo ""

if [[ "$INSTALL_SYSTEMD" == "true" ]]; then
    echo "Systemd service installed and started ($SYSTEMD_SCOPE scope)"
elif [[ "$SYSTEMD_EXISTS" == "true" ]]; then
    echo "Systemd service already exists ($EXISTING_SCOPE scope)"
else
    echo "To install systemd service later:"
    echo "  spiderweb-config config install-service"
fi

echo ""
if [[ "$INSTALL_ZSS" == "true" ]]; then
    echo "Connect to your agent:"
    echo "  Local:  zss connect"
    # Only show remote URL if remote access is enabled
    if [[ -t 0 ]] && [[ "$BIND_ADDRESS" == "0.0.0.0" ]]; then
        echo "  Remote: zss connect --url ws://<host-ip>:${CURRENT_PORT}"
    fi
else
    echo "To connect to your agent, install ZiggyStarSpider:"
    echo "  https://github.com/DeanoC/ZiggyStarSpider"
fi
