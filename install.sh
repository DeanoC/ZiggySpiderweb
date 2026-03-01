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
# Pin installer repo refs (for testing non-main branches):
#   curl .../install.sh | SPIDERWEB_GIT_REF=feat/foo ZSS_GIT_REF=feat/bar bash

set -euo pipefail

# Error handler
cleanup_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        echo "[ERROR] Installation failed (exit code: $exit_code)"
        echo ""
        echo "Try running with --non-interactive or install dependencies:"
        echo "  sudo apt-get install curl jq git bubblewrap fuse3 libsecret-tools sqlite3 build-essential"
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

ensure_git_repo() {
    local dir="$1"
    local url="$2"
    local ref="${3:-}"
    local name
    name="$(basename "$dir")"

    if [[ -d "$dir/.git" ]]; then
        log_info "Updating ${name}${ref:+ (ref: ${ref})}..."
        git -C "$dir" remote set-url origin "$url" >/dev/null 2>&1 || true
        if [[ -n "$ref" ]]; then
            git -C "$dir" fetch -q origin || log_warn "Failed to fetch ${name}; using existing checkout"
            if git -C "$dir" rev-parse --verify --quiet "refs/remotes/origin/${ref}" >/dev/null; then
                if git -C "$dir" rev-parse --verify --quiet "$ref" >/dev/null; then
                    git -C "$dir" checkout -q "$ref" || log_warn "Failed to checkout ${name} ref ${ref}; using current branch"
                else
                    git -C "$dir" checkout -q -B "$ref" "origin/$ref" || log_warn "Failed to create local branch ${ref} for ${name}; using current branch"
                fi
                git -C "$dir" pull -q --ff-only origin "$ref" || log_warn "Failed to fast-forward ${name} ref ${ref}; using current checkout"
            else
                git -C "$dir" checkout -q "$ref" || log_warn "Ref ${ref} not found on origin for ${name}; using current checkout"
            fi
        else
            git -C "$dir" pull -q || log_warn "Failed to update ${name}; using existing checkout"
        fi
    elif [[ -d "$dir" ]]; then
        log_warn "${name} exists but is not a git repo: $dir"
        log_warn "Skipping clone and using existing directory"
    else
        log_info "Cloning ${name}${ref:+ (ref: ${ref})}..."
        if [[ -n "$ref" ]]; then
            if ! git clone -q --branch "$ref" "$url" "$dir"; then
                log_warn "Clone with ref ${ref} failed for ${name}; falling back to default branch"
                git clone -q "$url" "$dir"
            fi
        else
            git clone -q "$url" "$dir"
        fi
    fi
}

print_auth_tokens_summary() {
    local config_cmd="${INSTALL_DIR}/spiderweb-config"
    local has_auth_cli=false
    if [[ ! -x "$config_cmd" ]]; then
        config_cmd="$(command -v spiderweb-config || true)"
    fi
    if [[ -n "$config_cmd" ]]; then
        if "$config_cmd" auth path >/dev/null 2>&1; then
            has_auth_cli=true
        fi
    fi

    local -a candidates=()
    collect_auth_token_candidates "$config_cmd" candidates

    local token_file
    token_file="$(resolve_auth_tokens_file "$config_cmd")"

    if [[ -n "$token_file" ]]; then
        local admin_token
        local user_token
        admin_token="$(jq -r '.admin_token // empty' "$token_file" 2>/dev/null || true)"
        user_token="$(jq -r '.user_token // empty' "$token_file" 2>/dev/null || true)"
        if [[ -n "$admin_token" && -n "$user_token" ]]; then
            echo ""
            log_success "Auth tokens (save these now):"
            echo "  admin: $admin_token"
            echo "  user:  $user_token"
            echo "  path:  $token_file"
            return
        fi
    fi

    echo ""
    log_warn "Could not locate generated auth tokens."
    echo "Checked:"
    for candidate in "${candidates[@]}"; do
        echo "  - $candidate"
    done
    if [[ -n "$config_cmd" ]] && [[ "$has_auth_cli" == "true" ]]; then
        echo "If needed, generate new tokens with:"
        echo "  $config_cmd auth reset --yes"
        echo "Then restart spiderweb so new tokens are active."
    elif [[ -n "$config_cmd" ]]; then
        echo "Token reset command is unavailable in this spiderweb-config build."
        echo "Update spiderweb and rerun install.sh to get auth token management commands."
    else
        echo "Could not locate spiderweb-config in PATH or ${INSTALL_DIR}."
    fi
}

collect_auth_token_candidates() {
    local config_cmd="${1:-}"
    local -n out_ref="$2"
    out_ref=()
    out_ref+=("${REPO_DIR}/.spiderweb-ltm/auth_tokens.json")

    local config_file="${HOME}/.config/spiderweb/config.json"
    if [[ -f "$config_file" ]]; then
        local ltm_dir
        ltm_dir="$(jq -r '.runtime.ltm_directory // empty' "$config_file" 2>/dev/null || true)"
        if [[ -n "$ltm_dir" ]]; then
            if [[ "$ltm_dir" == /* ]]; then
                out_ref+=("${ltm_dir}/auth_tokens.json")
            else
                out_ref+=("${REPO_DIR}/${ltm_dir#./}/auth_tokens.json")
            fi
        fi
    fi

    if [[ -n "$config_cmd" ]]; then
        local raw_auth_path
        raw_auth_path=""
        if raw_auth_path="$("$config_cmd" auth path 2>/dev/null | tr -d '\r' | tail -n1)"; then
            :
        fi
        if [[ -n "$raw_auth_path" ]]; then
            if [[ "$raw_auth_path" == /* ]]; then
                out_ref+=("$raw_auth_path")
            else
                out_ref+=("${REPO_DIR}/${raw_auth_path#./}")
            fi
        fi
    fi
}

resolve_auth_tokens_file() {
    local config_cmd="${1:-}"
    local attempts="${2:-100}"
    local poll_interval="${3:-0.2}"
    local -a candidates=()
    collect_auth_token_candidates "$config_cmd" candidates

    local token_file=""
    for _ in $(seq 1 "$attempts"); do
        for candidate in "${candidates[@]}"; do
            if [[ -f "$candidate" ]]; then
                token_file="$candidate"
                break 2
            fi
        done
        sleep "$poll_interval"
    done
    echo "$token_file"
}

sync_zss_auth_tokens() {
    local config_cmd="${INSTALL_DIR}/spiderweb-config"
    if [[ ! -x "$config_cmd" ]]; then
        config_cmd="$(command -v spiderweb-config || true)"
    fi

    local token_file
    token_file="$(resolve_auth_tokens_file "$config_cmd" 5 0.2)"
    if [[ -z "$token_file" ]]; then
        log_warn "Skipping zss auth sync: spiderweb auth token file not found yet."
        return 0
    fi

    local admin_token
    local user_token
    admin_token="$(jq -r '.admin_token // empty' "$token_file" 2>/dev/null || true)"
    user_token="$(jq -r '.user_token // empty' "$token_file" 2>/dev/null || true)"
    if [[ -z "$admin_token" || -z "$user_token" ]]; then
        log_warn "Skipping zss auth sync: auth token file is missing admin/user tokens."
        return 0
    fi

    local zss_config_dir="${HOME}/.config/zss"
    local zss_config_file="${zss_config_dir}/config.json"
    mkdir -p "$zss_config_dir"

    local tmp_file
    tmp_file="$(mktemp)"
    if [[ -f "$zss_config_file" ]] && jq empty "$zss_config_file" >/dev/null 2>&1; then
        if jq \
            --arg admin "$admin_token" \
            --arg user "$user_token" \
            '.admin_token = $admin
             | .user_token = $user
             | .active_role = (.active_role // "admin")
             | .server_url = (.server_url // "ws://127.0.0.1:18790")' \
            "$zss_config_file" > "$tmp_file"; then
            mv "$tmp_file" "$zss_config_file"
            chmod 600 "$zss_config_file" 2>/dev/null || true
            log_success "Synced zss auth tokens from spiderweb auth store"
            return 0
        fi
    fi

    if ! jq -n \
        --arg admin "$admin_token" \
        --arg user "$user_token" \
        --arg server "ws://127.0.0.1:18790" \
        '{ server_url: $server, admin_token: $admin, user_token: $user, active_role: "admin" }' > "$tmp_file"; then
        rm -f "$tmp_file"
        log_warn "Failed to write zss auth config."
        return 0
    fi
    mv "$tmp_file" "$zss_config_file"
    chmod 600 "$zss_config_file" 2>/dev/null || true
    log_success "Initialized zss config with current spiderweb auth tokens"
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

has_fuse3_runtime() {
    if command -v ldconfig >/dev/null 2>&1; then
        if ldconfig -p 2>/dev/null | grep -qE 'libfuse3\.so(\.(4|3))?'; then
            return 0
        fi
    fi
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -s libfuse3-4 >/dev/null 2>&1 || dpkg -s libfuse3-3 >/dev/null 2>&1 || dpkg -s libfuse3-dev >/dev/null 2>&1; then
            return 0
        fi
    fi
    local candidates=(
        "/lib*/libfuse3.so.4"
        "/usr/lib*/libfuse3.so.4"
        "/lib/*/libfuse3.so.4"
        "/usr/lib/*/libfuse3.so.4"
        "/lib*/libfuse3.so.3"
        "/usr/lib*/libfuse3.so.3"
        "/lib/*/libfuse3.so.3"
        "/usr/lib/*/libfuse3.so.3"
        "/lib*/libfuse3.so"
        "/usr/lib*/libfuse3.so"
        "/lib/*/libfuse3.so"
        "/usr/lib/*/libfuse3.so"
    )
    local pattern
    for pattern in "${candidates[@]}"; do
        if compgen -G "$pattern" > /dev/null; then
            return 0
        fi
    done
    return 1
}

append_apt_dep() {
    local dep="$1"
    local existing
    for existing in "${APT_DEPS[@]}"; do
        if [[ "$existing" == "$dep" ]]; then
            return 0
        fi
    done
    APT_DEPS+=("$dep")
}

add_first_available_pkg() {
    local dep_name="$1"
    shift
    local pkg
    for pkg in "$@"; do
        if apt-cache show "$pkg" >/dev/null 2>&1; then
            append_apt_dep "$pkg"
            return 0
        fi
    done
    log_warn "No apt package found for ${dep_name}; install it manually if missing."
    return 1
}

DEPS_MISSING=()
NEEDS_APT_INSTALL=false
APT_DEPS=(libsecret-tools sqlite3 build-essential)

for cmd in curl jq git; do
    if ! command -v "$cmd" &> /dev/null; then
        DEPS_MISSING+=("$cmd")
        NEEDS_APT_INSTALL=true
        append_apt_dep "$cmd"
    fi
done

if ! command -v zig &> /dev/null; then
    DEPS_MISSING+=("zig")
fi

if ! command -v bwrap &> /dev/null; then
    DEPS_MISSING+=("bwrap")
    NEEDS_APT_INSTALL=true
    add_first_available_pkg "bwrap" bubblewrap || true
fi

if ! command -v fusermount3 &> /dev/null; then
    DEPS_MISSING+=("fusermount3")
    NEEDS_APT_INSTALL=true
    add_first_available_pkg "fusermount3" fuse3 || true
fi

if ! has_fuse3_runtime; then
    DEPS_MISSING+=("libfuse3.so.3/libfuse3.so.4")
    NEEDS_APT_INSTALL=true
    add_first_available_pkg "libfuse3 runtime" libfuse3-4 libfuse3-3 fuse3 libfuse3-dev || true
fi

if [[ "$NEEDS_APT_INSTALL" == "true" ]]; then
    log_info "Installing dependencies: ${APT_DEPS[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y -qq "${APT_DEPS[@]}"
fi

if ! command -v zig &> /dev/null; then
    echo "Error: zig compiler is required but was not found in PATH."
    echo "Install zig and rerun install.sh."
    exit 1
fi

POST_MISSING=()
for cmd in curl jq git bwrap fusermount3; do
    if ! command -v "$cmd" &> /dev/null; then
        POST_MISSING+=("$cmd")
    fi
done
if ! has_fuse3_runtime; then
    POST_MISSING+=("libfuse3.so.3/libfuse3.so.4")
fi
if [[ ${#POST_MISSING[@]} -gt 0 ]]; then
    echo "Error: missing required dependencies: ${POST_MISSING[*]}"
    echo "Install them and rerun install.sh."
    exit 1
fi

# Clone and build
REPO_DIR="${HOME}/.local/share/ziggy-spiderweb"
INSTALL_DIR="${HOME}/.local/bin"
export PATH="${INSTALL_DIR}:${PATH}"
SPIDERWEB_REPO_URL="${SPIDERWEB_REPO_URL:-https://github.com/DeanoC/ZiggySpiderweb.git}"
SPIDERWEB_GIT_REF="${SPIDERWEB_GIT_REF:-main}"
ZSS_REPO_URL="${ZSS_REPO_URL:-https://github.com/DeanoC/ZiggyStarSpider.git}"
ZSS_GIT_REF="${ZSS_GIT_REF:-main}"

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

mkdir -p "$(dirname "$REPO_DIR")"
ensure_git_repo "$REPO_DIR" "$SPIDERWEB_REPO_URL" "$SPIDERWEB_GIT_REF"

REPO_BASE_DIR="$(dirname "$REPO_DIR")"
log_info "Ensuring local Ziggy module dependencies..."
ensure_git_repo "${REPO_BASE_DIR}/ZiggyPiAi" "https://github.com/DeanoC/ZiggyPiAi.git"
ensure_git_repo "${REPO_BASE_DIR}/ZiggySpiderProtocol" "https://github.com/DeanoC/ZiggySpiderProtocol.git"
ensure_git_repo "${REPO_BASE_DIR}/ZiggyMemoryStore" "https://github.com/DeanoC/ZiggyMemoryStore.git"
ensure_git_repo "${REPO_BASE_DIR}/ZiggyToolRuntime" "https://github.com/DeanoC/ZiggyToolRuntime.git"
ensure_git_repo "${REPO_BASE_DIR}/ZiggyRuntimeHooks" "https://github.com/DeanoC/ZiggyRuntimeHooks.git"
ensure_git_repo "${REPO_BASE_DIR}/ZiggyRunOrchestrator" "https://github.com/DeanoC/ZiggyRunOrchestrator.git"

cd "$REPO_DIR"

log_info "Building ZiggySpiderweb..."
zig build -Doptimize=ReleaseSafe

log_info "Installing binaries..."
mkdir -p "$INSTALL_DIR"

SPIDERWEB_BINARIES=(spiderweb spiderweb-config spiderweb-control spiderweb-fs-mount spiderweb-agent-runtime)
for bin in "${SPIDERWEB_BINARIES[@]}"; do
    if [[ ! -x "zig-out/bin/${bin}" ]]; then
        echo "Error: expected build artifact missing: zig-out/bin/${bin}"
        exit 1
    fi
done

# Copy binaries (spiderweb should be stopped by now)
copy_without_sudo=true
for bin in "${SPIDERWEB_BINARIES[@]}"; do
    if ! cp "zig-out/bin/${bin}" "$INSTALL_DIR/" 2>/dev/null; then
        copy_without_sudo=false
        break
    fi
done
if [[ "$copy_without_sudo" != "true" ]]; then
    log_info "Need elevated permissions to update binary..."
    for bin in "${SPIDERWEB_BINARIES[@]}"; do
        sudo cp "zig-out/bin/${bin}" "$INSTALL_DIR/"
    done
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

    mkdir -p "$(dirname "$ZSS_REPO")"
    ensure_git_repo "$ZSS_REPO" "$ZSS_REPO_URL" "$ZSS_GIT_REF"
    cd "$ZSS_REPO"
    
    log_info "Building ZiggyStarSpider CLI..."
    zig build cli -Doptimize=ReleaseSafe -Dtarget=native
    
    log_info "Building ZiggyStarSpider TUI..."
    zig build tui -Doptimize=ReleaseSafe -Dtarget=native
    
    log_info "Installing zss binaries..."
    cp zig-out/bin/zss "$INSTALL_DIR/" 2>/dev/null || true
    cp zig-out/bin/zss-tui "$INSTALL_DIR/" 2>/dev/null || true
    
    log_success "ZiggyStarSpider installed!"
fi

# Ensure remaining install steps run from the spiderweb repo.
cd "$REPO_DIR"

# Ensure Mother system agent scaffold exists.
log_info "Ensuring Mother system agent scaffold..."
mkdir -p "$REPO_DIR/agents/mother"
if [[ ! -f "$REPO_DIR/agents/mother/agent.json" ]]; then
cat > "$REPO_DIR/agents/mother/agent.json" <<'EOF'
{
  "name": "Mother",
  "description": "System orchestration and bootstrap guardian",
  "is_default": true,
  "capabilities": ["chat","plan","code","research"]
}
EOF
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
WorkingDirectory=$REPO_DIR
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
WorkingDirectory=$REPO_DIR
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
    log_info "Run 'spiderweb-config first-run' manually to configure provider/auth"
else
    # Clear any leftover input before running first-run
    while IFS= read -r -t 0.1 dummy 2>/dev/null; do : ; done
    "${INSTALL_DIR}/spiderweb-config" first-run
fi

# Only configure bind address in interactive mode (when we asked the user)
if [[ -t 0 ]]; then
    log_info "Configuring bind address (${BIND_ADDRESS})..."
    
    # Get current port from config - spiderweb-config outputs "Bind: <host>:<port>"
    # Extract port from format like "Bind: 127.0.0.1:18790"
    DETECTED_PORT=$("${INSTALL_DIR}/spiderweb-config" config 2>/dev/null | grep -oP 'Bind: [^:]+:\K\d+' || echo "18790")
    if [[ -n "$DETECTED_PORT" ]]; then
        CURRENT_PORT="$DETECTED_PORT"
    fi
    
    "${INSTALL_DIR}/spiderweb-config" config set-server --bind "$BIND_ADDRESS" --port "$CURRENT_PORT"
    
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
            "${INSTALL_DIR}/spiderweb" &
        fi
    fi
fi

# Post-install summary
echo ""
log_success "Installation complete!"
echo ""
echo "Binaries installed to:"
for bin in "${SPIDERWEB_BINARIES[@]}"; do
    echo "  $INSTALL_DIR/${bin}"
done
if [[ "$INSTALL_ZSS" == "true" ]]; then
    echo "  $INSTALL_DIR/zss"
    echo "  $INSTALL_DIR/zss-tui"
fi
echo ""

ACTIVE_CONFIG_CMD="$(command -v spiderweb-config || true)"
if [[ -n "$ACTIVE_CONFIG_CMD" ]] && [[ "$ACTIVE_CONFIG_CMD" != "${INSTALL_DIR}/spiderweb-config" ]]; then
    echo ""
    log_warn "Another spiderweb-config is earlier in PATH: $ACTIVE_CONFIG_CMD"
    echo "Use the latest build at:"
    echo "  ${INSTALL_DIR}/spiderweb-config"
    echo "Then update PATH to prefer ${INSTALL_DIR} and run: hash -r"
fi

if [[ "$INSTALL_SYSTEMD" == "true" ]]; then
    echo "Systemd service installed and started ($SYSTEMD_SCOPE scope)"
elif [[ "$SYSTEMD_EXISTS" == "true" ]]; then
    echo "Systemd service already exists ($EXISTING_SCOPE scope)"
else
    echo "To install systemd service later:"
    echo "  spiderweb-config config install-service"
fi

SYNC_ZSS_AUTH=false
if [[ "$INSTALL_ZSS" == "true" ]]; then
    SYNC_ZSS_AUTH=true
elif [[ -x "${INSTALL_DIR}/zss" ]] || command -v zss >/dev/null 2>&1 || [[ -f "${HOME}/.config/zss/config.json" ]]; then
    SYNC_ZSS_AUTH=true
fi
if [[ "$SYNC_ZSS_AUTH" == "true" ]]; then
    sync_zss_auth_tokens
fi

print_auth_tokens_summary

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
