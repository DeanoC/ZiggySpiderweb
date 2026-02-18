#!/bin/bash
# ZiggySpiderweb First Install Script
# Debian/Ubuntu only for now
# Usage: curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh | bash
#
# Non-interactive mode (for CI/testing):
#   SPIDERWEB_PROVIDER=openai \
#   SPIDERWEB_MODEL=gpt-4o-mini \
#   SPIDERWEB_API_KEY=sk-xxx \
#   SPIDERWEB_AGENT_NAME=ziggy \
#   ./install.sh --non-interactive

set -euo pipefail

# Error handler - show friendly message on failure
cleanup_on_error() {
    local exit_code=$?
    local line_no=$1
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        echo -e "${RED}[ERROR]${NC} Installation failed at line $line_no (exit code: $exit_code)"
        echo ""
        echo "Common causes:"
        echo "  • sudo password not entered or incorrect"
        echo "  • Network issue downloading packages"
        echo "  • Missing write permissions"
        echo ""
        echo "Try running with --non-interactive or install dependencies manually:"
        echo "  sudo apt-get install curl jq git libsecret-tools sqlite3 build-essential"
        echo ""
    fi
    exit $exit_code
}
trap 'cleanup_on_error $LINENO' ERR

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SPIDERWEB_VERSION="0.2.0"
INSTALL_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/spiderweb"
LTM_DIR=".spiderweb-ltm"

# Non-interactive mode detection
NON_INTERACTIVE=false
if [[ "${1:-}" == "--non-interactive" ]] || [[ -n "${SPIDERWEB_NON_INTERACTIVE:-}" ]]; then
    NON_INTERACTIVE=true
fi

# Environment overrides
PROVIDER="${SPIDERWEB_PROVIDER:-}"
MODEL="${SPIDERWEB_MODEL:-}"
API_KEY="${SPIDERWEB_API_KEY:-}"
AGENT_NAME="${SPIDERWEB_AGENT_NAME:-ziggy}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    command -v "$1" &> /dev/null
}

print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🕸️  ZiggySpiderweb - First Time Setup                      ║
║                                                               ║
║   Pi AI Agent Gateway                                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_os() {
    log_info "Checking operating system..."
    
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        log_error "This installer only supports Linux (Debian/Ubuntu)."
        log_error "Detected: $OSTYPE"
        exit 1
    fi
    
    if [[ -f /etc/debian_version ]]; then
        log_success "Debian/Ubuntu detected"
    else
        log_warn "Non-Debian system detected. Continuing anyway..."
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local deps_missing=()
    
    # Essential tools
    if ! check_command curl; then
        deps_missing+=("curl")
    fi
    
    if ! check_command jq; then
        deps_missing+=("jq")
    fi
    
    if ! check_command git; then
        deps_missing+=("git")
    fi
    
    # Check for Zig
    if ! check_command zig; then
        deps_missing+=("zig")
        log_warn "Zig not found. Will need to install."
    else
        local zig_version
        zig_version=$(zig version 2>/dev/null || echo "unknown")
        log_success "Zig found: $zig_version"
    fi
    
    # Check for secret-tool (libsecret)
    if ! check_command secret-tool; then
        deps_missing+=("libsecret-tools")
        log_warn "secret-tool not found. Will need to install for secure credential storage."
    else
        log_success "secret-tool found (secure credential storage available)"
    fi
    
    # Check for SQLite3 (runtime dependency)
    if ! check_command sqlite3; then
        deps_missing+=("sqlite3")
        log_warn "sqlite3 not found. Will need to install."
    else
        log_success "sqlite3 found"
    fi
    
    if [[ ${#deps_missing[@]} -gt 0 ]]; then
        log_info "Missing dependencies: ${deps_missing[*]}"
        return 1
    fi
    
    return 0
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log_info "Non-interactive mode: auto-installing dependencies"
    else
        echo ""
        read -rp "Install missing dependencies? This requires sudo. [Y/n]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]] && [[ -n "$confirm" ]]; then
            log_error "Cannot continue without dependencies."
            exit 1
        fi
    fi
    
    log_info "Updating package list..."
    sudo apt-get update
    
    log_info "Installing packages..."
    sudo apt-get install -y \
        curl \
        jq \
        git \
        libsecret-tools \
        sqlite3 \
        build-essential
    
    # Check if Zig needs installation
    if ! check_command zig; then
        install_zig
    fi
    
    log_success "Dependencies installed"
}

install_zig() {
    log_info "Installing Zig..."
    
    # Download latest Zig 0.15.0 (or compatible)
    local zig_version="0.15.0"
    local arch
    arch=$(uname -m)
    local zig_arch
    
    case "$arch" in
        x86_64) zig_arch="x86_64" ;;
        aarch64) zig_arch="aarch64" ;;
        *) 
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    local zig_url="https://ziglang.org/download/${zig_version}/zig-linux-${zig_arch}-${zig_version}.tar.xz"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    
    log_info "Downloading Zig ${zig_version}..."
    curl -fsSL "$zig_url" -o "${tmp_dir}/zig.tar.xz"
    
    log_info "Extracting Zig..."
    tar -xf "${tmp_dir}/zig.tar.xz" -C "$tmp_dir"
    
    log_info "Installing Zig to ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"
    cp "${tmp_dir}/zig-linux-${zig_arch}-${zig_version}/zig" "$INSTALL_DIR/"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
        echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> ~/.bashrc
        log_info "Added ${INSTALL_DIR} to PATH in ~/.bashrc"
        export PATH="${INSTALL_DIR}:$PATH"
    fi
    
    rm -rf "$tmp_dir"
    log_success "Zig installed"
}

clone_and_build() {
    log_info "Cloning ZiggySpiderweb..."
    
    local repo_dir
    repo_dir="${HOME}/.local/share/ziggy-spiderweb"
    
    if [[ -d "$repo_dir" ]]; then
        log_warn "Existing installation found at ${repo_dir}"
        read -rp "Remove and re-clone? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "$repo_dir"
        else
            log_info "Using existing repository"
            cd "$repo_dir"
            git pull
        fi
    fi
    
    if [[ ! -d "$repo_dir" ]]; then
        mkdir -p "$(dirname "$repo_dir")"
        git clone https://github.com/DeanoC/ZiggySpiderweb.git "$repo_dir"
        cd "$repo_dir"
    fi
    
    log_info "Building ZiggySpiderweb (this may take a few minutes)..."
    zig build -Doptimize=ReleaseSafe
    
    log_info "Installing binaries..."
    mkdir -p "$INSTALL_DIR"
    cp zig-out/bin/spiderweb "$INSTALL_DIR/"
    cp zig-out/bin/spiderweb-config "$INSTALL_DIR/"
    
    log_success "ZiggySpiderweb built and installed"
}

configure_provider() {
    log_info "DEBUG: Entering configure_provider"
    
    log_info "Configuring AI Provider"
    
    # Non-interactive mode: use environment variables
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ -z "$PROVIDER" ]] || [[ -z "$MODEL" ]]; then
            log_error "Non-interactive mode requires SPIDERWEB_PROVIDER and SPIDERWEB_MODEL environment variables"
            exit 1
        fi
        log_info "Non-interactive mode: Using provider=$PROVIDER, model=$MODEL"
        
        # API key check
        if [[ -z "$API_KEY" ]]; then
            log_warn "No SPIDERWEB_API_KEY provided - you will need to configure this manually"
        fi
        return 0
    fi
    
    # Interactive mode
    echo ""
    log_info "Select your AI provider"
    echo ""
    echo "Quick setup (recommended):"
    echo "  1) OpenAI        - GPT-4o, GPT-4.1"
    echo "  2) OpenAI Codex  - GPT-5.1, GPT-5.2, GPT-5.3, GPT-5.3-codex-spark"
    echo "  3) Kimi Coding   - Kimi K2, K2.5 (Moonshot AI)"
    echo ""
    echo "  4) Manual setup  - Configure provider manually"
    echo ""
    
    local provider_choice
    while true; do
        read -rp "Select [1-4]: " provider_choice
        case "$provider_choice" in
            1) PROVIDER="openai"; break ;;
            2) PROVIDER="openai-codex"; break ;;
            3) PROVIDER="kimi-coding"; break ;;
            4) 
                echo ""
                log_info "Manual provider setup"
                echo ""
                echo "Available providers:"
                echo "  openai, openai-codex, openai-codex-spark, kimi-coding, anthropic, azure-openai"
                echo ""
                read -rp "Enter provider name: " PROVIDER
                if [[ -z "$PROVIDER" ]]; then
                    log_error "Provider name required"
                    continue
                fi
                break
                ;;
            *) log_error "Invalid choice. Please enter 1, 2, 3, or 4." ;;
        esac
    done
    
    echo ""
    log_info "Selected provider: $PROVIDER"
    
    # Model selection
    local model
    case "$PROVIDER" in
        openai)
            echo "Available models:"
            echo "  1) gpt-4o-mini (fast, cheap)"
            echo "  2) gpt-4.1-mini (reasoning, large context)"
            read -rp "Select model [1-2]: " model_choice
            case "$model_choice" in
                1) model="gpt-4o-mini" ;;
                2) model="gpt-4.1-mini" ;;
                *) model="gpt-4o-mini" ;;
            esac
            ;;
        openai-codex)
            echo "Available models:"
            echo "  1) gpt-5.1-codex-mini (balanced)"
            echo "  2) gpt-5.1 (powerful)"
            echo "  3) gpt-5.3-codex (latest)"
            echo "  4) gpt-5.3-codex-spark (fast)"
            read -rp "Select model [1-4]: " model_choice
            case "$model_choice" in
                1) model="gpt-5.1-codex-mini" ;;
                2) model="gpt-5.1" ;;
                3) model="gpt-5.3-codex" ;;
                4) model="gpt-5.3-codex-spark" ;;
                *) model="gpt-5.1-codex-mini" ;;
            esac
            ;;
        kimi-coding)
            echo "Available models:"
            echo "  1) k2p5 (Kimi K2.5)"
            echo "  2) kimi-k2.5"
            read -rp "Select model [1-2]: " model_choice
            case "$model_choice" in
                1) model="k2p5" ;;
                2) model="kimi-k2.5" ;;
                *) model="k2p5" ;;
            esac
            ;;
        *)
            echo ""
            log_info "Enter model name for $PROVIDER"
            echo ""
            read -rp "Model name: " model
            if [[ -z "$model" ]]; then
                log_error "Model name required"
                model="gpt-4o-mini"
            fi
            ;;
    esac
    
    log_info "Selected model: $model"
    

    MODEL="$model"

    # API Key (skip prompts in non-interactive mode)
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        return 0
    fi
    # API Key
    echo ""
    log_info "API Key Setup"
    echo "Your API key will be stored securely using your system's credential store (secret-tool)."
    echo ""
    
    local api_key
    while true; do
        read -rsp "Enter API key for $PROVIDER: " api_key
        echo ""
        if [[ -z "$api_key" ]]; then
            log_error "API key cannot be empty"
            continue
        fi
        
        # Confirm
        read -rsp "Confirm API key: " api_key_confirm
        echo ""
        if [[ "$api_key" != "$api_key_confirm" ]]; then
            log_error "API keys do not match"
            continue
        fi
        
        break
    done
    
    # Store configuration
    log_info "Storing configuration..."
    mkdir -p "$CONFIG_DIR"
    
    spiderweb-config config set-provider "$PROVIDER" "$model"
    
    # Store API key securely
    if check_command secret-tool; then
        echo "$api_key" | secret-tool store --label="ZiggySpiderweb $PROVIDER API Key" service ziggyspiderweb kind provider_api_key provider "$PROVIDER"
        log_success "API key stored securely"
    else
        log_warn "secret-tool not available. Storing in config (less secure)."
        # Fall back to config file storage
        local config_file="${CONFIG_DIR}/config.json"
        if [[ -f "$config_file" ]]; then
            jq --arg provider "$PROVIDER" --arg key "$api_key" \
               '.provider.api_key = $key' "$config_file" > "${config_file}.tmp"
            mv "${config_file}.tmp" "$config_file"
        fi
    fi
    
    log_success "Provider configured"
}

name_first_agent() {
    log_info "DEBUG: Entering name_first_agent"
    
    # Non-interactive mode: use environment variable
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log_info "Non-interactive mode: Agent name = $AGENT_NAME"
        return 0
    fi
    
    echo ""
    log_info "Name Your First Agent"
    echo ""
    echo "This will be the identity of your first Spiderweb agent."
    echo "The agent will hatch from templates/SOUL.md, AGENT.md, and IDENTITY.md"
    echo ""
    
    local agent_name
    while true; do
        read -rp "Agent name [default: ziggy]: " agent_name
        agent_name="${agent_name:-ziggy}"
        
        # Validate name (alphanumeric, dash, underscore only)
        if [[ ! "$agent_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            log_error "Invalid name. Use only letters, numbers, dash, or underscore."
            continue
        fi
        
        break
    done
    
    AGENT_NAME="$agent_name"
    log_success "First agent will be named: $AGENT_NAME"
}

setup_per_brain_config() {
    log_info "Setting up per-brain configuration..."
    
    local repo_dir="${HOME}/.local/share/ziggy-spiderweb"
    local agent_dir="${HOME}/.local/share/ziggy-spiderweb/agents/${AGENT_NAME}"
    
    # Create agent directory structure
    mkdir -p "${agent_dir}/deep-thinker"
    
    # Determine sub-brain config based on primary provider
    # Sub-brain should be in same ecosystem but cheaper/appropriate
    local sub_provider
    local sub_model
    local sub_think
    
    case "$PROVIDER" in
        openai)
            sub_provider="openai"
            sub_model="gpt-4.1-mini"
            sub_think="medium"
            ;;
        openai-codex)
            sub_provider="openai-codex"
            sub_model="gpt-5.1-codex-mini"
            sub_think="high"
            ;;
        kimi-coding)
            sub_provider="kimi-coding"
            sub_model="kimi-k2-thinking"
            sub_think="high"
            ;;
        *)
            # Fallback to same as primary
            sub_provider="$PROVIDER"
            sub_model="$MODEL"
            sub_think="medium"
            ;;
    esac
    
    # Primary brain config with user's selected provider/model
    cat > "${agent_dir}/agent.json" << EOF
{
  "name": "${AGENT_NAME}",
  "creature": "Interface gremlin",
  "vibe": "Fast, responsive, helpful",
  "emoji": "🕸️",
  "specialization": "primary_interface",
  "description": "Primary brain using ${MODEL}",
  
  "provider": {
    "name": "${PROVIDER}",
    "model": "${MODEL}",
    "think_level": "low"
  },
  
  "capabilities": ["chat", "tools", "spawn_subbrains"],
  "can_spawn_subbrains": true,
  
  "allowed_tools": [
    "memory.create",
    "memory.load", 
    "memory.mutate",
    "memory.search",
    "talk.user",
    "talk.brain",
    "talk.agent",
    "wait.for"
  ]
}
EOF
    
    # Deep thinker sub-brain config (appropriate for provider ecosystem)
    cat > "${agent_dir}/deep-thinker/agent.json" << EOF
{
  "name": "Deep Thinker",
  "creature": "Background scholar",
  "vibe": "Thorough, methodical, precise",
  "emoji": "🧠",
  "specialization": "complex_problem_solving",
  "description": "Sub-brain for hard problems using ${sub_model}",
  
  "provider": {
    "name": "${sub_provider}",
    "model": "${sub_model}",
    "think_level": "${sub_think}"
  },
  
  "capabilities": ["deep_analysis", "code_generation", "complex_reasoning"],
  "can_spawn_subbrains": false,
  
  "allowed_tools": [
    "memory.create",
    "memory.load",
    "memory.mutate",
    "memory.search",
    "memory.evict",
    "talk.brain",
    "talk.agent",
    "talk.log",
    "wait.for"
  ]
}
EOF
    
    log_success "Per-brain configuration created"
    echo ""
    echo "Configuration:"
    echo "  - Identity files: templates/ (hatched into LTM)"
    echo "  - Primary brain: ${PROVIDER}/${MODEL}"
    echo "  - deep-thinker: ${sub_provider}/${sub_model}"
    echo ""
    echo "Config directory: ${agent_dir}/"
    echo "See: ${repo_dir}/agents/identities/examples/README.md for more examples"
}

run_first_agent() {
    echo ""
    log_info "Starting First Agent"
    echo ""
    
    # Create LTM directory
    mkdir -p "$LTM_DIR"
    
    # Determine sub-brain values for summary (same logic as setup_per_brain_config)
    local sub_template="coder"
    local sub_provider
    local sub_model
    case "$PROVIDER" in
        openai) sub_provider="openai"; sub_model="gpt-4.1-mini" ;;
        openai-codex) sub_provider="openai-codex"; sub_model="gpt-5.1-codex-mini" ;;
        kimi-coding) sub_provider="kimi-coding"; sub_model="kimi-k2-thinking" ;;
        *) sub_provider="$PROVIDER"; sub_model="$MODEL" ;;
    esac
    
    # Show configuration summary
    echo "Configuration Summary:"
    echo "  Config directory: $CONFIG_DIR"
    echo "  LTM directory: $LTM_DIR"
    echo "  Install directory: $INSTALL_DIR"
    echo "  Agent config: ${HOME}/.local/share/ziggy-spiderweb/agents/${AGENT_NAME}_config.json"
    echo "  First agent: $AGENT_NAME"
    echo ""
    echo "Per-brain providers:"
    echo "  Primary: ${PROVIDER}/${MODEL}"
    echo "  coder: ${sub_template} template + ${sub_provider}/${sub_model}"
    echo "  memory-keeper: memory-keeper template + openai/gpt-4o-mini"
    echo ""
    
    # Non-interactive mode: start server automatically
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log_info "Non-interactive mode: Starting server..."
        echo ""
        echo "The server will run on http://127.0.0.1:18790"
        echo ""
        exec spiderweb
    fi
    
    read -rp "Start the server now? [Y/n]: " confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]] || [[ -z "$confirm" ]]; then
        log_info "Starting ZiggySpiderweb server..."
        echo ""
        echo "The server will run on http://127.0.0.1:18790"
        echo "Press Ctrl+C to stop"
        echo ""
        
        # Run the server
        exec spiderweb
    else
        echo ""
        log_info "You can start the server later with: spiderweb"
        log_info "Or test with: zsc --gateway-test ping ws://127.0.0.1:18790/v1/agents/$AGENT_NAME/stream"
    fi
}

main() {
    print_banner
    
    check_os
    
    if ! check_dependencies; then
        install_dependencies
    fi
    
    clone_and_build
    
    configure_provider
    
    name_first_agent
    
    setup_per_brain_config
    
    run_first_agent
    
    log_success "Installation complete!"
}

# Run main function
main "$@"
