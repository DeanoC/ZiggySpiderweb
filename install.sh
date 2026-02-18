#!/bin/bash
# ZiggySpiderweb Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh | bash

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
GREEN='\033[0;32m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

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

if [[ -d "$REPO_DIR" ]]; then
    echo ""
    read -rp "Remove existing install and re-clone? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$REPO_DIR"
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
cp zig-out/bin/spiderweb "$INSTALL_DIR/"
cp zig-out/bin/spiderweb-config "$INSTALL_DIR/"

log_success "Build complete!"

# Run first-run wizard
echo ""
log_info "Starting first-time setup..."
echo ""

spiderweb-config first-run
