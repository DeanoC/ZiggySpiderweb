#!/bin/bash
# ZiggyStarSpider (zss) Client Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install-zss.sh | bash

set -euo pipefail

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This installer only supports Linux"
    exit 1
fi

INSTALL_DIR="${HOME}/.local/bin"
ZSS_REPO="${HOME}/.local/share/ziggy-starspider"

# Check dependencies
log_info "Checking dependencies..."

if ! command -v zig &> /dev/null; then
    log_warn "Zig not found. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq zig build-essential
    else
        echo "Please install Zig manually: https://ziglang.org/download/"
        exit 1
    fi
fi

if ! command -v git &> /dev/null; then
    log_warn "Git not found. Installing..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq git
fi

# Clone or update ZiggyStarSpider
if [[ -d "$ZSS_REPO" ]]; then
    log_info "Updating ZiggyStarSpider..."
    cd "$ZSS_REPO"
    git pull -q
else
    log_info "Cloning ZiggyStarSpider (this may take a minute)..."
    mkdir -p "$(dirname "$ZSS_REPO")"
    git clone --progress https://github.com/DeanoC/ZiggyStarSpider.git "$ZSS_REPO"
    cd "$ZSS_REPO"
fi

# Build zss
log_info "Building zss client (this may take 2-3 minutes)..."
zig build cli -Doptimize=ReleaseSafe -Dtarget=native

# Install
log_info "Installing zss to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp zig-out/bin/zss "$INSTALL_DIR/"

# Also try to build/install zss-tui if available
if zig build tui -Doptimize=ReleaseSafe -Dtarget=native 2>/dev/null; then
    cp zig-out/bin/zss-tui "$INSTALL_DIR/" 2>/dev/null || true
    log_success "zss and zss-tui installed!"
else
    log_success "zss installed!"
fi

echo ""
echo "Usage:"
echo "  zss connect                    # Connect to local spiderweb"
echo "  zss connect --url ws://...     # Connect to remote spiderweb"
echo "  zss --help                     # Show all options"
echo ""
echo "Make sure $INSTALL_DIR is in your PATH:"
echo '  export PATH="$HOME/.local/bin:$PATH"'
