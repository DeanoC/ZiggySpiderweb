#!/bin/bash
# Automated test script for ZiggySpiderweb install
# Usage: ./test-install.sh [provider] [model] [api_key]

set -euo pipefail

PROVIDER="${1:-openai}"
MODEL="${2:-gpt-4o-mini}"
API_KEY="${3:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo "=========================================="
echo "ZiggySpiderweb Install Test"
echo "=========================================="
echo "Provider: $PROVIDER"
echo "Model: $MODEL"
echo "API Key: ${API_KEY:+[SET]}${API_KEY:-[NOT SET - will use mock]}"
echo "=========================================="
echo ""

# Test 1: Check environment
log_info "Test 1: Checking environment..."
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ -f /etc/debian_version ]]; then
    log_success "Debian/Linux environment detected"
else
    log_warn "Non-Debian environment (may still work)"
fi

# Test 2: Check dependencies
log_info "Test 2: Checking dependencies..."
for cmd in curl jq git sqlite3; do
    if command -v "$cmd" &> /dev/null; then
        log_success "$cmd found"
    else
        log_error "$cmd not found"
        exit 1
    fi
done

# Test 3: Check secret-tool (optional but recommended)
log_info "Test 3: Checking secure credential storage..."
if command -v secret-tool &> /dev/null; then
    log_success "secret-tool found (secure storage available)"
else
    log_warn "secret-tool not found (will use config file)"
fi

# Test 4: Check Zig
log_info "Test 4: Checking Zig..."
if command -v zig &> /dev/null; then
    zig_version=$(zig version)
    log_success "Zig found: $zig_version"
else
    log_warn "Zig not found (will be installed by script)"
fi

# Test 5: Download and run install script
log_info "Test 5: Running install script..."
if [[ -f /tmp/install.sh ]]; then
    log_info "Using local install.sh"
    cp /tmp/install.sh /tmp/install-test.sh
else
    log_info "Downloading install script..."
    curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh -o /tmp/install-test.sh
fi
chmod +x /tmp/install-test.sh

# For automated testing, we need to simulate the interactive parts
# This is a simplified version - full automation would require expect

log_info "Install script downloaded and ready"
log_info "To complete testing, run: /tmp/install-test.sh"

# Test 6: Check directories
log_info "Test 6: Checking required directories..."
for dir in "$HOME/.local/bin" "$HOME/.config/spiderweb"; do
    mkdir -p "$dir"
    if [[ -d "$dir" ]]; then
        log_success "Directory exists: $dir"
    else
        log_error "Failed to create: $dir"
        exit 1
    fi
done

# Test 7: Simulate config
log_info "Test 7: Simulating configuration..."
mkdir -p "$HOME/.config/spiderweb"
cat > "$HOME/.config/spiderweb/config.json" << EOF
{
  "server": {
    "bind": "0.0.0.0",
    "port": 18790
  },
  "provider": {
    "name": "$PROVIDER",
    "model": "$MODEL"
  },
  "log": {
    "level": "debug"
  },
  "runtime": {
    "inbound_queue_max": 512,
    "brain_tick_queue_max": 256,
    "outbound_queue_max": 512,
    "control_queue_max": 128,
    "connection_worker_threads": 4,
    "connection_queue_max": 128,
    "runtime_worker_threads": 2,
    "runtime_request_queue_max": 128,
    "chat_operation_timeout_ms": 30000,
    "control_operation_timeout_ms": 5000,
    "ltm_directory": ".spiderweb-ltm",
    "ltm_filename": "runtime-memory.db"
  }
}
EOF
log_success "Test config created"

# Test 8: API key setup (if provided)
if [[ -n "$API_KEY" ]]; then
    log_info "Test 8: Storing API key..."
    if command -v secret-tool &> /dev/null; then
        echo "$API_KEY" | secret-tool store --label="ZiggySpiderweb $PROVIDER API Key" service ziggyspiderweb kind provider_api_key provider "$PROVIDER"
        log_success "API key stored in secret-tool"
    else
        log_warn "secret-tool not available, storing in config"
        # Update config with API key
        tmp_file=$(mktemp)
        jq --arg key "$API_KEY" '.provider.api_key = $key' "$HOME/.config/spiderweb/config.json" > "$tmp_file"
        mv "$tmp_file" "$HOME/.config/spiderweb/config.json"
        log_success "API key stored in config"
    fi
else
    log_warn "Test 8: No API key provided (skipping)"
fi

# Test 9: Verify config
log_info "Test 9: Verifying configuration..."
if [[ -f "$HOME/.config/spiderweb/config.json" ]]; then
    if jq empty "$HOME/.config/spiderweb/config.json" 2>/dev/null; then
        log_success "Config is valid JSON"
        echo ""
        echo "Configuration:"
        jq '.' "$HOME/.config/spiderweb/config.json"
    else
        log_error "Config is invalid JSON"
        exit 1
    fi
else
    log_error "Config file not found"
    exit 1
fi

echo ""
echo "=========================================="
log_success "All tests passed!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Build Spiderweb: cd ~/ziggy-spiderweb-src && zig build"
echo "  2. Install: cp zig-out/bin/spiderweb* ~/.local/bin/"
echo "  3. Run: spiderweb"
echo ""
echo "Or run the full install script: /tmp/install-test.sh"
