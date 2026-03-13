#!/bin/bash
# Spiderweb Install Script
#
# RECOMMENDED (interactive):
#   curl -fsSL https://raw.githubusercontent.com/DeanoC/Spiderweb/main/install.sh -o /tmp/install.sh
#   bash /tmp/install.sh
#
# PIPED (non-interactive, uses defaults):
#   curl -fsSL https://raw.githubusercontent.com/DeanoC/Spiderweb/main/install.sh | bash
#
# NON-INTERACTIVE with defaults:
#   curl ... | SPIDERWEB_NON_INTERACTIVE=1 bash
#
# NON-INTERACTIVE with options:
#   curl ... | SPIDERWEB_INSTALL_ZSS=0 SPIDERWEB_INSTALL_SYSTEMD=0 bash
# Use a prebuilt release archive instead of compiling locally:
#   curl ... | SPIDERWEB_INSTALL_SOURCE=release SPIDERWEB_RELEASE_ARCHIVE_URL=https://github.com/DeanoC/Spiderweb/releases/download/vX.Y.Z/spiderweb-linux-x86_64.tar.gz bash
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

normalize_bool() {
    local raw="${1:-}"
    local default="${2:-0}"
    case "${raw,,}" in
        1|true|yes|y|on)
            echo "1"
            ;;
        0|false|no|n|off)
            echo "0"
            ;;
        *)
            echo "$default"
            ;;
    esac
}

path_within_dir() {
    local path="$1"
    local dir="$2"
    local norm_path norm_dir
    norm_path="$(readlink -f "$path" 2>/dev/null || printf '%s' "$path")"
    norm_dir="$(readlink -f "$dir" 2>/dev/null || printf '%s' "$dir")"
    [[ "$norm_path" == "$norm_dir" || "$norm_path" == "$norm_dir/"* ]]
}

collect_spiderweb_pids_by_install_dir() {
    local install_dir="$1"
    local -n matching_ref="$2"
    local -n foreign_ref="$3"
    matching_ref=()
    foreign_ref=()

    local pid exe
    while read -r pid; do
        [[ -n "$pid" ]] || continue
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
        if [[ -z "$exe" ]]; then
            foreign_ref+=("$pid")
        elif path_within_dir "$exe" "$install_dir"; then
            matching_ref+=("$pid")
        else
            foreign_ref+=("$pid")
        fi
    done < <(pgrep -x spiderweb 2>/dev/null || true)
}

stop_spiderweb_processes() {
    log_info "Stopping spiderweb..."
    if systemctl --user is-active spiderweb >/dev/null 2>&1; then
        systemctl --user stop spiderweb || true
    elif sudo systemctl is-active spiderweb >/dev/null 2>&1; then
        sudo systemctl stop spiderweb || true
    fi
    local pid
    for pid in "${MATCHING_SPIDERWEB_PIDS[@]:-}"; do
        [[ -n "$pid" ]] || continue
        kill "$pid" 2>/dev/null || sudo kill "$pid" 2>/dev/null || true
    done
    sleep 2
    for pid in "${MATCHING_SPIDERWEB_PIDS[@]:-}"; do
        [[ -n "$pid" ]] || continue
        kill -9 "$pid" 2>/dev/null || sudo kill -9 "$pid" 2>/dev/null || true
    done
    sleep 1
}

systemd_spiderweb_scope() {
    if [[ "${INSTALL_SYSTEMD_BOOL:-0}" == "1" ]]; then
        printf '%s' "${SYSTEMD_SCOPE:-user}"
    elif [[ "${SYSTEMD_EXISTS:-false}" == "true" ]]; then
        printf '%s' "${EXISTING_SCOPE:-user}"
    fi
}

restore_previously_running_spiderweb() {
    local scope
    scope="$(systemd_spiderweb_scope)"
    if [[ -n "$scope" ]]; then
        log_info "Restoring previously-running spiderweb service after upgrade..."
        if [[ "$scope" == "system" ]]; then
            sudo systemctl start spiderweb 2>/dev/null || true
        else
            systemctl --user start spiderweb 2>/dev/null || true
        fi
    else
        log_info "Restoring previously-running spiderweb after upgrade..."
        "${INSTALL_DIR}/spiderweb" &
    fi
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

sync_git_submodules() {
    local dir="$1"
    local name
    name="$(basename "$dir")"

    if [[ ! -f "$dir/.gitmodules" ]]; then
        return 0
    fi

    log_info "Initializing ${name} submodules..."
    git -C "$dir" submodule sync --recursive >/dev/null 2>&1 || true
    git -C "$dir" submodule update --init --recursive
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
if [[ ! -t 0 && -z "${SPIDERWEB_NON_INTERACTIVE:-}" ]]; then
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

NON_INTERACTIVE="$(normalize_bool "${SPIDERWEB_NON_INTERACTIVE:-}" "0")"
SPIDERWEB_INSTALL_SOURCE="${SPIDERWEB_INSTALL_SOURCE:-auto}"
SPIDERWEB_RELEASE_ARCHIVE_URL="${SPIDERWEB_RELEASE_ARCHIVE_URL:-}"
SPIDERWEB_RELEASE_ARCHIVE_SHA256="${SPIDERWEB_RELEASE_ARCHIVE_SHA256:-}"
SPIDERWEB_RELEASE_VERSION="${SPIDERWEB_RELEASE_VERSION:-}"

INSTALL_SOURCE_RESOLVED="$SPIDERWEB_INSTALL_SOURCE"
if [[ "$INSTALL_SOURCE_RESOLVED" == "auto" ]]; then
    if [[ -n "$SPIDERWEB_RELEASE_ARCHIVE_URL" ]]; then
        INSTALL_SOURCE_RESOLVED="release"
    else
        INSTALL_SOURCE_RESOLVED="source"
    fi
fi
if [[ "$INSTALL_SOURCE_RESOLVED" != "source" && "$INSTALL_SOURCE_RESOLVED" != "release" ]]; then
    echo "Error: SPIDERWEB_INSTALL_SOURCE must be one of: auto, source, release"
    exit 1
fi
if [[ "$INSTALL_SOURCE_RESOLVED" == "release" && -z "$SPIDERWEB_RELEASE_ARCHIVE_URL" ]]; then
    echo "Error: SPIDERWEB_RELEASE_ARCHIVE_URL is required when SPIDERWEB_INSTALL_SOURCE=release"
    exit 1
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

download_release_archive() {
    local url="$1"
    local output="$2"
    log_info "Downloading Spiderweb release archive..."
    curl -fL "$url" -o "$output"
}

verify_release_archive_sha256() {
    local archive_path="$1"
    local expected_sha="$2"
    [[ -n "$expected_sha" ]] || return 0

    if ! command -v sha256sum >/dev/null 2>&1; then
        log_warn "sha256sum is unavailable; skipping release archive checksum verification."
        return 0
    fi

    local actual_sha
    actual_sha="$(sha256sum "$archive_path" | awk '{print $1}')"
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        echo "Error: release archive SHA256 mismatch"
        echo "  expected: $expected_sha"
        echo "  actual:   $actual_sha"
        exit 1
    fi
}

extract_release_archive() {
    local archive_path="$1"
    local extract_dir="$2"

    mkdir -p "$extract_dir"
    case "$archive_path" in
        *.tar.gz|*.tgz)
            tar -xzf "$archive_path" -C "$extract_dir"
            ;;
        *.tar)
            tar -xf "$archive_path" -C "$extract_dir"
            ;;
        *.zip)
            if ! command -v unzip >/dev/null 2>&1; then
                echo "Error: unzip is required for .zip Spiderweb release archives"
                exit 1
            fi
            unzip -q "$archive_path" -d "$extract_dir"
            ;;
        *)
            echo "Error: unsupported Spiderweb release archive format: $archive_path"
            exit 1
            ;;
    esac
}

copy_release_binaries() {
    local extract_dir="$1"
    local install_dir="$2"
    shift 2
    local binaries=("$@")
    local staged_dir
    staged_dir="$(mktemp -d)"

    local bin source_path
    for bin in "${binaries[@]}"; do
        source_path="$(find "$extract_dir" -type f -name "$bin" -perm -u+x 2>/dev/null | head -n1 || true)"
        if [[ -z "$source_path" ]]; then
            echo "Error: expected release artifact missing executable: $bin"
            exit 1
        fi
        cp "$source_path" "$staged_dir/$bin"
    done

    mkdir -p "$install_dir"

    local copy_without_sudo=true
    for bin in "${binaries[@]}"; do
        if ! cp "$staged_dir/$bin" "$install_dir/" 2>/dev/null; then
            copy_without_sudo=false
            break
        fi
    done
    if [[ "$copy_without_sudo" != "true" ]]; then
        log_info "Need elevated permissions to update binary..."
        for bin in "${binaries[@]}"; do
            sudo cp "$staged_dir/$bin" "$install_dir/"
        done
    fi

    rm -rf "$staged_dir"
}

DEPS_MISSING=()
NEEDS_APT_INSTALL=false
APT_DEPS=(libsecret-tools sqlite3)
NEEDS_SOURCE_TOOLCHAIN=0
if [[ "$INSTALL_SOURCE_RESOLVED" == "source" ]]; then
    NEEDS_SOURCE_TOOLCHAIN=1
elif [[ "$(normalize_bool "${SPIDERWEB_INSTALL_ZSS:-}" "0")" == "1" ]]; then
    NEEDS_SOURCE_TOOLCHAIN=1
fi
if [[ "$NEEDS_SOURCE_TOOLCHAIN" == "1" ]]; then
    append_apt_dep build-essential
fi

for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        DEPS_MISSING+=("$cmd")
        NEEDS_APT_INSTALL=true
        append_apt_dep "$cmd"
    fi
done

if [[ "$NEEDS_SOURCE_TOOLCHAIN" == "1" ]] && ! command -v git &> /dev/null; then
    DEPS_MISSING+=("git")
    NEEDS_APT_INSTALL=true
    append_apt_dep git
fi

if [[ "$NEEDS_SOURCE_TOOLCHAIN" == "1" ]] && ! command -v zig &> /dev/null; then
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

if [[ "$NEEDS_SOURCE_TOOLCHAIN" == "1" ]] && ! command -v zig &> /dev/null; then
    echo "Error: zig compiler is required but was not found in PATH."
    echo "Install zig and rerun install.sh."
    exit 1
fi

POST_MISSING=()
for cmd in curl jq bwrap fusermount3; do
    if ! command -v "$cmd" &> /dev/null; then
        POST_MISSING+=("$cmd")
    fi
done
if [[ "$NEEDS_SOURCE_TOOLCHAIN" == "1" ]] && ! command -v git &> /dev/null; then
    POST_MISSING+=("git")
fi
if ! has_fuse3_runtime; then
    POST_MISSING+=("libfuse3.so.3/libfuse3.so.4")
fi
if [[ ${#POST_MISSING[@]} -gt 0 ]]; then
    echo "Error: missing required dependencies: ${POST_MISSING[*]}"
    echo "Install them and rerun install.sh."
    exit 1
fi

# Install Spiderweb
REPO_DIR="${SPIDERWEB_REPO_DIR:-$HOME/.local/share/ziggy-spiderweb}"
INSTALL_DIR="${SPIDERWEB_INSTALL_DIR:-$HOME/.local/bin}"
export PATH="${INSTALL_DIR}:${PATH}"
SPIDERWEB_REPO_URL="${SPIDERWEB_REPO_URL:-https://github.com/DeanoC/Spiderweb.git}"
SPIDERWEB_GIT_REF="${SPIDERWEB_GIT_REF:-main}"
ZSS_REPO_URL="${ZSS_REPO_URL:-https://github.com/DeanoC/ZiggyStarSpider.git}"
ZSS_GIT_REF="${ZSS_GIT_REF:-main}"
DEFAULT_START_AFTER_INSTALL="0"
DEFAULT_INSTALL_ZSS="0"
DEFAULT_INSTALL_SYSTEMD="0"
if [[ "$NON_INTERACTIVE" != "1" ]]; then
    DEFAULT_START_AFTER_INSTALL="1"
    DEFAULT_INSTALL_ZSS="1"
fi
START_AFTER_INSTALL="$(normalize_bool "${SPIDERWEB_START_AFTER_INSTALL:-}" "$DEFAULT_START_AFTER_INSTALL")"
INSTALL_ZSS="${SPIDERWEB_INSTALL_ZSS:-}"
INSTALL_SYSTEMD="${SPIDERWEB_INSTALL_SYSTEMD:-}"
SPIDERWEB_REPO_DIR_SET=0
if [[ -n "${SPIDERWEB_REPO_DIR+x}" ]]; then
    SPIDERWEB_REPO_DIR_SET=1
fi
MANAGED_REPO=1

# Check if spiderweb is running and offer to stop it first
SPIDERWEB_RUNNING=false
RESTORE_STOPPED_MATCHING_SPIDERWEB=0
MATCHING_SPIDERWEB_PIDS=()
FOREIGN_SPIDERWEB_PIDS=()
collect_spiderweb_pids_by_install_dir "$INSTALL_DIR" MATCHING_SPIDERWEB_PIDS FOREIGN_SPIDERWEB_PIDS
if (( ${#MATCHING_SPIDERWEB_PIDS[@]} > 0 || ${#FOREIGN_SPIDERWEB_PIDS[@]} > 0 )); then
    SPIDERWEB_RUNNING=true
    if (( ${#MATCHING_SPIDERWEB_PIDS[@]} > 0 )); then
        if [[ "$NON_INTERACTIVE" == "1" ]]; then
            stop_spiderweb_processes
            RESTORE_STOPPED_MATCHING_SPIDERWEB=1
        elif [[ -t 0 ]]; then
            echo ""
            read -rp "Spiderweb is currently running from ${INSTALL_DIR}. Stop it to allow update? [Y/n]: " stop_confirm
            if [[ ! "$stop_confirm" =~ ^[Nn]$ ]] || [[ -z "$stop_confirm" ]]; then
                stop_spiderweb_processes
                RESTORE_STOPPED_MATCHING_SPIDERWEB=1
            fi
        fi
    elif [[ "$NON_INTERACTIVE" == "1" ]]; then
        log_info "Detected an existing spiderweb process outside ${INSTALL_DIR}; continuing without stopping it"
    elif [[ -t 0 ]]; then
        echo ""
        log_warn "Another spiderweb process is running outside ${INSTALL_DIR}; leaving it untouched"
    fi
fi

if [[ "$INSTALL_SOURCE_RESOLVED" == "source" && -d "$REPO_DIR" ]]; then
    if [[ "$SPIDERWEB_REPO_DIR_SET" == "1" ]]; then
        log_info "Using provided Spiderweb checkout at ${REPO_DIR}"
        MANAGED_REPO=0
    elif [[ -t 0 ]]; then
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

mkdir -p "$INSTALL_DIR"
SPIDERWEB_BINARIES=(spiderweb spiderweb-config spiderweb-control spiderweb-fs-mount spiderweb-fs-node)
if [[ "$INSTALL_SOURCE_RESOLVED" == "source" ]]; then
    mkdir -p "$(dirname "$REPO_DIR")"
    if [[ "$MANAGED_REPO" == "1" ]]; then
        ensure_git_repo "$REPO_DIR" "$SPIDERWEB_REPO_URL" "$SPIDERWEB_GIT_REF"
        log_info "Syncing Spiderweb submodules..."
        git -C "$REPO_DIR" submodule sync --recursive
        git -C "$REPO_DIR" submodule update --init --recursive
    else
        if [[ ! -d "$REPO_DIR" ]] || [[ ! -f "$REPO_DIR/build.zig" ]]; then
            echo "Error: SPIDERWEB_REPO_DIR does not look like a Spiderweb checkout: $REPO_DIR"
            exit 1
        fi
    fi

    cd "$REPO_DIR"

    log_info "Building Spiderweb..."
    zig build -Doptimize=ReleaseSafe

    log_info "Installing binaries..."
    for bin in "${SPIDERWEB_BINARIES[@]}"; do
        if [[ ! -x "zig-out/bin/${bin}" ]]; then
            echo "Error: expected build artifact missing: zig-out/bin/${bin}"
            exit 1
        fi
    done

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
else
    RELEASE_TMP_DIR="$(mktemp -d)"
    RELEASE_ARCHIVE_NAME="$(basename "${SPIDERWEB_RELEASE_ARCHIVE_URL%%\?*}")"
    if [[ -z "$RELEASE_ARCHIVE_NAME" || "$RELEASE_ARCHIVE_NAME" == "/" || "$RELEASE_ARCHIVE_NAME" == "." ]]; then
        RELEASE_ARCHIVE_NAME="spiderweb-release.tar.gz"
    fi
    RELEASE_ARCHIVE_PATH="$RELEASE_TMP_DIR/$RELEASE_ARCHIVE_NAME"
    if [[ -n "$SPIDERWEB_RELEASE_VERSION" ]]; then
        log_info "Installing Spiderweb release ${SPIDERWEB_RELEASE_VERSION} from archive..."
    else
        log_info "Installing Spiderweb from release archive..."
    fi
    download_release_archive "$SPIDERWEB_RELEASE_ARCHIVE_URL" "$RELEASE_ARCHIVE_PATH"
    verify_release_archive_sha256 "$RELEASE_ARCHIVE_PATH" "$SPIDERWEB_RELEASE_ARCHIVE_SHA256"
    extract_release_archive "$RELEASE_ARCHIVE_PATH" "$RELEASE_TMP_DIR/extracted"
    copy_release_binaries "$RELEASE_TMP_DIR/extracted" "$INSTALL_DIR" "${SPIDERWEB_BINARIES[@]}"
    rm -rf "$RELEASE_TMP_DIR"
    log_success "Release archive installed!"
fi

# Ask about installing ZiggyStarSpider client
INSTALL_ZSS_BOOL="$DEFAULT_INSTALL_ZSS"
if [[ -n "$INSTALL_ZSS" ]]; then
    INSTALL_ZSS_BOOL="$(normalize_bool "$INSTALL_ZSS" "$DEFAULT_INSTALL_ZSS")"
elif [[ -t 0 ]]; then
    echo ""
    read -rp "Also install ZiggyStarSpider client (zss)? [Y/n]: " zss_confirm
    if [[ ! "$zss_confirm" =~ ^[Nn]$ ]] || [[ -z "$zss_confirm" ]]; then
        INSTALL_ZSS_BOOL="1"
    else
        INSTALL_ZSS_BOOL="0"
    fi
fi

if [[ "$INSTALL_ZSS_BOOL" == "1" ]]; then
    if ! command -v zig >/dev/null 2>&1; then
        echo "Error: zig is required to build ZiggyStarSpider (zss)."
        echo "Install zig or rerun with SPIDERWEB_INSTALL_ZSS=0."
        exit 1
    fi

    ZSS_REPO="${HOME}/.local/share/ziggy-starspider"

    mkdir -p "$(dirname "$ZSS_REPO")"
    ensure_git_repo "$ZSS_REPO" "$ZSS_REPO_URL" "$ZSS_GIT_REF"
    sync_git_submodules "$ZSS_REPO"
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

# Ensure remaining install steps run from a stable working directory.
if [[ "$INSTALL_SOURCE_RESOLVED" == "source" ]]; then
    cd "$REPO_DIR"
else
    mkdir -p "$REPO_DIR"
    cd "$REPO_DIR"
fi

# Ask about systemd service
INSTALL_SYSTEMD_BOOL="$DEFAULT_INSTALL_SYSTEMD"
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
    INSTALL_SYSTEMD_BOOL="0"
elif [[ -n "$INSTALL_SYSTEMD" ]]; then
    INSTALL_SYSTEMD_BOOL="$(normalize_bool "$INSTALL_SYSTEMD" "$DEFAULT_INSTALL_SYSTEMD")"
elif [[ -t 0 ]]; then
    echo ""
    read -rp "Install systemd service? [Y/n]: " systemd_confirm
    if [[ ! "$systemd_confirm" =~ ^[Nn]$ ]] || [[ -z "$systemd_confirm" ]]; then
        INSTALL_SYSTEMD_BOOL="1"
        echo ""
        read -rp "User or system service? [user/system]: " scope_choice
        if [[ "$scope_choice" =~ ^[Ss]ystem$ ]]; then
            SYSTEMD_SCOPE="system"
        fi
    else
        INSTALL_SYSTEMD_BOOL="0"
    fi
fi

if [[ "$INSTALL_SYSTEMD_BOOL" == "1" ]]; then
    log_info "Installing systemd service..."
    
    # Get current user for system service
    CURRENT_USER=$(whoami)
    
    # Create service file content
    if [[ "$SYSTEMD_SCOPE" == "system" ]]; then
        SERVICE_FILE="[Unit]
Description=Spiderweb Workspace Host
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
        if [[ "$START_AFTER_INSTALL" == "1" ]]; then
            sudo systemctl enable --now spiderweb
            log_success "System service installed and started"
        else
            sudo systemctl enable spiderweb
            log_success "System service installed"
        fi
    else
        SERVICE_FILE="[Unit]
Description=Spiderweb Workspace Host
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
        if [[ "$START_AFTER_INSTALL" == "1" ]]; then
            systemctl --user enable --now spiderweb
            log_success "User service installed and started"
        else
            systemctl --user enable spiderweb
            log_success "User service installed"
        fi
    fi
fi

# Ask about remote access
BIND_ADDRESS="${SPIDERWEB_BIND_ADDRESS:-127.0.0.1}"
CURRENT_PORT="18790"
CONFIGURE_BIND_ADDRESS="0"
if [[ "$NON_INTERACTIVE" != "1" && -t 0 ]]; then
    echo ""
    read -rp "Allow remote connections (Tailscale/VPN)? [y/N]: " remote_confirm
    if [[ "$remote_confirm" =~ ^[Yy]$ ]]; then
        BIND_ADDRESS="0.0.0.0"
        log_info "Server will bind to all interfaces (0.0.0.0)"
    else
        log_info "Server will bind to localhost only (127.0.0.1)"
    fi
    CONFIGURE_BIND_ADDRESS="1"
elif [[ -n "${SPIDERWEB_BIND_ADDRESS:-}" ]]; then
    log_info "Using requested bind address (${BIND_ADDRESS}) from SPIDERWEB_BIND_ADDRESS"
    CONFIGURE_BIND_ADDRESS="1"
fi

echo ""
log_info "Preparing local workspace-host config..."
echo ""

if [[ "$NON_INTERACTIVE" == "1" ]]; then
    log_info "Skipping interactive setup notes (non-interactive mode)"
else
    "${INSTALL_DIR}/spiderweb-config" first-run --non-interactive
fi

# Only configure bind address when it was chosen interactively or explicitly requested.
if [[ "$CONFIGURE_BIND_ADDRESS" == "1" ]]; then
    log_info "Configuring bind address (${BIND_ADDRESS})..."
    
    # Get current port from config - spiderweb-config outputs "Bind: <host>:<port>"
    # Extract port from format like "Bind: 127.0.0.1:18790"
    DETECTED_PORT=$("${INSTALL_DIR}/spiderweb-config" config 2>/dev/null | grep -oP 'Bind: [^:]+:\K\d+' || echo "18790")
    if [[ -n "$DETECTED_PORT" ]]; then
        CURRENT_PORT="$DETECTED_PORT"
    fi
    
    "${INSTALL_DIR}/spiderweb-config" config set-server --bind "$BIND_ADDRESS" --port "$CURRENT_PORT"
    
    # Restart service if running to apply new bind address
    if [[ "$START_AFTER_INSTALL" == "1" ]] && ([[ "$INSTALL_SYSTEMD_BOOL" == "1" ]] || [[ "$SYSTEMD_EXISTS" == "true" ]]); then
        if systemctl --user is-active spiderweb >/dev/null 2>&1 || sudo systemctl is-active spiderweb >/dev/null 2>&1; then
            log_info "Restarting service with new bind address..."
            if [[ "$SYSTEMD_SCOPE" == "system" ]] || [[ "$EXISTING_SCOPE" == "system" ]]; then
                sudo systemctl restart spiderweb 2>/dev/null || true
            else
                systemctl --user restart spiderweb 2>/dev/null || true
            fi
        fi
    elif [[ "$START_AFTER_INSTALL" == "1" ]]; then
        # No systemd - check if spiderweb is running directly and restart it
        if pgrep -x spiderweb > /dev/null 2>&1; then
            log_info "Restarting spiderweb with new bind address..."
            pkill -x spiderweb 2>/dev/null || true
            sleep 1
            # User can start Spiderweb manually after install when not using systemd.
            "${INSTALL_DIR}/spiderweb" &
        fi
    fi
fi

if [[ "$RESTORE_STOPPED_MATCHING_SPIDERWEB" == "1" && "$START_AFTER_INSTALL" != "1" ]]; then
    restore_previously_running_spiderweb
fi

# Post-install summary
echo ""
log_success "Installation complete!"
echo ""
echo "Install source: ${INSTALL_SOURCE_RESOLVED}"
if [[ "$INSTALL_SOURCE_RESOLVED" == "release" ]]; then
    echo "Release archive: ${SPIDERWEB_RELEASE_ARCHIVE_URL}"
    if [[ -n "$SPIDERWEB_RELEASE_VERSION" ]]; then
        echo "Release version: ${SPIDERWEB_RELEASE_VERSION}"
    fi
fi
echo ""
echo "Binaries installed to:"
for bin in "${SPIDERWEB_BINARIES[@]}"; do
    echo "  $INSTALL_DIR/${bin}"
done
if [[ "$INSTALL_ZSS_BOOL" == "1" ]]; then
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

if [[ "$INSTALL_SYSTEMD_BOOL" == "1" ]]; then
    if [[ "$START_AFTER_INSTALL" == "1" ]]; then
        echo "Systemd service installed and started ($SYSTEMD_SCOPE scope)"
    else
        echo "Systemd service installed ($SYSTEMD_SCOPE scope)"
    fi
elif [[ "$SYSTEMD_EXISTS" == "true" ]]; then
    echo "Systemd service already exists ($EXISTING_SCOPE scope)"
else
    echo "To install systemd service later:"
    echo "  spiderweb-config config install-service"
fi

if [[ "$RESTORE_STOPPED_MATCHING_SPIDERWEB" == "1" ]]; then
    echo "Previously-running spiderweb was restored after upgrade"
fi

SYNC_ZSS_AUTH=false
if [[ "$INSTALL_ZSS_BOOL" == "1" ]]; then
    SYNC_ZSS_AUTH=true
elif [[ -x "${INSTALL_DIR}/zss" ]] || command -v zss >/dev/null 2>&1 || [[ -f "${HOME}/.config/zss/config.json" ]]; then
    SYNC_ZSS_AUTH=true
fi
if [[ "$SYNC_ZSS_AUTH" == "true" ]]; then
    sync_zss_auth_tokens
fi

print_auth_tokens_summary

echo ""
echo "Next steps:"
echo "  1. Reveal auth tokens: spiderweb-config auth status --reveal"
echo "  2. Create a workspace: spiderweb-control workspace_create '{\"name\":\"Demo\",\"vision\":\"Mounted workspace\"}'"
echo "  3. Namespace-mount it: spiderweb-fs-mount --namespace-url ws://127.0.0.1:${CURRENT_PORT}/ --auth-token <admin-token> --workspace-id <workspace-id> --agent-id codex --session-key main mount ./workspace"
echo "  4. Start your external worker inside the mount; for Codex, read /meta/protocol.json and /projects/<workspace-id>/meta/* first."
echo "  5. Add remote filesystems with spiderweb-fs-node --control-url ws://127.0.0.1:${CURRENT_PORT}/ --pair-mode invite ..."
if [[ "$INSTALL_ZSS_BOOL" == "1" ]]; then
    echo ""
    echo "Optional GUI/tooling:"
    echo "  zss connect"
fi
