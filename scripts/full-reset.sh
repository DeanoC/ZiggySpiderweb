#!/bin/bash
#
# ZiggySpiderweb Full Reset Script
# Removes all known user + system install/runtime artifacts.
# Requires two confirmations before any cleanup begins.
#

set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-spiderweb}"
TARGET_HOME_FROM_ENV=0
if [ -n "${TARGET_HOME:-}" ]; then
    TARGET_HOME_FROM_ENV=1
fi
TARGET_HOME="${TARGET_HOME:-$HOME}"
if [ "${EUID:-$(id -u)}" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ] && [ "$TARGET_HOME_FROM_ENV" -eq 0 ]; then
    TARGET_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
    if [ -z "$TARGET_HOME" ]; then
        TARGET_HOME="$HOME"
    fi
fi

USER_PATHS=(
    "$TARGET_HOME/.config/systemd/user/spiderweb.service"
    "$TARGET_HOME/.config/systemd/user/default.target.wants/spiderweb.service"
    "$TARGET_HOME/.config/spiderweb"
    "$TARGET_HOME/.cache/ziggy-spiderweb"
    "$TARGET_HOME/.spiderweb-ltm"
    "$TARGET_HOME/.local/share/ziggy-spiderweb"
    "$TARGET_HOME/.local/share/ziggy-starspider"
    "$TARGET_HOME/.config/ziggystarclaw"
    "$TARGET_HOME/.local/share/ziggy"
    "$TARGET_HOME/.local/bin/spiderweb"
    "$TARGET_HOME/.local/bin/spiderweb-config"
    "/tmp/spiderweb.log"
)

SYSTEM_PATHS=(
    "/etc/systemd/system/spiderweb.service"
    "/etc/systemd/system/multi-user.target.wants/spiderweb.service"
    "/etc/spiderweb"
    "/var/lib/spiderweb"
    "/var/log/spiderweb"
    "/opt/spiderweb"
    "/usr/local/bin/spiderweb"
    "/usr/local/bin/spiderweb-config"
)

log_info() {
    printf '[INFO] %s\n' "$1"
}

log_warn() {
    printf '[WARN] %s\n' "$1"
}

log_ok() {
    printf '[OK] %s\n' "$1"
}

run_root() {
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

remove_path() {
    local path="$1"
    if [ ! -e "$path" ]; then
        return 0
    fi

    rm -rf "$path" 2>/dev/null || true
    if [ -e "$path" ]; then
        run_root rm -rf "$path" 2>/dev/null || true
    fi

    if [ -e "$path" ]; then
        log_warn "Failed to remove: $path"
        return 1
    fi

    log_ok "Removed: $path"
    return 0
}

print_plan() {
    echo "========================================"
    echo "  ZiggySpiderweb Full Reset"
    echo "========================================"
    echo ""
    echo "This script will:"
    echo "  1) Stop and disable spiderweb services/processes"
    echo "  2) Delete known user + system install/runtime artifacts"
    echo ""
    echo "User paths:"
    for p in "${USER_PATHS[@]}"; do
        echo "  - $p"
    done
    echo ""
    echo "System paths:"
    for p in "${SYSTEM_PATHS[@]}"; do
        echo "  - $p"
    done
    echo ""
}

confirm_one() {
    read -r -p "Confirmation 1/2: Proceed to full reset flow? [y/N] " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
        log_info "Cancelled"
        exit 0
    fi
}

confirm_two() {
    echo ""
    echo "Confirmation 2/2: This is destructive."
    read -r -p "Type RESET to continue: " token
    if [[ "$token" != "RESET" ]]; then
        log_info "Cancelled"
        exit 0
    fi
}

stop_services_and_processes() {
    log_info "Stopping running spiderweb process/service(s)..."

    pkill -f '^'"$TARGET_HOME"'/.local/bin/spiderweb$' 2>/dev/null || true
    pkill -x spiderweb 2>/dev/null || true

    systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl --user disable "$SERVICE_NAME" 2>/dev/null || true
    systemctl --user daemon-reload 2>/dev/null || true

    run_root systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    run_root systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    run_root systemctl daemon-reload
    run_root systemctl reset-failed 2>/dev/null || true
}

delete_user_artifacts() {
    log_info "Removing user artifacts..."
    for p in "${USER_PATHS[@]}"; do
        remove_path "$p" || true
    done
}

delete_system_artifacts() {
    log_info "Removing system artifacts..."
    for p in "${SYSTEM_PATHS[@]}"; do
        remove_path "$p" || true
    done
}

verify_clean() {
    echo ""
    log_info "Verification:"

    if pgrep -f '^'"$TARGET_HOME"'/.local/bin/spiderweb$' >/dev/null 2>&1; then
        log_warn "Process still running: spiderweb"
    else
        log_info "No spiderweb process running"
    fi

    if ss -ltnp 2>/dev/null | grep -q ':18790'; then
        log_warn "Port 18790 still in use"
    else
        log_info "No listener on :18790"
    fi

    for p in "${USER_PATHS[@]}" "${SYSTEM_PATHS[@]}"; do
        if [ -e "$p" ]; then
            log_warn "Still exists: $p"
        fi
    done
}

main() {
    print_plan
    confirm_one
    confirm_two
    echo ""
    stop_services_and_processes
    delete_user_artifacts
    delete_system_artifacts
    verify_clean
    echo ""
    log_info "Full reset complete"
}

main "$@"
