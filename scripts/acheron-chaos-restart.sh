#!/usr/bin/env bash
set -euo pipefail

SPIDERWEB_URL="${SPIDERWEB_URL:-ws://127.0.0.1:18790/}"
SPIDERWEB_PROJECT_ID="${SPIDERWEB_PROJECT_ID:-system}"
SPIDERWEB_PROJECT_TOKEN="${SPIDERWEB_PROJECT_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN="${SPIDERWEB_AUTH_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN_FILE="${SPIDERWEB_AUTH_TOKEN_FILE:-$HOME/.local/share/ziggy-spiderweb/.spiderweb-ltm/auth_tokens.json}"
SPIDERWEB_SERVICE="${SPIDERWEB_SERVICE:-spiderweb.service}"

CHAOS_ITERATIONS="${CHAOS_ITERATIONS:-30}"
CHAOS_RESTART_AT="${CHAOS_RESTART_AT:-10}"
CHAOS_INTERVAL_MS="${CHAOS_INTERVAL_MS:-500}"
CHAOS_TIMEOUT_SEC="${CHAOS_TIMEOUT_SEC:-8}"
CHAOS_LIST_PATH="${CHAOS_LIST_PATH:-/nodes}"
CHAOS_ATTR_PATH="${CHAOS_ATTR_PATH:-/nodes}"
CHAOS_LOG_PATH="${CHAOS_LOG_PATH:-/tmp/acheron-chaos-restart-$(date +%s).log}"

require_bin() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required binary not found: $1" >&2
        exit 2
    fi
}

require_bin systemctl
require_bin systemd-run
require_bin spiderweb-control
require_bin spiderweb-fs-mount
require_bin jq
require_bin timeout

spiderweb_control_bin="$(command -v spiderweb-control)"
spiderweb_fs_mount_bin="$(command -v spiderweb-fs-mount)"
timeout_bin="$(command -v timeout)"

if [[ -z "$SPIDERWEB_AUTH_TOKEN" && -f "$SPIDERWEB_AUTH_TOKEN_FILE" ]]; then
    SPIDERWEB_AUTH_TOKEN="$(jq -r '.admin_token // .user_token // empty' "$SPIDERWEB_AUTH_TOKEN_FILE" 2>/dev/null || true)"
fi

if [[ "$CHAOS_ITERATIONS" -lt 4 ]]; then
    echo "error: CHAOS_ITERATIONS must be at least 4" >&2
    exit 2
fi
if [[ "$CHAOS_RESTART_AT" -lt 2 || "$CHAOS_RESTART_AT" -gt $((CHAOS_ITERATIONS - 2)) ]]; then
    echo "error: CHAOS_RESTART_AT must be between 2 and CHAOS_ITERATIONS-2" >&2
    exit 2
fi

run_unit_cmd() {
    systemd-run --user --wait --collect --pipe --quiet "$timeout_bin" "${CHAOS_TIMEOUT_SEC}s" "$@"
}

control_args=(--url "$SPIDERWEB_URL")
if [[ -n "$SPIDERWEB_AUTH_TOKEN" ]]; then
    control_args+=(--auth-token "$SPIDERWEB_AUTH_TOKEN")
fi

mount_args=(--workspace-url "$SPIDERWEB_URL")
if [[ -n "$SPIDERWEB_AUTH_TOKEN" ]]; then
    mount_args+=(--auth-token "$SPIDERWEB_AUTH_TOKEN")
fi
if [[ -n "$SPIDERWEB_PROJECT_ID" ]]; then
    mount_args+=(--project-id "$SPIDERWEB_PROJECT_ID")
fi
if [[ -n "$SPIDERWEB_PROJECT_TOKEN" ]]; then
    mount_args+=(--project-token "$SPIDERWEB_PROJECT_TOKEN")
fi

payload='{}'
if [[ -n "$SPIDERWEB_PROJECT_ID" ]]; then
    if [[ -n "$SPIDERWEB_PROJECT_TOKEN" ]]; then
        payload="$(jq -cn --arg project_id "$SPIDERWEB_PROJECT_ID" --arg project_token "$SPIDERWEB_PROJECT_TOKEN" '{project_id: $project_id, project_token: $project_token}')"
    else
        payload="$(jq -cn --arg project_id "$SPIDERWEB_PROJECT_ID" '{project_id: $project_id}')"
    fi
fi

echo "chaos log: $CHAOS_LOG_PATH"
echo "service: $SPIDERWEB_SERVICE"
echo "url: $SPIDERWEB_URL"
echo "project: $SPIDERWEB_PROJECT_ID"
echo "iterations: $CHAOS_ITERATIONS restart_at: $CHAOS_RESTART_AT interval_ms: $CHAOS_INTERVAL_MS"

if ! status_json="$(run_unit_cmd "$spiderweb_control_bin" "${control_args[@]}" workspace_status "$payload" 2>&1)"; then
    echo "error: preflight workspace_status failed" >&2
    echo "$status_json" >&2
    exit 1
fi
if ! jq -e '.ok == true and .type == "control.workspace_status"' >/dev/null <<<"$status_json"; then
    echo "error: preflight control response invalid" >&2
    echo "$status_json" >&2
    exit 1
fi

pre_ok=0
pre_err=0
post_ok=0
post_err=0

restart_done=0

for i in $(seq 1 "$CHAOS_ITERATIONS"); do
    if [[ "$i" -eq "$CHAOS_RESTART_AT" ]]; then
        echo "$(date --iso-8601=seconds) event=restart-start service=$SPIDERWEB_SERVICE" | tee -a "$CHAOS_LOG_PATH"
        systemctl --user restart "$SPIDERWEB_SERVICE"
        echo "$(date --iso-8601=seconds) event=restart-done service=$SPIDERWEB_SERVICE" | tee -a "$CHAOS_LOG_PATH"
        restart_done=1
    fi

    phase="pre"
    if [[ "$restart_done" -eq 1 ]]; then
        phase="post"
    fi

    list_err=""
    attr_err=""
    if ! run_unit_cmd "$spiderweb_fs_mount_bin" "${mount_args[@]}" readdir "$CHAOS_LIST_PATH" >/dev/null 2>/tmp/acheron-chaos-list.err; then
        list_err="$(head -n 1 /tmp/acheron-chaos-list.err | tr -d '\r')"
    fi
    if ! run_unit_cmd "$spiderweb_fs_mount_bin" "${mount_args[@]}" getattr "$CHAOS_ATTR_PATH" >/dev/null 2>/tmp/acheron-chaos-attr.err; then
        attr_err="$(head -n 1 /tmp/acheron-chaos-attr.err | tr -d '\r')"
    fi

    status="ok"
    if [[ -n "$list_err" || -n "$attr_err" ]]; then
        status="err"
    fi

    if [[ "$phase" == "pre" ]]; then
        if [[ "$status" == "ok" ]]; then
            pre_ok=$((pre_ok + 1))
        else
            pre_err=$((pre_err + 1))
        fi
    else
        if [[ "$status" == "ok" ]]; then
            post_ok=$((post_ok + 1))
        else
            post_err=$((post_err + 1))
        fi
    fi

    ts="$(date +%s%3N)"
    {
        printf "%s iter=%d phase=%s status=%s" "$ts" "$i" "$phase" "$status"
        if [[ -n "$list_err" ]]; then
            printf " list_err=%q" "$list_err"
        fi
        if [[ -n "$attr_err" ]]; then
            printf " attr_err=%q" "$attr_err"
        fi
        printf "\n"
    } | tee -a "$CHAOS_LOG_PATH"

    sleep "$(awk "BEGIN {print $CHAOS_INTERVAL_MS/1000}")"
done

echo "summary: pre_ok=$pre_ok pre_err=$pre_err post_ok=$post_ok post_err=$post_err" | tee -a "$CHAOS_LOG_PATH"

if [[ "$pre_ok" -eq 0 ]]; then
    echo "error: no successful probes before restart" >&2
    exit 1
fi
if [[ "$post_ok" -lt 3 ]]; then
    echo "error: insufficient successful probes after restart (post_ok=$post_ok)" >&2
    exit 1
fi

echo "chaos restart test passed"
