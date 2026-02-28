#!/usr/bin/env bash
set -euo pipefail

SPIDERWEB_URL="${SPIDERWEB_URL:-ws://127.0.0.1:18790/}"
SPIDERWEB_PROJECT_ID="${SPIDERWEB_PROJECT_ID:-}"
SPIDERWEB_PROJECT_TOKEN="${SPIDERWEB_PROJECT_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN="${SPIDERWEB_AUTH_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN_FILE="${SPIDERWEB_AUTH_TOKEN_FILE:-$HOME/.local/share/ziggy-spiderweb/.spiderweb-ltm/auth_tokens.json}"
EXPECTED_NODES="${EXPECTED_NODES:-}"
EXPECTED_SERVICES="${EXPECTED_SERVICES:-}"
HARNESS_TIMEOUT_SEC="${HARNESS_TIMEOUT_SEC:-90}"
HARNESS_POLL_SEC="${HARNESS_POLL_SEC:-2}"
RECONNECT_NODE_ID="${RECONNECT_NODE_ID:-}"
RECONNECT_TIMEOUT_SEC="${RECONNECT_TIMEOUT_SEC:-120}"
PERSISTENCE_NODE_ID="${PERSISTENCE_NODE_ID:-}"
PERSISTENCE_SERVICE_ID="${PERSISTENCE_SERVICE_ID:-}"

require_bin() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required binary not found: $1" >&2
        exit 2
    fi
}

require_bin spiderweb-control
require_bin spiderweb-fs-mount
require_bin jq
require_bin timeout

if [[ -z "$SPIDERWEB_AUTH_TOKEN" && -f "$SPIDERWEB_AUTH_TOKEN_FILE" ]]; then
    SPIDERWEB_AUTH_TOKEN="$(jq -r '.admin_token // .user_token // empty' "$SPIDERWEB_AUTH_TOKEN_FILE" 2>/dev/null || true)"
fi

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

workspace_payload='{}'
if [[ -n "$SPIDERWEB_PROJECT_ID" ]]; then
    if [[ -n "$SPIDERWEB_PROJECT_TOKEN" ]]; then
        workspace_payload="$(jq -cn --arg project_id "$SPIDERWEB_PROJECT_ID" --arg project_token "$SPIDERWEB_PROJECT_TOKEN" '{project_id: $project_id, project_token: $project_token}')"
    else
        workspace_payload="$(jq -cn --arg project_id "$SPIDERWEB_PROJECT_ID" '{project_id: $project_id}')"
    fi
fi

control_call() {
    local op="$1"
    local payload="$2"
    timeout "${HARNESS_TIMEOUT_SEC}s" spiderweb-control "${control_args[@]}" "$op" "$payload"
}

workspace_status() {
    control_call workspace_status "$workspace_payload"
}

wait_node_presence() {
    local node_id="$1"
    local should_exist="$2"
    local timeout_sec="$3"
    local deadline=$(( $(date +%s) + timeout_sec ))
    while (( $(date +%s) < deadline )); do
        local reply
        if ! reply="$(workspace_status 2>/dev/null)"; then
            sleep "$HARNESS_POLL_SEC"
            continue
        fi
        local found=0
        if jq -e --arg nid "$node_id" '((.payload.actual_mounts // []) | if length > 0 then . else (.payload.mounts // []) end)[]?.node_id | select(. == $nid)' >/dev/null <<<"$reply"; then
            found=1
        fi
        if [[ "$should_exist" == "1" && "$found" == "1" ]]; then
            return 0
        fi
        if [[ "$should_exist" == "0" && "$found" == "0" ]]; then
            return 0
        fi
        sleep "$HARNESS_POLL_SEC"
    done
    return 1
}

service_mount_path() {
    local node_id="$1"
    local service_id="$2"
    local payload
    payload="$(jq -cn --arg node_id "$node_id" '{node_id: $node_id}')"
    local reply
    reply="$(control_call node_service_get "$payload")"
    if ! jq -e --arg sid "$service_id" '.payload.services[] | select(.service_id == $sid)' >/dev/null <<<"$reply"; then
        return 1
    fi
    jq -r --arg sid "$service_id" '.payload.services[] | select(.service_id == $sid) | .mounts[0]?.mount_path // empty' <<<"$reply"
}

echo "multi-node runtime harness"
echo "server: $SPIDERWEB_URL"

if [[ -n "$EXPECTED_NODES" ]]; then
    IFS=',' read -r -a expected_nodes <<<"$EXPECTED_NODES"
    for expected_node in "${expected_nodes[@]}"; do
        node_trimmed="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$expected_node")"
        [[ -z "$node_trimmed" ]] && continue
        if ! wait_node_presence "$node_trimmed" "1" "$HARNESS_TIMEOUT_SEC"; then
            echo "error: expected node not mounted before timeout: $node_trimmed" >&2
            exit 1
        fi
        echo "ok: node online: $node_trimmed"
    done
fi

if [[ -n "$EXPECTED_NODES" && -n "$EXPECTED_SERVICES" ]]; then
    IFS=',' read -r -a expected_nodes <<<"$EXPECTED_NODES"
    IFS=',' read -r -a expected_services <<<"$EXPECTED_SERVICES"
    for expected_node in "${expected_nodes[@]}"; do
        node_trimmed="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$expected_node")"
        [[ -z "$node_trimmed" ]] && continue
        for expected_service in "${expected_services[@]}"; do
            service_trimmed="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$expected_service")"
            [[ -z "$service_trimmed" ]] && continue
            mount_path="$(service_mount_path "$node_trimmed" "$service_trimmed" || true)"
            if [[ -z "$mount_path" ]]; then
                echo "error: expected service not found: node=$node_trimmed service=$service_trimmed" >&2
                exit 1
            fi
            timeout "${HARNESS_TIMEOUT_SEC}s" spiderweb-fs-mount "${mount_args[@]}" getattr "$mount_path/health.json" >/dev/null
            timeout "${HARNESS_TIMEOUT_SEC}s" spiderweb-fs-mount "${mount_args[@]}" getattr "$mount_path/status.json" >/dev/null
            timeout "${HARNESS_TIMEOUT_SEC}s" spiderweb-fs-mount "${mount_args[@]}" getattr "$mount_path/config.json" >/dev/null
            echo "ok: runtime surface present: node=$node_trimmed service=$service_trimmed mount=$mount_path"
        done
    done
fi

marker_mount_path=""
marker_value=""
if [[ -n "$PERSISTENCE_NODE_ID" && -n "$PERSISTENCE_SERVICE_ID" ]]; then
    marker_mount_path="$(service_mount_path "$PERSISTENCE_NODE_ID" "$PERSISTENCE_SERVICE_ID" || true)"
    if [[ -z "$marker_mount_path" ]]; then
        echo "error: persistence target service not found: node=$PERSISTENCE_NODE_ID service=$PERSISTENCE_SERVICE_ID" >&2
        exit 1
    fi
    marker_value="harness-$(date +%s)"
    marker_payload="$(jq -cn --arg marker "$marker_value" '{harness_marker: $marker}')"
    timeout "${HARNESS_TIMEOUT_SEC}s" spiderweb-fs-mount "${mount_args[@]}" write "$marker_mount_path/config.json" "$marker_payload" >/dev/null
    confirm_now="$(timeout "${HARNESS_TIMEOUT_SEC}s" spiderweb-fs-mount "${mount_args[@]}" cat "$marker_mount_path/config.json")"
    if ! grep -q "$marker_value" <<<"$confirm_now"; then
        echo "error: failed to set persistence marker before reconnect" >&2
        exit 1
    fi
    echo "ok: persistence marker written: $marker_mount_path/config.json"
fi

if [[ -n "$RECONNECT_NODE_ID" ]]; then
    echo "waiting for reconnect flap on node: $RECONNECT_NODE_ID (offline then online)"
    if ! wait_node_presence "$RECONNECT_NODE_ID" "0" "$RECONNECT_TIMEOUT_SEC"; then
        echo "error: reconnect check failed, node never went offline: $RECONNECT_NODE_ID" >&2
        exit 1
    fi
    if ! wait_node_presence "$RECONNECT_NODE_ID" "1" "$RECONNECT_TIMEOUT_SEC"; then
        echo "error: reconnect check failed, node never returned online: $RECONNECT_NODE_ID" >&2
        exit 1
    fi
    echo "ok: reconnect detected for node: $RECONNECT_NODE_ID"
fi

if [[ -n "$marker_mount_path" && -n "$marker_value" ]]; then
    after_restart="$(timeout "${HARNESS_TIMEOUT_SEC}s" spiderweb-fs-mount "${mount_args[@]}" cat "$marker_mount_path/config.json")"
    if ! grep -q "$marker_value" <<<"$after_restart"; then
        echo "error: persistence marker missing after reconnect/startup" >&2
        exit 1
    fi
    echo "ok: persistence marker survived reconnect/startup"
fi

echo "multi-node runtime harness passed"

