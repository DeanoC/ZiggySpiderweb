#!/usr/bin/env bash
set -euo pipefail

SPIDERWEB_URL="${SPIDERWEB_URL:-ws://127.0.0.1:18790/}"
SPIDERWEB_PROJECT_ID="${SPIDERWEB_PROJECT_ID:-}"
SPIDERWEB_PROJECT_TOKEN="${SPIDERWEB_PROJECT_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN="${SPIDERWEB_AUTH_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN_FILE="${SPIDERWEB_AUTH_TOKEN_FILE:-$HOME/.local/share/ziggy-spiderweb/.spiderweb-ltm/auth_tokens.json}"
EXPECTED_NODES="${EXPECTED_NODES:-}"
SMOKE_TIMEOUT_SEC="${SMOKE_TIMEOUT_SEC:-15}"
SMOKE_FAIL_ON_DEGRADED="${SMOKE_FAIL_ON_DEGRADED:-1}"
SMOKE_CONNECT_RETRIES="${SMOKE_CONNECT_RETRIES:-8}"
SMOKE_RETRY_DELAY_MS="${SMOKE_RETRY_DELAY_MS:-500}"

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

payload='{}'
if [[ -n "$SPIDERWEB_PROJECT_ID" ]]; then
    if [[ -n "$SPIDERWEB_PROJECT_TOKEN" ]]; then
        payload="$(jq -cn --arg project_id "$SPIDERWEB_PROJECT_ID" --arg project_token "$SPIDERWEB_PROJECT_TOKEN" '{project_id: $project_id, project_token: $project_token}')"
    else
        payload="$(jq -cn --arg project_id "$SPIDERWEB_PROJECT_ID" '{project_id: $project_id}')"
    fi
fi

reply=""
attempt=1
while true; do
    if reply="$(timeout "${SMOKE_TIMEOUT_SEC}s" spiderweb-control "${control_args[@]}" workspace_status "$payload" 2>&1)"; then
        break
    fi
    if [[ "$attempt" -ge "$SMOKE_CONNECT_RETRIES" ]]; then
        echo "error: control.workspace_status failed" >&2
        echo "$reply" >&2
        exit 1
    fi
    sleep "$(awk "BEGIN {print $SMOKE_RETRY_DELAY_MS/1000}")"
    attempt=$((attempt + 1))
done
if ! jq -e '.type == "control.workspace_status"' >/dev/null <<<"$reply"; then
    echo "error: unexpected control reply:" >&2
    echo "$reply" >&2
    exit 1
fi

availability_total="$(jq -r '.payload.availability.mounts_total // 0' <<<"$reply")"
availability_online="$(jq -r '.payload.availability.online // 0' <<<"$reply")"
availability_degraded="$(jq -r '.payload.availability.degraded // 0' <<<"$reply")"
availability_missing="$(jq -r '.payload.availability.missing // 0' <<<"$reply")"
project_id_resolved="$(jq -r '.payload.project_id // "(none)"' <<<"$reply")"

echo "workspace project: ${project_id_resolved}"
echo "availability: online=${availability_online}/${availability_total} degraded=${availability_degraded} missing=${availability_missing}"

if [[ "$availability_total" -eq 0 ]]; then
    echo "error: no workspace mounts are active" >&2
    exit 1
fi

if [[ "$SMOKE_FAIL_ON_DEGRADED" == "1" && ( "$availability_degraded" -gt 0 || "$availability_missing" -gt 0 ) ]]; then
    echo "error: workspace is degraded or missing mounts" >&2
    exit 1
fi

mapfile -t mount_paths < <(
    jq -r '((.payload.actual_mounts // []) | if length > 0 then . else (.payload.mounts // []) end)[]?.mount_path' <<<"$reply"
)

if [[ "${#mount_paths[@]}" -eq 0 ]]; then
    echo "error: no mount paths returned from workspace status" >&2
    exit 1
fi

echo "checking mount paths:"
for mount_path in "${mount_paths[@]}"; do
    echo "  - ${mount_path}"
    if ! timeout "${SMOKE_TIMEOUT_SEC}s" spiderweb-fs-mount "${mount_args[@]}" getattr "$mount_path" >/dev/null; then
        echo "error: mount path is not readable: ${mount_path}" >&2
        exit 1
    fi
done

mapfile -t mounted_nodes < <(
    jq -r '((.payload.actual_mounts // []) | if length > 0 then . else (.payload.mounts // []) end)[]?.node_id' <<<"$reply" | sort -u
)

if [[ -n "$EXPECTED_NODES" ]]; then
    IFS=',' read -r -a expected_nodes <<<"$EXPECTED_NODES"
    for expected in "${expected_nodes[@]}"; do
        expected_trimmed="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$expected")"
        [[ -z "$expected_trimmed" ]] && continue
        found=0
        for mounted in "${mounted_nodes[@]}"; do
            if [[ "$mounted" == "$expected_trimmed" ]]; then
                found=1
                break
            fi
        done
        if [[ "$found" -ne 1 ]]; then
            echo "error: expected node not mounted: ${expected_trimmed}" >&2
            exit 1
        fi
    done
fi

echo "smoke check passed"
