#!/usr/bin/env bash
set -euo pipefail

SPIDERWEB_URL="${SPIDERWEB_URL:-ws://127.0.0.1:18790/}"
SPIDERWEB_WORKSPACE_ID="${SPIDERWEB_WORKSPACE_ID:-}"
SPIDERWEB_WORKSPACE_TOKEN="${SPIDERWEB_WORKSPACE_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN="${SPIDERWEB_AUTH_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN_FILE="${SPIDERWEB_AUTH_TOKEN_FILE:-}"
SPIDERWEB_CONFIG_BIN="${SPIDERWEB_CONFIG_BIN:-spiderweb-config}"
EXPECTED_NODES="${EXPECTED_NODES:-}"
SMOKE_TIMEOUT_SEC="${SMOKE_TIMEOUT_SEC:-15}"
SMOKE_FAIL_ON_DEGRADED="${SMOKE_FAIL_ON_DEGRADED:-1}"
SMOKE_CONNECT_RETRIES="${SMOKE_CONNECT_RETRIES:-8}"
SMOKE_RETRY_DELAY_MS="${SMOKE_RETRY_DELAY_MS:-500}"
SPIDERWEB_SERVICE="${SPIDERWEB_SERVICE:-spiderweb.service}"
SPIDERWEB_SERVICE_SCOPE="${SPIDERWEB_SERVICE_SCOPE:-auto}"

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

resolve_auth_token_file() {
    if command -v "$SPIDERWEB_CONFIG_BIN" >/dev/null 2>&1; then
        local resolved
        resolved="$("$SPIDERWEB_CONFIG_BIN" auth path 2>/dev/null | tr -d '\r' | tail -n 1 || true)"
        if [[ -n "$resolved" ]]; then
            printf '%s\n' "$resolved"
            return
        fi
    fi
    printf '%s\n' "$HOME/.local/share/ziggy-spiderweb/.spiderweb-ltm/auth_tokens.json"
}

resolve_service_scope() {
    case "$SPIDERWEB_SERVICE_SCOPE" in
        user|system)
            printf '%s\n' "$SPIDERWEB_SERVICE_SCOPE"
            ;;
        auto)
            if command -v systemctl >/dev/null 2>&1 && systemctl --user show "$SPIDERWEB_SERVICE" >/dev/null 2>&1; then
                printf 'user\n'
            elif command -v systemctl >/dev/null 2>&1 && systemctl show "$SPIDERWEB_SERVICE" >/dev/null 2>&1; then
                printf 'system\n'
            else
                printf 'unknown\n'
            fi
            ;;
        *)
            echo "error: invalid SPIDERWEB_SERVICE_SCOPE: $SPIDERWEB_SERVICE_SCOPE" >&2
            exit 2
            ;;
    esac
}

if [[ -z "$SPIDERWEB_AUTH_TOKEN_FILE" ]]; then
    SPIDERWEB_AUTH_TOKEN_FILE="$(resolve_auth_token_file)"
fi

service_scope="$(resolve_service_scope)"
if [[ "$service_scope" == "user" ]]; then
    restrict_namespaces="$(systemctl --user show "$SPIDERWEB_SERVICE" -p RestrictNamespaces --value 2>/dev/null || true)"
elif [[ "$service_scope" == "system" ]]; then
    restrict_namespaces="$(systemctl show "$SPIDERWEB_SERVICE" -p RestrictNamespaces --value 2>/dev/null || true)"
else
    restrict_namespaces=""
fi
if [[ -n "$restrict_namespaces" ]]; then
    if [[ "$restrict_namespaces" == "yes" ]]; then
        echo "error: $SPIDERWEB_SERVICE has RestrictNamespaces=yes; sandbox runtime/bwrap will fail" >&2
        echo "hint: reinstall with scripts/install-systemd.sh or set RestrictNamespaces=false in the unit" >&2
        exit 1
    fi
fi

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
if [[ -n "$SPIDERWEB_WORKSPACE_ID" ]]; then
    mount_args+=(--workspace-id "$SPIDERWEB_WORKSPACE_ID")
fi
if [[ -n "$SPIDERWEB_WORKSPACE_TOKEN" ]]; then
    mount_args+=(--workspace-token "$SPIDERWEB_WORKSPACE_TOKEN")
fi

payload='{}'
if [[ -n "$SPIDERWEB_WORKSPACE_ID" ]]; then
    if [[ -n "$SPIDERWEB_WORKSPACE_TOKEN" ]]; then
        payload="$(jq -cn --arg workspace_id "$SPIDERWEB_WORKSPACE_ID" --arg workspace_token "$SPIDERWEB_WORKSPACE_TOKEN" '{workspace_id: $workspace_id, workspace_token: $workspace_token}')"
    else
        payload="$(jq -cn --arg workspace_id "$SPIDERWEB_WORKSPACE_ID" '{workspace_id: $workspace_id}')"
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
workspace_id_resolved="$(jq -r '.payload.workspace_id // .payload.project_id // "(none)"' <<<"$reply")"

echo "workspace id: ${workspace_id_resolved}"
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
