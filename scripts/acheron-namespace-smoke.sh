#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

SPIDERWEB_URL="${SPIDERWEB_URL:-ws://127.0.0.1:18790/}"
SPIDERWEB_WORKSPACE_ID="${SPIDERWEB_WORKSPACE_ID:-}"
SPIDERWEB_WORKSPACE_TOKEN="${SPIDERWEB_WORKSPACE_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN="${SPIDERWEB_AUTH_TOKEN:-}"
SPIDERWEB_AUTH_TOKEN_FILE="${SPIDERWEB_AUTH_TOKEN_FILE:-$HOME/.local/share/ziggy-spiderweb/.spiderweb-ltm/auth_tokens.json}"
SPIDERWEB_AGENT_ID="${SPIDERWEB_AGENT_ID:-}"
SPIDERWEB_SESSION_KEY="${SPIDERWEB_SESSION_KEY:-}"
SPIDERWEB_MOUNT_BACKEND="${SPIDERWEB_MOUNT_BACKEND:-auto}"
SPIDERWEB_FS_MOUNT_BIN="${SPIDERWEB_FS_MOUNT_BIN:-}"
SMOKE_TIMEOUT_SEC="${SMOKE_TIMEOUT_SEC:-20}"
SMOKE_CONNECT_RETRIES="${SMOKE_CONNECT_RETRIES:-8}"
SMOKE_RETRY_DELAY_MS="${SMOKE_RETRY_DELAY_MS:-500}"
SMOKE_REQUIRE_ROUTED_FS="${SMOKE_REQUIRE_ROUTED_FS:-1}"
SMOKE_WRITE_PATH="${SMOKE_WRITE_PATH:-}"
SMOKE_WRITE_RELATIVE_PATH="${SMOKE_WRITE_RELATIVE_PATH:-.spiderweb-fs-mount-smoke.txt}"
SMOKE_WRITE_CONTENT="${SMOKE_WRITE_CONTENT:-spiderweb-fs-mount-smoke-$(date +%s)}"
SMOKE_PROTOCOL_PATH="${SMOKE_PROTOCOL_PATH:-/meta/protocol.json}"
SMOKE_UNSUPPORTED_TARGET="${SMOKE_UNSUPPORTED_TARGET:-/projects/__spiderweb_fs_mount_smoke__}"
SMOKE_USE_OS_MOUNT="${SMOKE_USE_OS_MOUNT:-0}"
SMOKE_MOUNTPOINT="${SMOKE_MOUNTPOINT:-}"

resolve_bin() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return
    fi
    local cache_candidate
    cache_candidate="$(find "$REPO_ROOT/.zig-cache" -type f -name "$name" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || true)"
    if [[ -n "$cache_candidate" ]]; then
        printf '%s\n' "$cache_candidate"
        return
    fi
    if [[ -x "$REPO_ROOT/zig-out/bin/$name" ]]; then
        printf '%s\n' "$REPO_ROOT/zig-out/bin/$name"
        return
    fi
    echo "error: required binary not found: $name" >&2
    exit 2
}

require_bin() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required binary not found: $1" >&2
        exit 2
    fi
}

sleep_seconds_from_ms() {
    awk "BEGIN {print $1/1000}"
}

if [[ -n "$SPIDERWEB_FS_MOUNT_BIN" ]]; then
    FS_MOUNT_BIN="$SPIDERWEB_FS_MOUNT_BIN"
else
    FS_MOUNT_BIN="$(resolve_bin spiderweb-fs-mount)"
fi
require_bin jq
require_bin timeout

if [[ -z "$SPIDERWEB_AUTH_TOKEN" && -f "$SPIDERWEB_AUTH_TOKEN_FILE" ]]; then
    SPIDERWEB_AUTH_TOKEN="$(jq -r '.admin_token // .user_token // empty' "$SPIDERWEB_AUTH_TOKEN_FILE" 2>/dev/null || true)"
fi

mount_args=(--namespace-url "$SPIDERWEB_URL" --mount-backend "$SPIDERWEB_MOUNT_BACKEND")
if [[ -n "$SPIDERWEB_WORKSPACE_ID" ]]; then
    mount_args+=(--workspace-id "$SPIDERWEB_WORKSPACE_ID")
fi
if [[ -n "$SPIDERWEB_WORKSPACE_TOKEN" ]]; then
    mount_args+=(--workspace-token "$SPIDERWEB_WORKSPACE_TOKEN")
fi
if [[ -n "$SPIDERWEB_AUTH_TOKEN" ]]; then
    mount_args+=(--auth-token "$SPIDERWEB_AUTH_TOKEN")
fi
if [[ -n "$SPIDERWEB_AGENT_ID" ]]; then
    mount_args+=(--agent-id "$SPIDERWEB_AGENT_ID")
fi
if [[ -n "$SPIDERWEB_SESSION_KEY" ]]; then
    mount_args+=(--session-key "$SPIDERWEB_SESSION_KEY")
fi

run_fs_mount() {
    timeout "${SMOKE_TIMEOUT_SEC}s" "$FS_MOUNT_BIN" "${mount_args[@]}" "$@"
}

status_json=""
attempt=1
while true; do
    if status_json="$(run_fs_mount status --no-probe 2>&1)"; then
        if jq -e '.mode == "namespace"' >/dev/null 2>&1 <<<"$status_json"; then
            break
        fi
    fi
    if [[ "$attempt" -ge "$SMOKE_CONNECT_RETRIES" ]]; then
        echo "error: namespace status probe failed" >&2
        echo "$status_json" >&2
        exit 1
    fi
    sleep "$(sleep_seconds_from_ms "$SMOKE_RETRY_DELAY_MS")"
    attempt=$((attempt + 1))
done

resolved_project_id="$(jq -r '.project_id // empty' <<<"$status_json")"
resolved_agent_id="$(jq -r '.agent_id // empty' <<<"$status_json")"
echo "namespace workspace: ${resolved_project_id:-"(none)"}"
echo "namespace agent: ${resolved_agent_id:-"(none)"}"

for path in /agents /nodes /global; do
    echo "checking namespace path: $path"
    run_fs_mount getattr "$path" >/dev/null
done

protocol_json="$(run_fs_mount cat "$SMOKE_PROTOCOL_PATH")"
if ! jq -e . >/dev/null 2>&1 <<<"$protocol_json"; then
    echo "error: protocol payload is not valid JSON at $SMOKE_PROTOCOL_PATH" >&2
    exit 1
fi
echo "protocol file read ok: $SMOKE_PROTOCOL_PATH"

write_path="$SMOKE_WRITE_PATH"
if [[ -z "$write_path" ]]; then
    routed_mount="$(
        jq -r '
            (.router.endpoints // [])[]
            | select(.export_ro != true)
            | select(.source_kind == "fs" or (.mount_path | startswith("/nodes/")))
            | .mount_path
        ' <<<"$status_json" | head -n 1
    )"
    if [[ -n "$routed_mount" && "$routed_mount" != "null" ]]; then
        write_path="${routed_mount%/}/${SMOKE_WRITE_RELATIVE_PATH}"
    fi
fi

if [[ -n "$write_path" ]]; then
    echo "writing routed file: $write_path"
    run_fs_mount write "$write_path" "$SMOKE_WRITE_CONTENT" >/dev/null
    read_back="$(run_fs_mount cat "$write_path")"
    if [[ "$read_back" != "$SMOKE_WRITE_CONTENT" ]]; then
        echo "error: routed write verification failed for $write_path" >&2
        exit 1
    fi
elif [[ "$SMOKE_REQUIRE_ROUTED_FS" == "1" ]]; then
    echo "error: no writable routed filesystem export was discovered" >&2
    exit 1
else
    echo "routed fs write skipped: no writable routed export discovered"
fi

unsupported_output=""
if unsupported_output="$(run_fs_mount mkdir "$SMOKE_UNSUPPORTED_TARGET" 2>&1)"; then
    echo "error: synthetic namespace mkdir unexpectedly succeeded: $SMOKE_UNSUPPORTED_TARGET" >&2
    exit 1
fi
echo "synthetic mutation failed as expected: $SMOKE_UNSUPPORTED_TARGET"

mount_pid=""
mountpoint=""
created_mountpoint=0
mount_log=""
cleanup_mount() {
    if [[ -n "$mount_pid" ]]; then
        if command -v fusermount3 >/dev/null 2>&1 && [[ -n "$mountpoint" ]]; then
            fusermount3 -u "$mountpoint" >/dev/null 2>&1 || true
        elif command -v umount >/dev/null 2>&1 && [[ -n "$mountpoint" ]]; then
            umount "$mountpoint" >/dev/null 2>&1 || true
        fi
        kill "$mount_pid" >/dev/null 2>&1 || true
        wait "$mount_pid" >/dev/null 2>&1 || true
    fi
    if [[ "$created_mountpoint" -eq 1 && -n "$mountpoint" ]]; then
        rmdir "$mountpoint" >/dev/null 2>&1 || true
    fi
    if [[ -n "$mount_log" ]]; then
        rm -f "$mount_log" >/dev/null 2>&1 || true
    fi
}
trap cleanup_mount EXIT

if [[ "$SMOKE_USE_OS_MOUNT" == "1" ]]; then
    if [[ -n "$SMOKE_MOUNTPOINT" ]]; then
        mountpoint="$SMOKE_MOUNTPOINT"
        mkdir -p "$mountpoint"
    else
        mountpoint="$(mktemp -d)"
        created_mountpoint=1
    fi
    mount_log="$(mktemp)"

    "$FS_MOUNT_BIN" "${mount_args[@]}" mount "$mountpoint" >"$mount_log" 2>&1 &
    mount_pid="$!"

    attempt=1
    while true; do
        if [[ -d "$mountpoint/agents" && -d "$mountpoint/nodes" && -d "$mountpoint/global" ]]; then
            break
        fi
        if ! kill -0 "$mount_pid" >/dev/null 2>&1; then
            echo "error: mount process exited before the mount became available" >&2
            cat "$mount_log" >&2 || true
            exit 1
        fi
        if [[ "$attempt" -ge "$SMOKE_CONNECT_RETRIES" ]]; then
            echo "error: mountpoint did not become readable: $mountpoint" >&2
            cat "$mount_log" >&2 || true
            exit 1
        fi
        sleep "$(sleep_seconds_from_ms "$SMOKE_RETRY_DELAY_MS")"
        attempt=$((attempt + 1))
    done

    if ! jq -e . >/dev/null 2>&1 <"$mountpoint${SMOKE_PROTOCOL_PATH}"; then
        echo "error: mounted protocol payload is not valid JSON at $mountpoint${SMOKE_PROTOCOL_PATH}" >&2
        exit 1
    fi

    if [[ -n "$write_path" ]]; then
        mounted_write_path="${mountpoint%/}${write_path}"
        printf '%s' "$SMOKE_WRITE_CONTENT" >"$mounted_write_path"
        mounted_read_back="$(cat "$mounted_write_path")"
        if [[ "$mounted_read_back" != "$SMOKE_WRITE_CONTENT" ]]; then
            echo "error: mounted routed write verification failed for $mounted_write_path" >&2
            exit 1
        fi
    fi

    echo "mounted namespace check passed: $mountpoint"
fi

echo "namespace smoke check passed"
