#!/usr/bin/env bash
# Distributed workspace drift scenario:
# - start spiderweb + one node
# - bootstrap project_up with an intentionally unusual export
# - assert workspace drift metadata is present and well-formed

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
SPIDERWEB_PORT="${SPIDERWEB_PORT:-28790}"
NODE1_PORT="${NODE1_PORT:-28911}"

SPIDERWEB_BIN="$ROOT_DIR/zig-out/bin/spiderweb"
FS_NODE_BIN="$ROOT_DIR/zig-out/bin/embed-multi-service-node"
FS_MOUNT_BIN="$ROOT_DIR/zig-out/bin/spiderweb-fs-mount"
CONTROL_BIN="$ROOT_DIR/zig-out/bin/spiderweb-control"
CONTROL_URL="ws://$BIND_ADDR:$SPIDERWEB_PORT/"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

cleanup() {
    if [[ -n "${NODE1_PID:-}" ]]; then kill "$NODE1_PID" >/dev/null 2>&1 || true; wait "$NODE1_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "${SPIDERWEB_PID:-}" ]]; then kill "$SPIDERWEB_PID" >/dev/null 2>&1 || true; wait "$SPIDERWEB_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "${TEST_TMP_DIR:-}" && -d "$TEST_TMP_DIR" ]]; then rm -rf "$TEST_TMP_DIR"; fi
}
trap cleanup EXIT

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    log_info "Building binaries (zig build)..."
    (cd "$ROOT_DIR" && zig build)
fi

for bin in "$SPIDERWEB_BIN" "$FS_NODE_BIN" "$FS_MOUNT_BIN" "$CONTROL_BIN"; do
    if [[ ! -x "$bin" ]]; then
        log_fail "Missing binary: $bin"
        exit 1
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    log_fail "python3 is required"
    exit 1
fi

CONTROL_ARGS=(--url "$CONTROL_URL")
if [[ -n "${SPIDERWEB_CONTROL_OPERATOR_TOKEN:-}" ]]; then
    CONTROL_ARGS+=(--operator-token "$SPIDERWEB_CONTROL_OPERATOR_TOKEN")
fi

control_call() {
    local op="$1"
    local payload="${2-}"
    if [[ -n "$payload" ]]; then
        "$CONTROL_BIN" "${CONTROL_ARGS[@]}" "$op" "$payload"
    else
        "$CONTROL_BIN" "${CONTROL_ARGS[@]}" "$op"
    fi
}

json_query() {
    local json="$1"
    local path="$2"
    python3 - "$json" "$path" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
path = sys.argv[2].split(".")
cur = data
for part in path:
    if part == "":
        continue
    if isinstance(cur, list):
        cur = cur[int(part)]
    else:
        cur = cur[part]
if isinstance(cur, bool):
    print("true" if cur else "false")
elif cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
PY
}

wait_for_control_ready() {
    for _ in $(seq 1 120); do
        if control_call workspace_status >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_for_node_ready() {
    local port="$1"
    local endpoint="tmp=ws://$BIND_ADDR:$port/v2/fs#work"
    for _ in $(seq 1 120); do
        if "$FS_MOUNT_BIN" --endpoint "$endpoint" readdir /tmp >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

TEST_TMP_DIR="$(mktemp -d)"
LTM_DIR="$TEST_TMP_DIR/ltm"
NODE1_EXPORT="$TEST_TMP_DIR/node1-export"
mkdir -p "$LTM_DIR" "$NODE1_EXPORT"
echo "drift-node-1" > "$NODE1_EXPORT/drift.txt"

SPIDERWEB_CONFIG_FILE="$TEST_TMP_DIR/spiderweb.json"
cat > "$SPIDERWEB_CONFIG_FILE" <<EOF
{
  "provider": {
    "name": "openai",
    "model": "gpt-4o-mini"
  },
  "runtime": {
    "default_agent_id": "default",
    "ltm_directory": "$LTM_DIR",
    "ltm_filename": "runtime-memory.db"
  }
}
EOF

SPIDERWEB_LOG="$TEST_TMP_DIR/spiderweb.log"
NODE1_LOG="$TEST_TMP_DIR/node1.log"

log_info "Starting spiderweb on ws://$BIND_ADDR:$SPIDERWEB_PORT ..."
(
    cd "$ROOT_DIR"
    SPIDERWEB_CONFIG="$SPIDERWEB_CONFIG_FILE" \
        "$SPIDERWEB_BIN" \
        --bind "$BIND_ADDR" \
        --port "$SPIDERWEB_PORT" \
        >> "$SPIDERWEB_LOG" 2>&1
) &
SPIDERWEB_PID="$!"

if ! wait_for_control_ready; then
    log_fail "spiderweb did not become ready"
    cat "$SPIDERWEB_LOG"
    exit 1
fi

log_info "Starting filesystem node ..."
"$FS_NODE_BIN" --bind "$BIND_ADDR" --port "$NODE1_PORT" --export "work=$NODE1_EXPORT:rw" > "$NODE1_LOG" 2>&1 &
NODE1_PID="$!"
if ! wait_for_node_ready "$NODE1_PORT"; then
    log_fail "node did not become ready"
    cat "$NODE1_LOG"
    exit 1
fi
log_pass "node endpoint is ready"

INVITE="$(control_call node_invite_create)"
INVITE_TOKEN="$(json_query "$INVITE" "payload.invite_token")"
JOIN_PAYLOAD="$(printf '{"invite_token":"%s","node_name":"node-drift","fs_url":"ws://%s:%s/v2/fs"}' "$INVITE_TOKEN" "$BIND_ADDR" "$NODE1_PORT")"
JOIN_RESP="$(control_call node_join "$JOIN_PAYLOAD")"
NODE_ID="$(json_query "$JOIN_RESP" "payload.node_id")"

PROJECT_NAME="Drift Matrix $(date +%s)"
# Use export_name=missing to exercise desired/actual drift metadata paths.
PROJECT_UP_PAYLOAD="$(printf '{"name":"%s","activate":true,"desired_mounts":[{"mount_path":"/broken","node_id":"%s","export_name":"missing"}]}' "$PROJECT_NAME" "$NODE_ID")"
PROJECT_UP_RESP="$(control_call project_up "$PROJECT_UP_PAYLOAD")"
PROJECT_ID="$(json_query "$PROJECT_UP_RESP" "payload.project_id")"

if [[ -z "$PROJECT_ID" ]]; then
    log_fail "project_up response missing project id"
    echo "$PROJECT_UP_RESP"
    exit 1
fi

DRIFT_COUNT=0
RECONCILE_STATE=""
LAST_ERROR=""
for _ in $(seq 1 40); do
    STATUS_RESP="$(control_call workspace_status "$(printf '{"project_id":"%s"}' "$PROJECT_ID")")"
    DRIFT_COUNT="$(json_query "$STATUS_RESP" "payload.drift.count")"
    RECONCILE_STATE="$(json_query "$STATUS_RESP" "payload.reconcile_state")"
    LAST_ERROR="$(json_query "$STATUS_RESP" "payload.last_error")"
    if [[ "$DRIFT_COUNT" =~ ^[0-9]+$ ]]; then
        break
    fi
    sleep 0.25
done

if [[ ! "$DRIFT_COUNT" =~ ^[0-9]+$ ]]; then
    log_fail "expected numeric drift.count, got: $DRIFT_COUNT"
    echo "$STATUS_RESP"
    exit 1
fi

log_pass "drift scenario validated (drift.count=$DRIFT_COUNT state=$RECONCILE_STATE last_error=$LAST_ERROR)"
