#!/usr/bin/env bash
# Distributed workspace bootstrap scenario:
# - start spiderweb + two nodes
# - join nodes through control-plane
# - run control.project_up with desired mounts
# - verify workspace desired/actual/drift shape

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
SPIDERWEB_PORT="${SPIDERWEB_PORT:-28790}"
NODE1_PORT="${NODE1_PORT:-28911}"
NODE2_PORT="${NODE2_PORT:-28912}"

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
    if [[ -n "${NODE2_PID:-}" ]]; then kill "$NODE2_PID" >/dev/null 2>&1 || true; wait "$NODE2_PID" >/dev/null 2>&1 || true; fi
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
SPIDER_WEB_ROOT="$TEST_TMP_DIR/spider-web-root"
NODE1_EXPORT="$TEST_TMP_DIR/node1-export"
NODE2_EXPORT="$TEST_TMP_DIR/node2-export"
mkdir -p "$LTM_DIR" "$SPIDER_WEB_ROOT" "$NODE1_EXPORT" "$NODE2_EXPORT"
echo "bootstrap-node-1" > "$NODE1_EXPORT/bootstrap.txt"
echo "bootstrap-node-2" > "$NODE2_EXPORT/bootstrap.txt"

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
    "ltm_filename": "runtime-memory.db",
    "spider_web_root": "$SPIDER_WEB_ROOT"
  }
}
EOF

SPIDERWEB_LOG="$TEST_TMP_DIR/spiderweb.log"
NODE1_LOG="$TEST_TMP_DIR/node1.log"
NODE2_LOG="$TEST_TMP_DIR/node2.log"

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

log_info "Starting filesystem nodes ..."
"$FS_NODE_BIN" --bind "$BIND_ADDR" --port "$NODE1_PORT" --export "work=$NODE1_EXPORT:rw" > "$NODE1_LOG" 2>&1 &
NODE1_PID="$!"
"$FS_NODE_BIN" --bind "$BIND_ADDR" --port "$NODE2_PORT" --export "work=$NODE2_EXPORT:rw" > "$NODE2_LOG" 2>&1 &
NODE2_PID="$!"

if ! wait_for_node_ready "$NODE1_PORT"; then
    log_fail "node 1 did not become ready"
    cat "$NODE1_LOG"
    exit 1
fi
if ! wait_for_node_ready "$NODE2_PORT"; then
    log_fail "node 2 did not become ready"
    cat "$NODE2_LOG"
    exit 1
fi
log_pass "node endpoints are ready"

INVITE_A="$(control_call node_invite_create)"
INVITE_A_TOKEN="$(json_query "$INVITE_A" "payload.invite_token")"
JOIN_A_PAYLOAD="$(printf '{"invite_token":"%s","node_name":"node-a","fs_url":"ws://%s:%s/v2/fs"}' "$INVITE_A_TOKEN" "$BIND_ADDR" "$NODE1_PORT")"
JOIN_A="$(control_call node_join "$JOIN_A_PAYLOAD")"
NODE_A_ID="$(json_query "$JOIN_A" "payload.node_id")"

INVITE_B="$(control_call node_invite_create)"
INVITE_B_TOKEN="$(json_query "$INVITE_B" "payload.invite_token")"
JOIN_B_PAYLOAD="$(printf '{"invite_token":"%s","node_name":"node-b","fs_url":"ws://%s:%s/v2/fs"}' "$INVITE_B_TOKEN" "$BIND_ADDR" "$NODE2_PORT")"
JOIN_B="$(control_call node_join "$JOIN_B_PAYLOAD")"
NODE_B_ID="$(json_query "$JOIN_B" "payload.node_id")"

PROJECT_NAME="Bootstrap Matrix $(date +%s)"
PROJECT_UP_PAYLOAD="$(printf '{"name":"%s","activate":true,"desired_mounts":[{"mount_path":"/workspace","node_id":"%s","export_name":"work"},{"mount_path":"/workspace","node_id":"%s","export_name":"work"}]}' "$PROJECT_NAME" "$NODE_A_ID" "$NODE_B_ID")"
PROJECT_UP_RESP="$(control_call project_up "$PROJECT_UP_PAYLOAD")"

PROJECT_ID="$(json_query "$PROJECT_UP_RESP" "payload.project_id")"
PROJECT_TOKEN="$(json_query "$PROJECT_UP_RESP" "payload.project_token")"
CREATED="$(json_query "$PROJECT_UP_RESP" "payload.created")"
ACTIVATED="$(json_query "$PROJECT_UP_RESP" "payload.activated")"
WORKSPACE_MOUNTS_JSON="$(json_query "$PROJECT_UP_RESP" "payload.workspace.mounts")"
WORKSPACE_DESIRED_JSON="$(json_query "$PROJECT_UP_RESP" "payload.workspace.desired_mounts")"
WORKSPACE_ACTUAL_JSON="$(json_query "$PROJECT_UP_RESP" "payload.workspace.actual_mounts")"

if [[ -z "$PROJECT_ID" || -z "$PROJECT_TOKEN" ]]; then
    log_fail "project_up response missing project id/token"
    echo "$PROJECT_UP_RESP"
    exit 1
fi
if [[ "$CREATED" != "true" && "$CREATED" != "false" ]]; then
    log_fail "project_up response missing created flag"
    echo "$PROJECT_UP_RESP"
    exit 1
fi
if [[ "$ACTIVATED" != "true" ]]; then
    log_fail "project_up did not activate project"
    echo "$PROJECT_UP_RESP"
    exit 1
fi

python3 - "$WORKSPACE_MOUNTS_JSON" "$WORKSPACE_DESIRED_JSON" "$WORKSPACE_ACTUAL_JSON" <<'PY'
import json
import sys

mounts = json.loads(sys.argv[1])
desired = json.loads(sys.argv[2])
actual = json.loads(sys.argv[3])
if len(desired) == 0:
    raise SystemExit("expected desired_mounts to be non-empty")
if len(mounts) == 0 and len(actual) == 0:
    raise SystemExit("expected at least one effective/actual mount")
PY

STATUS_RESP="$(control_call workspace_status "$(printf '{"project_id":"%s"}' "$PROJECT_ID")")"
STATUS_PROJECT_ID="$(json_query "$STATUS_RESP" "payload.project_id")"
STATUS_DRIFT_COUNT="$(json_query "$STATUS_RESP" "payload.drift.count")"
if [[ "$STATUS_PROJECT_ID" != "$PROJECT_ID" ]]; then
    log_fail "workspace_status project mismatch"
    echo "$STATUS_RESP"
    exit 1
fi
if [[ -z "$STATUS_DRIFT_COUNT" ]]; then
    log_fail "workspace_status missing drift count"
    echo "$STATUS_RESP"
    exit 1
fi

log_pass "bootstrap scenario validated project_up + workspace desired/actual/drift payload"
