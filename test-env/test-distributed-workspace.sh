#!/usr/bin/env bash
# End-to-end distributed workspace test:
# - start spiderweb control server
# - start two filesystem nodes
# - invite/join both nodes through control v2
# - create+activate project
# - mount both nodes on same mount_path for failover
# - verify read succeeds, then kill primary and verify failover

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
SPIDERWEB_PORT="${SPIDERWEB_PORT:-28790}"
SPIDERWEB_METRICS_PORT="${SPIDERWEB_METRICS_PORT:-0}"
NODE1_PORT="${NODE1_PORT:-28911}"
NODE2_PORT="${NODE2_PORT:-28912}"

SPIDERWEB_BIN="$ROOT_DIR/zig-out/bin/spiderweb"
FS_NODE_BIN="$ROOT_DIR/zig-out/bin/embed-multi-service-node"
FS_MOUNT_BIN="$ROOT_DIR/zig-out/bin/spiderweb-fs-mount"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

cleanup() {
    if [[ -n "${NODE1_PID:-}" ]]; then
        kill "$NODE1_PID" >/dev/null 2>&1 || true
        wait "$NODE1_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${NODE2_PID:-}" ]]; then
        kill "$NODE2_PID" >/dev/null 2>&1 || true
        wait "$NODE2_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${SPIDERWEB_PID:-}" ]]; then
        kill "$SPIDERWEB_PID" >/dev/null 2>&1 || true
        wait "$SPIDERWEB_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${TEST_TMP_DIR:-}" && -d "$TEST_TMP_DIR" ]]; then
        rm -rf "$TEST_TMP_DIR"
    fi
}
trap cleanup EXIT

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    log_info "Building binaries (zig build)..."
    (cd "$ROOT_DIR" && zig build)
fi

for bin in "$SPIDERWEB_BIN" "$FS_NODE_BIN" "$FS_MOUNT_BIN"; do
    if [[ ! -x "$bin" ]]; then
        log_fail "Missing binary: $bin"
        exit 1
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    log_fail "python3 is required"
    exit 1
fi

TEST_TMP_DIR="$(mktemp -d)"
LTM_DIR="$TEST_TMP_DIR/ltm"
NODE1_EXPORT="$TEST_TMP_DIR/node1-export"
NODE2_EXPORT="$TEST_TMP_DIR/node2-export"
mkdir -p "$LTM_DIR" "$NODE1_EXPORT" "$NODE2_EXPORT"

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

FIXTURE_NAME="failover.txt"
NODE1_CONTENT="alpha-primary-content"
NODE2_CONTENT="beta-failover-content"
printf '%s\n' "$NODE1_CONTENT" > "$NODE1_EXPORT/$FIXTURE_NAME"
printf '%s\n' "$NODE2_CONTENT" > "$NODE2_EXPORT/$FIXTURE_NAME"

SPIDERWEB_LOG="$TEST_TMP_DIR/spiderweb.log"
NODE1_LOG="$TEST_TMP_DIR/node1.log"
NODE2_LOG="$TEST_TMP_DIR/node2.log"

start_spiderweb() {
    log_info "Starting spiderweb control server on ws://$BIND_ADDR:$SPIDERWEB_PORT ..."
    (
        cd "$ROOT_DIR"
        SPIDERWEB_CONFIG="$SPIDERWEB_CONFIG_FILE" \
            SPIDERWEB_METRICS_PORT="$SPIDERWEB_METRICS_PORT" \
            "$SPIDERWEB_BIN" \
            --bind "$BIND_ADDR" \
            --port "$SPIDERWEB_PORT" \
            >> "$SPIDERWEB_LOG" 2>&1
    ) &
    SPIDERWEB_PID="$!"
}

start_spiderweb

wait_for_control_ready() {
    local ready=0
    for _ in $(seq 1 120); do
        if ! kill -0 "$SPIDERWEB_PID" >/dev/null 2>&1; then
            return 1
        fi
        if python3 - "$BIND_ADDR" "$SPIDERWEB_PORT" <<'PY' >/dev/null 2>&1
import base64
import json
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

def read_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("eof")
        out.extend(chunk)
    return bytes(out)

def write_text(sock, payload):
    data = payload.encode("utf-8")
    header = bytearray([0x81])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(n.to_bytes(8, "big"))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytearray(data)
    for i in range(n):
        masked[i] ^= mask[i % 4]
    sock.sendall(header + masked)

def read_text(sock):
    while True:
        b0, b1 = read_exact(sock, 2)
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(read_exact(sock, 2), "big")
        elif n == 127:
            n = int.from_bytes(read_exact(sock, 8), "big")
        if masked:
            mask = read_exact(sock, 4)
            data = bytearray(read_exact(sock, n))
            for i in range(n):
                data[i] ^= mask[i % 4]
            payload = bytes(data)
        else:
            payload = read_exact(sock, n)
        if opcode == 0x9:
            header = bytearray([0x8A])
            m = len(payload)
            if m < 126:
                header.append(0x80 | m)
            elif m < 65536:
                header.append(0x80 | 126)
                header.extend(m.to_bytes(2, "big"))
            else:
                header.append(0x80 | 127)
                header.extend(m.to_bytes(8, "big"))
            pong_mask = os.urandom(4)
            header.extend(pong_mask)
            masked_payload = bytearray(payload)
            for i in range(m):
                masked_payload[i] ^= pong_mask[i % 4]
            sock.sendall(header + masked_payload)
            continue
        if opcode == 0x1:
            return json.loads(payload.decode("utf-8"))
        if opcode == 0x8:
            raise RuntimeError("closed")

sock = socket.create_connection((host, port), timeout=2)
sock.settimeout(2)
try:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(req)
    raw = b""
    while b"\r\n\r\n" not in raw:
        raw += sock.recv(4096)
    status = raw.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise RuntimeError("bad status")

    write_text(sock, json.dumps({
        "channel": "control",
        "type": "control.version",
        "id": "ready-version",
        "payload": {"protocol": "unified-v2"},
    }, separators=(",", ":")))
    msg = read_text(sock)
    if msg.get("type") != "control.version_ack":
        raise RuntimeError("no version ack")

    write_text(sock, json.dumps({
        "channel": "control",
        "type": "control.connect",
        "id": "ready-connect",
    }, separators=(",", ":")))
    msg = read_text(sock)
    if msg.get("type") != "control.connect_ack":
        raise RuntimeError("no connect ack")
finally:
    sock.close()
PY
        then
            ready=1
            break
        fi
        sleep 0.1
    done
    [[ "$ready" -eq 1 ]]
}

if ! wait_for_control_ready; then
    log_fail "spiderweb did not become ready"
    echo "--- spiderweb log ---"
    cat "$SPIDERWEB_LOG"
    exit 1
fi
log_pass "spiderweb control endpoint is ready"

if [[ "${ASSERT_OPERATOR_TOKEN_GATE:-0}" == "1" ]]; then
    if [[ -z "${SPIDERWEB_CONTROL_OPERATOR_TOKEN:-}" ]]; then
        log_fail "ASSERT_OPERATOR_TOKEN_GATE=1 requires SPIDERWEB_CONTROL_OPERATOR_TOKEN"
        exit 1
    fi
    log_info "Validating operator-token gate (reject missing/wrong, allow correct)..."
    python3 - "$BIND_ADDR" "$SPIDERWEB_PORT" "$SPIDERWEB_CONTROL_OPERATOR_TOKEN" <<'PY'
import base64
import json
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
operator_token = sys.argv[3]

def read_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("connection closed")
        out.extend(chunk)
    return bytes(out)

def write_frame(sock, opcode, payload):
    data = payload if isinstance(payload, (bytes, bytearray)) else payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(n.to_bytes(8, "big"))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytearray(data)
    for i in range(n):
        masked[i] ^= mask[i % 4]
    sock.sendall(header + masked)

def read_message(sock):
    while True:
        b0, b1 = read_exact(sock, 2)
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(read_exact(sock, 2), "big")
        elif n == 127:
            n = int.from_bytes(read_exact(sock, 8), "big")
        if masked:
            mask = read_exact(sock, 4)
            data = bytearray(read_exact(sock, n))
            for i in range(n):
                data[i] ^= mask[i % 4]
            payload = bytes(data)
        else:
            payload = read_exact(sock, n)
        if opcode == 0x9:
            write_frame(sock, 0xA, payload)
            continue
        if opcode == 0xA:
            continue
        if opcode == 0x8:
            raise RuntimeError("closed")
        if opcode != 0x1:
            continue
        return json.loads(payload.decode("utf-8"))

def call(sock, op, payload, request_id):
    msg = {"channel": "control", "type": f"control.{op}", "id": request_id}
    if payload is not None:
        msg["payload"] = payload
    write_frame(sock, 0x1, json.dumps(msg, separators=(",", ":")))
    while True:
        reply = read_message(sock)
        if reply.get("channel") != "control":
            continue
        if reply.get("id") != request_id:
            continue
        return reply

sock = socket.create_connection((host, port), timeout=3)
sock.settimeout(3)
try:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(req)
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("handshake closed")
        raw += chunk
    status = raw.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise RuntimeError(f"handshake failed: {status.decode('utf-8', 'replace')}")

    version = call(sock, "version", {"protocol": "unified-v2"}, "gate-version")
    if version.get("type") != "control.version_ack":
        raise RuntimeError(f"expected version_ack, got {json.dumps(version)}")

    connect = call(sock, "connect", {}, "gate-connect")
    if connect.get("type") != "control.connect_ack":
        raise RuntimeError(f"expected connect_ack, got {json.dumps(connect)}")

    missing = call(
        sock,
        "project_create",
        {"name": "Gate Missing", "vision": "operator gate check"},
        "gate-missing",
    )
    if missing.get("type") != "control.error":
        raise RuntimeError(f"missing token unexpectedly allowed: {json.dumps(missing)}")

    wrong = call(
        sock,
        "project_create",
        {
            "name": "Gate Wrong",
            "vision": "operator gate check",
            "operator_token": "definitely-wrong",
        },
        "gate-wrong",
    )
    if wrong.get("type") != "control.error":
        raise RuntimeError(f"wrong token unexpectedly allowed: {json.dumps(wrong)}")
    wrong_code = (((wrong.get("error") or {}).get("code")) or "")
    if wrong_code != "operator_auth_failed":
        raise RuntimeError(f"expected operator_auth_failed for wrong token: {json.dumps(wrong)}")

    ok = call(
        sock,
        "project_create",
        {
            "name": "Gate Allowed",
            "vision": "operator gate check",
            "operator_token": operator_token,
        },
        "gate-good",
    )
    if ok.get("type") != "control.project_create":
        raise RuntimeError(f"correct token was rejected: {json.dumps(ok)}")
    payload = ok.get("payload") or {}
    project_id = payload.get("project_id")
    project_token = payload.get("project_token")
    if not project_id or not project_token:
        raise RuntimeError(f"project_create payload missing ids: {json.dumps(ok)}")

    deleted = call(
        sock,
        "project_delete",
        {
            "project_id": project_id,
            "project_token": project_token,
            "operator_token": operator_token,
        },
        "gate-delete",
    )
    if deleted.get("type") != "control.project_delete":
        raise RuntimeError(f"cleanup delete failed: {json.dumps(deleted)}")
finally:
    try:
        write_frame(sock, 0x8, b"")
    except Exception:
        pass
    sock.close()
PY
    log_pass "operator-token gate validated"
fi

if [[ "$SPIDERWEB_METRICS_PORT" -gt 0 ]]; then
    if ! python3 - "$BIND_ADDR" "$SPIDERWEB_METRICS_PORT" <<'PY' >/dev/null 2>&1
import json
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

def request(path):
    sock = socket.create_connection((host, port), timeout=2)
    sock.settimeout(2)
    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendall(req)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.partition(b"\r\n\r\n")
    finally:
        sock.close()

head, _, body = request("/livez")
if b"200 OK" not in head:
    raise RuntimeError("livez status not 200")
if b"ok" not in body.lower():
    raise RuntimeError("livez body missing ok")

head, _, body = request("/readyz")
if b"200 OK" not in head:
    raise RuntimeError("readyz status not 200")
if b"ready" not in body.lower():
    raise RuntimeError("readyz body missing ready")

head, _, body = request("/metrics")
if b"200 OK" not in head:
    raise RuntimeError("metrics status not 200")
if b"spiderweb_nodes_total" not in body:
    raise RuntimeError("prometheus metrics missing spiderweb_nodes_total")

head, _, body = request("/metrics.json")
if b"200 OK" not in head:
    raise RuntimeError("metrics.json status not 200")
payload = json.loads(body.decode("utf-8"))
if "nodes" not in payload or "projects" not in payload:
    raise RuntimeError("metrics.json payload missing keys")
PY
    then
        log_fail "metrics endpoint did not become ready"
        echo "--- spiderweb log ---"
        cat "$SPIDERWEB_LOG"
        exit 1
    fi
    log_pass "metrics endpoint is ready"
fi

log_info "Starting node A at ws://$BIND_ADDR:$NODE1_PORT/v2/fs ..."
"$FS_NODE_BIN" \
    --bind "$BIND_ADDR" \
    --port "$NODE1_PORT" \
    --export "work=$NODE1_EXPORT:rw" \
    > "$NODE1_LOG" 2>&1 &
NODE1_PID="$!"

log_info "Starting node B at ws://$BIND_ADDR:$NODE2_PORT/v2/fs ..."
"$FS_NODE_BIN" \
    --bind "$BIND_ADDR" \
    --port "$NODE2_PORT" \
    --export "work=$NODE2_EXPORT:rw" \
    > "$NODE2_LOG" 2>&1 &
NODE2_PID="$!"

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

if ! wait_for_node_ready "$NODE1_PORT"; then
    log_fail "node A did not become ready"
    echo "--- node A log ---"
    cat "$NODE1_LOG"
    exit 1
fi
if ! wait_for_node_ready "$NODE2_PORT"; then
    log_fail "node B did not become ready"
    echo "--- node B log ---"
    cat "$NODE2_LOG"
    exit 1
fi
log_pass "both node endpoints are ready"

CONTROL_SUMMARY="$TEST_TMP_DIR/control-summary.json"
log_info "Running control workflow (invite/join/project/mount/activate)..."
python3 - "$BIND_ADDR" "$SPIDERWEB_PORT" "ws://$BIND_ADDR:$NODE1_PORT/v2/fs" "ws://$BIND_ADDR:$NODE2_PORT/v2/fs" "$CONTROL_SUMMARY" <<'PY'
import base64
import json
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
node1_url = sys.argv[3]
node2_url = sys.argv[4]
summary_path = sys.argv[5]

def read_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("connection closed")
        out.extend(chunk)
    return bytes(out)

def write_frame(sock, opcode, payload):
    data = payload if isinstance(payload, (bytes, bytearray)) else payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(n.to_bytes(8, "big"))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytearray(data)
    for i in range(n):
        masked[i] ^= mask[i % 4]
    sock.sendall(header + masked)

def read_message(sock):
    while True:
        b0, b1 = read_exact(sock, 2)
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(read_exact(sock, 2), "big")
        elif n == 127:
            n = int.from_bytes(read_exact(sock, 8), "big")
        if masked:
            mask = read_exact(sock, 4)
            data = bytearray(read_exact(sock, n))
            for i in range(n):
                data[i] ^= mask[i % 4]
            payload = bytes(data)
        else:
            payload = read_exact(sock, n)

        if opcode == 0x9:
            write_frame(sock, 0xA, payload)
            continue
        if opcode == 0xA:
            continue
        if opcode == 0x8:
            raise RuntimeError("server closed")
        if opcode != 0x1:
            continue
        return json.loads(payload.decode("utf-8"))

def call(sock, op, payload, request_id):
    msg = {
        "channel": "control",
        "type": f"control.{op}",
        "id": request_id,
    }
    operator_token = os.environ.get("SPIDERWEB_CONTROL_OPERATOR_TOKEN", "").strip()
    protected_ops = {
        "node_invite_create",
        "node_delete",
        "project_create",
        "project_update",
        "project_delete",
        "project_mount_set",
        "project_mount_remove",
        "project_token_rotate",
        "project_token_revoke",
    }
    if payload is not None:
        msg["payload"] = dict(payload)
    if operator_token and op in protected_ops:
        msg.setdefault("payload", {})
        msg["payload"]["operator_token"] = operator_token
    write_frame(sock, 0x1, json.dumps(msg, separators=(",", ":")))
    while True:
        reply = read_message(sock)
        if reply.get("channel") != "control":
            continue
        if reply.get("id") != request_id:
            continue
        msg_type = reply.get("type")
        if msg_type == "control.error":
            raise RuntimeError(f"control error for {op}: {json.dumps(reply)}")
        return reply.get("payload", {})

sock = socket.create_connection((host, port), timeout=3)
sock.settimeout(3)
try:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(req)
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("handshake closed")
        raw += chunk
    status = raw.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise RuntimeError(f"handshake failed: {status.decode('utf-8', 'replace')}")

    call(sock, "version", {"protocol": "unified-v2"}, "version-1")
    call(sock, "connect", {}, "connect-1")

    invite_a = call(sock, "node_invite_create", {}, "inv-a")
    node_a = call(sock, "node_join", {
        "invite_token": invite_a["invite_token"],
        "node_name": "node-a",
        "fs_url": node1_url,
    }, "join-a")

    invite_b = call(sock, "node_invite_create", {}, "inv-b")
    node_b = call(sock, "node_join", {
        "invite_token": invite_b["invite_token"],
        "node_name": "node-b",
        "fs_url": node2_url,
    }, "join-b")

    project = call(sock, "project_create", {
        "name": "Distributed Workspace",
        "vision": "multi-node fs mount graph",
    }, "project-create")
    project_id = project["project_id"]
    project_token = project["project_token"]

    call(sock, "project_mount_set", {
        "project_id": project_id,
        "project_token": project_token,
        "node_id": node_a["node_id"],
        "export_name": "work",
        "mount_path": "/src",
    }, "mount-a")
    call(sock, "project_mount_set", {
        "project_id": project_id,
        "project_token": project_token,
        "node_id": node_b["node_id"],
        "export_name": "work",
        "mount_path": "/src",
    }, "mount-b")
    call(sock, "project_activate", {
        "project_id": project_id,
        "project_token": project_token,
    }, "activate")
    status_payload = call(sock, "workspace_status", {}, "workspace-status")

    mounts = status_payload.get("mounts", [])
    if len(mounts) != 2:
        raise RuntimeError(f"expected 2 workspace mounts, got {len(mounts)}: {json.dumps(status_payload)}")

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "project_id": project_id,
            "project_token": project_token,
            "node_a_id": node_a["node_id"],
            "node_b_id": node_b["node_id"],
            "mounts": mounts,
        }, f)
finally:
    try:
        write_frame(sock, 0x8, b"")
    except Exception:
        pass
    sock.close()
PY
log_pass "control workflow completed"

PROJECT_ID="$(python3 - "$CONTROL_SUMMARY" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["project_id"])
PY
)"
PROJECT_TOKEN="$(python3 - "$CONTROL_SUMMARY" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["project_token"])
PY
)"
NODE_A_ID="$(python3 - "$CONTROL_SUMMARY" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["node_a_id"])
PY
)"
NODE_B_ID="$(python3 - "$CONTROL_SUMMARY" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["node_b_id"])
PY
)"

log_info "Restarting spiderweb to validate control-plane persistence recovery..."
kill "$SPIDERWEB_PID" >/dev/null 2>&1 || true
wait "$SPIDERWEB_PID" >/dev/null 2>&1 || true
unset SPIDERWEB_PID
start_spiderweb
if ! wait_for_control_ready; then
    log_fail "spiderweb did not recover after restart"
    echo "--- spiderweb log ---"
    cat "$SPIDERWEB_LOG"
    exit 1
fi
if [[ "$SPIDERWEB_METRICS_PORT" -gt 0 ]]; then
    if ! python3 - "$BIND_ADDR" "$SPIDERWEB_METRICS_PORT" <<'PY' >/dev/null 2>&1
import json
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

def request(path):
    sock = socket.create_connection((host, port), timeout=2)
    sock.settimeout(2)
    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendall(req)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.partition(b"\r\n\r\n")
    finally:
        sock.close()

head, _, body = request("/livez")
if b"200 OK" not in head:
    raise RuntimeError("livez status not 200")
if b"ok" not in body.lower():
    raise RuntimeError("livez body missing ok")

head, _, body = request("/readyz")
if b"200 OK" not in head:
    raise RuntimeError("readyz status not 200")
if b"ready" not in body.lower():
    raise RuntimeError("readyz body missing ready")

head, _, body = request("/metrics")
if b"200 OK" not in head:
    raise RuntimeError("metrics status not 200")
if b"spiderweb_nodes_total" not in body:
    raise RuntimeError("prometheus metrics missing spiderweb_nodes_total")

head, _, body = request("/metrics.json")
if b"200 OK" not in head:
    raise RuntimeError("metrics.json status not 200")
payload = json.loads(body.decode("utf-8"))
if "nodes" not in payload or "projects" not in payload:
    raise RuntimeError("metrics.json payload missing keys")
PY
    then
        log_fail "metrics endpoint did not recover after restart"
        echo "--- spiderweb log ---"
        cat "$SPIDERWEB_LOG"
        exit 1
    fi
fi

python3 - "$BIND_ADDR" "$SPIDERWEB_PORT" "$PROJECT_ID" <<'PY'
import base64
import json
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
expected_project_id = sys.argv[3]

def read_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("connection closed")
        out.extend(chunk)
    return bytes(out)

def write_frame(sock, opcode, payload):
    data = payload if isinstance(payload, (bytes, bytearray)) else payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(n.to_bytes(8, "big"))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytearray(data)
    for i in range(n):
        masked[i] ^= mask[i % 4]
    sock.sendall(header + masked)

def read_message(sock):
    while True:
        b0, b1 = read_exact(sock, 2)
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(read_exact(sock, 2), "big")
        elif n == 127:
            n = int.from_bytes(read_exact(sock, 8), "big")
        if masked:
            mask = read_exact(sock, 4)
            data = bytearray(read_exact(sock, n))
            for i in range(n):
                data[i] ^= mask[i % 4]
            payload = bytes(data)
        else:
            payload = read_exact(sock, n)
        if opcode == 0x9:
            write_frame(sock, 0xA, payload)
            continue
        if opcode == 0xA:
            continue
        if opcode == 0x8:
            raise RuntimeError("closed")
        if opcode != 0x1:
            continue
        return json.loads(payload.decode("utf-8"))

def call(sock, op, payload, request_id):
    msg = {"channel": "control", "type": f"control.{op}", "id": request_id}
    operator_token = os.environ.get("SPIDERWEB_CONTROL_OPERATOR_TOKEN", "").strip()
    protected_ops = {
        "node_invite_create",
        "node_delete",
        "project_create",
        "project_update",
        "project_delete",
        "project_mount_set",
        "project_mount_remove",
        "project_token_rotate",
        "project_token_revoke",
    }
    if payload is not None:
        msg["payload"] = dict(payload)
    if operator_token and op in protected_ops:
        msg.setdefault("payload", {})
        msg["payload"]["operator_token"] = operator_token
    write_frame(sock, 0x1, json.dumps(msg, separators=(",", ":")))
    while True:
        reply = read_message(sock)
        if reply.get("channel") != "control":
            continue
        if reply.get("id") != request_id:
            continue
        if reply.get("type") == "control.error":
            raise RuntimeError(f"control error {op}: {json.dumps(reply)}")
        return reply.get("payload", {})

sock = socket.create_connection((host, port), timeout=3)
sock.settimeout(3)
try:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(req)
    raw = b""
    while b"\r\n\r\n" not in raw:
        raw += sock.recv(4096)
    status = raw.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise RuntimeError(f"bad handshake: {status!r}")

    call(sock, "version", {"protocol": "unified-v2"}, "restart-version")
    call(sock, "connect", {}, "restart-connect")
    workspace = call(sock, "workspace_status", {}, "restart-status")
    if workspace.get("project_id") != expected_project_id:
        raise RuntimeError(f"project mismatch after restart: {workspace}")
    mounts = workspace.get("mounts", [])
    if len(mounts) < 2:
        raise RuntimeError(f"expected >=2 mounts after restart, got {len(mounts)}: {workspace}")
finally:
    try:
        write_frame(sock, 0x8, b"")
    except Exception:
        pass
    sock.close()
PY
log_pass "control-plane state recovered after spiderweb restart"

WORKSPACE_URL="ws://$BIND_ADDR:$SPIDERWEB_PORT/"
INITIAL_READ="$("$FS_MOUNT_BIN" --workspace-url "$WORKSPACE_URL" cat "/src/$FIXTURE_NAME")"

FAILOVER_TARGET_CONTENT=""
STOPPED_NODE_PORT=""
STOPPED_NODE_EXPORT=""
STOPPED_NODE_CONTENT=""
STOPPED_NODE_LABEL=""
if [[ "$INITIAL_READ" == "$NODE1_CONTENT" ]]; then
    log_pass "initial read returned node A content"
    log_info "Stopping currently-active node A to force failover..."
    kill "$NODE1_PID" >/dev/null 2>&1 || true
    wait "$NODE1_PID" >/dev/null 2>&1 || true
    unset NODE1_PID
    FAILOVER_TARGET_CONTENT="$NODE2_CONTENT"
    STOPPED_NODE_PORT="$NODE1_PORT"
    STOPPED_NODE_EXPORT="$NODE1_EXPORT"
    STOPPED_NODE_CONTENT="$NODE1_CONTENT"
    STOPPED_NODE_LABEL="A"
elif [[ "$INITIAL_READ" == "$NODE2_CONTENT" ]]; then
    log_pass "initial read returned node B content"
    log_info "Stopping currently-active node B to force failover..."
    kill "$NODE2_PID" >/dev/null 2>&1 || true
    wait "$NODE2_PID" >/dev/null 2>&1 || true
    unset NODE2_PID
    FAILOVER_TARGET_CONTENT="$NODE1_CONTENT"
    STOPPED_NODE_PORT="$NODE2_PORT"
    STOPPED_NODE_EXPORT="$NODE2_EXPORT"
    STOPPED_NODE_CONTENT="$NODE2_CONTENT"
    STOPPED_NODE_LABEL="B"
else
    log_fail "initial read returned unexpected payload"
    echo "Observed: $INITIAL_READ"
    echo "--- control summary ---"
    cat "$CONTROL_SUMMARY"
    exit 1
fi

log_info "Updating project mounts live (/src -> /live) and validating client convergence..."
python3 - "$BIND_ADDR" "$SPIDERWEB_PORT" "$PROJECT_ID" "$PROJECT_TOKEN" "$NODE_A_ID" "$NODE_B_ID" <<'PY'
import base64
import json
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
project_id = sys.argv[3]
project_token = sys.argv[4]
node_a = sys.argv[5]
node_b = sys.argv[6]

def read_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("connection closed")
        out.extend(chunk)
    return bytes(out)

def write_frame(sock, opcode, payload):
    data = payload if isinstance(payload, (bytes, bytearray)) else payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(n.to_bytes(8, "big"))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytearray(data)
    for i in range(n):
        masked[i] ^= mask[i % 4]
    sock.sendall(header + masked)

def read_message(sock):
    while True:
        b0, b1 = read_exact(sock, 2)
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(read_exact(sock, 2), "big")
        elif n == 127:
            n = int.from_bytes(read_exact(sock, 8), "big")
        if masked:
            mask = read_exact(sock, 4)
            data = bytearray(read_exact(sock, n))
            for i in range(n):
                data[i] ^= mask[i % 4]
            payload = bytes(data)
        else:
            payload = read_exact(sock, n)
        if opcode == 0x9:
            write_frame(sock, 0xA, payload)
            continue
        if opcode == 0xA:
            continue
        if opcode == 0x8:
            raise RuntimeError("closed")
        if opcode != 0x1:
            continue
        return json.loads(payload.decode("utf-8"))

def call(sock, op, payload, request_id):
    msg = {"channel": "control", "type": f"control.{op}", "id": request_id}
    operator_token = os.environ.get("SPIDERWEB_CONTROL_OPERATOR_TOKEN", "").strip()
    protected_ops = {
        "node_invite_create",
        "node_delete",
        "project_create",
        "project_update",
        "project_delete",
        "project_mount_set",
        "project_mount_remove",
        "project_token_rotate",
        "project_token_revoke",
    }
    if payload is not None:
        msg["payload"] = dict(payload)
    if operator_token and op in protected_ops:
        msg.setdefault("payload", {})
        msg["payload"]["operator_token"] = operator_token
    write_frame(sock, 0x1, json.dumps(msg, separators=(",", ":")))
    while True:
        reply = read_message(sock)
        if reply.get("channel") != "control":
            continue
        if reply.get("id") != request_id:
            continue
        if reply.get("type") == "control.error":
            raise RuntimeError(f"control error {op}: {json.dumps(reply)}")
        return reply.get("payload", {})

sock = socket.create_connection((host, port), timeout=3)
sock.settimeout(3)
try:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(req)
    raw = b""
    while b"\r\n\r\n" not in raw:
        raw += sock.recv(4096)
    status = raw.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise RuntimeError(f"bad handshake: {status!r}")

    call(sock, "version", {"protocol": "unified-v2"}, "version-live")
    call(sock, "connect", {}, "connect-live")
    call(sock, "project_mount_remove", {"project_id": project_id, "project_token": project_token, "mount_path": "/src"}, "rm-1")
    call(sock, "project_mount_remove", {"project_id": project_id, "project_token": project_token, "mount_path": "/src"}, "rm-2")
    call(sock, "project_mount_set", {"project_id": project_id, "project_token": project_token, "node_id": node_a, "export_name": "work", "mount_path": "/live"}, "add-live-a")
    call(sock, "project_mount_set", {"project_id": project_id, "project_token": project_token, "node_id": node_b, "export_name": "work", "mount_path": "/live"}, "add-live-b")
finally:
    try:
        write_frame(sock, 0x8, b"")
    except Exception:
        pass
    sock.close()
PY

live_ok=0
for _ in $(seq 1 80); do
    if LIVE_READ="$("$FS_MOUNT_BIN" --workspace-url "$WORKSPACE_URL" cat "/live/$FIXTURE_NAME" 2>/dev/null)"; then
        if [[ "$LIVE_READ" == "$NODE1_CONTENT" || "$LIVE_READ" == "$NODE2_CONTENT" ]]; then
            live_ok=1
            break
        fi
    fi
    sleep 0.2
done
if [[ "$live_ok" -ne 1 ]]; then
    log_fail "mount-path update did not converge to /live"
    echo "--- spiderweb log ---"
    cat "$SPIDERWEB_LOG"
    exit 1
fi
log_pass "client converged after live mount-path update"

FAILOVER_READ=""
failover_ok=0
for _ in $(seq 1 80); do
    if FAILOVER_READ="$("$FS_MOUNT_BIN" --workspace-url "$WORKSPACE_URL" cat "/live/$FIXTURE_NAME" 2>/dev/null)"; then
        if [[ "$FAILOVER_READ" == "$FAILOVER_TARGET_CONTENT" ]]; then
            failover_ok=1
            break
        fi
    fi
    sleep 0.2
done

if [[ "$failover_ok" -ne 1 ]]; then
    log_fail "failover read did not converge to the surviving node"
    echo "Last observed: $FAILOVER_READ"
    echo "--- spiderweb log ---"
    cat "$SPIDERWEB_LOG"
    echo "--- node B log ---"
    cat "$NODE2_LOG"
    exit 1
fi
log_pass "failover read returned surviving node content"

if [[ "$STOPPED_NODE_LABEL" == "A" ]]; then
    log_info "Restarting node A for chaos rejoin test..."
    "$FS_NODE_BIN" \
        --bind "$BIND_ADDR" \
        --port "$STOPPED_NODE_PORT" \
        --export "work=$STOPPED_NODE_EXPORT:rw" \
        > "$NODE1_LOG" 2>&1 &
    NODE1_PID="$!"
else
    log_info "Restarting node B for chaos rejoin test..."
    "$FS_NODE_BIN" \
        --bind "$BIND_ADDR" \
        --port "$STOPPED_NODE_PORT" \
        --export "work=$STOPPED_NODE_EXPORT:rw" \
        > "$NODE2_LOG" 2>&1 &
    NODE2_PID="$!"
fi

if ! wait_for_node_ready "$STOPPED_NODE_PORT"; then
    log_fail "restarted node did not become ready"
    if [[ "$STOPPED_NODE_LABEL" == "A" ]]; then
        cat "$NODE1_LOG"
    else
        cat "$NODE2_LOG"
    fi
    exit 1
fi

python3 - "$BIND_ADDR" "$SPIDERWEB_PORT" "$PROJECT_ID" "$PROJECT_TOKEN" "$BIND_ADDR" "$STOPPED_NODE_PORT" "$STOPPED_NODE_LABEL" <<'PY'
import base64
import json
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
project_id = sys.argv[3]
project_token = sys.argv[4]
node_host = sys.argv[5]
node_port = int(sys.argv[6])
node_label = sys.argv[7]
node_url = f"ws://{node_host}:{node_port}/v2/fs"

def read_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("connection closed")
        out.extend(chunk)
    return bytes(out)

def write_frame(sock, opcode, payload):
    data = payload if isinstance(payload, (bytes, bytearray)) else payload.encode("utf-8")
    header = bytearray([0x80 | opcode])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(n.to_bytes(8, "big"))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytearray(data)
    for i in range(n):
        masked[i] ^= mask[i % 4]
    sock.sendall(header + masked)

def read_message(sock):
    while True:
        b0, b1 = read_exact(sock, 2)
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(read_exact(sock, 2), "big")
        elif n == 127:
            n = int.from_bytes(read_exact(sock, 8), "big")
        if masked:
            mask = read_exact(sock, 4)
            data = bytearray(read_exact(sock, n))
            for i in range(n):
                data[i] ^= mask[i % 4]
            payload = bytes(data)
        else:
            payload = read_exact(sock, n)
        if opcode == 0x9:
            write_frame(sock, 0xA, payload)
            continue
        if opcode == 0xA:
            continue
        if opcode == 0x8:
            raise RuntimeError("closed")
        if opcode != 0x1:
            continue
        return json.loads(payload.decode("utf-8"))

def call(sock, op, payload, request_id):
    msg = {"channel": "control", "type": f"control.{op}", "id": request_id}
    operator_token = os.environ.get("SPIDERWEB_CONTROL_OPERATOR_TOKEN", "").strip()
    protected_ops = {
        "node_invite_create",
        "node_delete",
        "project_create",
        "project_update",
        "project_delete",
        "project_mount_set",
        "project_mount_remove",
        "project_token_rotate",
        "project_token_revoke",
    }
    if payload is not None:
        msg["payload"] = dict(payload)
    if operator_token and op in protected_ops:
        msg.setdefault("payload", {})
        msg["payload"]["operator_token"] = operator_token
    write_frame(sock, 0x1, json.dumps(msg, separators=(",", ":")))
    while True:
        reply = read_message(sock)
        if reply.get("channel") != "control":
            continue
        if reply.get("id") != request_id:
            continue
        if reply.get("type") == "control.error":
            raise RuntimeError(f"control error {op}: {json.dumps(reply)}")
        return reply.get("payload", {})

sock = socket.create_connection((host, port), timeout=3)
sock.settimeout(3)
try:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(req)
    raw = b""
    while b"\r\n\r\n" not in raw:
        raw += sock.recv(4096)
    status = raw.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise RuntimeError(f"bad handshake: {status!r}")

    call(sock, "version", {"protocol": "unified-v2"}, "rejoin-version")
    call(sock, "connect", {}, "rejoin-connect")
    invite = call(sock, "node_invite_create", {}, "rejoin-invite")
    joined = call(sock, "node_join", {
        "invite_token": invite["invite_token"],
        "node_name": f"node-{node_label.lower()}-rejoin",
        "fs_url": node_url,
    }, "rejoin-join")
    call(sock, "project_mount_set", {
        "project_id": project_id,
        "project_token": project_token,
        "node_id": joined["node_id"],
        "export_name": "work",
        "mount_path": "/live",
    }, "rejoin-mount")
finally:
    try:
        write_frame(sock, 0x8, b"")
    except Exception:
        pass
    sock.close()
PY
log_pass "restarted node rejoined and remounted at /live"

if [[ "$STOPPED_NODE_LABEL" == "A" ]]; then
    log_info "Stopping surviving node B to force second failover..."
    kill "$NODE2_PID" >/dev/null 2>&1 || true
    wait "$NODE2_PID" >/dev/null 2>&1 || true
    unset NODE2_PID
else
    log_info "Stopping surviving node A to force second failover..."
    kill "$NODE1_PID" >/dev/null 2>&1 || true
    wait "$NODE1_PID" >/dev/null 2>&1 || true
    unset NODE1_PID
fi

SECOND_FAILOVER_READ=""
second_failover_ok=0
for _ in $(seq 1 80); do
    if SECOND_FAILOVER_READ="$("$FS_MOUNT_BIN" --workspace-url "$WORKSPACE_URL" cat "/live/$FIXTURE_NAME" 2>/dev/null)"; then
        if [[ "$SECOND_FAILOVER_READ" == "$STOPPED_NODE_CONTENT" ]]; then
            second_failover_ok=1
            break
        fi
    fi
    sleep 0.2
done

if [[ "$second_failover_ok" -ne 1 ]]; then
    log_fail "second failover read did not converge to the rejoined node"
    echo "Last observed: $SECOND_FAILOVER_READ"
    echo "--- spiderweb log ---"
    cat "$SPIDERWEB_LOG"
    exit 1
fi
log_pass "second failover read returned rejoined node content"

echo ""
log_pass "distributed workspace integration test passed"
