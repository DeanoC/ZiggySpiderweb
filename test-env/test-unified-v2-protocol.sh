#!/usr/bin/env bash
# Unified v2 protocol validation:
# - control/runtime negotiation order on spiderweb endpoint
# - FS routing negotiation order on standalone fs node endpoint
# - FS hello auth token enforcement on standalone fs node endpoint
# - source-level envelope/type guard for core CLI clients

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
SPIDERWEB_PORT="${SPIDERWEB_PORT:-28794}"
FS_NODE_PORT="${FS_NODE_PORT:-28931}"

SPIDERWEB_BIN="$ROOT_DIR/zig-out/bin/spiderweb"
FS_NODE_BIN="$ROOT_DIR/zig-out/bin/spiderweb-fs-node"

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
    if [[ -n "${FS_NODE_PID:-}" ]]; then
        kill "$FS_NODE_PID" >/dev/null 2>&1 || true
        wait "$FS_NODE_PID" >/dev/null 2>&1 || true
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

for bin in "$SPIDERWEB_BIN" "$FS_NODE_BIN"; do
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
AUTH_TOKENS_FILE="$LTM_DIR/auth_tokens.json"
SPIDER_WEB_ROOT="$TEST_TMP_DIR/spider-web-root"
FS_EXPORT_DIR="$TEST_TMP_DIR/fs-export"
mkdir -p "$LTM_DIR" "$SPIDER_WEB_ROOT" "$FS_EXPORT_DIR"

printf 'fixture from unified protocol test\n' > "$FS_EXPORT_DIR/fixture.txt"

SPIDERWEB_CONFIG_FILE="$TEST_TMP_DIR/spiderweb.json"
cat > "$SPIDERWEB_CONFIG_FILE" <<JSON
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
JSON

SPIDERWEB_LOG="$TEST_TMP_DIR/spiderweb.log"
FS_NODE_LOG="$TEST_TMP_DIR/fs-node.log"
FS_NODE_AUTH_TOKEN="protocol-fs-secret"

WS_HELPER="$TEST_TMP_DIR/ws_suite.py"
cat > "$WS_HELPER" <<'PY'
#!/usr/bin/env python3
import base64
import json
import os
import socket
import sys


class WsError(RuntimeError):
    pass


class WsClosed(WsError):
    pass


class WSConn:
    def __init__(self, sock: socket.socket, remainder: bytes):
        self.sock = sock
        self.buffer = bytearray(remainder)

    @classmethod
    def connect(cls, host: str, port: int, path: str, auth_token=None) -> "WSConn":
        sock = socket.create_connection((host, port), timeout=3)
        sock.settimeout(3)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        auth_line = f"Authorization: Bearer {auth_token}\r\n" if auth_token else ""
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"{auth_line}"
            "\r\n"
        ).encode("ascii")
        sock.sendall(request)

        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                raise WsError("connection closed during handshake")
            raw += chunk

        headers, remainder = raw.split(b"\r\n\r\n", 1)
        status = headers.split(b"\r\n", 1)[0]
        if b"101" not in status:
            sock.close()
            raise WsError(f"websocket handshake failed: {status.decode('utf-8', 'replace')}")
        return cls(sock, remainder)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _read_exact(self, n: int) -> bytes:
        while len(self.buffer) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WsClosed("eof")
            self.buffer.extend(chunk)
        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out

    def read_frame(self) -> tuple[int, bytes]:
        b0, b1 = self._read_exact(2)
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        length = b1 & 0x7F
        if length == 126:
            length = int.from_bytes(self._read_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(self._read_exact(8), "big")

        if masked:
            mask = self._read_exact(4)
            payload = bytearray(self._read_exact(length))
            for i in range(length):
                payload[i] ^= mask[i % 4]
            return opcode, bytes(payload)
        return opcode, self._read_exact(length)

    def send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | (opcode & 0x0F)])
        n = len(payload)
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
        masked = bytearray(payload)
        for i in range(n):
            masked[i] ^= mask[i % 4]
        self.sock.sendall(header + masked)

    def send_json(self, msg: dict) -> None:
        self.send_frame(0x1, json.dumps(msg, separators=(",", ":")).encode("utf-8"))

    def read_json(self) -> dict:
        while True:
            opcode, payload = self.read_frame()
            if opcode == 0x9:
                self.send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x8:
                raise WsClosed("close")
            if opcode != 0x1:
                continue
            try:
                return json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise WsError(f"invalid json payload: {exc}") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WsError(message)


def expect_type(msg: dict, channel: str, msg_type: str) -> None:
    require(msg.get("channel") == channel, f"expected channel={channel}, got {msg.get('channel')}")
    require(msg.get("type") == msg_type, f"expected type={msg_type}, got {msg.get('type')}")


def control_ready(host: str, port: int, auth_token=None) -> None:
    conn = WSConn.connect(host, port, "/", auth_token)
    try:
        conn.send_json({
            "channel": "control",
            "type": "control.version",
            "id": "ready-version",
            "payload": {"protocol": "unified-v2"},
        })
        version_ack = conn.read_json()
        expect_type(version_ack, "control", "control.version_ack")

        conn.send_json({
            "channel": "control",
            "type": "control.connect",
            "id": "ready-connect",
            "payload": {},
        })
        connect_ack = conn.read_json()
        expect_type(connect_ack, "control", "control.connect_ack")
    finally:
        conn.close()


def run_control_runtime_order(host: str, port: int, auth_token=None) -> None:
    # control.connect before control.version must fail.
    conn = WSConn.connect(host, port, "/", auth_token)
    try:
        conn.send_json({
            "channel": "control",
            "type": "control.connect",
            "id": "bad-order-connect",
            "payload": {},
        })
        msg = conn.read_json()
        expect_type(msg, "control", "control.error")
        err = msg.get("error") or {}
        require(err.get("code") == "protocol_mismatch", f"unexpected control error code: {err}")
        require("control.version" in str(err.get("message", "")), f"unexpected control error message: {err}")
        opcode, _ = conn.read_frame()
        require(opcode == 0x8, "expected close frame after control protocol mismatch")
    finally:
        conn.close()

    # After control.version + control.connect, acheron.t_attach before acheron.t_version must fail.
    conn = WSConn.connect(host, port, "/", auth_token)
    try:
        conn.send_json({
            "channel": "control",
            "type": "control.version",
            "id": "cv1",
            "payload": {"protocol": "unified-v2"},
        })
        version_ack = conn.read_json()
        expect_type(version_ack, "control", "control.version_ack")

        conn.send_json({
            "channel": "control",
            "type": "control.connect",
            "id": "cc1",
            "payload": {},
        })
        connect_ack = conn.read_json()
        expect_type(connect_ack, "control", "control.connect_ack")

        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_attach",
            "tag": 100,
            "fid": 1,
        })
        err_msg = conn.read_json()
        expect_type(err_msg, "acheron", "acheron.error")
        err = err_msg.get("error") or {}
        require(err.get("code") == "protocol_mismatch", f"unexpected acheron error code: {err}")
        require("acheron.t_version" in str(err.get("message", "")), f"unexpected acheron error message: {err}")
        opcode, _ = conn.read_frame()
        require(opcode == 0x8, "expected close frame after acheron protocol mismatch")
    finally:
        conn.close()

    # Happy-path control/runtime negotiation should use canonical type names.
    conn = WSConn.connect(host, port, "/", auth_token)
    try:
        conn.send_json({
            "channel": "control",
            "type": "control.version",
            "id": "cv2",
            "payload": {"protocol": "unified-v2"},
        })
        version_ack = conn.read_json()
        expect_type(version_ack, "control", "control.version_ack")

        conn.send_json({
            "channel": "control",
            "type": "control.connect",
            "id": "cc2",
            "payload": {},
        })
        connect_ack = conn.read_json()
        expect_type(connect_ack, "control", "control.connect_ack")

        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_version",
            "tag": 1,
            "msize": 1048576,
            "version": "acheron-1",
        })
        tversion_ack = conn.read_json()
        expect_type(tversion_ack, "acheron", "acheron.r_version")

        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_attach",
            "tag": 2,
            "fid": 1,
        })
        attach_ack = conn.read_json()
        expect_type(attach_ack, "acheron", "acheron.r_attach")
    finally:
        conn.close()


def fs_ready(host: str, port: int, auth_token: str) -> None:
    conn = WSConn.connect(host, port, "/v2/fs")
    try:
        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_fs_hello",
            "tag": 1,
            "payload": {
                "protocol": "unified-v2-fs",
                "proto": 2,
                "auth_token": auth_token,
            },
        })
        reply = conn.read_json()
        expect_type(reply, "acheron", "acheron.r_fs_hello")
    finally:
        conn.close()


def run_fs_hello_order_and_auth(host: str, port: int, auth_token: str) -> None:
    # Sending FS op before acheron.t_fs_hello must fail.
    conn = WSConn.connect(host, port, "/v2/fs")
    try:
        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_fs_exports",
            "tag": 11,
            "payload": {},
        })
        err_msg = conn.read_json()
        expect_type(err_msg, "acheron", "acheron.err_fs")
        err = err_msg.get("error") or {}
        require("acheron.t_fs_hello" in str(err.get("message", "")), f"unexpected fs order error: {err}")
        opcode, _ = conn.read_frame()
        require(opcode == 0x8, "expected close frame after fs order mismatch")
    finally:
        conn.close()

    # Missing auth_token in hello must fail when node auth is enabled.
    conn = WSConn.connect(host, port, "/v2/fs")
    try:
        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_fs_hello",
            "tag": 12,
            "payload": {
                "protocol": "unified-v2-fs",
                "proto": 2,
            },
        })
        err_msg = conn.read_json()
        expect_type(err_msg, "acheron", "acheron.err_fs")
        err = err_msg.get("error") or {}
        require("AuthMissing" in str(err.get("message", "")), f"unexpected missing-auth error: {err}")
        opcode, _ = conn.read_frame()
        require(opcode == 0x8, "expected close frame after missing auth token")
    finally:
        conn.close()

    # Wrong auth_token in hello must fail.
    conn = WSConn.connect(host, port, "/v2/fs")
    try:
        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_fs_hello",
            "tag": 13,
            "payload": {
                "protocol": "unified-v2-fs",
                "proto": 2,
                "auth_token": "wrong-token",
            },
        })
        err_msg = conn.read_json()
        expect_type(err_msg, "acheron", "acheron.err_fs")
        err = err_msg.get("error") or {}
        require("AuthFailed" in str(err.get("message", "")), f"unexpected wrong-auth error: {err}")
        opcode, _ = conn.read_frame()
        require(opcode == 0x8, "expected close frame after wrong auth token")
    finally:
        conn.close()

    # Correct auth_token should negotiate and allow fs operation.
    conn = WSConn.connect(host, port, "/v2/fs")
    try:
        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_fs_hello",
            "tag": 14,
            "payload": {
                "protocol": "unified-v2-fs",
                "proto": 2,
                "auth_token": auth_token,
            },
        })
        hello_reply = conn.read_json()
        expect_type(hello_reply, "acheron", "acheron.r_fs_hello")

        conn.send_json({
            "channel": "acheron",
            "type": "acheron.t_fs_exports",
            "tag": 15,
            "payload": {},
        })
        exports_reply = conn.read_json()
        expect_type(exports_reply, "acheron", "acheron.r_fs_exports")
        payload = exports_reply.get("payload") or {}
        exports = payload.get("exports") or []
        require(isinstance(exports, list), "expected exports list in acheron.r_fs_exports payload")
        require(len(exports) >= 1, "expected at least one export from standalone fs node")
    finally:
        conn.close()


def run_source_guard(root_dir: str) -> None:
    checks = [
        ("src/control_cli.zig", '\\"channel\\":\\"control\\",\\"type\\":\\"{s}\\",\\"id\\":\\"{s}\\",\\"payload\\":{s}'),
        ("src/control_cli.zig", '.msg_type = "control.version"'),
        ("src/control_cli.zig", '.msg_type = "control.connect"'),
        ("src/fs_mount_main.zig", '\\"channel\\":\\"control\\",\\"type\\":\\"control.version\\"'),
        ("src/fs_mount_main.zig", '\\"channel\\":\\"control\\",\\"type\\":\\"control.connect\\"'),
        ("src/fs_mount_main.zig", '\\"channel\\":\\"control\\",\\"type\\":\\"control.workspace_status\\"'),
        ("src/fs_node_main.zig", '\\"channel\\":\\"control\\",\\"type\\":\\"control.version\\"'),
        ("src/fs_node_main.zig", '\\"channel\\":\\"control\\",\\"type\\":\\"control.connect\\"'),
        ("src/fs_node_main.zig", '\\"channel\\":\\"acheron\\",\\"type\\":\\"acheron.t_fs_hello\\"'),
    ]

    for rel_path, snippet in checks:
        path = os.path.join(root_dir, rel_path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        if snippet not in content:
            raise WsError(f"source guard failed: missing snippet in {rel_path}: {snippet}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: ws_suite.py <command> [args...]")

    command = sys.argv[1]
    if command == "control-ready":
        if len(sys.argv) not in (4, 5):
            raise SystemExit("usage: ws_suite.py control-ready <host> <port> [auth_token]")
        token = sys.argv[4] if len(sys.argv) == 5 else None
        control_ready(sys.argv[2], int(sys.argv[3]), token)
    elif command == "control-runtime-order":
        if len(sys.argv) not in (4, 5):
            raise SystemExit("usage: ws_suite.py control-runtime-order <host> <port> [auth_token]")
        token = sys.argv[4] if len(sys.argv) == 5 else None
        run_control_runtime_order(sys.argv[2], int(sys.argv[3]), token)
    elif command == "fs-ready":
        if len(sys.argv) != 5:
            raise SystemExit("usage: ws_suite.py fs-ready <host> <port> <auth_token>")
        fs_ready(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif command == "fs-hello-order-auth":
        if len(sys.argv) != 5:
            raise SystemExit("usage: ws_suite.py fs-hello-order-auth <host> <port> <auth_token>")
        run_fs_hello_order_and_auth(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif command == "source-guard":
        if len(sys.argv) != 3:
            raise SystemExit("usage: ws_suite.py source-guard <repo_root>")
        run_source_guard(sys.argv[2])
    else:
        raise SystemExit(f"unknown command: {command}")
PY
chmod +x "$WS_HELPER"

start_spiderweb() {
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
}

start_fs_node() {
    log_info "Starting standalone spiderweb-fs-node on ws://$BIND_ADDR:$FS_NODE_PORT/v2/fs ..."
    (
        cd "$ROOT_DIR"
        "$FS_NODE_BIN" \
            --bind "$BIND_ADDR" \
            --port "$FS_NODE_PORT" \
            --auth-token "$FS_NODE_AUTH_TOKEN" \
            --export "work=$FS_EXPORT_DIR:rw" \
            >> "$FS_NODE_LOG" 2>&1
    ) &
    FS_NODE_PID="$!"
}

load_spiderweb_auth_token() {
    if [[ -n "${SPIDERWEB_AUTH_TOKEN:-}" ]]; then
        return 0
    fi
    if [[ ! -f "$AUTH_TOKENS_FILE" ]]; then
        return 1
    fi
    local token
    token="$(python3 - "$AUTH_TOKENS_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
token = str(data.get("admin_token") or "").strip()
if token:
    print(token)
PY
)" || return 1
    if [[ -z "$token" ]]; then
        return 1
    fi
    SPIDERWEB_AUTH_TOKEN="$token"
    export SPIDERWEB_AUTH_TOKEN
    return 0
}

wait_for_control_ready() {
    for _ in $(seq 1 120); do
        if ! kill -0 "$SPIDERWEB_PID" >/dev/null 2>&1; then
            return 1
        fi
        if ! load_spiderweb_auth_token; then
            sleep 0.1
            continue
        fi
        if python3 "$WS_HELPER" control-ready "$BIND_ADDR" "$SPIDERWEB_PORT" "$SPIDERWEB_AUTH_TOKEN" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_for_fs_ready() {
    for _ in $(seq 1 120); do
        if ! kill -0 "$FS_NODE_PID" >/dev/null 2>&1; then
            return 1
        fi
        if python3 "$WS_HELPER" fs-ready "$BIND_ADDR" "$FS_NODE_PORT" "$FS_NODE_AUTH_TOKEN" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

start_spiderweb
if ! wait_for_control_ready; then
    log_fail "spiderweb did not become ready"
    echo "--- spiderweb log ---"
    cat "$SPIDERWEB_LOG"
    exit 1
fi
log_pass "spiderweb control endpoint is ready"

log_info "Running source-level client envelope/type guard..."
python3 "$WS_HELPER" source-guard "$ROOT_DIR"
log_pass "core client envelope/type snippets are canonical"

log_info "Validating control/runtime negotiation order..."
python3 "$WS_HELPER" control-runtime-order "$BIND_ADDR" "$SPIDERWEB_PORT" "$SPIDERWEB_AUTH_TOKEN"
log_pass "control/runtime negotiation order is enforced"

start_fs_node
if ! wait_for_fs_ready; then
    log_fail "standalone fs node did not become ready"
    echo "--- standalone fs-node log ---"
    cat "$FS_NODE_LOG"
    exit 1
fi
log_pass "standalone fs node endpoint is ready"

log_info "Validating fs hello negotiation order and auth token enforcement..."
python3 "$WS_HELPER" fs-hello-order-auth "$BIND_ADDR" "$FS_NODE_PORT" "$FS_NODE_AUTH_TOKEN"
log_pass "fs hello order/auth token checks passed"

echo ""
log_pass "unified v2 protocol validation passed"
