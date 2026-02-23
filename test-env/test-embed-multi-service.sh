#!/usr/bin/env bash
# Integration test for embed-multi-service-node:
# - boots embedded multi-service node
# - probes /v2/fs via spiderweb-fs-mount
# - probes /v1/health via a raw WebSocket handshake

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-21910}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"

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
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
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

if [[ ! -x "$FS_NODE_BIN" ]]; then
    log_fail "Missing binary: $FS_NODE_BIN"
    exit 1
fi
if [[ ! -x "$FS_MOUNT_BIN" ]]; then
    log_fail "Missing binary: $FS_MOUNT_BIN"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    log_fail "python3 is required for /v1/health websocket probe"
    exit 1
fi

TEST_TMP_DIR="$(mktemp -d)"
EXPORT_DIR="$TEST_TMP_DIR/export"
mkdir -p "$EXPORT_DIR"

FIXTURE_NAME="fixture.txt"
FIXTURE_CONTENT="hello from embed multi service integration test"
printf '%s\n' "$FIXTURE_CONTENT" > "$EXPORT_DIR/$FIXTURE_NAME"

SERVER_LOG="$TEST_TMP_DIR/embed-multi-service.log"
READDIR_OUT="$TEST_TMP_DIR/readdir.json"
READDIR_ERR="$TEST_TMP_DIR/readdir.err"
ENDPOINT="a=ws://$BIND_ADDR:$PORT/v2/fs#work"

log_info "Starting embed-multi-service-node on ws://$BIND_ADDR:$PORT ..."
"$FS_NODE_BIN" \
    --bind "$BIND_ADDR" \
    --port "$PORT" \
    --export "work=$EXPORT_DIR:rw" \
    > "$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

log_info "Waiting for /v2/fs readiness..."
ready=0
for _ in $(seq 1 80); do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        log_fail "Server exited before becoming ready"
        echo "--- server log ---"
        cat "$SERVER_LOG"
        exit 1
    fi

    if "$FS_MOUNT_BIN" --endpoint "$ENDPOINT" readdir /a > "$READDIR_OUT" 2> "$READDIR_ERR"; then
        ready=1
        break
    fi
    sleep 0.1
done

if [[ "$ready" -ne 1 ]]; then
    log_fail "Timed out waiting for /v2/fs readiness"
    echo "--- spiderweb-fs-mount stderr ---"
    cat "$READDIR_ERR"
    echo "--- server log ---"
    cat "$SERVER_LOG"
    exit 1
fi
log_pass "/v2/fs accepted requests"

if ! grep -Fq "\"name\":\"$FIXTURE_NAME\"" "$READDIR_OUT"; then
    log_fail "Directory listing did not contain $FIXTURE_NAME"
    echo "--- readdir output ---"
    cat "$READDIR_OUT"
    exit 1
fi
log_pass "readdir contains test fixture"

CAT_OUTPUT="$("$FS_MOUNT_BIN" --endpoint "$ENDPOINT" cat "/a/$FIXTURE_NAME")"
if [[ "$CAT_OUTPUT" != "$FIXTURE_CONTENT" ]]; then
    log_fail "cat output mismatch"
    echo "Expected: $FIXTURE_CONTENT"
    echo "Actual:   $CAT_OUTPUT"
    exit 1
fi
log_pass "cat returned expected fixture content"

log_info "Probing /v1/health over WebSocket..."
HEALTH_PAYLOAD="$(python3 - "$BIND_ADDR" "$PORT" <<'PY'
import base64
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

s = socket.create_connection((host, port), timeout=3)
try:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        "GET /v1/health HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")
    s.sendall(req)

    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = s.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed during handshake")
        raw += chunk

    header_blob, remainder = raw.split(b"\r\n\r\n", 1)
    status = header_blob.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise RuntimeError(f"unexpected handshake status: {status.decode('utf-8', 'replace')}")

    buffer = bytearray(remainder)

    def read_exact(n: int) -> bytes:
        while len(buffer) < n:
            chunk = s.recv(4096)
            if not chunk:
                raise RuntimeError("connection closed while reading frame")
            buffer.extend(chunk)
        out = bytes(buffer[:n])
        del buffer[:n]
        return out

    hdr = read_exact(2)
    opcode = hdr[0] & 0x0F
    masked = (hdr[1] & 0x80) != 0
    length = hdr[1] & 0x7F

    if length == 126:
        length = int.from_bytes(read_exact(2), "big")
    elif length == 127:
        length = int.from_bytes(read_exact(8), "big")

    if masked:
        mask = read_exact(4)
        payload = bytearray(read_exact(length))
        for i in range(length):
            payload[i] ^= mask[i % 4]
        data = bytes(payload)
    else:
        data = read_exact(length)

    if opcode != 0x1:
        raise RuntimeError(f"unexpected opcode: {opcode}")

    message = data.decode("utf-8")
    if '"ok":true' not in message:
        raise RuntimeError(f"health payload missing ok=true: {message}")
    print(message)
finally:
    s.close()
PY
)"
log_pass "/v1/health payload: $HEALTH_PAYLOAD"

echo ""
log_pass "embed-multi-service integration test passed"
