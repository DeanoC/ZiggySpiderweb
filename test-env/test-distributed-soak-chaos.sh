#!/usr/bin/env bash
# Long-running soak/chaos harness for distributed workspace routing.
# Repeats the full distributed integration scenario across randomized ports
# with optional operator-token and encrypted-state modes.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_TEST="$ROOT_DIR/test-env/test-distributed-workspace.sh"

if [[ ! -x "$BASE_TEST" ]]; then
    echo "[FAIL] Missing base test script: $BASE_TEST" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[FAIL] python3 is required" >&2
    exit 1
fi

ITERATIONS="${SOAK_ITERATIONS:-10}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
ENABLE_OPERATOR_MODE="${SOAK_ENABLE_OPERATOR_MODE:-1}"
ENABLE_ENCRYPTED_MODE="${SOAK_ENABLE_ENCRYPTED_MODE:-1}"

if [[ "$ITERATIONS" -le 0 ]]; then
    echo "[FAIL] SOAK_ITERATIONS must be > 0" >&2
    exit 1
fi

echo "[INFO] Starting soak/chaos run: iterations=$ITERATIONS bind=$BIND_ADDR"

for iteration in $(seq 1 "$ITERATIONS"); do
    attempt=0
    while true; do
        base_port="$((30000 + (RANDOM % 20000)))"
        export BIND_ADDR
        export SPIDERWEB_PORT="$base_port"
        export NODE1_PORT="$((base_port + 1))"
        export NODE2_PORT="$((base_port + 2))"
        export SPIDERWEB_METRICS_PORT="$((base_port + 3))"

        if [[ "$iteration" -gt 1 ]]; then
            export SKIP_BUILD=1
        else
            unset SKIP_BUILD || true
        fi

        if [[ "$ENABLE_OPERATOR_MODE" == "1" && $((RANDOM % 2)) -eq 0 ]]; then
            export SPIDERWEB_CONTROL_OPERATOR_TOKEN="soak-operator-token-$iteration"
            export ASSERT_OPERATOR_TOKEN_GATE=1
            mode_operator="on"
        else
            unset SPIDERWEB_CONTROL_OPERATOR_TOKEN || true
            unset ASSERT_OPERATOR_TOKEN_GATE || true
            mode_operator="off"
        fi

        if [[ "$ENABLE_ENCRYPTED_MODE" == "1" && $((RANDOM % 2)) -eq 0 ]]; then
            export SPIDERWEB_CONTROL_STATE_KEY_HEX="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
            mode_encrypted="on"
        else
            unset SPIDERWEB_CONTROL_STATE_KEY_HEX || true
            mode_encrypted="off"
        fi

        echo "[INFO] [iteration $iteration/$ITERATIONS] ports=$SPIDERWEB_PORT,$NODE1_PORT,$NODE2_PORT metrics=$SPIDERWEB_METRICS_PORT operator=$mode_operator encrypted=$mode_encrypted"
        run_log="$(mktemp)"
        if bash "$BASE_TEST" 2>&1 | tee "$run_log"; then
            rm -f "$run_log"
            break
        fi

        if grep -q "AddressInUse" "$run_log" && [[ "$attempt" -lt 6 ]]; then
            attempt=$((attempt + 1))
            echo "[WARN] [iteration $iteration/$ITERATIONS] port collision detected; retrying with new ports (attempt $attempt/6)"
            rm -f "$run_log"
            continue
        fi
        rm -f "$run_log"
        exit 1
    done
done

echo "[PASS] soak/chaos run completed ($ITERATIONS iterations)"
