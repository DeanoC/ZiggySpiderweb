#!/usr/bin/env bash
# Wrapper integration test:
# - enables encrypted control-plane snapshot persistence
# - runs the full distributed workspace failover scenario

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_TEST="$ROOT_DIR/test-env/test-distributed-workspace.sh"

if [[ ! -x "$BASE_TEST" ]]; then
    echo "[FAIL] Missing base test script: $BASE_TEST" >&2
    exit 1
fi

if [[ -z "${SPIDERWEB_CONTROL_STATE_KEY_HEX:-}" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[FAIL] python3 is required to generate SPIDERWEB_CONTROL_STATE_KEY_HEX" >&2
        exit 1
    fi
    SPIDERWEB_CONTROL_STATE_KEY_HEX="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
fi

export SPIDERWEB_CONTROL_STATE_KEY_HEX
echo "[INFO] Running distributed workspace test with SPIDERWEB_CONTROL_STATE_KEY_HEX enabled"

exec bash "$BASE_TEST" "$@"
