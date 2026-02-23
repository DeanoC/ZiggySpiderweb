#!/usr/bin/env bash
# Wrapper integration test:
# - enables operator-token protection
# - validates deny/allow behavior
# - runs the full distributed workspace failover scenario

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_TEST="$ROOT_DIR/test-env/test-distributed-workspace.sh"

if [[ ! -x "$BASE_TEST" ]]; then
    echo "[FAIL] Missing base test script: $BASE_TEST" >&2
    exit 1
fi

export SPIDERWEB_CONTROL_OPERATOR_TOKEN="${SPIDERWEB_CONTROL_OPERATOR_TOKEN:-operator-token-integration-secret}"
export ASSERT_OPERATOR_TOKEN_GATE=1

echo "[INFO] Running distributed workspace test with SPIDERWEB_CONTROL_OPERATOR_TOKEN enabled"

exec bash "$BASE_TEST" "$@"
