#!/usr/bin/env bash
# Distributed workspace matrix:
# - failover + reconnect (base scenario)
# - project_up bootstrap scenario
# - drift/reconcile scenario

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BASE_TEST="$ROOT_DIR/test-env/test-distributed-workspace.sh"
BOOTSTRAP_TEST="$ROOT_DIR/test-env/test-distributed-workspace-bootstrap.sh"
DRIFT_TEST="$ROOT_DIR/test-env/test-distributed-workspace-drift.sh"

for script in "$BASE_TEST" "$BOOTSTRAP_TEST" "$DRIFT_TEST"; do
    if [[ ! -x "$script" ]]; then
        echo "[FAIL] Missing executable script: $script" >&2
        exit 1
    fi
done

echo "[INFO] Running matrix scenario 1/3: failover + reconnect"
bash "$BASE_TEST"

echo "[INFO] Running matrix scenario 2/3: bootstrap"
SKIP_BUILD=1 bash "$BOOTSTRAP_TEST"

echo "[INFO] Running matrix scenario 3/3: drift"
SKIP_BUILD=1 bash "$DRIFT_TEST"

echo "[PASS] distributed workspace matrix completed"
