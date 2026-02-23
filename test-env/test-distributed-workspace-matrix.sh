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
SPIDERWEB_PORT="${MATRIX_SCENARIO1_SPIDERWEB_PORT:-28790}" \
NODE1_PORT="${MATRIX_SCENARIO1_NODE1_PORT:-28911}" \
NODE2_PORT="${MATRIX_SCENARIO1_NODE2_PORT:-28912}" \
bash "$BASE_TEST"

echo "[INFO] Running matrix scenario 2/3: bootstrap"
SPIDERWEB_PORT="${MATRIX_SCENARIO2_SPIDERWEB_PORT:-28791}" \
NODE1_PORT="${MATRIX_SCENARIO2_NODE1_PORT:-28921}" \
NODE2_PORT="${MATRIX_SCENARIO2_NODE2_PORT:-28922}" \
SKIP_BUILD=1 bash "$BOOTSTRAP_TEST"

echo "[INFO] Running matrix scenario 3/3: drift"
SPIDERWEB_PORT="${MATRIX_SCENARIO3_SPIDERWEB_PORT:-28792}" \
NODE1_PORT="${MATRIX_SCENARIO3_NODE1_PORT:-28931}" \
NODE2_PORT="${MATRIX_SCENARIO3_NODE2_PORT:-28932}" \
SKIP_BUILD=1 bash "$DRIFT_TEST"

echo "[PASS] distributed workspace matrix completed"
