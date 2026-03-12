#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_SCRIPT="${HARNESS_SCRIPT:-$ROOT_DIR/test-env/test-external-codex-workspace.sh}"
REPEAT_OUTPUT_DIR="${REPEAT_OUTPUT_DIR:-/tmp/spiderweb-external-codex-repeatability-$(date +%Y%m%d-%H%M%S)-$$}"
REPEAT_RUNS="${REPEAT_RUNS:-3}"
REPEAT_AUTH_MODE="${REPEAT_AUTH_MODE:-existing_login}"
REPEAT_KEEP_TEMP="${REPEAT_KEEP_TEMP:-0}"
REPEAT_RUN_TIMEOUT_SECONDS="${REPEAT_RUN_TIMEOUT_SECONDS:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

CURRENT_RUN_PID=""
CURRENT_RUN_PGID=""
CURRENT_RUN_INDEX=""

kill_current_run() {
    if [[ -n "$CURRENT_RUN_PGID" ]]; then
        kill -TERM -- "-$CURRENT_RUN_PGID" >/dev/null 2>&1 || true
        sleep 1
        kill -KILL -- "-$CURRENT_RUN_PGID" >/dev/null 2>&1 || true
    elif [[ -n "$CURRENT_RUN_PID" ]]; then
        kill "$CURRENT_RUN_PID" >/dev/null 2>&1 || true
    fi
}

cleanup_repeatability() {
    local exit_code=$?
    if [[ $exit_code -ne 0 && -n "$CURRENT_RUN_INDEX" ]]; then
        log_info "Cleaning up interrupted repeatability run $CURRENT_RUN_INDEX ..."
    fi
    kill_current_run
    exit "$exit_code"
}
trap cleanup_repeatability EXIT INT TERM

if [[ ! -f "$HARNESS_SCRIPT" ]]; then
    log_fail "missing harness script: $HARNESS_SCRIPT"
    exit 1
fi

if ! [[ "$REPEAT_RUNS" =~ ^[0-9]+$ ]] || [[ "$REPEAT_RUNS" -lt 1 ]]; then
    log_fail "REPEAT_RUNS must be a positive integer"
    exit 1
fi

mkdir -p "$REPEAT_OUTPUT_DIR"

run_once() {
    local run_index="$1"
    local run_dir="$REPEAT_OUTPUT_DIR/run-$run_index"
    local exit_code=0
    local run_log="$run_dir/harness.log"

    mkdir -p "$run_dir"
    log_info "Starting repeatability run $run_index/$REPEAT_RUNS ..."
    CURRENT_RUN_INDEX="$run_index"

    (
        if (( REPEAT_RUN_TIMEOUT_SECONDS > 0 )) && command -v timeout >/dev/null 2>&1; then
            OUTPUT_DIR="$run_dir" \
                CODEX_MODE=live \
                CODEX_AUTH_MODE="$REPEAT_AUTH_MODE" \
                KEEP_TEMP="$REPEAT_KEEP_TEMP" \
                timeout "$REPEAT_RUN_TIMEOUT_SECONDS" bash "$HARNESS_SCRIPT"
        else
            OUTPUT_DIR="$run_dir" \
                CODEX_MODE=live \
                CODEX_AUTH_MODE="$REPEAT_AUTH_MODE" \
                KEEP_TEMP="$REPEAT_KEEP_TEMP" \
                bash "$HARNESS_SCRIPT"
        fi
    ) >"$run_log" 2>&1 &
    CURRENT_RUN_PID="$!"
    CURRENT_RUN_PGID="$(ps -o pgid= "$CURRENT_RUN_PID" | tr -d '[:space:]')"

    if wait "$CURRENT_RUN_PID"; then
        exit_code=0
    else
        exit_code=$?
    fi
    CURRENT_RUN_PID=""
    CURRENT_RUN_PGID=""
    CURRENT_RUN_INDEX=""

    python3 - "$run_dir" "$run_index" "$exit_code" <<'PY'
import json
import re
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
payload = {
    "run_index": int(sys.argv[2]),
    "harness_exit_code": int(sys.argv[3]),
}

def load_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))

usage = load_json(run_dir / "codex_usage_report.json")
validation = load_json(run_dir / "game_validation.json")
bootstrap = load_json(run_dir / "bootstrap_provenance.json")
exec_summary = load_json(run_dir / "codex_exec_summary.json")
runtime = load_json(run_dir / "snapshots" / "codex_runtime.json")

handoff_reason = None
handoff_path = run_dir / "codex_handoff" / "README.md"
if handoff_path.exists():
    match = re.search(r"^- Reason: (.+)$", handoff_path.read_text(encoding="utf-8"), re.MULTILINE)
    if match:
        handoff_reason = match.group(1).strip()

payload["selected_auth_mode"] = (runtime or {}).get("selected_auth_mode")
payload["validation_ok"] = (validation or {}).get("ok")
payload["reliability_ok"] = (usage or {}).get("reliability_ok")
payload["workspace_bootstrap_ok"] = (usage or {}).get("workspace_bootstrap_ok")
payload["machine_independence_ok"] = (usage or {}).get("machine_independence_ok")
payload["candidate_venom_gaps"] = [item.get("venom_id") for item in (usage or {}).get("candidate_venom_gaps", [])]
payload["project_bound_services"] = (usage or {}).get("project_bound_services", [])
payload["required_reads_complete"] = (bootstrap or {}).get("required_reads_complete")
payload["bootstrap_actions"] = [item.get("action") for item in (bootstrap or {}).get("agent_bootstrap_actions_after_mount", [])]
payload["turn_completed"] = (exec_summary or {}).get("turn_completed")
payload["stall_stage"] = (exec_summary or {}).get("stall_stage")
payload["handoff_reason"] = handoff_reason
payload["run_log"] = str(run_dir / "harness.log")

(run_dir / "repeatability_summary.json").write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

    if [[ "$exit_code" -eq 0 ]]; then
        log_pass "repeatability run $run_index completed successfully"
    else
        log_fail "repeatability run $run_index exited with $exit_code"
        tail -n 120 "$run_log" || true
    fi
}

for run_index in $(seq 1 "$REPEAT_RUNS"); do
    run_once "$run_index"
done

python3 - "$REPEAT_OUTPUT_DIR" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
runs = []
for path in sorted(root.glob("run-*/repeatability_summary.json")):
    runs.append(json.loads(path.read_text(encoding="utf-8")))

gap_counter = Counter()
for run in runs:
    gap_counter.update(run.get("candidate_venom_gaps", []))

summary = {
    "repeat_output_dir": str(root),
    "run_count": len(runs),
    "successful_runs": sum(1 for run in runs if run.get("harness_exit_code") == 0),
    "reliability_passes": sum(1 for run in runs if run.get("reliability_ok") is True),
    "workspace_bootstrap_passes": sum(1 for run in runs if run.get("workspace_bootstrap_ok") is True),
    "validation_passes": sum(1 for run in runs if run.get("validation_ok") is True),
    "machine_independence_passes": sum(1 for run in runs if run.get("machine_independence_ok") is True),
    "gap_frequency": dict(sorted(gap_counter.items())),
    "runs": runs,
}

(root / "repeatability_summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

lines = [
    "# External Codex Repeatability",
    "",
    f"- Runs: {summary['run_count']}",
    f"- Successful Harness Runs: {summary['successful_runs']}",
    f"- Reliability Passes: {summary['reliability_passes']}",
    f"- Workspace Bootstrap Passes: {summary['workspace_bootstrap_passes']}",
    f"- Validation Passes: {summary['validation_passes']}",
    f"- Machine Independence Passes: {summary['machine_independence_passes']}",
    "",
    "## Gap Frequency",
]
if summary["gap_frequency"]:
    for key, value in summary["gap_frequency"].items():
        lines.append(f"- {key}: {value}")
else:
    lines.append("- none")

lines.extend([
    "",
    "| Run | Exit | Reliability | Bootstrap | Validation | Independence | Handoff | Stall |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
])
for run in runs:
    lines.append(
        "| {run_index} | {harness_exit_code} | {reliability_ok} | {workspace_bootstrap_ok} | {validation_ok} | {machine_independence_ok} | {handoff_reason} | {stall_stage} |".format(
            run_index=run.get("run_index"),
            harness_exit_code=run.get("harness_exit_code"),
            reliability_ok="yes" if run.get("reliability_ok") else "no",
            workspace_bootstrap_ok="yes" if run.get("workspace_bootstrap_ok") else "no",
            validation_ok="yes" if run.get("validation_ok") else "no",
            machine_independence_ok="yes" if run.get("machine_independence_ok") else "no",
            handoff_reason=run.get("handoff_reason") or "",
            stall_stage=run.get("stall_stage") or "",
        )
    )

(root / "repeatability_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

log_pass "repeatability summary written to $REPEAT_OUTPUT_DIR"
