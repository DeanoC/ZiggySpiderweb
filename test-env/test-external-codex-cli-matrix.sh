#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_SCRIPT="${HARNESS_SCRIPT:-$ROOT_DIR/test-env/test-external-codex-workspace.sh}"
MATRIX_OUTPUT_DIR="${MATRIX_OUTPUT_DIR:-$ROOT_DIR/test-env/out/external-codex-cli-matrix-$(date +%Y%m%d-%H%M%S)}"
MATRIX_AUTH_MODE="${MATRIX_AUTH_MODE:-existing_login}"
MATRIX_TIMEOUT_SECONDS="${MATRIX_TIMEOUT_SECONDS:-240}"
MATRIX_IDLE_TIMEOUT_SECONDS="${MATRIX_IDLE_TIMEOUT_SECONDS:-120}"
MATRIX_KEEP_TEMP="${MATRIX_KEEP_TEMP:-0}"

DEFAULT_CASES=$'v0.110.0-json-no-pty|0.110.0|0|1|1\nv0.111.0-json-no-pty|0.111.0|0|1|1\nv0.111.0-json-pty|0.111.0|1|1|1'
MATRIX_CASES="${MATRIX_CASES:-$DEFAULT_CASES}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

mkdir -p "$MATRIX_OUTPUT_DIR"

if [[ ! -f "$HARNESS_SCRIPT" ]]; then
    log_fail "missing harness script: $HARNESS_SCRIPT"
    exit 1
fi

run_case() {
    local case_name="$1"
    local codex_version="$2"
    local use_pty="$3"
    local json_events="$4"
    local disable_collab="$5"
    local case_dir="$MATRIX_OUTPUT_DIR/$case_name"

    mkdir -p "$case_dir"
    log_info "Running case $case_name (version=$codex_version, pty=$use_pty, json=$json_events, disable_collab=$disable_collab)"

    local exit_code=0
    if OUTPUT_DIR="$case_dir" \
        CODEX_MODE=live \
        CODEX_AUTH_MODE="$MATRIX_AUTH_MODE" \
        CODEX_CLI_VERSION="$codex_version" \
        CODEX_USE_PTY="$use_pty" \
        CODEX_JSON_EVENTS="$json_events" \
        CODEX_DISABLE_COLLABORATION_MODES="$disable_collab" \
        CODEX_TIMEOUT_SECONDS="$MATRIX_TIMEOUT_SECONDS" \
        CODEX_IDLE_TIMEOUT_SECONDS="$MATRIX_IDLE_TIMEOUT_SECONDS" \
        KEEP_TEMP="$MATRIX_KEEP_TEMP" \
        bash "$HARNESS_SCRIPT"; then
        exit_code=0
    else
        exit_code=$?
    fi

    python3 - "$case_dir" "$case_name" "$codex_version" "$use_pty" "$json_events" "$disable_collab" "$exit_code" <<'PY'
import json
import re
import sys
from pathlib import Path

case_dir = Path(sys.argv[1])
payload = {
    "case_name": sys.argv[2],
    "codex_cli_version": sys.argv[3],
    "use_pty": sys.argv[4] == "1",
    "json_events": sys.argv[5] == "1",
    "disable_collaboration_modes": sys.argv[6] == "1",
    "harness_exit_code": int(sys.argv[7]),
}

def load_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))

runtime = load_json(case_dir / "snapshots" / "codex_runtime.json")
validation = load_json(case_dir / "game_validation.json")
usage = load_json(case_dir / "codex_usage_report.json")
exec_summary = load_json(case_dir / "codex_exec_summary.json")

handoff_reason = None
handoff_path = case_dir / "codex_handoff" / "README.md"
if handoff_path.exists():
    match = re.search(r"^- Reason: (.+)$", handoff_path.read_text(encoding="utf-8"), re.MULTILINE)
    if match:
        handoff_reason = match.group(1).strip()

payload["selected_auth_mode"] = (runtime or {}).get("selected_auth_mode")
payload["resolved_codex_version"] = (runtime or {}).get("codex_version")
payload["validation_ok"] = (validation or {}).get("ok")
payload["validation_reason"] = (validation or {}).get("reason")
payload["reliability_ok"] = (usage or {}).get("reliability_ok")
payload["machine_independence_ok"] = (usage or {}).get("machine_independence_ok")
payload["usage_skipped_reason"] = (usage or {}).get("skipped_reason")
payload["handoff_reason"] = handoff_reason
payload["event_count"] = (exec_summary or {}).get("event_count")
payload["stall_stage"] = (exec_summary or {}).get("stall_stage")
payload["last_event_type"] = ((exec_summary or {}).get("last_event") or {}).get("type")
payload["last_completed_item_type"] = ((exec_summary or {}).get("last_completed_item") or {}).get("type")
payload["last_agent_message"] = (exec_summary or {}).get("last_agent_message")
payload["turn_completed"] = (exec_summary or {}).get("turn_completed")
payload["json_events_detected"] = (exec_summary or {}).get("json_events_detected")

(case_dir / "case_summary.json").write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

    if [[ "$exit_code" -eq 0 ]]; then
        log_pass "case $case_name completed successfully"
    else
        log_fail "case $case_name finished with harness exit code $exit_code"
    fi
}

while IFS='|' read -r case_name codex_version use_pty json_events disable_collab; do
    [[ -z "${case_name:-}" ]] && continue
    run_case "$case_name" "$codex_version" "$use_pty" "$json_events" "$disable_collab"
done <<<"$MATRIX_CASES"

python3 - "$MATRIX_OUTPUT_DIR" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
cases = []
for path in sorted(root.glob("*/case_summary.json")):
    cases.append(json.loads(path.read_text(encoding="utf-8")))

summary = {
    "matrix_output_dir": str(root),
    "case_count": len(cases),
    "cases": cases,
}
(root / "matrix_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    "# External Codex CLI Matrix",
    "",
    f"- Cases: {len(cases)}",
    f"- Output Dir: {root}",
    "",
    "| Case | Version | PTY | JSON | Exit | Handoff | Stall | Last Event | Last Item |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
]
for case in cases:
    lines.append(
        "| {case_name} | {resolved_codex_version} | {use_pty} | {json_events} | {harness_exit_code} | {handoff_reason} | {stall_stage} | {last_event_type} | {last_completed_item_type} |".format(
            case_name=case.get("case_name", ""),
            resolved_codex_version=case.get("resolved_codex_version", case.get("codex_cli_version", "")),
            use_pty="yes" if case.get("use_pty") else "no",
            json_events="yes" if case.get("json_events") else "no",
            harness_exit_code=case.get("harness_exit_code"),
            handoff_reason=case.get("handoff_reason") or "",
            stall_stage=case.get("stall_stage") or "",
            last_event_type=case.get("last_event_type") or "",
            last_completed_item_type=case.get("last_completed_item_type") or "",
        )
    )

(root / "matrix_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

log_pass "matrix summary written to $MATRIX_OUTPUT_DIR"
