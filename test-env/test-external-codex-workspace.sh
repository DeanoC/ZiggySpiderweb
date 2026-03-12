#!/usr/bin/env bash
# Installer-first external Codex E2E scenario:
# - install Spiderweb into an isolated temp HOME via install.sh
# - start Spiderweb on Linux with an internal runtime root
# - attach a clean standalone workspace node and a separate remote data node
# - compose a workspace with canonical /nodes/local/fs and /shared_data mounts
# - namespace-mount the workspace
# - run a separate plain Codex CLI against the mounted workspace
# - validate the generated Python text adventure and emit usage reports

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSET_DIR="$ROOT_DIR/test-env/codex-assets"
HOST_HOME_DIR="${HOME:-}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"

if [[ -v SPIDERWEB_PORT ]]; then
    SPIDERWEB_PORT="$SPIDERWEB_PORT"
else
    SPIDERWEB_PORT=""
fi
if [[ -v LOCAL_WORKSPACE_NODE_PORT ]]; then
    LOCAL_WORKSPACE_NODE_PORT="$LOCAL_WORKSPACE_NODE_PORT"
else
    LOCAL_WORKSPACE_NODE_PORT=""
fi
if [[ -v REMOTE_NODE_PORT ]]; then
    REMOTE_NODE_PORT="$REMOTE_NODE_PORT"
else
    REMOTE_NODE_PORT=""
fi

CODEX_MODE="${CODEX_MODE:-auto}"
CODEX_LAUNCH_CMD="${CODEX_LAUNCH_CMD:-}"
TRACE_BACKEND="${TRACE_BACKEND:-strace}"
KEEP_TEMP="${KEEP_TEMP:-0}"
CODEX_BIN="${CODEX_BIN:-}"
CODEX_CLI_VERSION="${CODEX_CLI_VERSION:-0.111.0}"
CODEX_AUTH_MODE="${CODEX_AUTH_MODE:-auto}"
CODEX_API_KEY_ENV="${CODEX_API_KEY_ENV:-OPENAI_API_KEY}"
CODEX_HOME_DIR="${CODEX_HOME_DIR:-$HOST_HOME_DIR}"
CODEX_TIMEOUT_SECONDS="${CODEX_TIMEOUT_SECONDS:-900}"
CODEX_IDLE_TIMEOUT_SECONDS="${CODEX_IDLE_TIMEOUT_SECONDS:-0}"
CODEX_JSON_EVENTS="${CODEX_JSON_EVENTS:-1}"
CODEX_USE_PTY="${CODEX_USE_PTY:-1}"
CODEX_DISABLE_COLLABORATION_MODES="${CODEX_DISABLE_COLLABORATION_MODES:-1}"
CODEX_DISABLE_APPS="${CODEX_DISABLE_APPS:-1}"
CODEX_DISABLE_SHELL_SNAPSHOT="${CODEX_DISABLE_SHELL_SNAPSHOT:-1}"
CODEX_ALLOW_HOST_CODEX_HOME="${CODEX_ALLOW_HOST_CODEX_HOME:-1}"
CODEX_INSTALL_IF_MISSING="${CODEX_INSTALL_IF_MISSING:-1}"
MANUAL_EXIT_CODE=20
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/test-env/out/external-codex-workspace-$(date +%Y%m%d-%H%M%S)}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

require_bin() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_fail "required command not found: $1"
        exit 1
    fi
}

run_with_timeout() {
    local seconds="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$seconds" "$@"
    else
        "$@"
    fi
}

pick_free_port() {
    python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

json_field() {
    local json="$1"
    local filter="$2"
    jq -er "$filter" <<<"$json"
}

shell_quote() {
    printf '%q' "$1"
}

ensure_linux_host() {
    local platform
    platform="$(uname -s)"
    if [[ "$platform" != "Linux" ]]; then
        log_fail "this harness currently supports Linux only (found: $platform)"
        exit 1
    fi
}

SPIDERWEB_PID=""
LOCAL_WORKSPACE_NODE_PID=""
REMOTE_NODE_PID=""
MOUNT_PID=""
PROJECT_ID=""
PROJECT_TOKEN=""
SPIDERWEB_AUTH_TOKEN=""
LOCAL_WORKSPACE_NODE_ID=""
REMOTE_NODE_ID=""
CODEX_RESOLVED_BIN=""
CODEX_RESOLVED_VERSION=""
CODEX_SELECTED_AUTH_MODE=""
CODEX_EFFECTIVE_HOME=""
CODEX_FAILURE_REASON=""
CODEX_RUN_STATE="not_started"
CODEX_LAUNCH_SOURCE=""
declare -a CODEX_ENV_BASE=()

cleanup() {
    local exit_code=$?

    if [[ -n "${MOUNT_POINT:-}" && -d "${MOUNT_POINT:-}" ]]; then
        if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$MOUNT_POINT"; then
            fusermount3 -u "$MOUNT_POINT" >/dev/null 2>&1 || true
        fi
    fi

    if [[ -n "${MOUNT_PID:-}" ]]; then
        kill "$MOUNT_PID" >/dev/null 2>&1 || true
        wait "$MOUNT_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${REMOTE_NODE_PID:-}" ]]; then
        kill "$REMOTE_NODE_PID" >/dev/null 2>&1 || true
        wait "$REMOTE_NODE_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${LOCAL_WORKSPACE_NODE_PID:-}" ]]; then
        kill "$LOCAL_WORKSPACE_NODE_PID" >/dev/null 2>&1 || true
        wait "$LOCAL_WORKSPACE_NODE_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${SPIDERWEB_PID:-}" ]]; then
        kill "$SPIDERWEB_PID" >/dev/null 2>&1 || true
        wait "$SPIDERWEB_PID" >/dev/null 2>&1 || true
    fi

    if [[ "$KEEP_TEMP" == "1" ]]; then
        log_info "Preserved temporary workspace at ${TEST_TMP_DIR:-<unset>}"
    elif [[ -n "${TEST_TMP_DIR:-}" && -d "${TEST_TMP_DIR:-}" ]]; then
        rm -rf "$TEST_TMP_DIR"
    fi

    exit "$exit_code"
}
trap cleanup EXIT

ensure_linux_host
require_bin jq
require_bin python3
require_bin fusermount3
require_bin bash

if [[ -z "$SPIDERWEB_PORT" ]]; then
    SPIDERWEB_PORT="$(pick_free_port)"
fi
if [[ -z "$LOCAL_WORKSPACE_NODE_PORT" ]]; then
    LOCAL_WORKSPACE_NODE_PORT="$(pick_free_port)"
fi
if [[ -z "$REMOTE_NODE_PORT" ]]; then
    REMOTE_NODE_PORT="$(pick_free_port)"
fi

mkdir -p "$OUTPUT_DIR" "$OUTPUT_DIR/logs" "$OUTPUT_DIR/snapshots"

TEST_TMP_DIR="$(mktemp -d)"
TEMP_HOME="$TEST_TMP_DIR/home"
INSTALL_DIR="$TEMP_HOME/.local/bin"
PATH="$INSTALL_DIR:$PATH"
export PATH
mkdir -p "$TEMP_HOME" "$INSTALL_DIR"

INSTALL_LOG="$OUTPUT_DIR/logs/install.log"
SPIDERWEB_LOG="$OUTPUT_DIR/logs/spiderweb.log"
LOCAL_WORKSPACE_NODE_LOG="$OUTPUT_DIR/logs/local-workspace-node.log"
REMOTE_NODE_LOG="$OUTPUT_DIR/logs/remote-node.log"
MOUNT_LOG="$OUTPUT_DIR/logs/namespace-mount.log"
CODEX_STDOUT_LOG="$OUTPUT_DIR/logs/codex.stdout.log"
CODEX_STDERR_LOG="$OUTPUT_DIR/logs/codex.stderr.log"
CODEX_PTY_LOG="$OUTPUT_DIR/logs/codex.pty.log"
CODEX_INSTALL_LOG="$OUTPUT_DIR/logs/codex-install.log"
CODEX_AUTH_LOG="$OUTPUT_DIR/logs/codex-auth.log"
CODEX_EVENT_SUMMARY="$OUTPUT_DIR/codex_exec_summary.json"

SPIDERWEB_CONFIG_FILE="$TEST_TMP_DIR/spiderweb.json"
LTM_DIR="$TEST_TMP_DIR/ltm"
SPIDERWEB_RUNTIME_ROOT="$TEST_TMP_DIR/spiderweb-runtime"
WORKSPACE_EXPORT_ROOT="$TEST_TMP_DIR/workspace-export"
REMOTE_EXPORT_ROOT="$TEST_TMP_DIR/remote-export"
MOUNT_POINT="$TEST_TMP_DIR/mount"
MOUNT_WORKSPACE_PATH="$MOUNT_POINT/nodes/local/fs"
PROMPT_FILE="$OUTPUT_DIR/codex_prompt.txt"
HANDOFF_DIR="$OUTPUT_DIR/codex_handoff"
VALIDATION_OUTPUT="$OUTPUT_DIR/game_validation.json"
USAGE_JSON="$OUTPUT_DIR/codex_usage_report.json"
USAGE_MD="$OUTPUT_DIR/codex_usage_report.md"
STRACE_PREFIX="$OUTPUT_DIR/logs/codex.strace"
TASK_FILE="$WORKSPACE_EXPORT_ROOT/TASK.md"
VALIDATOR_SRC="$ASSET_DIR/validate_text_adventure.py"
PARSER_SRC="$ASSET_DIR/parse_codex_usage_report.py"
CODEX_EVENT_SUMMARY_SRC="$ASSET_DIR/summarize_codex_exec_json.py"
CONTROL_URL="ws://$BIND_ADDR:$SPIDERWEB_PORT/"
CODEX_RUNTIME_ROOT="$TEST_TMP_DIR/codex-runtime"
CODEX_NPM_PREFIX="$CODEX_RUNTIME_ROOT/npm-prefix"
CODEX_ISOLATED_HOME="$CODEX_RUNTIME_ROOT/home"
CODEX_XDG_CONFIG_HOME="$CODEX_RUNTIME_ROOT/xdg-config"
CODEX_XDG_CACHE_HOME="$CODEX_RUNTIME_ROOT/xdg-cache"
CODEX_XDG_DATA_HOME="$CODEX_RUNTIME_ROOT/xdg-data"
CODEX_XDG_STATE_HOME="$CODEX_RUNTIME_ROOT/xdg-state"

AUTH_TOKENS_FILE="$LTM_DIR/auth_tokens.json"
mkdir -p \
    "$LTM_DIR" \
    "$SPIDERWEB_RUNTIME_ROOT/agents" \
    "$SPIDERWEB_RUNTIME_ROOT/templates" \
    "$WORKSPACE_EXPORT_ROOT" \
    "$REMOTE_EXPORT_ROOT" \
    "$MOUNT_POINT" \
    "$CODEX_RUNTIME_ROOT"

build_usage_report() {
    local skipped_reason="${1-}"
    local -a cmd=(
        python3 "$PARSER_SRC"
        --strace-prefix "$STRACE_PREFIX"
        --mount-root "$MOUNT_POINT"
        --artifact-root "$OUTPUT_DIR"
        --project-id "${PROJECT_ID:-unknown}"
        --mode "$CODEX_MODE"
        --mounted-services "$OUTPUT_DIR/snapshots/mounted_services.json"
        --venom-packages "$OUTPUT_DIR/snapshots/venom_packages.json"
        --repo-root "$ROOT_DIR"
        --json-output "$USAGE_JSON"
        --markdown-output "$USAGE_MD"
    )
    if [[ -d "$CODEX_RUNTIME_ROOT" ]]; then
        cmd+=(--allowed-runtime-root "$CODEX_RUNTIME_ROOT")
    fi
    if [[ "$CODEX_ALLOW_HOST_CODEX_HOME" == "1" && -n "$CODEX_HOME_DIR" && -d "$CODEX_HOME_DIR/.codex" ]]; then
        cmd+=(--allowed-host-write-prefix "$CODEX_HOME_DIR/.codex")
    fi
    if [[ -n "$skipped_reason" ]]; then
        cmd+=(--skipped-reason "$skipped_reason")
    fi
    "${cmd[@]}"
}

write_skip_outputs() {
    local reason="$1"
    build_usage_report "$reason"

    python3 - "$VALIDATION_OUTPUT" "$reason" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "ok": False,
    "reason": sys.argv[2],
    "skipped": True,
    "validation_ok": False,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_codex_runtime_snapshot() {
    jq -cn \
        --arg bin "${CODEX_RESOLVED_BIN:-}" \
        --arg version "${CODEX_RESOLVED_VERSION:-}" \
        --arg requested_auth "$CODEX_AUTH_MODE" \
        --arg selected_auth "${CODEX_SELECTED_AUTH_MODE:-}" \
        --arg effective_home "${CODEX_EFFECTIVE_HOME:-}" \
        --arg launch_source "${CODEX_LAUNCH_SOURCE:-}" \
        --arg runtime_root "$CODEX_RUNTIME_ROOT" \
        --arg existing_home "$CODEX_HOME_DIR" \
        --arg timeout_seconds "$CODEX_TIMEOUT_SECONDS" \
        --arg idle_timeout_seconds "$CODEX_IDLE_TIMEOUT_SECONDS" \
        --arg json_events "$CODEX_JSON_EVENTS" \
        --arg use_pty "$CODEX_USE_PTY" \
        --arg disable_collaboration_modes "$CODEX_DISABLE_COLLABORATION_MODES" \
        --arg disable_apps "$CODEX_DISABLE_APPS" \
        --arg disable_shell_snapshot "$CODEX_DISABLE_SHELL_SNAPSHOT" \
        --arg allow_host_codex_home "$CODEX_ALLOW_HOST_CODEX_HOME" \
        --arg launch_cmd_custom "$CODEX_LAUNCH_CMD" \
        '{
            codex_bin: $bin,
            codex_version: $version,
            requested_auth_mode: $requested_auth,
            selected_auth_mode: $selected_auth,
            effective_home: $effective_home,
            launch_source: $launch_source,
            codex_runtime_root: $runtime_root,
            existing_login_home: $existing_home,
            timeout_seconds: ($timeout_seconds | tonumber),
            idle_timeout_seconds: ($idle_timeout_seconds | tonumber),
            json_events: ($json_events == "1"),
            use_pty: ($use_pty == "1"),
            disable_collaboration_modes: ($disable_collaboration_modes == "1"),
            disable_apps: ($disable_apps == "1"),
            disable_shell_snapshot: ($disable_shell_snapshot == "1"),
            allow_host_codex_home: ($allow_host_codex_home == "1"),
            custom_launch_cmd: ($launch_cmd_custom | if . == "" then null else . end)
        }' > "$OUTPUT_DIR/snapshots/codex_runtime.json"
}

handoff_intro() {
    case "$CODEX_RUN_STATE" in
        not_started)
            printf '%s\n' "This run stopped before live Codex execution."
            ;;
        running)
            printf '%s\n' "This run reached live Codex execution, but Codex did not finish successfully."
            ;;
        completed)
            printf '%s\n' "Codex finished running, but the overall E2E did not pass validation/reporting."
            ;;
        *)
            printf '%s\n' "This run preserved a handoff bundle after an incomplete external Codex attempt."
            ;;
    esac
}

write_handoff_bundle() {
    local reason="$1"
    mkdir -p "$HANDOFF_DIR"
    cp "$PROMPT_FILE" "$HANDOFF_DIR/PROMPT.txt"
    cp "$TASK_FILE" "$HANDOFF_DIR/TASK.md"
    cp "$OUTPUT_DIR/snapshots/protocol.json" "$HANDOFF_DIR/protocol.json"
    cp "$OUTPUT_DIR/snapshots/mounted_services.json" "$HANDOFF_DIR/mounted_services.json"
    cp "$OUTPUT_DIR/snapshots/workspace_status.json" "$HANDOFF_DIR/workspace_status.json"
    cp "$OUTPUT_DIR/snapshots/venom_packages.json" "$HANDOFF_DIR/venom_packages.json"
    if [[ -f "$OUTPUT_DIR/snapshots/codex_runtime.json" ]]; then
        cp "$OUTPUT_DIR/snapshots/codex_runtime.json" "$HANDOFF_DIR/codex_runtime.json"
    fi
    if [[ -f "$CODEX_EVENT_SUMMARY" ]]; then
        cp "$CODEX_EVENT_SUMMARY" "$HANDOFF_DIR/codex_exec_summary.json"
    fi

    local codex_summary_lines=""
    if [[ -f "$CODEX_EVENT_SUMMARY" ]]; then
        codex_summary_lines="$(jq -r '
            [
                "- Codex JSON events captured: \(.json_events_detected)",
                "- Codex event count: \(.event_count)",
                "- Last observed event: \(.last_event.type // "none")",
                "- Last completed item: \(.last_completed_item.type // "none")",
                "- Inferred stall stage: \(.stall_stage // "unknown")",
                (if .last_agent_message then "- Last agent message: " + (.last_agent_message | gsub("[\\r\\n]+"; " ") | .[0:220]) else empty end)
            ] | .[]' "$CODEX_EVENT_SUMMARY")"
    fi

    cat > "$HANDOFF_DIR/README.md" <<EOF
# Codex Handoff

$(handoff_intro)

- Reason: $reason
- Mode: $CODEX_MODE
- Project ID: ${PROJECT_ID:-unknown}
- Namespace mount root during the run: $MOUNT_POINT
- Writable project path inside the mount: $MOUNT_WORKSPACE_PATH
- Namespace metadata directory: $MOUNT_POINT/meta
- Project metadata directory: $MOUNT_POINT/projects/${PROJECT_ID:-unknown}/meta
- Remote shared-data directory: $MOUNT_POINT/shared_data
- Codex auth mode selected: ${CODEX_SELECTED_AUTH_MODE:-unresolved}
- Codex binary: ${CODEX_RESOLVED_BIN:-unresolved}
- Codex stdout log: $CODEX_STDOUT_LOG
- Codex stderr log: $CODEX_STDERR_LOG
- Codex PTY transcript: $CODEX_PTY_LOG

${codex_summary_lines}

Rerun a strict live test with the default launcher:

\`\`\`bash
CODEX_MODE=live \\
CODEX_AUTH_MODE=api_key \\
OPENAI_API_KEY=... \\
bash test-env/test-external-codex-workspace.sh
\`\`\`

Optional custom launch templates may use these placeholders:

- \`{codex_bin}\`
- \`{workspace_root}\`
- \`{namespace_root}\`
- \`{namespace_meta_dir}\`
- \`{project_meta_dir}\`
- \`{shared_data_dir}\`
- \`{prompt_file}\`
- \`{artifact_dir}\`

If you need the temporary environment to stay live for a manual handoff, rerun with \`KEEP_TEMP=1\`.
EOF
}

wait_for_control_ready() {
    for _ in $(seq 1 180); do
        if [[ -f "$AUTH_TOKENS_FILE" ]]; then
            SPIDERWEB_AUTH_TOKEN="$(jq -r '.admin_token // empty' "$AUTH_TOKENS_FILE" 2>/dev/null || true)"
            if [[ -n "${SPIDERWEB_AUTH_TOKEN:-}" ]]; then
                export SPIDERWEB_AUTH_TOKEN
                if run_with_timeout 3 "$INSTALL_DIR/spiderweb-control" \
                    --url "$CONTROL_URL" \
                    --auth-token "$SPIDERWEB_AUTH_TOKEN" \
                    workspace_status '{"project_id":"system"}' >/dev/null 2>&1; then
                    return 0
                fi
            fi
        fi
        sleep 0.1
    done
    return 1
}

control_call() {
    local op="$1"
    local payload="${2-}"
    local output
    if [[ -n "$payload" ]]; then
        output="$(run_with_timeout 8 "$INSTALL_DIR/spiderweb-control" --url "$CONTROL_URL" --auth-token "$SPIDERWEB_AUTH_TOKEN" "$op" "$payload" 2>&1)" || {
            echo "$output" >&2
            return 1
        }
    else
        output="$(run_with_timeout 8 "$INSTALL_DIR/spiderweb-control" --url "$CONTROL_URL" --auth-token "$SPIDERWEB_AUTH_TOKEN" "$op" 2>&1)" || {
            echo "$output" >&2
            return 1
        }
    fi
    printf '%s\n' "$output"
}

wait_for_node_join() {
    local node_name="$1"
    local result_var="$2"
    local reply node_id
    for _ in $(seq 1 180); do
        reply="$(control_call node_list)" || {
            sleep 0.2
            continue
        }
        node_id="$(jq -r --arg node_name "$node_name" '.payload.nodes[]? | select(.node_name == $node_name) | .node_id' <<<"$reply" | head -n1)"
        if [[ -n "$node_id" ]]; then
            printf -v "$result_var" '%s' "$node_id"
            return 0
        fi
        sleep 0.2
    done
    return 1
}

wait_for_workspace_mounts() {
    local reply
    for _ in $(seq 1 180); do
        reply="$(control_call workspace_status "$(jq -cn --arg project_id "$PROJECT_ID" '{project_id: $project_id}')")" || {
            sleep 0.2
            continue
        }
        if jq -e '
            (((.payload.actual_mounts // []) + (.payload.mounts // [])) | map(.mount_path) | index("/nodes/local/fs")) != null and
            (((.payload.actual_mounts // []) + (.payload.mounts // [])) | map(.mount_path) | index("/shared_data")) != null
        ' >/dev/null <<<"$reply"; then
            printf '%s\n' "$reply" > "$OUTPUT_DIR/snapshots/workspace_status.control.json"
            return 0
        fi
        sleep 0.2
    done
    return 1
}

wait_for_namespace_mount() {
    for _ in $(seq 1 180); do
        if [[ -f "$MOUNT_POINT/meta/protocol.json" &&
              -f "$MOUNT_POINT/projects/$PROJECT_ID/meta/mounted_services.json" &&
              -f "$MOUNT_POINT/projects/$PROJECT_ID/meta/workspace_status.json" &&
              -f "$MOUNT_POINT/projects/$PROJECT_ID/meta/venom_packages.json" &&
              -d "$MOUNT_WORKSPACE_PATH" &&
              -d "$MOUNT_POINT/shared_data" ]]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

assert_clean_workspace_layout() {
    local path="$1"
    python3 - "$path" <<'PY'
import sys
from pathlib import Path

workspace = Path(sys.argv[1])
expected = ["TASK.md", "validate_game.py"]
entries = sorted(item.name for item in workspace.iterdir())
if entries != expected:
    raise SystemExit(f"expected clean workspace entries {expected}, found {entries}")
PY
}

inject_codex_cli_workarounds() {
    local cmd="$1"

    if [[ "$CODEX_DISABLE_COLLABORATION_MODES" == "1" && "$cmd" != *"--disable collaboration_modes"* ]]; then
        cmd="${cmd/ exec / exec --disable collaboration_modes }"
    fi
    if [[ "$CODEX_DISABLE_APPS" == "1" && "$cmd" != *"--disable apps"* ]]; then
        cmd="${cmd/ exec / exec --disable apps }"
    fi
    if [[ "$CODEX_DISABLE_SHELL_SNAPSHOT" == "1" && "$cmd" != *"--disable shell_snapshot"* ]]; then
        cmd="${cmd/ exec / exec --disable shell_snapshot }"
    fi
    if [[ "$CODEX_JSON_EVENTS" == "1" && "$cmd" != *" --json"* ]]; then
        cmd="${cmd/ exec / exec --json }"
    fi

    printf '%s' "$cmd"
}

render_prompt() {
    python3 - "$ASSET_DIR/external_codex_game_prompt.txt" "$PROMPT_FILE" \
        "$PROJECT_ID" \
        "$MOUNT_POINT" \
        "$MOUNT_POINT/meta" \
        "$MOUNT_POINT/projects/$PROJECT_ID/meta" \
        "$MOUNT_WORKSPACE_PATH" \
        "$MOUNT_POINT/shared_data" <<'PY'
from pathlib import Path
import sys

template_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
replacements = {
    "__PROJECT_ID__": sys.argv[3],
    "__MOUNT_ROOT__": sys.argv[4],
    "__NAMESPACE_META_DIR__": sys.argv[5],
    "__PROJECT_META_DIR__": sys.argv[6],
    "__WORKSPACE_ROOT__": sys.argv[7],
    "__SHARED_DATA_DIR__": sys.argv[8],
}

text = template_path.read_text(encoding="utf-8")
for key, value in replacements.items():
    text = text.replace(key, value)
output_path.write_text(text, encoding="utf-8")
PY
}

write_workspace_seed_files() {
    cp "$VALIDATOR_SRC" "$WORKSPACE_EXPORT_ROOT/validate_game.py"
    chmod +x "$WORKSPACE_EXPORT_ROOT/validate_game.py"
    cat > "$TASK_FILE" <<'EOF'
# Spiderweb Text Adventure Task

Build a Python terminal adventure in this workspace.

Required outputs:
- game.py
- game_manifest.json
- walkthrough.txt
- README.md

Rules:
- Treat this directory as the only writable project root.
- Preserve validate_game.py.
- Read the shared seed files exactly as instructed by the rendered prompt.
- Keep all project writes in this directory.
- In this external Codex CLI run, apply_patch is not available. Use shell commands or small local scripts to create and edit files here.
- After the required discovery reads, start implementing immediately instead of doing extra exploratory reads unless validation fails.
- Prefer writing all deliverables in one shell or Python file-generation step, then iterate only if validation fails.
- The victory line must be:
  VICTORY: Lantern of Nine Paths recovered
EOF
}

setup_spiderweb_runtime_root() {
    cp -R "$ROOT_DIR/templates/." "$SPIDERWEB_RUNTIME_ROOT/templates/"
}

resolve_candidate_codex_bin() {
    if [[ -n "$CODEX_BIN" ]]; then
        if [[ ! -x "$CODEX_BIN" ]]; then
            log_fail "CODEX_BIN is not executable: $CODEX_BIN"
            exit 1
        fi
        printf '%s\n' "$CODEX_BIN"
        return 0
    fi

    local on_path
    on_path="$(command -v codex 2>/dev/null || true)"
    if [[ -n "$on_path" ]]; then
        printf '%s\n' "$on_path"
        return 0
    fi

    if [[ -x "$HOST_HOME_DIR/.npm-global/bin/codex" ]]; then
        printf '%s\n' "$HOST_HOME_DIR/.npm-global/bin/codex"
        return 0
    fi

    return 1
}

codex_version_of() {
    local bin="$1"
    "$bin" --version 2>/dev/null | awk '{print $NF}' | tail -n1
}

install_pinned_codex() {
    require_bin npm
    mkdir -p "$CODEX_NPM_PREFIX"
    log_info "Installing pinned Codex CLI @openai/codex@$CODEX_CLI_VERSION into isolated prefix..."
    if ! npm install --no-fund --no-audit --prefix "$CODEX_NPM_PREFIX" "@openai/codex@$CODEX_CLI_VERSION" >"$CODEX_INSTALL_LOG" 2>&1; then
        log_fail "failed installing @openai/codex@$CODEX_CLI_VERSION"
        tail -n 120 "$CODEX_INSTALL_LOG" || true
        return 1
    fi

    CODEX_RESOLVED_BIN="$CODEX_NPM_PREFIX/node_modules/.bin/codex"
    if [[ ! -x "$CODEX_RESOLVED_BIN" ]]; then
        log_fail "isolated Codex installation did not produce an executable binary"
        return 1
    fi
    CODEX_RESOLVED_VERSION="$(codex_version_of "$CODEX_RESOLVED_BIN")"
    CODEX_LAUNCH_SOURCE="installed"
    return 0
}

ensure_codex_cli() {
    if [[ "$CODEX_MODE" == "manual" ]]; then
        return 0
    fi

    local candidate=""
    local candidate_version=""
    candidate="$(resolve_candidate_codex_bin || true)"
    if [[ -n "$candidate" ]]; then
        candidate_version="$(codex_version_of "$candidate")"
    fi

    if [[ -n "$candidate" && "$candidate_version" == "$CODEX_CLI_VERSION" ]]; then
        CODEX_RESOLVED_BIN="$candidate"
        CODEX_RESOLVED_VERSION="$candidate_version"
        CODEX_LAUNCH_SOURCE="detected"
        return 0
    fi

    if [[ "$CODEX_INSTALL_IF_MISSING" == "1" ]]; then
        install_pinned_codex
        return $?
    fi

    if [[ -z "$candidate" ]]; then
        log_fail "no Codex CLI found and CODEX_INSTALL_IF_MISSING=0"
        return 1
    fi

    log_fail "found Codex CLI $candidate_version at $candidate, but expected $CODEX_CLI_VERSION and auto-install is disabled"
    return 1
}

configure_codex_env() {
    local auth_mode="$1"
    local home_dir="$2"
    CODEX_ENV_BASE=(env HOME="$home_dir")
    if [[ "$auth_mode" == "api_key" ]]; then
        CODEX_ENV_BASE+=(
            XDG_CONFIG_HOME="$CODEX_XDG_CONFIG_HOME"
            XDG_CACHE_HOME="$CODEX_XDG_CACHE_HOME"
            XDG_DATA_HOME="$CODEX_XDG_DATA_HOME"
            XDG_STATE_HOME="$CODEX_XDG_STATE_HOME"
        )
    fi
}

existing_login_available() {
    if [[ -z "$CODEX_HOME_DIR" ]]; then
        return 1
    fi
    env HOME="$CODEX_HOME_DIR" "$CODEX_RESOLVED_BIN" login status >/dev/null 2>&1
}

setup_codex_auth() {
    if [[ "$CODEX_MODE" == "manual" ]]; then
        return 0
    fi

    local requested_mode="$CODEX_AUTH_MODE"
    local api_key="${!CODEX_API_KEY_ENV-}"

    case "$requested_mode" in
        auto)
            if [[ -n "$api_key" ]]; then
                requested_mode="api_key"
            elif existing_login_available; then
                requested_mode="existing_login"
            else
                log_fail "no Codex auth available: set $CODEX_API_KEY_ENV or provide a working login in CODEX_HOME_DIR"
                return 1
            fi
            ;;
        api_key)
            if [[ -z "$api_key" ]]; then
                log_fail "CODEX_AUTH_MODE=api_key requires $CODEX_API_KEY_ENV"
                return 1
            fi
            ;;
        existing_login)
            if ! existing_login_available; then
                log_fail "CODEX_AUTH_MODE=existing_login requested, but no working login was found in CODEX_HOME_DIR"
                return 1
            fi
            ;;
        *)
            log_fail "unsupported CODEX_AUTH_MODE: $requested_mode"
            return 1
            ;;
    esac

    if [[ "$requested_mode" == "api_key" ]]; then
        mkdir -p \
            "$CODEX_ISOLATED_HOME" \
            "$CODEX_XDG_CONFIG_HOME" \
            "$CODEX_XDG_CACHE_HOME" \
            "$CODEX_XDG_DATA_HOME" \
            "$CODEX_XDG_STATE_HOME"
        CODEX_SELECTED_AUTH_MODE="api_key"
        CODEX_EFFECTIVE_HOME="$CODEX_ISOLATED_HOME"
        configure_codex_env "$CODEX_SELECTED_AUTH_MODE" "$CODEX_EFFECTIVE_HOME"

        if ! printf '%s\n' "$api_key" | "${CODEX_ENV_BASE[@]}" "$CODEX_RESOLVED_BIN" login --with-api-key >"$CODEX_AUTH_LOG" 2>&1; then
            log_fail "failed authenticating Codex with API key"
            tail -n 120 "$CODEX_AUTH_LOG" || true
            return 1
        fi
    else
        CODEX_SELECTED_AUTH_MODE="existing_login"
        CODEX_EFFECTIVE_HOME="$CODEX_HOME_DIR"
        configure_codex_env "$CODEX_SELECTED_AUTH_MODE" "$CODEX_EFFECTIVE_HOME"

        if ! "${CODEX_ENV_BASE[@]}" "$CODEX_RESOLVED_BIN" login status >"$CODEX_AUTH_LOG" 2>&1; then
            log_fail "Codex login status failed in existing login mode"
            tail -n 120 "$CODEX_AUTH_LOG" || true
            return 1
        fi
    fi

    write_codex_runtime_snapshot
    return 0
}

default_codex_launch_cmd() {
    printf '%s' 'cat {prompt_file} | {codex_bin} exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox --ephemeral --color never --add-dir {namespace_meta_dir} --add-dir {project_meta_dir} --add-dir {shared_data_dir} --add-dir {artifact_dir} -C {workspace_root} -o {artifact_dir}/codex_last_message.txt -'
}

render_codex_launch_command() {
    local artifact_dir="$OUTPUT_DIR/codex_artifacts"
    mkdir -p "$artifact_dir"

    local cmd="$CODEX_LAUNCH_CMD"
    if [[ -z "$cmd" ]]; then
        cmd="$(default_codex_launch_cmd)"
        CODEX_LAUNCH_SOURCE="${CODEX_LAUNCH_SOURCE:-default}"
    else
        CODEX_LAUNCH_SOURCE="${CODEX_LAUNCH_SOURCE:-custom}"
    fi

    cmd="${cmd//\{codex_bin\}/$(shell_quote "$CODEX_RESOLVED_BIN")}"
    cmd="${cmd//\{workspace_root\}/$(shell_quote "$MOUNT_WORKSPACE_PATH")}"
    cmd="${cmd//\{namespace_root\}/$(shell_quote "$MOUNT_POINT")}"
    cmd="${cmd//\{namespace_meta_dir\}/$(shell_quote "$MOUNT_POINT/meta")}"
    cmd="${cmd//\{project_meta_dir\}/$(shell_quote "$MOUNT_POINT/projects/$PROJECT_ID/meta")}"
    cmd="${cmd//\{shared_data_dir\}/$(shell_quote "$MOUNT_POINT/shared_data")}"
    cmd="${cmd//\{prompt_file\}/$(shell_quote "$PROMPT_FILE")}"
    cmd="${cmd//\{artifact_dir\}/$(shell_quote "$artifact_dir")}"
    cmd="$(inject_codex_cli_workarounds "$cmd")"

    write_codex_runtime_snapshot
    printf '%s' "$cmd"
}

progress_fingerprint() {
    python3 - "$MOUNT_WORKSPACE_PATH" "$CODEX_STDOUT_LOG" "$CODEX_STDERR_LOG" "$CODEX_PTY_LOG" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
stdout_log = Path(sys.argv[2])
stderr_log = Path(sys.argv[3])
pty_log = Path(sys.argv[4])
skip_files = {"TASK.md", "validate_game.py"}

count = 0
latest = 0
if workspace.exists():
    for entry in workspace.rglob("*"):
        if entry.name in skip_files:
            continue
        try:
            stat = entry.stat()
        except FileNotFoundError:
            continue
        count += 1
        latest = max(latest, stat.st_mtime_ns)

stdout_size = stdout_log.stat().st_size if stdout_log.exists() else 0
stderr_size = stderr_log.stat().st_size if stderr_log.exists() else 0
pty_size = pty_log.stat().st_size if pty_log.exists() else 0
print(f"{count}:{latest}:{stdout_size}:{stderr_size}:{pty_size}")
PY
}

kill_process_group() {
    local pgid="$1"
    kill -TERM -- "-$pgid" >/dev/null 2>&1 || true
    sleep 1
    kill -KILL -- "-$pgid" >/dev/null 2>&1 || true
}

monitor_codex_process() {
    local runner_pid="$1"
    local start_ts last_progress_ts now_ts
    local last_fingerprint current_fingerprint

    start_ts="$(date +%s)"
    last_progress_ts="$start_ts"
    last_fingerprint=""

    while kill -0 "$runner_pid" >/dev/null 2>&1; do
        now_ts="$(date +%s)"
        current_fingerprint="$(progress_fingerprint)"
        if [[ "$current_fingerprint" != "$last_fingerprint" ]]; then
            last_fingerprint="$current_fingerprint"
            last_progress_ts="$now_ts"
        fi

        if (( CODEX_TIMEOUT_SECONDS > 0 && now_ts - start_ts >= CODEX_TIMEOUT_SECONDS )); then
            CODEX_FAILURE_REASON="codex_timeout_after_${CODEX_TIMEOUT_SECONDS}s"
            kill_process_group "$runner_pid"
            break
        fi
        if (( CODEX_IDLE_TIMEOUT_SECONDS > 0 && now_ts - last_progress_ts >= CODEX_IDLE_TIMEOUT_SECONDS )); then
            CODEX_FAILURE_REASON="codex_idle_after_${CODEX_IDLE_TIMEOUT_SECONDS}s"
            kill_process_group "$runner_pid"
            break
        fi
        sleep 2
    done
}

summarize_codex_events() {
    python3 "$CODEX_EVENT_SUMMARY_SRC" \
        --events-log "$CODEX_STDOUT_LOG" \
        --stderr-log "$CODEX_STDERR_LOG" \
        --transcript-log "$CODEX_PTY_LOG" \
        --output "$CODEX_EVENT_SUMMARY"
}

run_live_codex() {
    if [[ "$TRACE_BACKEND" != "strace" ]]; then
        log_fail "unsupported TRACE_BACKEND: $TRACE_BACKEND"
        exit 1
    fi
    require_bin strace
    require_bin setsid
    if [[ "$CODEX_USE_PTY" == "1" ]]; then
        require_bin script
    fi

    local cmd
    cmd="$(render_codex_launch_command)"
    CODEX_RUN_STATE="running"
    CODEX_FAILURE_REASON=""

    : >"$CODEX_STDOUT_LOG"
    : >"$CODEX_STDERR_LOG"
    rm -f "$CODEX_PTY_LOG" "$CODEX_EVENT_SUMMARY"

    local quoted_cmd
    quoted_cmd="$(shell_quote "$cmd")"

    if [[ "$CODEX_USE_PTY" == "1" ]]; then
        "${CODEX_ENV_BASE[@]}" \
            PATH="$INSTALL_DIR:$PATH" \
            setsid \
            strace -ff -s 4096 -e trace=%file,%process -o "$STRACE_PREFIX" \
            script -qefc "bash -lc $quoted_cmd" "$CODEX_PTY_LOG" >"$CODEX_STDOUT_LOG" 2>"$CODEX_STDERR_LOG" &
    else
        "${CODEX_ENV_BASE[@]}" \
            PATH="$INSTALL_DIR:$PATH" \
            setsid \
            strace -ff -s 4096 -e trace=%file,%process -o "$STRACE_PREFIX" \
            bash -lc "$cmd" >"$CODEX_STDOUT_LOG" 2>"$CODEX_STDERR_LOG" &
    fi
    local runner_pid="$!"

    monitor_codex_process "$runner_pid"

    set +e
    wait "$runner_pid"
    CODEX_EXIT_CODE=$?
    set -e
    summarize_codex_events

    if [[ "$CODEX_EXIT_CODE" -ne 0 ]]; then
        local failure_reason="${CODEX_FAILURE_REASON:-codex_exit_$CODEX_EXIT_CODE}"
        write_handoff_bundle "$failure_reason"
        write_skip_outputs "$failure_reason"
        log_fail "Codex command failed with exit code $CODEX_EXIT_CODE"
        tail -n 120 "$CODEX_STDERR_LOG" || true
        exit 1
    fi

    CODEX_RUN_STATE="completed"
}

log_info "Running installer into isolated HOME..."
HOME="$TEMP_HOME" \
PATH="$PATH" \
SPIDERWEB_NON_INTERACTIVE=1 \
SPIDERWEB_INSTALL_DIR="$INSTALL_DIR" \
SPIDERWEB_REPO_DIR="$ROOT_DIR" \
SPIDERWEB_INSTALL_ZSS=0 \
SPIDERWEB_INSTALL_SYSTEMD=0 \
SPIDERWEB_START_AFTER_INSTALL=0 \
bash "$ROOT_DIR/install.sh" >"$INSTALL_LOG" 2>&1

for bin in spiderweb spiderweb-config spiderweb-control spiderweb-fs-mount spiderweb-fs-node; do
    if [[ ! -x "$INSTALL_DIR/$bin" ]]; then
        log_fail "installer did not produce expected binary: $bin"
        exit 1
    fi
done
log_pass "installer completed and produced required binaries"

setup_spiderweb_runtime_root
cp "$ASSET_DIR/shared_data/"* "$REMOTE_EXPORT_ROOT/"
write_workspace_seed_files
assert_clean_workspace_layout "$WORKSPACE_EXPORT_ROOT"
log_pass "seeded a clean local workspace export"

cat > "$SPIDERWEB_CONFIG_FILE" <<EOF
{
  "provider": {
    "name": "openai",
    "model": "gpt-4o-mini"
  },
  "runtime": {
    "default_agent_id": "default",
    "ltm_directory": "$LTM_DIR",
    "ltm_filename": "runtime-memory.db",
    "spider_web_root": "$SPIDERWEB_RUNTIME_ROOT"
  }
}
EOF

log_info "Starting Spiderweb on $CONTROL_URL ..."
(
    cd "$ROOT_DIR"
    HOME="$TEMP_HOME" \
    SPIDERWEB_CONFIG="$SPIDERWEB_CONFIG_FILE" \
    "$INSTALL_DIR/spiderweb" \
    --bind "$BIND_ADDR" \
    --port "$SPIDERWEB_PORT" >>"$SPIDERWEB_LOG" 2>&1
) &
SPIDERWEB_PID="$!"

if ! wait_for_control_ready; then
    log_fail "Spiderweb did not become ready"
    tail -n 200 "$SPIDERWEB_LOG" || true
    exit 1
fi
log_pass "Spiderweb control plane is ready"

LOCAL_INVITE_RESP="$(control_call node_invite_create)"
LOCAL_INVITE_TOKEN="$(json_field "$LOCAL_INVITE_RESP" '.payload.invite_token')"

log_info "Starting clean local workspace node ..."
HOME="$TEMP_HOME" \
"$INSTALL_DIR/spiderweb-fs-node" \
    --bind "$BIND_ADDR" \
    --port "$LOCAL_WORKSPACE_NODE_PORT" \
    --export "workspace=$WORKSPACE_EXPORT_ROOT:rw" \
    --control-url "$CONTROL_URL" \
    --control-auth-token "$SPIDERWEB_AUTH_TOKEN" \
    --pair-mode invite \
    --invite-token "$LOCAL_INVITE_TOKEN" \
    --node-name "codex-local-workspace-node" \
    --state-file "$TEST_TMP_DIR/local-workspace-node-state.json" >"$LOCAL_WORKSPACE_NODE_LOG" 2>&1 &
LOCAL_WORKSPACE_NODE_PID="$!"

if ! wait_for_node_join "codex-local-workspace-node" LOCAL_WORKSPACE_NODE_ID; then
    log_fail "clean local workspace node did not join Spiderweb"
    tail -n 200 "$LOCAL_WORKSPACE_NODE_LOG" || true
    exit 1
fi
log_pass "clean local workspace node joined as $LOCAL_WORKSPACE_NODE_ID"

REMOTE_INVITE_RESP="$(control_call node_invite_create)"
REMOTE_INVITE_TOKEN="$(json_field "$REMOTE_INVITE_RESP" '.payload.invite_token')"

log_info "Starting standalone remote shared-data node ..."
HOME="$TEMP_HOME" \
"$INSTALL_DIR/spiderweb-fs-node" \
    --bind "$BIND_ADDR" \
    --port "$REMOTE_NODE_PORT" \
    --export "shared=$REMOTE_EXPORT_ROOT:rw" \
    --control-url "$CONTROL_URL" \
    --control-auth-token "$SPIDERWEB_AUTH_TOKEN" \
    --pair-mode invite \
    --invite-token "$REMOTE_INVITE_TOKEN" \
    --node-name "codex-remote-node" \
    --state-file "$TEST_TMP_DIR/remote-node-state.json" >"$REMOTE_NODE_LOG" 2>&1 &
REMOTE_NODE_PID="$!"

if ! wait_for_node_join "codex-remote-node" REMOTE_NODE_ID; then
    log_fail "standalone remote node did not join Spiderweb"
    tail -n 200 "$REMOTE_NODE_LOG" || true
    exit 1
fi
log_pass "remote shared-data node joined as $REMOTE_NODE_ID"

PROJECT_UP_PAYLOAD="$(jq -cn \
    --arg name "External Codex Text Adventure" \
    --arg vision "Installer-first external Codex workspace validation" \
    --arg local_node "$LOCAL_WORKSPACE_NODE_ID" \
    --arg remote_node "$REMOTE_NODE_ID" \
    '{
        name: $name,
        vision: $vision,
        activate: true,
        desired_mounts: [
            {mount_path: "/nodes/local/fs", node_id: $local_node, export_name: "workspace"},
            {mount_path: "/shared_data", node_id: $remote_node, export_name: "shared"}
        ]
    }'
)"
PROJECT_UP_RESP="$(control_call project_up "$PROJECT_UP_PAYLOAD")"
PROJECT_ID="$(json_field "$PROJECT_UP_RESP" '.payload.project_id')"
PROJECT_TOKEN="$(jq -r '.payload.project_token // empty' <<<"$PROJECT_UP_RESP")"
printf '%s\n' "$PROJECT_UP_RESP" > "$OUTPUT_DIR/snapshots/project_up.json"

if ! wait_for_workspace_mounts; then
    log_fail "workspace mounts did not converge for /nodes/local/fs and /shared_data"
    exit 1
fi
log_pass "workspace topology converged for project $PROJECT_ID"

log_info "Mounting namespace ..."
HOME="$TEMP_HOME" \
"$INSTALL_DIR/spiderweb-fs-mount" \
    --namespace-url "$CONTROL_URL" \
    --workspace-id "$PROJECT_ID" \
    --auth-token "$SPIDERWEB_AUTH_TOKEN" \
    --agent-id codex \
    --session-key e2e \
    mount "$MOUNT_POINT" >"$MOUNT_LOG" 2>&1 &
MOUNT_PID="$!"

if ! wait_for_namespace_mount; then
    log_fail "namespace mount did not become ready"
    tail -n 200 "$MOUNT_LOG" || true
    exit 1
fi
log_pass "namespace mount is ready"

cp "$MOUNT_POINT/meta/protocol.json" "$OUTPUT_DIR/snapshots/protocol.json"
cp "$MOUNT_POINT/projects/$PROJECT_ID/meta/mounted_services.json" "$OUTPUT_DIR/snapshots/mounted_services.json"
cp "$MOUNT_POINT/projects/$PROJECT_ID/meta/workspace_status.json" "$OUTPUT_DIR/snapshots/workspace_status.json"
cp "$MOUNT_POINT/projects/$PROJECT_ID/meta/venom_packages.json" "$OUTPUT_DIR/snapshots/venom_packages.json"

if [[ ! -d "$MOUNT_WORKSPACE_PATH" || ! -d "$MOUNT_POINT/shared_data" ]]; then
    log_fail "mounted namespace is missing /nodes/local/fs or /shared_data"
    exit 1
fi
assert_clean_workspace_layout "$MOUNT_WORKSPACE_PATH"
log_pass "preflight discovery files, mount paths, and clean workspace layout are present"

render_prompt

if [[ "$CODEX_MODE" == "manual" ]]; then
    write_handoff_bundle "manual_mode_requested"
    write_skip_outputs "manual_mode_requested"
    log_info "manual handoff bundle written to $HANDOFF_DIR"
    exit "$MANUAL_EXIT_CODE"
fi

if ! ensure_codex_cli; then
    if [[ "$CODEX_MODE" == "auto" ]]; then
        write_handoff_bundle "codex_cli_unavailable"
        write_skip_outputs "codex_cli_unavailable"
        log_info "auto mode fell back to handoff because Codex CLI could not be prepared"
        exit "$MANUAL_EXIT_CODE"
    fi
    exit 1
fi
log_pass "Codex CLI prepared at $CODEX_RESOLVED_BIN ($CODEX_RESOLVED_VERSION)"

if ! setup_codex_auth; then
    if [[ "$CODEX_MODE" == "auto" ]]; then
        write_handoff_bundle "codex_auth_unavailable"
        write_skip_outputs "codex_auth_unavailable"
        log_info "auto mode fell back to handoff because Codex auth could not be prepared"
        exit "$MANUAL_EXIT_CODE"
    fi
    exit 1
fi
log_pass "Codex auth prepared using $CODEX_SELECTED_AUTH_MODE"

run_live_codex

python3 "$MOUNT_WORKSPACE_PATH/validate_game.py" \
    --workspace "$MOUNT_WORKSPACE_PATH" \
    --shared-data "$MOUNT_POINT/shared_data" \
    --output "$VALIDATION_OUTPUT"

build_usage_report

if ! jq -e '.ok == true' "$VALIDATION_OUTPUT" >/dev/null 2>&1; then
    write_handoff_bundle "game_validation_failed"
    log_fail "game validation failed"
    cat "$VALIDATION_OUTPUT"
    exit 1
fi

if ! jq -e '.reliability_ok == true' "$USAGE_JSON" >/dev/null 2>&1; then
    write_handoff_bundle "usage_reliability_failed"
    log_fail "usage report detected disallowed writes outside the mounted workspace/runtime allowlist"
    cat "$USAGE_JSON"
    exit 1
fi

if ! jq -e '.machine_independence_ok == true' "$USAGE_JSON" >/dev/null 2>&1; then
    log_info "run passed reliability, but machine-independence gaps are still present"
fi

log_pass "external Codex workspace scenario completed successfully"
