#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BIN_DIR=${BIN_DIR:-"$REPO_ROOT/zig-out/bin"}
if [[ "$BIN_DIR" != /* ]]; then
  BIN_DIR="$REPO_ROOT/$BIN_DIR"
fi
SPIDERWEB_BIN=${SPIDERWEB_BIN:-"$BIN_DIR/spiderweb"}
CONTROL_BIN=${CONTROL_BIN:-"$BIN_DIR/spiderweb-control"}
FS_MOUNT_BIN=${FS_MOUNT_BIN:-"$BIN_DIR/spiderweb-fs-mount"}
WEBSOCAT_BIN=${WEBSOCAT_BIN:-"$(command -v websocat || true)"}
JQ_BIN=${JQ_BIN:-"$(command -v jq || true)"}
MOTHER_E2E_MODE=${MOTHER_E2E_MODE:-provider_chat}

if [[ -z "$WEBSOCAT_BIN" ]]; then
  echo "error: websocat is required" >&2
  exit 1
fi
if [[ -z "$JQ_BIN" ]]; then
  echo "error: jq is required" >&2
  exit 1
fi
if [[ ! -x "$SPIDERWEB_BIN" || ! -x "$CONTROL_BIN" || ! -x "$FS_MOUNT_BIN" ]]; then
  echo "error: expected spiderweb, spiderweb-control, and spiderweb-fs-mount under $BIN_DIR (build first with: zig build)" >&2
  exit 1
fi
if [[ "$MOTHER_E2E_MODE" != "provider_chat" && "$MOTHER_E2E_MODE" != "deterministic" ]]; then
  echo "error: MOTHER_E2E_MODE must be one of: provider_chat, deterministic" >&2
  exit 1
fi

CONFIG_SOURCE_PATH=${CANARY_PROVIDER_CONFIG:-${SPIDERWEB_CONFIG:-$HOME/.config/spiderweb/config.json}}
HAS_PROVIDER_CONFIG=0
if [[ -f "$CONFIG_SOURCE_PATH" ]]; then
  HAS_PROVIDER_CONFIG=1
fi

if [[ "$HAS_PROVIDER_CONFIG" == "1" ]]; then
  PROVIDER_NAME=${CANARY_PROVIDER_NAME:-$($JQ_BIN -r '.provider.name // empty' "$CONFIG_SOURCE_PATH")}
  PROVIDER_MODEL=${CANARY_PROVIDER_MODEL:-$($JQ_BIN -r '.provider.model // empty' "$CONFIG_SOURCE_PATH")}
  PROVIDER_BASE_URL=${CANARY_PROVIDER_BASE_URL:-$($JQ_BIN -r '.provider.base_url // empty' "$CONFIG_SOURCE_PATH")}
  PROVIDER_API_KEY=${CANARY_PROVIDER_API_KEY:-$($JQ_BIN -r '.provider.api_key // empty' "$CONFIG_SOURCE_PATH")}
else
  PROVIDER_NAME=${CANARY_PROVIDER_NAME:-}
  PROVIDER_MODEL=${CANARY_PROVIDER_MODEL:-}
  PROVIDER_BASE_URL=${CANARY_PROVIDER_BASE_URL:-}
  PROVIDER_API_KEY=${CANARY_PROVIDER_API_KEY:-}
fi

if [[ -z "$PROVIDER_NAME" && "$MOTHER_E2E_MODE" == "deterministic" ]]; then
  PROVIDER_NAME="openai-codex"
fi
if [[ -z "$PROVIDER_MODEL" && "$MOTHER_E2E_MODE" == "deterministic" ]]; then
  PROVIDER_MODEL="gpt-5.3-codex"
fi

if [[ -z "$PROVIDER_NAME" ]]; then
  if [[ "$HAS_PROVIDER_CONFIG" == "1" ]]; then
    echo "error: provider.name is empty in $CONFIG_SOURCE_PATH" >&2
  else
    echo "error: provider config not found at $CONFIG_SOURCE_PATH; set CANARY_PROVIDER_NAME (and optionally CANARY_PROVIDER_MODEL/CANARY_PROVIDER_API_KEY)" >&2
  fi
  exit 1
fi

if [[ -z "$PROVIDER_API_KEY" ]]; then
  case "$PROVIDER_NAME" in
    openrouter)
      PROVIDER_API_KEY=${OPENROUTER_API_KEY:-}
      ;;
    openai)
      PROVIDER_API_KEY=${OPENAI_API_KEY:-}
      ;;
    openai-codex|openai-codex-spark)
      PROVIDER_API_KEY=${OPENAI_CODEX_API_KEY:-${OPENAI_API_KEY:-}}
      ;;
    anthropic)
      PROVIDER_API_KEY=${ANTHROPIC_API_KEY:-}
      ;;
    google|gemini)
      PROVIDER_API_KEY=${GOOGLE_API_KEY:-${GEMINI_API_KEY:-}}
      ;;
  esac
fi

CANARY_PORT=${CANARY_PORT:-28832}
CONTROL_RETRY_ATTEMPTS=${CONTROL_RETRY_ATTEMPTS:-40}
CONTROL_RETRY_DELAY_SEC=${CONTROL_RETRY_DELAY_SEC:-0.25}
WS_ATTACH_RETRY_ATTEMPTS=${WS_ATTACH_RETRY_ATTEMPTS:-30}
CHAT_MAX_ATTEMPTS=${CHAT_MAX_ATTEMPTS:-2}
CHAT_TIMEOUT_SEC=${CHAT_TIMEOUT_SEC:-360}
SERVICE_STATUS_TIMEOUT_SEC=${SERVICE_STATUS_TIMEOUT_SEC:-90}
KEEP_CANARY_DIR=${KEEP_CANARY_DIR:-0}

RUN_SUFFIX=${RUN_SUFFIX:-$(date +%s)}
PROJECT_NAME=${PROJECT_NAME:-"mother-e2e-${RUN_SUFFIX}"}
PROJECT_VISION=${PROJECT_VISION:-"Mother-driven e2e for project, agent, mount, bind, and resolve."}
AGENT_ID=${AGENT_ID:-"mother-e2e-agent-${RUN_SUFFIX}"}
AGENT_NAME=${AGENT_NAME:-"Mother E2E Agent ${RUN_SUFFIX}"}
MOUNT_PATH=${MOUNT_PATH:-"/nodes/local/fs"}
BIND_PATH=${BIND_PATH:-"/repo"}

TMP_ROOT=$(mktemp -d /tmp/spiderweb-manual-mother-agent-e2e-XXXXXX)
STATE_DIR="$TMP_ROOT/state"
AGENTS_DIR="$TMP_ROOT/agents"
mkdir -p "$STATE_DIR" "$AGENTS_DIR"
CONFIG_PATH="$TMP_ROOT/config.json"
SERVER_LOG="$TMP_ROOT/server.log"
WS_TRACE="$TMP_ROOT/ws-trace.ndjson"

SPIDERWEB_PID=""
WS_PID=""
WS_IN=""
WS_OUT=""
TAG_COUNTER=100
CURRENT_TAG=0

cleanup() {
  if [[ -n "${WS_IN:-}" ]]; then
    exec {WS_IN}>&- || true
    WS_IN=""
  fi
  if [[ -n "${WS_OUT:-}" ]]; then
    exec {WS_OUT}<&- || true
    WS_OUT=""
  fi
  if [[ -n "${WS_PID:-}" ]]; then
    kill "$WS_PID" >/dev/null 2>&1 || true
    if kill -0 "$WS_PID" >/dev/null 2>&1; then
      wait "$WS_PID" >/dev/null 2>&1 || true
    fi
    WS_PID=""
  fi
  if [[ -n "${SPIDERWEB_PID:-}" ]]; then
    kill "$SPIDERWEB_PID" >/dev/null 2>&1 || true
    if kill -0 "$SPIDERWEB_PID" >/dev/null 2>&1; then
      wait "$SPIDERWEB_PID" >/dev/null 2>&1 || true
    fi
    SPIDERWEB_PID=""
  fi
  if [[ "$KEEP_CANARY_DIR" != "1" ]]; then
    if command -v timeout >/dev/null 2>&1; then
      timeout --kill-after=2s 10s rm -rf "$TMP_ROOT" >/dev/null 2>&1 || true
    else
      rm -rf "$TMP_ROOT" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

$JQ_BIN -n \
  --arg provider_name "$PROVIDER_NAME" \
  --arg provider_model "$PROVIDER_MODEL" \
  --arg provider_base_url "$PROVIDER_BASE_URL" \
  --arg provider_api_key "$PROVIDER_API_KEY" \
  --arg ltm_dir "state" \
  --arg assets_dir "$REPO_ROOT/templates" \
  --arg agents_dir "agents" \
  --arg sandbox_mounts_root "$TMP_ROOT/sandbox/mounts" \
  --arg sandbox_runtime_root "$TMP_ROOT/sandbox/runtime" \
  --arg sandbox_rootfs_store_root "$TMP_ROOT/sandbox/rootfs-store" \
  --arg sandbox_overlay_root "$TMP_ROOT/sandbox/overlay" \
  --arg sandbox_snapshot_root "$TMP_ROOT/sandbox/snapshot" \
  --arg sandbox_fs_mount_bin "$BIN_DIR/spiderweb-fs-mount" \
  --arg sandbox_agent_runtime_bin "$BIN_DIR/spiderweb-agent-runtime" \
  --argjson port "$CANARY_PORT" \
  '{
    server: { bind: "127.0.0.1", port: $port },
    provider: (
      { name: $provider_name }
      + (if $provider_model != "" then { model: $provider_model } else {} end)
      + (if $provider_base_url != "" then { base_url: $provider_base_url } else {} end)
      + (if $provider_api_key != "" then { api_key: $provider_api_key } else {} end)
    ),
    log: { level: "warn" },
    runtime: {
      sandbox_enabled: true,
      default_agent_id: "mother",
      ltm_directory: $ltm_dir,
      assets_dir: $assets_dir,
      agents_dir: $agents_dir,
      sandbox_mounts_root: $sandbox_mounts_root,
      sandbox_runtime_root: $sandbox_runtime_root,
      sandbox_rootfs_base_ref: "mother-e2e-default",
      sandbox_rootfs_store_root: $sandbox_rootfs_store_root,
      sandbox_overlay_root: $sandbox_overlay_root,
      sandbox_snapshot_root: $sandbox_snapshot_root,
      sandbox_launcher: "bwrap",
      sandbox_fs_mount_bin: $sandbox_fs_mount_bin,
      sandbox_agent_runtime_bin: $sandbox_agent_runtime_bin
    }
  }' > "$CONFIG_PATH"

echo "[mother-e2e] config: $CONFIG_PATH"
echo "[mother-e2e] provider: ${PROVIDER_NAME}/${PROVIDER_MODEL:-default}"
echo "[mother-e2e] mode: $MOTHER_E2E_MODE"
if [[ -z "$PROVIDER_API_KEY" && "$MOTHER_E2E_MODE" == "provider_chat" ]]; then
  echo "[mother-e2e] warning: no provider API key supplied via CANARY_PROVIDER_API_KEY, config provider.api_key, or provider env var."
  if [[ "$PROVIDER_NAME" == "openrouter" ]]; then
    echo "error: openrouter provider requires an API key; set CANARY_PROVIDER_API_KEY or OPENROUTER_API_KEY." >&2
    exit 1
  fi
fi

(
  cd "$TMP_ROOT"
  SPIDERWEB_CONFIG="$CONFIG_PATH" "$SPIDERWEB_BIN" --port "$CANARY_PORT" >"$SERVER_LOG" 2>&1
) &
SPIDERWEB_PID=$!

AUTH_PATH="$STATE_DIR/auth_tokens.json"
for _ in $(seq 1 120); do
  if [[ -f "$AUTH_PATH" ]]; then
    break
  fi
  sleep 0.25
done
if [[ ! -f "$AUTH_PATH" ]]; then
  echo "error: auth token file not created: $AUTH_PATH" >&2
  exit 1
fi

ADMIN_TOKEN=$($JQ_BIN -r '.admin_token // empty' "$AUTH_PATH")
if [[ -z "$ADMIN_TOKEN" ]]; then
  echo "error: admin token missing in $AUTH_PATH" >&2
  exit 1
fi

URL="ws://127.0.0.1:${CANARY_PORT}/"
control() {
  "$CONTROL_BIN" --url "$URL" --auth-token "$ADMIN_TOKEN" "$@"
}

control_retry() {
  local attempts="$1"
  local delay_sec="$2"
  shift 2
  local tmp_err output
  tmp_err=$(mktemp /tmp/spiderweb-mother-e2e-control-retry-XXXXXX)
  for attempt in $(seq 1 "$attempts"); do
    if output=$(control "$@" 2>"$tmp_err"); then
      rm -f "$tmp_err"
      printf '%s' "$output"
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$delay_sec"
    fi
  done
  cat "$tmp_err" >&2
  rm -f "$tmp_err"
  return 1
}

json_assert() {
  local json="$1"
  local filter="$2"
  local message="$3"
  shift 3
  if ! $JQ_BIN -e "$filter" "$@" >/dev/null <<<"$json"; then
    echo "error: $message" >&2
    echo "json: $json" >&2
    exit 1
  fi
}

next_tag() {
  TAG_COUNTER=$((TAG_COUNTER + 1))
  CURRENT_TAG=$TAG_COUNTER
}

ws_open() {
  coproc WS { "$WEBSOCAT_BIN" -H="Authorization: Bearer $ADMIN_TOKEN" "$URL"; }
  exec {WS_IN}>&"${WS[1]}"
  exec {WS_OUT}<&"${WS[0]}"
}

ws_close() {
  if [[ -n "${WS_IN:-}" ]]; then
    exec {WS_IN}>&- || true
    WS_IN=""
  fi
  if [[ -n "${WS_OUT:-}" ]]; then
    exec {WS_OUT}<&- || true
    WS_OUT=""
  fi
  if [[ -n "${WS_PID:-}" ]]; then
    kill "$WS_PID" >/dev/null 2>&1 || true
    if kill -0 "$WS_PID" >/dev/null 2>&1; then
      wait "$WS_PID" >/dev/null 2>&1 || true
    fi
    WS_PID=""
  fi
}

ws_send() {
  local frame="$1"
  printf '%s\n' "$frame" >&$WS_IN
}

ws_expect_type() {
  local expected_type="$1"
  local timeout_sec="$2"
  local deadline=$((SECONDS + timeout_sec))
  local line
  while (( SECONDS < deadline )); do
    if IFS= read -r -t 1 -u "$WS_OUT" line; then
      [[ -z "$line" ]] && continue
      printf '%s\n' "$line" >> "$WS_TRACE"
      local line_type
      line_type=$($JQ_BIN -r '.type // empty' 2>/dev/null <<<"$line" || true)
      if [[ "$line_type" == "$expected_type" ]]; then
        printf '%s\n' "$line"
        return 0
      fi
      if [[ "$line_type" == "control.error" || "$line_type" == "acheron.error" || "$line_type" == "acheron.err" || "$line_type" == "acheron.err_fs" ]]; then
        echo "error: unexpected error frame while waiting for $expected_type" >&2
        echo "$line" >&2
        return 1
      fi
    fi
  done
  echo "error: timeout waiting for $expected_type" >&2
  return 1
}

ws_attach_with_retry() {
  local version_id="$1"
  local connect_id="$2"
  local t_version_tag="$3"
  local t_attach_tag="$4"
  local attempts="$5"
  for attempt in $(seq 1 "$attempts"); do
    ws_close
    ws_open
    if ws_send "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"${version_id}\",\"payload\":{\"protocol\":\"unified-v2\"}}" \
      && ws_expect_type "control.version_ack" 30 >/dev/null \
      && ws_send "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"${connect_id}\"}" \
      && ws_expect_type "control.connect_ack" 30 >/dev/null \
      && ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_version\",\"tag\":${t_version_tag},\"msize\":1048576,\"version\":\"acheron-1\"}" \
      && ws_expect_type "acheron.r_version" 30 >/dev/null \
      && ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_attach\",\"tag\":${t_attach_tag},\"fid\":1}" \
      && ws_expect_type "acheron.r_attach" 30 >/dev/null; then
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep 1
    fi
  done
  echo "error: websocket attach handshake failed after ${attempts} attempts" >&2
  return 1
}

path_to_json_array() {
  local path="$1"
  $JQ_BIN -cn --arg path "$path" '$path | split("/") | map(select(length > 0))'
}

ws_write_text_file() {
  local path="$1"
  local content="$2"
  local write_timeout_sec="${3:-30}"
  local walk_tag open_tag write_tag clunk_tag
  local path_json data_b64
  path_json=$(path_to_json_array "$path")
  data_b64=$(printf '%s' "$content" | base64 -w0)

  next_tag
  walk_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_walk\",\"tag\":${walk_tag},\"fid\":1,\"newfid\":2,\"path\":${path_json}}"
  ws_expect_type "acheron.r_walk" 30 >/dev/null

  next_tag
  open_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_open\",\"tag\":${open_tag},\"fid\":2,\"mode\":\"rw\"}"
  ws_expect_type "acheron.r_open" 30 >/dev/null

  next_tag
  write_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_write\",\"tag\":${write_tag},\"fid\":2,\"offset\":0,\"data_b64\":\"${data_b64}\"}"
  local write_frame
  write_frame=$(ws_expect_type "acheron.r_write" "$write_timeout_sec")

  next_tag
  clunk_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_clunk\",\"tag\":${clunk_tag},\"fid\":2}"
  ws_expect_type "acheron.r_clunk" 30 >/dev/null

  printf '%s\n' "$write_frame"
}

ws_read_text_file() {
  local path="$1"
  local read_timeout_sec="${2:-120}"
  local walk_tag open_tag read_tag clunk_tag
  local path_json
  path_json=$(path_to_json_array "$path")

  next_tag
  walk_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_walk\",\"tag\":${walk_tag},\"fid\":1,\"newfid\":3,\"path\":${path_json}}"
  ws_expect_type "acheron.r_walk" 30 >/dev/null

  next_tag
  open_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_open\",\"tag\":${open_tag},\"fid\":3,\"mode\":\"r\"}"
  ws_expect_type "acheron.r_open" 30 >/dev/null

  next_tag
  read_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_read\",\"tag\":${read_tag},\"fid\":3,\"offset\":0,\"count\":1048576}"
  local read_frame
  read_frame=$(ws_expect_type "acheron.r_read" "$read_timeout_sec")

  next_tag
  clunk_tag=$CURRENT_TAG
  ws_send "{\"channel\":\"acheron\",\"type\":\"acheron.t_clunk\",\"tag\":${clunk_tag},\"fid\":3}"
  ws_expect_type "acheron.r_clunk" 30 >/dev/null

  local data_b64
  data_b64=$($JQ_BIN -r '.payload.data_b64 // empty' <<<"$read_frame")
  if [[ -z "$data_b64" ]]; then
    printf ''
  else
    printf '%s' "$data_b64" | base64 --decode
  fi
}

ws_wait_service_done() {
  local service_name="$1"
  local timeout_sec="${2:-60}"
  local deadline=$((SECONDS + timeout_sec))
  local status_json state
  while (( SECONDS < deadline )); do
    status_json=$(ws_read_text_file "/agents/self/${service_name}/status.json" 30 || true)
    state=$($JQ_BIN -r '.state // empty' 2>/dev/null <<<"$status_json" || true)
    if [[ "$state" == "done" ]]; then
      return 0
    fi
    if [[ "$state" == "error" ]]; then
      echo "error: service ${service_name} entered error state: $status_json" >&2
      return 1
    fi
    sleep 1
  done
  echo "error: timeout waiting for /agents/self/${service_name}/status.json to reach done" >&2
  return 1
}

ws_invoke_and_read_result() {
  local service_name="$1"
  local control_path="$2"
  local payload="$3"
  local timeout_sec="${4:-60}"
  local padding
  padding=$(printf '%2048s' '')
  _=$(ws_write_text_file "$control_path" "${payload}
${padding}" 60)
  ws_wait_service_done "$service_name" "$timeout_sec"
  ws_read_text_file "/agents/self/${service_name}/result.json" 30
}

ws_chat_and_read_reply() {
  local prompt="$1"
  local timeout_sec="${2:-240}"
  local write_frame chat_job chat_result_path
  write_frame=$(ws_write_text_file "/agents/self/chat/control/input" "$prompt" 180)
  chat_job=$($JQ_BIN -r '.payload.job // empty' <<<"$write_frame")
  chat_result_path=$($JQ_BIN -r '.payload.result_path // empty' <<<"$write_frame")
  if [[ -z "$chat_result_path" ]]; then
    if [[ -z "$chat_job" ]]; then
      echo "error: chat write did not return job/result_path" >&2
      exit 1
    fi
    chat_result_path="/agents/self/jobs/${chat_job}/result.txt"
  fi
  ws_read_text_file "$chat_result_path" "$timeout_sec"
}

retry_cmd() {
  local attempts="$1"
  local delay_sec="$2"
  shift 2
  for attempt in $(seq 1 "$attempts"); do
    if "$@"; then
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$delay_sec"
    fi
  done
  return 1
}

# 1) first connect should be bootstrap-only on clean state
CONNECT_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" connect)
json_assert "$CONNECT_JSON" '.type == "control.connect_ack"' 'connect did not return control.connect_ack'
json_assert "$CONNECT_JSON" '.payload.agent_id == "mother" and .payload.project_id == "system"' 'connect ack not bound to mother/system'
json_assert "$CONNECT_JSON" '.payload.bootstrap_only == true' 'expected bootstrap_only=true on first connect'

WORKSPACE_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" workspace_status '{}')
json_assert "$WORKSPACE_JSON" '.type == "control.workspace_status"' 'workspace_status failed'
NODE_ID=$($JQ_BIN -r '
  def mounts: ((.payload.actual_mounts // []) | if length > 0 then . else (.payload.mounts // []) end);
  (mounts | map(select((.mount_path // "") == "/nodes/local/fs")) | .[0].node_id)
  // (mounts[0].node_id)
  // empty
' <<<"$WORKSPACE_JSON")
EXPORT_NAME=$($JQ_BIN -r '
  def mounts: ((.payload.actual_mounts // []) | if length > 0 then . else (.payload.mounts // []) end);
  (mounts | map(select((.mount_path // "") == "/nodes/local/fs")) | .[0].export_name)
  // (mounts[0].export_name)
  // empty
' <<<"$WORKSPACE_JSON")
if [[ -z "$NODE_ID" || -z "$EXPORT_NAME" ]]; then
  echo "error: could not resolve source node/export from workspace_status" >&2
  echo "$WORKSPACE_JSON" >&2
  exit 1
fi

ws_attach_with_retry "mother-e2e-version" "mother-e2e-connect" 1 2 "$WS_ATTACH_RETRY_ATTEMPTS"

CHAT_REPLY=""
PROJECT_ID=""
if [[ "$MOTHER_E2E_MODE" == "deterministic" ]]; then
  PROJECT_UP_PAYLOAD=$($JQ_BIN -cn --arg name "$PROJECT_NAME" --arg vision "$PROJECT_VISION" '{name:$name,vision:$vision,activate:false}')
  PROJECT_UP_RESULT=$(ws_invoke_and_read_result "projects" "/agents/self/projects/control/up.json" "$PROJECT_UP_PAYLOAD" "$SERVICE_STATUS_TIMEOUT_SEC")
  json_assert "$PROJECT_UP_RESULT" '.ok == true' 'deterministic project up failed'

  PROJECT_ID=$($JQ_BIN -r '.result.project_id // empty' 2>/dev/null <<<"$PROJECT_UP_RESULT" || true)
  if [[ -z "$PROJECT_ID" ]]; then
    PROJECT_LIST_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" project_list)
    PROJECT_ID=$($JQ_BIN -r --arg name "$PROJECT_NAME" '.payload.projects[]? | select((.name // "") == $name) | .project_id' <<<"$PROJECT_LIST_JSON" | head -n1)
  fi
  if [[ -z "$PROJECT_ID" ]]; then
    echo "error: deterministic flow could not resolve project_id for $PROJECT_NAME" >&2
    echo "$PROJECT_UP_RESULT" >&2
    exit 1
  fi

  AGENT_CREATE_PAYLOAD=$($JQ_BIN -cn \
    --arg agent_id "$AGENT_ID" \
    --arg name "$AGENT_NAME" \
    --arg description "Mother-driven e2e validation agent." \
    --arg project_id "$PROJECT_ID" \
    '{agent_id:$agent_id,name:$name,description:$description,project_id:$project_id}')
  AGENT_CREATE_RESULT=$(ws_invoke_and_read_result "agents" "/agents/self/agents/control/create.json" "$AGENT_CREATE_PAYLOAD" "$SERVICE_STATUS_TIMEOUT_SEC")
  json_assert "$AGENT_CREATE_RESULT" '.ok == true' 'deterministic agent create failed'

  MOUNT_PAYLOAD=$($JQ_BIN -cn \
    --arg project_id "$PROJECT_ID" \
    --arg node_id "$NODE_ID" \
    --arg export_name "$EXPORT_NAME" \
    --arg mount_path "$MOUNT_PATH" \
    '{project_id:$project_id,node_id:$node_id,export_name:$export_name,mount_path:$mount_path}')
  MOUNT_RESULT=$(ws_invoke_and_read_result "mounts" "/agents/self/mounts/control/mount.json" "$MOUNT_PAYLOAD" "$SERVICE_STATUS_TIMEOUT_SEC")
  json_assert "$MOUNT_RESULT" '.ok == true' 'deterministic mount failed'

  BIND_PAYLOAD=$($JQ_BIN -cn \
    --arg project_id "$PROJECT_ID" \
    --arg bind_path "$BIND_PATH" \
    --arg target_path "$MOUNT_PATH" \
    '{project_id:$project_id,bind_path:$bind_path,target_path:$target_path}')
  BIND_RESULT=$(ws_invoke_and_read_result "mounts" "/agents/self/mounts/control/bind.json" "$BIND_PAYLOAD" "$SERVICE_STATUS_TIMEOUT_SEC")
  json_assert "$BIND_RESULT" '.ok == true' 'deterministic bind failed'

  RESOLVE_PAYLOAD=$($JQ_BIN -cn --arg project_id "$PROJECT_ID" --arg path "$BIND_PATH" '{project_id:$project_id,path:$path}')
  RESOLVE_RESULT=$(ws_invoke_and_read_result "mounts" "/agents/self/mounts/control/resolve.json" "$RESOLVE_PAYLOAD" "$SERVICE_STATUS_TIMEOUT_SEC")
  json_assert "$RESOLVE_RESULT" '.ok == true' 'deterministic resolve failed'

  CHAT_REPLY=$(printf '{"ok":true,"mode":"deterministic","project_id":"%s","agent_id":"%s"}' "$PROJECT_ID" "$AGENT_ID")
else
  SETUP_PROMPT=$(cat <<EOF
Run this setup now using your tools and Acheron control files:
1) Create project via /agents/self/projects/control/up.json with name="$PROJECT_NAME" and vision="$PROJECT_VISION".
2) Create agent via /agents/self/agents/control/create.json with:
   agent_id="$AGENT_ID"
   name="$AGENT_NAME"
   description="Mother-driven e2e validation agent."
   project_id=<project_id from step 1>
Reply with compact JSON only:
{"ok":true,"project_id":"...","agent_id":"$AGENT_ID"}
EOF
)

  SETUP_REPLY=""
  for attempt in $(seq 1 "$CHAT_MAX_ATTEMPTS"); do
    SETUP_REPLY=$(ws_chat_and_read_reply "$SETUP_PROMPT" "$CHAT_TIMEOUT_SEC")
    LOWER_REPLY=$(printf '%s' "$SETUP_REPLY" | tr '[:upper:]' '[:lower:]')
    if [[ "$LOWER_REPLY" == *"provider request invalid"* ]]; then
      echo "error: provider request invalid (check provider credentials/model in $CONFIG_SOURCE_PATH)" >&2
      echo "$SETUP_REPLY" >&2
      exit 1
    fi
    if grep -Eqi '"ok"[[:space:]]*:[[:space:]]*true' <<<"$SETUP_REPLY"; then
      break
    fi
    if [[ "$attempt" -lt "$CHAT_MAX_ATTEMPTS" ]]; then
      sleep 1
    fi
  done
  if [[ -z "$SETUP_REPLY" ]]; then
    echo "error: Mother setup reply is empty" >&2
    exit 1
  fi

  PROJECT_ID=$($JQ_BIN -r '.project_id // empty' 2>/dev/null <<<"$SETUP_REPLY" || true)
  if [[ -z "$PROJECT_ID" ]]; then
    PROJECT_LIST_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" project_list)
    PROJECT_ID=$($JQ_BIN -r --arg name "$PROJECT_NAME" '.payload.projects[]? | select((.name // "") == $name) | .project_id' <<<"$PROJECT_LIST_JSON" | head -n1)
  fi
  if [[ -z "$PROJECT_ID" ]]; then
    echo "error: Mother setup did not yield project_id" >&2
    echo "$SETUP_REPLY" >&2
    exit 1
  fi

  MOUNTS_PROMPT=$(cat <<EOF
Now execute mount and bind for project_id "$PROJECT_ID" using control files:
1) /agents/self/mounts/control/mount.json with {"project_id":"$PROJECT_ID","node_id":"$NODE_ID","export_name":"$EXPORT_NAME","mount_path":"$MOUNT_PATH"}
2) /agents/self/mounts/control/bind.json with {"project_id":"$PROJECT_ID","bind_path":"$BIND_PATH","target_path":"$MOUNT_PATH"}
3) /agents/self/mounts/control/resolve.json with {"project_id":"$PROJECT_ID","path":"$BIND_PATH"}
Reply with compact JSON only:
{"ok":true,"project_id":"$PROJECT_ID","bind_path":"$BIND_PATH","resolved_path":"..."}
EOF
)
  MOUNTS_REPLY=""
  for attempt in $(seq 1 "$CHAT_MAX_ATTEMPTS"); do
    MOUNTS_REPLY=$(ws_chat_and_read_reply "$MOUNTS_PROMPT" "$CHAT_TIMEOUT_SEC")
    LOWER_REPLY=$(printf '%s' "$MOUNTS_REPLY" | tr '[:upper:]' '[:lower:]')
    if [[ "$LOWER_REPLY" == *"provider request invalid"* ]]; then
      echo "error: provider request invalid (check provider credentials/model in $CONFIG_SOURCE_PATH)" >&2
      echo "$MOUNTS_REPLY" >&2
      exit 1
    fi
    if grep -Eqi '"ok"[[:space:]]*:[[:space:]]*true' <<<"$MOUNTS_REPLY"; then
      break
    fi
    if [[ "$attempt" -lt "$CHAT_MAX_ATTEMPTS" ]]; then
      sleep 1
    fi
  done
  CHAT_REPLY="$SETUP_REPLY"$'\n'"$MOUNTS_REPLY"
fi

PROJECT_LIST_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" project_list)
json_assert "$PROJECT_LIST_JSON" '.payload.projects[]? | select((.project_id // "") == $id) | .project_id == $id' 'Mother-reported project_id not found in project_list' --arg id "$PROJECT_ID"
echo "[mother-e2e] verify project_id: $PROJECT_ID"

AGENT_LIST_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" agent_list)
json_assert "$AGENT_LIST_JSON" '.payload.agents[]? | select((.id // "") == $id) | .id == $id' 'Mother did not create expected agent' --arg id "$AGENT_ID"

if [[ ! -f "$AGENTS_DIR/$AGENT_ID/HATCH.md" ]]; then
  echo "error: expected agent HATCH scaffold missing for $AGENT_ID" >&2
  exit 1
fi
if [[ ! -f "$AGENTS_DIR/$AGENT_ID/agent.json" ]]; then
  echo "[mother-e2e] note: $AGENTS_DIR/$AGENT_ID/agent.json was not generated in this flow; continuing with control-plane verification."
fi

# 3) verify mount via control-plane list, and bind via project fs path access
PROJECT_MOUNT_LIST_PAYLOAD=$($JQ_BIN -cn --arg project_id "$PROJECT_ID" '{project_id:$project_id}')
PROJECT_MOUNTS_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" project_mount_list "$PROJECT_MOUNT_LIST_PAYLOAD")
json_assert "$PROJECT_MOUNTS_JSON" '.type == "control.project_mount_list" and .ok == true' 'project_mount_list failed for Mother-created project'
json_assert "$PROJECT_MOUNTS_JSON" '.payload.mounts[]? | select((.mount_path // "") == $mount_path and (.node_id // "") == $node_id and (.export_name // "") == $export_name)' 'expected mount not found in project_mount_list' --arg mount_path "$MOUNT_PATH" --arg node_id "$NODE_ID" --arg export_name "$EXPORT_NAME"

if ! retry_cmd 10 0.5 "$FS_MOUNT_BIN" --workspace-url "$URL" --auth-token "$ADMIN_TOKEN" --project-id "$PROJECT_ID" getattr "$MOUNT_PATH" >/dev/null 2>&1; then
  echo "error: mounted path is not readable in project namespace: $MOUNT_PATH" >&2
  exit 1
fi

check_bind_and_resolve() {
  local list_result resolve_result
  list_result=$(ws_invoke_and_read_result "mounts" "/agents/self/mounts/control/list.json" "{\"project_id\":\"$PROJECT_ID\"}" "$SERVICE_STATUS_TIMEOUT_SEC")
  if ! $JQ_BIN -e '.ok == true' >/dev/null <<<"$list_result"; then
    return 1
  fi
  if ! $JQ_BIN -e --arg bind_path "$BIND_PATH" --arg target_path "$MOUNT_PATH" \
    '.result.binds[]? | select((.bind_path // "") == $bind_path and (.target_path // "") == $target_path)' >/dev/null <<<"$list_result"; then
    return 1
  fi
  resolve_result=$(ws_invoke_and_read_result "mounts" "/agents/self/mounts/control/resolve.json" "{\"project_id\":\"$PROJECT_ID\",\"path\":\"$BIND_PATH\"}" "$SERVICE_STATUS_TIMEOUT_SEC")
  if ! $JQ_BIN -e --arg target_path "$MOUNT_PATH" '.ok == true and .result.matched == true and .result.resolved_path == $target_path' >/dev/null <<<"$resolve_result"; then
    return 1
  fi
  return 0
}

if [[ "$MOTHER_E2E_MODE" == "provider_chat" ]]; then
  if ! check_bind_and_resolve; then
    for _ in $(seq 1 3); do
      BIND_FIX_PROMPT=$(cat <<EOF
Bind is missing for project_id "$PROJECT_ID".
Please execute only this now:
1) Write {"project_id":"$PROJECT_ID","bind_path":"$BIND_PATH","target_path":"$MOUNT_PATH"} to /agents/self/mounts/control/bind.json
2) Write {"project_id":"$PROJECT_ID","path":"$BIND_PATH"} to /agents/self/mounts/control/resolve.json
3) Reply with compact JSON: {"ok":true,"project_id":"$PROJECT_ID","bind_path":"$BIND_PATH","resolved_path":"..."}
EOF
      )
      _=$(ws_chat_and_read_reply "$BIND_FIX_PROMPT" "$CHAT_TIMEOUT_SEC")
      if check_bind_and_resolve; then
        break
      fi
    done
  fi
else
  if ! check_bind_and_resolve; then
    echo "error: deterministic bind/resolve verification failed for project_id=$PROJECT_ID path=$BIND_PATH" >&2
    exit 1
  fi
fi

if [[ "$MOTHER_E2E_MODE" == "provider_chat" ]] && ! check_bind_and_resolve; then
  echo "error: expected bind path mapping not established for project namespace: $BIND_PATH -> $MOUNT_PATH" >&2
  exit 1
fi

if [[ "$MOTHER_E2E_MODE" == "deterministic" ]] && ! check_bind_and_resolve; then
  echo "error: expected bind path mapping not established for deterministic flow: $BIND_PATH -> $MOUNT_PATH" >&2
  exit 1
fi

# 4) verify attach to created project/agent works and bootstrap ends
ATTACH_PAYLOAD=$($JQ_BIN -cn --arg session_key "main" --arg project_id "$PROJECT_ID" --arg agent_id "$AGENT_ID" '{session_key:$session_key,project_id:$project_id,agent_id:$agent_id}')
ATTACH_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" session_attach "$ATTACH_PAYLOAD")
json_assert "$ATTACH_JSON" '.type == "control.session_attach" and .ok == true' 'session_attach failed for Mother-created project/agent'

POST_CONNECT_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" connect)
json_assert "$POST_CONNECT_JSON" '.type == "control.connect_ack" and .payload.bootstrap_only == false' 'post-bootstrap connect still reports bootstrap mode'

ws_close

cat <<SUMMARY
[mother-e2e] PASS
[mother-e2e] temp_root: $TMP_ROOT
[mother-e2e] server_log: $SERVER_LOG
[mother-e2e] ws_trace: $WS_TRACE
[mother-e2e] provider: ${PROVIDER_NAME}/${PROVIDER_MODEL:-default}
[mother-e2e] project_name: $PROJECT_NAME
[mother-e2e] project_id: $PROJECT_ID
[mother-e2e] agent_id: $AGENT_ID
[mother-e2e] mount_source: node_id=$NODE_ID export_name=$EXPORT_NAME
[mother-e2e] mount_path: $MOUNT_PATH
[mother-e2e] bind_path: $BIND_PATH
[mother-e2e] mother_reply_preview: $(printf '%s' "$CHAT_REPLY" | tr '\n' ' ' | cut -c1-200)
SUMMARY

if [[ "$KEEP_CANARY_DIR" == "1" ]]; then
  echo "[mother-e2e] KEEP_CANARY_DIR=1 so artifacts were preserved." >&2
fi
