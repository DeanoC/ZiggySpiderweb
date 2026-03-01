#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BIN_DIR=${BIN_DIR:-"$REPO_ROOT/zig-out/bin"}
SPIDERWEB_BIN=${SPIDERWEB_BIN:-"$BIN_DIR/spiderweb"}
CONTROL_BIN=${CONTROL_BIN:-"$BIN_DIR/spiderweb-control"}
WEBSOCAT_BIN=${WEBSOCAT_BIN:-"$(command -v websocat || true)"}
JQ_BIN=${JQ_BIN:-"$(command -v jq || true)"}

if [[ -z "$WEBSOCAT_BIN" ]]; then
  echo "error: websocat is required" >&2
  exit 1
fi
if [[ -z "$JQ_BIN" ]]; then
  echo "error: jq is required" >&2
  exit 1
fi
if [[ ! -x "$SPIDERWEB_BIN" || ! -x "$CONTROL_BIN" ]]; then
  echo "error: expected binaries under $BIN_DIR (build first with: zig build)" >&2
  exit 1
fi

CONFIG_SOURCE_PATH=${CANARY_PROVIDER_CONFIG:-${SPIDERWEB_CONFIG:-$HOME/.config/spiderweb/config.json}}
if [[ ! -f "$CONFIG_SOURCE_PATH" ]]; then
  echo "error: provider config not found at $CONFIG_SOURCE_PATH" >&2
  exit 1
fi

PROVIDER_NAME=${CANARY_PROVIDER_NAME:-$($JQ_BIN -r '.provider.name // empty' "$CONFIG_SOURCE_PATH")}
PROVIDER_MODEL=${CANARY_PROVIDER_MODEL:-$($JQ_BIN -r '.provider.model // empty' "$CONFIG_SOURCE_PATH")}
PROVIDER_BASE_URL=${CANARY_PROVIDER_BASE_URL:-$($JQ_BIN -r '.provider.base_url // empty' "$CONFIG_SOURCE_PATH")}
PROVIDER_API_KEY=${CANARY_PROVIDER_API_KEY:-$($JQ_BIN -r '.provider.api_key // empty' "$CONFIG_SOURCE_PATH")}

if [[ -z "$PROVIDER_NAME" ]]; then
  echo "error: provider.name is empty in $CONFIG_SOURCE_PATH" >&2
  exit 1
fi

if [[ -z "$PROVIDER_API_KEY" ]]; then
  case "$PROVIDER_NAME" in
    openrouter)
      PROVIDER_API_KEY=${OPENROUTER_API_KEY:-}
      ;;
    openai|openai-codex|openai-codex-spark)
      PROVIDER_API_KEY=${OPENAI_API_KEY:-}
      ;;
    anthropic)
      PROVIDER_API_KEY=${ANTHROPIC_API_KEY:-}
      ;;
    google|gemini)
      PROVIDER_API_KEY=${GOOGLE_API_KEY:-${GEMINI_API_KEY:-}}
      ;;
  esac
fi

CANARY_PORT=${CANARY_PORT:-28831}
ASK_TEXT=${ASK_TEXT:-"In one short sentence, ask me for the first project name, project vision, and first non-system agent name."}
CHAT_MAX_ATTEMPTS=${CHAT_MAX_ATTEMPTS:-3}
CONTROL_RETRY_ATTEMPTS=${CONTROL_RETRY_ATTEMPTS:-30}
CONTROL_RETRY_DELAY_SEC=${CONTROL_RETRY_DELAY_SEC:-0.2}
WS_ATTACH_RETRY_ATTEMPTS=${WS_ATTACH_RETRY_ATTEMPTS:-5}
PROJECT_NAME=${PROJECT_NAME:-"manual-canary-project"}
PROJECT_VISION=${PROJECT_VISION:-"Validate Mother bootstrap and provider-backed provisioning flow."}
AGENT_ID=${AGENT_ID:-"manual-canary-agent"}
AGENT_NAME=${AGENT_NAME:-"Manual Canary Agent"}
KEEP_CANARY_DIR=${KEEP_CANARY_DIR:-0}

TMP_ROOT=$(mktemp -d /tmp/spiderweb-manual-mother-canary-XXXXXX)
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
    rm -rf "$TMP_ROOT"
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
      sandbox_enabled: false,
      default_agent_id: "mother",
      ltm_directory: $ltm_dir,
      assets_dir: $assets_dir,
      agents_dir: $agents_dir
    }
  }' > "$CONFIG_PATH"

echo "[canary] config: $CONFIG_PATH"
echo "[canary] provider: ${PROVIDER_NAME}/${PROVIDER_MODEL:-default}"
if [[ -z "$PROVIDER_API_KEY" ]]; then
  echo "[canary] warning: no provider API key supplied via CANARY_PROVIDER_API_KEY, config provider.api_key, or provider env var."
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
for _ in $(seq 1 100); do
  if [[ -f "$AUTH_PATH" ]]; then
    break
  fi
  sleep 0.2
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
  tmp_err=$(mktemp /tmp/spiderweb-canary-control-retry-XXXXXX)
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

# 1) baseline: Mother-only bootstrap connect
CONNECT_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" connect)
json_assert "$CONNECT_JSON" '.type == "control.connect_ack"' 'connect did not return control.connect_ack'
json_assert "$CONNECT_JSON" '.payload.agent_id == "mother" and .payload.project_id == "system"' 'connect ack not bound to mother/system'
json_assert "$CONNECT_JSON" '.payload.bootstrap_only == true' 'expected bootstrap_only=true on first connect'
json_assert "$CONNECT_JSON" '.payload.bootstrap_message != null' 'expected bootstrap bootstrap_message'

AGENT_LIST_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" agent_list)
json_assert "$AGENT_LIST_JSON" '.payload.agents | length == 1' 'expected only mother agent before provisioning'
json_assert "$AGENT_LIST_JSON" '.payload.agents[0].id == "mother"' 'expected mother as only bootstrap agent'

# 2) provider-backed Mother prompt
ws_attach_with_retry "manual-version" "manual-connect" 1 2 "$WS_ATTACH_RETRY_ATTEMPTS"

EXPECTED_PROMPT="$ASK_TEXT"
CHAT_REPLY=""
for attempt in $(seq 1 "$CHAT_MAX_ATTEMPTS"); do
  CHAT_WRITE_FRAME=$(ws_write_text_file "/agents/self/chat/control/input" "$EXPECTED_PROMPT" 180)
  CHAT_JOB=$($JQ_BIN -r '.payload.job // empty' <<<"$CHAT_WRITE_FRAME")
  CHAT_RESULT_PATH=$($JQ_BIN -r '.payload.result_path // empty' <<<"$CHAT_WRITE_FRAME")
  if [[ -z "$CHAT_RESULT_PATH" ]]; then
    if [[ -z "$CHAT_JOB" ]]; then
      echo "error: chat write did not return job/result_path" >&2
      exit 1
    fi
    CHAT_RESULT_PATH="/agents/self/jobs/${CHAT_JOB}/result.txt"
  fi
  CHAT_REPLY=$(ws_read_text_file "$CHAT_RESULT_PATH" 240)
  LOWER_REPLY=$(printf '%s' "$CHAT_REPLY" | tr '[:upper:]' '[:lower:]')
  if [[ "$LOWER_REPLY" == *"provider request invalid"* ]]; then
    echo "error: provider request invalid (check provider credentials/model in $CONFIG_SOURCE_PATH)" >&2
    echo "$CHAT_REPLY" >&2
    exit 1
  fi
  if [[ "$LOWER_REPLY" == *project* && "$LOWER_REPLY" == *vision* && "$LOWER_REPLY" == *agent* ]]; then
    break
  fi
  if [[ "$attempt" -lt "$CHAT_MAX_ATTEMPTS" ]]; then
    sleep 1
  fi
done
ws_close

if [[ -z "$CHAT_REPLY" ]]; then
  echo "error: Mother chat reply is empty" >&2
  exit 1
fi
LOWER_REPLY=$(printf '%s' "$CHAT_REPLY" | tr '[:upper:]' '[:lower:]')
if [[ "$LOWER_REPLY" != *project* || "$LOWER_REPLY" != *vision* || "$LOWER_REPLY" != *agent* ]]; then
  echo "error: Mother reply did not include project/vision/agent onboarding prompts after $CHAT_MAX_ATTEMPTS attempts" >&2
  echo "$CHAT_REPLY" >&2
  exit 1
fi

# 3) provision project + first non-system agent
SYSTEM_ATTACH_PAYLOAD=$($JQ_BIN -cn \
  --arg session_key "main" \
  --arg project_id "system" \
  --arg agent_id "mother" \
  '{session_key:$session_key,project_id:$project_id,agent_id:$agent_id}')
SYSTEM_ATTACH_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" session_attach "$SYSTEM_ATTACH_PAYLOAD")
json_assert "$SYSTEM_ATTACH_JSON" '.type == "control.session_attach" and .ok == true' 'session_attach failed for system/mother bootstrap context'

PROJECT_CREATE_PAYLOAD=$($JQ_BIN -cn --arg name "$PROJECT_NAME" --arg vision "$PROJECT_VISION" '{name:$name,vision:$vision}')
PROJECT_ID=""
PROJECT_CREATE_TMP_ERR=$(mktemp /tmp/spiderweb-canary-project-create-XXXXXX)
set +e
PROJECT_CREATE_JSON=""
PROJECT_CREATE_RC=1
for attempt in $(seq 1 "$CONTROL_RETRY_ATTEMPTS"); do
  PROJECT_CREATE_JSON=$(control project_create "$PROJECT_CREATE_PAYLOAD" 2>"$PROJECT_CREATE_TMP_ERR")
  PROJECT_CREATE_RC=$?
  if [[ "$PROJECT_CREATE_RC" -eq 0 ]]; then
    break
  fi
  if [[ "$attempt" -lt "$CONTROL_RETRY_ATTEMPTS" ]]; then
    sleep "$CONTROL_RETRY_DELAY_SEC"
  fi
done
set -e
if [[ "$PROJECT_CREATE_RC" -eq 0 ]]; then
  json_assert "$PROJECT_CREATE_JSON" '.type == "control.project_create" and .ok == true' 'project_create failed'
  PROJECT_ID=$($JQ_BIN -r '.payload.project_id // empty' <<<"$PROJECT_CREATE_JSON")
  if [[ -z "$PROJECT_ID" ]]; then
    echo "error: project_create did not return project_id" >&2
    rm -f "$PROJECT_CREATE_TMP_ERR"
    exit 1
  fi
else
  PROJECT_CREATE_ERR=$(cat "$PROJECT_CREATE_TMP_ERR")
  if [[ "$PROJECT_CREATE_ERR" == *"project_context_required"* ]]; then
    PROJECT_LIST_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" project_list)
    PROJECT_ID=$($JQ_BIN -r '.payload.projects[]? | select((.project_id // "") != "system") | .project_id' <<<"$PROJECT_LIST_JSON" | head -n1)
    if [[ -z "$PROJECT_ID" ]]; then
      echo "error: project_create gated by project_context_required and no non-system project exists" >&2
      echo "$PROJECT_CREATE_ERR" >&2
      rm -f "$PROJECT_CREATE_TMP_ERR"
      exit 1
    fi
  else
    echo "error: project_create failed" >&2
    echo "$PROJECT_CREATE_ERR" >&2
    rm -f "$PROJECT_CREATE_TMP_ERR"
    exit 1
  fi
fi
rm -f "$PROJECT_CREATE_TMP_ERR"

ws_attach_with_retry "manual-version-2" "manual-connect-2" 3 4 "$WS_ATTACH_RETRY_ATTEMPTS"

AGENT_CREATE_PAYLOAD=$($JQ_BIN -cn \
  --arg agent_id "$AGENT_ID" \
  --arg name "$AGENT_NAME" \
  '{agent_id:$agent_id,name:$name,description:"Manual provider canary agent",capabilities:["chat","plan","code"]}')

_=$(ws_write_text_file "/agents/self/agents/control/create.json" "$AGENT_CREATE_PAYLOAD" 60)

AGENT_STATE=""
for _ in $(seq 1 60); do
  STATUS_JSON=$(ws_read_text_file "/agents/self/agents/status.json" 30)
  AGENT_STATE=$($JQ_BIN -r '.state // empty' <<<"$STATUS_JSON" 2>/dev/null || true)
  if [[ "$AGENT_STATE" == "done" ]]; then
    break
  fi
  sleep 1
done
if [[ "$AGENT_STATE" != "done" ]]; then
  echo "error: agents_create did not reach done state" >&2
  exit 1
fi
AGENT_RESULT_JSON=$(ws_read_text_file "/agents/self/agents/result.json" 30)
ws_close
json_assert "$AGENT_RESULT_JSON" '.ok == true and .operation == "create" and .result.agent_id == $id' 'agents/result.json did not confirm create' --arg id "$AGENT_ID"

HATCH_PATH="$AGENTS_DIR/$AGENT_ID/HATCH.md"
META_PATH="$AGENTS_DIR/$AGENT_ID/agent.json"
if [[ ! -f "$HATCH_PATH" ]]; then
  echo "error: expected HATCH file missing at $HATCH_PATH" >&2
  exit 1
fi
if [[ ! -f "$META_PATH" ]]; then
  echo "error: expected agent metadata missing at $META_PATH" >&2
  exit 1
fi
if ! grep -q "Create your identity by writing SOUL.md" "$HATCH_PATH"; then
  echo "error: HATCH.md did not contain expected hatching instruction text" >&2
  exit 1
fi

ATTACH_PAYLOAD=$($JQ_BIN -cn --arg session_key "main" --arg project_id "$PROJECT_ID" --arg agent_id "$AGENT_ID" '{session_key:$session_key,project_id:$project_id,agent_id:$agent_id}')
ATTACH_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" session_attach "$ATTACH_PAYLOAD")
json_assert "$ATTACH_JSON" '.type == "control.session_attach" and .ok == true' 'session_attach failed for provisioned project/agent'

POST_CONNECT_JSON=$(control_retry "$CONTROL_RETRY_ATTEMPTS" "$CONTROL_RETRY_DELAY_SEC" connect)
json_assert "$POST_CONNECT_JSON" '.type == "control.connect_ack" and .payload.bootstrap_only == false' 'post-bootstrap connect still reports bootstrap mode'

cat <<SUMMARY
[canary] PASS
[canary] temp_root: $TMP_ROOT
[canary] server_log: $SERVER_LOG
[canary] ws_trace: $WS_TRACE
[canary] provider: ${PROVIDER_NAME}/${PROVIDER_MODEL:-default}
[canary] project_id: $PROJECT_ID
[canary] agent_id: $AGENT_ID
[canary] mother_reply_preview: $(printf '%s' "$CHAT_REPLY" | tr '\n' ' ' | cut -c1-200)
SUMMARY

if [[ "$KEEP_CANARY_DIR" == "1" ]]; then
  echo "[canary] KEEP_CANARY_DIR=1 so artifacts were preserved." >&2
fi
