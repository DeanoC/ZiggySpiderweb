#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
E2E_SCRIPT="$SCRIPT_DIR/manual-mother-agent-e2e.sh"

ZIG_BIN=${ZIG_BIN:-zig}
ZIG_OUT_DIR=${ZIG_OUT_DIR:-"$REPO_ROOT/.zig-out-user"}
ZIG_LOCAL_CACHE_DIR=${ZIG_LOCAL_CACHE_DIR:-"$REPO_ROOT/.zig-cache-user"}
ZIG_GLOBAL_CACHE_DIR=${ZIG_GLOBAL_CACHE_DIR:-"$REPO_ROOT/.zig-global-cache-user"}
BIN_DIR=${BIN_DIR:-"$ZIG_OUT_DIR/bin"}

if [[ "$ZIG_OUT_DIR" != /* ]]; then
  ZIG_OUT_DIR="$REPO_ROOT/$ZIG_OUT_DIR"
fi
if [[ "$ZIG_LOCAL_CACHE_DIR" != /* ]]; then
  ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/$ZIG_LOCAL_CACHE_DIR"
fi
if [[ "$ZIG_GLOBAL_CACHE_DIR" != /* ]]; then
  ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/$ZIG_GLOBAL_CACHE_DIR"
fi
if [[ "$BIN_DIR" != /* ]]; then
  BIN_DIR="$REPO_ROOT/$BIN_DIR"
fi

RUN_DETERMINISTIC=${RUN_DETERMINISTIC:-1}
RUN_PROVIDER_CHAT=${RUN_PROVIDER_CHAT:-auto}
CODEX_AUTH_PATH=${CODEX_AUTH_PATH:-"$HOME/.codex/auth.json"}
CANARY_PROVIDER_NAME=${CANARY_PROVIDER_NAME:-openai-codex}
CANARY_PROVIDER_MODEL=${CANARY_PROVIDER_MODEL:-gpt-5.3-codex}
CANARY_PORT_DETERMINISTIC=${CANARY_PORT_DETERMINISTIC:-28832}
CANARY_PORT_PROVIDER_CHAT=${CANARY_PORT_PROVIDER_CHAT:-28833}
KEEP_CANARY_DIR=${KEEP_CANARY_DIR:-0}
SKIP_BUILD=${SKIP_BUILD:-0}

if [[ "$RUN_DETERMINISTIC" != "0" && "$RUN_DETERMINISTIC" != "1" ]]; then
  echo "error: RUN_DETERMINISTIC must be 0 or 1" >&2
  exit 1
fi
if [[ "$SKIP_BUILD" != "0" && "$SKIP_BUILD" != "1" ]]; then
  echo "error: SKIP_BUILD must be 0 or 1" >&2
  exit 1
fi

if [[ "$RUN_PROVIDER_CHAT" == "auto" ]]; then
  if [[ -f "$CODEX_AUTH_PATH" || -n "${CANARY_PROVIDER_API_KEY:-}" || -n "${OPENAI_CODEX_API_KEY:-}" || -n "${OPENAI_API_KEY:-}" ]]; then
    RUN_PROVIDER_CHAT=1
  else
    RUN_PROVIDER_CHAT=0
  fi
fi

if [[ "$RUN_PROVIDER_CHAT" != "0" && "$RUN_PROVIDER_CHAT" != "1" ]]; then
  echo "error: RUN_PROVIDER_CHAT must be auto, 0, or 1" >&2
  exit 1
fi

if [[ ! -x "$E2E_SCRIPT" ]]; then
  echo "error: missing executable $E2E_SCRIPT" >&2
  exit 1
fi

mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

if [[ "$SKIP_BUILD" == "1" ]]; then
  echo "[mother-e2e-suite] skip build (SKIP_BUILD=1)"
else
  echo "[mother-e2e-suite] build: $ZIG_OUT_DIR"
  (
    cd "$REPO_ROOT"
    ZIG_LOCAL_CACHE_DIR="$ZIG_LOCAL_CACHE_DIR" \
    ZIG_GLOBAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR" \
    "$ZIG_BIN" build -p "$ZIG_OUT_DIR"
  )
fi

if [[ "$RUN_DETERMINISTIC" == "1" ]]; then
  echo "[mother-e2e-suite] run deterministic mode"
  (
    cd "$REPO_ROOT"
    MOTHER_E2E_MODE=deterministic \
    CANARY_PORT="$CANARY_PORT_DETERMINISTIC" \
    BIN_DIR="$BIN_DIR" \
    KEEP_CANARY_DIR="$KEEP_CANARY_DIR" \
    "$E2E_SCRIPT"
  )
fi

if [[ "$RUN_PROVIDER_CHAT" == "1" ]]; then
  echo "[mother-e2e-suite] run provider_chat mode using $CANARY_PROVIDER_NAME/$CANARY_PROVIDER_MODEL"
  (
    cd "$REPO_ROOT"
    CANARY_PROVIDER_NAME="$CANARY_PROVIDER_NAME" \
    CANARY_PROVIDER_MODEL="$CANARY_PROVIDER_MODEL" \
    MOTHER_E2E_MODE=provider_chat \
    CANARY_PORT="$CANARY_PORT_PROVIDER_CHAT" \
    BIN_DIR="$BIN_DIR" \
    KEEP_CANARY_DIR="$KEEP_CANARY_DIR" \
    "$E2E_SCRIPT"
  )
else
  echo "[mother-e2e-suite] skip provider_chat mode (no auth or provider secret detected)"
fi

echo "[mother-e2e-suite] PASS"
