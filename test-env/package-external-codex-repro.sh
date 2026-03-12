#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$ROOT_DIR/test-env/codex-assets/build_external_codex_repro_bundle.py"
REPRO_OUTPUT_DIR="${REPRO_OUTPUT_DIR:-$ROOT_DIR/test-env/out/external-codex-repro-$(date +%Y%m%d-%H%M%S)}"
REPRO_INCLUDE_STRACE="${REPRO_INCLUDE_STRACE:-0}"
REPRO_CREATE_TARBALL="${REPRO_CREATE_TARBALL:-1}"
REPRO_CASE_NAMES="${REPRO_CASE_NAMES:-v0.110.0-json-no-pty,v0.111.0-json-no-pty,v0.111.0-json-pty,v0.112.0-json-no-pty}"

if [[ ! -f "$BUILDER" ]]; then
    echo "Missing bundle builder: $BUILDER" >&2
    exit 1
fi

declare -a SOURCE_DIRS=()
if [[ "$#" -gt 0 ]]; then
    for source in "$@"; do
        SOURCE_DIRS+=("$source")
    done
elif [[ -n "${REPRO_SOURCE_DIRS:-}" ]]; then
    IFS=':' read -r -a SOURCE_DIRS <<<"$REPRO_SOURCE_DIRS"
else
    for source in \
        /tmp/spiderweb-external-codex-matrix1 \
        /tmp/spiderweb-external-codex-matrix2 \
        /tmp/spiderweb-external-codex-matrix3
    do
        if [[ -d "$source" ]]; then
            SOURCE_DIRS+=("$source")
        fi
    done
fi

if [[ "${#SOURCE_DIRS[@]}" -eq 0 ]]; then
    echo "No source matrix directories found. Pass them as arguments or set REPRO_SOURCE_DIRS." >&2
    exit 1
fi

declare -a CASE_ARGS=()
IFS=',' read -r -a CASE_NAMES <<<"$REPRO_CASE_NAMES"
for case_name in "${CASE_NAMES[@]}"; do
    [[ -z "$case_name" ]] && continue
    CASE_ARGS+=(--case-name "$case_name")
done

declare -a CMD=(
    python3 "$BUILDER"
    --output-dir "$REPRO_OUTPUT_DIR"
    --repo-root "$ROOT_DIR"
)

for source_dir in "${SOURCE_DIRS[@]}"; do
    CMD+=(--source-dir "$source_dir")
done
CMD+=("${CASE_ARGS[@]}")

if [[ "$REPRO_INCLUDE_STRACE" == "1" ]]; then
    CMD+=(--include-strace)
fi

"${CMD[@]}"

if [[ "$REPRO_CREATE_TARBALL" == "1" ]]; then
    tar -C "$(dirname "$REPRO_OUTPUT_DIR")" -czf "$REPRO_OUTPUT_DIR.tar.gz" "$(basename "$REPRO_OUTPUT_DIR")"
fi

echo "Repro bundle written to $REPRO_OUTPUT_DIR"
if [[ "$REPRO_CREATE_TARBALL" == "1" ]]; then
    echo "Tarball written to $REPRO_OUTPUT_DIR.tar.gz"
fi
