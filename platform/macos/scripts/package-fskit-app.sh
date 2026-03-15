#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_PATH="$("$SCRIPT_DIR/build-fskit-app.sh")"
ZIP_PATH="$MACOS_DIR/build/SpiderwebFSKit-macos.zip"

if [[ ! -d "$APP_PATH" ]]; then
  echo "Expected built app at $APP_PATH" >&2
  exit 1
fi

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP_PATH" >/dev/null
fi

rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
echo "$ZIP_PATH"
