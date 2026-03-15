#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SDK_PATH="${SPIDERWEB_FSKIT_SDK_PATH:-}"

if [[ -z "$SDK_PATH" ]]; then
  SDK_PATH="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
fi

if [[ -z "$SDK_PATH" || ! -d "$SDK_PATH" ]]; then
  echo "Missing a macOS SDK. Install Command Line Tools or full Xcode." >&2
  exit 1
fi

swiftc -typecheck \
  -sdk "$SDK_PATH" \
  -target arm64-apple-macos15.4 \
  "$MACOS_DIR/Sources/Shared/SpiderwebMountRequest.swift" \
  "$MACOS_DIR/Sources/SpiderwebFSKitExtension/SpiderwebFSKitExtension.swift"

swiftc -typecheck \
  -sdk "$SDK_PATH" \
  -target arm64-apple-macos15.4 \
  "$MACOS_DIR/Sources/Shared/SpiderwebMountRequest.swift" \
  "$MACOS_DIR/Sources/SpiderwebFSKitApp/SpiderwebFSKitAppMain.swift" \
  "$MACOS_DIR/Sources/SpiderwebFSKitApp/SpiderwebFSKitAppController.swift"
