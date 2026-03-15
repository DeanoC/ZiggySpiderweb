#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$MACOS_DIR/../.." && pwd)"
PROJECT_SPEC="$MACOS_DIR/project.yml"
PROJECT_PATH="$MACOS_DIR/SpiderwebFSKit.xcodeproj"
DERIVED_DATA_PATH="$MACOS_DIR/build/DerivedData"
GENERATED_CONFIG_DIR="$MACOS_DIR/build/generated"
APP_ENTITLEMENTS_TEMPLATE="$MACOS_DIR/Config/SpiderwebFSKit.entitlements.in"
EXTENSION_ENTITLEMENTS_TEMPLATE="$MACOS_DIR/Config/SpiderwebFSKitExtension.entitlements.in"
APP_ENTITLEMENTS_PATH="$GENERATED_CONFIG_DIR/SpiderwebFSKit.entitlements"
EXTENSION_ENTITLEMENTS_PATH="$GENERATED_CONFIG_DIR/SpiderwebFSKitExtension.entitlements"
APP_PATH="$DERIVED_DATA_PATH/Build/Products/Release/SpiderwebFSKit.app"
HELPER_PATH="$REPO_ROOT/zig-out/bin/spiderweb-fs-helper"
HELPER_DEST="$APP_PATH/Contents/MacOS/spiderweb-fs-helper"
RUNTIME_READY_MANIFEST="$APP_PATH/Contents/Resources/SpiderwebFSKit.runtime-ready"
APP_XCENT="$DERIVED_DATA_PATH/Build/Intermediates.noindex/SpiderwebFSKit.build/Release/SpiderwebFSKit.build/SpiderwebFSKit.app.xcent"
DEVELOPMENT_TEAM="${SPIDERWEB_FSKIT_DEVELOPMENT_TEAM:-}"
CODE_SIGN_IDENTITY_NAME="${SPIDERWEB_FSKIT_CODE_SIGN_IDENTITY:-Apple Development}"

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild is required. Install full Xcode 16+ and select it with xcode-select." >&2
  exit 1
fi

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "xcodegen is required to generate platform/macos/SpiderwebFSKit.xcodeproj." >&2
  echo "Install it with Homebrew: brew install xcodegen" >&2
  exit 1
fi

if [[ -z "$DEVELOPMENT_TEAM" ]]; then
  DEVELOPMENT_TEAM="$(defaults read com.apple.dt.Xcode IDEProvisioningTeamByIdentifier 2>/dev/null | awk -F'= ' '/teamID = / {gsub(/["; ]/, "", $2); print $2; exit}')"
fi

if [[ -z "$DEVELOPMENT_TEAM" ]]; then
  echo "No Xcode development team was found. Sign into Xcode and ensure a team is available, or set SPIDERWEB_FSKIT_DEVELOPMENT_TEAM." >&2
  exit 1
fi

pushd "$REPO_ROOT" >/dev/null
# `zig build <step>` compiles the helper target but does not guarantee it lands
# in `zig-out/bin`; include the install step so the app bundling path can copy it.
zig build install spiderweb-fs-helper
popd >/dev/null

mkdir -p "$MACOS_DIR/build"
mkdir -p "$GENERATED_CONFIG_DIR"
cp "$APP_ENTITLEMENTS_TEMPLATE" "$APP_ENTITLEMENTS_PATH"
cp "$EXTENSION_ENTITLEMENTS_TEMPLATE" "$EXTENSION_ENTITLEMENTS_PATH"
xcodegen generate --spec "$PROJECT_SPEC"
xcodebuild \
  -project "$PROJECT_PATH" \
  -scheme SpiderwebFSKit \
  -configuration Release \
  -derivedDataPath "$DERIVED_DATA_PATH" \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" \
  CODE_SIGN_IDENTITY="$CODE_SIGN_IDENTITY_NAME" \
  CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION=YES \
  build

if [[ ! -f "$HELPER_PATH" ]]; then
  echo "Expected Zig helper at $HELPER_PATH" >&2
  exit 1
fi

mkdir -p "$(dirname "$HELPER_DEST")"
cp "$HELPER_PATH" "$HELPER_DEST"
chmod +x "$HELPER_DEST"
mkdir -p "$(dirname "$RUNTIME_READY_MANIFEST")"
: >"$RUNTIME_READY_MANIFEST"

if [[ "$CODE_SIGN_IDENTITY_NAME" == "Apple Development" ]]; then
  RESOLVED_CODE_SIGN_IDENTITY="$(security find-identity -v -p codesigning | awk -F'\"' '/Apple Development/ {print $2; exit}')"
  if [[ -n "$RESOLVED_CODE_SIGN_IDENTITY" ]]; then
    CODE_SIGN_IDENTITY_NAME="$RESOLVED_CODE_SIGN_IDENTITY"
  fi
fi

codesign --force --sign "$CODE_SIGN_IDENTITY_NAME" "$HELPER_DEST"
codesign --force --sign "$CODE_SIGN_IDENTITY_NAME" --entitlements "$APP_XCENT" "$APP_PATH"

echo "$APP_PATH"
