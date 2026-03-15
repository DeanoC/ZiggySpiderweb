# SpiderwebFSKit

This directory contains the native macOS FSKit scaffold for Spiderweb's
first-party mount backend.

Current scope:
- containing app bundle: `SpiderwebFSKit.app`
- FSKit extension target: `SpiderwebFSKitExtension`
- bundled Zig helper: `spiderweb-fs-helper`
- CLI install hooks: `spiderweb-config config install-fs-extension`

Current status:
- the Zig-side native mount handshake, helper binary, install/status CLI, and
  request file flow are implemented in the main repo
- the Swift app/extension bundle now hosts a helper-backed FSKit volume surface for
  getattr/readdir/statfs/open/read/write/create/remove/rename/xattr flows
- native auto-selection remains gated until the app bundle has been smoke-tested
  with a paid Apple Developer team that preserves the FSKit and App Group
  entitlements
- Xcode Personal Team / free signing is not sufficient: macOS registers the
  module, but strips the required entitlements and leaves the FSKit module
  disabled

Build flow:
1. Install full Xcode 16+ and select it with `sudo xcode-select -s`.
2. Install `xcodegen`.
3. Run `platform/macos/scripts/build-fskit-app.sh`.
4. Install the resulting app with `./zig-out/bin/spiderweb-config config install-fs-extension`.
5. Check `./zig-out/bin/spiderweb-config config fs-extension-status` and verify
   `app_group_entitlements`, `extension_fs_entitlement`, and `module_enabled`
   are all `yes`.

Verification flow on a macOS development machine:
1. `platform/macos/scripts/typecheck-fskit-swift.sh`
2. `zig build spiderweb-fs-helper`
3. `platform/macos/scripts/build-fskit-app.sh`
4. `./zig-out/bin/spiderweb-config config fs-extension-status`

The native backend is intentionally staged. On machines without a paid Apple
Developer team that preserves those entitlements, `--mount-backend fuse`
remains the reliable macOS path.
