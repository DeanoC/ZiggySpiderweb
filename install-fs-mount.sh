#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/DeanoC/Spiderweb.git}"
DEST_DIR="${DEST_DIR:-$HOME/.local/share/spiderweb-fs-mount-src}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need_cmd git
need_cmd zig

if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v mount.fuse3 >/dev/null 2>&1; then
  cat >&2 <<'EOF'
fuse3 runtime tools were not found.
Install fuse3 first, for example:
  Debian/Ubuntu: sudo apt-get install fuse3
  Fedora: sudo dnf install fuse3
  Arch: sudo pacman -S fuse3
EOF
  exit 1
fi

mkdir -p "$(dirname "$DEST_DIR")"
if [ -d "$DEST_DIR/.git" ]; then
  git -C "$DEST_DIR" fetch --all --tags
  git -C "$DEST_DIR" pull --ff-only
  git -C "$DEST_DIR" submodule update --init --recursive
else
  git clone --recurse-submodules "$REPO_URL" "$DEST_DIR"
fi

cd "$DEST_DIR"
zig build fs-mount

mkdir -p "$INSTALL_DIR"
install -m 0755 zig-out/bin/spiderweb-fs-mount "$INSTALL_DIR/spiderweb-fs-mount"

cat <<EOF
Installed spiderweb-fs-mount to:
  $INSTALL_DIR/spiderweb-fs-mount

Linux notes:
  - Non-root mounts require a working fuse3 setup on this machine.
  - Your user may need fuse access, depending on distro policy.
  - Example:
      spiderweb-fs-mount --namespace-url ws://host:18790/ --project-id proj-a mount /mnt/spiderweb
EOF
