# Spiderweb 🕸️

[![CI](https://github.com/DeanoC/Spiderweb/actions/workflows/ci.yml/badge.svg)](https://github.com/DeanoC/Spiderweb/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.15.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An **AI agent gateway + Acheron-based distributed RPC filesystem** for multi-node, tool-capable agents. Built in Zig. The Spiderweb server remains Linux-oriented, and the standalone `spiderweb-fs-mount` client now builds for Linux and Windows.

## Vision

Spiderweb’s goal is to make agents work across machines and services **as if they were navigating a filesystem**. Instead of bespoke APIs, agents get a unified WorldFS where chat, tools, files, and remote services are just paths. This makes multi-node workspaces, device services, and project context feel native and composable.

In short: **a gateway + distributed RPC filesystem that turns the world into paths**.

If that resonates, start with:
- `docs/overview.md`
- `docs/README.md`

The docs tree is intentionally minimal and code-grounded. Older RFC/migration notes were removed once the single-websocket worldfs transport became the shipped behavior.

## Quick Start

### Automated Install (Recommended for Debian/Ubuntu)

```bash
# One-line install - downloads, builds, configures, and runs
curl -fsSL https://raw.githubusercontent.com/DeanoC/Spiderweb/main/install.sh -o /tmp/install.sh
chmod +x /tmp/install.sh
/tmp/instaill.sh
```

This script will:
1. Check and install dependencies (Zig, secret-tool, jq, etc.)
2. Clone and build Spiderweb
3. Prompt for AI provider and API key
4. Configure secure credential storage
5. Provision Mother system agent scaffold
6. Start the server

### Manual Install

```bash
# Clone and build
git clone --recurse-submodules https://github.com/DeanoC/Spiderweb.git
cd Spiderweb
# If you already cloned without submodules:
git submodule update --init --recursive
zig build

# Store provider key in secure credential backend (Linux: secret-tool)
./zig-out/bin/spiderweb-config config set-key sk-... openai

# Run on default port 18790
./zig-out/bin/spiderweb

# Or specify custom port
./zig-out/bin/spiderweb --port 9000
```

## Standalone Mount Client

`spiderweb-fs-mount` can now run as a standalone client on machines that do not host Spiderweb locally.

- `--workspace-url <ws-url>` keeps the existing routed `/v2/fs` mount mode.
- `--namespace-url <ws-url>` connects to the main Spiderweb websocket, attaches an Acheron session root, and mounts the full namespace (`/agents`, `/nodes`, `/global`, optional `/debug`).
- In namespace mode, node-backed filesystem subtrees discovered from workspace topology still route through `/v2/fs`, so regular file mutation keeps working under mounted workspace exports.
- Session-only synthetic paths support `stat`, `readdir`, `read`, and writes to existing writable files. `create`, `unlink`, `mkdir`, `rmdir`, `rename`, and `truncate` return unsupported errors on those paths.

Build only the standalone client:

```bash
zig build fs-mount
zig build test-fs-mount
```

Installers:

- Linux: `./install-fs-mount.sh`
- Windows: `powershell -ExecutionPolicy Bypass -File .\install-fs-mount.ps1`
- Smoke harnesses: `./scripts/acheron-namespace-smoke.sh` and `powershell -ExecutionPolicy Bypass -File .\scripts\acheron-namespace-smoke.ps1`

Examples:

```bash
# Existing routed-FS mode
./zig-out/bin/spiderweb-fs-mount --workspace-url ws://127.0.0.1:18790/ mount /mnt/spiderweb

# Full namespace mode
./zig-out/bin/spiderweb-fs-mount --namespace-url ws://127.0.0.1:18790/ --project-id proj-a mount /mnt/spiderweb

# Namespace smoke harness (low-level commands, optional real mount when SMOKE_USE_OS_MOUNT=1)
SPIDERWEB_PROJECT_ID=proj-a ./scripts/acheron-namespace-smoke.sh
```
