# Spiderweb 🕸️

[![CI](https://github.com/DeanoC/Spiderweb/actions/workflows/ci.yml/badge.svg)](https://github.com/DeanoC/Spiderweb/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.15.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Spiderweb is a **workspace host + Acheron-based distributed RPC filesystem** for external agents. It provides the workspace, virtual filesystem, nodes, venoms, and control plane. The agent process itself lives outside Spiderweb and uses the mounted workspace as its contract.

Built in Zig. The Spiderweb server remains Linux-oriented, and the standalone `spiderweb-fs-mount` client builds for Linux and Windows.

## Vision

Spiderweb’s goal is to make agent systems feel like they are navigating a filesystem instead of stitching together bespoke APIs. Chat, jobs, memory surfaces, worker registration, files, and remote services are projected into one namespace so agents can discover and use them by path.

In short: **Spiderweb hosts the namespace; workers operate through it**.

If that resonates, start with:
- `docs/overview.md`
- `docs/README.md`
- `CODEX_EXTERNAL_AGENT.md` for the current non-Spider-Monkey external-worker path

## Quick Start

### Workspace-First External Worker Flow

This is the current product path.

```bash
# Build Spiderweb
git clone --recurse-submodules https://github.com/DeanoC/Spiderweb.git
cd Spiderweb
zig build

# Check the local control auth tokens used by spiderweb-control/spiderweb-fs-mount
./zig-out/bin/spiderweb-config auth status --reveal

# Start Spiderweb
./zig-out/bin/spiderweb

# Create a workspace
./zig-out/bin/spiderweb-control \
  --auth-token <admin-token> \
  workspace_create \
  '{"name":"Demo","vision":"Mounted workspace demo"}'

# Mount that workspace into the local filesystem
./zig-out/bin/spiderweb-fs-mount \
  --workspace-url ws://127.0.0.1:18790/ \
  --workspace-id <workspace-id> \
  --auth-token <admin-or-user-token> \
  mount /mnt/spiderweb-demo

# Start an external worker against the mounted folder
../SpiderMonkey/zig-out/bin/spider-monkey \
  run \
  --agent-id spider-monkey \
  --worker-id spider-monkey-a \
  --workspace-root /mnt/spiderweb-demo
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
./zig-out/bin/spiderweb-fs-mount --namespace-url ws://127.0.0.1:18790/ --workspace-id ws-demo mount /mnt/spiderweb

# Namespace smoke harness (low-level commands, optional real mount when SMOKE_USE_OS_MOUNT=1)
SPIDERWEB_WORKSPACE_ID=ws-demo ./scripts/acheron-namespace-smoke.sh
```

This flow has been smoke-tested with:
- `spiderweb`
- `spiderweb-control workspace_create`
- `spiderweb-control workspace_list`
- `spiderweb-fs-mount ... readdir /`

### What Spiderweb Owns

- Workspace creation, topology, control-plane metadata, and workspace tokens.
- Mounted namespace projection through Acheron / WorldFS.
- Shared workspace services such as `/services/home`, `/services/workers`, chat/job queue surfaces, and control venoms.
- Durable per-agent home allocation inside a workspace.
- Ephemeral worker-node projection and liveness tracking for attached workers.

### What External Workers Own

- Model/provider configuration and credentials.
- Private loopback services such as worker-owned `memory` and `sub_brains`.
- Job consumption and reply writing through the mounted workspace.
- Their own process lifecycle outside Spiderweb.

## Notes

- If `runtime.spider_web_root` is empty, Spiderweb uses its current working directory as the default local workspace root.
- If `runtime.spider_web_root` is set, relative runtime paths such as `agents`, `templates`, and `sandbox_fs_mount_bin` are resolved from that root instead of the process launch cwd.
- `spiderweb-config auth path` and `auth status` now resolve auth tokens from the local runtime context instead of assuming an embedded AI setup.
- The happy path no longer uses Mother/system bootstrap or provider setup inside Spiderweb.
- Spider Monkey is the first external worker for this model, but the intent is broader: any agent that can work against a filesystem can use a mounted Spiderweb workspace.
