# Codex External Agent Guide

This guide is for running a non-Spider-Monkey agent inside Spiderweb, using Codex as the reference worker.

## Tested Status

Validated on March 11, 2026 against `Spiderweb` `main`.

- Windows native:
  - `git submodule update --init --recursive` is required before builds or docs are trustworthy.
  - `zig build fs-mount`
  - `zig build test-fs-mount`
  - Full `zig build` does not currently pass on Windows on this machine. The failures were in `zwasm`/POSIX-dependent targets plus missing `sqlite3` linkage for the server binary.
- WSL / Linux:
  - `zig build` passes in a clean Linux checkout.
  - Namespace attach with `spiderweb-fs-mount --namespace-url ...` works.

## Current Recommendation

Run the Spiderweb server in Linux or WSL.

Use Windows only for the standalone `spiderweb-fs-mount` client and the final mounted workspace if you want Codex Desktop on Windows to work against it.

## Setup

### 1. Clone with submodules

```bash
git clone --recurse-submodules https://github.com/DeanoC/Spiderweb.git
cd Spiderweb
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

### 2. Build

Linux / WSL:

```bash
zig build
```

Windows-only mount client:

```powershell
zig build fs-mount
zig build test-fs-mount
```

### 3. Start Spiderweb and reveal auth

Linux / WSL:

```bash
./zig-out/bin/spiderweb-config auth reset --yes
./zig-out/bin/spiderweb-config auth status --reveal
./zig-out/bin/spiderweb
```

## Attach Flow For Codex

If you already have a workspace id:

```bash
./zig-out/bin/spiderweb-fs-mount \
  --namespace-url ws://127.0.0.1:18790/ \
  --workspace-id <workspace-id> \
  --auth-token <admin-or-user-token> \
  --agent-id codex \
  --session-key main \
  mount /mnt/spiderweb
```

For Windows with WinFsp:

```powershell
spiderweb-fs-mount.exe `
  --namespace-url ws://127.0.0.1:18790/ `
  --workspace-id <workspace-id> `
  --auth-token <admin-or-user-token> `
  --agent-id codex `
  --session-key main `
  --mount-backend winfsp `
  mount X:
```

Codex itself does not need a Spiderweb-specific runtime binary. It only needs filesystem access to the mounted workspace.

## What A Fresh Codex Should Read First

Once Codex is dropped into the mounted workspace, the minimum discovery order should be:

1. `/meta/protocol.json`
2. `/projects/<project_id>/meta/mounted_services.json`
3. `/projects/<project_id>/meta/workspace_status.json`
4. `/services/<service>/README.md`
5. `/services/<service>/OPS.json`
6. `/services/<service>/SCHEMA.json`
7. `/services/<service>/CAPS.json`
8. `/agents/<agent_id>/`

What this gives Codex:

- protocol and namespace shape
- which services are actually mounted into the current project
- current workspace health and path topology
- the live control-file contract for each service
- the agent identity files Spiderweb seeded for the current `agent_id`

## Minimal Codex Prompt

Use something close to this when placing a fresh Codex into a Spiderweb mount:

```text
You are operating inside a Spiderweb-mounted workspace.
Treat the filesystem as the contract.
Do not assume service availability from docs alone.
Start by reading /meta/protocol.json, /projects/<project_id>/meta/mounted_services.json, and /projects/<project_id>/meta/workspace_status.json.
Before using any service, read its README.md, OPS.json, SCHEMA.json, and CAPS.json.
Prefer /services/<venom_id> when present.
If a service is not bound there, fall back to the path reported in mounted_services.json.
Report path drift or missing writable control files before assuming the host is misconfigured.
```

## What Worked In Validation

- `spiderweb-fs-mount --namespace-url ... status --no-probe`
- `spiderweb-fs-mount --namespace-url ... readdir /`
- `spiderweb-fs-mount --namespace-url ... cat /meta/protocol.json`
- `spiderweb-fs-mount --namespace-url ... cat /projects/system/meta/mounted_services.json`
- automatic `control.agent_ensure` on attach created `/agents/codex` with seeded identity files

## Historical Notes

Earlier validation found several rough edges while Spiderweb still carried its embedded runtime path. Those specific `spiderweb-agent-runtime` and Mother/bootstrap issues are no longer the expected product path after the Spider Monkey split. Keep this document focused on mounted-workspace behavior and current namespace/service discovery instead of the removed embedded-runtime flow.

## Practical Operator Rule

Right now, the safest external-agent story is:

- host Spiderweb on Linux or WSL
- mount the namespace with `spiderweb-fs-mount`
- let Codex work against the mounted filesystem
- treat project metadata discovery as stable
- treat service-control writes as an area still needing hardening and better error reporting
