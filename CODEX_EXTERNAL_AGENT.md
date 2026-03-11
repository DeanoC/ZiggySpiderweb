# Codex External Agent Guide

This guide is for running a non-Spider-Monkey agent inside Spiderweb, using Codex as the reference worker.

## Tested Status

Validated on March 11, 2026 against current `Spiderweb` `main`, plus the Windows/WSL follow-up fixes in this branch.

- Windows native:
  - `git submodule update --init --recursive` is required before builds or docs are trustworthy.
  - `zig build fs-mount`
  - `zig build test-fs-mount`
  - `spiderweb-fs-mount.exe --mount-backend winfsp` works from Windows against a WSL-hosted Spiderweb server.
  - Windows namespace validation passed for `dir X:\services`, `Get-Content X:\meta\protocol.json`, `Get-Content X:\projects\<project_id>\meta\mounted_services.json`, and routed writes under `X:\nodes\local\fs\...`.
  - Full `zig build` does not currently pass on Windows on this machine. The failures were in `zwasm`/POSIX-dependent targets plus missing `sqlite3` linkage for the server binary.
- WSL / Linux:
  - `zig build` passes in a clean Linux checkout.
  - Namespace attach with `spiderweb-fs-mount --namespace-url ...` works.
  - Starting `spiderweb` from a different WSL working directory still works when `runtime.spider_web_root` is set.

## Current Recommendation

Run the Spiderweb server in Linux or WSL.

Use Windows for the standalone `spiderweb-fs-mount` client and the final mounted workspace if you want Codex Desktop on Windows to work against it. That client path is now validated with WinFsp; the unsupported part is the full native Windows host build.

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

- `spiderweb-control workspace_create '{"name":"...","vision":"..."}'`
- `spiderweb-fs-mount --namespace-url ... status --no-probe`
- `spiderweb-fs-mount --namespace-url ... status`
- `spiderweb-fs-mount --namespace-url ... readdir /`
- `spiderweb-fs-mount --namespace-url ... readdir /services`
- `spiderweb-fs-mount --namespace-url ... cat /meta/protocol.json`
- `spiderweb-fs-mount --namespace-url ... cat /projects/<project_id>/meta/mounted_services.json`
- `spiderweb-fs-mount.exe --mount-backend winfsp ... mount X:` against a WSL-hosted Spiderweb server
- Windows `dir X:\services` and `Get-ChildItem X:\services`
- Windows reads from `X:\services\home\README.md` and `X:\services\workers\OPS.json`
- Windows routed writes under `X:\nodes\local\fs\...`
- project-scoped `workspace_status` now returns `fs_auth_token` for authorized callers, so routed namespace endpoints come up healthy
- automatic `control.agent_ensure` on attach created `/agents/codex` with seeded identity files
- the Linux / WSL host no longer depends on launch cwd for `agents`, `templates`, or the local agents export when `runtime.spider_web_root` is configured

## Fixed Since First Pass

These issues from the earlier Codex validation are no longer reproducing on the current branch:

1. `workspace_create` now succeeds with just `name` and `vision`.
2. `/services` now enumerates cleanly in namespace directory listing, including through the Windows WinFsp mount.
3. namespace-routed `/v2/fs` endpoints now hydrate correctly from project-scoped `workspace_status`, instead of staying unhealthy because `fs_auth_token` was omitted.
4. launching the WSL host from the wrong cwd no longer breaks agent/template discovery or the local agents export when `runtime.spider_web_root` is set.
5. remote `missing_field` and `invalid_payload` errors are now surfaced by `spiderweb-fs-mount` as `MissingField` and `InvalidPayload` instead of generic `InvalidResponse`.

## Gaps Found While Testing

These are the current missing pieces for a fresh Codex operator story:

1. `/meta/workspace_services.json` was still absent in live namespace validation. The reliable service inventory is still `/projects/<project_id>/meta/mounted_services.json`.
2. Service-control writes are still not reliable enough for a clear operator story, including from a real Windows mounted drive:
   - `/services/home/control/ensure.json` still leaves `result.json` at `{"ok":false,...}` for a minimal `{"agent_id":"codex"}` payload
   - `/services/workers/control/register.json` still leaves `result.json` at `{"ok":false,...}` and `/nodes/codex-worker` is still absent
   - the Windows-mounted path is therefore good for discovery and routed filesystem work, but not yet for durable service provisioning
3. Native Windows server builds are still not ready for the full host flow on this machine; the practical split is Linux/WSL host plus Windows mount client.
4. `docs/overview.md` still depends on submodules being initialized, so `git submodule update --init --recursive` remains mandatory before trusting the docs.

## Practical Operator Rule

Right now, the safest external-agent story is:

- host Spiderweb on Linux or WSL
- mount the namespace with `spiderweb-fs-mount`
- let Codex work against the mounted filesystem
- treat project metadata discovery as stable
- treat service-control writes as an area still needing hardening, payload clarification, and better result propagation
