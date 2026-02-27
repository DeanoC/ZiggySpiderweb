# Node Namespace Extension Phases

This tracks the multi-phase expansion from FS-only nodes to general Acheron
namespace services.

## Phase 1 - Service Contract + Catalog Metadata

Status: completed

- Service descriptors now include `mounts`, `ops`, `runtime`, `permissions`,
  `schema`, and optional `help_md`.
- Built-in FS/terminal providers emit the richer metadata in
  `control.node_service_upsert`.
- Control-plane catalog parsing keeps these fields and publishes them into
  WorldFS service directories.

## Phase 2 - Manifest-Driven Service Definitions

Status: completed

- Node runtime supports:
  - `--service-manifest <path>` (repeatable)
  - `--services-dir <path>` (repeatable)
- Manifest loader supports:
  - `{node_id}` templating
  - `enabled: false` gating
  - defaults for `mounts`, `ops`, `runtime`, `permissions`, `schema`
- Duplicate `service_id` values across built-ins/manifests are rejected.

## Phase 3 - Runtime Namespace Execution

Status: completed

- Manifest services with `runtime.type = native_proc` and
  `runtime.executable_path` now materialize as executable namespace exports:
  - `service:<service_id>` source ID
  - synthetic files: `control/invoke.json`, `result.json`, `status.json`,
    `last_error.txt`, `README.md`, `SCHEMA.json`
- Writing JSON to `control/invoke.json` now executes the driver process
  (stdin payload -> stdout/stderr/status mapping).
- Runtime exports are merged with CLI exports for both standalone node mode and
  control-routed tunnel mode.

## Phase 4 - Driver ABI v1 + Reference Driver

Status: completed

- Added ABI v1 documentation:
  - `ZiggySpiderProtocol/docs/NAMESPACE_DRIVER_ABI_V1.md`
- Added reference native process driver in `ZiggySpiderNode`:
  - `examples/drivers/echo_driver.zig`
  - installed binary: `spiderweb-echo-driver`
- Added runnable reference manifest:
  - `examples/services.d/echo.json`

## Phase 5 - WorldFS Permission Enforcement + Ops Controls

Status: completed

- WorldFS service projection now enforces service `permissions` for non-admin
  sessions, with explicit admin bypass.
- WorldFS service projection now also enforces project action policy for
  `invoke` (`access_policy.actions.invoke` + per-agent overrides), so service
  visibility can be denied per project/agent even when service permissions
  would otherwise allow it.
- `allow_roles` and `default` permission fields are honored for visibility
  decisions in `/nodes/<id>/services/*` and derived node roots.
- Built-in FS/terminal provider metadata now includes
  `allow_roles:["admin","user"]` so normal sessions keep access.
- Namespace service scaffolds now include `control/reset`, which resets
  `result.json`, `status.json`, and `last_error.txt` to idle state.
- Added/updated tests across protocol and server repos for runtime export
  building, reset control behavior, permission enforcement, and admin bypass.

## Next Backlog

- Implement `native_inproc` loader execution against a stable symbol ABI.
- Implement WASM host execution path (`runtime.type = wasm`) for the same
  namespace control surface.
- Add per-service process lifecycle supervision (timeouts, restart policy,
  crash counters, health probes).
- Add hot-reload for manifest/runtime changes without full node restart.
