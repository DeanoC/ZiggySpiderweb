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

## Phase 6 - Runtime Reload + Host Contract + Multi-Node Harness

Status: completed

- Control-tunnel nodes now support manifest hot reload without process restart:
  - periodic manifest reconciliation (`--manifest-reload-interval-ms`)
  - service namespace reload (add/remove/update) with runtime state carryover
  - service catalog re-upsert after reload
- Runtime-state persistence remains durable across reconnects/restarts via
  `<state-file>.runtime-services.json`.
- Lease refresh now uses a shared, mutable service registry snapshot, preventing
  stale catalog overwrites after manifest changes.
- Added runtime host abstraction metadata (`HOST.json`) in namespace service
  roots, exposing a shared host contract for static/native/wasm drivers.
- Added multi-node runtime harness script + runbook:
  - `scripts/acheron-multi-node-runtime.sh`
  - `docs/MULTI_NODE_RUNTIME_HARNESS.md`

## Phase 7 - Node Service Event Stream + GUI Diagnostics

Status: completed

- Added control-channel node service subscription flow:
  - `control.node_service_watch`
  - `control.node_service_unwatch`
  - pushed `control.node_service_event` frames
- `control.node_service_upsert` now computes and returns `service_delta`:
  - `changed`
  - `timestamp_ms`
  - `added[]`, `updated[]`, `removed[]`
  - per-entry digest hash + version metadata
- Server now broadcasts node service events to active watchers (optional
  `node_id` filter).
- CLI now supports live watch mode:
  - `zss node watch [node_id]`
- GUI now handles `control.node_service_event` and surfaces the stream in Debug
  diagnostics, including explicit node-service watch status.
- Added/updated tests for:
  - service delta generation
  - node service watch push delivery
  - payload helper extraction/parsing

## Phase 8 - Scoped Watch Controls + Replay Persistence + Policy

Status: completed

- Server-side node service event stream now supports:
  - persisted history in `<ltm>/node-service-events.ndjson`
  - bounded in-memory replay ring for immediate watch replays
  - `replay_limit` request option on `control.node_service_watch`
- Watch delivery policy is now role and project aware:
  - role gates:
    - `SPIDERWEB_NODE_SERVICE_WATCH_ALLOW_ADMIN`
    - `SPIDERWEB_NODE_SERVICE_WATCH_ALLOW_USER`
  - per-user/project stream filtering based on mounted nodes and
    `access_policy.actions.observe`
- Added server-level helper/tests for:
  - watch request parsing
  - user visibility gating to mounted nodes
- GUI Debug panel now includes:
  - node watch filter input (`node_id`)
  - replay limit input
  - apply/unwatch controls
  - quick jump action to `/nodes/<node_id>/fs` from selected
    `control.node_service_event`

## Next Backlog

- Add CLI flags for `node watch` replay controls (`--replay-limit`) to match
  GUI/server capabilities.
- Add event-log rotation/retention controls for
  `node-service-events.ndjson` (parity with debug stream archive handling).
- Add project-scoped watch UX in GUI (explicit project override preview and
  policy explainers for denied streams).
