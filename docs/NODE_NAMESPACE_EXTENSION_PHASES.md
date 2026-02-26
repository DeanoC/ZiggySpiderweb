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

## Phase 3 - Namespace Driver Runtime Scaffolding

Status: completed (scaffold)

- Added `namespace_driver` contract (`ServiceDescriptor`, mounts, runtime type,
  driver vtable, health shape).
- Added `service_runtime_manager` registry with duplicate protection and
  lifecycle hooks (`register`, `startAll`, `stopAll`).
- Current use is scaffolding for incremental driver/runtime activation.

## Phase 4 - Plugin Runtime Loader Scaffolding

Status: completed (scaffold + validation)

- Added loader modules:
  - `plugin_loader_native`
  - `plugin_loader_process`
  - `plugin_loader_wasm`
- Loader modules now validate/capture runtime config and are invoked by
  manifest runtime validation.
- Runtime validator currently accepts declarative metadata with optional loader
  paths and rejects unknown runtime types.

## Phase 5 - WorldFS Projection + Discoverability

Status: completed

- `/nodes/<id>/services/<service_id>/` now includes:
  - `SCHEMA.json`
  - `STATUS.json`
  - `CAPS.json`
  - `MOUNTS.json`
  - `OPS.json`
  - `RUNTIME.json`
  - `PERMISSIONS.json`
  - `README.md` (uses `help_md` when provided)
- Node root mount directories are now derived from service mount metadata
  (`mount_path`) in addition to legacy kind-based roots.
- Tests cover custom mount roots and metadata projection.

## Phase 2+ Backlog (Next)

- Bind manifest services to live runtime drivers (not just metadata publish).
- Add runtime transport contract for namespace driver I/O over control tunnel.
- Implement wasm host bridge and native plugin ABI loading.
- Add service health probes and per-service state transitions.
- Add hot-reload for manifest/runtime changes without full node restart.
- Add policy-enforced service capability filtering per project/agent.
