# Node Namespace Status (Current)

This document replaces the older phase plan with the features that are actually implemented today in Spiderweb.

## Implemented Capabilities

- **Service catalog projection**
  - Control-plane service metadata is projected into `/nodes/<node_id>/services/*`.
  - Service descriptors include `mounts`, `ops`, `runtime`, `permissions`, `schema`, and optional `help_md`.

- **Service manifest support (node side)**
  - Node runtimes can publish service manifests and have them upserted into the catalog.

- **Permission filtering**
  - Non-admin sessions only see node services allowed by `PERMISSIONS.json`.
  - Admin sessions bypass service visibility filtering.

- **Invoke-aware mount gating**
  - Workspace mounts derived from invoke-capable services are omitted when policy disallows `invoke`.

- **Node service watch**
  - `control.node_service_watch` + `control.node_service_event` for live catalog updates.
  - Optional replay and on-disk event history via `node-service-events.ndjson`.

## Non-Goals (Not Implemented Here)

The following are outside this repo’s scope or not implemented in Spiderweb itself:

- GUI-specific watch tooling
- Client CLI commands
- Node runtime supervision UX

## Implementation Pointers

- Control catalog + projection: `src/node_service_catalog.zig`, `src/fsrpc_session.zig`
- Control operations: `src/server_piai.zig`
- Node service events: `src/server_piai.zig`
