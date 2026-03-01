# Service Inventory and Usage Model (Current)

This document summarizes the services that are currently implemented and how agents should discover and invoke them via Acheron WorldFS.

## Discovery Order

1. `/agents/self/services/SERVICES.json` (agent namespace index)
2. `/nodes/<node_id>/services/SERVICES.json` (node-scoped catalog, if advertised)
3. Inspect service contract files before invoking:
   - `README.md`, `SCHEMA.json`, `TEMPLATE.json`, `CAPS.json`, `OPS.json`, `PERMISSIONS.json`, `STATUS.json`

## Agent Namespace Services (Implemented)

These services are implemented by Spiderweb itself under `/agents/self`:

- `chat` (input under `/agents/self/chat/control/input`)
- `jobs` (status/result under `/agents/self/jobs/<job_id>/*`)
- `events` (wait/next under `/agents/self/events/*`)
- `memory` (control + result/status)
- `web_search` (control + result/status)
- `search_code` (control + result/status)
- `terminal` (terminal-v2 session model)
- `mounts` (project mounts/binds + local workspace folder create)
- `sub_brains` (sub-brain list/upsert/delete)
- `agents` (agent list/create)

Each service exposes `control/*.json` endpoints plus `status.json` and `result.json` for invocation results.

## Node Services (Catalog-Driven)

Node services are advertised through the control-plane catalog (`control.node_service_*`) and projected into:

- `/nodes/<node_id>/services/<service_id>`
- `/nodes/<node_id>/<resource>` (compat view derived from service mounts)

If a node advertises an empty service list, no fallback resources are exposed for that node.

## Invoke Contract

1. Read `OPS.json` for the `invoke` target (or `paths.invoke`).
2. If needed, seed a payload from `TEMPLATE.json`.
3. Write the payload to the invoke path.
4. Read `status.json` and `result.json` until completion.

Event waits can be driven through `/agents/self/events/control/wait.json` + `/agents/self/events/next.json`.

## Implementation Pointers

- WorldFS and service projection: `src/fsrpc_session.zig`
- Node service catalog: `src/node_service_catalog.zig`, `src/fs_node_service.zig`
- Project policy gating: `src/fs_control_plane.zig`, `src/server_piai.zig`
