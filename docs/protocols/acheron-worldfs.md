# Acheron WorldFS

Acheron WorldFS is the agent-visible filesystem exposed over the `acheron-1` protocol. The layout below reflects the current runtime implementation.

## Root Layout

```
/
├── agents/
│   └── self/
│       ├── chat/
│       │   ├── control/input
│       │   └── meta.json
│       ├── jobs/<job_id>/{status.json,result.txt}
│       ├── events/{control/wait.json,next.json,sources/*}
│       ├── memory/...
│       ├── web_search/...
│       ├── search_code/...
│       ├── terminal/...
│       ├── mounts/...
│       ├── sub_brains/...
│       ├── agents/...
│       └── services/SERVICES.json
├── nodes/
│   └── <node_id>/
│       ├── services/<service_id>/...
│       └── <resource_roots...>
├── projects/
│   └── <project_id>/{fs,nodes,agents,meta}
├── meta/
│   ├── protocol.json
│   ├── view.json
│   ├── workspace_status.json
│   ├── workspace_availability.json
│   ├── workspace_health.json
│   └── workspace_alerts.json
└── debug/ (only when enabled by policy)
```

`protocol.json` records `acheron-1` and the `world-v1` layout.

## Agent Namespace Services

Service discovery starts at:

- `/agents/self/services/SERVICES.json`

Each service directory contains a contract set (`README.md`, `SCHEMA.json`, `CAPS.json`, `OPS.json`, `PERMISSIONS.json`, `STATUS.json`) plus `control/*.json`, `status.json`, and `result.json` for invocation.

Implemented services:
- `memory`
- `web_search`
- `search_code`
- `terminal` (terminal-v2)
- `mounts`
- `sub_brains`
- `agents`

## Jobs and Events

- Chat input path: `/agents/self/chat/control/input`
- Job status path: `/agents/self/jobs/<job_id>/status.json`
- Job result path: `/agents/self/jobs/<job_id>/result.txt`

Event wait flow:

1. Write a selector to `/agents/self/events/control/wait.json`.
2. Read `/agents/self/events/next.json` for the next matching event.

Supported event sources include:
- `/agents/self/chat/control/input`
- `/agents/self/jobs/<job_id>/status.json`
- `/agents/self/events/sources/time/after/<ms>.json`
- `/agents/self/events/sources/time/at/<unix_ms>.json`
- `/agents/self/events/sources/agent/<parameter>.json`
- `/agents/self/events/sources/hook/<parameter>.json`
- `/agents/self/events/sources/user/<parameter>.json`

## Node Services

Node services are projected from the control-plane catalog into:

- `/nodes/<node_id>/services/<service_id>`
- `/nodes/<node_id>/<resource>` (compat view derived from service mounts)

If a node advertises an explicit empty catalog, no fallback resources are exposed for that node.

## Project View

Project links under `/projects/<project_id>` expose:

- `fs/` (links to mount paths)
- `nodes/` (links to `/nodes/<node_id>`)
- `agents/` (links to `/agents/<agent_id>`)
- `meta/` (project topology, mounts, availability, drift, and reconcile state)

## Debug Pairing

When debug is enabled by policy (typically for `mother`), `/debug/` exposes pairing queue controls and invite workflows.

## Implementation Pointers

- WorldFS session: `src/fsrpc_session.zig`
- Policy defaults: `src/world_policy.zig`
- Control-plane topology: `src/fs_control_plane.zig`
