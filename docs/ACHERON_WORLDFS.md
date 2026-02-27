# Acheron WorldFS

This document defines the agent-visible runtime namespace for Acheron sessions.

## Root Layout

```
/
├── nodes/
│   └── <node_id>/
│       ├── services/
│       │   └── <service_id>/
│       │       ├── SCHEMA.json
│       │       ├── STATUS.json
│       │       ├── CAPS.json
│       │       ├── MOUNTS.json
│       │       ├── OPS.json
│       │       ├── RUNTIME.json
│       │       ├── PERMISSIONS.json
│       │       └── README.md
│       ├── <dynamic_mount_roots...>
│       └── README.md
├── agents/
│   └── self/
│       ├── chat/
│       ├── jobs/
│       ├── events/
│       ├── memory/
│       └── services/
│           ├── SERVICES.json
│           └── contracts/
│               ├── memory/
│               └── web_search/
├── projects/
│   └── <project_id>/
├── meta/
└── debug/            # policy-gated
    └── pairing/
```

Major directories include:

- `README.md` (human + agent instructions)
- `SCHEMA.json` (shape contract)
- `CAPS.json` (capability contract)

Node-level service capability metadata is managed via control-plane service catalog
operations and rendered into `/nodes/<node_id>/services/*`.

Current runtime behavior prefers `control.node_service_get` catalog data when available,
and falls back to policy node resources (`fs`, `camera`, `screen`, `user`, `terminal-*`)
for `/nodes/<node_id>/services/*`, with per-service `SCHEMA.json`, `CAPS.json`,
and `STATUS.json`.
`/nodes/<node_id>/services/SERVICES.json` provides a flat service index.

Node resource roots (`/nodes/<node_id>/fs`, `camera`, `screen`, `user`, `terminal/*`,
and custom roots like `drive/*`)
follow the same service view:
- when service catalog is available, roots are derived from service `mount_path`
  metadata (with kind-based compatibility behavior for legacy services)
- otherwise roots are derived from policy fallback resources
Node-level `CAPS.json` uses the same effective service view.
If a node advertises an explicit empty service catalog, runtime exposes no fallback
policy roots for that node.
For non-admin sessions, service visibility is filtered by each service
`PERMISSIONS.json` policy (`allow_roles`, `default`, and token requirements).
Admin sessions bypass this filter.

For phase tracking and backlog, see `docs/NODE_NAMESPACE_EXTENSION_PHASES.md`.

When project workspace mounts reference nodes not present in policy, runtime creates
discovered `/nodes/<node_id>` entries so project FS links always resolve.

Node directories also expose:

- `STATUS.json` (node-level availability/status)
- `NODE.json` (raw `control.get_node` payload when available)

## Chat and Jobs

- Service discovery index path: `/agents/self/services/SERVICES.json`
- Chat input path: `/agents/self/chat/control/input`
- Job status path: `/agents/self/jobs/<job_id>/status.json`
- Job result path: `/agents/self/jobs/<job_id>/result.txt`
- Event wait config path: `/agents/self/events/control/wait.json`
- Event wait next path: `/agents/self/events/next.json`
- First-class memory service path: `/agents/self/memory`
- First-class web search service path: `/agents/self/web_search`

`/agents/self/services/SERVICES.json` entries include:

- `node_id`
- `service_id`
- `service_path`
- `invoke_path`
- `has_invoke`
- `scope` (`node`, `agent_contract`, or `agent_namespace`)

Use `service_path` to inspect each service descriptor (`SCHEMA.json`, `CAPS.json`,
`MOUNTS.json`, `OPS.json`, `PERMISSIONS.json`, `README.md`).
Use `invoke_path` only when `has_invoke` is true.
For node services with `CAPS.invoke=true`, runtime now derives `invoke_path` from
mounted service roots (for example `/nodes/<node>/tool/main/control/invoke.json`)
instead of metadata-only paths.

`/agents/self/services/contracts/` currently seeds baseline contracts for:

- `memory`
- `web_search`

Contract service invoke flow:

1. Write invoke payload JSON to:
   - `/agents/self/services/contracts/<service_id>/control/invoke.json`
2. Read runtime status:
   - `/agents/self/services/contracts/<service_id>/status.json`
3. Read tool result payload:
   - `/agents/self/services/contracts/<service_id>/result.json`

Invoke payload shape:
`{"tool_name":"memory_create","arguments":{...}}`
(`tool` and `args` aliases are also accepted.)

First-class memory namespace flow:

1. Write operation payload JSON to one of:
   - `/agents/self/memory/control/create.json`
   - `/agents/self/memory/control/load.json`
   - `/agents/self/memory/control/versions.json`
   - `/agents/self/memory/control/mutate.json`
   - `/agents/self/memory/control/evict.json`
   - `/agents/self/memory/control/search.json`
   - `/agents/self/memory/control/invoke.json` (generic tool call envelope)
2. Read runtime status:
   - `/agents/self/memory/status.json`
3. Read tool result payload:
   - `/agents/self/memory/result.json`

First-class web search namespace flow:

1. Write search payload JSON to one of:
   - `/agents/self/web_search/control/search.json`
   - `/agents/self/web_search/control/invoke.json` (generic tool call envelope)
2. Read runtime status:
   - `/agents/self/web_search/status.json`
3. Read tool result payload:
   - `/agents/self/web_search/result.json`

`acheron.t_write` responses for chat include:

- `job`
- `result_path` (now `/agents/self/jobs/<job>/result.txt`)

Event wait flow:

1. Write selector JSON to `/agents/self/events/control/wait.json`:
   `{"paths":["/agents/self/chat/control/input"],"timeout_ms":60000}`
2. Read `/agents/self/events/next.json` to block until the first matching event.

Single-event waits may also use a direct blocking read on that endpoint when
the endpoint supports blocking behavior.
Current implementation supports blocking reads on:
- `/agents/self/jobs/<job_id>/status.json`
- `/agents/self/jobs/<job_id>/result.txt`

## Debug Pairing Queue

When debug is enabled (typically `mother`), WorldFS exposes manual node pairing controls:

- `/debug/pairing/pending.json` (snapshot of `control.node_join_pending_list`)
- `/debug/pairing/last_result.json` (last approve/deny/refresh result envelope)
- `/debug/pairing/last_error.json` (last error envelope or `null`)
- `/debug/pairing/control/approve.json` (writable, payload for `control.node_join_approve`)
- `/debug/pairing/control/deny.json` (writable, payload for `control.node_join_deny`)
- `/debug/pairing/control/refresh` (writable trigger to refresh queue snapshot)
- `/debug/pairing/invites/active.json` (snapshot of active invite tokens from `control.node_invite_create` state)
- `/debug/pairing/invites/last_result.json` (last invite create/refresh result envelope)
- `/debug/pairing/invites/last_error.json` (last invite action error envelope or `null`)
- `/debug/pairing/invites/control/create.json` (writable, payload for `control.node_invite_create`)
- `/debug/pairing/invites/control/refresh` (writable trigger to refresh invite snapshot)

Writing to queue and invite control files updates snapshot/result/error files so an
operator agent can complete both manual-approval and invite-token pairing workflows
entirely through filesystem operations.

## Project View

Project links are exposed under:

- `/projects/<project_id>/fs/`
- `/projects/<project_id>/nodes/`
- `/projects/<project_id>/agents/`
- `/projects/<project_id>/meta/`

Each of these project subdirectories is self-describing with `README.md`,
`SCHEMA.json`, and `CAPS.json`.

`/projects/<project_id>/fs/<name>` entries are logical link files with target paths like:

`/nodes/<node_id>/<resource>`

`/projects/<project_id>/nodes/<node_id>` entries are logical link files with targets:

`/nodes/<node_id>`

Current runtime behavior prefers live `control.workspace_status` selected mounts for
project FS links, using names derived from mount paths:

- `/src` -> `mount::src`
- `/docs/api` -> `mount::docs::api`
- `/` -> `mount::root`

When workspace status is unavailable, project FS links fall back to policy
`project_links`.

Workspace status payloads include mount auth token redaction by role:

- non-primary agents: `"fs_auth_token": null`
- primary/system (`mother`) agent: token included

Project metadata now includes:

- `topology.json` (policy-derived node + link view)
- `nodes.json` (project node membership summary with per-node selected-mount state and count)
- `agents.json` (project-visible agents and their `/agents/*` link targets)
- `sources.json` (provenance for project FS/nodes/meta views: control-plane workspace vs policy fallback)
- `contracts.json` (stable project-view contract index for directories, metadata files, and link semantics)
- `paths.json` (canonical project and global path entrypoints for agent path resolution)
- `summary.json` (single-file project rollup: sources, key counts, and workspace health state)
- `alerts.json` (derived risk signals from availability, drift, and reconcile queue/state)
- `workspace_status.json` (live `control.workspace_status` when available)
- `mounts.json` (selected mount entries from workspace status `mounts`)
- `desired_mounts.json` (desired mount set from workspace status `desired_mounts`)
- `actual_mounts.json` (resolved/selected mount set from workspace status `actual_mounts`)
- `drift.json` (workspace drift summary from workspace status `drift`)
- `reconcile.json` (workspace reconcile health from `reconcile_state`, timestamps, `last_error`, and `queue_depth`)
- `availability.json` (extracted workspace availability rollup)
- `health.json` (single-file health summary combining availability, drift count, and reconcile state)

Runtime uses project token (when bound) for workspace status lookup and falls back
to policy-derived placeholder status if control-plane status is unavailable.
Fallback control-plane status is accepted only when `project_id` matches the
requested project to avoid cross-project topology leakage.

## Policy Files

Policy is compiled from optional JSON manifests:

- `agents/<agent_id>/agent_policy.json`
- `projects/<project_id>/project_policy.json`

Supported fields:

- `show_debug` (`bool`)
- `project_id` (`string`)
- `nodes` (`array`)
- `visible_agents` (`array<string>`)
- `project_links` (`array`)

Node entry:

```json
{
  "id": "local",
  "resources": { "fs": true, "camera": false, "screen": false, "user": false },
  "terminals": ["1", "2"]
}
```

Project link entry:

```json
{
  "name": "local::fs",
  "node_id": "local",
  "resource": "fs"
}
```

Defaults if files are missing:

- `project_id = "system"` (or active bound project)
- one `local` node with `fs` + terminal `1`
- `visible_agents` includes current agent
- `project_links` derived from `node::fs`
- `show_debug = true` for `mother`, otherwise `false`
