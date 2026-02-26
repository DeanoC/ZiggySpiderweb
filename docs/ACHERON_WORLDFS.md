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
│       │       └── CAPS.json
│       └── README.md
├── agents/
│   └── self/
├── projects/
│   └── <project_id>/
├── meta/
└── debug/            # policy-gated
```

Major directories include:

- `README.md` (human + agent instructions)
- `SCHEMA.json` (shape contract)
- `CAPS.json` (capability contract)

Node-level service capability metadata is managed via control-plane service catalog
operations and rendered into `/nodes/<node_id>/services/*`.

## Chat and Jobs

- Chat input path: `/agents/self/chat/control/input`
- Job status path: `/agents/self/jobs/<job_id>/status.json`
- Job result path: `/agents/self/jobs/<job_id>/result.txt`

`acheron.t_write` responses for chat include:

- `job`
- `result_path` (now `/agents/self/jobs/<job>/result.txt`)

## Project View

Project links are exposed under:

- `/projects/<project_id>/fs/`
- `/projects/<project_id>/agents/`

`/projects/<project_id>/fs/<name>` entries are logical link files with target paths like:

`/nodes/<node_id>/<resource>`

Workspace status payloads include mount auth token redaction by role:

- non-primary agents: `"fs_auth_token": null`
- primary/system (`mother`) agent: token included

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
