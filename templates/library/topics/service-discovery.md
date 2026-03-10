# Venom Discovery

Start at:

- `/global/venoms/VENOMS.json`

Each entry provides:

- `node_id`
- `venom_id`
- `venom_path`
- `invoke_path`
- `has_invoke`
- `scope` (`node` | `project_namespace` | `global_namespace`)

Scope guidance:

- `project_namespace`: project-shared services under `/global/*`
- `node`: node/device Venoms under `/nodes/<node_id>/venoms/*`
- `global_namespace`: shared global resources under `/global/*`

Contract check workflow:

1. Read `VENOMS.json`.
2. Select a candidate Venom entry.
3. Read contract files under `venom_path`:
   - `README.md`
   - `SCHEMA.json`
   - `CAPS.json`
   - `OPS.json`
   - `PERMISSIONS.json`
   - optional: `RUNTIME.json`, `MOUNTS.json`, `STATUS.json`
4. If `has_invoke=true`, write to `invoke_path`.
5. Read Venom `status.json` and `result.json`.

Example: invoke terminal

1. Read `/global/venoms/VENOMS.json`.
2. Select `{"venom_id":"terminal","invoke_path":"/global/terminal/control/invoke.json"}`.
3. Read `/global/terminal/SCHEMA.json`.
4. Write:
   - path: `/global/terminal/control/invoke.json`
   - payload: `{"op":"exec","arguments":{"command":"pwd"}}`
5. Read:
   - `/global/terminal/status.json`
   - `/global/terminal/result.json`

Quick roots:

- `/global/memory`
- `/global/web_search`
- `/global/search_code`
- `/global/terminal`
- `/global/mounts`
- `/global/sub_brains`
- `/global/agents`
- `/global/workspaces`
- `/global/library`

Node-scoped discovery root:

- `/nodes/<node_id>/venoms/<venom_id>`
