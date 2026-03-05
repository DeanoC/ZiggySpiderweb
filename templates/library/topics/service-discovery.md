# Service Discovery

Start at:

- `/global/services/SERVICES.json`

Each entry provides:

- `node_id`
- `service_id`
- `service_path`
- `invoke_path`
- `has_invoke`
- `scope` (`node` | `agent_namespace` | `global_namespace`)

Scope guidance:

- `agent_namespace`: agent-local services under `/global/*`
- `node`: node/device services under `/nodes/<node_id>/services/*`
- `global_namespace`: shared global resources under `/global/*`

Contract check workflow:

1. Read `SERVICES.json`.
2. Select a candidate service entry.
3. Read contract files under `service_path`:
   - `README.md`
   - `SCHEMA.json`
   - `CAPS.json`
   - `OPS.json`
   - `PERMISSIONS.json`
   - optional: `RUNTIME.json`, `MOUNTS.json`, `STATUS.json`
4. If `has_invoke=true`, write to `invoke_path`.
5. Read service `status.json` and `result.json`.

Example: invoke terminal

1. Read `/global/services/SERVICES.json`.
2. Select `{"service_id":"terminal","invoke_path":"/global/terminal/control/invoke.json"}`.
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
- `/global/projects`
- `/global/library`
