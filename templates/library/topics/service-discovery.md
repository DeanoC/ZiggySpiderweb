# Service Discovery

Start at:

- `/agents/self/services/SERVICES.json`

Each entry provides:

- `node_id`
- `service_id`
- `service_path`
- `invoke_path`
- `has_invoke`
- `scope` (`node` | `agent_namespace` | `global_namespace`)

Scope guidance:

- `agent_namespace`: agent-local services under `/agents/self/*`
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

1. Read `/agents/self/services/SERVICES.json`.
2. Select `{"service_id":"terminal","invoke_path":"/agents/self/terminal/control/invoke.json"}`.
3. Read `/agents/self/terminal/SCHEMA.json`.
4. Write:
   - path: `/agents/self/terminal/control/invoke.json`
   - payload: `{"op":"exec","arguments":{"command":"pwd"}}`
5. Read:
   - `/agents/self/terminal/status.json`
   - `/agents/self/terminal/result.json`

Quick roots:

- `/agents/self/memory`
- `/agents/self/web_search`
- `/agents/self/search_code`
- `/agents/self/terminal`
- `/agents/self/mounts`
- `/agents/self/sub_brains`
- `/agents/self/agents`
- `/global/library`
