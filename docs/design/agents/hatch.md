# Agent Hatching (Current)

An agent is considered “unhatched” when `HATCH.md` exists in its directory. The registry reports this as `needs_hatching` in `control.agent_list` / `control.agent_get`.

Typical hatching flow:

1. Create agent directory (via `/agents/self/agents/control/create.json`).
2. Populate identity files and `agent.json`.
3. Remove or replace `HATCH.md` once the agent is ready.

Implementation pointers:
- `src/agent_registry.zig`
- `src/fsrpc_session.zig`
