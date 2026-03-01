# Agent Design (Current)

Agents are defined by directories under `agents/` and loaded by the runtime registry at startup or on demand.

## Identity Layers

Identity prompts are composed from layered files (in order):

- `SOUL.md`
- `AGENT.md`
- `IDENTITY.md`
- `USER.md`

Only the first occurrence of a heading is kept across layers; later duplicates are skipped to avoid conflicts.

If no identity files exist, a fallback prompt is used.

## `agent.json`

If present, `agent.json` supplies structured metadata (name, description, capabilities, default flag). If missing, metadata is inferred from identity files.

## Registry & Discovery

The agent registry:

- scans `agents/<agent_id>/` directories
- tracks `identity_loaded` and `needs_hatching`
- exposes `control.agent_list` / `control.agent_get`

## Hatching

If `HATCH.md` exists, the agent is considered unhatched and may require bootstrap steps.

## Implementation Pointers

- Registry: `src/agent_registry.zig`
- Identity loader: `src/identity.zig`
- Control responses: `src/server_piai.zig`
