# Brain Tools (Current)

Brain tools are internal runtime actions used by the agent execution loop. They are not exposed directly to providers in Acheron strict mode.

## Tool Set

Implemented brain tool schemas include:

- `memory_load`, `memory_versions`, `memory_search`, `memory_create`, `memory_mutate`, `memory_evict`
- `wait_for`
- `talk_user`, `talk_agent`, `talk_brain`, `talk_log`

These map to the runtime memory store and event bus.

## Provider Exposure

Provider tool schemas are intentionally restricted to `file_read`, `file_write`, and `file_list`. Brain tools remain internal and are surfaced via Acheron service paths (for example `/agents/self/memory`).

## Implementation Pointers

- Brain tool schemas and execution: `src/brain_tools.zig`
- Memory store: `ziggy-memory-store`
- Event bus: `ziggy-runtime-hooks`
