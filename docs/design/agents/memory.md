# Memory Model (Current)

Memory is managed by the runtime memory store and exposed via Acheron service paths.

## Access Paths

Use `/agents/self/memory` control files instead of calling `memory_*` tools directly:

- `/agents/self/memory/control/create.json`
- `/agents/self/memory/control/load.json`
- `/agents/self/memory/control/versions.json`
- `/agents/self/memory/control/mutate.json`
- `/agents/self/memory/control/evict.json`
- `/agents/self/memory/control/search.json`

Results and status:
- `/agents/self/memory/result.json`
- `/agents/self/memory/status.json`

## Seeded Runtime Memories

The runtime seeds system instructions and loop/tool contracts on boot (see `src/memory_schema.zig`). These include:

- `system.policy`
- `system.loop_contract`
- `system.tool_contract`
- `system.completion_contract`

## Implementation Pointers

- Memory schema + seeds: `src/memory_schema.zig`
- Memory store: `ziggy-memory-store`
- Acheron bridge: `src/fsrpc_session.zig`
