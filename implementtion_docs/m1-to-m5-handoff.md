# M1→M5 Handoff (Runtime Milestones)

## Current milestone status (repository snapshot)

- **M1 (RAM memory model)**: complete.
- **M2 (Long-term persistence)**: implemented with SQLite-first restore and legacy JSON fallback.
- **M3 (Identity layering)**: implemented and loaded on handshake.
- **M4 (Primary Brain planner loop)**: implemented end-to-end for goal-based flow.
- **M5 (Worker sub-brains)**: partial.

## What is implemented

### M1 / RAM (`src/memory.zig`)
- `MemoryID` typing and RAM mutation APIs.
- `LOAD`, `UPDATE`, `EVICT`, `SUMMARIZE` behavior with limits and tombstones.
- Thread-safe mutability model retained through the RAM context abstraction.

### M2 / LTM (`src/ltm_store.zig`, `src/server_piai.zig`, `build.zig`)
- SQLite persistence module in `src/ltm_store.zig` with archive/load/prune/migration helpers.
- Startup migration from `.spiderweb-ltm/archive-index.ndjson` into SQLite.
- Snapshot restore flow in `restoreSessionFromLatestArchive` favors DB first, then JSON.
- `memory.recall` and `memory.query` follow DB-first, JSON-fallback paths where implemented.
- Legacy `.spiderweb-ltm` archive index and snapshots are still preserved.

### M3 / Identity (`src/identity.zig`, `src/server_piai.zig`)
- `loadMergedPrompt` merges `SOUL.md`, `AGENT.md`, `IDENTITY.md`, `USER.md` with precedence `SOUL > AGENT > IDENTITY > USER`.
- Conflict headings are shadowed by higher-priority layers.
- Merged identity prompt is attached to each session on handshake and injected as system context for model calls.

### M4 / Primary Brain (`src/orchestrator.zig`, `src/protocol.zig`, `src/server_piai.zig`)
- `orchestrator.buildPlan` parses user goals into tasks and deterministic response text.
- Goal entry points:
  - `/goal <text>` in `chat.send` / `session.send`
  - `agent.control` with `goal` / `content`
- Planner path emits:
  - `agent.plan` event
  - `agent.progress` events (`planner.received`, `planner.ready`, worker delegation lifecycle)
- Plan summary is persisted into RAM as a `.system` memory entry for context continuity.

### M5 / Workers v1 (`src/workers.zig`, `src/server_piai.zig`, `src/protocol.zig`, `implementtion_docs`)
- Added `src/workers.zig` with:
  - deterministic task typing (`research`, `execution`, `status`)
  - bounded batching by configured parallelism
  - threaded worker execution over task slices
  - deterministic in-memory result struct
- `server_piai` now:
  - dispatches `orchestrator` plan tasks through workers
  - emits `agent.progress` updates for worker lifecycle
  - emits additive `agent.status` updates per worker completion
  - accepts `agent.control` with `action:"state"` and emits `agent.state` snapshots
- Protocol coverage:
  - `agent.status` added to `MessageType`
  - parse tests include `agent.status` round-trip case
  - `agent.state` now has parser and tests

## Known remaining holes

1. `agent.control` supports only state snapshot and goal-oriented controls; dedicated control command registry is still missing.
2. Worker behavior is deterministic/stubbed local text logic; it is not yet connected to any long-running tooling or stateful sub-brain side effects.
3. No dedicated queue/backpressure metrics or persistent worker session state yet (all worker outputs remain ephemeral).
4. Runtime tests for websocket load and saturation behavior remain open.
5. Protocol parser tests are now covering malformed envelopes; protocol-level builder/shape tests for `agent.status` and `agent.state` are still useful follow-ups.
6. `agent.state` shape is added but the full contract (expected worker/session lifecycle fields and semantics) is still to be finalized.

## Next milestone recommendations

1. Move M5 to "complete" by introducing structured worker task/results types and richer commands for worker lifecycle:
   - `/agent.control` subcommands
   - explicit `agent.state` snapshots
   - bounded queueing/metrics and saturation behavior
2. Keep `agent.status` semantics stable as additive telemetry while extending `agent.control` and `/goal` runtime tests.
3. Advance to M6:
   - Memory-manager worker that persists and summarizes RAM transitions into LTM.
4. Advance to M7:
   - Heartbeat worker with proactive suggestion behavior.
