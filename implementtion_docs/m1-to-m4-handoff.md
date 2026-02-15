# M1→M4 Handoff (Runtime Milestones)

## Current milestone status (repository snapshot)

- **M1 (RAM memory model)**: complete.
- **M2 (Long-term persistence)**: implemented with SQLite-first restore and legacy JSON fallback.
- **M3 (Identity layering)**: implemented and loaded on handshake.
- **M4 (Primary Brain planner loop)**: implemented end-to-end for goal-based flow.
- **M5 (Worker sub-brains)**: not started.

## What was implemented

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
  - `agent.progress` events (`planner.received`, `planner.ready`, execution start/done/failed)
- Planner summary is persisted into RAM as a `.system` memory entry for context continuity.

## Known remaining holes

1. `agent.status` is parsed in protocol enum but has no dedicated server action yet.
2. Runtime tests for M3/M4 message flows are still missing (especially `/goal` and `agent.control` handling).
3. M2 restore/query is still primarily latest-snapshot oriented and does not perform deep historical scans yet.
4. `agent.control` still uses a minimal command path until workers/sub-brains are introduced.

## Recommended M5 start point

1. Introduce deterministic worker queue abstraction and bound concurrency.
2. Add `ResearchWorker`, `ExecutionWorker`, `StatusWorker` with explicit task payload/result structures.
3. Add `agent.status` and richer `agent.control` commands once worker execution contracts are in place.
4. Extend recall/query APIs for historical snapshot scans before only-latest semantics.
