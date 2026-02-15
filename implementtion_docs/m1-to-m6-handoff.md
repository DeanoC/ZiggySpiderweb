# M1→M6 Handoff (Runtime Milestones)

## Current milestone status (repository snapshot)

- **M1 (RAM memory model)**: complete.
- **M2 (Long-term persistence)**: implemented with SQLite-first restore and legacy JSON fallback.
- **M3 (Identity layering)**: implemented and loaded on handshake.
- **M4 (Primary Brain planner loop)**: implemented end-to-end for goal-based flow.
- **M5 (Worker sub-brains)**: complete for deterministic local worker execution and control-state telemetry.
- **M6 (Memory manager worker)**: implemented with bounded RAM compacting + snapshot events.
- **M7 (Heartbeat worker v1)**: scaffolded as periodic backlog heartbeat checks and manual heartbeat control action.

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
  - supports `agent.control` actions `pause`, `resume`, `cancel` and tracks session worker mode

### M6 / Memory manager worker (`src/server_piai.zig`, `src/protocol.zig`)
- Added passive runtime compacting helper in message path:
  - threshold-based `runMemoryManager(...)` helper invoked after each message append
  - bounded summarization per message tick (`MEMORY_MANAGER_SUMMARIES_PER_TICK`)
  - optional snapshot persistence into LTM when `state.ltm_store` is configured
- Added `memory.event` protocol message support for memory-worker telemetry
- Added runtime tests for `sendMemoryEvent` and `runMemoryManager` behavior
- Protocol coverage:
  - `agent.status` added to `MessageType`
  - `agent.heartbeat` added to `MessageType`
  - parse tests include `agent.status` round-trip case
  - parse tests include `agent.state` and `agent.heartbeat`

## Known remaining holes

1. Worker behavior is deterministic/stubbed local text logic; it is not yet connected to any long-running tooling or stateful sub-brain side effects.
2. Full queue/backpressure policy (saturation, dropped work, queued deadlines) is still missing.
3. Runtime tests for websocket load and sustained saturation remain open.
4. Memory-manager scheduling is still coarse and only runs opportunistically during inbound messages.
5. `agent.state` contract is still evolving for future worker lifecycle states (`blocked`, `heartbeat`, etc.).
6. `memory.event` contract is intentionally minimal and should be expanded for richer memory-manager diagnostics.
7. `agent.heartbeat` is currently backlog-aware and piggybacks on inbound traffic / explicit calls; there is no dedicated background heartbeat timer loop yet.

## Next milestone recommendations

1. Move M6 to "complete" by stabilizing snapshot policy and memory-manager scheduling.
   - tune summary trigger/snapshot policy for stable context retention
   - broaden `memory.event` payloads for observability
   - bounded queueing/metrics and saturation behavior
2. Keep `agent.status` semantics stable as additive telemetry while extending `agent.control`, `/goal`, and heartbeat runtime tests.
3. Advance M7:
   - Heartbeat worker with proactive suggestion behavior.
   - add a true interval-based background loop with low-cost scheduling
   - add user-facing suggestion payloads under `agent.heartbeat` and `agent.state`
