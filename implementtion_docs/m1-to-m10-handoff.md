# M1→M10 Handoff (Runtime Milestones)

## Current milestone status (repository snapshot)

- **M1 (RAM memory model)**: complete.
- **M2 (Long-term persistence)**: implemented with SQLite-first restore and legacy JSON fallback.
- **M3 (Identity layering)**: implemented and loaded on handshake.
- **M4 (Primary Brain planner loop)**: implemented end-to-end for goal-based flow.
- **M5 (Worker sub-brains)**: complete for deterministic local worker execution and control-state telemetry.
- **M6 (Memory manager worker)**: implemented with bounded RAM compacting + snapshot events.
- **M7 (Heartbeat worker v1)**: implemented with interval-based websocket session sweep + manual heartbeat control action.
- **M8 (Protocol-flow harness)**: expanded end-to-end mock-backed websocket chat validation.
  - includes reconnect restore from persisted in-memory sessions and long-term snapshot store.
- **M9 (Queue discipline & saturation)**: added worker admission cap with dropped-task telemetry in plan dispatch.
- **M10 (Reconnect-aware saturation telemetry)**: implemented resume-aware session persistence and prolonged backpressure signaling.

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

### M7 / Heartbeat worker (`src/server_piai.zig`, `src/protocol.zig`)
- Added heartbeat scheduler context to session state:
  - `SessionContext.last_heartbeat_ms` and background `HEARTBEAT_SWEEP_INTERVAL_MS` polling cadence
- Extended `EventLoop.wait` to accept timeout and implemented `runHeartbeatSweep` over active websocket sessions
- Added timed sweep loop in server `run()` so heartbeat progresses emit even without inbound traffic
- Heartbeat progress remains on `agent.progress` phase `heartbeat` with statuses `watching` / `blocked`
- Added tests validating heartbeat sweep behavior (`runHeartbeatSweep`)

### M8 / Protocol-flow harness (`src/server_piai.zig`)
- Added test for websocket-style handshake + `chat.send` flow using mocked provider callback.
- Verifies `session.ack` frame and outbound `session.receive` from mocked stream on the same connection path.
- Added handshake-restoration test verifying persisted session context is recovered by session key.
- Added handshake reconnect test that restores session context from a long-term snapshot.
- Added provider-stream error mock test asserting `error` payload is emitted on stream failure.

### M9 / Saturation and backpressure (`src/server_piai.zig`)
- Added `WORKER_MAX_TASKS_PER_DISPATCH` cap for worker dispatch admission.
- Added planner saturation progress telemetry when a plan exceeds dispatch cap (`status: "saturated"`).
- Added test coverage for worker admission cap and reduced dispatched worker status count on saturation.

### M10 / Reconnect-aware saturation (`src/server_piai.zig`)
- Extended persisted session state (`SESSION_STATE_VERSION=2`) with worker context:
  - queue depth, active tasks, worker mode
  - dropped-task count, saturation timestamp
  - backpressure-notified flag, last goal snapshot
- Persisted restore path now rehydrates worker backpressure context and last goal:
  - handshake sends reconnect progress (`phase: "reconnect"`) with `status: "state_restored"` or `"backpressure_resumed"`
  - zero-backlog sessions restore from in-memory snapshot only; sessions with backlog resume with telemetry.
- Added long-running saturation path in heartbeat loop:
  - after `WORKER_BACKPRESSURE_WARNING_MS`, emits `agent.progress` with `phase: "planner"` and `status: "prolonged_saturation"`.
- Added `sendAgentProgressWithBackpressure(...)` for compact metric payload (`accepted`, `total`, `dropped`, `queued`, `active`).
- Updated test coverage:
  - admission saturation event verifies backpressure metrics are included.
  - handshake reconnect tests verify `reconnect` progress for restored state and backlog resume.
  - heartbeat prolonged saturation test verifies delayed escalated progress emission.

## Known remaining holes

1. Worker behavior is deterministic/stubbed local text logic; it is not yet connected to any long-running tooling or stateful sub-brain side effects.
2. Runtime tests for websocket load and sustained saturation remain open.
3. Memory-manager scheduling is still coarse and only runs opportunistically during inbound messages.
4. `memory.event` contract is intentionally minimal and should be expanded for richer memory-manager diagnostics.
5. Heartbeat suggestions currently stay telemetry-only and do not include explicit escalation or action-recommendation payloads.
6. Heartbeat failure-mode recommendations are still advisory only (telemetry without explicit suggestion payloads).

## Next milestone recommendations

1. Tighten protocol contract for backpressure fields in `agent.progress` payload (`accepted`, `total`, `dropped`, `queued`, `active`) with explicit schema docs.
2. Add reconnect test coverage for bursty, sustained saturation under mixed pause/cancel modes.
3. Add explicit operator action to clear worker-saturation state for a "fresh RAM" recovery path while preserving persisted RAM history in LTM.
4. Expand load/perf coverage for prolonged saturation events under concurrent websocket sessions.
