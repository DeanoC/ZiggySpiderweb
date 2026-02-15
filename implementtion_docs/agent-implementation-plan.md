# Iterative Implementation Plan: Agent Runtime from Context Chat to PM/Workers v1

## Summary
Build the agent system in small, low-risk milestones, starting from current behavior (single chat connection with in-memory `conn.messages`) and progressively adding:
1. structured session memory,
2. persistent long-term memory,
3. identity layering (`SOUL.md`, `AGENT.md`, `IDENTITY.md`, `USER.md`),
4. a Primary Brain planner loop,
5. deterministic worker sub-brains,
6. memory-manager and heartbeat workers.

No backwards-compatibility is required or recommended for this roadmap.

## Scope, Constraints, and Defaults
- In scope: `MemoryID` model, memory persistence, identity loading, orchestrator + workers v1, proactive heartbeat v1.
- Out of scope for this roadmap: virtual filesystem/FUSE and multi-node storage.
- Chosen defaults:
  - LTM backend: SQLite + JSON summaries.
  - Orchestration: Primary-brain first; workers deterministic/local in v1.
  - Protocol strategy: non-breaking additive messages and capability flags.
  - Horizon: through Memory + PM/Workers v1.

## Public Interfaces and Types to Add
1. WebSocket capability negotiation (additive):
   - `{"type":"session.ack","capabilities":[...]}`
2. New additive inbound message types:
   - `memory.query`, `memory.recall`, `agent.status`, `agent.control`
3. New additive outbound message types:
   - `memory.event`, `agent.plan`, `agent.progress`, `agent.blocked`
4. Core internal Zig modules:
   - `src/memory.zig`: `MemoryID`, `RamEntry`, `SummaryEntry`, `LtmRecord`
   - `src/identity.zig`: merged identity config with precedence rules
   - `src/orchestrator.zig`: Primary Brain planning/execution loop
   - `src/workers/*.zig`: `memory_manager`, `heartbeat`, task workers
   - `src/session_store.zig`: chat/session lifecycle abstraction

## Milestone Plan

### M0: Baseline Hardening
- Refactor current `conn.messages` usage into a `SessionContext` abstraction.
- Add explicit message size/turn-count limits for active context.
- Emit request/session IDs in logs for traceability.
- Exit criteria: existing chat behavior hardened; tracing enabled.

### M1: RAM Memory Model v1
- Introduce `MemoryID` for each context item.
- Support RAM ops internally: `LOAD`, `UPDATE`, `EVICT`, `SUMMARIZE`.
- Add tombstones on eviction/summarization to preserve recall links.
- Add simple lock/queue for RAM mutations to prevent race conditions.
- Exit criteria: Every user/assistant turn has a stable `MemoryID`; safe concurrent mutation path exists.

### M2: LTM Persistence v1
- Add SQLite-backed LTM store (`memory.db`) with tables for:
  - sessions, ram_snapshots, summaries, events.
- Persist summarized/evicted RAM entries into LTM with metadata and timestamps.
- Add recall API path (`memory.recall`) returning summarized-first, full detail on request.
- Exit criteria: restart server, recover prior chat summaries and recall by topic/ID.

### M3: Identity Layer v1
- Add identity loader for `SOUL.md`, `AGENT.md`, `IDENTITY.md`, `USER.md`.
- Enforce precedence: `SOUL > AGENT > IDENTITY > USER` for conflicts.
- Compile to a single effective system prompt packet per agent/session.
- Exit criteria: deterministic merged identity output; conflict reporting in logs.

### M4: Primary Brain Planner v1
- Add orchestrator module that converts a user goal into:
  - immediate response,
  - short task list,
  - memory writes.
- Keep only Primary Brain making LLM calls.
- Add `agent.plan` and `agent.progress` outbound events (additive).
- Exit criteria: user can request a goal and receive explicit plan/progress messages in chat.

### M5: Worker Sub-Brains v1
- Implement deterministic local workers (no extra LLM calls yet):
  - `ResearchWorker` (repo/doc indexing tasks),
  - `ExecutionWorker` (task state transitions),
  - `StatusWorker` (progress synthesis).
- Add worker queue and bounded concurrency per architecture principles.
- Primary Brain delegates tasks and receives structured worker results.
- Exit criteria: parallel worker execution with bounded queues; progress updates visible.

### M6: Memory Manager Worker v1
- Background Memory Manager summarizes stale RAM entries and moves details to LTM.
- Use mutation queue/locks from M1; never directly mutate active item under processing.
- Emit `memory.event` for summarize/evict/recall actions.
- Exit criteria: active context remains within threshold while recall quality remains acceptable.

### M7: Heartbeat and Proactive Behavior v1
- Add heartbeat worker on interval (configurable) to:
  - check blocked tasks,
  - suggest next actions,
  - produce user-visible status nudges.
- If blocked, create speculative low-risk tasks and report rationale.
- Exit criteria: proactive updates occur without disrupting user-led chat flow.

## Testing and Acceptance Criteria

### Unit Tests
- `memory.zig`: `MemoryID` generation, tombstone behavior, lock/queue ordering.
- `identity.zig`: precedence conflict resolution determinism.
- `session_store.zig`: `/new` lifecycle semantics and persistence boundaries.
- `orchestrator.zig`: plan generation shape and delegation rules.

### Integration Tests
- Memory lifecycle: turn -> RAM -> summarize -> LTM -> recall.
- Worker orchestration: queued tasks execute with bounded concurrency and status events.

### Failure and Edge Scenarios
- Missing identity files: fallback to defaults with warning logs.
- SQLite unavailable/corrupt: degrade to RAM-only mode with explicit error events.
- Worker backlog saturation: backpressure behavior with no main-thread blocking.
- AI provider timeout/error: graceful `error` message and consistent task state.

## Rollout Strategy
1. Ship each milestone behind config flags (`agent_runtime_v1`, `memory_v1`, `workers_v1`).
2. Enable internally first, then default-on after a stability window.
3. Track milestone SLOs:
   - p95 response latency,
   - queue depth,
   - memory recall success rate,
   - error rates by worker type.

## Assumptions
- SQLite local file storage is acceptable for v1 and can be abstracted later for Postgres/vector stores.
