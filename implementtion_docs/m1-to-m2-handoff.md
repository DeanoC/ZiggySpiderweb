# M1 → M2 Handoff (with M3/M4 Continuation Notes)

## Current milestone status (repository snapshot: as of this handoff)

- **M0**: baseline hardening and limits already present.
- **M1**: fully delivered (stable RAM model + IDs + locking semantics + tombstones/summaries).
- **M2**: in-progress completion. SQLite-backed long-term store is wired, plus legacy JSON fallback compatibility.
- **M3**: completed (`identity.zig` merged identity loader and hierarchy support).
- **M4**: completed in principle (`orchestrator.zig` + planner/progress plumbing).
- **M5**: not started yet.

## What is implemented in the current tree

### RAM (M1)
- `src/memory.zig` now owns RAM operations with:
  - `MemoryID` generation
  - `MemoryOperation` flows for `LOAD`, `UPDATE`, `EVICT`, `SUMMARIZE`
  - tombstone entries and stable summary chain behavior
  - size/byte gating to prevent unbounded context growth
  - concurrency safety around RAM mutations

### Long-term persistence (M2)
- `src/ltm_store.zig` provides SQLite persistence:
  - `Store.open/close`
  - `Store.archiveRamSnapshot`
  - `Store.loadLatestSnapshot`
  - `Store.pruneSnapshots`
  - `Store.migrateLegacyArchives`
  - snapshot tables for sessions, snapshots, summaries, entries, and events
- `src/server_piai.zig` now:
  - owns `ServerState.ltm_store`
  - restores session memory via SQLite snapshot first, with JSON archive fallback
  - serves `memory.recall` and `memory.query` with DB-first precedence
  - preserves legacy `.spiderweb-ltm` archive behavior for compatibility
- Bootstrap behavior now:
  - runs legacy migration into SQLite (`archive-index.ndjson` → `memory.db`)
  - applies retention pruning on startup
- `build.zig` links sqlite3 for both app and tests
- `ltm_store` tests added:
  - archive + load latest
  - prune by session limit
  - prune by age
  - legacy migration

### Identity (M3)
- `src/identity.zig` added with identity file layering and deterministic merge
- Used in session prompt compilation path for system behavior shaping.

### Planner (M4)
- `src/orchestrator.zig` added:
  - `buildPlan`/`deinitPlan` for simple goal decomposition
  - deterministic fallback handling for empty/invalid goal text
- `src/protocol.zig` includes planner/control event enum additions (`agent.plan`, `agent.progress`, `agent.control`, `agent.status`)
- `src/server_piai.zig` supports goal ingress and progress telemetry:
  - `/goal` command path in chat messages
  - `agent.control` with `goal`
  - `agent.plan` and `agent.progress` outbound events for clients
  - plan persisted into `.system` RAM entry to keep traceability

## What is still missing (M2 tail + M5 bootstrapping)

1. Full M2 historical recall behavior is still limited:
   - restore/query is currently primarily latest-snapshot oriented
   - no multi-snapshot/session-level scan yet
2. No dedicated DB-vs-legacy fallback tests for protocol restore/recall pathways.
3. No explicit protocol event for “fresh RAM restart” session acknowledgment.
4. M5 worker sub-brains are still TODO:
   - no deterministic worker queue yet
   - no bounded worker concurrency
   - no `ResearchWorker`, `ExecutionWorker`, or `StatusWorker` implementations

## Operational notes for the next AI

- Keep protocol payload compatibility:
  - `memory.recall` and `memory.query` schemas remain unchanged
  - continue emitting legacy-like `source: "ltm"` and `kind` values
- Keep `.spiderweb-session-state.json` semantics stable.
- Keep `.spiderweb-ltm` in place for recovery compatibility until JSON path is retired.
- If deploying without SQLite installed, ensure graceful DB failure paths still allow JSON fallback behavior.

## Suggested next sequence

1. Finish M2:
   - add tests for DB/JSON precedence in restore + recall/query
   - add historical snapshot scan/selection APIs
2. Start M5:
   - introduce worker queue + bounded concurrency
   - add deterministic worker modules
   - wire worker progress into `agent.progress` event stream
