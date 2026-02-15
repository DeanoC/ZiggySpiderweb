# M1 RAM Guide & Handoff for Future AIs

## Current state (post-M1 and early M2)

- RAM model is implemented in `src/memory.zig` and is the active runtime context:
  - Stable `MemoryID` values
  - queued mutation model (`load`, `update`, `evict`, `summarize`)
  - mutex-guarded context mutations
  - FIFO mutation application
  - hard limit enforcement (`max_messages`, `max_bytes`)
  - tombstones + summary linkage via `related_to`
- Session runtime uses RAM via `SessionContext` in `src/server_piai.zig`.
- RAM survives process restart through session persistence in `.spiderweb-session-state.json`
  (`loadPersistedSessions` / `savePersistedSessions`).
- Fresh RAM behavior exists:
  - `session.reset` control message
  - `session.new` control path
  - `/new` user command
  - optional RAM archive output under `.spiderweb-ltm/<session>-<timestamp>.json`
  - archive includes `version`, `timestamp_ms`, `session_id`, `reason`, `next_id`, `entries`, `summaries`.
- Optional LTM fallback recovery on client reconnect:
  - handshake now attempts in-memory session restore first
  - if not found, it loads the latest archive for that `sessionKey`
  - restored sessions recover `summaries` plus capped recent active RAM entries
  - this keeps topic continuity without crashing if RAM snapshot is missing.

## Useful file map

- `src/memory.zig`
  - Core RAM types + mutation queue + limit logic + tests.
- `src/server_piai.zig`
  - Session runtime, websocket handling, RAM persistence restore/save
  - reset/new control handling and new RAM archive writer.
- `implementtion_docs/agent-implementation-plan.md`
  - Milestone map and M2 target expectations.
- `AGENTS.md`
  - Repository rules and build requirements.

## What is still missing for M1 completeness

1. RAM eviction/summarization should be persisted to long-term memory as structured records, not only active session JSON snapshots.
2. Concurrency safety for RAM mutations is present, but cross-component locking/queue ownership boundaries are not yet isolated behind a dedicated session store abstraction.
3. Client-facing control surface is added for reset/new; add tests around message pathing for `session.new` and `/new`.
4. `memory.recall` returns a compact snapshot payload but currently lacks topic-level filtering and richer schema fields (`memory.query` path is still pending).

## M2 start plan (next steps)

M2 target in the plan: **SQLite-backed long-term memory store** with recall APIs.

Recommended execution order:

1. Add `src/ltm_store.zig` abstraction first.
   - `store` API: `init/open`, `close`, `archiveRamSnapshot`, `queryRecentArchives`, `queryBySession`.
   - Keep this interface small; start with a file-backed adapter for now if DB deps are missing.
2. Introduce persistent tables per session for RAM snapshots, entries, and summaries.
   - Include timestamps, `next_id`, source IDs, and `related_to` links.
3. Wire summarization/eviction output into LTM writes.
   - Persist source entry + generated tombstone + summary metadata at mutation time.
4. Implement `memory.recall` protocol entrypoint in `server_piai.zig`.
   - Inputs: `sessionKey`, optional `memoryId`, optional `limit`.
   - Output: structured `memory.event`/`memory.recall` payloads.
5. Add startup recovery path:
   - restore recent summarized facts from LTM when session RAM is hot-started.
   - done: latest archive fallback if persisted session state is unavailable.
6. Add tests:
   - archive write/read
   - recall precedence (summaries first, full entries by request)
   - fallback behavior if LTM unavailable.

### Current M2 status

- Added `memory.recall` implementation with archive-aware recall (`summaries` first; optionally full entries) in `src/server_piai.zig`.
- Added startup reconnect fallback to latest LTM archive when a requested session has no in-memory snapshot.
- Added `memory.query` websocket request (`memory.query`) supporting:
  - ID-based filtering via `memoryId` or `memoryIds`
  - optional `kind` (`summary`/`entry`/`all`)
  - optional `topic` substring match
  - optional `include_archived` scanning of latest archive snapshot
- Still missing for M2:
  - first-class SQLite-backed `memory.db` store (plan still defines NDJSON/JSON archives as temporary persistence)
  - dedicated migration/retention policy and background summarize->LTM flush path

## Operational notes

- Keep `.spiderweb-session-state.json` for fast restart continuity as today.
- Keep `.spiderweb-ltm` as an intermediate/compatibility path while SQLite is bootstrapped.
- Prefer additive protocol fields to avoid breaking older clients.
- For any environment work, ensure a plain-text timestamped path (`.spiderweb-ltm/<session>-<ms>.json`) remains human readable for emergency debugging.
