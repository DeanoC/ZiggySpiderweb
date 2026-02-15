# M1/M2 RAM Handoff for Future AIs

## Current state (post-M1 and M2 bootstrap)

- RAM runtime is active in `src/memory.zig`:
  - Stable `MemoryID`
  - mutex-guarded update/evict/summarize model
  - hard limits (`max_messages`, `max_bytes`)
  - tombstones + summary linkage
- Session runtime is in `src/server_piai.zig`:
  - active RAM is persisted in `.spiderweb-session-state.json` via existing `loadPersistedSessions` / `savePersistedSessions`
  - RAM reset flows exist:
    - `session.reset`
    - `session.new` control message
    - `/new` command path
- Legacy long-term archives still write JSON snapshots under `.spiderweb-ltm/<session>-<timestamp>.json`.

## What was completed for M2 bootstrap

- Added `src/ltm_store.zig` with SQLite-backed persistence:
  - `Store.open`
  - `Store.close`
  - `Store.archiveRamSnapshot`
  - `Store.loadLatestSnapshot`
  - `Store.pruneSnapshots`
  - `Store.migrateLegacyArchives`
- Added tables:
  - `sessions`
  - `ram_snapshots`
  - `summaries`
  - `entries`
  - `ltm_events`
- `src/server_piai.zig` now stores `ServerState.ltm_store`:
  - `restoreSessionFromLatestArchive` tries DB first
  - `memory.recall` prefers DB snapshot then falls back to JSON archive
  - `memory.query` prefers DB snapshot then falls back to JSON archive
  - `archiveSessionRamToLongTerm` tries DB archive first and falls back to JSON archive
- `build.zig` now links `sqlite3` for both app and tests.
- Startup LTM bootstrap now:
  - migrates legacy `.spiderweb-ltm/archive-index.ndjson` rows into `memory.db`
  - runs retention pruning on boot with defaults:
    - keep last 24 snapshots per session
    - keep snapshots up to 30 days old
    - override with `SPIDERWEB_LTM_KEEP_SNAPSHOTS` and `SPIDERWEB_LTM_KEEP_DAYS`
- Legacy JSON path (`ltm_index.zig`) remains in place for compatibility:
  - index file `.spiderweb-ltm/archive-index.ndjson`
  - snapshot files `.spiderweb-ltm/*.json`
- LTM tests in `src/ltm_store.zig` include:
  - `ltm_store: archive and load latest snapshot`
  - `ltm_store: prune snapshots by per-session limit`
  - `ltm_store: prune snapshots by age cutoff`
  - `ltm_store: migrate legacy archive into sqlite snapshot table`

## What is still missing (M2)

1. Restore behavior is still DB-latest-only for long-term content; there is no session-level historical scan yet.
2. No dedicated tests yet for:
   - DB then JSON fallback precedence in protocol restore/recall paths
   - invalid payload handling when both DB and legacy JSON inputs exist
3. Long-term memory is currently "session snapshot" semantics, not stream/snapshot deltas.

## Operational notes for next AI

- Prefer keeping `.spiderweb-session-state.json` behavior unchanged.
- Keep `.spiderweb-ltm` for emergency compatibility and recovery of old archives.
- Existing restart path should continue to return session state quickly even if DB is unavailable.
- If DB storage is critical, validate sqlite3 availability in runtime images and install runtime package if needed.
- When adding future persistence work, keep protocol payloads unchanged:
  - existing clients still expect `memory.recall` and `memory.query` schema
  - maintain old `source: "ltm"` field and `kind` values.

## Suggested M2 continuation order

1. Add tests for DB/JSON restore precedence (`memory.recall`, `memory.query`, and initial session restore path).
2. Add session-level historical archive scan (not just latest snapshot) to recall/query APIs.
3. Consider explicit protocol event for "fresh session start" if clients need stronger server acknowledgment.
