## FileSystem Source Layering Overview

This document describes how to layer multiple filesystem sources across different machines and operating systems.

### Goals
- Allow a single node to mount multiple source types.
- Keep the wire protocol stable while source implementations vary.
- Support mixed fleets: Linux, generic POSIX, Windows, and cloud-backed sources.
- Keep node embedding simple so FS can run as one component inside larger multi-use processes.

### Layer Model
1. Transport/Protocol Layer
- Existing WS protocol (`HELLO`, `EXPORTS`, `LOOKUP`, `READDIRP`, `OPEN`, `READ`, `...`).
- Source-agnostic on the wire.

2. Node Router Layer
- Maps exported namespace names to source adapters.
- Handles capabilities, readonly policy, and source-scoped errors.

3. Source Adapter Layer
- A single interface all source types implement.
- Adapter is responsible for translating source-native behavior to protocol semantics.

4. Source Runtime Layer
- Concrete backends:
  - Linux native source (inotify, Linux metadata behavior)
  - POSIX portable source (no Linux-only assumptions)
  - Windows source (ReadDirectoryChangesW, Windows ACL/attr mapping)
  - Google Drive source (API-backed object/file model)

### Proposed Adapter Contract
- `listExports()`
- `lookup(parent_id, name)`
- `getattr(node_id)`
- `readdirp(dir_id, cookie, max)`
- `open/read/close`
- `create/write/truncate/unlink/mkdir/rmdir/rename`
- `pollOrPushInvalidations()`

All adapters return protocol-level errno mappings and normalized `Attr`.

### Process Roles
- Source node:
  - Runs close to storage and hosts one or more adapters.
  - Examples: Linux host exposing local ext4 + Drive; Windows host exposing NTFS + Drive.
- Router/mount client:
  - Aggregates many source nodes behind unified endpoint aliases.
  - Applies failover and cache policy based on per-export capabilities.
- Optional control plane:
  - Distributes source config and credential handles.
  - Not required for protocol correctness.

### Source Identity and Namespace
- Keep current endpoint alias + export name model.
- Extend export metadata with source tags:
  - `source_kind`: `linux|posix|windows|gdrive|...`
  - `source_id`: stable identifier per source instance
- Attach source capabilities under export metadata:
  - `caps.native_watch`
  - `caps.case_sensitive`
  - Later: `caps.symlink`, `caps.xattr`, size limits, lock semantics
- Recommended logical mount shape:
  - `/endpoint/export/...` (current)
  - Optional future expansion: `/endpoint/source/export/...`

Example `EXPORTS` item shape:
```json
{
  "name": "work",
  "root": 281474976710657,
  "ro": false,
  "desc": "/srv/work",
  "source_kind": "linux",
  "source_id": "linux:work",
  "caps": {
    "native_watch": true,
    "case_sensitive": true
  }
}
```

### Mixed-Machine Behavior
- A Linux node can host `linux` and `gdrive` adapters.
- A Windows node can host `windows` and `gdrive` adapters.
- Router failover remains at endpoint group level, but capability-aware routing should avoid incompatible fallbacks.
- POSIX-only hosts (macOS/BSD or restricted libc targets) can run a `posix` adapter with scanner invalidation.

### Capability Negotiation
- Add per-export/source capabilities in `EXPORTS` metadata over time.
- Router should adapt behavior per source capability (cache policy, path normalization, rename checks).

### Topology Patterns
1. Single machine, multi-source
- One node process on Linux exposes local paths (`linux`) and cloud (`gdrive`) together.
- Useful for laptops/desktops where one agent needs local + cloud context.

2. Per-OS source nodes
- Linux machine exports Linux paths.
- Windows machine exports Windows paths.
- One mount/router process consumes both under separate endpoint aliases (for example `/lin`, `/win`).

3. Redundant source group by alias
- Two endpoints share alias `a` but point to replicated exports.
- Router failover stays alias-local; source/capability metadata gates incompatible fallback.

### Consistency and Invalidation
- Keep close-to-open baseline.
- Prefer push invalidations when source supports native watchers.
- Fallback to polling scanner invalidations for sources without native watch APIs.
- Cloud sources should coalesce/batch invalidations due API quotas.

### Error and Metadata Normalization
- Map source-native errors to Linux errno for protocol consistency.
- Normalize attrs:
  - Mode/kind/nlink/uid/gid/size/time/gen
- For cloud sources with missing POSIX data:
  - use synthetic/stable defaults and explicit capability flags.

### Credentials and Security
- Source credentials are adapter-owned, not protocol payload-owned.
- Node-side secret storage per source adapter (e.g. OAuth tokens for Drive).
- Export configs should reference credential handles, not raw secrets.

### Suggested Rollout Order
1. Extract a formal adapter interface from local FS implementation.
2. Split current local FS into `linux` + `posix` adapters.
3. Add `windows` adapter with metadata/error normalization and host-native execution helpers.
4. Add `gdrive` adapter with object-to-node mapping and batching.
5. Expand `EXPORTS` metadata and router capability-aware routing.

### Current Status
- Protocol and router foundation are in place.
- Push invalidation path exists (server fanout + client background pump).
- Linux native change trigger is now introduced via inotify backend with scanner fallback.
- `EXPORTS` now carries initial source metadata (`source_kind`, `source_id`, capability hints).
- A formal node-side `SourceAdapter` contract now exists.
- Local backend is split into explicit `linux` and `posix` source adapters (shared local implementation, separate selection points).
- A `windows` source adapter with real execution helpers is now wired (available on Windows hosts; non-Windows hosts fail fast with `UnsupportedSourceHost`).
- A `gdrive` adapter now supports read/write protocol operations (`LOOKUP`, `GETATTR`, `READDIRP`, `OPEN`, `READ`, `CLOSE`, `CREATE`, `WRITE`, `TRUNCATE`, `MKDIR`, `UNLINK`, `RMDIR`, `RENAME`) with node-id mapping for Drive file IDs.
- Google Drive API calls are opt-in (`SPIDERWEB_GDRIVE_ENABLE_API=1` + access token env var). When disabled, exports stay in scaffold mode and expose `.gdrive-status.txt`.
- Per-export gdrive credential handles are now supported for embedded/library and CLI node configs; OAuth refresh bundles can be resolved from node-side secure credential storage and refreshed in-place.
- GDrive API mode now polls the Drive Changes feed and converts change entries into protocol invalidation events for router/mount cache coherence.
- GDrive change feed page tokens are now persisted per export (when secure storage exists) to reduce cold-start resync cost.
- Router now parses per-export metadata from `EXPORTS` and applies capability-aware writable routing so read-only exports can be skipped for write-intent path resolution in alias groups.
- GDrive write-path operations (`CREATE`, `WRITE`, `TRUNCATE`) are now mapped in API mode with resumable chunk upload flushes and optimistic generation conflict checks.
- GDrive write handles now use file-backed staging buffers and upload from staged files to reduce memory pressure on large write sessions.
- GDrive staging now supports dedicated spool directory/limit controls (`SPIDERWEB_GDRIVE_SPOOL_DIR`, `SPIDERWEB_GDRIVE_SPOOL_MAX_BYTES`) with startup stale-spool cleanup.
- Source behavior routing now has an explicit `fs_source_policy` layer (write eligibility, case normalization, case-only rename behavior, cross-endpoint move policy).
- Router cross-endpoint file rename now has a policy-gated best-effort fallback (`copy + unlink`) for mixed-source topologies, using temporary destination staging and destination-exists guardrails.
- `STATFS` and `HELLO` capability behavior are now source-aware (`STATFS` path implemented and `HELLO.caps` computed from active exports).
- Router cache keys now normalize names for case-insensitive exports, and case-only same-parent renames are guarded as no-ops on case-insensitive sources.
- Source adapters now expose operation capability checks directly (`supportsOperation`), and node-side unsupported-op gating is now adapter-driven.
- Local source adapter now owns POSIX lock/xattr syscall behavior used by node dispatch for linux/posix exports.
- Router alias failover now uses health-weighted and capability-aware endpoint scoring when selecting which endpoint handles path resolution.

### Source Capability Matrix (PR Review)
| Operation | linux | posix | windows | gdrive (API mode) |
| --- | --- | --- | --- | --- |
| `LOOKUP` / `GETATTR` / `READDIRP` | yes | yes | yes | yes |
| `OPEN` / `READ` / `CLOSE` | yes | yes | yes | yes |
| `CREATE` / `WRITE` / `TRUNCATE` | yes | yes | yes | yes |
| `MKDIR` / `UNLINK` / `RMDIR` / `RENAME` | yes | yes | yes | yes |
| `STATFS` | yes | yes | yes | yes |
| `SYMLINK` | yes | yes | no (`ENOSYS`) | no (`ENOSYS`) |
| `SETXATTR` / `GETXATTR` / `LISTXATTR` / `REMOVEXATTR` | yes | yes | no (`ENOSYS`) | no (`ENOSYS`) |
| `LOCK` | yes | yes | yes | no (`ENOSYS`) |

Notes:
- `windows` source kind is host-gated: non-Windows hosts reject it with `UnsupportedSourceHost`.
- `gdrive` operations run in scaffold mode unless `SPIDERWEB_GDRIVE_ENABLE_API=1` and credentials are configured.
