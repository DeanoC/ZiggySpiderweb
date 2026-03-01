# File System Sources

This doc describes how Spiderweb routes filesystem operations across heterogeneous sources.

## Source Adapters

Source adapters live under `src/fs_*_source_adapter.zig` and are created via `fs_source_adapter_factory.zig`.

Implemented adapters include:
- `local` / `posix` / `linux`
- `windows` (host-gated)
- `gdrive`
- `namespace`

Each adapter advertises capability hints (case sensitivity, native watch, xattr, etc.) used by the router.

## Router Behavior

The router (`src/fs_router.zig`) chooses a target export for each operation based on:

- read/write intent
- export capability flags
- read-only status
- health / availability scoring
- alias groups and failover ordering

Routing policy decisions are centralized in `src/fs_source_policy.zig`.

## Metadata & Export Discovery

Exports include metadata used by the router and mount client:
- `source_kind`
- `source_id`
- `caps.native_watch`
- `caps.case_sensitive`

## Implementation Pointers

- `src/fs_router.zig`
- `src/fs_source_policy.zig`
- `src/fs_source_adapter.zig`
- `src/fs_source_adapter_factory.zig`
