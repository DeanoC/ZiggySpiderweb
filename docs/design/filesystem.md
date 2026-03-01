## Distributed File System (Current)

Spiderweb exposes a unified project workspace by routing file operations over WebSocket to one or more node runtimes. The wire protocol is Acheron JSON envelopes with base64 payloads.

### Key Binaries

- `spiderweb-fs-node` (node runtime, exports file roots)
- `spiderweb-fs-mount` (FUSE mount client)

### Runtime Flow

1. Node runtime exports one or more roots (exports).
2. Control plane records mounts and project topology.
3. WorldFS projects mounts into `/projects/<project_id>/fs/*`.
4. The mount client (`spiderweb-fs-mount`) connects to the node FS endpoint (`/v2/fs`) and serves a local workspace.

### Protocol Notes

- Acheron runtime FS protocol: `acheron-1`.
- Node FS protocol negotiation: `acheron.t_fs_hello` with `protocol=unified-v2-fs` and `proto=2`.
- Binary data is base64-encoded in JSON as `data_b64`.

### Source Adapters

The node runtime supports multiple source adapters via the `SourceAdapter` contract:

- `local` / `posix` / `linux`
- `windows` (gated by host support)
- `gdrive` (Google Drive)
- `namespace` (synthetic namespace sources)

Adapters are wired through `src/fs_source_adapter*.zig` and the router in `src/fs_router.zig`.

### Google Drive (GDrive)

GDrive support is implemented in `src/fs_gdrive_backend.zig` and adapters:
- API mode is enabled with `SPIDERWEB_GDRIVE_ENABLE_API=1`.
- Access tokens can be provided via environment variables or credential store.
- Read + write operations are supported in API mode; non-API mode exposes scaffolding files.

### Implementation Pointers

- Node runtime: `src/fs_node_main.zig`, `src/fs_node_server.zig`, `src/fs_node_ops.zig`
- Router + adapters: `src/fs_router.zig`, `src/fs_source_adapter*.zig`
- Mount client: `src/fs_fuse_adapter.zig`, `src/fs_mount_main.zig`
- Protocol types: `src/fs_protocol.zig`
