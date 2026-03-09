# Filesystem Venom Layer

This folder contains Spiderweb-owned filesystem Venom code.

It is split into two kinds of files:

- real Spiderweb FS Venom code such as routing helpers, cache/policy, mount glue, and the embeddable facade
- thin compatibility shims that re-export the shared runtime from `spiderweb_node`

Authoritative generic node/runtime behavior lives in:

- `deps/spider-protocol/src/spiderweb_node/`

The shim files now live under `src/venoms/fs/shared/`.

Examples are:

- `shared/fs_node_main.zig`
- `shared/fs_node_ops.zig`
- `shared/fs_node_service.zig`
- `shared/fs_node_server.zig`
- `shared/fs_watch_runtime.zig`

If a change is generic to all nodes, move it into the shared protocol runtime.
If a change is specifically about Spiderweb’s FS Venom surface, keep it here.
