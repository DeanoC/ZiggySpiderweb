# Spiderweb Architecture (Current)

This document reflects the runtime architecture as implemented in this repo.

## High-Level Components

- **WebSocket gateway** (`src/server_piai.zig`)
  - Accepts connections, negotiates unified-v2 control + Acheron runtime.
  - Handles control-plane ops (auth, sessions, projects, nodes, service catalog).

- **Runtime server** (`src/runtime_server.zig`)
  - Executes chat and tool-call loops.
  - Enforces tool-call constraints and emits debug frames.

- **Acheron WorldFS** (`src/fsrpc_session.zig`)
  - Projects control-plane state into filesystem namespaces.
  - Hosts agent services under `/agents/self/*`.

- **Control plane** (`src/fs_control_plane.zig`)
  - Projects, mounts, tokens, node registry, and workspace topology.

- **Sandbox runtime** (`src/sandbox_runtime.zig`)
  - Optional sandboxing for runtime tool execution (Linux + bubblewrap).

- **Node FS runtime** (`src/fs_node_*`)
  - Node-side filesystem protocol and service export surface.

## Concurrency Model

Spiderweb uses bounded queues and fixed worker pools defined in `Config.RuntimeConfig`:

- inbound/outbound queues for connection I/O
- control queue for control operations
- runtime worker pool for provider requests
- connection worker pool for WebSocket lifecycle

Key config fields (see `src/config.zig`):
- `inbound_queue_max`, `outbound_queue_max`, `control_queue_max`
- `connection_worker_threads`, `connection_queue_max`
- `runtime_worker_threads`, `runtime_request_queue_max`

## Protocols

- **Control:** unified-v2 (`control.version` + `control.connect` required)
- **Runtime FS:** Acheron (`acheron-1`)
- **Node FS:** unified-v2-fs (`acheron.t_fs_hello` with `proto=2`)

## State & Persistence

- Auth tokens, session history, and workspace metadata persist under `runtime.ltm_directory`.
- Project/mount topology is owned by the control plane and reflected into WorldFS.

## Observability

- Debug stream frames can be logged to `<ltm>/debug-stream.ndjson`.
- Node service events can be logged to `<ltm>/node-service-events.ndjson`.

## Implementation Pointers

- `src/server_piai.zig`
- `src/runtime_server.zig`
- `src/fsrpc_session.zig`
- `src/fs_control_plane.zig`
- `src/config.zig`
