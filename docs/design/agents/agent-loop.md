# Agent Loop (Current)

The runtime loop is centered on Acheron chat + job processing:

1. Client writes chat input to `/agents/self/chat/control/input`.
2. Runtime queues a chat job and returns a job id.
3. Job status is available at `/agents/self/jobs/<job_id>/status.json`.
4. Job result text is available at `/agents/self/jobs/<job_id>/result.txt`.
5. Optional event waits can be used via `/agents/self/events/*`.

The WebSocket gateway enforces unified-v2 control negotiation and maintains per-session bindings to `(agent_id, project_id)`.

## Implementation Pointers

- Acheron session & jobs: `src/fsrpc_session.zig`
- Runtime server: `src/runtime_server.zig`
- Gateway/session handling: `src/server_piai.zig`
