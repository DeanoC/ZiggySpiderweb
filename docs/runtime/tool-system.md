# Tool System (Runtime Implementation)

Spiderweb exposes tools to providers through the runtime tool loop. There is no standalone `tool.list`/`tool.call` WebSocket API for clients. Tool execution is driven by provider tool calls during `session.send` and by Acheron control files under `/agents/self/*`.

## Provider Tool Loop

1. Client sends `session.send`.
2. Runtime builds provider context and tool schema.
3. Provider emits exactly one tool call per response (multi-tool batches are rejected).
4. Runtime executes the tool and returns a `tool_result` to the provider.
5. The loop repeats until the provider returns a final assistant message.
6. Client receives `session.receive` plus any `tool.event`/`memory.event` frames.

### Provider-Exposed Tools

Direct provider schema exposure is intentionally limited:
- `file_read`
- `file_write`
- `file_list`

These are the only tool names accepted in `agent.control` `tool.call` while running in Acheron strict mode.

### Runtime Tool Registry (Internal)

The runtime tool registry includes additional tools used by Acheron services:
- `search_code`
- `shell_exec`

These are invoked via `/agents/self/search_code` and `/agents/self/terminal` control paths rather than being exposed directly to providers.

## Constraints & Safeguards

- One tool call per provider response (enforced).
- Tool call cap per request (see `runtime_server.zig` guard rails).
- File tools are the only direct provider tools.
- Tool retry and lease behavior is configured via `runtime` settings in `config.json`.

## Implementation Pointers

- Tool loop: `src/runtime_server.zig`
- Tool registry/exec: `ZiggyToolRuntime/src/tool_registry.zig`, `ZiggyToolRuntime/src/tool_executor.zig`
- Acheron service bridges: `src/fsrpc_session.zig`
- Runtime configuration: `src/config.zig`
