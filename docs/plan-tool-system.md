# Tool System (Current Implementation)

## Overview
The world tool system is implemented as a provider-driven tool-calling loop.

There is no standalone websocket `tool.list` / `tool.call` protocol in this implementation.
Tools are exposed to the model during `session.send`, and model-emitted tool calls are executed inside runtime.

## Runtime Flow

1. Client sends `session.send`.
2. Runtime builds provider context with world tool schemas.
3. Provider may emit tool calls.
4. Runtime executes tool calls through the world tool registry.
5. Tool results are fed back to provider as `tool_result` messages.
6. Loop repeats until provider returns final assistant text.
7. Runtime emits:
   - `session.receive`
   - `tool.event`
   - `memory.event`

## Implemented World Tools

- `file_read`
- `file_write`
- `file_list`
- `search_code`
- `shell_exec`

## Core Modules

- `src/tool_registry.zig`: world/brain tool schemas, registration, provider schema export, execution dispatch.
- `src/tool_executor.zig`: implementations for the five world tools.
- `src/agent_runtime.zig`: runtime-owned world tool registry and registration.
- `src/brain_tools.zig`: dispatches unknown tool names to world tool registry.
- `src/runtime_server.zig`: provider tool-call roundtrip loop and event emission.

## Limits and Safeguards

- Max provider tool rounds per request: `8`
- Max total tool calls per request: `32`
- `shell_exec` timeout is bounded and output is capped
- Queue saturation/runtime pause/cancel semantics continue to apply

## Testing

- Unit tests:
  - world tool handlers in `src/tool_executor.zig`
  - runtime/provider tool loop in `src/runtime_server.zig`
- Full suite:
  - `zig build test`
- Build verification:
  - `zig build`
