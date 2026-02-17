# Tool System Tests

## Current Status

The active tool architecture is provider-driven.

- Tools are surfaced to the AI provider during `session.send`.
- The provider emits tool calls.
- Runtime executes tools and returns tool results back to provider.
- Clients observe results via `tool.event` and `memory.event` frames.

Standalone websocket messages like `tool.list` and `tool.call` are not part of the current runtime protocol path.

## What Is Covered

1. Unit-level world tool behavior in `src/tool_executor.zig`:
   - `file.read`
   - `file.write`
   - `file.list`
   - `search.code`
   - `shell.exec`
2. Runtime/provider integration in `src/runtime_server.zig`:
   - provider emits tool call
   - runtime executes it
   - provider returns final response

## How To Run

```bash
zig build test
```

Optional full build verification:

```bash
zig build
```

## Notes

The older `tests/tools/test_runner*.zig` files were designed around direct `tool.list` / `tool.call` protocol experimentation and are not the source of truth for the current provider-driven implementation.
