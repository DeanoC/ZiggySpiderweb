# Tool Test Framework (Provider-Driven)

## Objective
Validate that world tools execute through the provider tool-calling loop during normal `session.send` handling.

## Architecture Under Test

1. Runtime exports world tool schemas to provider context.
2. Provider emits tool calls.
3. Runtime executes world tools.
4. Runtime emits `tool.event` / `memory.event`.
5. Runtime sends tool results back to provider.
6. Provider returns final assistant message.

## Canonical Tool Names

- `file.read`
- `file.write`
- `file.list`
- `search.code`
- `shell.exec`

## Primary Test Layers

### 1. Unit Handler Tests (`src/tool_executor.zig`)

Focused tests for:
- File read/write/list correctness
- Search result shaping
- Shell cwd handling
- Shell timeout behavior

### 2. Runtime Loop Tests (`src/runtime_server.zig`)

Mock-provider integration test verifies:
- provider tool call is received
- runtime executes tool call
- `tool.event` is emitted
- final assistant text is returned

## Execution

```bash
zig build test
```

## Non-Goals for This Framework

- Direct websocket `tool.list` and `tool.call` protocol validation
- Client-side manual tool orchestration

Those were part of an earlier exploratory direction and are not the active runtime contract.
