# Tool System Implementation Plan

GitHub Issue #3: Add tool registry and calling mechanism

## Overview
Implement a complete tool system allowing agents to call tools like file_read, search, shell, etc.

## Architecture

### 1. Tool Registry (`src/tool_registry.zig`)
- Register tools with JSON schemas
- Tool metadata: name, description, parameters, handler function
- Dynamic tool discovery

### 2. Tool Schema (`src/tool_schema.zig`)
- JSON Schema generation for tools
- Parameter validation
- Type conversion

### 3. Tool Execution (`src/tool_executor.zig`)
- Execute tool calls
- Handle results/errors
- Security sandboxing (where applicable)

### 4. Protocol Integration (`src/server_piai.zig`)
- `tool.list` → `tool.list.response`
- `tool.call` → `tool.result` / `tool.error`
- Stream tool results for long-running operations

## Tools to Implement (Phase 1)

### File Operations
- `file_read` - Read file contents
- `file_write` - Write/modify files
- `file_list` - List directory contents

### Search
- `search_code` - Search codebase (grep/ripgrep)
- `search_memory` - Query LTM store

### System
- `shell` - Execute shell commands (with restrictions)
- `exec` - Run background tasks

### Memory
- `memory_query` - Query long-term memory
- `memory_store` - Store to long-term memory

## Implementation Steps

1. Define tool types and interfaces
2. Create tool registry
3. Implement core tools
4. Add protocol handlers
5. Write tests
6. Document API

## Security Considerations
- Shell commands restricted to workspace
- File access within project boundaries
- Rate limiting on expensive operations
