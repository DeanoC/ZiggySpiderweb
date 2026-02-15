# Tool System Test Framework

## Overview
End-to-end testing using real AI providers to verify tools are discoverable and callable.

## Architecture

### Test Runner (`tests/tools/test_runner.zig`)
- Connects to running Spiderweb server
- Sends test scenarios as chat messages
- Validates tool calls and results
- Reports pass/fail with logs

### Test Agent (`agents/test-agent/`)
- Identity: Test-focused agent that uses tools
- SOUL.md: Instructions to use tools when helpful
- Capabilities: All tool-enabled

### Test Scenarios
Each scenario is a conversation that should trigger specific tool usage:

1. **File Read Test**
   - Input: "Read the contents of README.md"
   - Expected: `tool.call` with `file_read`
   - Validate: Result contains actual file content

2. **File Write Test**
   - Input: "Create a file called test.txt with content 'Hello World'"
   - Expected: `tool.call` with `file_write`
   - Validate: File exists with correct content

3. **Directory List Test**
   - Input: "List the files in the src directory"
   - Expected: `tool.call` with `file_list`
   - Validate: Result contains known files

4. **Search Code Test**
   - Input: "Search for 'TODO' in the codebase"
   - Expected: `tool.call` with `search_code`
   - Validate: Results contain TODO comments

5. **Shell Test**
   - Input: "Run 'echo test123' in shell"
   - Expected: `tool.call` with `shell`
   - Validate: Output contains "test123"

6. **Multi-Tool Test**
   - Input: "Find all files containing 'main' then read the first one"
   - Expected: Two tool calls (search_code → file_read)
   - Validate: Both succeed with related data

## Validation Strategy

### Step 1: Tool Discovery
```
→ Send: {"type":"tool.list"}
← Expect: All 5 tools in response with correct schemas
```

### Step 2: Tool Invocation
```
→ Send chat message that should trigger tool use
← Expect: {"type":"tool.call",...} from AI
→ Execute tool
← Expect: {"type":"tool.result",...}
→ AI continues with tool results incorporated
```

### Step 3: Result Validation
- Tool was called with correct parameters
- Tool result was received by AI
- AI's response references tool output

## Test Agent Identity

### `agents/test-agent/SOUL.md`
```markdown
# Test Agent

You are a testing agent designed to verify tool functionality.

When asked to perform file operations, searches, or commands:
1. Use the available tools
2. Call them with proper JSON arguments
3. Wait for results before responding

You have access to:
- file_read: Read file contents
- file_write: Write files
- file_list: List directories
- search_code: Search codebase
- shell: Execute commands
```

### `agents/test-agent/agent.json`
```json
{
  "id": "test-agent",
  "name": "Tool Test Agent",
  "description": "Agent for testing tool system",
  "is_default": false,
  "capabilities": ["chat", "tools"]
}
```

## Test Execution Flow

1. **Setup Phase**
   - Start Spiderweb server
   - Create test files (test-data/)
   - Verify test agent exists

2. **Discovery Phase**
   - Connect as test-agent
   - Request tool.list
   - Validate all tools present

3. **Execution Phase**
   - For each test scenario:
     - Send prompt
     - Wait for tool.call (timeout 30s)
     - Validate call format
     - Server executes tool
     - Wait for AI response
     - Validate response uses tool results

4. **Cleanup Phase**
   - Remove test files
   - Disconnect
   - Report results

## Implementation Steps

1. Create test agent identity files
2. Create test runner CLI tool
3. Define test scenarios as JSON/YAML
4. Implement validation logic
5. Run against real provider (OpenAI, etc.)
6. Generate report

## Example Test Definition

```yaml
# tests/tools/scenarios/file_read.yaml
name: "File Read Test"
description: "Verify AI can read files using file_read tool"
steps:
  - action: "chat"
    message: "Read the file tests/test-data/sample.txt"
    
  - action: "expect_tool_call"
    tool: "file_read"
    timeout_ms: 10000
    validate_args:
      path: "tests/test-data/sample.txt"
      
  - action: "expect_response_contains"
    text: "Hello from test file"
```
