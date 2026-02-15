# Tool System Tests

## Quick Start

1. **Start the Spiderweb server** with tool support:
   ```bash
   cd /safe/Safe/openclaw-config/workspace/ziggy-spiderweb-worktrees/tool-system
   zig build
   ./zig-out/bin/spiderweb
   ```

2. **Run the test suite**:
   ```bash
   zig run tests/tools/test_runner.zig -- --host 127.0.0.1 --port 18790
   ```

## Test Scenarios

The test runner validates:

1. **Tool Discovery** - Server returns all 5 tools with schemas
2. **File Read** - Can read files from the filesystem
3. **File List** - Can list directory contents
4. **Search Code** - Can search codebase with ripgrep/grep
5. **Shell** - Can execute shell commands

## Manual Testing with AI

For end-to-end testing with a real AI provider:

1. Copy the test agent:
   ```bash
   cp -r agents/test-agent /path/to/spiderweb/agents/
   ```

2. Connect as test-agent:
   ```
   ws://localhost:18790/new?agent=test-agent
   ```

3. Send test messages:
   - "Read the README.md file"
   - "List the files in src directory"
   - "Search for TODO in the codebase"
   - "Run echo Hello World"

4. Verify AI calls tools and responds with actual results

## Adding New Tests

Add test methods to `ToolTestRunner` in `test_runner.zig`:

```zig
fn testMyNewTool(self: *ToolTestRunner) !TestResult {
    std.log.info("Test: My New Tool", .{});
    
    // Send tool.call
    try self.client.sendJson("...");
    
    // Receive response
    const response = try self.client.receiveFrame(self.allocator);
    
    // Validate
    // ...
    
    return .passed;
}
```

## Test Data

Create test files in `tests/test-data/` for file operations tests.
