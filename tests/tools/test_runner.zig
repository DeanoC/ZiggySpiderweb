const std = @import("std");
const builtin = @import("builtin");

// Simple WebSocket client for testing
const TestClient = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    connected: bool,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !TestClient {
        const addr = try std.net.Address.parseIp(host, port);
        const stream = try std.net.tcpConnectToAddress(addr);
        return .{
            .allocator = allocator,
            .stream = stream,
            .connected = true,
        };
    }

    pub fn deinit(self: *TestClient) void {
        self.stream.close();
        self.connected = false;
    }

    pub fn sendJson(self: *TestClient, json: []const u8) !void {
        // Simple WebSocket text frame
        var frame = std.ArrayList(u8).init(self.allocator);
        defer frame.deinit();

        // FIN=1, opcode=text (0x81)
        try frame.append(0x81);

        // Masked payload length
        if (json.len < 126) {
            try frame.append(@intCast(0x80 | json.len));
        } else if (json.len < 65536) {
            try frame.append(0xFE); // 0x80 | 126
            try frame.append(@intCast((json.len >> 8) & 0xFF));
            try frame.append(@intCast(json.len & 0xFF));
        } else {
            return error.PayloadTooLarge;
        }

        // Mask key (4 bytes)
        const mask_key = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
        try frame.appendSlice(&mask_key);

        // Masked payload (XOR with mask key)
        for (json, 0..) |byte, i| {
            try frame.append(byte ^ mask_key[i % 4]);
        }

        try self.stream.writeAll(frame.items);
    }

    pub fn receiveFrame(self: *TestClient, allocator: std.mem.Allocator) ![]u8 {
        var header: [2]u8 = undefined;
        _ = try self.stream.read(&header);

        const masked = (header[1] & 0x80) != 0;
        var len = @as(usize, header[1] & 0x7F);

        if (len == 126) {
            var len_bytes: [2]u8 = undefined;
            _ = try self.stream.read(&len_bytes);
            len = @as(usize, len_bytes[0]) << 8 | len_bytes[1];
        } else if (len == 127) {
            return error.PayloadTooLarge;
        }

        var mask_key: [4]u8 = undefined;
        if (masked) {
            _ = try self.stream.read(&mask_key);
        }

        const payload = try allocator.alloc(u8, len);
        errdefer allocator.free(payload);

        _ = try self.stream.read(payload);

        if (masked) {
            for (payload, 0..) |*byte, i| {
                byte.* ^= mask_key[i % 4];
            }
        }

        return payload;
    }
};

const TestResult = enum {
    passed,
    failed,
    skipped,
};

const ToolTestRunner = struct {
    allocator: std.mem.Allocator,
    client: TestClient,
    server_host: []const u8,
    server_port: u16,
    agent_id: []const u8,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16, agent_id: []const u8) !ToolTestRunner {
        const client = try TestClient.init(allocator, host, port);
        return .{
            .allocator = allocator,
            .client = client,
            .server_host = host,
            .server_port = port,
            .agent_id = agent_id,
        };
    }

    pub fn deinit(self: *ToolTestRunner) void {
        self.client.deinit();
    }

    /// Run all tool tests
    pub fn runAllTests(self: *ToolTestRunner) !void {
        std.log.info("=== Tool System Test Suite ===", .{});
        std.log.info("Server: {s}:{d}", .{ self.server_host, self.server_port });
        std.log.info("Agent: {s}\n", .{self.agent_id});

        var passed: usize = 0;
        var failed: usize = 0;

        // Test 1: Tool Discovery
        const t1 = try self.testToolDiscovery();
        if (t1 == .passed) passed += 1 else failed += 1;

        // Test 2: File Read
        const t2 = try self.testFileRead();
        if (t2 == .passed) passed += 1 else failed += 1;

        // Test 3: File List
        const t3 = try self.testFileList();
        if (t3 == .passed) passed += 1 else failed += 1;

        // Test 4: Search Code
        const t4 = try self.testSearchCode();
        if (t4 == .passed) passed += 1 else failed += 1;

        // Test 5: Shell
        const t5 = try self.testShell();
        if (t5 == .passed) passed += 1 else failed += 1;

        std.log.info("\n=== Results ===", .{});
        std.log.info("Passed: {d}", .{passed});
        std.log.info("Failed: {d}", .{failed});
        std.log.info("Total:  {d}", .{passed + failed});
    }

    fn testToolDiscovery(self: *ToolTestRunner) !TestResult {
        std.log.info("Test: Tool Discovery", .{});

        // Request tool list
        try self.client.sendJson("{\"type\":\"tool.list\",\"request\":\"test-discovery\"}");

        const response = try self.client.receiveFrame(self.allocator);
        defer self.allocator.free(response);

        std.log.info("  Response: {s}", .{response});

        // Parse response
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, response, .{}) catch {
            std.log.err("  FAILED: Invalid JSON response", .{});
            return .failed;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;

        // Validate response type
        const msg_type = obj.get("type") orelse {
            std.log.err("  FAILED: Missing type field", .{});
            return .failed;
        };
        if (!std.mem.eql(u8, msg_type.string, "tool.list.response")) {
            std.log.err("  FAILED: Wrong response type: {s}", .{msg_type.string});
            return .failed;
        }

        // Validate tools array exists
        const tools = obj.get("tools") orelse {
            std.log.err("  FAILED: Missing tools array", .{});
            return .failed;
        };
        if (tools.array.items.len == 0) {
            std.log.err("  FAILED: Empty tools array", .{});
            return .failed;
        }

        std.log.info("  PASSED: Found {d} tools", .{tools.array.items.len});
        return .passed;
    }

    fn testFileRead(self: *ToolTestRunner) !TestResult {
        std.log.info("Test: File Read", .{});

        // Create test file first
        const test_content = "Hello from test file!";
        try std.fs.cwd().writeFile(.{
            .sub_path = "tests/test-data/sample.txt",
            .data = test_content,
        });

        // Execute tool directly (no AI for this unit test)
        try self.client.sendJson(
            "{\"type\":\"tool.call\",\"request\":\"test-file-read\",\"tool\":\"file_read\",\"args\":{\"path\":\"tests/test-data/sample.txt\"}}"
        );

        const response = try self.client.receiveFrame(self.allocator);
        defer self.allocator.free(response);

        std.log.info("  Response: {s}", .{response});

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, response, .{}) catch {
            std.log.err("  FAILED: Invalid JSON", .{});
            return .failed;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;

        // Should get tool.result
        const msg_type = obj.get("type") orelse {
            std.log.err("  FAILED: Missing type", .{});
            return .failed;
        };
        if (!std.mem.eql(u8, msg_type.string, "tool.result")) {
            std.log.err("  FAILED: Expected tool.result, got {s}", .{msg_type.string});
            return .failed;
        }

        // Validate content
        const content = obj.get("content") orelse {
            std.log.err("  FAILED: Missing content", .{});
            return .failed;
        };
        if (!std.mem.contains(u8, content.string, "Hello from test file")) {
            std.log.err("  FAILED: Content mismatch", .{});
            return .failed;
        }

        // Cleanup
        std.fs.cwd().deleteFile("tests/test-data/sample.txt") catch {};

        std.log.info("  PASSED", .{});
        return .passed;
    }

    fn testFileList(self: *ToolTestRunner) !TestResult {
        std.log.info("Test: File List", .{});

        try self.client.sendJson(
            "{\"type\":\"tool.call\",\"request\":\"test-file-list\",\"tool\":\"file_list\",\"args\":{\"path\":\"src\"}}"
        );

        const response = try self.client.receiveFrame(self.allocator);
        defer self.allocator.free(response);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, response, .{}) catch {
            std.log.err("  FAILED: Invalid JSON", .{});
            return .failed;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;

        if (!std.mem.eql(u8, obj.get("type").?.string, "tool.result")) {
            std.log.err("  FAILED: Not a tool result", .{});
            return .failed;
        }

        std.log.info("  PASSED", .{});
        return .passed;
    }

    fn testSearchCode(self: *ToolTestRunner) !TestResult {
        std.log.info("Test: Search Code", .{});

        try self.client.sendJson(
            "{\"type\":\"tool.call\",\"request\":\"test-search\",\"tool\":\"search_code\",\"args\":{\"query\":\"fn main\",\"path\":\"src\"}}"
        );

        const response = try self.client.receiveFrame(self.allocator);
        defer self.allocator.free(response);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, response, .{}) catch {
            std.log.err("  FAILED: Invalid JSON", .{});
            return .failed;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;

        if (!std.mem.eql(u8, obj.get("type").?.string, "tool.result")) {
            std.log.err("  FAILED: Not a tool result", .{});
            return .failed;
        }

        std.log.info("  PASSED", .{});
        return .passed;
    }

    fn testShell(self: *ToolTestRunner) !TestResult {
        std.log.info("Test: Shell", .{});

        try self.client.sendJson(
            "{\"type\":\"tool.call\",\"request\":\"test-shell\",\"tool\":\"shell\",\"args\":{\"command\":\"echo test123\"}}"
        );

        const response = try self.client.receiveFrame(self.allocator);
        defer self.allocator.free(response);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, response, .{}) catch {
            std.log.err("  FAILED: Invalid JSON", .{});
            return .failed;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;

        if (!std.mem.eql(u8, obj.get("type").?.string, "tool.result")) {
            std.log.err("  FAILED: Not a tool result", .{});
            return .failed;
        }

        // Check content contains test123
        const content = obj.get("content").?.string;
        if (!std.mem.contains(u8, content, "test123")) {
            std.log.err("  FAILED: Output doesn't contain expected text", .{});
            return .failed;
        }

        std.log.info("  PASSED", .{});
        return .passed;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var host: []const u8 = "127.0.0.1";
    var port: u16 = 18790;
    var agent_id: []const u8 = "test-agent";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--host")) {
            i += 1;
            if (i < args.len) host = args[i];
        } else if (std.mem.eql(u8, args[i], "--port")) {
            i += 1;
            if (i < args.len) port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--agent")) {
            i += 1;
            if (i < args.len) agent_id = args[i];
        }
    }

    var runner = try ToolTestRunner.init(allocator, host, port, agent_id);
    defer runner.deinit();

    try runner.runAllTests();
}
