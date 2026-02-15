const std = @import("std");

// Tool System Test Runner
// Tests the Spiderweb tool system by connecting and executing tool calls

const TestResult = enum {
    passed,
    failed,
};

fn runTest(allocator: std.mem.Allocator, name: []const u8, test_fn: *const fn (std.mem.Allocator) anyerror!TestResult) !TestResult {
    std.log.info("Test: {s}", .{name});
    const result = test_fn(allocator) catch |err| {
        std.log.err("  FAILED with error: {s}", .{@errorName(err)});
        return .failed;
    };
    if (result == .passed) {
        std.log.info("  PASSED", .{});
    } else {
        std.log.err("  FAILED", .{});
    }
    return result;
}

fn testToolDiscovery(allocator: std.mem.Allocator) !TestResult {
    // Use curl to test HTTP endpoint
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl", "-s", "-X", "POST",
            "http://127.0.0.1:18790/new",
            "-H", "Content-Type: application/json",
            "-d", "{\"type\":\"tool.list\",\"request\":\"test1\"}",
        },
        .max_output_bytes = 1024 * 1024,
    }) catch {
        return .failed;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    std.log.info("  Response: {s}", .{result.stdout});

    // Check if response contains tool.list.response
    if (std.mem.indexOf(u8, result.stdout, "tool.list.response") == null) {
        return .failed;
    }

    return .passed;
}

fn testFileRead(allocator: std.mem.Allocator) !TestResult {
    // Create test file
    try std.fs.cwd().makePath("tests/test-data");
    try std.fs.cwd().writeFile(.{
        .sub_path = "tests/test-data/sample.txt",
        .data = "Hello from test file!",
    });

    // Test file_read tool via curl
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl", "-s", "-X", "POST",
            "http://127.0.0.1:18790/new",
            "-H", "Content-Type: application/json",
            "-d", "{\"type\":\"tool.call\",\"request\":\"test2\",\"tool\":\"file_read\",\"args\":{\"path\":\"tests/test-data/sample.txt\"}}",
        },
        .max_output_bytes = 1024 * 1024,
    }) catch {
        return .failed;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    std.log.info("  Response: {s}", .{result.stdout});

    // Cleanup
    std.fs.cwd().deleteFile("tests/test-data/sample.txt") catch {};

    if (std.mem.indexOf(u8, result.stdout, "tool.result") == null) {
        return .failed;
    }
    if (std.mem.indexOf(u8, result.stdout, "Hello from test file") == null) {
        return .failed;
    }

    return .passed;
}

fn testFileList(allocator: std.mem.Allocator) !TestResult {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl", "-s", "-X", "POST",
            "http://127.0.0.1:18790/new",
            "-H", "Content-Type: application/json",
            "-d", "{\"type\":\"tool.call\",\"request\":\"test3\",\"tool\":\"file_list\",\"args\":{\"path\":\"src\"}}",
        },
        .max_output_bytes = 1024 * 1024,
    }) catch {
        return .failed;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    std.log.info("  Response: {s}", .{result.stdout});

    if (std.mem.indexOf(u8, result.stdout, "tool.result") == null) {
        return .failed;
    }

    return .passed;
}

fn testSearchCode(allocator: std.mem.Allocator) !TestResult {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl", "-s", "-X", "POST",
            "http://127.0.0.1:18790/new",
            "-H", "Content-Type: application/json",
            "-d", "{\"type\":\"tool.call\",\"request\":\"test4\",\"tool\":\"search_code\",\"args\":{\"query\":\"fn main\",\"path\":\"src\"}}",
        },
        .max_output_bytes = 1024 * 1024,
    }) catch {
        return .failed;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    std.log.info("  Response: {s}", .{result.stdout});

    if (std.mem.indexOf(u8, result.stdout, "tool.result") == null) {
        return .failed;
    }

    return .passed;
}

fn testShell(allocator: std.mem.Allocator) !TestResult {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl", "-s", "-X", "POST",
            "http://127.0.0.1:18790/new",
            "-H", "Content-Type: application/json",
            "-d", "{\"type\":\"tool.call\",\"request\":\"test5\",\"tool\":\"shell\",\"args\":{\"command\":\"echo test123\"}}",
        },
        .max_output_bytes = 1024 * 1024,
    }) catch {
        return .failed;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    std.log.info("  Response: {s}", .{result.stdout});

    if (std.mem.indexOf(u8, result.stdout, "tool.result") == null) {
        return .failed;
    }
    if (std.mem.indexOf(u8, result.stdout, "test123") == null) {
        return .failed;
    }

    return .passed;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Tool System Test Suite ===", .{});
    std.log.info("Server: 127.0.0.1:18790\n", .{});

    var passed: usize = 0;
    var failed: usize = 0;

    const tests = .{
        .{ "Tool Discovery", testToolDiscovery },
        .{ "File Read", testFileRead },
        .{ "File List", testFileList },
        .{ "Search Code", testSearchCode },
        .{ "Shell", testShell },
    };

    inline for (tests) |t| {
        const result = runTest(allocator, t[0], t[1]) catch .failed;
        if (result == .passed) passed += 1 else failed += 1;
    }

    std.log.info("\n=== Results ===", .{});
    std.log.info("Passed: {d}", .{passed});
    std.log.info("Failed: {d}", .{failed});
    std.log.info("Total:  {d}", .{passed + failed});

    if (failed > 0) {
        std.process.exit(1);
    }
}
