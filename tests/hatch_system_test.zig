const std = @import("std");
const AgentRegistry = @import("../src/agent_registry.zig").AgentRegistry;

// Test helper to create a temp directory for tests
fn setupTestDir(allocator: std.mem.Allocator, suffix: []const u8) ![]u8 {
    const test_dir = try std.fmt.allocPrint(allocator, "/tmp/zss-test-{s}-{d}", .{ suffix, std.time.milliTimestamp() });
    try std.fs.cwd().makePath(test_dir);
    return test_dir;
}

fn cleanupTestDir(test_dir: []const u8) void {
    std.fs.cwd().deleteTree(test_dir) catch {};
}

test "isFirstBoot returns true when only default agent exists" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "firstboot");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    // Fresh registry should be in first-boot state
    try std.testing.expect(registry.isFirstBoot());
}

test "isFirstBoot returns false after creating first agent" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "firstboot-false");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    // Create first agent
    try registry.initializeFirstAgent("test-agent", null);
    
    // Should no longer be in first-boot state
    try std.testing.expect(!registry.isFirstBoot());
}

test "createAgent creates HATCH.md file" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "create");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    try registry.createAgent("new-agent", null);
    
    // Check that HATCH.md was created
    const hatch_path = try std.fs.path.join(allocator, &.{ test_dir, "agents", "new-agent", "HATCH.md" });
    defer allocator.free(hatch_path);
    
    const content = try std.fs.cwd().readFileAlloc(allocator, hatch_path, 1024);
    defer allocator.free(content);
    
    try std.testing.expect(content.len > 0);
    try std.testing.expect(std.mem.containsAtLeast(u8, content, 1, "HATCH.md"));
}

test "agent has needs_hatching flag when HATCH.md exists" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "hatching-flag");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    try registry.createAgent("hatch-agent", null);
    
    const agent = registry.getAgent("hatch-agent");
    try std.testing.expect(agent != null);
    try std.testing.expect(agent.?.needs_hatching);
}

test "completeHatching removes HATCH.md and clears flag" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "complete");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    try registry.createAgent("complete-agent", null);
    
    // Verify HATCH.md exists
    const agent_before = registry.getAgent("complete-agent").?;
    try std.testing.expect(agent_before.needs_hatching);
    
    // Complete hatching
    try registry.completeHatching("complete-agent");
    
    // Verify flag is cleared
    const agent_after = registry.getAgent("complete-agent").?;
    try std.testing.expect(!agent_after.needs_hatching);
    
    // Verify HATCH.md is deleted
    const hatch_path = try std.fs.path.join(allocator, &.{ test_dir, "agents", "complete-agent", "HATCH.md" });
    defer allocator.free(hatch_path);
    
    std.fs.cwd().access(hatch_path, .{}) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
        return;
    };
    return error.TestExpectedError;
}

test "readHatchFile returns HATCH.md content" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "read");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    try registry.createAgent("read-agent", null);
    
    const content = try registry.readHatchFile("read-agent");
    defer if (content) |c| allocator.free(c);
    
    try std.testing.expect(content != null);
    try std.testing.expect(content.?.len > 0);
}

test "readHatchFile returns null for hatched agent" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "read-null");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    try registry.createAgent("hatched-agent", null);
    try registry.completeHatching("hatched-agent");
    
    const content = try registry.readHatchFile("hatched-agent");
    try std.testing.expect(content == null);
}

test "agent list includes needs_hatching flag" {
    const allocator = std.testing.allocator;
    
    const test_dir = try setupTestDir(allocator, "list");
    defer allocator.free(test_dir);
    defer cleanupTestDir(test_dir);
    
    var registry = try AgentRegistry.init(allocator, test_dir);
    defer registry.deinit();
    
    try registry.createAgent("list-agent", null);
    
    const agents = registry.listAgents();
    
    // Find our agent
    var found = false;
    for (agents) |agent| {
        if (std.mem.eql(u8, agent.id, "list-agent")) {
            found = true;
            try std.testing.expect(agent.needs_hatching);
            break;
        }
    }
    try std.testing.expect(found);
}
