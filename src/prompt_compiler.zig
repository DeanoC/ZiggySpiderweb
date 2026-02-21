const std = @import("std");

pub const PromptInput = struct {
    core_prompt: []const u8,
    policy: []const u8,
    loop_contract: []const u8,
    tool_contract: []const u8,
    completion_contract: []const u8,
    task_goal: []const u8,
    dynamic_board: []const u8,
    working_memory_snapshot: []const u8,
    ltm_summary: []const u8,
};

pub fn compile(allocator: std.mem.Allocator, input: PromptInput) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    if (input.core_prompt.len > 0) {
        try out.appendSlice(allocator, input.core_prompt);
        if (input.core_prompt[input.core_prompt.len - 1] != '\n') {
            try out.appendSlice(allocator, "\n");
        }
        try out.appendSlice(allocator, "\n");
    }

    try appendSection(&out, allocator, "Policy", input.policy);
    try appendSection(&out, allocator, "Runtime Loop Contract", input.loop_contract);
    try appendSection(&out, allocator, "Tooling Contract", input.tool_contract);
    try appendSection(&out, allocator, "Completion Contract", input.completion_contract);
    try appendSection(&out, allocator, "Task Goal", input.task_goal);
    try appendSection(&out, allocator, "Dynamic Info Board", input.dynamic_board);
    try appendSection(&out, allocator, "Working Memory Snapshot", input.working_memory_snapshot);
    try appendSection(&out, allocator, "Long-Term Memory Summary", input.ltm_summary);

    return out.toOwnedSlice(allocator);
}

fn appendSection(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    title: []const u8,
    body: []const u8,
) !void {
    try out.appendSlice(allocator, "## ");
    try out.appendSlice(allocator, title);
    try out.appendSlice(allocator, "\n");
    if (body.len > 0) {
        try out.appendSlice(allocator, body);
        if (body[body.len - 1] != '\n') {
            try out.appendSlice(allocator, "\n");
        }
    } else {
        try out.appendSlice(allocator, "(empty)\n");
    }
    try out.appendSlice(allocator, "\n");
}

test "prompt_compiler: preserves deterministic section order" {
    const allocator = std.testing.allocator;
    const rendered = try compile(allocator, .{
        .core_prompt = "core",
        .policy = "policy",
        .loop_contract = "loop",
        .tool_contract = "tool",
        .completion_contract = "complete",
        .task_goal = "goal",
        .dynamic_board = "board",
        .working_memory_snapshot = "work",
        .ltm_summary = "ltm",
    });
    defer allocator.free(rendered);

    const policy_idx = std.mem.indexOf(u8, rendered, "## Policy") orelse return error.TestUnexpectedResult;
    const loop_idx = std.mem.indexOf(u8, rendered, "## Runtime Loop Contract") orelse return error.TestUnexpectedResult;
    const tool_idx = std.mem.indexOf(u8, rendered, "## Tooling Contract") orelse return error.TestUnexpectedResult;
    const completion_idx = std.mem.indexOf(u8, rendered, "## Completion Contract") orelse return error.TestUnexpectedResult;

    try std.testing.expect(policy_idx < loop_idx);
    try std.testing.expect(loop_idx < tool_idx);
    try std.testing.expect(tool_idx < completion_idx);
}
