const std = @import("std");

pub const GoalPlan = struct {
    goal: []const u8,
    tasks: std.ArrayListUnmanaged([]const u8),
    response_text: []const u8,
};

pub fn buildPlan(allocator: std.mem.Allocator, raw_goal: []const u8) !GoalPlan {
    const goal = std.mem.trim(u8, raw_goal, " \t\r\n");
    if (goal.len == 0) return error.EmptyGoal;

    var tasks = std.ArrayListUnmanaged([]const u8){};
    errdefer {
        for (tasks.items) |task| allocator.free(task);
        tasks.deinit(allocator);
    }

    try collectTaskCandidates(allocator, goal, &tasks);
    if (tasks.items.len == 0) {
        try appendTask(allocator, &tasks, "Understand the goal and required outcome");
        try appendTask(allocator, &tasks, "Collect key constraints and required inputs");
        try appendTask(allocator, &tasks, "Produce an actionable result and next steps");
    }

    if (tasks.items.len > 5) {
        while (tasks.items.len > 5) {
            _ = tasks.pop();
        }
    }

    const response_text = try std.fmt.allocPrint(
        allocator,
        "I have a deterministic plan with {d} task(s) for this goal.",
        .{tasks.items.len},
    );

    return .{
        .goal = try allocator.dupe(u8, goal),
        .tasks = tasks,
        .response_text = response_text,
    };
}

pub fn deinitPlan(allocator: std.mem.Allocator, plan: *GoalPlan) void {
    if (plan.goal.len > 0) allocator.free(plan.goal);
    plan.goal = &[_]u8{};

    for (plan.tasks.items) |task| allocator.free(task);
    plan.tasks.deinit(allocator);

    if (plan.response_text.len > 0) allocator.free(plan.response_text);
    plan.response_text = &[_]u8{};
}

pub fn formatPlanMemoryText(allocator: std.mem.Allocator, plan: *const GoalPlan) ![]const u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "Primary Brain plan for goal: ");
    try out.appendSlice(allocator, plan.goal);
    try out.appendSlice(allocator, "\n");

    for (plan.tasks.items, 0..) |task, idx| {
        if (idx > 0) {
            try out.appendSlice(allocator, "\n");
        }
        const prefix = try std.fmt.allocPrint(allocator, "{d}. ", .{idx + 1});
        defer allocator.free(prefix);
        try out.appendSlice(allocator, prefix);
        try out.appendSlice(allocator, task);
    }

    const text = try allocator.alloc(u8, out.items.len);
    @memcpy(text, out.items);
    return text;
}

fn collectTaskCandidates(
    allocator: std.mem.Allocator,
    goal: []const u8,
    tasks: *std.ArrayListUnmanaged([]const u8),
) !void {
    const has_line_breaks = std.mem.indexOf(u8, goal, "\n") != null;
    const has_semicolon = std.mem.indexOf(u8, goal, ";") != null;
    if (has_semicolon or has_line_breaks) {
        var it = std.mem.splitAny(u8, goal, ";\n");
        while (it.next()) |candidate| {
            try appendTask(allocator, tasks, candidate);
        }
        return;
    }

    if (std.mem.indexOf(u8, goal, " and ")) |_| {
        var it = std.mem.splitSequence(u8, goal, " and ");
        while (it.next()) |candidate| {
            try appendTask(allocator, tasks, candidate);
        }
        return;
    }

    if (std.mem.indexOf(u8, goal, ",")) |idx| {
        _ = idx;
        var it = std.mem.splitAny(u8, goal, ",");
        var count: usize = 0;
        while (it.next()) |candidate| {
            count += 1;
            try appendTask(allocator, tasks, candidate);
        }
        if (count > 1) return;
    }

    if (tasks.items.len == 0) {
        var sentence_iter = std.mem.splitAny(u8, goal, ".!?");
        while (sentence_iter.next()) |candidate| {
            try appendTask(allocator, tasks, candidate);
        }
    }
}

fn appendTask(
    allocator: std.mem.Allocator,
    tasks: *std.ArrayListUnmanaged([]const u8),
    candidate: []const u8,
) !void {
    const trimmed = sanitizeTaskLine(candidate);
    if (trimmed.len == 0) return;
    try tasks.append(allocator, try allocator.dupe(u8, trimmed));
}

fn sanitizeTaskLine(raw: []const u8) []const u8 {
    var text = std.mem.trim(u8, raw, " \t\r\n");
    if (text.len == 0) return text;

    if (std.mem.startsWith(u8, text, "- ") or std.mem.startsWith(u8, text, "* ") or std.mem.startsWith(u8, text, "+ ")) {
        text = text[2..];
    }

    if (text.len > 3 and std.ascii.isDigit(text[0]) and (text[1] == '.' or text[1] == ')') and text[2] == ' ') {
        text = text[3..];
    } else if (text.len > 2 and std.mem.startsWith(u8, text, "Task ")) {
        text = std.mem.trim(u8, text[4..], " \t\r\n-:.");
    }

    text = std.mem.trim(u8, text, " \t\r\n-.");
    return text;
}

test "orchestrator: builds deterministic tasks from goal with conjunctions" {
    const allocator = std.testing.allocator;
    var plan = try buildPlan(allocator, "Find open PRs and summarize findings and propose next steps");
    defer deinitPlan(allocator, &plan);

    try std.testing.expectEqualStrings("Find open PRs and summarize findings and propose next steps", plan.goal);
    try std.testing.expect(plan.tasks.items.len >= 1);
    try std.testing.expectEqualStrings(
        "Find open PRs",
        plan.tasks.items[0],
    );
    try std.testing.expectEqualStrings(
        "summarize findings",
        plan.tasks.items[1],
    );
    try std.testing.expectEqualStrings(
        "propose next steps",
        plan.tasks.items[2],
    );
}

test "orchestrator: fallback plan for empty candidate goals" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.EmptyGoal, buildPlan(allocator, "   "));
}
