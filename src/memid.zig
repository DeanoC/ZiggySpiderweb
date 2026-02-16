const std = @import("std");

pub const EOT_MARKER = "<EOT>";

pub const MemIdError = error{
    InvalidFormat,
    InvalidVersion,
    InvalidComponent,
};

pub const MemId = struct {
    agent: []const u8,
    brain: []const u8,
    name: []const u8,
    version: ?u64,

    pub fn parse(raw: []const u8) MemIdError!MemId {
        if (!std.mem.startsWith(u8, raw, EOT_MARKER) or !std.mem.endsWith(u8, raw, EOT_MARKER)) {
            return MemIdError.InvalidFormat;
        }

        if (raw.len <= EOT_MARKER.len * 2) return MemIdError.InvalidFormat;
        const inner = raw[EOT_MARKER.len .. raw.len - EOT_MARKER.len];

        var parts = std.mem.splitScalar(u8, inner, ':');
        const agent = parts.next() orelse return MemIdError.InvalidFormat;
        const brain = parts.next() orelse return MemIdError.InvalidFormat;
        const name = parts.next() orelse return MemIdError.InvalidFormat;
        const version_text = parts.next() orelse return MemIdError.InvalidFormat;
        if (parts.next() != null) return MemIdError.InvalidFormat;

        try validateComponent(agent);
        try validateComponent(brain);
        try validateComponent(name);

        const version: ?u64 = if (std.mem.eql(u8, version_text, "latest"))
            null
        else
            std.fmt.parseInt(u64, version_text, 10) catch return MemIdError.InvalidVersion;

        return .{
            .agent = agent,
            .brain = brain,
            .name = name,
            .version = version,
        };
    }

    pub fn validate(raw: []const u8) MemIdError!void {
        _ = try MemId.parse(raw);
    }

    pub fn format(self: MemId, allocator: std.mem.Allocator) ![]u8 {
        var version_buf: [32]u8 = undefined;
        const version_text = if (self.version) |version|
            try std.fmt.bufPrint(&version_buf, "{d}", .{version})
        else
            "latest";

        return std.fmt.allocPrint(
            allocator,
            "{s}{s}:{s}:{s}:{s}{s}",
            .{
                EOT_MARKER,
                self.agent,
                self.brain,
                self.name,
                version_text,
                EOT_MARKER,
            },
        );
    }

    pub fn formatBase(self: MemId, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{s}:{s}", .{ self.agent, self.brain, self.name });
    }

    pub fn withVersion(self: MemId, version: ?u64) MemId {
        return .{
            .agent = self.agent,
            .brain = self.brain,
            .name = self.name,
            .version = version,
        };
    }
};

fn validateComponent(component: []const u8) MemIdError!void {
    if (component.len == 0) return MemIdError.InvalidComponent;
    for (component) |char| {
        const ok = std.ascii.isAlphanumeric(char) or char == '_' or char == '-' or char == '.';
        if (!ok) return MemIdError.InvalidComponent;
    }
}

test "memid: parse + format round-trip" {
    const allocator = std.testing.allocator;
    const raw = "<EOT>AgentA:primary:task_plan:12<EOT>";

    const parsed = try MemId.parse(raw);
    try std.testing.expectEqualStrings("AgentA", parsed.agent);
    try std.testing.expectEqualStrings("primary", parsed.brain);
    try std.testing.expectEqualStrings("task_plan", parsed.name);
    try std.testing.expectEqual(@as(?u64, 12), parsed.version);

    const rendered = try parsed.format(allocator);
    defer allocator.free(rendered);
    try std.testing.expectEqualStrings(raw, rendered);
}

test "memid: latest alias maps to null version" {
    const allocator = std.testing.allocator;
    const parsed = try MemId.parse("<EOT>agent:sub:cache:latest<EOT>");
    try std.testing.expectEqual(@as(?u64, null), parsed.version);

    const rendered = try parsed.format(allocator);
    defer allocator.free(rendered);
    try std.testing.expectEqualStrings("<EOT>agent:sub:cache:latest<EOT>", rendered);
}

test "memid: rejects invalid forms" {
    try std.testing.expectError(MemIdError.InvalidFormat, MemId.parse("Agent:primary:x:1"));
    try std.testing.expectError(MemIdError.InvalidVersion, MemId.parse("<EOT>Agent:primary:x:not-a-number<EOT>"));
    try std.testing.expectError(MemIdError.InvalidComponent, MemId.parse("<EOT>Agent:primary bad:x:1<EOT>"));
}
