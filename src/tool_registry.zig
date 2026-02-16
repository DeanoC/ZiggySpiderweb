const std = @import("std");

pub const ToolDomain = enum {
    world,
    brain,
};

pub const ToolParamType = enum {
    string,
    integer,
    boolean,
    array,
    object,
};

pub const ToolParam = struct {
    name: []const u8,
    param_type: ToolParamType,
    description: []const u8,
    required: bool = true,
};

pub const ToolSchema = struct {
    name: []const u8,
    description: []const u8,
    domain: ToolDomain,
    params: []const ToolParam,
};

pub const ToolResult = union(enum) {
    success: []const u8,
    failure: []const u8,
};

pub const ToolHandler = *const fn (
    allocator: std.mem.Allocator,
    args: std.json.ObjectMap,
) ToolResult;

pub const RegisteredTool = struct {
    schema: ToolSchema,
    handler: ?ToolHandler,
};

pub const ToolRegistry = struct {
    allocator: std.mem.Allocator,
    tools: std.StringHashMapUnmanaged(RegisteredTool) = .{},

    pub fn init(allocator: std.mem.Allocator) ToolRegistry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ToolRegistry) void {
        var it = self.tools.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.tools.deinit(self.allocator);
    }

    pub fn registerWorldTool(
        self: *ToolRegistry,
        name: []const u8,
        description: []const u8,
        params: []const ToolParam,
        handler: ToolHandler,
    ) !void {
        try self.registerInternal(.{
            .schema = .{
                .name = name,
                .description = description,
                .domain = .world,
                .params = params,
            },
            .handler = handler,
        });
    }

    pub fn registerBrainToolSchema(
        self: *ToolRegistry,
        name: []const u8,
        description: []const u8,
        params: []const ToolParam,
    ) !void {
        try self.registerInternal(.{
            .schema = .{
                .name = name,
                .description = description,
                .domain = .brain,
                .params = params,
            },
            .handler = null,
        });
    }

    pub fn get(self: *const ToolRegistry, name: []const u8) ?RegisteredTool {
        return self.tools.get(name);
    }

    pub fn executeWorld(
        self: *const ToolRegistry,
        allocator: std.mem.Allocator,
        name: []const u8,
        args: std.json.ObjectMap,
    ) ToolResult {
        const tool = self.get(name) orelse {
            const msg = allocator.dupe(u8, "tool_not_found") catch return .{ .failure = "oom" };
            return .{ .failure = msg };
        };

        if (tool.schema.domain != .world or tool.handler == null) {
            const msg = allocator.dupe(u8, "tool_not_executable") catch return .{ .failure = "oom" };
            return .{ .failure = msg };
        }

        return tool.handler.?(allocator, args);
    }

    pub fn generateSchemasJson(
        self: *const ToolRegistry,
        allocator: std.mem.Allocator,
        domain_filter: ?ToolDomain,
    ) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(allocator);

        try out.append(allocator, '[');
        var it = self.tools.iterator();
        var first = true;
        while (it.next()) |entry| {
            const tool = entry.value_ptr.*;
            if (domain_filter) |filter| {
                if (tool.schema.domain != filter) continue;
            }

            if (!first) try out.append(allocator, ',');
            first = false;

            try out.appendSlice(allocator, "{\"name\":\"");
            try appendEscaped(allocator, &out, tool.schema.name);
            try out.appendSlice(allocator, "\",\"description\":\"");
            try appendEscaped(allocator, &out, tool.schema.description);
            try out.appendSlice(allocator, "\",\"domain\":\"");
            try out.appendSlice(allocator, @tagName(tool.schema.domain));
            try out.appendSlice(allocator, "\",\"parameters\":{\"type\":\"object\",\"properties\":{");

            for (tool.schema.params, 0..) |param, index| {
                if (index > 0) try out.append(allocator, ',');
                try out.append(allocator, '"');
                try appendEscaped(allocator, &out, param.name);
                try out.appendSlice(allocator, "\":{\"type\":\"");
                try out.appendSlice(allocator, paramTypeString(param.param_type));
                try out.appendSlice(allocator, "\",\"description\":\"");
                try appendEscaped(allocator, &out, param.description);
                try out.appendSlice(allocator, "\"}");
            }

            try out.appendSlice(allocator, "},\"required\":[");
            var required_first = true;
            for (tool.schema.params) |param| {
                if (!param.required) continue;
                if (!required_first) try out.append(allocator, ',');
                required_first = false;
                try out.append(allocator, '"');
                try appendEscaped(allocator, &out, param.name);
                try out.append(allocator, '"');
            }
            try out.appendSlice(allocator, "]}}");
        }

        try out.append(allocator, ']');
        return out.toOwnedSlice(allocator);
    }

    fn registerInternal(self: *ToolRegistry, tool: RegisteredTool) !void {
        const name = try self.allocator.dupe(u8, tool.schema.name);
        try self.tools.put(self.allocator, name, tool);
    }
};

fn paramTypeString(param_type: ToolParamType) []const u8 {
    return switch (param_type) {
        .string => "string",
        .integer => "integer",
        .boolean => "boolean",
        .array => "array",
        .object => "object",
    };
}

fn appendEscaped(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
    for (value) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, char),
        }
    }
}

test "tool_registry: registers brain schema and emits required fields" {
    const allocator = std.testing.allocator;
    var registry = ToolRegistry.init(allocator);
    defer registry.deinit();

    try registry.registerBrainToolSchema(
        "memory.mutate",
        "Mutate memory by mem_id",
        &[_]ToolParam{
            .{ .name = "mem_id", .param_type = .string, .description = "Canonical mem id", .required = true },
            .{ .name = "content", .param_type = .object, .description = "Replacement content", .required = true },
        },
    );

    const json = try registry.generateSchemasJson(allocator, .brain);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "memory.mutate") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"required\":[\"mem_id\",\"content\"]") != null);
}
