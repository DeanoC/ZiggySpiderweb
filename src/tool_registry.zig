const std = @import("std");

/// Tool parameter type
pub const ToolParamType = enum {
    string,
    integer,
    boolean,
    array,
    object,
};

/// Tool parameter definition
pub const ToolParam = struct {
    name: []const u8,
    param_type: ToolParamType,
    description: []const u8,
    required: bool = true,
    default_value: ?[]const u8 = null,
};

/// Tool definition
pub const Tool = struct {
    name: []const u8,
    description: []const u8,
    params: []const ToolParam,
    handler: ToolHandler,

    pub const ToolHandler = *const fn (
        allocator: std.mem.Allocator,
        args: std.json.ObjectMap,
    ) ToolResult;
};

/// Tool execution result
pub const ToolResult = union(enum) {
    success: struct {
        content: []const u8,
        format: ContentFormat = .text,
    },
    failure: struct {
        code: ErrorCode,
        message: []const u8,
    },

    pub const ContentFormat = enum {
        text,
        json,
        markdown,
    };

    pub const ErrorCode = enum {
        invalid_params,
        not_found,
        execution_failed,
        permission_denied,
        timeout,
    };
};

/// Tool registry - manages available tools
pub const ToolRegistry = struct {
    allocator: std.mem.Allocator,
    tools: std.StringHashMapUnmanaged(Tool),

    pub fn init(allocator: std.mem.Allocator) ToolRegistry {
        return .{
            .allocator = allocator,
            .tools = .{},
        };
    }

    pub fn deinit(self: *ToolRegistry) void {
        var it = self.tools.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.tools.deinit(self.allocator);
    }

    /// Register a tool
    pub fn register(self: *ToolRegistry, tool: Tool) !void {
        const name_copy = try self.allocator.dupe(u8, tool.name);
        try self.tools.put(self.allocator, name_copy, tool);
    }

    /// Get a tool by name
    pub fn get(self: *const ToolRegistry, name: []const u8) ?Tool {
        return self.tools.get(name);
    }

    /// List all registered tools
    pub fn list(self: *const ToolRegistry, allocator: std.mem.Allocator) ![]Tool {
        var result = try allocator.alloc(Tool, self.tools.count());
        var it = self.tools.iterator();
        var i: usize = 0;
        while (it.next()) |entry| : (i += 1) {
            result[i] = entry.value_ptr.*;
        }
        return result;
    }

    /// Execute a tool by name with arguments
    pub fn execute(
        self: *const ToolRegistry,
        allocator: std.mem.Allocator,
        name: []const u8,
        args: std.json.ObjectMap,
    ) ToolResult {
        const tool = self.get(name) orelse {
            const msg = allocator.dupe(u8, "Tool not found") catch return .{ .failure = .{ .code = .execution_failed, .message = @import("tool_executor.zig").OOM_MSG } };
            return .{ .failure = .{
                .code = .not_found,
                .message = msg,
            } };
        };
        return tool.handler(allocator, args);
    }

    /// Generate JSON schema for all tools (for LLM)
    pub fn generateSchemasJson(
        self: *const ToolRegistry,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        var json = std.ArrayListUnmanaged(u8){};
        defer json.deinit(allocator);

        try json.appendSlice(allocator, "[");

        var it = self.tools.iterator();
        var first = true;
        while (it.next()) |entry| {
            if (!first) try json.appendSlice(allocator, ",");
            first = false;

            const tool = entry.value_ptr.*;
            try json.appendSlice(allocator, "{\"name\":\"");
            try json.appendSlice(allocator, tool.name);
            try json.appendSlice(allocator, "\",\"description\":\"");
            try json.appendSlice(allocator, tool.description);
            try json.appendSlice(allocator, "\",\"parameters\":{");
            try json.appendSlice(allocator, "\"type\":\"object\",\"properties\":{");

            for (tool.params, 0..) |param, i| {
                if (i > 0) try json.appendSlice(allocator, ",");
                try json.appendSlice(allocator, "\"");
                try json.appendSlice(allocator, param.name);
                try json.appendSlice(allocator, "\":{\"type\":\"");
                try json.appendSlice(allocator, paramTypeToString(param.param_type));
                try json.appendSlice(allocator, "\",\"description\":\"");
                try json.appendSlice(allocator, param.description);
                try json.appendSlice(allocator, "\"}");
            }

            try json.appendSlice(allocator, "},\"required\":[");
            var req_first = true;
            for (tool.params) |param| {
                if (!param.required) continue;
                if (!req_first) try json.appendSlice(allocator, ",");
                req_first = false;
                try json.appendSlice(allocator, "\"");
                try json.appendSlice(allocator, param.name);
                try json.appendSlice(allocator, "\"");
            }
            try json.appendSlice(allocator, "]}}");
        }

        try json.appendSlice(allocator, "]");
        return json.toOwnedSlice(allocator);
    }
};

fn paramTypeToString(param_type: ToolParamType) []const u8 {
    return switch (param_type) {
        .string => "string",
        .integer => "integer",
        .boolean => "boolean",
        .array => "array",
        .object => "object",
    };
}

test "tool_registry: register and get" {
    const allocator = std.testing.allocator;
    var registry = ToolRegistry.init(allocator);
    defer registry.deinit();

    const test_tool = Tool{
        .name = "test_echo",
        .description = "Echoes input back",
        .params = &[_]ToolParam{
            .{
                .name = "message",
                .param_type = .string,
                .description = "Message to echo",
            },
        },
        .handler = struct {
            fn handle(alloc: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
                const msg = args.get("message") orelse return .{ .failure = .{
                    .code = .invalid_params,
                    .message = "Missing message parameter",
                } };
                if (msg != .string) return .{ .failure = .{
                    .code = .invalid_params,
                    .message = "Message must be a string",
                } };
                const copy = alloc.dupe(u8, msg.string) catch return .{ .failure = .{
                    .code = .execution_failed,
                    .message = "Out of memory",
                } };
                return .{ .success = .{ .content = copy } };
            }
        }.handle,
    };

    try registry.register(test_tool);

    const retrieved = registry.get("test_echo").?;
    try std.testing.expectEqualStrings("test_echo", retrieved.name);
}
