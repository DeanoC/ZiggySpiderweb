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

pub const ToolErrorCode = enum {
    invalid_params,
    permission_denied,
    timeout,
    execution_failed,
    tool_not_found,
    tool_not_executable,
};

pub const ToolExecutionResult = union(enum) {
    success: struct {
        payload_json: []u8,
    },
    failure: struct {
        code: ToolErrorCode,
        message: []u8,
    },

    pub fn deinit(self: *ToolExecutionResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*success| allocator.free(success.payload_json),
            .failure => |*failure| allocator.free(failure.message),
        }
        self.* = undefined;
    }
};

pub const ToolHandler = *const fn (
    allocator: std.mem.Allocator,
    args: std.json.ObjectMap,
) ToolExecutionResult;

pub const RegisteredTool = struct {
    schema: ToolSchema,
    handler: ?ToolHandler,
};

pub const ProviderTool = struct {
    name: []u8,
    description: []u8,
    parameters_json: []u8,

    pub fn deinit(self: *ProviderTool, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.description);
        allocator.free(self.parameters_json);
        self.* = undefined;
    }
};

pub fn deinitProviderTools(allocator: std.mem.Allocator, tools: []ProviderTool) void {
    for (tools) |*tool| tool.deinit(allocator);
    allocator.free(tools);
}

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
    ) ToolExecutionResult {
        const tool = self.get(name) orelse {
            const msg = allocator.dupe(u8, "tool not found") catch return .{ .failure = .{
                .code = .execution_failed,
                .message = allocator.dupe(u8, "out of memory") catch @panic("out of memory while reporting error"),
            } };
            return .{ .failure = .{ .code = .tool_not_found, .message = msg } };
        };

        if (tool.schema.domain != .world or tool.handler == null) {
            const msg = allocator.dupe(u8, "tool is not executable") catch return .{ .failure = .{
                .code = .execution_failed,
                .message = allocator.dupe(u8, "out of memory") catch @panic("out of memory while reporting error"),
            } };
            return .{ .failure = .{ .code = .tool_not_executable, .message = msg } };
        }

        return tool.handler.?(allocator, args);
    }

    pub fn exportProviderWorldTools(self: *const ToolRegistry, allocator: std.mem.Allocator) ![]ProviderTool {
        var out = std.ArrayListUnmanaged(ProviderTool){};
        errdefer {
            for (out.items) |*tool| tool.deinit(allocator);
            out.deinit(allocator);
        }

        var it = self.tools.iterator();
        while (it.next()) |entry| {
            const tool = entry.value_ptr.*;
            if (tool.schema.domain != .world) continue;

            var parameters = std.ArrayListUnmanaged(u8){};
            errdefer parameters.deinit(allocator);

            try parameters.appendSlice(allocator, "{\"type\":\"object\",\"properties\":{");
            for (tool.schema.params, 0..) |param, idx| {
                if (idx > 0) try parameters.append(allocator, ',');
                try parameters.append(allocator, '"');
                try appendEscaped(allocator, &parameters, param.name);
                try parameters.appendSlice(allocator, "\":{\"type\":\"");
                try parameters.appendSlice(allocator, paramTypeString(param.param_type));
                try parameters.appendSlice(allocator, "\",\"description\":\"");
                try appendEscaped(allocator, &parameters, param.description);
                try parameters.appendSlice(allocator, "\"}");
            }

            try parameters.appendSlice(allocator, "},\"required\":[");
            var required_first = true;
            for (tool.schema.params) |param| {
                if (!param.required) continue;
                if (!required_first) try parameters.append(allocator, ',');
                required_first = false;
                try parameters.append(allocator, '"');
                try appendEscaped(allocator, &parameters, param.name);
                try parameters.append(allocator, '"');
            }
            try parameters.appendSlice(allocator, "]}");

            try out.append(allocator, .{
                .name = try allocator.dupe(u8, tool.schema.name),
                .description = try allocator.dupe(u8, tool.schema.description),
                .parameters_json = try parameters.toOwnedSlice(allocator),
            });
        }

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

    try std.testing.expect(registry.get("memory.mutate") != null);
}
