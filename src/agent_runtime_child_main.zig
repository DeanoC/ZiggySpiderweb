const std = @import("std");
const tool_executor = @import("ziggy-tool-runtime").tool_executor;
const tool_registry = @import("ziggy-tool-runtime").tool_registry;

const max_line_bytes: usize = 16 * 1024 * 1024;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    _ = parseAgentId(args);

    var registry = tool_registry.ToolRegistry.init(allocator);
    defer registry.deinit();
    try tool_executor.BuiltinTools.registerAll(&registry);

    const stdin_file = std.fs.File.stdin();
    const stdout_file = std.fs.File.stdout();

    while (true) {
        const line = readLineAlloc(allocator, stdin_file, max_line_bytes) catch |err| switch (err) {
            error.EndOfStream => break,
            else => {
                try writeFailureResponseLine(allocator, stdout_file, .execution_failed, @errorName(err));
                continue;
            },
        };
        defer allocator.free(line);

        var request = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch |err| {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, @errorName(err));
            continue;
        };
        defer request.deinit();

        if (request.value != .object) {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, "request must be object");
            continue;
        }

        const tool_name_val = request.value.object.get("tool") orelse {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, "tool is required");
            continue;
        };
        if (tool_name_val != .string) {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, "tool must be string");
            continue;
        }

        const args_json_val = request.value.object.get("args_json") orelse {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, "args_json is required");
            continue;
        };
        if (args_json_val != .string) {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, "args_json must be string");
            continue;
        }

        var args_parsed = std.json.parseFromSlice(std.json.Value, allocator, args_json_val.string, .{}) catch |err| {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, @errorName(err));
            continue;
        };
        defer args_parsed.deinit();
        if (args_parsed.value != .object) {
            try writeFailureResponseLine(allocator, stdout_file, .invalid_params, "args_json must decode to object");
            continue;
        }

        var result = registry.executeWorld(allocator, tool_name_val.string, args_parsed.value.object);
        defer result.deinit(allocator);

        const response_line = try buildToolResultResponseLine(allocator, result);
        defer allocator.free(response_line);
        try stdout_file.writeAll(response_line);
        try stdout_file.writeAll("\n");
    }
}

fn parseAgentId(args: []const []const u8) ?[]const u8 {
    var idx: usize = 1;
    while (idx + 1 < args.len) : (idx += 1) {
        if (std.mem.eql(u8, args[idx], "--agent-id")) {
            return args[idx + 1];
        }
    }
    return null;
}

fn readLineAlloc(allocator: std.mem.Allocator, file: std.fs.File, max_bytes: usize) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var buf: [1024]u8 = undefined;
    while (out.items.len < max_bytes) {
        const read_n = try file.read(&buf);
        if (read_n == 0) {
            if (out.items.len == 0) return error.EndOfStream;
            return out.toOwnedSlice(allocator);
        }
        const chunk = buf[0..read_n];
        if (std.mem.indexOfScalar(u8, chunk, '\n')) |idx| {
            try out.appendSlice(allocator, chunk[0..idx]);
            return out.toOwnedSlice(allocator);
        }
        try out.appendSlice(allocator, chunk);
    }

    return error.LineTooLarge;
}

fn buildToolResultResponseLine(allocator: std.mem.Allocator, result: tool_registry.ToolExecutionResult) ![]u8 {
    return switch (result) {
        .success => |success| blk: {
            const escaped_payload = try std.json.Stringify.valueAlloc(
                allocator,
                success.payload_json,
                .{
                    .emit_null_optional_fields = true,
                    .whitespace = .minified,
                },
            );
            defer allocator.free(escaped_payload);
            break :blk std.fmt.allocPrint(
                allocator,
                "{{\"ok\":true,\"payload_json\":{s}}}",
                .{escaped_payload},
            );
        },
        .failure => |failure| blk: {
            const escaped_code = try std.json.Stringify.valueAlloc(
                allocator,
                @tagName(failure.code),
                .{
                    .emit_null_optional_fields = true,
                    .whitespace = .minified,
                },
            );
            defer allocator.free(escaped_code);
            const escaped_message = try std.json.Stringify.valueAlloc(
                allocator,
                failure.message,
                .{
                    .emit_null_optional_fields = true,
                    .whitespace = .minified,
                },
            );
            defer allocator.free(escaped_message);
            break :blk std.fmt.allocPrint(
                allocator,
                "{{\"ok\":false,\"code\":{s},\"message\":{s}}}",
                .{ escaped_code, escaped_message },
            );
        },
    };
}

fn writeFailureResponseLine(
    allocator: std.mem.Allocator,
    stdout_file: std.fs.File,
    code: tool_registry.ToolErrorCode,
    message: []const u8,
) !void {
    var result = tool_registry.ToolExecutionResult{
        .failure = .{
            .code = code,
            .message = try allocator.dupe(u8, message),
        },
    };
    defer result.deinit(allocator);

    const response_line = try buildToolResultResponseLine(allocator, result);
    defer allocator.free(response_line);
    try stdout_file.writeAll(response_line);
    try stdout_file.writeAll("\n");
}
