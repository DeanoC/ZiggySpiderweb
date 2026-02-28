const std = @import("std");
const tool_executor = @import("ziggy-tool-runtime").tool_executor;
const tool_registry = @import("ziggy-tool-runtime").tool_registry;

const max_line_bytes: usize = 16 * 1024 * 1024;
const file_list_timeout_ms: usize = 5_000;

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

        var result = executeWorldToolNoPanic(allocator, &registry, tool_name_val.string, args_parsed.value.object);
        defer result.deinit(allocator);

        const response_line = try buildToolResultResponseLine(allocator, result);
        defer allocator.free(response_line);
        try stdout_file.writeAll(response_line);
        try stdout_file.writeAll("\n");
    }
}

fn executeWorldToolNoPanic(
    allocator: std.mem.Allocator,
    registry: *tool_registry.ToolRegistry,
    tool_name: []const u8,
    args: std.json.ObjectMap,
) tool_registry.ToolExecutionResult {
    if (std.mem.eql(u8, tool_name, "file_list")) {
        return safeFileList(allocator, args);
    }
    return registry.executeWorld(allocator, tool_name, args);
}

fn safeFileList(
    allocator: std.mem.Allocator,
    args: std.json.ObjectMap,
) tool_registry.ToolExecutionResult {
    const path = blk: {
        const maybe = args.get("path") orelse break :blk ".";
        if (maybe != .string) return failResult(allocator, .invalid_params, "path must be string");
        break :blk maybe.string;
    };
    const recursive = blk: {
        const maybe = args.get("recursive") orelse break :blk false;
        if (maybe != .bool) return failResult(allocator, .invalid_params, "recursive must be boolean");
        break :blk maybe.bool;
    };
    const max_entries = blk: {
        const maybe = args.get("max_entries") orelse break :blk @as(usize, 500);
        if (maybe != .integer or maybe.integer < 0) {
            return failResult(allocator, .invalid_params, "max_entries must be integer");
        }
        break :blk @as(usize, @intCast(maybe.integer));
    };
    const effective_max = @min(max_entries, 5000);

    if (!isSafeRelativePath(path)) {
        return failResult(allocator, .permission_denied, "path must be relative and stay within workspace");
    }

    var payload = std.ArrayListUnmanaged(u8){};
    errdefer payload.deinit(allocator);

    payload.appendSlice(allocator, "{\"path\":\"") catch return failResult(allocator, .execution_failed, "out of memory");
    appendJsonEscaped(allocator, &payload, path) catch return failResult(allocator, .execution_failed, "out of memory");
    payload.appendSlice(allocator, "\",\"entries\":[") catch return failResult(allocator, .execution_failed, "out of memory");

    var first = true;
    var count: usize = 0;
    var truncated = false;
    const start_ms = std.time.milliTimestamp();
    var root_dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| {
        return failFileListFsError(allocator, err);
    };
    defer root_dir.close();
    walkFileListDirectory(
        allocator,
        &payload,
        &first,
        &count,
        &truncated,
        &root_dir,
        "",
        recursive,
        effective_max,
        start_ms,
    ) catch |err| {
        return failFileListFsError(allocator, err);
    };

    payload.appendSlice(allocator, "],\"truncated\":") catch return failResult(allocator, .execution_failed, "out of memory");
    payload.appendSlice(allocator, if (truncated) "true" else "false") catch return failResult(allocator, .execution_failed, "out of memory");

    payload.append(allocator, '}') catch return failResult(allocator, .execution_failed, "out of memory");
    return .{
        .success = .{
            .payload_json = payload.toOwnedSlice(allocator) catch return failResult(allocator, .execution_failed, "out of memory"),
        },
    };
}

fn walkFileListDirectory(
    allocator: std.mem.Allocator,
    payload: *std.ArrayListUnmanaged(u8),
    first: *bool,
    count: *usize,
    truncated: *bool,
    dir: *std.fs.Dir,
    prefix: []const u8,
    recursive: bool,
    max_entries: usize,
    start_ms: i64,
) anyerror!void {
    var it = dir.iterate();
    while (try it.next()) |entry| {
        try checkFileListTimeout(start_ms);
        if (entry.name.len == 0) continue;
        if (count.* >= max_entries) {
            truncated.* = true;
            return;
        }

        const display_name = if (prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, entry.name });
        defer allocator.free(display_name);

        const kind = mapDirEntryKind(entry.kind);
        try appendFileListEntry(allocator, payload, first, count, display_name, kind);

        if (!recursive or entry.kind != .directory) continue;
        if (count.* >= max_entries) {
            truncated.* = true;
            return;
        }

        var child = try dir.openDir(entry.name, .{ .iterate = true });
        defer child.close();
        try walkFileListDirectory(
            allocator,
            payload,
            first,
            count,
            truncated,
            &child,
            display_name,
            recursive,
            max_entries,
            start_ms,
        );
        if (truncated.*) return;
    }
}

fn appendFileListEntry(
    allocator: std.mem.Allocator,
    payload: *std.ArrayListUnmanaged(u8),
    first: *bool,
    count: *usize,
    name: []const u8,
    kind: []const u8,
) !void {
    if (!first.*) try payload.append(allocator, ',');
    first.* = false;
    count.* += 1;

    try payload.appendSlice(allocator, "{\"name\":\"");
    try appendJsonEscaped(allocator, payload, name);
    try payload.appendSlice(allocator, "\",\"type\":\"");
    try payload.appendSlice(allocator, kind);
    try payload.appendSlice(allocator, "\"}");
}

fn checkFileListTimeout(start_ms: i64) !void {
    const now_ms = std.time.milliTimestamp();
    if (now_ms - start_ms > @as(i64, @intCast(file_list_timeout_ms))) {
        return error.FileListTimedOut;
    }
}

fn failFileListFsError(
    allocator: std.mem.Allocator,
    err: anyerror,
) tool_registry.ToolExecutionResult {
    if (err == error.FileListTimedOut) {
        return failResult(allocator, .timeout, "file_list timed out before completion");
    }
    if (isMountUnavailableErrorName(@errorName(err))) {
        return failResult(
            allocator,
            .execution_failed,
            "filesystem_unavailable: project mount unavailable (input/output error)",
        );
    }
    return failResult(allocator, .execution_failed, @errorName(err));
}

fn failResult(
    allocator: std.mem.Allocator,
    code: tool_registry.ToolErrorCode,
    message: []const u8,
) tool_registry.ToolExecutionResult {
    return .{
        .failure = .{
            .code = code,
            .message = allocator.dupe(u8, message) catch allocator.dupe(u8, "out of memory") catch @panic("out of memory"),
        },
    };
}

fn isSafeRelativePath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.fs.path.isAbsolute(path)) return false;
    if (path[0] == '~') return false;
    if (path[0] == '-') return false;

    var parts = std.mem.splitScalar(u8, path, std.fs.path.sep);
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn mapDirEntryKind(kind: std.fs.Dir.Entry.Kind) []const u8 {
    return switch (kind) {
        .file => "file",
        .directory => "directory",
        .sym_link => "symlink",
        else => "other",
    };
}

fn isMountUnavailableErrorName(error_name: []const u8) bool {
    const markers = [_][]const u8{
        "inputoutput",
        "transportendpointisnotconnected",
        "stalefilehandle",
        "nodevice",
        "connectionreset",
        "connectiontimedout",
    };
    for (markers) |marker| {
        if (std.ascii.indexOfIgnoreCase(error_name, marker) != null) return true;
    }
    return false;
}

test "agent_runtime_child_main: mount-unavailable error-name markers" {
    try std.testing.expect(isMountUnavailableErrorName("InputOutput"));
    try std.testing.expect(isMountUnavailableErrorName("StaleFileHandle"));
    try std.testing.expect(isMountUnavailableErrorName("ConnectionTimedOut"));
    try std.testing.expect(!isMountUnavailableErrorName("FileNotFound"));
}

fn appendJsonEscaped(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
    for (value) |c| {
        switch (c) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => if (c < 0x20) {
                try out.writer(allocator).print("\\u00{x:0>2}", .{c});
            } else {
                try out.append(allocator, c);
            },
        }
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
