const std = @import("std");
const tool_executor = @import("ziggy-tool-runtime").tool_executor;
const tool_registry = @import("ziggy-tool-runtime").tool_registry;

const max_line_bytes: usize = 16 * 1024 * 1024;
const file_list_timeout_ms: usize = 5_000;
const workspace_root_env = "SPIDERWEB_WORKSPACE_ROOT";
const sandbox_namespace_allowed_roots = [_][]const u8{
    "/workspace",
    "/agents",
    "/nodes",
    "/projects",
    "/meta",
    "/global",
};

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
    if (std.mem.eql(u8, tool_name, "file_read")) {
        return safeFileRead(allocator, args);
    }
    if (std.mem.eql(u8, tool_name, "file_write")) {
        return safeFileWrite(allocator, args);
    }
    if (std.mem.eql(u8, tool_name, "file_list")) {
        return safeFileList(allocator, args);
    }
    return registry.executeWorld(allocator, tool_name, args);
}

fn safeFileRead(
    allocator: std.mem.Allocator,
    args: std.json.ObjectMap,
) tool_registry.ToolExecutionResult {
    const path_value = args.get("path") orelse return failResult(allocator, .invalid_params, "missing required parameter: path");
    if (path_value != .string) return failResult(allocator, .invalid_params, "path must be string");
    const path = path_value.string;

    if (validatePathOwned(allocator, path)) |message| {
        defer allocator.free(message);
        return failResult(allocator, .permission_denied, message);
    }

    const max_bytes = blk: {
        const maybe = args.get("max_bytes") orelse break :blk @as(usize, tool_executor.DEFAULT_MAX_FILE_READ_BYTES);
        if (maybe != .integer or maybe.integer < 0) {
            return failResult(allocator, .invalid_params, "max_bytes must be a non-negative integer");
        }
        break :blk @as(usize, @intCast(maybe.integer));
    };
    const wait_until_ready = blk: {
        const maybe = args.get("wait_until_ready") orelse break :blk true;
        if (maybe != .bool) return failResult(allocator, .invalid_params, "wait_until_ready must be boolean");
        break :blk maybe.bool;
    };
    const effective_max = @min(max_bytes, 8 * 1024 * 1024);

    const workspace_real = getWorkspaceRootRealpath(allocator) catch |err| {
        return failResult(allocator, .execution_failed, @errorName(err));
    };
    defer allocator.free(workspace_real);
    const absolute_path = resolveAbsolutePathInWorkspace(allocator, workspace_real, path) catch {
        return failResult(allocator, .execution_failed, "out of memory");
    };
    defer allocator.free(absolute_path);

    var file: std.fs.File = blk: {
        if (wait_until_ready) {
            break :blk std.fs.openFileAbsolute(absolute_path, .{}) catch |err| {
                return failResult(allocator, .execution_failed, @errorName(err));
            };
        }

        const fd = std.posix.open(
            absolute_path,
            .{
                .ACCMODE = .RDONLY,
                .NONBLOCK = true,
                .CLOEXEC = true,
            },
            0,
        ) catch |err| {
            if (isWouldBlockError(err)) {
                const payload = buildFileReadPayload(allocator, path, 0, false, "", false, false) catch {
                    return failResult(allocator, .execution_failed, "out of memory");
                };
                return .{ .success = .{ .payload_json = payload } };
            }
            return failResult(allocator, .execution_failed, @errorName(err));
        };
        break :blk .{ .handle = fd };
    };
    defer file.close();

    const file_size = if (file.stat()) |stat| stat.size else |_| 0;
    const content_buffer = allocator.alloc(u8, effective_max) catch return failResult(allocator, .execution_failed, "out of memory");
    defer allocator.free(content_buffer);
    const content_len = if (wait_until_ready)
        file.readAll(content_buffer) catch |err| return failResult(allocator, .execution_failed, @errorName(err))
    else
        file.read(content_buffer) catch |err| {
            if (isWouldBlockError(err)) {
                const payload = buildFileReadPayload(allocator, path, 0, false, "", false, false) catch {
                    return failResult(allocator, .execution_failed, "out of memory");
                };
                return .{ .success = .{ .payload_json = payload } };
            }
            return failResult(allocator, .execution_failed, @errorName(err));
        };
    const raw_content = content_buffer[0..content_len];
    const truncated = file_size > content_len;
    const content = if (truncated) utf8SafePrefix(raw_content) else raw_content;
    const payload = buildFileReadPayload(
        allocator,
        path,
        content.len,
        truncated,
        content,
        true,
        wait_until_ready,
    ) catch return failResult(allocator, .execution_failed, "out of memory");
    return .{ .success = .{ .payload_json = payload } };
}

fn safeFileWrite(
    allocator: std.mem.Allocator,
    args: std.json.ObjectMap,
) tool_registry.ToolExecutionResult {
    const path_value = args.get("path") orelse return failResult(allocator, .invalid_params, "missing required parameter: path");
    if (path_value != .string) return failResult(allocator, .invalid_params, "path must be string");
    const content_value = args.get("content") orelse return failResult(allocator, .invalid_params, "missing required parameter: content");
    if (content_value != .string) return failResult(allocator, .invalid_params, "content must be string");
    const path = path_value.string;
    const content = content_value.string;

    if (validatePathOwned(allocator, path)) |message| {
        defer allocator.free(message);
        return failResult(allocator, .permission_denied, message);
    }

    const append = blk: {
        const maybe = args.get("append") orelse break :blk false;
        if (maybe != .bool) return failResult(allocator, .invalid_params, "append must be boolean");
        break :blk maybe.bool;
    };
    const create_parents = blk: {
        const maybe = args.get("create_parents") orelse break :blk true;
        if (maybe != .bool) return failResult(allocator, .invalid_params, "create_parents must be boolean");
        break :blk maybe.bool;
    };
    const wait_until_ready = blk: {
        const maybe = args.get("wait_until_ready") orelse break :blk true;
        if (maybe != .bool) return failResult(allocator, .invalid_params, "wait_until_ready must be boolean");
        break :blk maybe.bool;
    };

    const workspace_real = getWorkspaceRootRealpath(allocator) catch |err| {
        return failResult(allocator, .execution_failed, @errorName(err));
    };
    defer allocator.free(workspace_real);
    const absolute_path = resolveAbsolutePathInWorkspace(allocator, workspace_real, path) catch {
        return failResult(allocator, .execution_failed, "out of memory");
    };
    defer allocator.free(absolute_path);

    if (create_parents) {
        ensureAbsoluteParentDir(absolute_path) catch |err| return failResult(allocator, .execution_failed, @errorName(err));
    }

    var bytes_written: usize = 0;
    var ready = true;
    if (wait_until_ready) {
        if (append) {
            var file = std.fs.createFileAbsolute(absolute_path, .{ .truncate = false }) catch |err| return failResult(allocator, .execution_failed, @errorName(err));
            defer file.close();
            file.seekFromEnd(0) catch |err| return failResult(allocator, .execution_failed, @errorName(err));
            file.writeAll(content) catch |err| return failResult(allocator, .execution_failed, @errorName(err));
        } else {
            var file = std.fs.createFileAbsolute(absolute_path, .{ .truncate = true }) catch |err| return failResult(allocator, .execution_failed, @errorName(err));
            defer file.close();
            file.writeAll(content) catch |err| return failResult(allocator, .execution_failed, @errorName(err));
        }
        bytes_written = content.len;
    } else {
        const fd = std.posix.open(
            absolute_path,
            .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = !append,
                .APPEND = append,
                .NONBLOCK = true,
                .CLOEXEC = true,
            },
            0o644,
        ) catch |err| {
            if (isWouldBlockError(err)) {
                const payload = buildFileWritePayload(allocator, path, 0, append, false, false) catch {
                    return failResult(allocator, .execution_failed, "out of memory");
                };
                return .{ .success = .{ .payload_json = payload } };
            }
            return failResult(allocator, .execution_failed, @errorName(err));
        };
        var file = std.fs.File{ .handle = fd };
        defer file.close();
        while (bytes_written < content.len) {
            const written_now = file.write(content[bytes_written..]) catch |err| {
                if (isWouldBlockError(err)) {
                    ready = false;
                    break;
                }
                return failResult(allocator, .execution_failed, @errorName(err));
            };
            if (written_now == 0) {
                ready = false;
                break;
            }
            bytes_written += written_now;
        }
    }
    const payload = buildFileWritePayload(
        allocator,
        path,
        bytes_written,
        append,
        ready,
        wait_until_ready,
    ) catch return failResult(allocator, .execution_failed, "out of memory");
    return .{ .success = .{ .payload_json = payload } };
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

    if (validatePathOwned(allocator, path)) |message| {
        defer allocator.free(message);
        return failResult(allocator, .permission_denied, message);
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
    const workspace_real = getWorkspaceRootRealpath(allocator) catch |err| {
        return failResult(allocator, .execution_failed, @errorName(err));
    };
    defer allocator.free(workspace_real);
    const absolute_path = resolveAbsolutePathInWorkspace(allocator, workspace_real, path) catch {
        return failResult(allocator, .execution_failed, "out of memory");
    };
    defer allocator.free(absolute_path);

    var root_dir = std.fs.openDirAbsolute(absolute_path, .{ .iterate = true }) catch |err| {
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

fn ensureAbsoluteParentDir(path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (std.fs.path.isAbsolute(parent)) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        const rel_parent = std.mem.trimLeft(u8, parent, "/");
        if (rel_parent.len == 0) return;
        try root.makePath(rel_parent);
        return;
    }
    try std.fs.cwd().makePath(parent);
}

fn buildFileReadPayload(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: usize,
    truncated: bool,
    content: []const u8,
    ready: bool,
    wait_until_ready: bool,
) ![]u8 {
    var payload = std.ArrayListUnmanaged(u8){};
    errdefer payload.deinit(allocator);

    try payload.appendSlice(allocator, "{\"path\":\"");
    try appendJsonEscaped(allocator, &payload, path);
    try payload.appendSlice(allocator, "\",\"bytes\":");
    try payload.writer(allocator).print("{d}", .{bytes});
    try payload.appendSlice(allocator, ",\"truncated\":");
    try payload.appendSlice(allocator, if (truncated) "true" else "false");
    try payload.appendSlice(allocator, ",\"content\":\"");
    try appendJsonEscaped(allocator, &payload, content);
    try payload.appendSlice(allocator, "\",\"ready\":");
    try payload.appendSlice(allocator, if (ready) "true" else "false");
    try payload.appendSlice(allocator, ",\"wait_until_ready\":");
    try payload.appendSlice(allocator, if (wait_until_ready) "true" else "false");
    try payload.append(allocator, '}');
    return payload.toOwnedSlice(allocator);
}

fn buildFileWritePayload(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes_written: usize,
    append: bool,
    ready: bool,
    wait_until_ready: bool,
) ![]u8 {
    var payload = std.ArrayListUnmanaged(u8){};
    errdefer payload.deinit(allocator);

    try payload.appendSlice(allocator, "{\"path\":\"");
    try appendJsonEscaped(allocator, &payload, path);
    try payload.appendSlice(allocator, "\",\"bytes_written\":");
    try payload.writer(allocator).print("{d}", .{bytes_written});
    try payload.appendSlice(allocator, ",\"append\":");
    try payload.appendSlice(allocator, if (append) "true" else "false");
    try payload.appendSlice(allocator, ",\"ready\":");
    try payload.appendSlice(allocator, if (ready) "true" else "false");
    try payload.appendSlice(allocator, ",\"wait_until_ready\":");
    try payload.appendSlice(allocator, if (wait_until_ready) "true" else "false");
    try payload.append(allocator, '}');
    return payload.toOwnedSlice(allocator);
}

fn getWorkspaceRootRealpath(allocator: std.mem.Allocator) ![]u8 {
    const configured_root = std.process.getEnvVarOwned(allocator, workspace_root_env) catch null;
    defer if (configured_root) |value| allocator.free(value);

    const cwd = std.fs.cwd();
    if (configured_root) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len > 0) {
            if (std.fs.path.isAbsolute(trimmed)) {
                return std.fs.realpathAlloc(allocator, trimmed);
            }
            const joined = try std.fs.path.join(allocator, &.{ ".", trimmed });
            defer allocator.free(joined);
            return cwd.realpathAlloc(allocator, joined);
        }
    }
    return cwd.realpathAlloc(allocator, ".");
}

fn resolveAbsolutePathInWorkspace(
    allocator: std.mem.Allocator,
    workspace_real: []const u8,
    path: []const u8,
) ![]u8 {
    if (std.fs.path.isAbsolute(path)) return allocator.dupe(u8, path);
    if (std.mem.eql(u8, path, ".")) return allocator.dupe(u8, workspace_real);
    return std.fs.path.join(allocator, &.{ workspace_real, path });
}

fn isWithinRootPath(root: []const u8, target: []const u8) bool {
    if (std.mem.eql(u8, root, target)) return true;
    if (!std.mem.startsWith(u8, target, root)) return false;
    if (target.len <= root.len) return false;
    return target[root.len] == std.fs.path.sep;
}

fn isWithinWorkspace(workspace: []const u8, target: []const u8) bool {
    if (std.mem.eql(u8, workspace, "/")) {
        for (sandbox_namespace_allowed_roots) |root| {
            if (isWithinRootPath(root, target)) return true;
        }
        return false;
    }
    return isWithinRootPath(workspace, target);
}

fn validatePathOwned(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    if (path.len == 0) return allocator.dupe(u8, "path cannot be empty") catch null;
    if (path[0] == '~') return allocator.dupe(u8, "home directory references are not allowed") catch null;
    if (path[0] == '-') return allocator.dupe(u8, "path cannot start with '-'") catch null;

    const workspace_real = getWorkspaceRootRealpath(allocator) catch |err| {
        return std.fmt.allocPrint(allocator, "failed to resolve workspace path: {s}", .{@errorName(err)}) catch null;
    };
    defer allocator.free(workspace_real);

    var candidate = path;
    while (true) {
        const candidate_abs = resolveAbsolutePathInWorkspace(allocator, workspace_real, candidate) catch {
            return allocator.dupe(u8, "failed to resolve candidate path") catch null;
        };
        defer allocator.free(candidate_abs);

        const resolved = std.fs.realpathAlloc(allocator, candidate_abs) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => {
                if ((std.fs.path.isAbsolute(candidate) and std.mem.eql(u8, candidate, "/")) or std.mem.eql(u8, candidate, ".")) {
                    return std.fmt.allocPrint(allocator, "failed to resolve path: {s}", .{@errorName(err)}) catch null;
                }
                candidate = std.fs.path.dirname(candidate) orelse if (std.fs.path.isAbsolute(candidate)) "/" else ".";
                continue;
            },
            else => return std.fmt.allocPrint(allocator, "failed to resolve path: {s}", .{@errorName(err)}) catch null,
        };
        defer allocator.free(resolved);

        if (!isWithinWorkspace(workspace_real, resolved)) {
            return allocator.dupe(u8, "path resolves outside workspace") catch null;
        }
        return null;
    }
}

fn utf8SafePrefix(value: []const u8) []const u8 {
    if (std.unicode.utf8ValidateSlice(value)) return value;
    return value[0..longestValidUtf8PrefixLen(value)];
}

fn longestValidUtf8PrefixLen(value: []const u8) usize {
    var i: usize = 0;
    while (i < value.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(value[i]) catch break;
        const next = i + @as(usize, @intCast(seq_len));
        if (next > value.len) break;
        _ = std.unicode.utf8Decode(value[i..next]) catch break;
        i = next;
    }
    return i;
}

fn isWouldBlockError(err: anyerror) bool {
    return switch (err) {
        error.WouldBlock => true,
        else => false,
    };
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

test "agent_runtime_child_main: slash workspace stays within namespace mounts" {
    try std.testing.expect(isWithinWorkspace("/", "/workspace"));
    try std.testing.expect(isWithinWorkspace("/", "/workspace/src"));
    try std.testing.expect(isWithinWorkspace("/", "/projects/system"));
    try std.testing.expect(isWithinWorkspace("/", "/agents/self"));
    try std.testing.expect(!isWithinWorkspace("/", "/"));
    try std.testing.expect(!isWithinWorkspace("/", "/usr/bin"));
    try std.testing.expect(!isWithinWorkspace("/", "/tmp"));
    try std.testing.expect(!isWithinWorkspace("/", "/projects2"));
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
