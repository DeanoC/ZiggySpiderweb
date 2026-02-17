const std = @import("std");
const registry_mod = @import("tool_registry.zig");

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_FILE_READ_BYTES: usize = 1024 * 1024;

fn fail(allocator: std.mem.Allocator, code: registry_mod.ToolErrorCode, msg: []const u8) registry_mod.ToolExecutionResult {
    const owned = allocator.dupe(u8, msg) catch return .{ .failure = .{
        .code = .execution_failed,
        .message = allocator.dupe(u8, "out of memory") catch @panic("out of memory while reporting error"),
    } };
    return .{ .failure = .{ .code = code, .message = owned } };
}

fn parseBool(args: std.json.ObjectMap, name: []const u8, default: bool) !bool {
    const value = args.get(name) orelse return default;
    if (value != .bool) return error.InvalidType;
    return value.bool;
}

fn parseUsize(args: std.json.ObjectMap, name: []const u8, default: usize) !usize {
    const value = args.get(name) orelse return default;
    if (value != .integer or value.integer < 0) return error.InvalidType;
    return @as(usize, @intCast(value.integer));
}

fn requiredString(args: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = args.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn optionalString(args: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = args.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
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

fn shellQuoteSingle(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    try out.append(allocator, '\'');
    for (input) |c| {
        if (c == '\'') {
            try out.appendSlice(allocator, "'\\''");
        } else {
            try out.append(allocator, c);
        }
    }
    try out.append(allocator, '\'');
    return out.toOwnedSlice(allocator);
}

pub const BuiltinTools = struct {
    pub fn registerAll(registry: *registry_mod.ToolRegistry) !void {
        try registry.registerWorldTool(
            "file.read",
            "Read file contents",
            &[_]registry_mod.ToolParam{
                .{ .name = "path", .param_type = .string, .description = "Path to file", .required = true },
                .{ .name = "max_bytes", .param_type = .integer, .description = "Maximum bytes to read", .required = false },
            },
            fileRead,
        );
        try registry.registerWorldTool(
            "file.write",
            "Write file contents",
            &[_]registry_mod.ToolParam{
                .{ .name = "path", .param_type = .string, .description = "Path to file", .required = true },
                .{ .name = "content", .param_type = .string, .description = "File content", .required = true },
                .{ .name = "append", .param_type = .boolean, .description = "Append instead of overwrite", .required = false },
                .{ .name = "create_parents", .param_type = .boolean, .description = "Create parent folders", .required = false },
            },
            fileWrite,
        );
        try registry.registerWorldTool(
            "file.list",
            "List directory contents",
            &[_]registry_mod.ToolParam{
                .{ .name = "path", .param_type = .string, .description = "Directory path", .required = false },
                .{ .name = "recursive", .param_type = .boolean, .description = "Walk recursively", .required = false },
                .{ .name = "max_entries", .param_type = .integer, .description = "Maximum entries to return", .required = false },
            },
            fileList,
        );
        try registry.registerWorldTool(
            "search.code",
            "Search code using ripgrep",
            &[_]registry_mod.ToolParam{
                .{ .name = "query", .param_type = .string, .description = "Search query", .required = true },
                .{ .name = "path", .param_type = .string, .description = "Search path", .required = false },
                .{ .name = "case_sensitive", .param_type = .boolean, .description = "Enable case-sensitive search", .required = false },
                .{ .name = "max_results", .param_type = .integer, .description = "Maximum match lines", .required = false },
            },
            searchCode,
        );
        try registry.registerWorldTool(
            "shell.exec",
            "Execute a shell command",
            &[_]registry_mod.ToolParam{
                .{ .name = "command", .param_type = .string, .description = "Command line to execute", .required = true },
                .{ .name = "timeout_ms", .param_type = .integer, .description = "Timeout in milliseconds", .required = false },
                .{ .name = "cwd", .param_type = .string, .description = "Working directory", .required = false },
            },
            shellExec,
        );
    }

    pub fn fileRead(allocator: std.mem.Allocator, args: std.json.ObjectMap) registry_mod.ToolExecutionResult {
        const path = requiredString(args, "path") orelse return fail(allocator, .invalid_params, "missing required parameter: path");

        const max_bytes = parseUsize(args, "max_bytes", DEFAULT_MAX_FILE_READ_BYTES) catch {
            return fail(allocator, .invalid_params, "max_bytes must be a non-negative integer");
        };
        const effective_max = @min(max_bytes, 8 * 1024 * 1024);

        const content = std.fs.cwd().readFileAlloc(allocator, path, effective_max) catch |err| {
            return fail(allocator, .execution_failed, @errorName(err));
        };
        defer allocator.free(content);

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(allocator);

        payload.appendSlice(allocator, "{\"path\":\"") catch return fail(allocator, .execution_failed, "out of memory");
        appendJsonEscaped(allocator, &payload, path) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, "\",\"bytes\":") catch return fail(allocator, .execution_failed, "out of memory");
        payload.writer(allocator).print("{d}", .{content.len}) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, ",\"content\":\"") catch return fail(allocator, .execution_failed, "out of memory");
        appendJsonEscaped(allocator, &payload, content) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, "\"}") catch return fail(allocator, .execution_failed, "out of memory");

        return .{ .success = .{ .payload_json = payload.toOwnedSlice(allocator) catch return fail(allocator, .execution_failed, "out of memory") } };
    }

    pub fn fileWrite(allocator: std.mem.Allocator, args: std.json.ObjectMap) registry_mod.ToolExecutionResult {
        const path = requiredString(args, "path") orelse return fail(allocator, .invalid_params, "missing required parameter: path");
        const content = requiredString(args, "content") orelse return fail(allocator, .invalid_params, "missing required parameter: content");

        const append = parseBool(args, "append", false) catch return fail(allocator, .invalid_params, "append must be boolean");
        const create_parents = parseBool(args, "create_parents", true) catch return fail(allocator, .invalid_params, "create_parents must be boolean");

        if (create_parents) {
            if (std.fs.path.dirname(path)) |dir| {
                std.fs.cwd().makePath(dir) catch |err| return fail(allocator, .execution_failed, @errorName(err));
            }
        }

        if (append) {
            var file = std.fs.cwd().createFile(path, .{ .truncate = false }) catch |err| return fail(allocator, .execution_failed, @errorName(err));
            defer file.close();
            file.seekFromEnd(0) catch |err| return fail(allocator, .execution_failed, @errorName(err));
            file.writeAll(content) catch |err| return fail(allocator, .execution_failed, @errorName(err));
        } else {
            std.fs.cwd().writeFile(.{ .sub_path = path, .data = content }) catch |err| return fail(allocator, .execution_failed, @errorName(err));
        }

        const payload = std.fmt.allocPrint(
            allocator,
            "{{\"path\":\"{s}\",\"bytes_written\":{d},\"append\":{s}}}",
            .{ path, content.len, if (append) "true" else "false" },
        ) catch return fail(allocator, .execution_failed, "out of memory");

        return .{ .success = .{ .payload_json = payload } };
    }

    pub fn fileList(allocator: std.mem.Allocator, args: std.json.ObjectMap) registry_mod.ToolExecutionResult {
        const path = optionalString(args, "path") orelse ".";
        const recursive = parseBool(args, "recursive", false) catch return fail(allocator, .invalid_params, "recursive must be boolean");
        const max_entries = parseUsize(args, "max_entries", 500) catch return fail(allocator, .invalid_params, "max_entries must be integer");
        const effective_max = @min(max_entries, 5000);

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(allocator);

        payload.appendSlice(allocator, "{\"path\":\"") catch return fail(allocator, .execution_failed, "out of memory");
        appendJsonEscaped(allocator, &payload, path) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, "\",\"entries\":[") catch return fail(allocator, .execution_failed, "out of memory");

        var first = true;
        var count: usize = 0;

        if (recursive) {
            var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| return fail(allocator, .execution_failed, @errorName(err));
            defer dir.close();

            var walker = dir.walk(allocator) catch |err| return fail(allocator, .execution_failed, @errorName(err));
            defer walker.deinit();

            while (walker.next() catch |err| return fail(allocator, .execution_failed, @errorName(err))) |entry| {
                if (count >= effective_max) break;
                if (!first) payload.append(allocator, ',') catch return fail(allocator, .execution_failed, "out of memory");
                first = false;
                count += 1;

                const kind = switch (entry.kind) {
                    .file => "file",
                    .directory => "directory",
                    .sym_link => "symlink",
                    else => "other",
                };

                payload.appendSlice(allocator, "{\"name\":\"") catch return fail(allocator, .execution_failed, "out of memory");
                appendJsonEscaped(allocator, &payload, entry.path) catch return fail(allocator, .execution_failed, "out of memory");
                payload.appendSlice(allocator, "\",\"type\":\"") catch return fail(allocator, .execution_failed, "out of memory");
                payload.appendSlice(allocator, kind) catch return fail(allocator, .execution_failed, "out of memory");
                payload.appendSlice(allocator, "\"}") catch return fail(allocator, .execution_failed, "out of memory");
            }
        } else {
            var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| return fail(allocator, .execution_failed, @errorName(err));
            defer dir.close();

            var it = dir.iterate();
            while (it.next() catch |err| return fail(allocator, .execution_failed, @errorName(err))) |entry| {
                if (count >= effective_max) break;
                if (!first) payload.append(allocator, ',') catch return fail(allocator, .execution_failed, "out of memory");
                first = false;
                count += 1;

                const kind = switch (entry.kind) {
                    .file => "file",
                    .directory => "directory",
                    .sym_link => "symlink",
                    else => "other",
                };

                payload.appendSlice(allocator, "{\"name\":\"") catch return fail(allocator, .execution_failed, "out of memory");
                appendJsonEscaped(allocator, &payload, entry.name) catch return fail(allocator, .execution_failed, "out of memory");
                payload.appendSlice(allocator, "\",\"type\":\"") catch return fail(allocator, .execution_failed, "out of memory");
                payload.appendSlice(allocator, kind) catch return fail(allocator, .execution_failed, "out of memory");
                payload.appendSlice(allocator, "\"}") catch return fail(allocator, .execution_failed, "out of memory");
            }
        }

        payload.appendSlice(allocator, "],\"truncated\":") catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, if (count >= effective_max) "true" else "false") catch return fail(allocator, .execution_failed, "out of memory");
        payload.append(allocator, '}') catch return fail(allocator, .execution_failed, "out of memory");

        return .{ .success = .{ .payload_json = payload.toOwnedSlice(allocator) catch return fail(allocator, .execution_failed, "out of memory") } };
    }

    pub fn searchCode(allocator: std.mem.Allocator, args: std.json.ObjectMap) registry_mod.ToolExecutionResult {
        const query = requiredString(args, "query") orelse return fail(allocator, .invalid_params, "missing required parameter: query");
        const path = optionalString(args, "path") orelse ".";
        const case_sensitive = parseBool(args, "case_sensitive", false) catch return fail(allocator, .invalid_params, "case_sensitive must be boolean");
        const max_results = parseUsize(args, "max_results", 200) catch return fail(allocator, .invalid_params, "max_results must be integer");
        const effective_max_results = @min(max_results, 5000);

        const rg_case_flag = if (case_sensitive) "--case-sensitive" else "-i";
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "rg", "-n", rg_case_flag, "--color=never", "-m", "5000", "-e", query, "--", path },
            .max_output_bytes = DEFAULT_MAX_OUTPUT_BYTES,
        }) catch {
            const grep_case_flag = if (case_sensitive) "" else "-i";
            const grep_argv = if (grep_case_flag.len == 0)
                &[_][]const u8{ "grep", "-rn", "--color=never", "-m", "5000", "-e", query, "--", path }
            else
                &[_][]const u8{ "grep", "-rn", "--color=never", grep_case_flag, "-m", "5000", "-e", query, "--", path };

            const grep_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = grep_argv,
                .max_output_bytes = DEFAULT_MAX_OUTPUT_BYTES,
            }) catch |grep_err| return fail(allocator, .execution_failed, @errorName(grep_err));
            defer allocator.free(grep_result.stderr);

            if (grep_result.term.Exited != 0 and grep_result.term.Exited != 1) {
                allocator.free(grep_result.stdout);
                return fail(allocator, .execution_failed, "grep command failed");
            }

            return buildSearchPayload(allocator, path, query, grep_result.stdout, effective_max_results);
        };
        defer allocator.free(result.stderr);

        if (result.term.Exited != 0 and result.term.Exited != 1) {
            allocator.free(result.stdout);
            return fail(allocator, .execution_failed, "rg command failed");
        }

        return buildSearchPayload(allocator, path, query, result.stdout, effective_max_results);
    }

    fn buildSearchPayload(
        allocator: std.mem.Allocator,
        path: []const u8,
        query: []const u8,
        raw_output: []u8,
        max_results: usize,
    ) registry_mod.ToolExecutionResult {
        defer allocator.free(raw_output);

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(allocator);

        payload.appendSlice(allocator, "{\"path\":\"") catch return fail(allocator, .execution_failed, "out of memory");
        appendJsonEscaped(allocator, &payload, path) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, "\",\"query\":\"") catch return fail(allocator, .execution_failed, "out of memory");
        appendJsonEscaped(allocator, &payload, query) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, "\",\"matches\":[") catch return fail(allocator, .execution_failed, "out of memory");

        var lines = std.mem.splitScalar(u8, raw_output, '\n');
        var count: usize = 0;
        var first = true;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (count >= max_results) break;
            if (!first) payload.append(allocator, ',') catch return fail(allocator, .execution_failed, "out of memory");
            first = false;
            count += 1;

            payload.appendSlice(allocator, "\"") catch return fail(allocator, .execution_failed, "out of memory");
            appendJsonEscaped(allocator, &payload, line) catch return fail(allocator, .execution_failed, "out of memory");
            payload.appendSlice(allocator, "\"") catch return fail(allocator, .execution_failed, "out of memory");
        }

        payload.appendSlice(allocator, "],\"count\":") catch return fail(allocator, .execution_failed, "out of memory");
        payload.writer(allocator).print("{d}", .{count}) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, ",\"truncated\":") catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, if (lines.next() != null) "true" else "false") catch return fail(allocator, .execution_failed, "out of memory");
        payload.append(allocator, '}') catch return fail(allocator, .execution_failed, "out of memory");

        return .{ .success = .{ .payload_json = payload.toOwnedSlice(allocator) catch return fail(allocator, .execution_failed, "out of memory") } };
    }

    pub fn shellExec(allocator: std.mem.Allocator, args: std.json.ObjectMap) registry_mod.ToolExecutionResult {
        const command = requiredString(args, "command") orelse return fail(allocator, .invalid_params, "missing required parameter: command");
        const timeout_ms = parseUsize(args, "timeout_ms", 30_000) catch return fail(allocator, .invalid_params, "timeout_ms must be integer");
        const bounded_timeout_ms = @min(timeout_ms, 300_000);
        const cwd = optionalString(args, "cwd");

        const timeout_sec = @max(@divTrunc(bounded_timeout_ms + 999, 1000), 1);
        const timeout_str = std.fmt.allocPrint(allocator, "{d}", .{timeout_sec}) catch return fail(allocator, .execution_failed, "out of memory");
        defer allocator.free(timeout_str);

        const wrapped_command = if (cwd) |cwd_value| blk: {
            const quoted = shellQuoteSingle(allocator, cwd_value) catch return fail(allocator, .execution_failed, "out of memory");
            defer allocator.free(quoted);
            break :blk std.fmt.allocPrint(allocator, "cd {s} && {s}", .{ quoted, command }) catch return fail(allocator, .execution_failed, "out of memory");
        } else allocator.dupe(u8, command) catch return fail(allocator, .execution_failed, "out of memory");
        defer allocator.free(wrapped_command);

        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "timeout", timeout_str, "bash", "-lc", wrapped_command },
            .max_output_bytes = DEFAULT_MAX_OUTPUT_BYTES,
        }) catch |err| return fail(allocator, .execution_failed, @errorName(err));

        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        const exit_code: i32 = switch (result.term) {
            .Exited => |code| @intCast(code),
            .Signal => |sig| @intCast(sig),
            .Stopped => |sig| @intCast(sig),
            .Unknown => |code| @intCast(code),
        };

        if (exit_code == 124) {
            return fail(allocator, .timeout, "command timed out");
        }

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(allocator);

        payload.appendSlice(allocator, "{\"exit_code\":") catch return fail(allocator, .execution_failed, "out of memory");
        payload.writer(allocator).print("{d}", .{exit_code}) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, ",\"stdout\":\"") catch return fail(allocator, .execution_failed, "out of memory");
        appendJsonEscaped(allocator, &payload, result.stdout) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, "\",\"stderr\":\"") catch return fail(allocator, .execution_failed, "out of memory");
        appendJsonEscaped(allocator, &payload, result.stderr) catch return fail(allocator, .execution_failed, "out of memory");
        payload.appendSlice(allocator, "\"}") catch return fail(allocator, .execution_failed, "out of memory");

        return .{ .success = .{ .payload_json = payload.toOwnedSlice(allocator) catch return fail(allocator, .execution_failed, "out of memory") } };
    }
};

fn inTempCwd(allocator: std.mem.Allocator, body: *const fn (std.mem.Allocator, []const u8) anyerror!void) !void {
    const original_cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(original_cwd);

    const temp_dir = try std.fmt.allocPrint(allocator, ".tmp-tool-tests-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(temp_dir);
    defer std.fs.cwd().deleteTree(temp_dir) catch {};

    try std.fs.cwd().makePath(temp_dir);
    const target_cwd = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ original_cwd, temp_dir });
    defer allocator.free(target_cwd);

    try std.process.changeCurDir(target_cwd);
    defer std.process.changeCurDir(original_cwd) catch {};

    try body(allocator, target_cwd);
}

fn testFileWriteReadImpl(allocator: std.mem.Allocator, _: []const u8) !void {
    var write_parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        "{\"path\":\"nested/a.txt\",\"content\":\"hello\",\"create_parents\":true}",
        .{},
    );
    defer write_parsed.deinit();

    var write_result = BuiltinTools.fileWrite(allocator, write_parsed.value.object);
    defer write_result.deinit(allocator);
    try std.testing.expect(write_result == .success);

    var read_parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"path\":\"nested/a.txt\"}", .{});
    defer read_parsed.deinit();

    var read_result = BuiltinTools.fileRead(allocator, read_parsed.value.object);
    defer read_result.deinit(allocator);

    try std.testing.expect(read_result == .success);
    try std.testing.expect(std.mem.indexOf(u8, read_result.success.payload_json, "\"content\":\"hello\"") != null);
}

test "tool_executor: file.write then file.read roundtrip" {
    try inTempCwd(std.testing.allocator, testFileWriteReadImpl);
}

fn testFileListImpl(allocator: std.mem.Allocator, _: []const u8) !void {
    try std.fs.cwd().writeFile(.{ .sub_path = "one.txt", .data = "1" });
    try std.fs.cwd().writeFile(.{ .sub_path = "two.txt", .data = "2" });
    try std.fs.cwd().writeFile(.{ .sub_path = "three.txt", .data = "3" });

    var list_parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"path\":\".\",\"max_entries\":2}", .{});
    defer list_parsed.deinit();

    var list_result = BuiltinTools.fileList(allocator, list_parsed.value.object);
    defer list_result.deinit(allocator);

    try std.testing.expect(list_result == .success);
    try std.testing.expect(std.mem.indexOf(u8, list_result.success.payload_json, "\"truncated\":true") != null);
}

test "tool_executor: file.list honors max_entries truncation" {
    try inTempCwd(std.testing.allocator, testFileListImpl);
}

fn testSearchCodeImpl(allocator: std.mem.Allocator, _: []const u8) !void {
    try std.fs.cwd().makePath("src");
    try std.fs.cwd().writeFile(.{ .sub_path = "src/sample.zig", .data = "const token = \"needle\";\n" });

    var search_parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"query\":\"needle\",\"path\":\"src\"}", .{});
    defer search_parsed.deinit();

    var search_result = BuiltinTools.searchCode(allocator, search_parsed.value.object);
    defer search_result.deinit(allocator);

    try std.testing.expect(search_result == .success);
    try std.testing.expect(std.mem.indexOf(u8, search_result.success.payload_json, "needle") != null);
}

test "tool_executor: search.code returns matching lines" {
    try inTempCwd(std.testing.allocator, testSearchCodeImpl);
}

fn testShellCwdImpl(allocator: std.mem.Allocator, _: []const u8) !void {
    try std.fs.cwd().makePath("workdir/sub");

    var shell_parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"command\":\"pwd\",\"cwd\":\"workdir/sub\"}", .{});
    defer shell_parsed.deinit();

    var shell_result = BuiltinTools.shellExec(allocator, shell_parsed.value.object);
    defer shell_result.deinit(allocator);

    try std.testing.expect(shell_result == .success);
    try std.testing.expect(std.mem.indexOf(u8, shell_result.success.payload_json, "\"exit_code\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, shell_result.success.payload_json, "workdir/sub") != null);
}

test "tool_executor: shell.exec supports cwd" {
    try inTempCwd(std.testing.allocator, testShellCwdImpl);
}

fn testShellTimeoutImpl(allocator: std.mem.Allocator, _: []const u8) !void {
    var timeout_parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"command\":\"sleep 2\",\"timeout_ms\":100}", .{});
    defer timeout_parsed.deinit();

    var timeout_result = BuiltinTools.shellExec(allocator, timeout_parsed.value.object);
    defer timeout_result.deinit(allocator);

    try std.testing.expect(timeout_result == .failure);
    try std.testing.expectEqual(registry_mod.ToolErrorCode.timeout, timeout_result.failure.code);
}

test "tool_executor: shell.exec returns timeout" {
    try inTempCwd(std.testing.allocator, testShellTimeoutImpl);
}
