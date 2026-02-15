const std = @import("std");
const ToolResult = @import("tool_registry.zig").ToolResult;

/// Escape a string for JSON (handles quotes, backslashes, control chars)
fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8){};
    errdefer result.deinit(allocator);

    for (input) |c| {
        switch (c) {
            '"' => try result.appendSlice(allocator, "\\\""),
            '\\' => try result.appendSlice(allocator, "\\\\"),
            '\n' => try result.appendSlice(allocator, "\\n"),
            '\r' => try result.appendSlice(allocator, "\\r"),
            '\t' => try result.appendSlice(allocator, "\\t"),
            // Backspace and form feed
            0x08 => try result.appendSlice(allocator, "\\b"),
            0x0C => try result.appendSlice(allocator, "\\f"),
            // Other control chars
            0x00...0x07, 0x0E...0x1F => try result.appendSlice(allocator, "\\u0000"),
            else => try result.append(allocator, c),
        }
    }

    return result.toOwnedSlice(allocator);
}

const PathMode = enum {
    read_or_list,
    write,
};

fn isWithinWorkspace(workspace: []const u8, target: []const u8) bool {
    if (std.mem.eql(u8, workspace, target)) return true;
    if (!std.mem.startsWith(u8, target, workspace)) return false;
    if (target.len <= workspace.len) return false;
    return target[workspace.len] == std.fs.path.sep;
}

/// Validate path resolves inside workspace, including symlink escapes.
/// Returns an owned error message that must be freed by caller.
fn validatePathOwned(allocator: std.mem.Allocator, path: []const u8, mode: PathMode) ?[]u8 {
    if (path.len == 0) {
        return allocator.dupe(u8, "Path cannot be empty") catch return null;
    }

    // Reject obvious external references up front.
    if (std.fs.path.isAbsolute(path)) {
        return allocator.dupe(u8, "Absolute paths are not allowed") catch return null;
    }
    if (path[0] == '~') {
        return allocator.dupe(u8, "Home directory references are not allowed") catch return null;
    }

    const cwd = std.fs.cwd();
    const workspace_real = cwd.realpathAlloc(allocator, ".") catch |err| {
        return std.fmt.allocPrint(allocator, "Failed to resolve workspace path: {s}", .{@errorName(err)}) catch return null;
    };
    defer allocator.free(workspace_real);

    var candidate = switch (mode) {
        .read_or_list => path,
        .write => std.fs.path.dirname(path) orelse ".",
    };

    // For write paths, walk upward until we find an existing ancestor.
    while (true) {
        const resolved = cwd.realpathAlloc(allocator, candidate) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => {
                if (std.mem.eql(u8, candidate, ".")) {
                    return std.fmt.allocPrint(allocator, "Failed to resolve path: {s}", .{@errorName(err)}) catch return null;
                }
                candidate = std.fs.path.dirname(candidate) orelse ".";
                continue;
            },
            else => {
                return std.fmt.allocPrint(allocator, "Failed to resolve path: {s}", .{@errorName(err)}) catch return null;
            },
        };
        defer allocator.free(resolved);

        if (!isWithinWorkspace(workspace_real, resolved)) {
            return allocator.dupe(u8, "Path resolves outside workspace") catch return null;
        }

        return null;
    }
}

/// Static OOM message - must NOT be freed
pub const OOM_MSG: []const u8 = "Out of memory";

/// Helper to create a failure result with an allocated message
fn fail(alloc: std.mem.Allocator, code: ToolResult.ErrorCode, msg: []const u8) ToolResult {
    const owned_msg = alloc.dupe(u8, msg) catch {
        // Return static OOM message - caller must check and not free this
        return .{ .failure = .{ .code = .execution_failed, .message = OOM_MSG } };
    };
    return .{ .failure = .{ .code = code, .message = owned_msg } };
}

/// Built-in tool implementations
pub const BuiltinTools = struct {
    /// Read file contents
    pub fn fileRead(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path_value = args.get("path") orelse {
            return fail(allocator, .invalid_params, "Missing required parameter: path");
        };
        if (path_value != .string) {
            return fail(allocator, .invalid_params, "Parameter 'path' must be a string");
        }
        const path = path_value.string;

        // Security: validate path
        if (validatePathOwned(allocator, path, .read_or_list)) |err| {
            return .{ .failure = .{
                .code = .permission_denied,
                .message = err,
            } };
        }

        const content = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to read file: {s}", .{@errorName(err)}) catch return fail(allocator, .execution_failed, "Failed to read file");
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

        return .{ .success = .{ .content = content } };
    }

    /// Write file contents
    pub fn fileWrite(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path_value = args.get("path") orelse {
            return fail(allocator, .invalid_params, "Missing required parameter: path");
        };
        const content_value = args.get("content") orelse {
            return fail(allocator, .invalid_params, "Missing required parameter: content");
        };

        if (path_value != .string or content_value != .string) {
            return fail(allocator, .invalid_params, "Parameters 'path' and 'content' must be strings");
        }

        const path = path_value.string;
        const content = content_value.string;

        // Security: validate path
        if (validatePathOwned(allocator, path, .write)) |err| {
            return .{ .failure = .{
                .code = .permission_denied,
                .message = err,
            } };
        }

        // Create parent directories if needed
        if (std.fs.path.dirname(path)) |dir| {
            std.fs.cwd().makePath(dir) catch |err| {
                const msg = std.fmt.allocPrint(allocator, "Failed to create directory: {s}", .{@errorName(err)}) catch return fail(allocator, .execution_failed, "Failed to create directory");
                return .{ .failure = .{
                    .code = .execution_failed,
                    .message = msg,
                } };
            };
        }

        std.fs.cwd().writeFile(.{
            .sub_path = path,
            .data = content,
        }) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to write file: {s}", .{@errorName(err)}) catch return fail(allocator, .execution_failed, "Failed to write file");
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

        const msg = std.fmt.allocPrint(allocator, "File written successfully: {s}", .{path}) catch return fail(allocator, .execution_failed, "Out of memory");
        return .{ .success = .{ .content = msg } };
    }

    /// List directory contents
    pub fn fileList(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path = if (args.get("path")) |pv|
            if (pv == .string) pv.string else "."
        else
            ".";

        // Security: validate path
        if (validatePathOwned(allocator, path, .read_or_list)) |err| {
            return .{ .failure = .{
                .code = .permission_denied,
                .message = err,
            } };
        }

        var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to open directory: {s}", .{@errorName(err)}) catch return fail(allocator, .execution_failed, "Failed to open directory");
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };
        defer dir.close();

        var result = std.ArrayListUnmanaged(u8){};
        errdefer result.deinit(allocator);

        result.appendSlice(allocator, "[\n") catch {
            result.deinit(allocator);
            return fail(allocator, .execution_failed, "Out of memory");
        };

        var it = dir.iterate();
        var first = true;
        while (it.next() catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to iterate directory: {s}", .{@errorName(err)}) catch return fail(allocator, .execution_failed, "Failed to iterate directory");
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        }) |entry| {
            if (!first) {
                result.appendSlice(allocator, ",\n") catch {
                    result.deinit(allocator);
                    return fail(allocator, .execution_failed, "Out of memory");
                };
            }
            first = false;

            const entry_type = switch (entry.kind) {
                .file => "file",
                .directory => "directory",
                .sym_link => "symlink",
                else => "other",
            };

            // Escape filename for JSON
            const escaped_name = jsonEscape(allocator, entry.name) catch {
                result.deinit(allocator);
                return fail(allocator, .execution_failed, "Out of memory");
            };
            defer allocator.free(escaped_name);

            result.appendSlice(allocator, "  {\"name\":\"") catch {
                result.deinit(allocator);
                return fail(allocator, .execution_failed, "Out of memory");
            };
            result.appendSlice(allocator, escaped_name) catch {
                result.deinit(allocator);
                return fail(allocator, .execution_failed, "Out of memory");
            };
            result.appendSlice(allocator, "\",\"type\":\"") catch {
                result.deinit(allocator);
                return fail(allocator, .execution_failed, "Out of memory");
            };
            result.appendSlice(allocator, entry_type) catch {
                result.deinit(allocator);
                return fail(allocator, .execution_failed, "Out of memory");
            };
            result.appendSlice(allocator, "\"}") catch {
                result.deinit(allocator);
                return fail(allocator, .execution_failed, "Out of memory");
            };
        }

        result.appendSlice(allocator, "\n]") catch {
            result.deinit(allocator);
            return fail(allocator, .execution_failed, "Out of memory");
        };

        return .{ .success = .{ .content = result.toOwnedSlice(allocator) catch return fail(allocator, .execution_failed, "Out of memory"), .format = .json } };
    }

    /// Search code using shell command
    pub fn searchCode(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const query_value = args.get("query") orelse {
            return fail(allocator, .invalid_params, "Missing required parameter: query");
        };
        if (query_value != .string) {
            return fail(allocator, .invalid_params, "Parameter 'query' must be a string");
        }
        const query = query_value.string;

        const path = if (args.get("path")) |pv|
            if (pv == .string) pv.string else "."
        else
            ".";

        // Security: validate path
        if (validatePathOwned(allocator, path, .read_or_list)) |err| {
            return .{ .failure = .{
                .code = .permission_denied,
                .message = err,
            } };
        }

        // Use ripgrep if available, fallback to grep
        // Use -e for query and -- to prevent flag injection
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "rg", "-n", "-i", "--color=never", "-e", query, "--", path },
            .max_output_bytes = 1024 * 1024,
        }) catch |err| {
            // Fallback to grep with -e and --
            const grep_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "grep", "-rn", "-i", "--color=never", "-e", query, "--", path },
                .max_output_bytes = 1024 * 1024,
            }) catch |grep_err| {
                const msg = std.fmt.allocPrint(allocator, "Search failed: rg={s}, grep={s}", .{
                    @errorName(err),
                    @errorName(grep_err),
                }) catch return fail(allocator, .execution_failed, "Search failed");
                return .{ .failure = .{
                    .code = .execution_failed,
                    .message = msg,
                } };
            };

            if (grep_result.term.Exited != 0 and grep_result.term.Exited != 1) {
                allocator.free(grep_result.stdout);
                allocator.free(grep_result.stderr);
                return fail(allocator, .execution_failed, "grep command failed");
            }

            const output = if (grep_result.stdout.len > 0)
                grep_result.stdout
            else
                allocator.dupe(u8, "No matches found") catch return fail(allocator, .execution_failed, "No matches found");
            allocator.free(grep_result.stderr);

            return .{ .success = .{ .content = output } };
        };

        if (result.term.Exited != 0 and result.term.Exited != 1) {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
            return fail(allocator, .execution_failed, "rg command failed");
        }

        const output = if (result.stdout.len > 0)
            result.stdout
        else
            allocator.dupe(u8, "No matches found") catch return fail(allocator, .execution_failed, "No matches found");
        allocator.free(result.stderr);

        return .{ .success = .{ .content = output } };
    }

    /// Execute shell command (restricted) with 30 second timeout
    pub fn shell(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const command_value = args.get("command") orelse {
            return fail(allocator, .invalid_params, "Missing required parameter: command");
        };
        if (command_value != .string) {
            return fail(allocator, .invalid_params, "Parameter 'command' must be a string");
        }
        const command = command_value.string;

        // Security: block dangerous commands
        const blocked = [_][]const u8{
            "rm -rf /",
            "rm -rf /*",
            ":(){ :|: & };:", // fork bomb
            "> /dev/sda",
            "dd if=/dev/zero",
        };
        for (blocked) |b| {
            if (std.mem.indexOf(u8, command, b) != null) {
                return fail(allocator, .permission_denied, "Command blocked for security reasons");
            }
        }

        // Use timeout command to enforce 30 second limit
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "timeout", "30", "bash", "-c", command },
            .max_output_bytes = 1024 * 1024,
        }) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Command execution failed: {s}", .{@errorName(err)}) catch return fail(allocator, .execution_failed, "Command execution failed");
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

        // Check if timed out (timeout returns 124 on timeout)
        const exit_code: i32 = switch (result.term) {
            .Exited => |code| @intCast(code),
            .Signal => |sig| @intCast(sig),
            .Stopped => |sig| @intCast(sig),
            .Unknown => |code| @intCast(code),
        };

        if (exit_code == 124) {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
            return fail(allocator, .timeout, "Command timed out after 30 seconds");
        }

        if (exit_code != 0) {
            // Build error message first, then free buffers
            const msg = blk: {
                if (result.stderr.len > 0) {
                    const m = std.fmt.allocPrint(allocator, "Command exited with code {d}: {s}", .{ exit_code, result.stderr }) catch {
                        allocator.free(result.stdout);
                        allocator.free(result.stderr);
                        break :blk allocator.dupe(u8, "Command failed") catch return fail(allocator, .execution_failed, "Command failed");
                    };
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                    break :blk m;
                } else if (result.stdout.len > 0) {
                    const m = std.fmt.allocPrint(allocator, "Command exited with code {d}: {s}", .{ exit_code, result.stdout }) catch {
                        allocator.free(result.stdout);
                        allocator.free(result.stderr);
                        break :blk allocator.dupe(u8, "Command failed") catch return fail(allocator, .execution_failed, "Command failed");
                    };
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                    break :blk m;
                } else {
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                    break :blk allocator.dupe(u8, "Command failed with no output") catch return fail(allocator, .execution_failed, "Command failed");
                }
            };
            return .{ .failure = .{ .code = .execution_failed, .message = msg } };
        }

        const output = if (result.stdout.len > 0)
            result.stdout
        else if (result.stderr.len > 0)
            result.stderr
        else
            allocator.dupe(u8, "Command completed with no output") catch return fail(allocator, .execution_failed, "Command completed");

        if (result.stdout.len == 0 and result.stderr.len > 0) {
            allocator.free(result.stdout);
        } else if (result.stderr.len > 0) {
            allocator.free(result.stderr);
        }

        return .{ .success = .{ .content = output } };
    }
};
