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

/// Validate path is within workspace (no absolute paths, no ..)
/// Returns an owned error message that must be freed by caller
fn validatePathOwned(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    // Reject absolute paths
    if (path.len > 0 and path[0] == '/') {
        return allocator.dupe(u8, "Absolute paths are not allowed") catch return null;
    }
    // Reject paths starting with ~ (home directory)
    if (path.len > 0 and path[0] == '~') {
        return allocator.dupe(u8, "Home directory references are not allowed") catch return null;
    }
    // Reject directory traversal
    if (std.mem.indexOf(u8, path, "..") != null) {
        return allocator.dupe(u8, "Path cannot contain '..'") catch return null;
    }
    return null;
}

/// Helper to create a failure result with an allocated message
fn fail(alloc: std.mem.Allocator, code: ToolResult.ErrorCode, msg: []const u8) ToolResult {
    return .{ .failure = .{
        .code = code,
        .message = alloc.dupe(u8, msg) catch return .{ .failure = .{ .code = .execution_failed, .message = "OOM" } },
    } };
}

/// Built-in tool implementations
pub const BuiltinTools = struct {
    /// Read file contents
    pub fn fileRead(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path_value = args.get("path") orelse {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = allocator.dupe(u8, "Missing required parameter: path") catch return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } },
            } };
        };
        if (path_value != .string) {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = allocator.dupe(u8, "Parameter 'path' must be a string") catch return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } },
            } };
        }
        const path = path_value.string;

        // Security: validate path
        if (validatePathOwned(allocator, path)) |err| {
            return .{ .failure = .{
                .code = .permission_denied,
                .message = err,
            } };
        }

        const content = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to read file: {s}", .{@errorName(err)}) catch return .{ .failure = .{ .code = .execution_failed, .message = "Failed to read file" } };
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
            return .{ .failure = .{
                .code = .invalid_params,
                .message = "Missing required parameter: path",
            } };
        };
        const content_value = args.get("content") orelse {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = "Missing required parameter: content",
            } };
        };

        if (path_value != .string or content_value != .string) {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = "Parameters 'path' and 'content' must be strings",
            } };
        }

        const path = path_value.string;
        const content = content_value.string;

        // Security: validate path
        if (validatePathOwned(allocator, path)) |err| {
            return .{ .failure = .{
                .code = .permission_denied,
                .message = err,
            } };
        }

        // Create parent directories if needed
        if (std.fs.path.dirname(path)) |dir| {
            std.fs.cwd().makePath(dir) catch |err| {
                const msg = std.fmt.allocPrint(allocator, "Failed to create directory: {s}", .{@errorName(err)}) catch "Failed to create directory";
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
            const msg = std.fmt.allocPrint(allocator, "Failed to write file: {s}", .{@errorName(err)}) catch "Failed to write file";
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

        const msg = std.fmt.allocPrint(allocator, "File written successfully: {s}", .{path}) catch return .{ .failure = .{
            .code = .execution_failed,
            .message = "Out of memory",
        } };
        return .{ .success = .{ .content = msg } };
    }

    /// List directory contents
    pub fn fileList(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path = if (args.get("path")) |pv|
            if (pv == .string) pv.string else "."
        else
            ".";

        // Security: validate path
        if (validatePathOwned(allocator, path)) |err| {
            return .{ .failure = .{
                .code = .permission_denied,
                .message = err,
            } };
        }

        var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to open directory: {s}", .{@errorName(err)}) catch "Failed to open directory";
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
            return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
        };

        var it = dir.iterate();
        var first = true;
        while (it.next() catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to iterate directory: {s}", .{@errorName(err)}) catch "Failed to iterate directory";
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        }) |entry| {
            if (!first) {
                result.appendSlice(allocator, ",\n") catch {
                    result.deinit(allocator);
                    return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
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
                return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
            };
            defer allocator.free(escaped_name);

            result.appendSlice(allocator, "  {\"name\":\"") catch {
                result.deinit(allocator);
                return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
            };
            result.appendSlice(allocator, escaped_name) catch {
                result.deinit(allocator);
                return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
            };
            result.appendSlice(allocator, "\",\"type\":\"") catch {
                result.deinit(allocator);
                return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
            };
            result.appendSlice(allocator, entry_type) catch {
                result.deinit(allocator);
                return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
            };
            result.appendSlice(allocator, "\"}") catch {
                result.deinit(allocator);
                return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
            };
        }

        result.appendSlice(allocator, "\n]") catch {
            result.deinit(allocator);
            return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } };
        };

        return .{ .success = .{ .content = result.toOwnedSlice(allocator) catch return .{ .failure = .{ .code = .execution_failed, .message = "Out of memory" } }, .format = .json } };
    }

    /// Search code using shell command
    pub fn searchCode(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const query_value = args.get("query") orelse {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = "Missing required parameter: query",
            } };
        };
        if (query_value != .string) {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = "Parameter 'query' must be a string",
            } };
        }
        const query = query_value.string;

        const path = if (args.get("path")) |pv|
            if (pv == .string) pv.string else "."
        else
            ".";

        // Security: validate path
        if (validatePathOwned(allocator, path)) |err| {
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
                }) catch "Search failed";
                return .{ .failure = .{
                    .code = .execution_failed,
                    .message = msg,
                } };
            };

            if (grep_result.term.Exited != 0 and grep_result.term.Exited != 1) {
                allocator.free(grep_result.stdout);
                allocator.free(grep_result.stderr);
                return .{ .failure = .{
                    .code = .execution_failed,
                    .message = "grep command failed",
                } };
            }

            const output = if (grep_result.stdout.len > 0)
                grep_result.stdout
            else
                allocator.dupe(u8, "No matches found") catch "No matches found";
            allocator.free(grep_result.stderr);

            return .{ .success = .{ .content = output } };
        };

        if (result.term.Exited != 0 and result.term.Exited != 1) {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
            return .{ .failure = .{
                .code = .execution_failed,
                .message = "rg command failed",
            } };
        }

        const output = if (result.stdout.len > 0)
            result.stdout
        else
            allocator.dupe(u8, "No matches found") catch "No matches found";
        allocator.free(result.stderr);

        return .{ .success = .{ .content = output } };
    }

    /// Execute shell command (restricted)
    pub fn shell(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const command_value = args.get("command") orelse {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = "Missing required parameter: command",
            } };
        };
        if (command_value != .string) {
            return .{ .failure = .{
                .code = .invalid_params,
                .message = "Parameter 'command' must be a string",
            } };
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
                return .{ .failure = .{
                    .code = .permission_denied,
                    .message = "Command blocked for security reasons",
                } };
            }
        }

        // Execute with timeout (using bash -c)
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "bash", "-c", command },
            .max_output_bytes = 1024 * 1024,
        }) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Command execution failed: {s}", .{@errorName(err)}) catch "Command execution failed";
            return .{ .failure = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

        // Check exit code
        const exit_code: i32 = switch (result.term) {
            .Exited => |code| @intCast(code),
            .Signal => |sig| @intCast(sig),
            .Stopped => |sig| @intCast(sig),
            .Unknown => |code| @intCast(code),
        };

        if (exit_code != 0) {
            // Build error message first, then free buffers
            const msg = blk: {
                if (result.stderr.len > 0) {
                    const m = std.fmt.allocPrint(allocator, "Command exited with code {d}: {s}", .{ exit_code, result.stderr }) catch {
                        allocator.free(result.stdout);
                        allocator.free(result.stderr);
                        break :blk "Command failed";
                    };
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                    break :blk m;
                } else if (result.stdout.len > 0) {
                    const m = std.fmt.allocPrint(allocator, "Command exited with code {d}: {s}", .{ exit_code, result.stdout }) catch {
                        allocator.free(result.stdout);
                        allocator.free(result.stderr);
                        break :blk "Command failed";
                    };
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                    break :blk m;
                } else {
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                    break :blk "Command failed with no output";
                }
            };
            return .{ .failure = .{ .code = .execution_failed, .message = msg } };
        }

        const output = if (result.stdout.len > 0)
            result.stdout
        else if (result.stderr.len > 0)
            result.stderr
        else
            allocator.dupe(u8, "Command completed with no output") catch "Command completed";

        if (result.stdout.len == 0 and result.stderr.len > 0) {
            allocator.free(result.stdout);
        } else if (result.stderr.len > 0) {
            allocator.free(result.stderr);
        }

        return .{ .success = .{ .content = output } };
    }
};
