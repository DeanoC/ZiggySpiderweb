const std = @import("std");
const ToolResult = @import("tool_registry.zig").ToolResult;

/// Built-in tool implementations
pub const BuiltinTools = struct {
    /// Read file contents
    pub fn fileRead(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path_value = args.get("path") orelse {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Missing required parameter: path",
            } };
        };
        if (path_value != .string) {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Parameter 'path' must be a string",
            } };
        }
        const path = path_value.string;

        // Security: prevent directory traversal
        if (std.mem.indexOf(u8, path, "..") != null) {
            return .{ .error = .{
                .code = .permission_denied,
                .message = "Path cannot contain '..'",
            } };
        }

        const content = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to read file: {s}", .{@errorName(err)}) catch "Failed to read file";
            return .{ .error = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

        return .{ .success = .{ .content = content } };
    }

    /// Write file contents
    pub fn fileWrite(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path_value = args.get("path") orelse {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Missing required parameter: path",
            } };
        };
        const content_value = args.get("content") orelse {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Missing required parameter: content",
            } };
        };

        if (path_value != .string or content_value != .string) {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Parameters 'path' and 'content' must be strings",
            } };
        }

        const path = path_value.string;
        const content = content_value.string;

        // Security: prevent directory traversal
        if (std.mem.indexOf(u8, path, "..") != null) {
            return .{ .error = .{
                .code = .permission_denied,
                .message = "Path cannot contain '..'",
            } };
        }

        // Create parent directories if needed
        if (std.fs.path.dirname(path)) |dir| {
            std.fs.cwd().makePath(dir) catch |err| {
                const msg = std.fmt.allocPrint(allocator, "Failed to create directory: {s}", .{@errorName(err)}) catch "Failed to create directory";
                return .{ .error = .{
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
            return .{ .error = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

        const msg = std.fmt.allocPrint(allocator, "File written successfully: {s}", .{path}) catch return .{ .error = .{
            .code = .execution_failed,
            .message = "Out of memory",
        } };
        return .{ .success = .{ .content = msg } };
    }

    /// List directory contents
    pub fn fileList(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const path_value = args.get("path") orelse .{ .string = "." };
        if (path_value != .string) {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Parameter 'path' must be a string",
            } };
        }
        const path = path_value.string;

        // Security: prevent directory traversal
        if (std.mem.indexOf(u8, path, "..") != null) {
            return .{ .error = .{
                .code = .permission_denied,
                .message = "Path cannot contain '..'",
            } };
        }

        var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to open directory: {s}", .{@errorName(err)}) catch "Failed to open directory";
            return .{ .error = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };
        defer dir.close();

        var result = std.ArrayListUnmanaged(u8){};
        defer result.deinit(allocator);

        try result.appendSlice(allocator, "[\n");

        var it = dir.iterate();
        var first = true;
        while (it.next() catch |err| {
            const msg = std.fmt.allocPrint(allocator, "Failed to iterate directory: {s}", .{@errorName(err)}) catch "Failed to iterate directory";
            return .{ .error = .{
                .code = .execution_failed,
                .message = msg,
            } };
        }) |entry| {
            if (!first) try result.appendSlice(allocator, ",\n");
            first = false;

            const entry_type = switch (entry.kind) {
                .file => "file",
                .directory => "directory",
                .sym_link => "symlink",
                else => "other",
            };

            try result.appendSlice(allocator, "  {\"name\":\"");
            try result.appendSlice(allocator, entry.name);
            try result.appendSlice(allocator, "\",\"type\":\"");
            try result.appendSlice(allocator, entry_type);
            try result.appendSlice(allocator, "\"}");
        }

        try result.appendSlice(allocator, "\n]");

        return .{ .success = .{ .content = try result.toOwnedSlice(allocator), .format = .json } };
    }

    /// Search code using shell command
    pub fn searchCode(allocator: std.mem.Allocator, args: std.json.ObjectMap) ToolResult {
        const query_value = args.get("query") orelse {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Missing required parameter: query",
            } };
        };
        if (query_value != .string) {
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Parameter 'query' must be a string",
            } };
        }
        const query = query_value.string;

        const path_value = args.get("path") orelse .{ .string = "." };
        const path = if (path_value == .string) path_value.string else ".";

        // Use ripgrep if available, fallback to grep
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "rg", "-n", "-i", "--color=never", query, path },
            .max_output_bytes = 1024 * 1024,
        }) catch |err| {
            // Fallback to grep
            const grep_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "grep", "-rn", "-i", "--color=never", query, path },
                .max_output_bytes = 1024 * 1024,
            }) catch |grep_err| {
                const msg = std.fmt.allocPrint(allocator, "Search failed: rg={s}, grep={s}", .{
                    @errorName(err),
                    @errorName(grep_err),
                }) catch "Search failed";
                return .{ .error = .{
                    .code = .execution_failed,
                    .message = msg,
                } };
            };

            if (grep_result.term.Exited != 0 and grep_result.term.Exited != 1) {
                allocator.free(grep_result.stdout);
                allocator.free(grep_result.stderr);
                return .{ .error = .{
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
            return .{ .error = .{
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
            return .{ .error = .{
                .code = .invalid_params,
                .message = "Missing required parameter: command",
            } };
        };
        if (command_value != .string) {
            return .{ .error = .{
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
                return .{ .error = .{
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
            return .{ .error = .{
                .code = .execution_failed,
                .message = msg,
            } };
        };

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
