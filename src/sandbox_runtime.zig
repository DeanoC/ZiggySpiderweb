const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const tool_registry = @import("ziggy-tool-runtime").tool_registry;

const max_ipc_line_bytes: usize = 16 * 1024 * 1024;
const mount_startup_timeout_ms: u64 = 15_000;
const mount_poll_interval_ms: u64 = 100;
const sandbox_namespace_root = "/underworld";
const sandbox_workspace_path = "/underworld/workspace";

pub const Options = struct {
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    project_id: []const u8,
    project_token: ?[]const u8 = null,
    workspace_url: []const u8,
    workspace_auth_token: ?[]const u8 = null,
    runtime_cfg: Config.RuntimeConfig,
};

pub const SandboxRuntime = struct {
    allocator: std.mem.Allocator,
    agent_id: []u8,
    project_id: []u8,
    workspace_url: []u8,
    project_token: ?[]u8 = null,
    workspace_auth_token: ?[]u8 = null,
    workspace_mount_path: []u8,
    workspace_bind_source_path: []u8,
    child_bin_path: []u8,
    mount_process: ?std.process.Child = null,
    owns_mount_process: bool = false,
    child: std.process.Child,
    io_mutex: std.Thread.Mutex = .{},
    runtime_cfg: Config.RuntimeConfig,

    pub fn create(options: Options) !*SandboxRuntime {
        if (builtin.os.tag != .linux) return error.UnsupportedOs;

        const self = try options.allocator.create(SandboxRuntime);
        errdefer options.allocator.destroy(self);

        var runtime_cfg_for_child = try options.runtime_cfg.clone(options.allocator);
        errdefer runtime_cfg_for_child.deinit(options.allocator);

        const mounts_root_trimmed = std.mem.trim(u8, runtime_cfg_for_child.sandbox_mounts_root, " \t\r\n");
        if (mounts_root_trimmed.len == 0) return error.InvalidSandboxConfig;

        try ensurePathExists(mounts_root_trimmed);
        const project_mount_root = try std.fs.path.join(options.allocator, &.{ mounts_root_trimmed, options.project_id });
        defer options.allocator.free(project_mount_root);
        try ensurePathExists(project_mount_root);
        cleanupStaleAgentMounts(options.allocator, project_mount_root, options.agent_id);

        const workspace_mount_path = try makeRuntimeMountPath(options.allocator, project_mount_root, options.agent_id);
        errdefer options.allocator.free(workspace_mount_path);
        // Runtime-unique mount path: recycle only this runtime's path so concurrent
        // agents on the same project do not unmount each other.
        detachMountAtPath(options.allocator, workspace_mount_path);
        try ensurePathExists(workspace_mount_path);

        const child_bin_path = try resolveChildBinaryPath(options.allocator, std.mem.trim(u8, runtime_cfg_for_child.sandbox_agent_runtime_bin, " \t\r\n"));
        errdefer options.allocator.free(child_bin_path);

        // Inside bwrap, workspace mount may be read-only depending on exported source.
        // Keep runtime persistence under sandbox-local /tmp to avoid startup failures.
        var ltm_hash = std.hash.Wyhash.init(0);
        ltm_hash.update(options.project_id);
        ltm_hash.update("|");
        ltm_hash.update(options.agent_id);
        const ltm_key = ltm_hash.final();
        options.allocator.free(runtime_cfg_for_child.ltm_directory);
        runtime_cfg_for_child.ltm_directory = try std.fmt.allocPrint(options.allocator, "/tmp/.spiderweb-ltm/{x}", .{ltm_key});

        var mount_process: ?std.process.Child = null;
        var owns_mount_process = false;
        errdefer {
            if (owns_mount_process) {
                if (mount_process) |*mount_child| {
                    _ = mount_child.kill() catch {};
                    _ = mount_child.wait() catch {};
                }
            }
        }

        mount_process = try spawnProjectMountProcess(
            options.allocator,
            std.mem.trim(u8, runtime_cfg_for_child.sandbox_fs_mount_bin, " \t\r\n"),
            options.workspace_url,
            options.project_id,
            options.project_token,
            options.workspace_auth_token,
            workspace_mount_path,
        );
        owns_mount_process = true;
        try waitForMountPoint(options.allocator, workspace_mount_path, mount_startup_timeout_ms);
        if (!isMountPoint(options.allocator, workspace_mount_path)) {
            return error.ProjectMountUnavailable;
        }
        const workspace_bind_source_path = try resolveWorkspaceBindSourcePath(options.allocator, workspace_mount_path);
        errdefer options.allocator.free(workspace_bind_source_path);

        var child = try spawnSandboxChild(
            options.allocator,
            std.mem.trim(u8, runtime_cfg_for_child.sandbox_launcher, " \t\r\n"),
            child_bin_path,
            workspace_bind_source_path,
            options.agent_id,
            runtime_cfg_for_child,
        );
        errdefer {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
        }

        self.* = .{
            .allocator = options.allocator,
            .agent_id = try options.allocator.dupe(u8, options.agent_id),
            .project_id = try options.allocator.dupe(u8, options.project_id),
            .workspace_url = try options.allocator.dupe(u8, options.workspace_url),
            .project_token = if (options.project_token) |value| try options.allocator.dupe(u8, value) else null,
            .workspace_auth_token = if (options.workspace_auth_token) |value| try options.allocator.dupe(u8, value) else null,
            .workspace_mount_path = workspace_mount_path,
            .workspace_bind_source_path = workspace_bind_source_path,
            .child_bin_path = child_bin_path,
            .mount_process = mount_process,
            .owns_mount_process = owns_mount_process,
            .child = child,
            .runtime_cfg = runtime_cfg_for_child,
        };
        return self;
    }

    pub fn destroy(self: *SandboxRuntime) void {
        self.io_mutex.lock();
        _ = self.child.kill() catch {};
        _ = self.child.wait() catch {};
        self.io_mutex.unlock();

        if (self.owns_mount_process) {
            if (self.mount_process) |*mount_child| {
                _ = mount_child.kill() catch {};
                _ = mount_child.wait() catch {};
            }
        }
        detachMountAtPath(self.allocator, self.workspace_mount_path);

        self.allocator.free(self.agent_id);
        self.allocator.free(self.project_id);
        self.allocator.free(self.workspace_url);
        if (self.project_token) |value| self.allocator.free(value);
        if (self.workspace_auth_token) |value| self.allocator.free(value);
        self.allocator.free(self.workspace_mount_path);
        self.allocator.free(self.workspace_bind_source_path);
        self.allocator.free(self.child_bin_path);
        self.runtime_cfg.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn isHealthy(self: *SandboxRuntime) bool {
        if (!processIsAlive(self.child.id)) return false;

        if (self.owns_mount_process) {
            const mount_child = self.mount_process orelse return false;
            if (!processIsAlive(mount_child.id)) return false;
        }

        return isMountPoint(self.allocator, self.workspace_mount_path);
    }

    pub fn handleMessageFramesWithDebug(
        self: *SandboxRuntime,
        raw_json: []const u8,
        emit_debug: bool,
    ) ![][]u8 {
        _ = self;
        _ = raw_json;
        _ = emit_debug;
        return error.UnsupportedOperation;
    }

    pub fn executeWorldTool(
        self: *SandboxRuntime,
        allocator: std.mem.Allocator,
        tool_name: []const u8,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        self.io_mutex.lock();
        defer self.io_mutex.unlock();

        const request_line = buildToolRequestLine(allocator, tool_name, args_json) catch |err| {
            return toolBridgeFailureOwned(
                allocator,
                std.fmt.allocPrint(allocator, "failed to build tool request: {s}", .{@errorName(err)}) catch null,
            );
        };
        defer allocator.free(request_line);

        if (!processIsAlive(self.child.id)) {
            self.restartChildRuntime() catch |err| {
                return toolBridgeFailureOwned(
                    allocator,
                    std.fmt.allocPrint(allocator, "sandbox child restart failed before request: {s}", .{@errorName(err)}) catch null,
                );
            };
        }

        const child_stdin = self.child.stdin orelse return toolBridgeFailure(allocator, "sandbox child stdin pipe is unavailable");
        const child_stdout = self.child.stdout orelse return toolBridgeFailure(allocator, "sandbox child stdout pipe is unavailable");

        child_stdin.writeAll(request_line) catch |err| {
            if (isRecoverableBridgeError(err)) {
                self.restartChildRuntime() catch |restart_err| {
                    return toolBridgeFailureOwned(
                        allocator,
                        std.fmt.allocPrint(allocator, "sandbox tool request write failed: {s}; restart failed: {s}", .{ @errorName(err), @errorName(restart_err) }) catch null,
                    );
                };
            }
            return toolBridgeFailureOwned(
                allocator,
                std.fmt.allocPrint(allocator, "sandbox tool request write failed: {s}", .{@errorName(err)}) catch null,
            );
        };
        child_stdin.writeAll("\n") catch |err| {
            if (isRecoverableBridgeError(err)) {
                self.restartChildRuntime() catch |restart_err| {
                    return toolBridgeFailureOwned(
                        allocator,
                        std.fmt.allocPrint(allocator, "sandbox tool request newline failed: {s}; restart failed: {s}", .{ @errorName(err), @errorName(restart_err) }) catch null,
                    );
                };
            }
            return toolBridgeFailureOwned(
                allocator,
                std.fmt.allocPrint(allocator, "sandbox tool request newline failed: {s}", .{@errorName(err)}) catch null,
            );
        };

        const response_line = readLineAlloc(allocator, child_stdout, max_ipc_line_bytes) catch |err| {
            if (isRecoverableBridgeError(err)) {
                self.restartChildRuntime() catch |restart_err| {
                    return toolBridgeFailureOwned(
                        allocator,
                        std.fmt.allocPrint(allocator, "sandbox tool response read failed: {s}; restart failed: {s}", .{ @errorName(err), @errorName(restart_err) }) catch null,
                    );
                };
            }
            return toolBridgeFailureOwned(
                allocator,
                std.fmt.allocPrint(allocator, "sandbox tool response read failed: {s}", .{@errorName(err)}) catch null,
            );
        };
        defer allocator.free(response_line);

        var parsed_result = parseToolResponseLine(allocator, response_line) catch |err| {
            return toolBridgeFailureOwned(
                allocator,
                std.fmt.allocPrint(allocator, "sandbox tool response parse failed: {s}", .{@errorName(err)}) catch null,
            );
        };
        if (shouldRestartOnToolFailure(parsed_result)) {
            parsed_result.deinit(allocator);
            self.restartMountAndChild() catch |restart_err| {
                return toolBridgeFailureOwned(
                    allocator,
                    std.fmt.allocPrint(allocator, "sandbox mount/runtime restart failed: {s}", .{@errorName(restart_err)}) catch null,
                );
            };
            return toolBridgeFailure(allocator, "sandbox runtime restarted after tool failure; request was not retried");
        }
        return parsed_result;
    }

    fn restartChildRuntime(self: *SandboxRuntime) !void {
        _ = self.child.kill() catch {};
        _ = self.child.wait() catch {};

        const replacement = try spawnSandboxChild(
            self.allocator,
            std.mem.trim(u8, self.runtime_cfg.sandbox_launcher, " \t\r\n"),
            self.child_bin_path,
            self.workspace_bind_source_path,
            self.agent_id,
            self.runtime_cfg,
        );
        self.child = replacement;
    }

    fn restartMountAndChild(self: *SandboxRuntime) !void {
        _ = self.child.kill() catch {};
        _ = self.child.wait() catch {};

        if (self.owns_mount_process) {
            if (self.mount_process) |*mount_child| {
                _ = mount_child.kill() catch {};
                _ = mount_child.wait() catch {};
            }
        }
        self.mount_process = null;

        detachMountAtPath(self.allocator, self.workspace_mount_path);
        try ensurePathExists(self.workspace_mount_path);

        var mount_process = try spawnProjectMountProcess(
            self.allocator,
            std.mem.trim(u8, self.runtime_cfg.sandbox_fs_mount_bin, " \t\r\n"),
            self.workspace_url,
            self.project_id,
            self.project_token,
            self.workspace_auth_token,
            self.workspace_mount_path,
        );
        errdefer {
            _ = mount_process.kill() catch {};
            _ = mount_process.wait() catch {};
        }

        try waitForMountPoint(self.allocator, self.workspace_mount_path, mount_startup_timeout_ms);
        if (!isMountPoint(self.allocator, self.workspace_mount_path)) {
            return error.ProjectMountUnavailable;
        }
        self.allocator.free(self.workspace_bind_source_path);
        self.workspace_bind_source_path = try resolveWorkspaceBindSourcePath(self.allocator, self.workspace_mount_path);

        var replacement = try spawnSandboxChild(
            self.allocator,
            std.mem.trim(u8, self.runtime_cfg.sandbox_launcher, " \t\r\n"),
            self.child_bin_path,
            self.workspace_bind_source_path,
            self.agent_id,
            self.runtime_cfg,
        );
        errdefer {
            _ = replacement.kill() catch {};
            _ = replacement.wait() catch {};
        }

        self.mount_process = mount_process;
        self.owns_mount_process = true;
        self.child = replacement;
    }

    pub fn dispatchWorldTool(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        tool_name: []const u8,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        const runtime: *SandboxRuntime = @ptrCast(@alignCast(ctx));
        return runtime.executeWorldTool(allocator, tool_name, args_json);
    }
};

fn isRecoverableBridgeError(err: anyerror) bool {
    return switch (err) {
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.NotOpenForWriting,
        => true,
        else => false,
    };
}

fn shouldRestartOnToolFailure(result: tool_registry.ToolExecutionResult) bool {
    return switch (result) {
        .success => false,
        .failure => |failure| blk: {
            if (failure.code == .timeout) break :blk true;
            break :blk containsAnyIgnoreCase(failure.message, &.{
                "filesystem_unavailable",
                "input/output error",
                "transport endpoint is not connected",
                "stale file handle",
                "project mount unavailable",
                "no such device",
                "connection reset",
                "command timed out",
            });
        },
    };
}

fn containsAnyIgnoreCase(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (std.ascii.indexOfIgnoreCase(haystack, needle) != null) return true;
    }
    return false;
}

fn makeRuntimeMountPath(
    allocator: std.mem.Allocator,
    project_mount_root: []const u8,
    agent_id: []const u8,
) ![]u8 {
    var nonce_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&nonce_bytes);
    const nonce = std.fmt.bytesToHex(nonce_bytes, .lower);
    const mount_leaf = try std.fmt.allocPrint(allocator, "{s}-{s}", .{ agent_id, nonce });
    defer allocator.free(mount_leaf);
    return std.fs.path.join(allocator, &.{ project_mount_root, mount_leaf });
}

fn cleanupStaleAgentMounts(
    allocator: std.mem.Allocator,
    project_mount_root: []const u8,
    agent_id: []const u8,
) void {
    var prefix_buf = std.ArrayListUnmanaged(u8){};
    defer prefix_buf.deinit(allocator);
    prefix_buf.appendSlice(allocator, agent_id) catch return;
    prefix_buf.append(allocator, '-') catch return;
    const prefix = prefix_buf.items;

    var dir = std.fs.openDirAbsolute(project_mount_root, .{ .iterate = true }) catch return;
    defer dir.close();

    var it = dir.iterate();
    while (true) {
        const maybe_entry = it.next() catch break;
        const entry = maybe_entry orelse break;
        if (entry.kind != .directory and entry.kind != .sym_link) continue;
        if (!std.mem.startsWith(u8, entry.name, prefix)) continue;

        const path = std.fs.path.join(allocator, &.{ project_mount_root, entry.name }) catch continue;
        defer allocator.free(path);
        detachMountAtPath(allocator, path);
    }
}


fn resolveWorkspaceBindSourcePath(
    allocator: std.mem.Allocator,
    workspace_mount_path: []const u8,
) ![]u8 {
    return allocator.dupe(u8, workspace_mount_path);
}

fn buildToolRequestLine(allocator: std.mem.Allocator, tool_name: []const u8, args_json: []const u8) ![]u8 {
    const escaped_tool_name = try std.json.Stringify.valueAlloc(allocator, tool_name, .{
        .emit_null_optional_fields = true,
        .whitespace = .minified,
    });
    defer allocator.free(escaped_tool_name);

    const escaped_args = try std.json.Stringify.valueAlloc(allocator, args_json, .{
        .emit_null_optional_fields = true,
        .whitespace = .minified,
    });
    defer allocator.free(escaped_args);

    return std.fmt.allocPrint(
        allocator,
        "{{\"tool\":{s},\"args_json\":{s}}}",
        .{ escaped_tool_name, escaped_args },
    );
}

fn parseToolResponseLine(allocator: std.mem.Allocator, line: []const u8) !tool_registry.ToolExecutionResult {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidChildResponse;

    const ok_val = parsed.value.object.get("ok") orelse return error.InvalidChildResponse;
    if (ok_val != .bool) return error.InvalidChildResponse;

    if (ok_val.bool) {
        const payload_val = parsed.value.object.get("payload_json") orelse return error.InvalidChildResponse;
        if (payload_val != .string) return error.InvalidChildResponse;
        return .{ .success = .{
            .payload_json = try allocator.dupe(u8, payload_val.string),
        } };
    }

    const code_val = parsed.value.object.get("code") orelse return error.InvalidChildResponse;
    if (code_val != .string) return error.InvalidChildResponse;
    const message_val = parsed.value.object.get("message") orelse return error.InvalidChildResponse;
    if (message_val != .string) return error.InvalidChildResponse;

    return .{ .failure = .{
        .code = parseToolErrorCode(code_val.string),
        .message = try allocator.dupe(u8, message_val.string),
    } };
}

fn parseToolErrorCode(raw: []const u8) tool_registry.ToolErrorCode {
    if (std.mem.eql(u8, raw, "invalid_params")) return .invalid_params;
    if (std.mem.eql(u8, raw, "permission_denied")) return .permission_denied;
    if (std.mem.eql(u8, raw, "timeout")) return .timeout;
    if (std.mem.eql(u8, raw, "tool_not_found")) return .tool_not_found;
    if (std.mem.eql(u8, raw, "tool_not_executable")) return .tool_not_executable;
    return .execution_failed;
}

fn toolBridgeFailure(allocator: std.mem.Allocator, message: []const u8) tool_registry.ToolExecutionResult {
    return .{ .failure = .{
        .code = .execution_failed,
        .message = allocator.dupe(u8, message) catch allocator.dupe(u8, "sandbox tool bridge failed") catch @panic("out of memory while reporting sandbox bridge failure"),
    } };
}

fn toolBridgeFailureOwned(allocator: std.mem.Allocator, maybe_message: ?[]u8) tool_registry.ToolExecutionResult {
    if (maybe_message) |message| {
        return .{ .failure = .{
            .code = .execution_failed,
            .message = message,
        } };
    }
    return toolBridgeFailure(allocator, "sandbox tool bridge failed");
}

fn spawnProjectMountProcess(
    allocator: std.mem.Allocator,
    fs_mount_bin_raw: []const u8,
    workspace_url: []const u8,
    project_id: []const u8,
    project_token: ?[]const u8,
    workspace_auth_token: ?[]const u8,
    mount_path: []const u8,
) !std.process.Child {
    const fs_mount_bin = if (fs_mount_bin_raw.len > 0) fs_mount_bin_raw else "spiderweb-fs-mount";

    var args = std.ArrayListUnmanaged([]const u8){};
    defer args.deinit(allocator);

    try args.append(allocator, fs_mount_bin);
    try args.append(allocator, "--workspace-url");
    try args.append(allocator, workspace_url);
    try args.append(allocator, "--project-id");
    try args.append(allocator, project_id);
    if (project_token) |token| {
        try args.append(allocator, "--project-token");
        try args.append(allocator, token);
    }
    if (workspace_auth_token) |token| {
        try args.append(allocator, "--auth-token");
        try args.append(allocator, token);
    }
    try args.append(allocator, "--workspace-sync-interval-ms");
    try args.append(allocator, "5000");
    try args.append(allocator, "mount");
    try args.append(allocator, mount_path);

    var child = std.process.Child.init(args.items, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    return child;
}

fn spawnSandboxChild(
    allocator: std.mem.Allocator,
    launcher_raw: []const u8,
    child_bin_path: []const u8,
    workspace_bind_source_path: []const u8,
    agent_id: []const u8,
    runtime_cfg: Config.RuntimeConfig,
) !std.process.Child {
    const launcher = if (launcher_raw.len > 0) launcher_raw else "bwrap";

    const runtime_json = try std.json.Stringify.valueAlloc(allocator, runtime_cfg, .{
        .emit_null_optional_fields = true,
        .whitespace = .minified,
    });
    defer allocator.free(runtime_json);

    const child_dir = std.fs.path.dirname(child_bin_path) orelse return error.InvalidChildBinary;

    var args = std.ArrayListUnmanaged([]const u8){};
    defer args.deinit(allocator);

    try args.append(allocator, launcher);
    try args.append(allocator, "--die-with-parent");
    try args.append(allocator, "--new-session");
    try args.append(allocator, "--clearenv");
    try args.append(allocator, "--proc");
    try args.append(allocator, "/proc");
    try args.append(allocator, "--dev");
    try args.append(allocator, "/dev");
    try args.append(allocator, "--tmpfs");
    try args.append(allocator, "/tmp");
    try args.append(allocator, "--tmpfs");
    try args.append(allocator, sandbox_namespace_root);
    try args.append(allocator, "--ro-bind");
    try args.append(allocator, "/usr");
    try args.append(allocator, "/usr");
    if (pathExists("/bin")) {
        try args.append(allocator, "--ro-bind");
        try args.append(allocator, "/bin");
        try args.append(allocator, "/bin");
    }
    if (pathExists("/lib")) {
        try args.append(allocator, "--ro-bind");
        try args.append(allocator, "/lib");
        try args.append(allocator, "/lib");
    }
    if (pathExists("/lib64")) {
        try args.append(allocator, "--ro-bind");
        try args.append(allocator, "/lib64");
        try args.append(allocator, "/lib64");
    }
    try args.append(allocator, "--ro-bind");
    try args.append(allocator, child_dir);
    try args.append(allocator, child_dir);
    try args.append(allocator, "--bind");
    try args.append(allocator, workspace_bind_source_path);
    try args.append(allocator, sandbox_namespace_root);
    try args.append(allocator, "--chdir");
    try args.append(allocator, sandbox_namespace_root);
    try args.append(allocator, "--setenv");
    try args.append(allocator, "HOME");
    try args.append(allocator, sandbox_workspace_path);
    try args.append(allocator, "--setenv");
    try args.append(allocator, "PATH");
    try args.append(allocator, "/usr/bin:/bin");
    try args.append(allocator, "--");
    try args.append(allocator, child_bin_path);
    try args.append(allocator, "--agent-id");
    try args.append(allocator, agent_id);

    var child = std.process.Child.init(args.items, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;

    var env = std.process.EnvMap.init(allocator);
    defer env.deinit();
    try env.put("SPIDERWEB_CHILD_RUNTIME_CONFIG", runtime_json);
    try env.put("SPIDERWEB_WORKSPACE_ROOT", sandbox_namespace_root);
    child.env_map = &env;
    try child.spawn();

    // Child makes an internal copy at spawn time.
    child.env_map = null;

    return child;
}

fn readLineAlloc(allocator: std.mem.Allocator, file: std.fs.File, max_bytes: usize) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var buf: [1024]u8 = undefined;
    while (out.items.len < max_bytes) {
        const read_n = try file.read(&buf);
        if (read_n == 0) break;
        const chunk = buf[0..read_n];
        if (std.mem.indexOfScalar(u8, chunk, '\n')) |idx| {
            try out.appendSlice(allocator, chunk[0..idx]);
            return out.toOwnedSlice(allocator);
        }
        try out.appendSlice(allocator, chunk);
    }

    if (out.items.len == 0) return error.EndOfStream;
    if (out.items.len >= max_bytes) return error.IpcFrameTooLarge;
    return out.toOwnedSlice(allocator);
}

fn pathExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.accessAbsolute(path, .{}) catch return false;
        return true;
    }
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn detachMountAtPath(allocator: std.mem.Allocator, path: []const u8) void {
    runBestEffortCommand(allocator, &.{ "fusermount3", "-u", "-z", path });
    runBestEffortCommand(allocator, &.{ "umount", "-l", path });

    if (std.fs.path.isAbsolute(path)) {
        std.fs.deleteTreeAbsolute(path) catch {};
    } else {
        std.fs.cwd().deleteTree(path) catch {};
    }
}

fn runBestEffortCommand(allocator: std.mem.Allocator, argv: []const []const u8) void {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch return;
    _ = child.wait() catch {};
}

fn processIsAlive(pid_raw: anytype) bool {
    if (builtin.os.tag != .linux) return true;

    const pid: std.posix.pid_t = @intCast(pid_raw);
    if (pid <= 0) return false;

    std.posix.kill(pid, 0) catch |err| switch (err) {
        error.PermissionDenied => return true,
        error.ProcessNotFound => return false,
        else => return false,
    };
    return true;
}

fn ensurePathExists(path: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        const rel = std.mem.trimLeft(u8, path, "/");
        if (rel.len == 0) return;
        try root.makePath(rel);
        return;
    }
    try std.fs.cwd().makePath(path);
}

fn waitForMountPoint(allocator: std.mem.Allocator, mount_path: []const u8, timeout_ms: u64) !void {
    const started_ms = std.time.milliTimestamp();
    const timeout_i64: i64 = @intCast(timeout_ms);

    while (true) {
        if (isMountPoint(allocator, mount_path)) return;

        const elapsed = std.time.milliTimestamp() - started_ms;
        if (elapsed >= timeout_i64) break;
        std.Thread.sleep(mount_poll_interval_ms * std.time.ns_per_ms);
    }
    return error.ProjectMountUnavailable;
}

fn isMountPoint(allocator: std.mem.Allocator, path: []const u8) bool {
    const canonical_path = std.fs.realpathAlloc(allocator, path) catch return false;
    defer allocator.free(canonical_path);

    const content = std.fs.cwd().readFileAlloc(allocator, "/proc/self/mountinfo", 1024 * 1024) catch return false;
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        var idx: usize = 0;
        var mount_point_escaped: ?[]const u8 = null;
        while (fields.next()) |field| {
            if (idx == 4) {
                mount_point_escaped = field;
                break;
            }
            idx += 1;
        }
        const escaped = mount_point_escaped orelse continue;
        const mount_point = decodeMountInfoPath(allocator, escaped) catch continue;
        defer allocator.free(mount_point);
        if (std.mem.eql(u8, mount_point, canonical_path)) return true;
    }
    return false;
}

fn decodeMountInfoPath(allocator: std.mem.Allocator, escaped: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < escaped.len) {
        if (escaped[i] == '\\' and i + 3 < escaped.len and isOctalDigit(escaped[i + 1]) and isOctalDigit(escaped[i + 2]) and isOctalDigit(escaped[i + 3])) {
            const value = std.fmt.parseInt(u8, escaped[i + 1 .. i + 4], 8) catch {
                try out.append(allocator, escaped[i]);
                i += 1;
                continue;
            };
            try out.append(allocator, value);
            i += 4;
            continue;
        }
        try out.append(allocator, escaped[i]);
        i += 1;
    }

    return out.toOwnedSlice(allocator);
}

fn isOctalDigit(value: u8) bool {
    return value >= '0' and value <= '7';
}

fn resolveChildBinaryPath(allocator: std.mem.Allocator, configured: []const u8) ![]u8 {
    if (configured.len > 0 and std.fs.path.isAbsolute(configured)) {
        return allocator.dupe(u8, configured);
    }

    const self_exe = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_exe);
    const self_dir = std.fs.path.dirname(self_exe) orelse return error.InvalidExecutablePath;

    const child_name = if (configured.len > 0) configured else "spiderweb-agent-runtime";
    return std.fs.path.join(allocator, &.{ self_dir, child_name });
}
