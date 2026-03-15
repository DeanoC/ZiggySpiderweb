const std = @import("std");
const fs_router = @import("acheron_fs_router");
const hybrid_mount_provider = @import("hybrid_mount_provider.zig");
const mount_provider = @import("spiderweb_mount_provider");
const mount_session = @import("mount_session.zig");
const namespace_client = @import("namespace_client.zig");
const native_protocol = @import("native_mount_protocol.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4 or !std.mem.eql(u8, args[1], "serve") or !std.mem.eql(u8, args[2], "--config")) {
        try printUsage();
        return error.InvalidArguments;
    }

    const config_path = args[3];
    const config_json = try readFileAllocAny(allocator, config_path, 1024 * 1024);
    defer allocator.free(config_json);

    var config = try native_protocol.parseLaunchConfigOwned(allocator, config_json);
    defer config.deinit(allocator);

    var endpoint_configs = try allocator.alloc(fs_router.EndpointConfig, config.endpoints.len);
    defer allocator.free(endpoint_configs);
    for (config.endpoints, 0..) |endpoint, idx| {
        endpoint_configs[idx] = .{
            .name = endpoint.name,
            .url = endpoint.url,
            .export_name = endpoint.export_name,
            .mount_path = endpoint.mount_path,
            .auth_token = endpoint.auth_token,
        };
    }

    var router = try fs_router.Router.init(allocator, endpoint_configs);
    defer router.deinit();

    var namespace_client_instance: ?namespace_client.NamespaceClient = null;
    defer if (namespace_client_instance) |*client| client.deinit();

    const provider = if (config.namespace) |namespace_binding| blk: {
        var client = try namespace_client.NamespaceClient.connect(allocator, namespace_binding.namespace_url, namespace_binding.auth_token);
        errdefer client.deinit();
        try client.controlAgentEnsure(namespace_binding.agent_id);
        var attach_info = try client.controlSessionAttach(.{
            .session_key = namespace_binding.session_key,
            .agent_id = namespace_binding.agent_id,
            .project_id = namespace_binding.project_id,
            .project_token = namespace_binding.project_token,
        });
        defer attach_info.deinit(allocator);
        try client.attachNamespaceRoot(attach_info.session_key);
        namespace_client_instance = client;
        break :blk try hybrid_mount_provider.init(allocator, &router, &namespace_client_instance.?);
    } else try mount_provider.initRouterProvider(allocator, &router);

    var session = mount_session.MountSession.init(allocator, provider);
    defer session.deinit();

    var keepalive_thread: ?std.Thread = null;
    var keepalive_state: ?KeepaliveState = null;
    defer if (keepalive_thread) |thread| {
        if (keepalive_state) |*state| {
            state.stop.store(true, .monotonic);
        }
        thread.join();
    };
    if (config.namespace != null) {
        keepalive_state = .{
            .session = &session,
            .interval_ms = config.namespace_keepalive_interval_ms,
        };
        keepalive_thread = try std.Thread.spawn(.{}, keepaliveThreadMain, .{&keepalive_state.?});
    }

    var stdin_file = std.fs.File.stdin();
    var stdout_file = std.fs.File.stdout();
    var reader = stdin_file.reader(&.{});
    const stdin_reader = &reader.interface;

    while (true) {
        const line = stdin_reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;
        const response = handleRequest(allocator, &session, trimmed) catch |err| blk: {
            const encoded = try native_protocol.encodeErrorResponse(allocator, .{
                .op = "unknown",
                .code = errorCode(err),
                .message = @errorName(err),
            });
            break :blk encoded;
        };
        defer allocator.free(response);
        try stdout_file.writeAll(response);
        try stdout_file.writeAll("\n");
    }
}

const KeepaliveState = struct {
    session: *mount_session.MountSession,
    interval_ms: u64,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn keepaliveThreadMain(state: *KeepaliveState) void {
    while (!state.stop.load(.monotonic)) {
        std.Thread.sleep(state.interval_ms * std.time.ns_per_ms);
        _ = state.session.tryKeepAliveIfIdle() catch false;
    }
}

fn handleRequest(allocator: std.mem.Allocator, session: *mount_session.MountSession, line: []const u8) ![]u8 {
    var request = try native_protocol.parseRequestOwned(allocator, line);
    defer request.deinit(allocator);

    switch (request) {
        .ping => {
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "ping", .result_json = "{}" });
        },
        .getattr => |payload| {
            const attr_json = try session.getattr(payload.path);
            defer allocator.free(attr_json);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "getattr", .result_json = attr_json });
        },
        .readdir => |payload| {
            const listing_json = try session.readdir(payload.path, payload.cookie, payload.max_entries);
            defer allocator.free(listing_json);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "readdir", .result_json = listing_json });
        },
        .statfs => |payload| {
            const statfs_json = try session.statfs(payload.path);
            defer allocator.free(statfs_json);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "statfs", .result_json = statfs_json });
        },
        .open => |payload| {
            const handle_id = try session.openAndStoreHandle(payload.path, payload.flags);
            const open_file = session.lookupOpenHandle(handle_id) orelse return error.InvalidResponse;
            const writable = switch (open_file) {
                .router => |router_file| router_file.writable,
                .namespace => |namespace_file| namespace_file.writable,
            };
            return native_protocol.encodeSuccessResponse(allocator, .{
                .op = "open",
                .handle_id = handle_id,
                .writable = writable,
            });
        },
        .read => |payload| {
            const open_file = session.lookupOpenHandle(payload.handle_id) orelse return error.FileNotFound;
            const data = try session.read(open_file, payload.off, payload.len);
            defer allocator.free(data);
            const data_b64 = try native_protocol.encodeBase64(allocator, data);
            defer allocator.free(data_b64);
            return native_protocol.encodeSuccessResponse(allocator, .{
                .op = "read",
                .data_b64 = data_b64,
            });
        },
        .release => |payload| {
            session.releaseStoredHandle(payload.handle_id);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "release", .result_json = "{}" });
        },
        .create => |payload| {
            const handle_id = try session.createAndStoreHandle(payload.path, payload.mode, payload.flags);
            const open_file = session.lookupOpenHandle(handle_id) orelse return error.InvalidResponse;
            const writable = switch (open_file) {
                .router => |router_file| router_file.writable,
                .namespace => |namespace_file| namespace_file.writable,
            };
            return native_protocol.encodeSuccessResponse(allocator, .{
                .op = "create",
                .handle_id = handle_id,
                .writable = writable,
            });
        },
        .write => |payload| {
            const open_file = session.lookupOpenHandle(payload.handle_id) orelse return error.FileNotFound;
            const bytes_written = try session.write(open_file, payload.off, payload.data);
            return native_protocol.encodeSuccessResponse(allocator, .{
                .op = "write",
                .bytes_written = bytes_written,
            });
        },
        .truncate => |payload| {
            try session.truncate(payload.path, payload.size);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "truncate", .result_json = "{}" });
        },
        .unlink => |payload| {
            try session.unlink(payload.path);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "unlink", .result_json = "{}" });
        },
        .mkdir => |payload| {
            try session.mkdir(payload.path);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "mkdir", .result_json = "{}" });
        },
        .rmdir => |payload| {
            try session.rmdir(payload.path);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "rmdir", .result_json = "{}" });
        },
        .rename => |payload| {
            try session.rename(payload.old_path, payload.new_path);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "rename", .result_json = "{}" });
        },
        .symlink => |payload| {
            try session.symlink(payload.target, payload.link_path);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "symlink", .result_json = "{}" });
        },
        .setxattr => |payload| {
            try session.setxattr(payload.path, payload.name, payload.value, payload.flags);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "setxattr", .result_json = "{}" });
        },
        .getxattr => |payload| {
            const value = try session.getxattr(payload.path, payload.name);
            defer allocator.free(value);
            const value_b64 = try native_protocol.encodeBase64(allocator, value);
            defer allocator.free(value_b64);
            return native_protocol.encodeSuccessResponse(allocator, .{
                .op = "getxattr",
                .data_b64 = value_b64,
            });
        },
        .listxattr => |payload| {
            const names = try session.listxattr(payload.path);
            defer allocator.free(names);
            const names_b64 = try native_protocol.encodeBase64(allocator, names);
            defer allocator.free(names_b64);
            return native_protocol.encodeSuccessResponse(allocator, .{
                .op = "listxattr",
                .data_b64 = names_b64,
            });
        },
        .removexattr => |payload| {
            try session.removexattr(payload.path, payload.name);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "removexattr", .result_json = "{}" });
        },
        .lock => |payload| {
            const open_file = session.lookupOpenHandle(payload.handle_id) orelse return error.FileNotFound;
            const mode: mount_provider.LockMode = switch (payload.mode) {
                .shared => .shared,
                .exclusive => .exclusive,
                .unlock => .unlock,
            };
            try session.lock(open_file, mode, payload.wait);
            return native_protocol.encodeSuccessResponse(allocator, .{ .op = "lock", .result_json = "{}" });
        },
    }
}

fn errorCode(err: anyerror) []const u8 {
    return switch (err) {
        error.FileNotFound => "enoent",
        error.PermissionDenied => "eacces",
        error.NotDirectory => "enotdir",
        error.IsDirectory => "eisdir",
        error.AlreadyExists => "eexist",
        error.NoData => "enodata",
        error.NoSpace => "enospc",
        error.Range => "erange",
        error.WouldBlock => "eagain",
        error.CrossEndpointRename => "exdev",
        error.ReadOnlyFilesystem => "erofs",
        error.OperationNotSupported => "enosys",
        error.InvalidResponse => "einval",
        else => "eio",
    };
}

fn readFileAllocAny(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
        defer file.close();
        return file.readToEndAlloc(allocator, max_bytes);
    }
    return std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
}

fn printUsage() !void {
    try std.fs.File.stdout().writeAll(
        \\spiderweb-fs-helper - Native macOS mount helper
        \\
        \\Usage:
        \\  spiderweb-fs-helper serve --config <launch-config.json>
        \\
        \\This helper owns the Spiderweb router/provider lifecycle for the native
        \\macOS mount backend and speaks newline-delimited JSON requests on stdin.
        \\
    );
}
