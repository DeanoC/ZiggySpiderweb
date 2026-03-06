const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const connection_dispatcher = @import("connection_dispatcher.zig");
const memory = @import("ziggy-memory-store").memory;
const protocol = @import("spider-protocol").protocol;
const runtime_server_mod = @import("runtime_server.zig");
const runtime_handle_mod = @import("runtime_handle.zig");
const sandbox_runtime_mod = @import("sandbox_runtime.zig");
const websocket_transport = @import("websocket_transport.zig");
const fsrpc_session = @import("fsrpc_session.zig");
const fs_control_plane = @import("fs_control_plane.zig");
const chat_job_index = @import("chat_job_index.zig");
const fs_protocol = @import("fs_protocol.zig");
const fs_node_ops = @import("fs_node_ops.zig");
const fs_node_service = @import("fs_node_service.zig");
const fs_watch_runtime = @import("fs_watch_runtime.zig");
const agent_registry_mod = @import("agent_registry.zig");
const tool_registry = @import("ziggy-tool-runtime").tool_registry;
const unified = @import("spider-protocol").unified;

pub const RuntimeServer = runtime_server_mod.RuntimeServer;

const default_max_agent_runtimes: usize = 64;
const max_agent_id_len: usize = 64;
const max_project_id_len: usize = 128;
const max_actor_type_len: usize = 64;
const max_actor_id_len: usize = 128;
const debug_stream_log_filename = "debug-stream.ndjson";
const debug_stream_archive_prefix = "debug-stream-";
const debug_stream_archive_suffix = ".ndjson";
const debug_stream_archive_suffix_gz = ".ndjson.gz";
const debug_stream_rotate_max_bytes: u64 = 8 * 1024 * 1024;
const debug_stream_archive_keep: usize = 8;
const node_service_event_log_filename = "node-service-events.ndjson";
const node_service_event_archive_prefix = "node-service-events-";
const node_service_event_history_max_default: usize = 1024;
const local_node_export_path_env = "SPIDERWEB_LOCAL_NODE_EXPORT_PATH";
const local_node_export_name_env = "SPIDERWEB_LOCAL_NODE_EXPORT_NAME";
const local_node_export_ro_env = "SPIDERWEB_LOCAL_NODE_EXPORT_RO";
const local_node_fs_url_env = "SPIDERWEB_LOCAL_NODE_FS_URL";
const local_node_name_env = "SPIDERWEB_LOCAL_NODE_NAME";
const local_node_lease_ttl_env = "SPIDERWEB_LOCAL_NODE_LEASE_TTL_MS";
const local_node_heartbeat_ms_env = "SPIDERWEB_LOCAL_NODE_HEARTBEAT_MS";
const local_node_watcher_enabled_env = "SPIDERWEB_LOCAL_NODE_WATCHER_ENABLED";
const system_agent_id = "mother";
const system_project_id = fs_control_plane.spider_web_project_id;
const local_node_default_workspace_export_name = "system-workspace";
const local_node_agents_export_name = "system-agents";
const local_node_meta_export_name = "system-meta";
const local_node_chat_export_name = "system-chat";
const local_node_jobs_export_name = "system-jobs";
const local_node_mount_agents_root = "/agents";
const local_node_mount_meta = "/meta";
const local_node_mount_agents_self_chat = "/global/chat";
const local_node_mount_agents_self_jobs = "/global/jobs";
const local_node_mount_nodes_local_fs = "/nodes/local/fs";
const local_node_mount_projects_system_agents_root = "/nodes/local/projects/" ++ system_project_id ++ "/agents";
const local_node_mount_projects_system_meta = "/nodes/local/projects/" ++ system_project_id ++ "/meta";
const local_node_mount_projects_system_agents_self_chat = "/nodes/local/projects/" ++ system_project_id ++ "/global/chat";
const local_node_mount_projects_system_agents_self_jobs = "/nodes/local/projects/" ++ system_project_id ++ "/global/jobs";
const local_node_mount_projects_system_nodes_local_fs = "/nodes/local/projects/" ++ system_project_id ++ "/nodes/local/fs";
const local_node_mount_projects_system_fs_local = "/nodes/local/projects/" ++ system_project_id ++ "/fs/local::fs";
const legacy_local_node_mount_agents_self_capabilities = "/global/capabilities";
const legacy_local_node_mount_projects_system_agents_self_capabilities = "/nodes/local/projects/" ++ system_project_id ++ "/global/capabilities";
const control_operator_token_env = "SPIDERWEB_CONTROL_OPERATOR_TOKEN";
const control_project_scope_token_env = "SPIDERWEB_CONTROL_PROJECT_SCOPE_TOKEN";
const control_node_scope_token_env = "SPIDERWEB_CONTROL_NODE_SCOPE_TOKEN";
const node_service_event_history_max_env = "SPIDERWEB_NODE_SERVICE_EVENT_HISTORY_MAX";
const node_service_event_log_rotate_max_bytes_env = "SPIDERWEB_NODE_SERVICE_EVENT_LOG_ROTATE_MAX_BYTES";
const node_service_event_log_archive_keep_env = "SPIDERWEB_NODE_SERVICE_EVENT_LOG_ARCHIVE_KEEP";
const metrics_port_env = "SPIDERWEB_METRICS_PORT";
const control_protocol_version = "unified-v2";
const fsrpc_runtime_protocol_version = "acheron-1";
const fsrpc_node_protocol_version = "unified-v2-fs";
const fsrpc_node_proto_id: i64 = 2;
const node_tunnel_reply_timeout_ms: i32 = 45_000;
const service_presence_dispatch_queue_max: usize = 256;
// Each accepted websocket occupies a worker thread for its full lifetime.
// Internal fs-mount/runtime fan-out can exceed 16 steady-state connections,
// which starves new control/gui handshakes and appears as "can't connect".
const min_connection_worker_threads: usize = 64;
const runtime_warmup_stale_timeout_ms: i64 = 30_000;
const runtime_warmup_error_retry_backoff_ms: i64 = 10_000;
const runtime_residency_worker_interval_ms_default: u64 = 1_000;
const session_heartbeat_ttl_ms: i64 = 5 * 60 * 1000;
const agent_heartbeat_ttl_ms: i64 = 5 * 60 * 1000;

const DebugStreamFileSink = struct {
    allocator: std.mem.Allocator,
    path: ?[]u8 = null,
    gzip_available: bool = false,
    mutex: std.Thread.Mutex = .{},

    fn init(allocator: std.mem.Allocator, runtime_config: Config.RuntimeConfig) DebugStreamFileSink {
        var sink = DebugStreamFileSink{ .allocator = allocator };
        if (runtime_config.ltm_directory.len == 0) return sink;

        const path = sink.initPath(runtime_config.ltm_directory) catch |err| {
            std.log.warn("Debug stream file logging disabled: {s}", .{@errorName(err)});
            return sink;
        };
        sink.path = path;
        sink.gzip_available = commandExists(allocator, "gzip");
        if (!sink.gzip_available) {
            std.log.warn("gzip not found; debug stream archives will be uncompressed", .{});
        }

        sink.touch() catch |err| {
            std.log.warn("Debug stream file logging disabled for {s}: {s}", .{ path, @errorName(err) });
            allocator.free(path);
            sink.path = null;
        };
        return sink;
    }

    fn deinit(self: *DebugStreamFileSink) void {
        if (self.path) |path| self.allocator.free(path);
    }

    fn append(self: *DebugStreamFileSink, agent_id: []const u8, frame_payload: []const u8) void {
        const path = self.path orelse return;
        if (std.mem.indexOf(u8, frame_payload, "\"type\":\"debug.event\"") == null) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        self.appendLocked(path, agent_id, frame_payload) catch |err| {
            std.log.warn("Failed to append debug event to {s}: {s}", .{ path, @errorName(err) });
        };
    }

    fn initPath(self: *DebugStreamFileSink, ltm_directory: []const u8) ![]u8 {
        try ensureDirectoryExists(ltm_directory);
        return std.fs.path.join(self.allocator, &.{ ltm_directory, debug_stream_log_filename });
    }

    fn touch(self: *DebugStreamFileSink) !void {
        const path = self.path orelse return;
        var file = try openOrCreateAppendFile(path);
        defer file.close();
        try file.seekFromEnd(0);
    }

    fn appendLocked(self: *DebugStreamFileSink, path: []const u8, agent_id: []const u8, frame_payload: []const u8) !void {
        var file = try openOrCreateAppendFile(path);
        defer file.close();
        try file.seekFromEnd(0);
        const line = try std.fmt.allocPrint(
            self.allocator,
            "{d}\t{s}\t{s}\n",
            .{ std.time.milliTimestamp(), agent_id, frame_payload },
        );
        defer self.allocator.free(line);
        try file.writeAll(line);
        try self.maybeRotateLocked(path);
    }

    fn maybeRotateLocked(self: *DebugStreamFileSink, path: []const u8) !void {
        const size = fileSize(path) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        if (size <= debug_stream_rotate_max_bytes) return;

        const archive_path = try self.allocateArchivePath(path);
        defer self.allocator.free(archive_path);

        renamePath(path, archive_path) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };

        if (self.gzip_available) {
            self.compressArchive(archive_path) catch |err| {
                std.log.warn("Failed to gzip debug archive {s}: {s}", .{ archive_path, @errorName(err) });
            };
        }

        self.pruneArchives(path) catch |err| {
            std.log.warn("Failed pruning debug archives for {s}: {s}", .{ path, @errorName(err) });
        };
        self.touch() catch |err| {
            std.log.warn("Failed to recreate debug stream log {s}: {s}", .{ path, @errorName(err) });
        };
    }

    fn allocateArchivePath(self: *DebugStreamFileSink, path: []const u8) ![]u8 {
        const now_ms_signed = std.time.milliTimestamp();
        const now_ms: u64 = if (now_ms_signed < 0) 0 else @intCast(now_ms_signed);
        const parent = std.fs.path.dirname(path) orelse ".";

        var attempt: usize = 0;
        while (attempt < 256) : (attempt += 1) {
            const name = if (attempt == 0)
                try std.fmt.allocPrint(self.allocator, "{s}{d}{s}", .{
                    debug_stream_archive_prefix,
                    now_ms,
                    debug_stream_archive_suffix,
                })
            else
                try std.fmt.allocPrint(self.allocator, "{s}{d}-{d}{s}", .{
                    debug_stream_archive_prefix,
                    now_ms,
                    attempt,
                    debug_stream_archive_suffix,
                });
            defer self.allocator.free(name);

            const candidate = try std.fs.path.join(self.allocator, &.{ parent, name });
            if (!pathExists(candidate)) return candidate;
            self.allocator.free(candidate);
        }
        return error.PathAlreadyExists;
    }

    fn compressArchive(self: *DebugStreamFileSink, archive_path: []const u8) !void {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &.{ "gzip", "-f", archive_path },
            .max_output_bytes = 16 * 1024,
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        switch (result.term) {
            .Exited => |code| if (code != 0) return error.ProcessFailed,
            else => return error.ProcessFailed,
        }
    }

    fn pruneArchives(self: *DebugStreamFileSink, path: []const u8) !void {
        if (debug_stream_archive_keep == 0) return;
        const parent = std.fs.path.dirname(path) orelse ".";
        var dir = if (std.fs.path.isAbsolute(parent))
            try std.fs.openDirAbsolute(parent, .{ .iterate = true })
        else
            try std.fs.cwd().openDir(parent, .{ .iterate = true });
        defer dir.close();

        var candidates = std.ArrayListUnmanaged(ArchiveCandidate){};
        defer {
            for (candidates.items) |entry| self.allocator.free(entry.name);
            candidates.deinit(self.allocator);
        }

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            const ts = parseArchiveTimestamp(entry.name) orelse continue;
            try candidates.append(self.allocator, .{
                .name = try self.allocator.dupe(u8, entry.name),
                .timestamp_ms = ts,
            });
        }

        while (candidates.items.len > debug_stream_archive_keep) {
            var oldest_idx: usize = 0;
            var oldest_ts = candidates.items[0].timestamp_ms;
            var i: usize = 1;
            while (i < candidates.items.len) : (i += 1) {
                if (candidates.items[i].timestamp_ms < oldest_ts) {
                    oldest_ts = candidates.items[i].timestamp_ms;
                    oldest_idx = i;
                }
            }

            const oldest = candidates.orderedRemove(oldest_idx);
            dir.deleteFile(oldest.name) catch |err| {
                std.log.warn("Failed deleting old debug archive {s}: {s}", .{ oldest.name, @errorName(err) });
            };
            self.allocator.free(oldest.name);
        }
    }
};

const ArchiveCandidate = struct {
    name: []u8,
    timestamp_ms: u64,
};

fn parseArchiveTimestampWithPrefix(name: []const u8, prefix: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    var tail = name[prefix.len..];

    if (std.mem.endsWith(u8, tail, debug_stream_archive_suffix_gz)) {
        tail = tail[0 .. tail.len - debug_stream_archive_suffix_gz.len];
    } else if (std.mem.endsWith(u8, tail, debug_stream_archive_suffix)) {
        tail = tail[0 .. tail.len - debug_stream_archive_suffix.len];
    } else {
        return null;
    }
    if (tail.len == 0) return null;

    const dash_idx = std.mem.indexOfScalar(u8, tail, '-');
    const numeric = if (dash_idx) |idx| tail[0..idx] else tail;
    if (numeric.len == 0) return null;
    return std.fmt.parseUnsigned(u64, numeric, 10) catch null;
}

fn parseArchiveTimestamp(name: []const u8) ?u64 {
    return parseArchiveTimestampWithPrefix(name, debug_stream_archive_prefix);
}

fn commandExists(allocator: std.mem.Allocator, command: []const u8) bool {
    var child = std.process.Child.init(&[_][]const u8{ command, "--help" }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch return false;
    _ = child.wait() catch return false;
    return true;
}

fn ensureDirectoryExists(dir_path: []const u8) !void {
    if (dir_path.len == 0) return error.InvalidPath;

    if (std.fs.path.isAbsolute(dir_path)) {
        var root_dir = try std.fs.openDirAbsolute("/", .{});
        defer root_dir.close();
        const rel_dir = std.mem.trimLeft(u8, dir_path, "/");
        if (rel_dir.len == 0) return;
        root_dir.makePath(rel_dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
        return;
    }

    std.fs.cwd().makePath(dir_path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

fn openFileReadWrite(path: []const u8) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    }
    return std.fs.cwd().openFile(path, .{ .mode = .read_write });
}

fn createFileNoTruncate(path: []const u8) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return std.fs.createFileAbsolute(path, .{ .read = true, .truncate = false });
    }
    return std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });
}

fn openOrCreateAppendFile(path: []const u8) !std.fs.File {
    return openFileReadWrite(path) catch |err| switch (err) {
        error.FileNotFound => createFileNoTruncate(path),
        else => err,
    };
}

fn fileSize(path: []const u8) !u64 {
    const file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{ .mode = .read_only })
    else
        try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();
    const stat = try file.stat();
    return stat.size;
}

fn renamePath(old_path: []const u8, new_path: []const u8) !void {
    if (std.fs.path.isAbsolute(old_path) and std.fs.path.isAbsolute(new_path)) {
        try std.fs.renameAbsolute(old_path, new_path);
        return;
    }
    try std.fs.cwd().rename(old_path, new_path);
}

fn pathExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.accessAbsolute(path, .{}) catch return false;
        return true;
    }
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn allocateArchivePathWithPrefix(
    allocator: std.mem.Allocator,
    path: []const u8,
    prefix: []const u8,
) ![]u8 {
    const now_ms_signed = std.time.milliTimestamp();
    const now_ms: u64 = if (now_ms_signed < 0) 0 else @intCast(now_ms_signed);
    const parent = std.fs.path.dirname(path) orelse ".";

    var attempt: usize = 0;
    while (attempt < 256) : (attempt += 1) {
        const name = if (attempt == 0)
            try std.fmt.allocPrint(allocator, "{s}{d}{s}", .{
                prefix,
                now_ms,
                debug_stream_archive_suffix,
            })
        else
            try std.fmt.allocPrint(allocator, "{s}{d}-{d}{s}", .{
                prefix,
                now_ms,
                attempt,
                debug_stream_archive_suffix,
            });
        defer allocator.free(name);

        const candidate = try std.fs.path.join(allocator, &.{ parent, name });
        if (!pathExists(candidate)) return candidate;
        allocator.free(candidate);
    }
    return error.PathAlreadyExists;
}

fn compressArchiveGzip(allocator: std.mem.Allocator, archive_path: []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "gzip", "-f", archive_path },
        .max_output_bytes = 16 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) return error.ProcessFailed,
        else => return error.ProcessFailed,
    }
}

fn pruneArchivesWithPrefix(
    allocator: std.mem.Allocator,
    path: []const u8,
    prefix: []const u8,
    keep: usize,
) !void {
    if (keep == 0) return;
    const parent = std.fs.path.dirname(path) orelse ".";
    var dir = if (std.fs.path.isAbsolute(parent))
        try std.fs.openDirAbsolute(parent, .{ .iterate = true })
    else
        try std.fs.cwd().openDir(parent, .{ .iterate = true });
    defer dir.close();

    var candidates = std.ArrayListUnmanaged(ArchiveCandidate){};
    defer {
        for (candidates.items) |entry| allocator.free(entry.name);
        candidates.deinit(allocator);
    }

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        const ts = parseArchiveTimestampWithPrefix(entry.name, prefix) orelse continue;
        try candidates.append(allocator, .{
            .name = try allocator.dupe(u8, entry.name),
            .timestamp_ms = ts,
        });
    }

    while (candidates.items.len > keep) {
        var oldest_idx: usize = 0;
        var oldest_ts = candidates.items[0].timestamp_ms;
        var i: usize = 1;
        while (i < candidates.items.len) : (i += 1) {
            if (candidates.items[i].timestamp_ms < oldest_ts) {
                oldest_ts = candidates.items[i].timestamp_ms;
                oldest_idx = i;
            }
        }

        const oldest = candidates.orderedRemove(oldest_idx);
        dir.deleteFile(oldest.name) catch |err| {
            std.log.warn("Failed deleting old archive {s}: {s}", .{ oldest.name, @errorName(err) });
        };
        allocator.free(oldest.name);
    }
}

fn parseBoolEnv(allocator: std.mem.Allocator, name: []const u8, default_value: bool) bool {
    const raw = std.process.getEnvVarOwned(allocator, name) catch return default_value;
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    if (std.ascii.eqlIgnoreCase(trimmed, "1") or std.ascii.eqlIgnoreCase(trimmed, "true") or std.ascii.eqlIgnoreCase(trimmed, "yes") or std.ascii.eqlIgnoreCase(trimmed, "on")) return true;
    if (std.ascii.eqlIgnoreCase(trimmed, "0") or std.ascii.eqlIgnoreCase(trimmed, "false") or std.ascii.eqlIgnoreCase(trimmed, "no") or std.ascii.eqlIgnoreCase(trimmed, "off")) return false;
    return default_value;
}

fn parseUnsignedEnv(allocator: std.mem.Allocator, name: []const u8, default_value: u64) u64 {
    const raw = std.process.getEnvVarOwned(allocator, name) catch return default_value;
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    return std.fmt.parseInt(u64, trimmed, 10) catch default_value;
}

fn pathIsAncestorOrEqual(parent_path_raw: []const u8, child_path_raw: []const u8) bool {
    var parent = std.mem.trim(u8, parent_path_raw, " \t\r\n");
    var child = std.mem.trim(u8, child_path_raw, " \t\r\n");
    if (parent.len == 0 or child.len == 0) return false;

    while (parent.len > 1 and parent[parent.len - 1] == '/') parent = parent[0 .. parent.len - 1];
    while (child.len > 1 and child[child.len - 1] == '/') child = child[0 .. child.len - 1];

    if (std.mem.eql(u8, parent, "/")) return true;
    if (!std.mem.startsWith(u8, child, parent)) return false;
    if (child.len == parent.len) return true;
    return child[parent.len] == '/';
}

fn resolveInternalWsClientHost(bind_addr: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, bind_addr, " \t\r\n");
    if (trimmed.len == 0) return "127.0.0.1";
    if (std.mem.eql(u8, trimmed, "0.0.0.0")) return "127.0.0.1";
    if (std.mem.eql(u8, trimmed, "::")) return "127.0.0.1";
    if (std.mem.eql(u8, trimmed, "[::]")) return "127.0.0.1";
    return trimmed;
}

fn formatInternalWsUrl(
    allocator: std.mem.Allocator,
    bind_addr: []const u8,
    port: u16,
    path: []const u8,
) ![]u8 {
    const host = resolveInternalWsClientHost(bind_addr);
    const is_ipv6_literal = std.mem.indexOfScalar(u8, host, ':') != null and
        !(host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']');
    if (is_ipv6_literal) {
        return std.fmt.allocPrint(allocator, "ws://[{s}]:{d}{s}", .{ host, port, path });
    }
    return std.fmt.allocPrint(allocator, "ws://{s}:{d}{s}", .{ host, port, path });
}

fn parseOptionalEnvOwned(allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
    const raw = std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return null,
    };
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;
    return allocator.dupe(u8, trimmed) catch null;
}

fn initNodeServiceEventLogPath(
    allocator: std.mem.Allocator,
    ltm_directory: []const u8,
) !?[]u8 {
    const base = std.mem.trim(u8, ltm_directory, " \t\r\n");
    if (base.len == 0) return null;
    try ensureDirectoryExists(base);
    const path = try std.fs.path.join(allocator, &.{ base, node_service_event_log_filename });
    errdefer allocator.free(path);
    var file = try openOrCreateAppendFile(path);
    defer file.close();
    try file.seekFromEnd(0);
    return path;
}

const FsHubConnection = struct {
    id: u64,
    stream: *std.net.Stream,
    write_mutex: std.Thread.Mutex = .{},
    allow_invalidations: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
};

const FsConnectionHub = struct {
    allocator: std.mem.Allocator,
    connections: std.ArrayListUnmanaged(*FsHubConnection) = .{},
    mutex: std.Thread.Mutex = .{},
    next_id: u64 = 1,

    fn deinit(self: *FsConnectionHub) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.connections.items) |conn| self.allocator.destroy(conn);
        self.connections.deinit(self.allocator);
    }

    fn register(self: *FsConnectionHub, stream: *std.net.Stream, allow_invalidations: bool) !*FsHubConnection {
        const conn = try self.allocator.create(FsHubConnection);
        errdefer self.allocator.destroy(conn);

        self.mutex.lock();
        defer self.mutex.unlock();
        conn.* = .{
            .id = self.next_id,
            .stream = stream,
        };
        conn.allow_invalidations.store(allow_invalidations, .release);
        self.next_id +%= 1;
        if (self.next_id == 0) self.next_id = 1;
        try self.connections.append(self.allocator, conn);
        return conn;
    }

    fn unregister(self: *FsConnectionHub, conn: *FsHubConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items, 0..) |item, idx| {
            if (item != conn) continue;
            _ = self.connections.swapRemove(idx);
            self.allocator.destroy(conn);
            return;
        }
    }

    fn broadcastInvalidations(self: *FsConnectionHub, origin_id: u64, events: []const fs_protocol.InvalidationEvent) void {
        for (events) |event| {
            const payload = fs_node_service.buildInvalidationEventJson(self.allocator, event) catch continue;
            defer self.allocator.free(payload);
            self.broadcastText(origin_id, payload);
        }
    }

    fn broadcastText(self: *FsConnectionHub, origin_id: u64, payload: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.connections.items) |conn| {
            if (conn.id == origin_id) continue;
            if (!conn.allow_invalidations.load(.acquire)) continue;
            // Drop invalidation frames when a connection is busy to avoid starving
            // in-band request/response traffic on the same websocket.
            if (!conn.write_mutex.tryLock()) continue;
            websocket_transport.writeFrame(conn.stream, payload, .text) catch {
                conn.stream.close();
            };
            conn.write_mutex.unlock();
        }
    }

    fn disableInvalidations(self: *FsConnectionHub, conn_id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.connections.items) |conn| {
            if (conn.id != conn_id) continue;
            conn.allow_invalidations.store(false, .release);
            return;
        }
    }
};

const NodeTunnelPendingRequest = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    done: bool = false,
    failed: bool = false,
    response_payload: ?[]u8 = null,

    fn deinit(self: *NodeTunnelPendingRequest, allocator: std.mem.Allocator) void {
        if (self.response_payload) |value| allocator.free(value);
        self.* = undefined;
    }
};

const NodeTunnelClient = struct {
    id: u64,
    stream: *std.net.Stream,
    write_mutex: *std.Thread.Mutex,
    allow_invalidations: bool = false,
};

const NodeTunnelEntry = struct {
    stream: ?*std.net.Stream = null,
    write_mutex: ?*std.Thread.Mutex = null,
    generation: u64 = 0,
    next_upstream_tag: u32 = 1,
    next_client_id: u64 = 1,
    pending: std.AutoHashMapUnmanaged(u32, *NodeTunnelPendingRequest) = .{},
    clients: std.ArrayListUnmanaged(NodeTunnelClient) = .{},

    fn deinit(self: *NodeTunnelEntry, allocator: std.mem.Allocator) void {
        var pending_it = self.pending.iterator();
        while (pending_it.next()) |item| {
            var pending = item.value_ptr.*;
            pending.deinit(allocator);
            allocator.destroy(pending);
        }
        self.pending.deinit(allocator);
        self.clients.deinit(allocator);
        self.* = undefined;
    }
};

const NodeTunnelAttachment = struct {
    node_id: []u8,
    generation: u64,

    fn deinit(self: *NodeTunnelAttachment, allocator: std.mem.Allocator) void {
        allocator.free(self.node_id);
        self.* = undefined;
    }
};

const NodeTunnelRegistry = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    tunnels: std.StringHashMapUnmanaged(*NodeTunnelEntry) = .{},

    fn deinit(self: *NodeTunnelRegistry) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.tunnels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var tunnel = entry.value_ptr.*;
            tunnel.deinit(self.allocator);
            self.allocator.destroy(tunnel);
        }
        self.tunnels.deinit(self.allocator);
    }

    fn attachTunnel(
        self: *NodeTunnelRegistry,
        node_id: []const u8,
        stream: *std.net.Stream,
        write_mutex: *std.Thread.Mutex,
    ) !NodeTunnelAttachment {
        self.mutex.lock();
        defer self.mutex.unlock();

        const tunnel = try self.getOrCreateTunnelLocked(node_id);
        if (tunnel.stream) |previous_stream| {
            if (previous_stream != stream) {
                previous_stream.close();
            }
            self.failAllPendingLocked(tunnel);
        }
        tunnel.stream = stream;
        tunnel.write_mutex = write_mutex;
        tunnel.generation +%= 1;
        if (tunnel.generation == 0) tunnel.generation = 1;
        return .{
            .node_id = try self.allocator.dupe(u8, node_id),
            .generation = tunnel.generation,
        };
    }

    fn detachTunnel(self: *NodeTunnelRegistry, node_id: []const u8, generation: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const tunnel = self.tunnels.get(node_id) orelse return;
        if (tunnel.generation != generation) return;
        tunnel.stream = null;
        tunnel.write_mutex = null;
        self.failAllPendingLocked(tunnel);
        self.removeTunnelIfUnusedLocked(node_id, tunnel);
    }

    fn registerClient(
        self: *NodeTunnelRegistry,
        node_id: []const u8,
        stream: *std.net.Stream,
        write_mutex: *std.Thread.Mutex,
        allow_invalidations: bool,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const tunnel = self.tunnels.get(node_id) orelse return error.NodeTunnelUnavailable;
        if (tunnel.stream == null or tunnel.write_mutex == null) return error.NodeTunnelUnavailable;

        const client_id = tunnel.next_client_id;
        tunnel.next_client_id +%= 1;
        if (tunnel.next_client_id == 0) tunnel.next_client_id = 1;
        try tunnel.clients.append(self.allocator, .{
            .id = client_id,
            .stream = stream,
            .write_mutex = write_mutex,
            .allow_invalidations = allow_invalidations,
        });
        return client_id;
    }

    fn updateClientInvalidations(
        self: *NodeTunnelRegistry,
        node_id: []const u8,
        client_id: u64,
        allow_invalidations: bool,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const tunnel = self.tunnels.get(node_id) orelse return;
        for (tunnel.clients.items) |*client| {
            if (client.id != client_id) continue;
            client.allow_invalidations = allow_invalidations;
            return;
        }
    }

    fn unregisterClient(self: *NodeTunnelRegistry, node_id: []const u8, client_id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const tunnel = self.tunnels.get(node_id) orelse return;
        for (tunnel.clients.items, 0..) |client, idx| {
            if (client.id != client_id) continue;
            _ = tunnel.clients.swapRemove(idx);
            break;
        }
        self.removeTunnelIfUnusedLocked(node_id, tunnel);
    }

    fn relayRequest(
        self: *NodeTunnelRegistry,
        node_id: []const u8,
        client_tag: u32,
        request_payload: []const u8,
    ) ![]u8 {
        var pending = try self.allocator.create(NodeTunnelPendingRequest);
        pending.* = .{};
        defer {
            pending.deinit(self.allocator);
            self.allocator.destroy(pending);
        }

        var upstream_tag: u32 = 0;
        var stream: ?*std.net.Stream = null;
        var stream_write_mutex: ?*std.Thread.Mutex = null;
        var generation: u64 = 0;

        self.mutex.lock();
        {
            const tunnel = self.tunnels.get(node_id) orelse {
                self.mutex.unlock();
                return error.NodeTunnelUnavailable;
            };
            if (tunnel.stream == null or tunnel.write_mutex == null) {
                self.mutex.unlock();
                return error.NodeTunnelUnavailable;
            }

            upstream_tag = self.nextUpstreamTagLocked(tunnel);
            try tunnel.pending.put(self.allocator, upstream_tag, pending);
            stream = tunnel.stream.?;
            stream_write_mutex = tunnel.write_mutex.?;
            generation = tunnel.generation;
        }
        self.mutex.unlock();

        const rewritten = rewriteAcheronTag(self.allocator, request_payload, upstream_tag) catch |err| {
            self.mutex.lock();
            if (self.tunnels.get(node_id)) |tunnel| {
                if (tunnel.generation == generation) {
                    _ = tunnel.pending.remove(upstream_tag);
                }
            }
            self.mutex.unlock();
            return err;
        };
        defer self.allocator.free(rewritten);

        stream_write_mutex.?.lock();
        const write_result = websocket_transport.writeFrame(stream.?, rewritten, .text);
        stream_write_mutex.?.unlock();
        if (write_result) |_| {} else |err| {
            self.mutex.lock();
            if (self.tunnels.get(node_id)) |tunnel| {
                if (tunnel.generation == generation) {
                    _ = tunnel.pending.remove(upstream_tag);
                    tunnel.stream = null;
                    tunnel.write_mutex = null;
                    self.failAllPendingLocked(tunnel);
                    self.removeTunnelIfUnusedLocked(node_id, tunnel);
                }
            }
            self.mutex.unlock();
            return err;
        }

        const deadline_ns: i128 = std.time.nanoTimestamp() + @as(i128, @intCast(node_tunnel_reply_timeout_ms)) * std.time.ns_per_ms;
        pending.mutex.lock();
        while (!pending.done) {
            const now_ns = std.time.nanoTimestamp();
            if (now_ns >= deadline_ns) {
                pending.failed = true;
                pending.done = true;
                break;
            }
            const remaining_ns: u64 = @intCast(deadline_ns - now_ns);
            pending.cond.timedWait(&pending.mutex, remaining_ns) catch |wait_err| switch (wait_err) {
                error.Timeout => continue,
            };
        }
        const failed = pending.failed;
        const response_payload = pending.response_payload;
        pending.response_payload = null;
        pending.mutex.unlock();

        if (failed or response_payload == null) {
            self.mutex.lock();
            if (self.tunnels.get(node_id)) |tunnel| {
                _ = tunnel.pending.remove(upstream_tag);
            }
            self.mutex.unlock();
            return error.NodeTunnelUnavailable;
        }

        defer self.allocator.free(response_payload.?);
        const response_rewritten = try rewriteAcheronTag(self.allocator, response_payload.?, client_tag);
        return response_rewritten;
    }

    fn dispatchTunnelFrame(
        self: *NodeTunnelRegistry,
        node_id: []const u8,
        generation: u64,
        payload: []const u8,
    ) void {
        var parsed = unified.parseMessage(self.allocator, payload) catch return;
        defer parsed.deinit(self.allocator);
        if (parsed.channel != .acheron) return;
        const frame_type = parsed.acheron_type orelse return;

        if (frame_type == .fs_evt_inval or frame_type == .fs_evt_inval_dir) {
            self.mutex.lock();
            defer self.mutex.unlock();

            const tunnel = self.tunnels.get(node_id) orelse return;
            if (tunnel.generation != generation) return;
            var idx: usize = 0;
            while (idx < tunnel.clients.items.len) {
                const client = tunnel.clients.items[idx];
                if (!client.allow_invalidations) {
                    idx += 1;
                    continue;
                }
                client.write_mutex.lock();
                const write_result = websocket_transport.writeFrame(client.stream, payload, .text);
                client.write_mutex.unlock();
                if (write_result) |_| {} else |_| {
                    _ = tunnel.clients.swapRemove(idx);
                    continue;
                }
                idx += 1;
            }
            return;
        }

        const upstream_tag = parsed.tag orelse return;
        var pending: ?*NodeTunnelPendingRequest = null;
        self.mutex.lock();
        if (self.tunnels.get(node_id)) |tunnel| {
            if (tunnel.generation == generation) {
                if (tunnel.pending.fetchRemove(upstream_tag)) |removed| {
                    pending = removed.value;
                }
            }
        }
        self.mutex.unlock();

        if (pending) |pending_req| {
            const copy = self.allocator.dupe(u8, payload) catch null;
            pending_req.mutex.lock();
            if (copy) |value| {
                pending_req.response_payload = value;
                pending_req.failed = false;
            } else {
                pending_req.failed = true;
            }
            pending_req.done = true;
            pending_req.cond.signal();
            pending_req.mutex.unlock();
        }
    }

    fn getOrCreateTunnelLocked(self: *NodeTunnelRegistry, node_id: []const u8) !*NodeTunnelEntry {
        if (self.tunnels.get(node_id)) |existing| return existing;
        const key = try self.allocator.dupe(u8, node_id);
        errdefer self.allocator.free(key);
        const tunnel = try self.allocator.create(NodeTunnelEntry);
        errdefer self.allocator.destroy(tunnel);
        tunnel.* = .{};
        try self.tunnels.put(self.allocator, key, tunnel);
        return tunnel;
    }

    fn removeTunnelIfUnusedLocked(
        self: *NodeTunnelRegistry,
        node_id: []const u8,
        tunnel: *NodeTunnelEntry,
    ) void {
        if (tunnel.stream != null) return;
        if (tunnel.pending.count() > 0) return;
        if (tunnel.clients.items.len > 0) return;

        if (self.tunnels.fetchRemove(node_id)) |removed| {
            self.allocator.free(removed.key);
            var removed_tunnel = removed.value;
            removed_tunnel.deinit(self.allocator);
            self.allocator.destroy(removed_tunnel);
        }
    }

    fn failAllPendingLocked(self: *NodeTunnelRegistry, tunnel: *NodeTunnelEntry) void {
        _ = self;
        var it = tunnel.pending.iterator();
        while (it.next()) |entry| {
            const pending = entry.value_ptr.*;
            pending.mutex.lock();
            pending.failed = true;
            pending.done = true;
            pending.cond.signal();
            pending.mutex.unlock();
        }
        tunnel.pending.clearRetainingCapacity();
    }

    fn nextUpstreamTagLocked(self: *NodeTunnelRegistry, tunnel: *NodeTunnelEntry) u32 {
        _ = self;
        var attempts: u64 = 0;
        while (attempts < std.math.maxInt(u32)) : (attempts += 1) {
            const candidate = tunnel.next_upstream_tag;
            tunnel.next_upstream_tag +%= 1;
            if (tunnel.next_upstream_tag == 0) tunnel.next_upstream_tag = 1;
            if (candidate == 0) continue;
            if (!tunnel.pending.contains(candidate)) return candidate;
        }
        return 1;
    }
};

const NodeServiceEventRecord = struct {
    timestamp_ms: i64,
    node_id: ?[]u8 = null,
    payload_json: []u8,

    fn deinit(self: *NodeServiceEventRecord, allocator: std.mem.Allocator) void {
        if (self.node_id) |value| allocator.free(value);
        allocator.free(self.payload_json);
        self.* = undefined;
    }
};

const NodeServiceEventMetricsSnapshot = struct {
    retained_events: usize = 0,
    retained_capacity: usize = 0,
    retained_oldest_ms: ?i64 = null,
    retained_newest_ms: ?i64 = null,
    retained_window_ms: u64 = 0,
};

const ControlMutationScope = enum {
    none,
    node,
    project,
    operator,
};

const AuditRecord = struct {
    id: u64,
    timestamp_ms: i64,
    agent_id: []u8,
    control_type: []u8,
    scope: ControlMutationScope,
    correlation_id: ?[]u8 = null,
    result: []u8,
    error_code: ?[]u8 = null,

    fn deinit(self: *AuditRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        allocator.free(self.control_type);
        if (self.correlation_id) |value| allocator.free(value);
        allocator.free(self.result);
        if (self.error_code) |value| allocator.free(value);
        self.* = undefined;
    }
};

const LocalFsMountSpec = struct {
    mount_path: []u8,
    export_name: []u8,

    fn deinit(self: *LocalFsMountSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.mount_path);
        allocator.free(self.export_name);
        self.* = undefined;
    }
};

const LocalFsNode = struct {
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    service: fs_node_service.NodeService,
    hub: FsConnectionHub,
    node_name: []u8,
    mount_specs: std.ArrayListUnmanaged(LocalFsMountSpec) = .{},
    fs_url: []u8,
    lease_ttl_ms: u64,
    heartbeat_interval_ms: u64,
    heartbeat_stop: bool = false,
    heartbeat_mutex: std.Thread.Mutex = .{},
    heartbeat_thread: ?std.Thread = null,
    registration_mutex: std.Thread.Mutex = .{},
    registered_node_id: ?[]u8 = null,
    session_auth_token: ?[]u8 = null,
    chat_jobs_mutex: std.Thread.Mutex = .{},
    chat_jobs_cond: std.Thread.Condition = .{},
    chat_jobs_inflight: usize = 0,
    chat_jobs_stopping: bool = false,

    fn create(
        allocator: std.mem.Allocator,
        runtime_registry: *AgentRuntimeRegistry,
        export_specs: []const fs_node_ops.ExportSpec,
        mount_specs: []const fs_control_plane.SpiderWebMountSpec,
        node_name: []const u8,
        fs_url: []const u8,
        lease_ttl_ms: u64,
        heartbeat_interval_ms: u64,
        watcher_enabled: bool,
    ) !*LocalFsNode {
        const endpoint = try allocator.create(LocalFsNode);
        errdefer allocator.destroy(endpoint);

        if (export_specs.len == 0) return error.InvalidPayload;
        if (mount_specs.len == 0) return error.InvalidPayload;

        var owned_mount_specs = std.ArrayListUnmanaged(LocalFsMountSpec){};
        errdefer {
            for (owned_mount_specs.items) |*item| item.deinit(allocator);
            owned_mount_specs.deinit(allocator);
        }
        for (mount_specs) |spec| {
            try owned_mount_specs.append(allocator, .{
                .mount_path = try allocator.dupe(u8, spec.mount_path),
                .export_name = try allocator.dupe(u8, spec.export_name),
            });
        }

        endpoint.* = .{
            .allocator = allocator,
            .runtime_registry = runtime_registry,
            .service = try fs_node_service.NodeService.initWithOptions(
                allocator,
                export_specs,
                .{
                    .chat_input_hook = .{
                        .ctx = @ptrCast(endpoint),
                        .on_submit = localFsNodeChatInputSubmitHook,
                    },
                },
            ),
            .hub = .{ .allocator = allocator },
            .node_name = try allocator.dupe(u8, node_name),
            .mount_specs = owned_mount_specs,
            .fs_url = try allocator.dupe(u8, fs_url),
            .lease_ttl_ms = lease_ttl_ms,
            .heartbeat_interval_ms = heartbeat_interval_ms,
        };
        errdefer {
            endpoint.hub.deinit();
            endpoint.service.deinit();
            allocator.free(endpoint.node_name);
            for (endpoint.mount_specs.items) |*item| item.deinit(allocator);
            endpoint.mount_specs.deinit(allocator);
            allocator.free(endpoint.fs_url);
        }

        const watch_source_export = export_specs[0];
        const watch_disabled_for_root_export = std.mem.eql(u8, std.mem.trim(u8, watch_source_export.path, " \t\r\n"), "/");
        const should_enable_watcher = watcher_enabled and !watch_disabled_for_root_export;
        if (!should_enable_watcher) {
            // Full-root recursive watcher scans can block on special mount points
            // and starve fsrpc request handling (shared NodeService mutex).
            if (watch_disabled_for_root_export) {
                std.log.warn("local fs node watcher disabled: export root '/' can block fsrpc under recursive scans", .{});
            } else {
                std.log.warn("local fs node watcher disabled by runtime policy", .{});
            }
        } else if (fs_watch_runtime.spawnDetached(
            allocator,
            &endpoint.service,
            emitLocalFsWatcherEvents,
            @ptrCast(endpoint),
            .{},
        )) |backend| {
            std.log.info("local fs node watcher backend active: {s}", .{@tagName(backend)});
        } else |err| {
            std.log.warn("local fs node watcher disabled: {s}", .{@errorName(err)});
        }

        return endpoint;
    }

    fn deinit(self: *LocalFsNode, control_plane: *fs_control_plane.ControlPlane) void {
        self.stopAndWaitForChatJobWorkers();
        self.requestHeartbeatStop();
        if (self.heartbeat_thread) |thread| {
            thread.join();
            self.heartbeat_thread = null;
        }

        var owned_node_id: ?[]u8 = null;
        var owned_auth_token: ?[]u8 = null;
        self.registration_mutex.lock();
        owned_node_id = self.registered_node_id;
        self.registered_node_id = null;
        owned_auth_token = self.session_auth_token;
        self.session_auth_token = null;
        self.registration_mutex.unlock();

        if (owned_node_id) |node_id| {
            control_plane.unregisterNodeById(node_id) catch |err| {
                std.log.warn("local fs node unregister failed for {s}: {s}", .{ node_id, @errorName(err) });
            };
            self.allocator.free(node_id);
        }
        if (owned_auth_token) |token| self.allocator.free(token);

        self.hub.deinit();
        self.service.deinit();
        self.allocator.free(self.node_name);
        for (self.mount_specs.items) |*item| item.deinit(self.allocator);
        self.mount_specs.deinit(self.allocator);
        self.allocator.free(self.fs_url);
        self.allocator.destroy(self);
    }

    fn beginChatJobWorker(self: *LocalFsNode) !void {
        self.chat_jobs_mutex.lock();
        defer self.chat_jobs_mutex.unlock();
        if (self.chat_jobs_stopping) return error.ShuttingDown;
        self.chat_jobs_inflight += 1;
    }

    fn finishChatJobWorker(self: *LocalFsNode) void {
        self.chat_jobs_mutex.lock();
        if (self.chat_jobs_inflight > 0) {
            self.chat_jobs_inflight -= 1;
        }
        if (self.chat_jobs_stopping and self.chat_jobs_inflight == 0) {
            self.chat_jobs_cond.broadcast();
        } else if (self.chat_jobs_inflight == 0) {
            self.chat_jobs_cond.signal();
        }
        self.chat_jobs_mutex.unlock();
    }

    fn stopAndWaitForChatJobWorkers(self: *LocalFsNode) void {
        self.chat_jobs_mutex.lock();
        self.chat_jobs_stopping = true;
        while (self.chat_jobs_inflight > 0) {
            self.chat_jobs_cond.wait(&self.chat_jobs_mutex);
        }
        self.chat_jobs_mutex.unlock();
    }

    fn startRegistrationAndHeartbeat(self: *LocalFsNode, control_plane: *fs_control_plane.ControlPlane) !void {
        try self.refreshRegistration(control_plane);
        self.heartbeat_thread = try std.Thread.spawn(.{}, localFsHeartbeatThreadMain, .{ self, control_plane });
    }

    fn refreshRegistration(self: *LocalFsNode, control_plane: *fs_control_plane.ControlPlane) !void {
        const payload_json = try control_plane.ensureNode(self.node_name, self.fs_url, self.lease_ttl_ms);
        defer self.allocator.free(payload_json);
        const registration = try parseNodeRegistrationFromJoinPayload(self.allocator, payload_json);
        var mount_node_id: []u8 = undefined;
        self.registration_mutex.lock();
        var unlock_needed = true;
        defer if (unlock_needed) self.registration_mutex.unlock();

        if (self.registered_node_id) |prev| {
            if (std.mem.eql(u8, prev, registration.node_id)) {
                mount_node_id = try self.allocator.dupe(u8, prev);
                self.registration_mutex.unlock();
                unlock_needed = false;
                defer self.allocator.free(mount_node_id);
                self.allocator.free(registration.node_id);
                self.allocator.free(registration.node_secret);
                try self.ensureSpiderWebMounts(control_plane, mount_node_id);
                return;
            }
            self.allocator.free(prev);
        }
        if (self.session_auth_token) |existing| self.allocator.free(existing);

        self.registered_node_id = registration.node_id;
        self.session_auth_token = registration.node_secret;
        mount_node_id = try self.allocator.dupe(u8, self.registered_node_id.?);
        self.registration_mutex.unlock();
        unlock_needed = false;
        defer self.allocator.free(mount_node_id);
        try self.ensureSpiderWebMounts(control_plane, mount_node_id);
    }

    fn ensureSpiderWebMounts(self: *LocalFsNode, control_plane: *fs_control_plane.ControlPlane, node_id: []const u8) !void {
        const specs = try self.allocator.alloc(fs_control_plane.SpiderWebMountSpec, self.mount_specs.items.len);
        defer self.allocator.free(specs);
        for (self.mount_specs.items, 0..) |spec, idx| {
            specs[idx] = .{
                .mount_path = spec.mount_path,
                .export_name = spec.export_name,
            };
        }
        try control_plane.ensureSpiderWebMounts(node_id, specs);
    }

    fn requestHeartbeatStop(self: *LocalFsNode) void {
        self.heartbeat_mutex.lock();
        self.heartbeat_stop = true;
        self.heartbeat_mutex.unlock();
    }

    fn shouldStopHeartbeat(self: *LocalFsNode) bool {
        self.heartbeat_mutex.lock();
        defer self.heartbeat_mutex.unlock();
        return self.heartbeat_stop;
    }

    fn copySessionAuthToken(self: *LocalFsNode, allocator: std.mem.Allocator) !?[]u8 {
        self.registration_mutex.lock();
        defer self.registration_mutex.unlock();
        if (self.session_auth_token) |token| {
            const copy = try allocator.dupe(u8, token);
            return @as(?[]u8, copy);
        }
        return null;
    }

    fn submitChatInput(
        self: *LocalFsNode,
        input: []const u8,
        correlation_id: ?[]const u8,
    ) !fs_node_service.NodeService.ChatInputSubmission {
        const job_id = try self.runtime_registry.job_index.createJob(system_agent_id, correlation_id);
        errdefer self.allocator.free(job_id);
        self.runtime_registry.job_index.markRunning(job_id) catch |err| {
            const message = try std.fmt.allocPrint(self.allocator, "chat job markRunning failed: {s}", .{@errorName(err)});
            defer self.allocator.free(message);
            try self.runtime_registry.job_index.markCompleted(
                job_id,
                false,
                message,
                message,
                "[local fs chat submit failure]\n",
            );
            return .{
                .job_id = job_id,
                .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
                .state = .failed,
                .error_text = try self.allocator.dupe(u8, message),
                .result_text = try self.allocator.dupe(u8, message),
                .log_text = try self.allocator.dupe(u8, "[local fs chat submit failure]\n"),
            };
        };

        self.beginChatJobWorker() catch |begin_err| {
            const message = try std.fmt.allocPrint(self.allocator, "chat job worker start blocked: {s}", .{@errorName(begin_err)});
            defer self.allocator.free(message);
            try self.runtime_registry.job_index.markCompleted(
                job_id,
                false,
                message,
                message,
                "[local fs chat worker start blocked]\n",
            );
            return .{
                .job_id = job_id,
                .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
                .state = .failed,
                .error_text = try self.allocator.dupe(u8, message),
                .result_text = try self.allocator.dupe(u8, message),
                .log_text = try self.allocator.dupe(u8, "[local fs chat worker start blocked]\n"),
            };
        };
        var worker_handed_off = false;
        defer if (!worker_handed_off) self.finishChatJobWorker();

        const worker_ctx = try self.allocator.create(LocalFsChatJobContext);
        worker_ctx.* = .{
            .allocator = self.allocator,
            .node = self,
            .job_id = try self.allocator.dupe(u8, job_id),
            .input = try self.allocator.dupe(u8, input),
            .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
        };
        const worker = std.Thread.spawn(.{}, localFsChatJobThreadMain, .{worker_ctx}) catch |spawn_err| {
            worker_ctx.deinit();
            const message = try std.fmt.allocPrint(self.allocator, "chat job worker spawn failed: {s}", .{@errorName(spawn_err)});
            defer self.allocator.free(message);
            try self.runtime_registry.job_index.markCompleted(
                job_id,
                false,
                message,
                message,
                "[local fs chat worker spawn failure]\n",
            );
            return .{
                .job_id = job_id,
                .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
                .state = .failed,
                .error_text = try self.allocator.dupe(u8, message),
                .result_text = try self.allocator.dupe(u8, message),
                .log_text = try self.allocator.dupe(u8, "[local fs chat worker spawn failure]\n"),
            };
        };
        worker_handed_off = true;
        worker.detach();

        return .{
            .job_id = job_id,
            .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
            .state = .running,
        };
    }

    fn publishChatJobUpdate(self: *LocalFsNode, update: fs_node_ops.NamespaceChatJobUpdate) void {
        const events = self.service.upsertNamespaceChatJobWithEvents(update) catch |err| {
            std.log.warn("local fs chat job namespace update failed for {s}: {s}", .{ update.job_id, @errorName(err) });
            return;
        };
        defer self.allocator.free(events);
        if (events.len > 0) self.hub.broadcastInvalidations(0, events);
    }
};

const LocalFsChatJobContext = struct {
    allocator: std.mem.Allocator,
    node: *LocalFsNode,
    job_id: []u8,
    input: []u8,
    correlation_id: ?[]u8 = null,

    fn deinit(self: *LocalFsChatJobContext) void {
        self.allocator.free(self.job_id);
        self.allocator.free(self.input);
        if (self.correlation_id) |value| self.allocator.free(value);
        self.allocator.destroy(self);
    }
};

fn localFsNodeChatInputSubmitHook(
    raw_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    input: []const u8,
    correlation_id: ?[]const u8,
) anyerror!fs_node_service.NodeService.ChatInputSubmission {
    _ = allocator;
    const ctx = raw_ctx orelse return error.InvalidContext;
    const node: *LocalFsNode = @ptrCast(@alignCast(ctx));
    return node.submitChatInput(input, correlation_id);
}

fn localFsChatJobThreadMain(ctx: *LocalFsChatJobContext) void {
    defer ctx.deinit();
    defer ctx.node.finishChatJobWorker();
    executeLocalFsChatJob(ctx.node, ctx.job_id, ctx.input, ctx.correlation_id) catch |err| {
        const message = std.fmt.allocPrint(
            ctx.allocator,
            "runtime execution failed: {s}",
            .{@errorName(err)},
        ) catch return;
        defer ctx.allocator.free(message);
        const log_owned = std.fmt.allocPrint(
            ctx.allocator,
            "[local fs chat runtime failure] {s}\n",
            .{@errorName(err)},
        ) catch null;
        defer if (log_owned) |value| ctx.allocator.free(value);
        const log = if (log_owned) |value|
            value
        else
            "[local fs chat runtime failure]\n";
        ctx.node.runtime_registry.job_index.markCompleted(
            ctx.job_id,
            false,
            message,
            message,
            log,
        ) catch |mark_err| {
            std.log.warn("local fs chat job completion update failed after runtime error: {s}", .{@errorName(mark_err)});
        };
        ctx.node.publishChatJobUpdate(.{
            .job_id = ctx.job_id,
            .state = .failed,
            .correlation_id = ctx.correlation_id,
            .error_text = message,
            .result_text = message,
            .log_text = log,
        });
    };
}

fn executeLocalFsChatJob(
    node: *LocalFsNode,
    job_id: []const u8,
    input: []const u8,
    correlation_id: ?[]const u8,
) !void {
    const runtime = try node.runtime_registry.getOrCreate(system_agent_id, system_project_id, null);
    defer runtime.release();

    const escaped = try unified.jsonEscape(node.allocator, input);
    defer node.allocator.free(escaped);
    const runtime_req = if (correlation_id) |value| blk: {
        const escaped_corr = try unified.jsonEscape(node.allocator, value);
        defer node.allocator.free(escaped_corr);
        break :blk try std.fmt.allocPrint(
            node.allocator,
            "{{\"id\":\"{s}\",\"type\":\"session.send\",\"content\":\"{s}\",\"correlation_id\":\"{s}\"}}",
            .{ job_id, escaped, escaped_corr },
        );
    } else try std.fmt.allocPrint(
        node.allocator,
        "{{\"id\":\"{s}\",\"type\":\"session.send\",\"content\":\"{s}\"}}",
        .{ job_id, escaped },
    );
    defer node.allocator.free(runtime_req);

    var log_buf = std.ArrayListUnmanaged(u8){};
    defer log_buf.deinit(node.allocator);

    var result_text = try node.allocator.dupe(u8, "");
    defer node.allocator.free(result_text);
    var failed = false;
    var failure_message: ?[]u8 = null;
    defer if (failure_message) |value| node.allocator.free(value);

    const frames = try runtime.handleMessageFramesWithDebug(runtime_req, false);
    defer runtime_server_mod.deinitResponseFrames(node.allocator, frames);
    for (frames) |frame| {
        try log_buf.appendSlice(node.allocator, frame);
        try log_buf.append(node.allocator, '\n');

        var parsed = std.json.parseFromSlice(std.json.Value, node.allocator, frame, .{}) catch continue;
        defer parsed.deinit();
        if (parsed.value != .object) continue;
        const obj = parsed.value.object;
        const type_value = obj.get("type") orelse continue;
        if (type_value != .string) continue;

        if (std.mem.eql(u8, type_value.string, "session.receive")) {
            if (obj.get("content")) |content| {
                if (content == .string) {
                    node.allocator.free(result_text);
                    result_text = try node.allocator.dupe(u8, content.string);
                }
            }
            continue;
        }

        if (std.mem.eql(u8, type_value.string, "error")) {
            failed = true;
            if (obj.get("message")) |message| {
                if (message == .string) {
                    if (failure_message) |value| node.allocator.free(value);
                    failure_message = try node.allocator.dupe(u8, message.string);
                }
            }
        }
    }

    const log_content = try log_buf.toOwnedSlice(node.allocator);
    defer node.allocator.free(log_content);

    if (failed) {
        const message = failure_message orelse "runtime error";
        try node.runtime_registry.job_index.markCompleted(
            job_id,
            false,
            message,
            message,
            log_content,
        );
        node.publishChatJobUpdate(.{
            .job_id = job_id,
            .state = .failed,
            .correlation_id = correlation_id,
            .error_text = message,
            .result_text = message,
            .log_text = log_content,
        });
        return;
    }

    try node.runtime_registry.job_index.markCompleted(
        job_id,
        true,
        result_text,
        null,
        log_content,
    );
    node.publishChatJobUpdate(.{
        .job_id = job_id,
        .state = .done,
        .correlation_id = correlation_id,
        .result_text = result_text,
        .log_text = log_content,
    });
}

const NodeRegistration = struct {
    node_id: []u8,
    node_secret: []u8,
};

fn parseNodeRegistrationFromJoinPayload(allocator: std.mem.Allocator, payload_json: []const u8) !NodeRegistration {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const node_id = parsed.value.object.get("node_id") orelse return error.MissingField;
    if (node_id != .string or node_id.string.len == 0) return error.InvalidPayload;
    const node_secret = parsed.value.object.get("node_secret") orelse return error.MissingField;
    if (node_secret != .string or node_secret.string.len == 0) return error.InvalidPayload;

    return .{
        .node_id = try allocator.dupe(u8, node_id.string),
        .node_secret = try allocator.dupe(u8, node_secret.string),
    };
}

fn emitLocalFsWatcherEvents(ctx: ?*anyopaque, events: []const fs_protocol.InvalidationEvent) void {
    const raw = ctx orelse return;
    const node: *LocalFsNode = @ptrCast(@alignCast(raw));
    node.hub.broadcastInvalidations(0, events);
}

fn writeFsHubFrame(conn: *FsHubConnection, payload: []const u8, frame_type: websocket_transport.FrameType) !void {
    conn.write_mutex.lock();
    defer conn.write_mutex.unlock();
    try websocket_transport.writeFrame(conn.stream, payload, frame_type);
}

fn writeStreamFrameWithMutex(
    stream: *std.net.Stream,
    write_mutex: *std.Thread.Mutex,
    payload: []const u8,
    frame_type: websocket_transport.FrameType,
) !void {
    write_mutex.lock();
    defer write_mutex.unlock();
    try websocket_transport.writeFrame(stream, payload, frame_type);
}

fn writeFsHubFrameMaybe(
    connection: ?*FsHubConnection,
    stream: *std.net.Stream,
    write_mutex: *std.Thread.Mutex,
    payload: []const u8,
    frame_type: websocket_transport.FrameType,
) !void {
    if (connection) |conn| {
        return writeFsHubFrame(conn, payload, frame_type);
    }
    return writeStreamFrameWithMutex(stream, write_mutex, payload, frame_type);
}

fn handleLocalFsConnection(
    allocator: std.mem.Allocator,
    local_node: *LocalFsNode,
    stream: *std.net.Stream,
) !void {
    const required_auth_token = try local_node.copySessionAuthToken(allocator);
    defer if (required_auth_token) |token| allocator.free(token);

    var connection: ?*FsHubConnection = null;
    defer if (connection) |conn| local_node.hub.unregister(conn);
    var connection_write_mutex: std.Thread.Mutex = .{};
    var fsrpc_negotiated = false;
    var hello_allow_invalidations = false;

    while (true) {
        var frame = websocket_transport.readFrame(
            allocator,
            stream,
            4 * 1024 * 1024,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = unified.parseMessage(allocator, frame.payload) catch |err| {
                    const response = try unified.buildFsrpcFsError(
                        allocator,
                        null,
                        fs_protocol.Errno.EINVAL,
                        @errorName(err),
                    );
                    defer allocator.free(response);
                    try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, response, .text);
                    try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, "", .close);
                    return;
                };
                defer parsed.deinit(allocator);

                var register_after_response = false;
                if (!fsrpc_negotiated) {
                    if (parsed.channel == .control) {
                        const response = try unified.buildControlError(
                            allocator,
                            parsed.id,
                            "invalid_endpoint",
                            "wrong websocket endpoint: use / for control protocol (/v2/fs is fsrpc-only)",
                        );
                        defer allocator.free(response);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, response, .text);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, "", .close);
                        return;
                    }
                    if (parsed.channel != .acheron or parsed.acheron_type != .fs_t_hello) {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            "acheron.t_fs_hello must be negotiated first",
                        );
                        defer allocator.free(response);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, response, .text);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, "", .close);
                        return;
                    }
                    const hello_opts = validateFsNodeHelloPayload(allocator, parsed.payload_json, required_auth_token) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer allocator.free(response);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, response, .text);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    hello_allow_invalidations = hello_opts.allow_invalidations;
                    fsrpc_negotiated = true;
                    register_after_response = true;
                } else if (parsed.acheron_type == .fs_t_hello) {
                    const hello_opts = validateFsNodeHelloPayload(allocator, parsed.payload_json, required_auth_token) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer allocator.free(response);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, response, .text);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    hello_allow_invalidations = hello_opts.allow_invalidations;
                    if (connection) |live_connection| {
                        if (!hello_allow_invalidations) {
                            local_node.hub.disableInvalidations(live_connection.id);
                        }
                    }
                }

                var handled = local_node.service.handleRequestJsonWithEvents(frame.payload) catch |err| blk: {
                    const fallback = try unified.buildFsrpcFsError(
                        allocator,
                        null,
                        fs_protocol.Errno.EIO,
                        @errorName(err),
                    );
                    break :blk fs_node_service.NodeService.HandledRequest{
                        .response_json = fallback,
                        .events = try allocator.alloc(fs_protocol.InvalidationEvent, 0),
                    };
                };
                defer handled.deinit(allocator);
                if (connection) |live_connection| {
                    if (parsed.acheron_type != .fs_t_hello) {
                        local_node.hub.disableInvalidations(live_connection.id);
                    }
                    for (handled.events) |event| {
                        const event_json = try fs_node_service.buildInvalidationEventJson(allocator, event);
                        defer allocator.free(event_json);
                        try writeFsHubFrame(live_connection, event_json, .text);
                    }

                    if (handled.events.len > 0) {
                        local_node.hub.broadcastInvalidations(live_connection.id, handled.events);
                    }
                    try writeFsHubFrame(live_connection, handled.response_json, .text);
                } else {
                    for (handled.events) |event| {
                        const event_json = try fs_node_service.buildInvalidationEventJson(allocator, event);
                        defer allocator.free(event_json);
                        try writeStreamFrameWithMutex(stream, &connection_write_mutex, event_json, .text);
                    }
                    try writeStreamFrameWithMutex(stream, &connection_write_mutex, handled.response_json, .text);
                }

                if (register_after_response) {
                    connection = try local_node.hub.register(stream, hello_allow_invalidations);
                }
            },
            0x8 => {
                writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, "", .close) catch {};
                return;
            },
            0x9 => {
                try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, frame.payload, .pong);
            },
            0xA => {},
            else => {
                const response = try unified.buildFsrpcFsError(
                    allocator,
                    null,
                    fs_protocol.Errno.EINVAL,
                    "unsupported websocket opcode",
                );
                defer allocator.free(response);
                try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, response, .text);
            },
        }
    }
}

const NodeTunnelHello = struct {
    node_id: []u8,
    node_secret: []u8,

    fn deinit(self: *NodeTunnelHello, allocator: std.mem.Allocator) void {
        allocator.free(self.node_id);
        allocator.free(self.node_secret);
        self.* = undefined;
    }
};

fn parseNodeTunnelHelloPayload(
    allocator: std.mem.Allocator,
    payload_json: ?[]const u8,
) !NodeTunnelHello {
    _ = try validateFsNodeHelloPayload(allocator, payload_json, null);
    const raw = payload_json orelse return error.MissingField;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidType;
    const node_id_value = parsed.value.object.get("node_id") orelse return error.MissingField;
    if (node_id_value != .string or !isValidNodeIdentifier(node_id_value.string)) return error.InvalidPayload;
    const node_secret_value = parsed.value.object.get("node_secret") orelse return error.MissingField;
    if (node_secret_value != .string or node_secret_value.string.len == 0) return error.InvalidPayload;

    return .{
        .node_id = try allocator.dupe(u8, node_id_value.string),
        .node_secret = try allocator.dupe(u8, node_secret_value.string),
    };
}

fn parseFsHelloAuthToken(allocator: std.mem.Allocator, payload_json: ?[]const u8) !?[]u8 {
    const raw = payload_json orelse return null;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidType;
    const auth_value = parsed.value.object.get("auth_token") orelse return null;
    if (auth_value != .string or auth_value.string.len == 0) return null;
    const copy = try allocator.dupe(u8, auth_value.string);
    return @as(?[]u8, copy);
}

fn controlNodeErrorToErrno(err: anyerror) i32 {
    return switch (err) {
        fs_control_plane.ControlPlaneError.NodeNotFound => fs_protocol.Errno.ENOENT,
        fs_control_plane.ControlPlaneError.NodeAuthFailed => fs_protocol.Errno.EACCES,
        else => fs_protocol.Errno.EIO,
    };
}

fn handleNodeTunnelConnection(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    stream: *std.net.Stream,
) !void {
    var attachment: ?NodeTunnelAttachment = null;
    defer if (attachment) |*attached| {
        runtime_registry.node_tunnels.detachTunnel(attached.node_id, attached.generation);
        attached.deinit(allocator);
    };
    var connection_write_mutex: std.Thread.Mutex = .{};

    while (true) {
        var frame = websocket_transport.readFrame(
            allocator,
            stream,
            websocket_transport.default_max_ws_frame_payload_bytes,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = unified.parseMessage(allocator, frame.payload) catch |err| {
                    const response = try unified.buildFsrpcFsError(
                        allocator,
                        null,
                        fs_protocol.Errno.EINVAL,
                        @errorName(err),
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                    return;
                };
                defer parsed.deinit(allocator);

                if (attachment == null) {
                    if (parsed.channel != .acheron or parsed.acheron_type != .fs_t_hello) {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            "acheron.t_fs_hello must be negotiated first",
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    }

                    var hello = parseNodeTunnelHelloPayload(allocator, parsed.payload_json) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    defer hello.deinit(allocator);

                    runtime_registry.control_plane.authenticateNodeSession(hello.node_id, hello.node_secret) catch |auth_err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            controlNodeErrorToErrno(auth_err),
                            @errorName(auth_err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };

                    attachment = try runtime_registry.node_tunnels.attachTunnel(
                        hello.node_id,
                        stream,
                        &connection_write_mutex,
                    );

                    const ack_payload = try std.fmt.allocPrint(
                        allocator,
                        "{{\"protocol\":\"{s}\",\"proto\":{d},\"node_id\":\"{s}\"}}",
                        .{ fsrpc_node_protocol_version, fsrpc_node_proto_id, attachment.?.node_id },
                    );
                    defer allocator.free(ack_payload);
                    const response = try unified.buildFsrpcResponse(
                        allocator,
                        .fs_r_hello,
                        parsed.tag,
                        ack_payload,
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    continue;
                }

                if (parsed.channel != .acheron) continue;
                if (parsed.acheron_type == .fs_t_hello) {
                    var hello = parseNodeTunnelHelloPayload(allocator, parsed.payload_json) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    defer hello.deinit(allocator);
                    if (!std.mem.eql(u8, hello.node_id, attachment.?.node_id)) {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EACCES,
                            "node_id mismatch for active tunnel",
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    }
                    runtime_registry.control_plane.authenticateNodeSession(hello.node_id, hello.node_secret) catch |auth_err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            controlNodeErrorToErrno(auth_err),
                            @errorName(auth_err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    const ack_payload = "{\"protocol\":\"unified-v2-fs\",\"proto\":2}";
                    const response = try unified.buildFsrpcResponse(
                        allocator,
                        .fs_r_hello,
                        parsed.tag,
                        ack_payload,
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    continue;
                }

                runtime_registry.node_tunnels.dispatchTunnelFrame(
                    attachment.?.node_id,
                    attachment.?.generation,
                    frame.payload,
                );
            },
            0x8 => {
                try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                return;
            },
            0x9 => {
                try writeFrameLocked(stream, &connection_write_mutex, frame.payload, .pong);
            },
            0xA => {},
            else => {
                const response = try unified.buildFsrpcFsError(
                    allocator,
                    null,
                    fs_protocol.Errno.EINVAL,
                    "unsupported websocket opcode",
                );
                defer allocator.free(response);
                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
            },
        }
    }
}

fn handleRoutedNodeFsConnection(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    node_id: []const u8,
    stream: *std.net.Stream,
) !void {
    var connection_write_mutex: std.Thread.Mutex = .{};
    var fsrpc_negotiated = false;
    var connection_client_id: ?u64 = null;
    defer if (connection_client_id) |client_id| {
        runtime_registry.node_tunnels.unregisterClient(node_id, client_id);
    };

    while (true) {
        var frame = websocket_transport.readFrame(
            allocator,
            stream,
            websocket_transport.default_max_ws_frame_payload_bytes,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = unified.parseMessage(allocator, frame.payload) catch |err| {
                    const response = try unified.buildFsrpcFsError(
                        allocator,
                        null,
                        fs_protocol.Errno.EINVAL,
                        @errorName(err),
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                    return;
                };
                defer parsed.deinit(allocator);

                if (parsed.channel != .acheron) {
                    const response = try unified.buildFsrpcFsError(
                        allocator,
                        parsed.tag,
                        fs_protocol.Errno.EINVAL,
                        "wrong websocket endpoint: use / for control protocol",
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                    return;
                }

                const fsrpc_type = parsed.acheron_type orelse {
                    const response = try unified.buildFsrpcFsError(
                        allocator,
                        parsed.tag,
                        fs_protocol.Errno.EINVAL,
                        "missing fsrpc message type",
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    continue;
                };
                const client_tag = parsed.tag orelse {
                    const response = try unified.buildFsrpcFsError(
                        allocator,
                        null,
                        fs_protocol.Errno.EINVAL,
                        "missing request tag",
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    continue;
                };

                if (!fsrpc_negotiated) {
                    if (fsrpc_type != .fs_t_hello) {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            "acheron.t_fs_hello must be negotiated first",
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    }
                    const hello_opts = validateFsNodeHelloPayload(allocator, parsed.payload_json, null) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    const auth_token = parseFsHelloAuthToken(allocator, parsed.payload_json) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    defer if (auth_token) |token| allocator.free(token);
                    if (auth_token == null) {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EACCES,
                            "missing auth_token in fs hello payload",
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    }
                    runtime_registry.control_plane.authenticateNodeSession(node_id, auth_token.?) catch |auth_err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            controlNodeErrorToErrno(auth_err),
                            @errorName(auth_err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };

                    connection_client_id = runtime_registry.node_tunnels.registerClient(
                        node_id,
                        stream,
                        &connection_write_mutex,
                        hello_opts.allow_invalidations,
                    ) catch {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EIO,
                            "node tunnel is unavailable",
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    fsrpc_negotiated = true;
                } else if (fsrpc_type == .fs_t_hello) {
                    const hello_opts = validateFsNodeHelloPayload(allocator, parsed.payload_json, null) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                        return;
                    };
                    if (connection_client_id) |client_id| {
                        runtime_registry.node_tunnels.updateClientInvalidations(
                            node_id,
                            client_id,
                            hello_opts.allow_invalidations,
                        );
                    }
                }

                const relayed_response = runtime_registry.node_tunnels.relayRequest(
                    node_id,
                    client_tag,
                    frame.payload,
                ) catch |relay_err| {
                    const response = try unified.buildFsrpcFsError(
                        allocator,
                        parsed.tag,
                        fs_protocol.Errno.EIO,
                        @errorName(relay_err),
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    continue;
                };
                defer allocator.free(relayed_response);
                try writeFrameLocked(stream, &connection_write_mutex, relayed_response, .text);
            },
            0x8 => {
                try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                return;
            },
            0x9 => {
                try writeFrameLocked(stream, &connection_write_mutex, frame.payload, .pong);
            },
            0xA => {},
            else => {
                const response = try unified.buildFsrpcFsError(
                    allocator,
                    null,
                    fs_protocol.Errno.EINVAL,
                    "unsupported websocket opcode",
                );
                defer allocator.free(response);
                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
            },
        }
    }
}

fn stripWsPathQuery(path: []const u8) []const u8 {
    const query_idx = std.mem.indexOfScalar(u8, path, '?') orelse return path;
    return path[0..query_idx];
}

fn isNodeTunnelPath(path: []const u8) bool {
    const normalized = stripWsPathQuery(path);
    return std.mem.eql(u8, normalized, "/v2/node") or std.mem.eql(u8, normalized, "/v2/node/");
}

fn parseNodeFsRoute(path: []const u8) ?[]const u8 {
    const normalized = stripWsPathQuery(path);
    const prefix = "/v2/fs/node/";
    if (!std.mem.startsWith(u8, normalized, prefix)) return null;
    const node_id = normalized[prefix.len..];
    if (!isValidNodeIdentifier(node_id)) return null;
    return node_id;
}

fn isValidNodeIdentifier(node_id: []const u8) bool {
    if (node_id.len == 0 or node_id.len > 128) return false;
    for (node_id) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '_' or char == '-' or char == '.') continue;
        return false;
    }
    return true;
}

fn rewriteAcheronTag(
    allocator: std.mem.Allocator,
    raw_json: []const u8,
    next_tag: u32,
) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const channel_val = parsed.value.object.get("channel") orelse return error.MissingField;
    if (channel_val != .string or !std.mem.eql(u8, channel_val.string, "acheron")) return error.InvalidPayload;
    try parsed.value.object.put("tag", .{ .integer = @as(i64, next_tag) });
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(parsed.value, .{})});
}

fn localFsHeartbeatThreadMain(local_node: *LocalFsNode, control_plane: *fs_control_plane.ControlPlane) void {
    while (true) {
        var elapsed: u64 = 0;
        while (elapsed < local_node.heartbeat_interval_ms) {
            if (local_node.shouldStopHeartbeat()) return;
            const step_ms: u64 = @min(@as(u64, 500), local_node.heartbeat_interval_ms - elapsed);
            std.Thread.sleep(step_ms * std.time.ns_per_ms);
            elapsed += step_ms;
        }
        if (local_node.shouldStopHeartbeat()) return;

        local_node.refreshRegistration(control_plane) catch |err| {
            std.log.warn("local fs node heartbeat refresh failed: {s}", .{@errorName(err)});
        };
    }
}

const auth_tokens_filename = "auth_tokens.json";

const ConnectionRole = enum {
    admin,
    user,
};

fn connectionRoleName(role: ConnectionRole) []const u8 {
    return switch (role) {
        .admin => "admin",
        .user => "user",
    };
}

const ConnectionPrincipal = struct {
    role: ConnectionRole,
    token_id: []const u8,
};

const SessionAttachState = enum {
    warming,
    ready,
    err,
};

const SessionAttachStateSnapshot = struct {
    state: SessionAttachState = .warming,
    runtime_ready: bool = false,
    mount_ready: bool = false,
    error_code: ?[]u8 = null,
    error_message: ?[]u8 = null,
    updated_at_ms: i64 = 0,

    fn deinit(self: *SessionAttachStateSnapshot, allocator: std.mem.Allocator) void {
        if (self.error_code) |value| allocator.free(value);
        if (self.error_message) |value| allocator.free(value);
        self.* = undefined;
    }
};

const RuntimeWarmupState = struct {
    state: SessionAttachState = .warming,
    runtime_ready: bool = false,
    mount_ready: bool = false,
    error_code: ?[]u8 = null,
    error_message: ?[]u8 = null,
    updated_at_ms: i64 = 0,
    retry_after_ms: i64 = 0,
    in_flight: bool = false,

    fn deinit(self: *RuntimeWarmupState, allocator: std.mem.Allocator) void {
        if (self.error_code) |value| allocator.free(value);
        if (self.error_message) |value| allocator.free(value);
        self.* = undefined;
    }

    fn setWarming(self: *RuntimeWarmupState, allocator: std.mem.Allocator) void {
        if (self.error_code) |value| allocator.free(value);
        if (self.error_message) |value| allocator.free(value);
        self.error_code = null;
        self.error_message = null;
        self.state = .warming;
        self.runtime_ready = false;
        self.mount_ready = false;
        self.updated_at_ms = std.time.milliTimestamp();
        self.retry_after_ms = 0;
    }

    fn setReady(self: *RuntimeWarmupState, allocator: std.mem.Allocator) void {
        if (self.error_code) |value| allocator.free(value);
        if (self.error_message) |value| allocator.free(value);
        self.error_code = null;
        self.error_message = null;
        self.state = .ready;
        self.runtime_ready = true;
        self.mount_ready = true;
        self.updated_at_ms = std.time.milliTimestamp();
        self.retry_after_ms = 0;
    }

    fn setError(self: *RuntimeWarmupState, allocator: std.mem.Allocator, code: []const u8, message: []const u8) !void {
        if (self.error_code) |value| allocator.free(value);
        if (self.error_message) |value| allocator.free(value);
        self.error_code = try allocator.dupe(u8, code);
        errdefer {
            allocator.free(self.error_code.?);
            self.error_code = null;
        }
        self.error_message = try allocator.dupe(u8, message);
        self.state = .err;
        self.runtime_ready = false;
        self.mount_ready = false;
        self.updated_at_ms = std.time.milliTimestamp();
        self.retry_after_ms = self.updated_at_ms + runtime_warmup_error_retry_backoff_ms;
    }

    fn snapshotOwned(self: *const RuntimeWarmupState, allocator: std.mem.Allocator) !SessionAttachStateSnapshot {
        var snapshot = SessionAttachStateSnapshot{
            .state = self.state,
            .runtime_ready = self.runtime_ready,
            .mount_ready = self.mount_ready,
            .updated_at_ms = self.updated_at_ms,
        };
        if (self.error_code) |value| {
            snapshot.error_code = try allocator.dupe(u8, value);
        }
        errdefer if (snapshot.error_code) |value| allocator.free(value);
        if (self.error_message) |value| {
            snapshot.error_message = try allocator.dupe(u8, value);
        }
        return snapshot;
    }
};

const SessionBinding = struct {
    agent_id: []u8,
    actor_type: []u8,
    actor_id: []u8,
    project_id: ?[]u8 = null,
    project_token: ?[]u8 = null,

    fn deinit(self: *SessionBinding, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        allocator.free(self.actor_type);
        allocator.free(self.actor_id);
        if (self.project_id) |value| allocator.free(value);
        if (self.project_token) |value| allocator.free(value);
        self.* = undefined;
    }
};

const ServicePresenceDispatchJob = struct {
    agent_id: []u8,
    project_id: ?[]u8 = null,
    session_key: []u8,
    service_id: []u8,
    attached: bool,
    payload_json: []u8,

    fn deinit(self: *ServicePresenceDispatchJob, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        if (self.project_id) |value| allocator.free(value);
        allocator.free(self.session_key);
        allocator.free(self.service_id);
        allocator.free(self.payload_json);
        self.* = undefined;
    }

    fn matches(
        self: *const ServicePresenceDispatchJob,
        agent_id: []const u8,
        project_id: ?[]const u8,
        session_key: []const u8,
        service_id: []const u8,
        attached: bool,
    ) bool {
        return std.mem.eql(u8, self.agent_id, agent_id) and
            optionalStringsEqual(self.project_id, project_id) and
            std.mem.eql(u8, self.session_key, session_key) and
            std.mem.eql(u8, self.service_id, service_id) and
            self.attached == attached;
    }
};

const RememberedTarget = struct {
    agent_id: []u8,
    project_id: []u8,

    fn deinit(self: *RememberedTarget, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        allocator.free(self.project_id);
        self.* = undefined;
    }
};

const SessionHistoryEntry = struct {
    session_key: []u8,
    agent_id: []u8,
    project_id: []u8,
    last_active_ms: i64,
    message_count: u64 = 0,
    summary: ?[]u8 = null,

    fn deinit(self: *SessionHistoryEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.session_key);
        allocator.free(self.agent_id);
        allocator.free(self.project_id);
        if (self.summary) |value| allocator.free(value);
        self.* = undefined;
    }

    fn cloneOwned(self: *const SessionHistoryEntry, allocator: std.mem.Allocator) !SessionHistoryEntry {
        return .{
            .session_key = try allocator.dupe(u8, self.session_key),
            .agent_id = try allocator.dupe(u8, self.agent_id),
            .project_id = try allocator.dupe(u8, self.project_id),
            .last_active_ms = self.last_active_ms,
            .message_count = self.message_count,
            .summary = if (self.summary) |value| try allocator.dupe(u8, value) else null,
        };
    }
};

const AuthTokenStore = struct {
    const PersistedTarget = struct {
        agent_id: ?[]const u8 = null,
        project_id: ?[]const u8 = null,
    };

    const PersistedSessionHistoryEntry = struct {
        session_key: []const u8,
        agent_id: []const u8,
        project_id: []const u8,
        last_active_ms: i64 = 0,
        message_count: u64 = 0,
        summary: ?[]const u8 = null,
    };

    const Persisted = struct {
        schema: u32 = 3,
        admin_token: []const u8,
        user_token: []const u8,
        admin_last_target: ?PersistedTarget = null,
        user_last_target: ?PersistedTarget = null,
        admin_session_history: ?[]PersistedSessionHistoryEntry = null,
        user_session_history: ?[]PersistedSessionHistoryEntry = null,
        updated_at_ms: i64,
    };

    allocator: std.mem.Allocator,
    path: ?[]u8 = null,
    admin_token: []u8,
    user_token: []u8,
    admin_last_target: ?RememberedTarget = null,
    user_last_target: ?RememberedTarget = null,
    admin_session_history: std.ArrayListUnmanaged(SessionHistoryEntry) = .{},
    user_session_history: std.ArrayListUnmanaged(SessionHistoryEntry) = .{},
    mutex: std.Thread.Mutex = .{},

    fn init(allocator: std.mem.Allocator, runtime_config: Config.RuntimeConfig) AuthTokenStore {
        var store = AuthTokenStore{
            .allocator = allocator,
            .admin_token = allocator.dupe(u8, "") catch @panic("oom"),
            .user_token = allocator.dupe(u8, "") catch @panic("oom"),
        };
        store.loadOrGenerate(runtime_config);
        return store;
    }

    fn deinit(self: *AuthTokenStore) void {
        if (self.path) |value| self.allocator.free(value);
        self.allocator.free(self.admin_token);
        self.allocator.free(self.user_token);
        if (self.admin_last_target) |*target| target.deinit(self.allocator);
        if (self.user_last_target) |*target| target.deinit(self.allocator);
        for (self.admin_session_history.items) |*entry| entry.deinit(self.allocator);
        self.admin_session_history.deinit(self.allocator);
        for (self.user_session_history.items) |*entry| entry.deinit(self.allocator);
        self.user_session_history.deinit(self.allocator);
        self.* = undefined;
    }

    fn authenticate(self: *const AuthTokenStore, authorization_header: ?[]const u8) ?ConnectionPrincipal {
        const raw = authorization_header orelse return null;
        const token = parseBearerToken(raw) orelse return null;
        const mutex = @constCast(&self.mutex);
        mutex.lock();
        defer mutex.unlock();
        if (secureTokenEql(self.admin_token, token)) return .{ .role = .admin, .token_id = "admin" };
        if (secureTokenEql(self.user_token, token)) return .{ .role = .user, .token_id = "user" };
        return null;
    }

    fn rotateRoleToken(self: *AuthTokenStore, role: ConnectionRole) ![]u8 {
        const next = try makeOpaqueToken(self.allocator, switch (role) {
            .admin => "sw-admin",
            .user => "sw-user",
        });
        errdefer self.allocator.free(next);
        const replacement = try self.allocator.dupe(u8, next);
        errdefer self.allocator.free(replacement);

        self.mutex.lock();
        defer self.mutex.unlock();
        switch (role) {
            .admin => {
                const previous = self.admin_token;
                self.admin_token = replacement;
                self.persistCurrentStateLocked() catch |err| {
                    self.admin_token = previous;
                    self.allocator.free(replacement);
                    return err;
                };
                self.allocator.free(previous);
            },
            .user => {
                const previous = self.user_token;
                self.user_token = replacement;
                self.persistCurrentStateLocked() catch |err| {
                    self.user_token = previous;
                    self.allocator.free(replacement);
                    return err;
                };
                self.allocator.free(previous);
            },
        }
        return next;
    }

    fn rememberedTargetOwned(self: *const AuthTokenStore, role: ConnectionRole) !?RememberedTarget {
        const mutex = @constCast(&self.mutex);
        mutex.lock();
        defer mutex.unlock();
        const stored = switch (role) {
            .admin => self.admin_last_target,
            .user => self.user_last_target,
        } orelse return null;
        return .{
            .agent_id = try self.allocator.dupe(u8, stored.agent_id),
            .project_id = try self.allocator.dupe(u8, stored.project_id),
        };
    }

    fn setRememberedTarget(self: *AuthTokenStore, role: ConnectionRole, agent_id: []const u8, project_id: []const u8) !void {
        const next_agent = try self.allocator.dupe(u8, agent_id);
        errdefer self.allocator.free(next_agent);
        const next_project = try self.allocator.dupe(u8, project_id);
        errdefer self.allocator.free(next_project);
        var next_target = RememberedTarget{
            .agent_id = next_agent,
            .project_id = next_project,
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        const slot = switch (role) {
            .admin => &self.admin_last_target,
            .user => &self.user_last_target,
        };
        var previous = slot.*;
        slot.* = next_target;
        self.persistCurrentStateLocked() catch |err| {
            slot.* = previous;
            next_target.deinit(self.allocator);
            return err;
        };
        if (previous) |*value| value.deinit(self.allocator);
    }

    fn clearRememberedTarget(self: *AuthTokenStore, role: ConnectionRole) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const slot = switch (role) {
            .admin => &self.admin_last_target,
            .user => &self.user_last_target,
        };
        var previous = slot.*;
        slot.* = null;
        self.persistCurrentStateLocked() catch |err| {
            slot.* = previous;
            return err;
        };
        if (previous) |*value| value.deinit(self.allocator);
    }

    fn recordSessionActivity(
        self: *AuthTokenStore,
        role: ConnectionRole,
        session_key: []const u8,
        agent_id: []const u8,
        project_id: []const u8,
        message_delta: u64,
    ) !void {
        const max_history_entries: usize = 10;
        self.mutex.lock();
        defer self.mutex.unlock();

        const history = switch (role) {
            .admin => &self.admin_session_history,
            .user => &self.user_session_history,
        };

        const now_ms = std.time.milliTimestamp();
        _ = self.pruneExpiredSessionHistoryLocked(history, now_ms);
        for (history.items) |*entry| {
            if (std.mem.eql(u8, entry.session_key, session_key) and
                std.mem.eql(u8, entry.agent_id, agent_id) and
                std.mem.eql(u8, entry.project_id, project_id))
            {
                entry.last_active_ms = now_ms;
                entry.message_count += message_delta;
                self.sortSessionHistoryNewestFirst(history);
                self.persistCurrentStateLocked() catch |err| {
                    std.log.warn("failed to persist session history update: {s}", .{@errorName(err)});
                };
                return;
            }
        }

        try history.append(self.allocator, .{
            .session_key = try self.allocator.dupe(u8, session_key),
            .agent_id = try self.allocator.dupe(u8, agent_id),
            .project_id = try self.allocator.dupe(u8, project_id),
            .last_active_ms = now_ms,
            .message_count = message_delta,
            .summary = try std.fmt.allocPrint(
                self.allocator,
                "{s} @ {s}",
                .{ agent_id, project_id },
            ),
        });
        self.sortSessionHistoryNewestFirst(history);
        while (history.items.len > max_history_entries) {
            var removed = history.pop().?;
            removed.deinit(self.allocator);
        }
        self.persistCurrentStateLocked() catch |err| {
            std.log.warn("failed to persist session history append: {s}", .{@errorName(err)});
        };
    }

    fn sessionHistoryOwned(
        self: *AuthTokenStore,
        role: ConnectionRole,
        agent_id_filter: ?[]const u8,
        limit: usize,
    ) !std.ArrayListUnmanaged(SessionHistoryEntry) {
        var out = std.ArrayListUnmanaged(SessionHistoryEntry){};
        errdefer {
            for (out.items) |*entry| entry.deinit(self.allocator);
            out.deinit(self.allocator);
        }

        const effective_limit = if (limit == 0) @as(usize, 10) else limit;
        const mutex = &self.mutex;
        mutex.lock();
        defer mutex.unlock();
        const history = switch (role) {
            .admin => &self.admin_session_history,
            .user => &self.user_session_history,
        };
        const now_ms = std.time.milliTimestamp();
        const pruned = self.pruneExpiredSessionHistoryLocked(history, now_ms);
        if (pruned) {
            self.persistCurrentStateLocked() catch |err| {
                std.log.warn("failed to persist pruned session history: {s}", .{@errorName(err)});
            };
        }
        for (history.items) |*entry| {
            if (agent_id_filter) |filter| {
                if (!std.mem.eql(u8, entry.agent_id, filter)) continue;
            }
            try out.append(self.allocator, try entry.cloneOwned(self.allocator));
            if (out.items.len >= effective_limit) break;
        }
        return out;
    }

    fn latestSessionOwned(
        self: *AuthTokenStore,
        role: ConnectionRole,
        agent_id_filter: ?[]const u8,
    ) !?SessionHistoryEntry {
        var history = try self.sessionHistoryOwned(role, agent_id_filter, 1);
        errdefer {
            for (history.items) |*entry| entry.deinit(self.allocator);
            history.deinit(self.allocator);
        }
        if (history.items.len == 0) {
            history.deinit(self.allocator);
            return null;
        }
        const entry = history.orderedRemove(0);
        history.deinit(self.allocator);
        return entry;
    }

    fn sessionLastActiveMs(self: *const AuthTokenStore, role: ConnectionRole, session_key: []const u8) ?i64 {
        const mutex = @constCast(&self.mutex);
        mutex.lock();
        defer mutex.unlock();
        const history = switch (role) {
            .admin => &self.admin_session_history,
            .user => &self.user_session_history,
        };
        var latest: ?i64 = null;
        for (history.items) |*entry| {
            if (!std.mem.eql(u8, entry.session_key, session_key)) continue;
            if (latest == null or entry.last_active_ms > latest.?) latest = entry.last_active_ms;
        }
        return latest;
    }

    fn sortSessionHistoryNewestFirst(self: *AuthTokenStore, history: *std.ArrayListUnmanaged(SessionHistoryEntry)) void {
        _ = self;
        var i: usize = 1;
        while (i < history.items.len) : (i += 1) {
            var j = i;
            while (j > 0 and history.items[j - 1].last_active_ms < history.items[j].last_active_ms) : (j -= 1) {
                const tmp = history.items[j - 1];
                history.items[j - 1] = history.items[j];
                history.items[j] = tmp;
            }
        }
    }

    fn pruneExpiredSessionHistoryLocked(
        self: *AuthTokenStore,
        history: *std.ArrayListUnmanaged(SessionHistoryEntry),
        now_ms: i64,
    ) bool {
        const max_age_ms: i64 = 24 * 60 * 60 * 1000;
        var removed_any = false;
        var idx: usize = 0;
        while (idx < history.items.len) {
            const age_ms = now_ms - history.items[idx].last_active_ms;
            if (age_ms > max_age_ms) {
                var removed = history.orderedRemove(idx);
                removed.deinit(self.allocator);
                removed_any = true;
                continue;
            }
            idx += 1;
        }
        return removed_any;
    }

    fn statusJson(self: *const AuthTokenStore) ![]u8 {
        const mutex = @constCast(&self.mutex);
        mutex.lock();
        defer mutex.unlock();
        const escaped_admin = try unified.jsonEscape(self.allocator, self.admin_token);
        defer self.allocator.free(escaped_admin);
        const escaped_user = try unified.jsonEscape(self.allocator, self.user_token);
        defer self.allocator.free(escaped_user);
        const path_json = if (self.path) |value| blk: {
            const escaped_path = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped_path);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_path});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(path_json);
        const admin_target_json = if (self.admin_last_target) |target| blk: {
            const escaped_agent = try unified.jsonEscape(self.allocator, target.agent_id);
            defer self.allocator.free(escaped_agent);
            const escaped_project = try unified.jsonEscape(self.allocator, target.project_id);
            defer self.allocator.free(escaped_project);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\"}}",
                .{ escaped_agent, escaped_project },
            );
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(admin_target_json);
        const user_target_json = if (self.user_last_target) |target| blk: {
            const escaped_agent = try unified.jsonEscape(self.allocator, target.agent_id);
            defer self.allocator.free(escaped_agent);
            const escaped_project = try unified.jsonEscape(self.allocator, target.project_id);
            defer self.allocator.free(escaped_project);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\"}}",
                .{ escaped_agent, escaped_project },
            );
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(user_target_json);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"admin_token\":\"{s}\",\"user_token\":\"{s}\",\"path\":{s},\"admin_last_target\":{s},\"user_last_target\":{s}}}",
            .{
                escaped_admin,
                escaped_user,
                path_json,
                admin_target_json,
                user_target_json,
            },
        );
    }

    fn loadOrGenerate(self: *AuthTokenStore, runtime_config: Config.RuntimeConfig) void {
        const base_dir = std.mem.trim(u8, runtime_config.ltm_directory, " \t\r\n");
        const storage_dir = if (base_dir.len == 0) "." else base_dir;
        ensureDirectoryExists(storage_dir) catch {};
        self.path = std.fs.path.join(self.allocator, &.{ storage_dir, auth_tokens_filename }) catch null;

        if (self.path) |path| {
            const loaded = self.loadFromPath(path) catch false;
            if (loaded) return;
        }

        const generated_admin = makeOpaqueToken(self.allocator, "sw-admin") catch return;
        defer self.allocator.free(generated_admin);
        const generated_user = makeOpaqueToken(self.allocator, "sw-user") catch return;
        defer self.allocator.free(generated_user);
        const next_admin = self.allocator.dupe(u8, generated_admin) catch return;
        errdefer self.allocator.free(next_admin);
        const next_user = self.allocator.dupe(u8, generated_user) catch return;
        errdefer self.allocator.free(next_user);

        self.mutex.lock();
        defer self.mutex.unlock();
        const previous_admin = self.admin_token;
        const previous_user = self.user_token;
        self.admin_token = next_admin;
        self.user_token = next_user;
        self.allocator.free(previous_admin);
        self.allocator.free(previous_user);
        self.persistCurrentStateLocked() catch |err| {
            std.log.warn("failed to persist generated auth tokens: {s}", .{@errorName(err)});
        };

        std.log.warn("Generated Spiderweb auth tokens (save these now):", .{});
        std.log.warn("  admin: {s}", .{self.admin_token});
        std.log.warn("  user:  {s}", .{self.user_token});
    }

    fn loadFromPath(self: *AuthTokenStore, path: []const u8) !bool {
        const raw = std.fs.cwd().readFileAlloc(self.allocator, path, 64 * 1024) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer self.allocator.free(raw);

        const parsed = try std.json.parseFromSlice(Persisted, self.allocator, raw, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();
        if (parsed.value.admin_token.len == 0 or parsed.value.user_token.len == 0) return false;
        const next_admin = try self.allocator.dupe(u8, parsed.value.admin_token);
        errdefer self.allocator.free(next_admin);
        const next_user = try self.allocator.dupe(u8, parsed.value.user_token);
        errdefer self.allocator.free(next_user);
        var next_admin_target = try copyPersistedTarget(self.allocator, parsed.value.admin_last_target);
        errdefer if (next_admin_target) |*target| target.deinit(self.allocator);
        var next_user_target = try copyPersistedTarget(self.allocator, parsed.value.user_last_target);
        errdefer if (next_user_target) |*target| target.deinit(self.allocator);
        var next_admin_history = try copyPersistedSessionHistory(
            self.allocator,
            parsed.value.admin_session_history,
        );
        errdefer deinitSessionHistoryList(self.allocator, &next_admin_history);
        var next_user_history = try copyPersistedSessionHistory(
            self.allocator,
            parsed.value.user_session_history,
        );
        errdefer deinitSessionHistoryList(self.allocator, &next_user_history);

        self.mutex.lock();
        defer self.mutex.unlock();
        const previous_admin = self.admin_token;
        const previous_user = self.user_token;
        var previous_admin_target = self.admin_last_target;
        var previous_user_target = self.user_last_target;
        var previous_admin_history = self.admin_session_history;
        var previous_user_history = self.user_session_history;
        self.admin_token = next_admin;
        self.user_token = next_user;
        self.admin_last_target = next_admin_target;
        self.user_last_target = next_user_target;
        self.admin_session_history = next_admin_history;
        self.user_session_history = next_user_history;
        self.allocator.free(previous_admin);
        self.allocator.free(previous_user);
        if (previous_admin_target) |*target| target.deinit(self.allocator);
        if (previous_user_target) |*target| target.deinit(self.allocator);
        deinitSessionHistoryList(self.allocator, &previous_admin_history);
        deinitSessionHistoryList(self.allocator, &previous_user_history);
        return true;
    }

    fn persistCurrentStateLocked(self: *AuthTokenStore) !void {
        const path = self.path orelse return error.AuthTokenPathUnavailable;
        const admin_history = try persistedSessionHistorySlice(
            self.allocator,
            self.admin_session_history.items,
        );
        defer if (admin_history) |value| self.allocator.free(value);
        const user_history = try persistedSessionHistorySlice(
            self.allocator,
            self.user_session_history.items,
        );
        defer if (user_history) |value| self.allocator.free(value);

        const payload = Persisted{
            .schema = 3,
            .admin_token = self.admin_token,
            .user_token = self.user_token,
            .admin_last_target = if (self.admin_last_target) |value| .{
                .agent_id = value.agent_id,
                .project_id = value.project_id,
            } else null,
            .user_last_target = if (self.user_last_target) |value| .{
                .agent_id = value.agent_id,
                .project_id = value.project_id,
            } else null,
            .admin_session_history = admin_history,
            .user_session_history = user_history,
            .updated_at_ms = std.time.milliTimestamp(),
        };
        const bytes = try std.json.Stringify.valueAlloc(self.allocator, payload, .{
            .emit_null_optional_fields = false,
            .whitespace = .indent_2,
        });
        defer self.allocator.free(bytes);

        const file = try std.fs.cwd().createFile(path, .{
            .truncate = true,
            .mode = 0o600,
        });
        defer file.close();
        if (builtin.os.tag != .windows) {
            try file.chmod(0o600);
        }
        try file.writeAll(bytes);
    }

    fn copyPersistedTarget(allocator: std.mem.Allocator, persisted: ?PersistedTarget) !?RememberedTarget {
        const value = persisted orelse return null;
        const agent_id = value.agent_id orelse return null;
        const project_id = value.project_id orelse return null;
        return .{
            .agent_id = try allocator.dupe(u8, agent_id),
            .project_id = try allocator.dupe(u8, project_id),
        };
    }

    fn copyPersistedSessionHistory(
        allocator: std.mem.Allocator,
        persisted: ?[]PersistedSessionHistoryEntry,
    ) !std.ArrayListUnmanaged(SessionHistoryEntry) {
        var out = std.ArrayListUnmanaged(SessionHistoryEntry){};
        errdefer deinitSessionHistoryList(allocator, &out);

        const items = persisted orelse return out;
        for (items) |entry| {
            try out.append(allocator, .{
                .session_key = try allocator.dupe(u8, entry.session_key),
                .agent_id = try allocator.dupe(u8, entry.agent_id),
                .project_id = try allocator.dupe(u8, entry.project_id),
                .last_active_ms = entry.last_active_ms,
                .message_count = entry.message_count,
                .summary = if (entry.summary) |value| try allocator.dupe(u8, value) else null,
            });
        }
        return out;
    }

    fn deinitSessionHistoryList(
        allocator: std.mem.Allocator,
        list: *std.ArrayListUnmanaged(SessionHistoryEntry),
    ) void {
        for (list.items) |*entry| entry.deinit(allocator);
        list.deinit(allocator);
        list.* = .{};
    }

    fn persistedSessionHistorySlice(
        allocator: std.mem.Allocator,
        entries: []const SessionHistoryEntry,
    ) !?[]PersistedSessionHistoryEntry {
        if (entries.len == 0) return null;
        var out = try allocator.alloc(PersistedSessionHistoryEntry, entries.len);
        for (entries, 0..) |entry, idx| {
            out[idx] = .{
                .session_key = entry.session_key,
                .agent_id = entry.agent_id,
                .project_id = entry.project_id,
                .last_active_ms = entry.last_active_ms,
                .message_count = entry.message_count,
                .summary = entry.summary,
            };
        }
        return out;
    }

    fn parseBearerToken(header_value: []const u8) ?[]const u8 {
        const trimmed = std.mem.trim(u8, header_value, " \t");
        if (trimmed.len == 0) return null;
        if (std.mem.startsWith(u8, trimmed, "Bearer ")) {
            const token = std.mem.trim(u8, trimmed["Bearer ".len..], " \t");
            if (token.len == 0) return null;
            return token;
        }
        if (std.mem.startsWith(u8, trimmed, "bearer ")) {
            const token = std.mem.trim(u8, trimmed["bearer ".len..], " \t");
            if (token.len == 0) return null;
            return token;
        }
        return trimmed;
    }

    fn makeOpaqueToken(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
        var random_bytes: [24]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        var encoded_buf: [std.base64.url_safe_no_pad.Encoder.calcSize(random_bytes.len)]u8 = undefined;
        const encoded = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buf, &random_bytes);
        return std.fmt.allocPrint(allocator, "{s}_{s}", .{ prefix, encoded });
    }

    fn copyAdminToken(self: *AuthTokenStore) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.allocator.dupe(u8, self.admin_token);
    }
};

const AgentRuntimeEntry = struct {
    runtime: *runtime_handle_mod.RuntimeHandle,
    project_id: []u8,
    runtime_agent_id: []u8,
    tool_dispatch_proxy: ?*RuntimeToolDispatchProxy = null,

    fn deinit(self: *AgentRuntimeEntry, allocator: std.mem.Allocator) void {
        self.runtime.destroy();
        if (self.tool_dispatch_proxy) |proxy| proxy.destroy();
        allocator.free(self.project_id);
        allocator.free(self.runtime_agent_id);
        self.* = undefined;
    }
};

fn pathExistsAsDirectory(path: []const u8) !bool {
    if (std.fs.path.isAbsolute(path)) {
        var dir = std.fs.openDirAbsolute(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer dir.close();
        return true;
    }
    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer dir.close();
    return true;
}

fn normalizeControlPath(path: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, path, " \t\r\n");
    const no_leading = std.mem.trimLeft(u8, trimmed, "/");
    return std.mem.trimRight(u8, no_leading, "/");
}

fn pathMatchesControlTarget(path: []const u8, target: []const u8) bool {
    const normalized = normalizeControlPath(path);
    return std.mem.eql(u8, normalized, target);
}

fn requiredStringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

fn optionalStringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

fn optionalBoolField(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const value = obj.get(key) orelse return null;
    if (value != .bool) return null;
    return value.bool;
}

fn optionalUsizeField(obj: std.json.ObjectMap, key: []const u8) ?usize {
    const value = obj.get(key) orelse return null;
    if (value != .integer or value.integer < 0) return null;
    return @as(usize, @intCast(value.integer));
}

fn utf8SafePrefix(value: []const u8) []const u8 {
    if (std.unicode.utf8ValidateSlice(value)) return value;
    var idx = value.len;
    while (idx > 0) : (idx -= 1) {
        if (std.unicode.utf8ValidateSlice(value[0..idx])) return value[0..idx];
    }
    return "";
}

fn isValidProvisioningAgentId(agent_id: []const u8) bool {
    if (agent_id.len == 0 or agent_id.len > max_agent_id_len) return false;
    if (std.mem.eql(u8, agent_id, ".") or std.mem.eql(u8, agent_id, "..")) return false;
    if (std.mem.eql(u8, agent_id, "self")) return false;
    for (agent_id) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '_' or char == '-') continue;
        return false;
    }
    return true;
}

const RuntimeToolDispatchProxy = struct {
    allocator: std.mem.Allocator,
    sandbox_runtime: *sandbox_runtime_mod.SandboxRuntime,
    control_plane: *fs_control_plane.ControlPlane,
    agents_dir: []const u8,
    assets_dir: []const u8,
    runtime_agent_id: []u8,

    const RuntimeFileListEntry = struct {
        name: []const u8,
        kind: []const u8,
    };

    const ProjectsOp = enum {
        list,
        get,
        up,
    };

    const AgentsOp = enum {
        list,
        create,
    };

    fn create(
        allocator: std.mem.Allocator,
        sandbox_runtime: *sandbox_runtime_mod.SandboxRuntime,
        control_plane: *fs_control_plane.ControlPlane,
        agents_dir: []const u8,
        assets_dir: []const u8,
        runtime_agent_id: []const u8,
    ) !*RuntimeToolDispatchProxy {
        const self = try allocator.create(RuntimeToolDispatchProxy);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .sandbox_runtime = sandbox_runtime,
            .control_plane = control_plane,
            .agents_dir = agents_dir,
            .assets_dir = assets_dir,
            .runtime_agent_id = try allocator.dupe(u8, runtime_agent_id),
        };
        return self;
    }

    fn destroy(self: *RuntimeToolDispatchProxy) void {
        self.allocator.free(self.runtime_agent_id);
        self.allocator.destroy(self);
    }

    pub fn dispatchWorldTool(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        tool_name: []const u8,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        const self: *RuntimeToolDispatchProxy = @ptrCast(@alignCast(ctx));
        return self.executeWorldTool(allocator, tool_name, args_json);
    }

    fn executeWorldTool(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        tool_name: []const u8,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        if (std.mem.eql(u8, tool_name, "file_read")) {
            return self.handleFileRead(allocator, args_json);
        }
        if (std.mem.eql(u8, tool_name, "file_write")) {
            return self.handleFileWrite(allocator, args_json);
        }
        if (std.mem.eql(u8, tool_name, "file_list")) {
            return self.handleFileList(allocator, args_json);
        }
        return self.sandbox_runtime.executeWorldTool(allocator, tool_name, args_json);
    }

    fn handleFileRead(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, args_json, .{}) catch {
            return runtimeDispatchFailure(allocator, .invalid_params, "file_read arguments must be a JSON object");
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "file_read arguments must be a JSON object");
        }

        const obj = parsed.value.object;
        const path = requiredStringField(obj, "path") orelse
            return runtimeDispatchFailure(allocator, .invalid_params, "file_read path must be provided");

        if (runtimeDispatchSyntheticReadContent(path)) |content| {
            return runtimeDispatchFileReadSuccess(allocator, path, content);
        }
        return self.sandbox_runtime.executeWorldTool(allocator, "file_read", args_json);
    }

    fn handleFileWrite(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, args_json, .{}) catch {
            return runtimeDispatchFailure(allocator, .invalid_params, "file_write arguments must be a JSON object");
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "file_write arguments must be a JSON object");
        }

        const obj = parsed.value.object;
        const path = requiredStringField(obj, "path") orelse
            return runtimeDispatchFailure(allocator, .invalid_params, "file_write path must be provided");
        const content = requiredStringField(obj, "content") orelse
            return runtimeDispatchFailure(allocator, .invalid_params, "file_write content must be provided");

        if (isProjectsControlPath(path)) {
            return self.handleProjectsControlWrite(allocator, path, content);
        }
        if (isAgentsControlPath(path)) {
            return self.handleAgentsControlWrite(allocator, path, content);
        }
        return self.sandbox_runtime.executeWorldTool(allocator, "file_write", args_json);
    }

    fn handleFileList(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, args_json, .{}) catch {
            return runtimeDispatchFailure(allocator, .invalid_params, "file_list arguments must be a JSON object");
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "file_list arguments must be a JSON object");
        }
        const obj = parsed.value.object;
        const path = optionalStringField(obj, "path") orelse ".";

        if (pathMatchesAnyControlTarget(path, &.{"global"})) {
            return runtimeDispatchFileListSuccess(allocator, path, &.{
                .{ .name = "services", .kind = "dir" },
                .{ .name = "chat", .kind = "dir" },
                .{ .name = "jobs", .kind = "dir" },
                .{ .name = "projects", .kind = "dir" },
                .{ .name = "agents", .kind = "dir" },
            });
        }
        if (pathMatchesAnyControlTarget(path, &.{"global/services"})) {
            return runtimeDispatchFileListSuccess(allocator, path, &.{
                .{ .name = "SERVICES.json", .kind = "file" },
            });
        }
        if (pathMatchesAnyControlTarget(path, &.{"global/projects"})) {
            return runtimeDispatchFileListSuccess(allocator, path, &.{
                .{ .name = "README.md", .kind = "file" },
                .{ .name = "SCHEMA.json", .kind = "file" },
                .{ .name = "CAPS.json", .kind = "file" },
                .{ .name = "OPS.json", .kind = "file" },
                .{ .name = "PERMISSIONS.json", .kind = "file" },
                .{ .name = "STATUS.json", .kind = "file" },
                .{ .name = "status.json", .kind = "file" },
                .{ .name = "result.json", .kind = "file" },
                .{ .name = "control", .kind = "dir" },
            });
        }
        if (pathMatchesAnyControlTarget(path, &.{"global/projects/control"})) {
            return runtimeDispatchFileListSuccess(allocator, path, &.{
                .{ .name = "README.md", .kind = "file" },
                .{ .name = "invoke.json", .kind = "file" },
                .{ .name = "list.json", .kind = "file" },
                .{ .name = "get.json", .kind = "file" },
                .{ .name = "up.json", .kind = "file" },
            });
        }
        if (pathMatchesAnyControlTarget(path, &.{"global/agents"})) {
            return runtimeDispatchFileListSuccess(allocator, path, &.{
                .{ .name = "README.md", .kind = "file" },
                .{ .name = "SCHEMA.json", .kind = "file" },
                .{ .name = "CAPS.json", .kind = "file" },
                .{ .name = "OPS.json", .kind = "file" },
                .{ .name = "PERMISSIONS.json", .kind = "file" },
                .{ .name = "STATUS.json", .kind = "file" },
                .{ .name = "status.json", .kind = "file" },
                .{ .name = "result.json", .kind = "file" },
                .{ .name = "control", .kind = "dir" },
            });
        }
        if (pathMatchesAnyControlTarget(path, &.{"global/agents/control"})) {
            return runtimeDispatchFileListSuccess(allocator, path, &.{
                .{ .name = "README.md", .kind = "file" },
                .{ .name = "invoke.json", .kind = "file" },
                .{ .name = "list.json", .kind = "file" },
                .{ .name = "create.json", .kind = "file" },
            });
        }
        return self.sandbox_runtime.executeWorldTool(allocator, "file_list", args_json);
    }

    fn handleProjectsUpWrite(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        path: []const u8,
        content: []const u8,
    ) tool_registry.ToolExecutionResult {
        const is_admin = std.mem.eql(u8, self.runtime_agent_id, system_agent_id);
        const up_result = self.control_plane.projectUpWithRole(self.runtime_agent_id, content, is_admin) catch |err| {
            return runtimeDispatchFailure(allocator, runtimeDispatchErrorCode(err), @errorName(err));
        };
        defer self.control_plane.allocator.free(up_result);
        return runtimeDispatchFileWriteSuccess(allocator, path, content.len, up_result);
    }

    fn handleProjectsControlWrite(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        path: []const u8,
        content: []const u8,
    ) tool_registry.ToolExecutionResult {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch {
            return runtimeDispatchFailure(allocator, .invalid_params, "projects payload must be a JSON object");
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "projects payload must be a JSON object");
        }
        const obj = parsed.value.object;

        const op = if (pathMatchesAnyControlTarget(path, &.{"global/projects/control/list.json"}))
            ProjectsOp.list
        else if (pathMatchesAnyControlTarget(path, &.{"global/projects/control/get.json"}))
            ProjectsOp.get
        else if (pathMatchesAnyControlTarget(path, &.{"global/projects/control/up.json"}))
            ProjectsOp.up
        else if (pathMatchesAnyControlTarget(path, &.{"global/projects/control/invoke.json"}))
            self.parseProjectsInvokeOp(obj) orelse
                return runtimeDispatchFailure(allocator, .invalid_params, "projects invoke payload requires op=list|get|up")
        else
            return runtimeDispatchFailure(allocator, .invalid_params, "unsupported projects control path");

        const args_value = if (obj.get("arguments")) |args| args else if (obj.get("args")) |args| args else parsed.value;
        if (args_value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "projects arguments must be a JSON object");
        }
        const args_obj = args_value.object;
        const is_admin = std.mem.eql(u8, self.runtime_agent_id, system_agent_id);

        switch (op) {
            .up => {
                if (pathMatchesAnyControlTarget(path, &.{"global/projects/control/up.json"})) {
                    return self.handleProjectsUpWrite(allocator, path, content);
                }
                const up_payload = stringifyJsonValueAlloc(allocator, args_value) catch {
                    return runtimeDispatchFailure(allocator, .execution_failed, "failed to serialize projects up payload");
                };
                defer allocator.free(up_payload);
                return self.handleProjectsUpWrite(allocator, path, up_payload);
            },
            .list => {
                const list_result = self.control_plane.listProjects() catch |err| {
                    return runtimeDispatchFailure(allocator, runtimeDispatchErrorCode(err), @errorName(err));
                };
                defer self.control_plane.allocator.free(list_result);
                return runtimeDispatchFileWriteSuccess(allocator, path, content.len, list_result);
            },
            .get => {
                const project_id = optionalStringField(args_obj, "project_id") orelse
                    return runtimeDispatchFailure(allocator, .invalid_params, "projects get requires project_id");
                const project_token = optionalStringField(args_obj, "project_token");
                const payload = buildProjectScopedPayload(allocator, project_id, project_token) catch {
                    return runtimeDispatchFailure(allocator, .execution_failed, "failed to build projects get payload");
                };
                defer allocator.free(payload);
                const get_result = self.control_plane.getProjectWithRole(payload, is_admin) catch |err| {
                    return runtimeDispatchFailure(allocator, runtimeDispatchErrorCode(err), @errorName(err));
                };
                defer self.control_plane.allocator.free(get_result);
                return runtimeDispatchFileWriteSuccess(allocator, path, content.len, get_result);
            },
        }
    }

    fn parseProjectsInvokeOp(self: *RuntimeToolDispatchProxy, obj: std.json.ObjectMap) ?ProjectsOp {
        _ = self;
        const raw = optionalStringField(obj, "op") orelse
            optionalStringField(obj, "operation") orelse
            optionalStringField(obj, "tool") orelse
            optionalStringField(obj, "tool_name") orelse
            return null;
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "projects_list")) return .list;
        if (std.mem.eql(u8, value, "get") or std.mem.eql(u8, value, "projects_get")) return .get;
        if (std.mem.eql(u8, value, "up") or std.mem.eql(u8, value, "projects_up")) return .up;
        return null;
    }

    fn handleAgentsCreateWrite(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        path: []const u8,
        content: []const u8,
    ) tool_registry.ToolExecutionResult {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch {
            return runtimeDispatchFailure(allocator, .invalid_params, "agents create payload must be a JSON object");
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "agents create payload must be a JSON object");
        }
        const obj = parsed.value.object;
        const agent_id = requiredStringField(obj, "agent_id") orelse optionalStringField(obj, "id") orelse
            return runtimeDispatchFailure(allocator, .invalid_params, "agents create payload requires agent_id (or id)");
        if (!isValidProvisioningAgentId(agent_id)) {
            return runtimeDispatchFailure(allocator, .invalid_params, "agent_id must be alphanumeric/underscore/hyphen and not self");
        }

        var registry = agent_registry_mod.AgentRegistry.init(
            self.allocator,
            ".",
            self.agents_dir,
            self.assets_dir,
        );
        defer registry.deinit();
        registry.scan() catch |err| {
            return runtimeDispatchFailure(allocator, .execution_failed, @errorName(err));
        };

        var created = false;
        if (registry.getAgent(agent_id) == null) {
            const template_path = optionalStringField(obj, "template_path") orelse optionalStringField(obj, "template");
            registry.createAgent(agent_id, template_path) catch |err| {
                return runtimeDispatchFailure(allocator, runtimeDispatchErrorCode(err), @errorName(err));
            };
            created = true;
        }

        const desired_project_id = optionalStringField(obj, "project_id");
        var activated = false;
        if (desired_project_id) |project_id| {
            const escaped_project = unified.jsonEscape(self.control_plane.allocator, project_id) catch null;
            if (escaped_project) |escaped| {
                defer self.control_plane.allocator.free(escaped);
                const activation_payload = std.fmt.allocPrint(self.control_plane.allocator, "{{\"project_id\":\"{s}\"}}", .{escaped}) catch null;
                if (activation_payload) |payload| {
                    defer self.control_plane.allocator.free(payload);
                    const activation_is_admin = std.mem.eql(u8, self.runtime_agent_id, system_agent_id);
                    if (self.control_plane.activateProjectWithRole(agent_id, payload, activation_is_admin)) |activation_result| {
                        defer self.control_plane.allocator.free(activation_result);
                        activated = true;
                    } else |_| {}
                }
            }
        }

        const escaped_agent = unified.jsonEscape(allocator, agent_id) catch {
            return runtimeDispatchFailure(allocator, .execution_failed, "failed to serialize agents create result");
        };
        defer allocator.free(escaped_agent);
        const project_json = if (desired_project_id) |project_id| blk: {
            const escaped_project = unified.jsonEscape(allocator, project_id) catch {
                return runtimeDispatchFailure(allocator, .execution_failed, "failed to serialize project id");
            };
            defer allocator.free(escaped_project);
            break :blk std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_project}) catch {
                return runtimeDispatchFailure(allocator, .execution_failed, "failed to serialize project id");
            };
        } else allocator.dupe(u8, "null") catch {
            return runtimeDispatchFailure(allocator, .execution_failed, "out of memory");
        };
        defer allocator.free(project_json);

        const op_json = std.fmt.allocPrint(
            allocator,
            "{{\"agent_id\":\"{s}\",\"created\":{},\"project_id\":{s},\"activated\":{}}}",
            .{ escaped_agent, created, project_json, activated },
        ) catch {
            return runtimeDispatchFailure(allocator, .execution_failed, "failed to build agents create result");
        };
        defer allocator.free(op_json);

        return runtimeDispatchFileWriteSuccess(allocator, path, content.len, op_json);
    }

    fn handleAgentsControlWrite(
        self: *RuntimeToolDispatchProxy,
        allocator: std.mem.Allocator,
        path: []const u8,
        content: []const u8,
    ) tool_registry.ToolExecutionResult {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch {
            return runtimeDispatchFailure(allocator, .invalid_params, "agents payload must be a JSON object");
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "agents payload must be a JSON object");
        }
        const obj = parsed.value.object;

        const op = if (pathMatchesAnyControlTarget(path, &.{"global/agents/control/list.json"}))
            AgentsOp.list
        else if (pathMatchesAnyControlTarget(path, &.{"global/agents/control/create.json"}))
            AgentsOp.create
        else if (pathMatchesAnyControlTarget(path, &.{"global/agents/control/invoke.json"}))
            self.parseAgentsInvokeOp(obj) orelse
                return runtimeDispatchFailure(allocator, .invalid_params, "agents invoke payload requires op=list|create")
        else
            return runtimeDispatchFailure(allocator, .invalid_params, "unsupported agents control path");

        const args_value = if (obj.get("arguments")) |args| args else if (obj.get("args")) |args| args else parsed.value;
        if (args_value != .object) {
            return runtimeDispatchFailure(allocator, .invalid_params, "agents arguments must be a JSON object");
        }
        switch (op) {
            .create => {
                if (pathMatchesAnyControlTarget(path, &.{"global/agents/control/create.json"})) {
                    return self.handleAgentsCreateWrite(allocator, path, content);
                }
                const create_payload = stringifyJsonValueAlloc(allocator, args_value) catch {
                    return runtimeDispatchFailure(allocator, .execution_failed, "failed to serialize agents create payload");
                };
                defer allocator.free(create_payload);
                return self.handleAgentsCreateWrite(allocator, path, create_payload);
            },
            .list => {
                const list_payload = self.buildAgentsListJson(allocator) catch |err| {
                    return runtimeDispatchFailure(allocator, runtimeDispatchErrorCode(err), @errorName(err));
                };
                defer allocator.free(list_payload);
                return runtimeDispatchFileWriteSuccess(allocator, path, content.len, list_payload);
            },
        }
    }

    fn parseAgentsInvokeOp(self: *RuntimeToolDispatchProxy, obj: std.json.ObjectMap) ?AgentsOp {
        _ = self;
        const raw = optionalStringField(obj, "op") orelse
            optionalStringField(obj, "operation") orelse
            optionalStringField(obj, "tool") orelse
            optionalStringField(obj, "tool_name") orelse
            return null;
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "agents_list")) return .list;
        if (std.mem.eql(u8, value, "create") or std.mem.eql(u8, value, "agents_create")) return .create;
        return null;
    }

    fn buildAgentsListJson(self: *RuntimeToolDispatchProxy, allocator: std.mem.Allocator) ![]u8 {
        var registry = agent_registry_mod.AgentRegistry.init(
            self.allocator,
            ".",
            self.agents_dir,
            self.assets_dir,
        );
        defer registry.deinit();
        try registry.scan();

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "{\"agents\":[");
        var first = true;
        for (registry.listAgents()) |agent| {
            if (!first) try out.append(allocator, ',');
            first = false;
            try appendAgentInfoJson(allocator, &out, agent);
        }
        try out.appendSlice(allocator, "]}");
        return out.toOwnedSlice(allocator);
    }
};

fn isProjectsControlPath(path: []const u8) bool {
    return pathMatchesAnyControlTarget(path, &.{
        "global/projects/control/invoke.json",
        "global/projects/control/list.json",
        "global/projects/control/get.json",
        "global/projects/control/up.json",
    });
}

fn isAgentsControlPath(path: []const u8) bool {
    return pathMatchesAnyControlTarget(path, &.{
        "global/agents/control/invoke.json",
        "global/agents/control/list.json",
        "global/agents/control/create.json",
    });
}

fn pathMatchesAnyControlTarget(path: []const u8, targets: []const []const u8) bool {
    for (targets) |target| {
        if (pathMatchesControlTarget(path, target)) return true;
    }
    return false;
}

fn runtimeDispatchErrorCode(err: anyerror) tool_registry.ToolErrorCode {
    return switch (err) {
        error.InvalidPayload,
        error.MissingField,
        error.InvalidAgentId,
        => .invalid_params,
        error.AccessDenied,
        error.ProjectAuthFailed,
        error.ProjectAssignmentForbidden,
        error.ProjectPolicyForbidden,
        error.ProjectProtected,
        => .permission_denied,
        else => .execution_failed,
    };
}

fn runtimeDispatchFailure(
    allocator: std.mem.Allocator,
    code: tool_registry.ToolErrorCode,
    message: []const u8,
) tool_registry.ToolExecutionResult {
    return .{
        .failure = .{
            .code = code,
            .message = allocator.dupe(u8, message) catch blk: {
                break :blk allocator.dupe(u8, "out of memory") catch @panic("out of memory");
            },
        },
    };
}

fn runtimeDispatchFileWriteSuccess(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes_written: usize,
    operation_result_json: []const u8,
) tool_registry.ToolExecutionResult {
    const escaped_path = unified.jsonEscape(allocator, path) catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "failed to encode file_write path");
    };
    defer allocator.free(escaped_path);

    const payload = std.fmt.allocPrint(
        allocator,
        "{{\"path\":\"{s}\",\"bytes_written\":{d},\"append\":false,\"ready\":true,\"wait_until_ready\":true,\"operation_result\":{s}}}",
        .{ escaped_path, bytes_written, operation_result_json },
    ) catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "failed to build file_write payload");
    };
    return .{ .success = .{ .payload_json = payload } };
}

fn runtimeDispatchFileReadSuccess(
    allocator: std.mem.Allocator,
    path: []const u8,
    content: []const u8,
) tool_registry.ToolExecutionResult {
    const escaped_path = unified.jsonEscape(allocator, path) catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "failed to encode file_read path");
    };
    defer allocator.free(escaped_path);
    const escaped_content = unified.jsonEscape(allocator, content) catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "failed to encode file_read content");
    };
    defer allocator.free(escaped_content);

    const payload = std.fmt.allocPrint(
        allocator,
        "{{\"path\":\"{s}\",\"bytes\":{d},\"truncated\":false,\"content\":\"{s}\",\"ready\":true,\"wait_until_ready\":true}}",
        .{ escaped_path, content.len, escaped_content },
    ) catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "failed to build file_read payload");
    };
    return .{ .success = .{ .payload_json = payload } };
}

fn runtimeDispatchFileListSuccess(
    allocator: std.mem.Allocator,
    path: []const u8,
    entries: []const RuntimeToolDispatchProxy.RuntimeFileListEntry,
) tool_registry.ToolExecutionResult {
    var payload = std.ArrayListUnmanaged(u8){};
    errdefer payload.deinit(allocator);

    const escaped_path = unified.jsonEscape(allocator, path) catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "failed to encode file_list path");
    };
    defer allocator.free(escaped_path);
    payload.writer(allocator).print("{{\"path\":\"{s}\",\"entries\":[", .{escaped_path}) catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "out of memory");
    };
    for (entries, 0..) |entry, idx| {
        if (idx != 0) payload.append(allocator, ',') catch {
            return runtimeDispatchFailure(allocator, .execution_failed, "out of memory");
        };
        const escaped_name = unified.jsonEscape(allocator, entry.name) catch {
            return runtimeDispatchFailure(allocator, .execution_failed, "out of memory");
        };
        defer allocator.free(escaped_name);
        const escaped_kind = unified.jsonEscape(allocator, entry.kind) catch {
            return runtimeDispatchFailure(allocator, .execution_failed, "out of memory");
        };
        defer allocator.free(escaped_kind);
        payload.writer(allocator).print("{{\"name\":\"{s}\",\"type\":\"{s}\"}}", .{ escaped_name, escaped_kind }) catch {
            return runtimeDispatchFailure(allocator, .execution_failed, "out of memory");
        };
    }
    payload.appendSlice(allocator, "],\"truncated\":false}") catch {
        return runtimeDispatchFailure(allocator, .execution_failed, "out of memory");
    };
    return .{ .success = .{ .payload_json = payload.toOwnedSlice(allocator) catch return runtimeDispatchFailure(allocator, .execution_failed, "out of memory") } };
}

fn stringifyJsonValueAlloc(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

fn runtimeDispatchSyntheticReadContent(path: []const u8) ?[]const u8 {
    if (pathMatchesAnyControlTarget(path, &.{"global/services/SERVICES.json"})) {
        return runtimeDispatchServicesIndexJson();
    }

    if (pathMatchesAnyControlTarget(path, &.{"global/projects/README.md"})) {
        return "# Projects Management\n\nList, inspect, and create/update projects through Acheron control files.\n";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/SCHEMA.json"})) {
        return "{\"kind\":\"service\",\"service_id\":\"projects\",\"shape\":\"/global/projects/{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/CAPS.json"})) {
        return "{\"invoke\":true,\"operations\":[\"projects_list\",\"projects_get\",\"projects_up\"],\"discoverable\":true}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/OPS.json"})) {
        return "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"get\":\"control/get.json\",\"up\":\"control/up.json\"},\"operations\":{\"list\":\"projects_list\",\"get\":\"projects_get\",\"up\":\"projects_up\"}}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/PERMISSIONS.json"})) {
        return "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"project_control_plane\"}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/STATUS.json"})) {
        return "{\"service_id\":\"projects\",\"state\":\"namespace\",\"has_invoke\":true}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/status.json"})) {
        return "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/result.json"})) {
        return "{\"projects\":[]}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/projects/control/README.md"})) {
        return "Use list/get/up operation files, or invoke.json with op=list|get|up plus arguments. For Mother bootstrap provisioning, use up with activate=false.\n";
    }

    if (pathMatchesAnyControlTarget(path, &.{"global/agents/README.md"})) {
        return "# Agents Management\n\nList and create agent workspaces through Acheron control files.\n";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/SCHEMA.json"})) {
        return "{\"kind\":\"service\",\"service_id\":\"agents\",\"shape\":\"/global/agents/{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/CAPS.json"})) {
        return "{\"invoke\":true,\"operations\":[\"agents_list\",\"agents_create\"],\"discoverable\":true,\"create_allowed\":true}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/OPS.json"})) {
        return "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"create\":\"control/create.json\"},\"operations\":{\"list\":\"agents_list\",\"create\":\"agents_create\"}}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/PERMISSIONS.json"})) {
        return "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\",\"project_token_required\":false}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/STATUS.json"})) {
        return "{\"service_id\":\"agents\",\"state\":\"namespace\",\"has_invoke\":true}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/status.json"})) {
        return "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/result.json"})) {
        return "{\"agents\":[]}";
    }
    if (pathMatchesAnyControlTarget(path, &.{"global/agents/control/README.md"})) {
        return "Use list/create operation files, or invoke.json with op=list|create plus arguments. Create requires agent provisioning capability.\n";
    }

    return null;
}

fn runtimeDispatchServicesIndexJson() []const u8 {
    return "[{\"node_id\":\"global\",\"service_id\":\"services\",\"service_path\":\"/global/services\",\"invoke_path\":null,\"has_invoke\":false,\"scope\":\"project_namespace\"},{\"node_id\":\"global\",\"service_id\":\"chat\",\"service_path\":\"/global/chat\",\"invoke_path\":null,\"has_invoke\":false,\"scope\":\"project_namespace\"},{\"node_id\":\"global\",\"service_id\":\"jobs\",\"service_path\":\"/global/jobs\",\"invoke_path\":null,\"has_invoke\":false,\"scope\":\"project_namespace\"},{\"node_id\":\"global\",\"service_id\":\"projects\",\"service_path\":\"/global/projects\",\"invoke_path\":\"/global/projects/control/invoke.json\",\"has_invoke\":true,\"scope\":\"project_namespace\"},{\"node_id\":\"global\",\"service_id\":\"agents\",\"service_path\":\"/global/agents\",\"invoke_path\":\"/global/agents/control/invoke.json\",\"has_invoke\":true,\"scope\":\"project_namespace\"},{\"node_id\":\"global\",\"service_id\":\"library\",\"service_path\":\"/global/library\",\"invoke_path\":null,\"has_invoke\":false,\"scope\":\"global_namespace\"}]";
}

fn buildProjectScopedPayload(allocator: std.mem.Allocator, project_id: []const u8, project_token: ?[]const u8) ![]u8 {
    const escaped_project = try unified.jsonEscape(allocator, project_id);
    defer allocator.free(escaped_project);
    if (project_token) |token| {
        const escaped_token = try unified.jsonEscape(allocator, token);
        defer allocator.free(escaped_token);
        return std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
            .{ escaped_project, escaped_token },
        );
    }
    return std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\"}}",
        .{escaped_project},
    );
}

const AgentRuntimeRegistry = struct {
    allocator: std.mem.Allocator,
    runtime_config: Config.RuntimeConfig,
    provider_config: ?Config.ProviderConfig,
    default_agent_id: []const u8,
    max_runtimes: usize,
    debug_stream_sink: DebugStreamFileSink,
    control_plane: fs_control_plane.ControlPlane,
    job_index: chat_job_index.ChatJobIndex,
    auth_tokens: AuthTokenStore,
    control_operator_token: ?[]u8 = null,
    control_project_scope_token: ?[]u8 = null,
    control_node_scope_token: ?[]u8 = null,
    local_fs_node: ?*LocalFsNode = null,
    node_tunnels: NodeTunnelRegistry,
    workspace_url: ?[]u8 = null,
    mutex: std.Thread.Mutex = .{},
    by_agent: std.StringHashMapUnmanaged(AgentRuntimeEntry) = .{},
    creating_runtime_keys: std.StringHashMapUnmanaged(void) = .{},
    runtime_create_cond: std.Thread.Condition = .{},
    runtime_warmups_mutex: std.Thread.Mutex = .{},
    runtime_warmups: std.StringHashMapUnmanaged(RuntimeWarmupState) = .{},
    runtime_warmup_lifecycle_mutex: std.Thread.Mutex = .{},
    runtime_warmup_lifecycle_cond: std.Thread.Condition = .{},
    runtime_warmup_inflight: usize = 0,
    runtime_warmup_stopping: bool = false,
    node_service_event_history_mutex: std.Thread.Mutex = .{},
    node_service_event_history: std.ArrayListUnmanaged(NodeServiceEventRecord) = .{},
    node_service_event_history_max: usize = node_service_event_history_max_default,
    node_service_event_log_path: ?[]u8 = null,
    node_service_event_log_rotate_max_bytes: u64 = 4 * 1024 * 1024,
    node_service_event_log_archive_keep: usize = 8,
    node_service_event_log_gzip_available: bool = false,
    service_presence_worker_thread: ?std.Thread = null,
    service_presence_worker_stop: bool = false,
    service_presence_worker_mutex: std.Thread.Mutex = .{},
    service_presence_worker_cond: std.Thread.Condition = .{},
    service_presence_jobs: std.ArrayListUnmanaged(ServicePresenceDispatchJob) = .{},
    audit_records_mutex: std.Thread.Mutex = .{},
    audit_records: std.ArrayListUnmanaged(AuditRecord) = .{},
    next_audit_record_id: u64 = 1,
    reconcile_worker_thread: ?std.Thread = null,
    reconcile_worker_stop: bool = false,
    reconcile_worker_mutex: std.Thread.Mutex = .{},
    reconcile_worker_interval_ms: u64 = 250,
    runtime_residency_worker_thread: ?std.Thread = null,
    runtime_residency_worker_stop: bool = false,
    runtime_residency_worker_mutex: std.Thread.Mutex = .{},
    runtime_residency_worker_interval_ms: u64 = runtime_residency_worker_interval_ms_default,

    fn init(
        allocator: std.mem.Allocator,
        runtime_config: Config.RuntimeConfig,
        provider_config: ?Config.ProviderConfig,
    ) AgentRuntimeRegistry {
        return initWithLimits(allocator, runtime_config, provider_config, default_max_agent_runtimes);
    }

    fn initWithLimits(
        allocator: std.mem.Allocator,
        runtime_config: Config.RuntimeConfig,
        provider_config: ?Config.ProviderConfig,
        max_runtimes: usize,
    ) AgentRuntimeRegistry {
        const configured_default = std.mem.trim(u8, runtime_config.default_agent_id, " \t\r\n");
        if (configured_default.len > 0 and !isValidAgentId(configured_default)) {
            std.log.warn(
                "Invalid default_agent_id '{s}', falling back to '{s}'",
                .{ configured_default, system_agent_id },
            );
        } else if (configured_default.len > 0 and !std.mem.eql(u8, configured_default, system_agent_id)) {
            std.log.warn(
                "Ignoring configured default_agent_id '{s}'; system agent '{s}' is reserved as the only default route",
                .{ configured_default, system_agent_id },
            );
        }
        const effective_default = system_agent_id;
        const debug_stream_sink = DebugStreamFileSink.init(allocator, runtime_config);
        const operator_token = parseOptionalEnvOwned(allocator, control_operator_token_env);
        const project_scope_token = parseOptionalEnvOwned(allocator, control_project_scope_token_env);
        const node_scope_token = parseOptionalEnvOwned(allocator, control_node_scope_token_env);
        if (operator_token != null) {
            std.log.info("control-plane operator token enabled via {s}", .{control_operator_token_env});
        }
        if (project_scope_token != null) {
            std.log.info("control-plane project-scope token enabled via {s}", .{control_project_scope_token_env});
        }
        if (node_scope_token != null) {
            std.log.info("control-plane node-scope token enabled via {s}", .{control_node_scope_token_env});
        }
        const history_max_raw = parseUnsignedEnv(
            allocator,
            node_service_event_history_max_env,
            @as(u64, node_service_event_history_max_default),
        );
        const history_max: usize = @intCast(@max(@as(u64, 64), @min(history_max_raw, 20_000)));
        const event_rotate_max_bytes = parseUnsignedEnv(
            allocator,
            node_service_event_log_rotate_max_bytes_env,
            8 * 1024 * 1024,
        );
        const event_archive_keep_raw = parseUnsignedEnv(
            allocator,
            node_service_event_log_archive_keep_env,
            8,
        );
        const event_archive_keep: usize = @intCast(@min(event_archive_keep_raw, 64));
        const event_log_path = initNodeServiceEventLogPath(allocator, runtime_config.ltm_directory) catch |err| blk: {
            std.log.warn("node service event persistence disabled: {s}", .{@errorName(err)});
            break :blk null;
        };
        const event_log_gzip_available = if (event_log_path != null)
            commandExists(allocator, "gzip")
        else
            false;

        var effective_runtime_config = runtime_config;
        effective_runtime_config.default_agent_id = effective_default;

        var registry: AgentRuntimeRegistry = .{
            .allocator = allocator,
            .runtime_config = effective_runtime_config,
            .provider_config = provider_config,
            .default_agent_id = effective_default,
            .max_runtimes = if (max_runtimes == 0) 1 else max_runtimes,
            .debug_stream_sink = debug_stream_sink,
            .control_plane = fs_control_plane.ControlPlane.initWithPersistenceOptions(
                allocator,
                effective_runtime_config.ltm_directory,
                effective_runtime_config.ltm_filename,
                .{
                    .primary_agent_id = system_agent_id,
                    .spider_web_root = effective_runtime_config.spider_web_root,
                    .node_service_event_history_max = history_max,
                },
            ),
            .job_index = chat_job_index.ChatJobIndex.init(
                allocator,
                effective_runtime_config.ltm_directory,
            ),
            .auth_tokens = AuthTokenStore.init(allocator, effective_runtime_config),
            .control_operator_token = operator_token,
            .control_project_scope_token = project_scope_token,
            .control_node_scope_token = node_scope_token,
            .node_service_event_history_max = history_max,
            .node_service_event_log_path = event_log_path,
            .node_service_event_log_rotate_max_bytes = event_rotate_max_bytes,
            .node_service_event_log_archive_keep = event_archive_keep,
            .node_service_event_log_gzip_available = event_log_gzip_available,
            .node_tunnels = .{ .allocator = allocator },
        };
        registry.loadNodeServiceEventHistory() catch |err| {
            std.log.warn("failed to load node service event history: {s}", .{@errorName(err)});
        };
        return registry;
    }

    fn deinit(self: *AgentRuntimeRegistry) void {
        self.requestServicePresenceWorkerStop();
        if (self.service_presence_worker_thread) |thread| {
            thread.join();
            self.service_presence_worker_thread = null;
        }
        self.service_presence_worker_mutex.lock();
        for (self.service_presence_jobs.items) |*job| job.deinit(self.allocator);
        self.service_presence_jobs.deinit(self.allocator);
        self.service_presence_jobs = .{};
        self.service_presence_worker_mutex.unlock();

        self.requestRuntimeResidencyWorkerStop();
        if (self.runtime_residency_worker_thread) |thread| {
            thread.join();
            self.runtime_residency_worker_thread = null;
        }

        self.requestReconcileWorkerStop();
        if (self.reconcile_worker_thread) |thread| {
            thread.join();
            self.reconcile_worker_thread = null;
        }

        self.runtime_warmup_lifecycle_mutex.lock();
        self.runtime_warmup_stopping = true;
        while (self.runtime_warmup_inflight > 0) {
            self.runtime_warmup_lifecycle_cond.wait(&self.runtime_warmup_lifecycle_mutex);
        }
        self.runtime_warmup_lifecycle_mutex.unlock();

        self.mutex.lock();
        const local_fs_node_for_shutdown = self.local_fs_node;
        self.mutex.unlock();
        if (local_fs_node_for_shutdown) |local_fs_node| {
            local_fs_node.stopAndWaitForChatJobWorkers();
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.by_agent.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var runtime_entry = entry.value_ptr.*;
            runtime_entry.deinit(self.allocator);
        }
        self.by_agent.deinit(self.allocator);
        var creating_it = self.creating_runtime_keys.iterator();
        while (creating_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.creating_runtime_keys.deinit(self.allocator);
        self.creating_runtime_keys = .{};
        self.runtime_warmups_mutex.lock();
        var warmup_it = self.runtime_warmups.iterator();
        while (warmup_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var warmup = entry.value_ptr.*;
            warmup.deinit(self.allocator);
        }
        self.runtime_warmups.deinit(self.allocator);
        self.runtime_warmups = .{};
        self.runtime_warmups_mutex.unlock();
        if (self.local_fs_node) |local_fs_node| {
            local_fs_node.deinit(&self.control_plane);
            self.local_fs_node = null;
        }
        if (self.control_operator_token) |token| {
            self.allocator.free(token);
            self.control_operator_token = null;
        }
        if (self.control_project_scope_token) |token| {
            self.allocator.free(token);
            self.control_project_scope_token = null;
        }
        if (self.control_node_scope_token) |token| {
            self.allocator.free(token);
            self.control_node_scope_token = null;
        }
        if (self.workspace_url) |value| {
            self.allocator.free(value);
            self.workspace_url = null;
        }
        self.clearNodeServiceEventHistory();
        if (self.node_service_event_log_path) |path| {
            self.allocator.free(path);
            self.node_service_event_log_path = null;
        }
        self.node_tunnels.deinit();
        self.audit_records_mutex.lock();
        for (self.audit_records.items) |*record| record.deinit(self.allocator);
        self.audit_records.deinit(self.allocator);
        self.audit_records = .{};
        self.next_audit_record_id = 1;
        self.audit_records_mutex.unlock();
        self.job_index.deinit();
        self.control_plane.deinit();
        self.debug_stream_sink.deinit();
        self.auth_tokens.deinit();
    }

    fn authenticateConnection(self: *AgentRuntimeRegistry, authorization_header: ?[]const u8) ?ConnectionPrincipal {
        return self.auth_tokens.authenticate(authorization_header);
    }

    fn authStatusJson(self: *AgentRuntimeRegistry) ![]u8 {
        return self.auth_tokens.statusJson();
    }

    fn listAgentsPayloadWithRole(self: *AgentRuntimeRegistry, is_admin: bool) ![]u8 {
        _ = is_admin;
        var registry = agent_registry_mod.AgentRegistry.init(
            self.allocator,
            ".",
            self.runtime_config.agents_dir,
            self.runtime_config.assets_dir,
        );
        defer registry.deinit();
        try registry.scan();

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"agents\":[");
        var first = true;
        for (registry.listAgents()) |agent| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try appendAgentInfoJson(self.allocator, &out, agent);
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    fn getAgentPayloadWithRole(
        self: *AgentRuntimeRegistry,
        payload_json: ?[]const u8,
        is_admin: bool,
    ) ![]u8 {
        _ = is_admin;
        const agent_id = try parseAgentIdFromPayload(self.allocator, payload_json);
        defer self.allocator.free(agent_id);

        var registry = agent_registry_mod.AgentRegistry.init(
            self.allocator,
            ".",
            self.runtime_config.agents_dir,
            self.runtime_config.assets_dir,
        );
        defer registry.deinit();
        try registry.scan();

        const agent = registry.getAgent(agent_id) orelse return error.AgentNotFound;
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"agent\":");
        try appendAgentInfoJson(self.allocator, &out, agent.*);
        try out.append(self.allocator, '}');
        return out.toOwnedSlice(self.allocator);
    }

    fn getLocalFsNode(self: *AgentRuntimeRegistry) ?*LocalFsNode {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.local_fs_node;
    }

    fn copyLocalFsWorkspaceRoot(self: *AgentRuntimeRegistry, allocator: std.mem.Allocator) !?[]u8 {
        const local_node = self.getLocalFsNode() orelse return null;
        const roots = try local_node.service.copyExportRootPaths(allocator);
        if (roots.len == 0) {
            allocator.free(roots);
            return null;
        }

        const selected = roots[0];
        var idx: usize = 1;
        while (idx < roots.len) : (idx += 1) allocator.free(roots[idx]);
        allocator.free(roots);
        return @as(?[]u8, selected);
    }

    fn rotateAuthToken(self: *AgentRuntimeRegistry, role: ConnectionRole) ![]u8 {
        return self.auth_tokens.rotateRoleToken(role);
    }

    const ConnectGateError = struct {
        code: []const u8,
        message: []const u8,
    };

    const InitialSessionBinding = struct {
        binding: SessionBinding,
        connect_gate_error: ?ConnectGateError = null,
        bootstrap_only: bool = false,
    };

    const ProjectSetupSnapshot = struct {
        vision: ?[]u8 = null,
        mount_count: usize = 0,

        fn deinit(self: *ProjectSetupSnapshot, allocator: std.mem.Allocator) void {
            if (self.vision) |value| allocator.free(value);
            self.* = undefined;
        }
    };

    const ProjectSetupHint = struct {
        required: bool = false,
        message: ?[]u8 = null,
        project_id: ?[]u8 = null,
        project_vision: ?[]u8 = null,

        fn deinit(self: *ProjectSetupHint, allocator: std.mem.Allocator) void {
            if (self.message) |value| allocator.free(value);
            if (self.project_id) |value| allocator.free(value);
            if (self.project_vision) |value| allocator.free(value);
            self.* = undefined;
        }
    };

    fn projectSetupSnapshot(self: *AgentRuntimeRegistry, project_id: []const u8, is_admin: bool) !ProjectSetupSnapshot {
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const payload = try std.fmt.allocPrint(self.allocator, "{{\"project_id\":\"{s}\"}}", .{escaped_project});
        defer self.allocator.free(payload);
        const project_json = try self.control_plane.getProjectWithRole(payload, is_admin);
        defer self.allocator.free(project_json);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, project_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidResponse;

        const vision_owned = if (parsed.value.object.get("vision")) |vision_val| blk: {
            if (vision_val != .string) break :blk null;
            if (vision_val.string.len == 0) break :blk null;
            break :blk try self.allocator.dupe(u8, vision_val.string);
        } else null;

        var mount_count: usize = 0;
        if (parsed.value.object.get("mounts")) |mounts_val| {
            if (mounts_val == .array) mount_count = mounts_val.array.items.len;
        }

        return .{
            .vision = vision_owned,
            .mount_count = mount_count,
        };
    }

    fn projectSetupHint(
        self: *AgentRuntimeRegistry,
        role: ConnectionRole,
        active_binding: SessionBinding,
        bootstrap_only: bool,
    ) !ProjectSetupHint {
        var hint = ProjectSetupHint{};
        errdefer hint.deinit(self.allocator);

        if (active_binding.project_id) |project_id| {
            hint.project_id = try self.allocator.dupe(u8, project_id);
        } else {
            return hint;
        }

        if (bootstrap_only and role == .admin) {
            hint.required = true;
            hint.message = try self.allocator.dupe(
                u8,
                "Project setup required: ask Mother for the first project name, vision, and first non-system agent.",
            );
            return hint;
        }

        const project_id = hint.project_id.?;
        if (std.mem.eql(u8, project_id, system_project_id)) return hint;

        var snapshot = self.projectSetupSnapshot(project_id, role == .admin) catch |err| {
            std.log.warn("failed to compute project setup snapshot for {s}: {s}", .{ project_id, @errorName(err) });
            return hint;
        };
        defer snapshot.deinit(self.allocator);

        if (snapshot.vision) |vision| {
            hint.project_vision = try self.allocator.dupe(u8, vision);
        }

        const vision_text = snapshot.vision orelse "";
        const vision_missing = std.mem.trim(u8, vision_text, " \t\r\n").len == 0;
        const mounts_missing = snapshot.mount_count == 0;
        const first_agent = self.firstAgentForProject(role, project_id);
        defer if (first_agent) |agent_id| self.allocator.free(agent_id);
        const agent_missing = first_agent == null;
        hint.required = vision_missing or mounts_missing or agent_missing;

        if (hint.required) {
            hint.message = if (agent_missing)
                try std.fmt.allocPrint(
                    self.allocator,
                    "Project setup required for {s}: attach a non-system agent, then ask Mother to confirm setup details.",
                    .{project_id},
                )
            else if (mounts_missing)
                try std.fmt.allocPrint(
                    self.allocator,
                    "Project setup required for {s}: no workspace mounts are configured yet.",
                    .{project_id},
                )
            else
                try std.fmt.allocPrint(
                    self.allocator,
                    "Project setup required for {s}: project vision is missing.",
                    .{project_id},
                );
        }

        return hint;
    }

    fn dispatchRuntimeAgentControlForTarget(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        project_id: ?[]const u8,
        action: []const u8,
        content_json: []const u8,
    ) !void {
        const runtime = self.getRuntimeForBindingIfReady(agent_id, project_id) orelse
            return error.RuntimeUnavailable;
        defer runtime.release();

        const escaped_content = try unified.jsonEscape(self.allocator, content_json);
        defer self.allocator.free(escaped_content);
        const request_id = try std.fmt.allocPrint(self.allocator, "runtime-control-{d}", .{std.time.nanoTimestamp()});
        defer self.allocator.free(request_id);
        const request_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":\"{s}\",\"type\":\"agent.control\",\"action\":\"{s}\",\"content\":\"{s}\"}}",
            .{ request_id, action, escaped_content },
        );
        defer self.allocator.free(request_json);

        const responses = try runtime.handleMessageFramesWithDebug(request_json, false);
        defer {
            for (responses) |frame| self.allocator.free(frame);
            self.allocator.free(responses);
        }
        if (responses.len == 0) return error.MissingJobResponse;
        if (std.mem.indexOf(u8, responses[0], "\"type\":\"error\"") != null) {
            std.log.warn(
                "runtime agent.control rejected: action={s} agent={s} project={s} response={s}",
                .{
                    action,
                    agent_id,
                    project_id orelse "null",
                    responses[0],
                },
            );
            return error.RuntimeControlRejected;
        }
    }

    fn dispatchRuntimeAgentControl(
        self: *AgentRuntimeRegistry,
        binding: SessionBinding,
        action: []const u8,
        content_json: []const u8,
    ) !void {
        return self.dispatchRuntimeAgentControlForTarget(binding.agent_id, binding.project_id, action, content_json);
    }

    fn enqueueServicePresenceDispatch(
        self: *AgentRuntimeRegistry,
        binding: SessionBinding,
        session_key: []const u8,
        service_id: []const u8,
        attached: bool,
        payload_json: []u8,
    ) !void {
        errdefer self.allocator.free(payload_json);

        const owned_agent_id = try self.allocator.dupe(u8, binding.agent_id);
        errdefer self.allocator.free(owned_agent_id);
        const owned_project_id = if (binding.project_id) |value|
            try self.allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_project_id) |value| self.allocator.free(value);
        const owned_session_key = try self.allocator.dupe(u8, session_key);
        errdefer self.allocator.free(owned_session_key);
        const owned_service_id = try self.allocator.dupe(u8, service_id);
        errdefer self.allocator.free(owned_service_id);

        self.service_presence_worker_mutex.lock();
        defer self.service_presence_worker_mutex.unlock();

        if (self.service_presence_worker_stop) return error.ShuttingDown;

        for (self.service_presence_jobs.items) |*job| {
            if (job.matches(binding.agent_id, binding.project_id, session_key, service_id, attached)) {
                self.allocator.free(owned_service_id);
                self.allocator.free(owned_session_key);
                if (owned_project_id) |value| self.allocator.free(value);
                self.allocator.free(owned_agent_id);
                self.allocator.free(payload_json);
                return;
            }
        }

        if (self.service_presence_jobs.items.len >= service_presence_dispatch_queue_max) return error.QueueFull;

        try self.service_presence_jobs.append(self.allocator, .{
            .agent_id = owned_agent_id,
            .project_id = owned_project_id,
            .session_key = owned_session_key,
            .service_id = owned_service_id,
            .attached = attached,
            .payload_json = payload_json,
        });
        self.service_presence_worker_cond.signal();
    }

    fn getRuntimeForBindingIfReady(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        project_id: ?[]const u8,
    ) ?*runtime_handle_mod.RuntimeHandle {
        var selected_runtime: ?*runtime_handle_mod.RuntimeHandle = null;
        const runtime_key = runtimeMapKeyForProject(project_id);
        self.mutex.lock();
        if (self.by_agent.getPtr(runtime_key)) |existing| {
            if (std.mem.eql(u8, existing.runtime_agent_id, agent_id)) {
                if (existing.runtime.isHealthy()) {
                    selected_runtime = existing.runtime;
                    selected_runtime.?.retain();
                }
            }
        }
        self.mutex.unlock();
        if (selected_runtime == null) {
            _ = self.dropUnhealthyRuntimeForBinding(
                agent_id,
                project_id,
                "runtime_unhealthy",
                "project runtime became unhealthy",
            );
        }
        return selected_runtime;
    }

    fn dropUnhealthyRuntimeForBinding(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        project_id: ?[]const u8,
        error_code: []const u8,
        error_message: []const u8,
    ) bool {
        var removed_unhealthy: ?RemovedRuntimeEntry = null;
        const runtime_key = runtimeMapKeyForProject(project_id);
        const binding_key = self.runtimeBindingKey(agent_id, project_id) catch null;
        defer if (binding_key) |value| self.allocator.free(value);

        self.mutex.lock();
        if (self.by_agent.getPtr(runtime_key)) |existing| {
            if (std.mem.eql(u8, existing.runtime_agent_id, agent_id) and !existing.runtime.isHealthy()) {
                removed_unhealthy = self.takeUnhealthyRuntimeLocked(runtime_key);
            }
        }
        self.mutex.unlock();

        if (removed_unhealthy) |removed| {
            const health_summary = removed.entry.runtime.healthSummary(self.allocator) catch null;
            defer if (health_summary) |value| self.allocator.free(value);
            std.log.warn(
                "dropping unhealthy ready runtime binding: project={s} agent={s} detail={s}",
                .{
                    project_id orelse "__auto__",
                    removed.entry.runtime_agent_id,
                    health_summary orelse "unavailable",
                },
            );
            if (binding_key) |key| {
                self.markRuntimeWarmupError(key, error_code, error_message);
            }
            self.deinitRemovedRuntime(removed);
            return true;
        }

        return false;
    }

    fn publishServicePresenceForBinding(
        self: *AgentRuntimeRegistry,
        role: ConnectionRole,
        binding: SessionBinding,
        session_key: []const u8,
        service_id: []const u8,
        attached: bool,
    ) void {
        var setup_hint = ProjectSetupHint{};
        defer setup_hint.deinit(self.allocator);
        if (attached and binding.project_id != null) {
            const bootstrap_only = self.isBootstrapMotherOnlyState();
            setup_hint = self.projectSetupHint(role, binding, bootstrap_only) catch |err| blk: {
                std.log.warn("project setup hint presence sync failed for {s}: {s}", .{ binding.agent_id, @errorName(err) });
                break :blk ProjectSetupHint{};
            };
        }

        const escaped_service = unified.jsonEscape(self.allocator, service_id) catch return;
        defer self.allocator.free(escaped_service);
        const escaped_session = unified.jsonEscape(self.allocator, session_key) catch return;
        defer self.allocator.free(escaped_session);
        const escaped_role = unified.jsonEscape(self.allocator, connectionRoleName(role)) catch return;
        defer self.allocator.free(escaped_role);
        const escaped_actor_type = unified.jsonEscape(self.allocator, binding.actor_type) catch return;
        defer self.allocator.free(escaped_actor_type);
        const escaped_actor_id = unified.jsonEscape(self.allocator, binding.actor_id) catch return;
        defer self.allocator.free(escaped_actor_id);
        const project_json = if (binding.project_id) |project_id| blk: {
            const escaped_project = unified.jsonEscape(self.allocator, project_id) catch return;
            defer self.allocator.free(escaped_project);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_project}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(project_json);
        const project_setup_required = attached and setup_hint.required;
        const project_setup_project_id_json = if (attached and setup_hint.project_id != null) blk: {
            const escaped_project = unified.jsonEscape(self.allocator, setup_hint.project_id.?) catch return;
            defer self.allocator.free(escaped_project);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_project}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(project_setup_project_id_json);
        const project_setup_message_json = if (attached and setup_hint.message != null) blk: {
            const escaped_message = unified.jsonEscape(self.allocator, setup_hint.message.?) catch return;
            defer self.allocator.free(escaped_message);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_message}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(project_setup_message_json);
        const project_setup_vision_json = if (attached and setup_hint.project_vision != null) blk: {
            const escaped_vision = unified.jsonEscape(self.allocator, setup_hint.project_vision.?) catch return;
            defer self.allocator.free(escaped_vision);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_vision}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(project_setup_vision_json);
        const project_setup_source_json = if (attached) blk: {
            const escaped_source = unified.jsonEscape(self.allocator, "service.event") catch return;
            defer self.allocator.free(escaped_source);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_source}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(project_setup_source_json);

        const payload_json = std.fmt.allocPrint(
            self.allocator,
            "{{\"service_id\":\"{s}\",\"status\":\"{s}\",\"session_key\":\"{s}\",\"role\":\"{s}\",\"actor_type\":\"{s}\",\"actor_id\":\"{s}\",\"project_id\":{s},\"project_setup_required\":{},\"project_setup_project_id\":{s},\"project_setup_message\":{s},\"project_setup_project_vision\":{s},\"project_setup_source\":{s}}}",
            .{
                escaped_service,
                if (attached) "attached" else "detached",
                escaped_session,
                escaped_role,
                escaped_actor_type,
                escaped_actor_id,
                project_json,
                project_setup_required,
                project_setup_project_id_json,
                project_setup_message_json,
                project_setup_vision_json,
                project_setup_source_json,
            },
        ) catch return;
        self.enqueueServicePresenceDispatch(
            binding,
            session_key,
            service_id,
            attached,
            payload_json,
        ) catch |err| {
            std.log.warn(
                "service presence enqueue failed: agent={s} session={s} status={s} err={s}",
                .{
                    binding.agent_id,
                    session_key,
                    if (attached) "attached" else "detached",
                    @errorName(err),
                },
            );
        };
    }

    fn projectExistsWithRole(self: *AgentRuntimeRegistry, project_id: []const u8, is_admin: bool) bool {
        const escaped_project = unified.jsonEscape(self.allocator, project_id) catch return false;
        defer self.allocator.free(escaped_project);
        const payload = std.fmt.allocPrint(self.allocator, "{{\"project_id\":\"{s}\"}}", .{escaped_project}) catch return false;
        defer self.allocator.free(payload);
        const result = self.control_plane.getProjectWithRole(payload, is_admin) catch return false;
        self.allocator.free(result);
        return true;
    }

    fn hasNonSystemProject(self: *AgentRuntimeRegistry) bool {
        const payload = self.control_plane.listProjects() catch return false;
        defer self.allocator.free(payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        const projects = parsed.value.object.get("projects") orelse return false;
        if (projects != .array) return false;
        for (projects.array.items) |item| {
            if (item != .object) continue;
            const id_val = item.object.get("project_id") orelse continue;
            if (id_val != .string) continue;
            if (!std.mem.eql(u8, id_val.string, system_project_id)) return true;
        }
        return false;
    }

    fn hasNonSystemAgent(self: *AgentRuntimeRegistry) bool {
        var registry = agent_registry_mod.AgentRegistry.init(
            self.allocator,
            ".",
            self.runtime_config.agents_dir,
            self.runtime_config.assets_dir,
        );
        defer registry.deinit();
        registry.scan() catch return false;
        for (registry.listAgents()) |agent| {
            if (!std.mem.eql(u8, agent.id, system_agent_id)) return true;
        }
        return false;
    }

    fn isBootstrapMotherOnlyState(self: *AgentRuntimeRegistry) bool {
        return !self.hasNonSystemProject() or !self.hasNonSystemAgent();
    }

    fn agentExists(self: *AgentRuntimeRegistry, agent_id: []const u8) bool {
        var registry = agent_registry_mod.AgentRegistry.init(
            self.allocator,
            ".",
            self.runtime_config.agents_dir,
            self.runtime_config.assets_dir,
        );
        defer registry.deinit();
        registry.scan() catch return false;
        return registry.getAgent(agent_id) != null;
    }

    fn firstAgentForProject(self: *AgentRuntimeRegistry, role: ConnectionRole, project_id: []const u8) ?[]u8 {
        const include_primary = role == .admin and std.mem.eql(u8, project_id, system_project_id);
        return self.control_plane.firstProjectAgent(project_id, include_primary) catch null;
    }

    fn listNonSystemProjectIds(self: *AgentRuntimeRegistry) ![][]u8 {
        const payload = try self.control_plane.listProjects();
        defer self.allocator.free(payload);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return self.allocator.alloc([]u8, 0);
        const projects_val = parsed.value.object.get("projects") orelse return self.allocator.alloc([]u8, 0);
        if (projects_val != .array) return self.allocator.alloc([]u8, 0);

        var project_ids = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (project_ids.items) |project_id| self.allocator.free(project_id);
            project_ids.deinit(self.allocator);
        }
        for (projects_val.array.items) |item| {
            if (item != .object) continue;
            const id_val = item.object.get("project_id") orelse continue;
            if (id_val != .string or id_val.string.len == 0) continue;
            if (std.mem.eql(u8, id_val.string, system_project_id)) continue;
            try project_ids.append(self.allocator, try self.allocator.dupe(u8, id_val.string));
        }
        std.mem.sort([]u8, project_ids.items, {}, struct {
            fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
                return std.mem.lessThan(u8, lhs, rhs);
            }
        }.lessThan);
        return project_ids.toOwnedSlice(self.allocator);
    }

    fn resolvePreferredBindingForRole(self: *AgentRuntimeRegistry, role: ConnectionRole) !?SessionBinding {
        const is_admin = role == .admin;
        if (try self.auth_tokens.rememberedTargetOwned(role)) |remembered| {
            defer {
                var owned = remembered;
                owned.deinit(self.allocator);
            }

            if (self.projectExistsWithRole(remembered.project_id, is_admin)) {
                var chosen_agent: ?[]u8 = null;
                if (self.agentExists(remembered.agent_id)) {
                    chosen_agent = try self.allocator.dupe(u8, remembered.agent_id);
                } else if (self.firstAgentForProject(role, remembered.project_id)) |fallback| {
                    chosen_agent = fallback;
                }

                if (chosen_agent) |agent_id| {
                    if (role == .user and (std.mem.eql(u8, remembered.project_id, system_project_id) or std.mem.eql(u8, agent_id, system_agent_id))) {
                        self.allocator.free(agent_id);
                    } else {
                        return .{
                            .agent_id = agent_id,
                            .actor_type = try self.allocator.dupe(u8, defaultActorTypeForRole(role)),
                            .actor_id = try self.allocator.dupe(u8, connectionRoleName(role)),
                            .project_id = try self.allocator.dupe(u8, remembered.project_id),
                            .project_token = null,
                        };
                    }
                }
            } else {
                self.auth_tokens.clearRememberedTarget(role) catch {};
            }
        }

        const project_ids = try self.listNonSystemProjectIds();
        defer {
            for (project_ids) |project_id| self.allocator.free(project_id);
            self.allocator.free(project_ids);
        }
        for (project_ids) |project_id| {
            if (self.firstAgentForProject(role, project_id)) |agent_id| {
                if (role == .user and std.mem.eql(u8, agent_id, system_agent_id)) {
                    self.allocator.free(agent_id);
                    continue;
                }
                return .{
                    .agent_id = agent_id,
                    .actor_type = try self.allocator.dupe(u8, defaultActorTypeForRole(role)),
                    .actor_id = try self.allocator.dupe(u8, connectionRoleName(role)),
                    .project_id = try self.allocator.dupe(u8, project_id),
                    .project_token = null,
                };
            }
        }

        return null;
    }

    fn buildInitialSessionBinding(self: *AgentRuntimeRegistry, role: ConnectionRole) !InitialSessionBinding {
        const bootstrap_only = self.isBootstrapMotherOnlyState();
        if (role == .admin) {
            return .{
                .binding = .{
                    .agent_id = try self.allocator.dupe(u8, system_agent_id),
                    .actor_type = try self.allocator.dupe(u8, defaultActorTypeForRole(role)),
                    .actor_id = try self.allocator.dupe(u8, connectionRoleName(role)),
                    .project_id = try self.allocator.dupe(u8, system_project_id),
                    .project_token = null,
                },
                .bootstrap_only = bootstrap_only,
            };
        }

        if (try self.resolvePreferredBindingForRole(role)) |binding| {
            return .{
                .binding = binding,
                .bootstrap_only = bootstrap_only,
            };
        }

        return .{
            .binding = .{
                .agent_id = try self.allocator.dupe(u8, system_agent_id),
                .actor_type = try self.allocator.dupe(u8, defaultActorTypeForRole(role)),
                .actor_id = try self.allocator.dupe(u8, connectionRoleName(role)),
                .project_id = try self.allocator.dupe(u8, system_project_id),
                .project_token = null,
            },
            .connect_gate_error = .{
                .code = if (bootstrap_only) "provisioning_required" else "project_context_required",
                .message = if (bootstrap_only)
                    "no non-system project/agent is available; an admin should use Mother to provision one"
                else
                    "project selection is required; call control.session_attach with project_id",
            },
            .bootstrap_only = bootstrap_only,
        };
    }

    fn rememberPrincipalSession(
        self: *AgentRuntimeRegistry,
        principal: ConnectionPrincipal,
        session_key: []const u8,
        agent_id: []const u8,
        project_id: ?[]const u8,
    ) void {
        const concrete_project = project_id orelse return;
        if (std.mem.eql(u8, concrete_project, system_project_id)) return;
        self.auth_tokens.recordSessionActivity(
            principal.role,
            session_key,
            agent_id,
            concrete_project,
            0,
        ) catch |err| {
            std.log.warn("failed to persist session history for {s}: {s}", .{ connectionRoleName(principal.role), @errorName(err) });
        };
        self.auth_tokens.setRememberedTarget(principal.role, agent_id, concrete_project) catch |err| {
            std.log.warn("failed to persist remembered target for {s}: {s}", .{ connectionRoleName(principal.role), @errorName(err) });
        };
    }

    fn startReconcileWorker(self: *AgentRuntimeRegistry) !void {
        self.reconcile_worker_mutex.lock();
        self.reconcile_worker_stop = false;
        self.reconcile_worker_mutex.unlock();
        self.reconcile_worker_thread = try std.Thread.spawn(
            .{},
            reconcileWorkerMain,
            .{self},
        );
    }

    fn startServicePresenceWorker(self: *AgentRuntimeRegistry) !void {
        self.service_presence_worker_mutex.lock();
        self.service_presence_worker_stop = false;
        self.service_presence_worker_mutex.unlock();
        self.service_presence_worker_thread = try std.Thread.spawn(
            .{},
            servicePresenceWorkerMain,
            .{self},
        );
    }

    fn startRuntimeResidencyWorker(self: *AgentRuntimeRegistry) !void {
        self.runtime_residency_worker_mutex.lock();
        self.runtime_residency_worker_stop = false;
        self.runtime_residency_worker_mutex.unlock();
        self.runtime_residency_worker_thread = try std.Thread.spawn(
            .{},
            runtimeResidencyWorkerMain,
            .{self},
        );
    }

    fn requestReconcileWorkerStop(self: *AgentRuntimeRegistry) void {
        self.reconcile_worker_mutex.lock();
        self.reconcile_worker_stop = true;
        self.reconcile_worker_mutex.unlock();
    }

    fn requestServicePresenceWorkerStop(self: *AgentRuntimeRegistry) void {
        self.service_presence_worker_mutex.lock();
        self.service_presence_worker_stop = true;
        self.service_presence_worker_cond.broadcast();
        self.service_presence_worker_mutex.unlock();
    }

    fn shouldStopReconcileWorker(self: *AgentRuntimeRegistry) bool {
        self.reconcile_worker_mutex.lock();
        defer self.reconcile_worker_mutex.unlock();
        return self.reconcile_worker_stop;
    }

    fn requestRuntimeResidencyWorkerStop(self: *AgentRuntimeRegistry) void {
        self.runtime_residency_worker_mutex.lock();
        self.runtime_residency_worker_stop = true;
        self.runtime_residency_worker_mutex.unlock();
    }

    fn shouldStopRuntimeResidencyWorker(self: *AgentRuntimeRegistry) bool {
        self.runtime_residency_worker_mutex.lock();
        defer self.runtime_residency_worker_mutex.unlock();
        return self.runtime_residency_worker_stop;
    }

    fn ensureActiveRuntimeResidency(self: *AgentRuntimeRegistry, retry_on_error: bool) !void {
        const bindings = try self.control_plane.snapshotActiveProjectBindings(self.allocator, true);
        defer {
            for (bindings) |*binding| binding.deinit(self.allocator);
            self.allocator.free(bindings);
        }

        for (bindings) |binding| {
            if (!self.control_plane.projectHasMounts(binding.project_id)) continue;
            if (std.mem.eql(u8, binding.agent_id, system_agent_id) and
                !std.mem.eql(u8, binding.project_id, system_project_id))
            {
                continue;
            }
            if (self.hasHealthyRuntimeForProject(binding.project_id) and
                !self.hasRuntimeForBinding(binding.agent_id, binding.project_id))
            {
                continue;
            }
            var attach_state = self.ensureRuntimeWarmup(
                binding.agent_id,
                binding.project_id,
                null,
                retry_on_error,
            ) catch |err| {
                std.log.warn(
                    "active runtime residency warmup failed: agent={s} project={s} err={s}",
                    .{ binding.agent_id, binding.project_id, @errorName(err) },
                );
                continue;
            };
            attach_state.deinit(self.allocator);
        }
    }

    const RemovedRuntimeEntry = struct {
        key: []const u8,
        entry: AgentRuntimeEntry,
    };

    fn runtimeMapKeyForProject(project_id: ?[]const u8) []const u8 {
        return project_id orelse "__auto__";
    }

    fn takeUnhealthyRuntimeLocked(self: *AgentRuntimeRegistry, runtime_key: []const u8) ?RemovedRuntimeEntry {
        const existing = self.by_agent.getPtr(runtime_key) orelse return null;
        if (existing.runtime.isHealthy()) return null;
        const removed = self.by_agent.fetchRemove(runtime_key) orelse return null;
        return .{
            .key = removed.key,
            .entry = removed.value,
        };
    }

    fn takeRuntimeLocked(self: *AgentRuntimeRegistry, runtime_key: []const u8) ?RemovedRuntimeEntry {
        const removed = self.by_agent.fetchRemove(runtime_key) orelse return null;
        return .{
            .key = removed.key,
            .entry = removed.value,
        };
    }

    fn deinitRemovedRuntime(self: *AgentRuntimeRegistry, removed: RemovedRuntimeEntry) void {
        self.allocator.free(removed.key);
        var entry = removed.entry;
        entry.deinit(self.allocator);
    }

    fn getOrCreate(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        requested_project_id: ?[]const u8,
        requested_project_token: ?[]const u8,
    ) !*runtime_handle_mod.RuntimeHandle {
        if (!isValidAgentId(agent_id)) return error.InvalidAgentId;
        const resolved_project_id = try self.resolveProjectId(agent_id, requested_project_id);
        defer self.allocator.free(resolved_project_id);
        const runtime_key = runtimeMapKeyForProject(resolved_project_id);

        var creation_claimed = false;
        while (!creation_claimed) {
            var removed_unhealthy: ?RemovedRuntimeEntry = null;
            var removed_mismatched: ?RemovedRuntimeEntry = null;
            var selected_runtime: ?*runtime_handle_mod.RuntimeHandle = null;
            var should_wait = false;

            self.mutex.lock();
            removed_unhealthy = self.takeUnhealthyRuntimeLocked(runtime_key);
            if (removed_unhealthy == null) {
                if (self.by_agent.getPtr(runtime_key)) |existing| {
                    if (std.mem.eql(u8, existing.runtime_agent_id, agent_id)) {
                        selected_runtime = existing.runtime;
                        selected_runtime.?.retain();
                    } else {
                        removed_mismatched = self.takeRuntimeLocked(runtime_key);
                    }
                }
            }
            if (selected_runtime == null) {
                if (self.creating_runtime_keys.contains(runtime_key)) {
                    should_wait = true;
                } else if (self.by_agent.count() >= self.max_runtimes) {
                    self.mutex.unlock();
                    if (removed_unhealthy) |removed| {
                        std.log.warn(
                            "replacing unhealthy project runtime: project={s} agent={s}",
                            .{ resolved_project_id, removed.entry.runtime_agent_id },
                        );
                        self.deinitRemovedRuntime(removed);
                    }
                    if (removed_mismatched) |removed| {
                        std.log.info(
                            "switching project runtime persona: project={s} from={s} to={s}",
                            .{ resolved_project_id, removed.entry.runtime_agent_id, agent_id },
                        );
                        self.deinitRemovedRuntime(removed);
                    }
                    return error.RuntimeLimitReached;
                } else {
                    const owned_runtime_key = try self.allocator.dupe(u8, runtime_key);
                    errdefer self.allocator.free(owned_runtime_key);
                    try self.creating_runtime_keys.put(self.allocator, owned_runtime_key, {});
                    creation_claimed = true;
                }
            }
            self.mutex.unlock();

            if (removed_unhealthy) |removed| {
                std.log.warn(
                    "replacing unhealthy project runtime: project={s} agent={s}",
                    .{ resolved_project_id, removed.entry.runtime_agent_id },
                );
                self.deinitRemovedRuntime(removed);
            }

            if (removed_mismatched) |removed| {
                std.log.info(
                    "switching project runtime persona: project={s} from={s} to={s}",
                    .{ resolved_project_id, removed.entry.runtime_agent_id, agent_id },
                );
                self.deinitRemovedRuntime(removed);
            }

            if (selected_runtime) |runtime| return runtime;
            if (!should_wait) break;

            self.mutex.lock();
            while (self.creating_runtime_keys.contains(runtime_key)) {
                self.runtime_create_cond.wait(&self.mutex);
            }
            self.mutex.unlock();
        }

        defer {
            self.mutex.lock();
            if (self.creating_runtime_keys.fetchRemove(runtime_key)) |removed| {
                self.allocator.free(removed.key);
            }
            self.runtime_create_cond.broadcast();
            self.mutex.unlock();
        }

        const entry = try self.createRuntimeEntry(
            agent_id,
            resolved_project_id,
            requested_project_token,
        );
        var entry_installed = false;
        errdefer if (!entry_installed) {
            var cleanup = entry;
            cleanup.deinit(self.allocator);
        };

        self.mutex.lock();
        var cleanup_after_unlock: ?AgentRuntimeEntry = null;
        var removed_conflict: ?RemovedRuntimeEntry = null;
        defer {
            self.mutex.unlock();
            if (cleanup_after_unlock) |*cleanup| {
                cleanup.deinit(self.allocator);
            }
            if (removed_conflict) |removed| {
                self.deinitRemovedRuntime(removed);
            }
        }

        if (self.by_agent.getPtr(runtime_key)) |existing| {
            if (std.mem.eql(u8, existing.runtime_agent_id, agent_id)) {
                const runtime = existing.runtime;
                cleanup_after_unlock = entry;
                entry_installed = true;
                runtime.retain();
                return runtime;
            }
            removed_conflict = self.takeRuntimeLocked(runtime_key);
        }

        if (self.by_agent.count() >= self.max_runtimes) return error.RuntimeLimitReached;

        const owned_runtime_key = try self.allocator.dupe(u8, runtime_key);
        errdefer self.allocator.free(owned_runtime_key);

        try self.by_agent.put(self.allocator, owned_runtime_key, entry);
        entry_installed = true;
        const runtime = self.by_agent.getPtr(owned_runtime_key).?.runtime;
        runtime.retain();
        return runtime;
    }

    fn createRuntimeEntry(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        project_id: []const u8,
        project_token: ?[]const u8,
    ) !AgentRuntimeEntry {
        if (!self.runtime_config.sandbox_enabled and !builtin.is_test) {
            std.log.err(
                "invalid runtime configuration: sandbox mode is required for agent runtime (agent={s} project={s})",
                .{ agent_id, project_id },
            );
            return error.InvalidSandboxConfig;
        }
        if (self.runtime_config.sandbox_enabled) {
            const workspace_url = self.workspace_url orelse return error.InvalidSandboxConfig;
            const workspace_auth = try self.auth_tokens.copyAdminToken();
            defer self.allocator.free(workspace_auth);
            const sandbox_runtime = sandbox_runtime_mod.SandboxRuntime.create(.{
                .allocator = self.allocator,
                .agent_id = agent_id,
                .project_id = project_id,
                .project_token = project_token,
                .workspace_url = workspace_url,
                .workspace_auth_token = workspace_auth,
                .runtime_cfg = self.runtime_config,
            }) catch |err| {
                std.log.warn(
                    "sandbox runtime create failed: agent={s} project={s} err={s}",
                    .{ agent_id, project_id, @errorName(err) },
                );
                switch (err) {
                    error.ProjectMountUnavailable => return error.SandboxMountUnavailable,
                    error.ProcessFdQuotaExceeded => return error.ProcessFdQuotaExceeded,
                    else => return error.InvalidSandboxConfig,
                }
            };
            errdefer sandbox_runtime.destroy();

            const tool_dispatch_proxy = try RuntimeToolDispatchProxy.create(
                self.allocator,
                sandbox_runtime,
                &self.control_plane,
                self.runtime_config.agents_dir,
                self.runtime_config.assets_dir,
                agent_id,
            );
            errdefer tool_dispatch_proxy.destroy();

            const runtime_server = if (self.provider_config) |provider_cfg|
                try RuntimeServer.createWithProviderAndToolDispatch(
                    self.allocator,
                    agent_id,
                    self.runtime_config,
                    provider_cfg,
                    tool_dispatch_proxy,
                    RuntimeToolDispatchProxy.dispatchWorldTool,
                )
            else
                try RuntimeServer.createWithToolDispatch(
                    self.allocator,
                    agent_id,
                    self.runtime_config,
                    tool_dispatch_proxy,
                    RuntimeToolDispatchProxy.dispatchWorldTool,
                );
            errdefer runtime_server.destroy();

            const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocalWithSandbox(
                self.allocator,
                runtime_server,
                sandbox_runtime,
            );
            errdefer runtime_handle.destroy();
            return .{
                .runtime = runtime_handle,
                .project_id = try self.allocator.dupe(u8, project_id),
                .runtime_agent_id = try self.allocator.dupe(u8, agent_id),
                .tool_dispatch_proxy = tool_dispatch_proxy,
            };
        }

        const runtime_server = if (self.provider_config) |provider_cfg|
            try RuntimeServer.createWithProvider(
                self.allocator,
                agent_id,
                self.runtime_config,
                provider_cfg,
            )
        else
            try RuntimeServer.create(
                self.allocator,
                agent_id,
                self.runtime_config,
            );
        errdefer runtime_server.destroy();

        const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(self.allocator, runtime_server);
        errdefer runtime_handle.destroy();
        return .{
            .runtime = runtime_handle,
            .project_id = try self.allocator.dupe(u8, project_id),
            .runtime_agent_id = try self.allocator.dupe(u8, agent_id),
            .tool_dispatch_proxy = null,
        };
    }

    fn resolveProjectId(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        requested_project_id: ?[]const u8,
    ) ![]u8 {
        _ = agent_id;
        if (requested_project_id) |project_id| {
            if (!isValidProjectId(project_id)) return error.InvalidProjectId;
            if (self.runtime_config.sandbox_enabled and !self.control_plane.projectHasMounts(project_id)) {
                return error.ProjectMountsMissing;
            }
            return self.allocator.dupe(u8, project_id);
        }

        if (!self.runtime_config.sandbox_enabled) {
            if (!builtin.is_test) return error.InvalidSandboxConfig;
            return self.allocator.dupe(u8, "__local__");
        }
        return error.ProjectRequired;
    }

    fn isValidAgentId(agent_id: []const u8) bool {
        if (agent_id.len == 0 or agent_id.len > max_agent_id_len) return false;
        if (std.mem.eql(u8, agent_id, ".")) return false;
        for (agent_id) |char| {
            if (std.ascii.isAlphanumeric(char)) continue;
            if (char == '_' or char == '-') continue;
            return false;
        }
        return true;
    }

    fn isValidProjectId(project_id: []const u8) bool {
        if (project_id.len == 0 or project_id.len > max_project_id_len) return false;
        if (std.mem.eql(u8, project_id, ".") or std.mem.eql(u8, project_id, "..")) return false;
        for (project_id) |char| {
            if (std.ascii.isAlphanumeric(char)) continue;
            if (char == '_' or char == '-' or char == '.') continue;
            return false;
        }
        return true;
    }

    fn hasRuntimeForBinding(self: *AgentRuntimeRegistry, agent_id: []const u8, project_id: ?[]const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const runtime_key = runtimeMapKeyForProject(project_id);
        const existing = self.by_agent.getPtr(runtime_key) orelse return false;
        if (!std.mem.eql(u8, existing.runtime_agent_id, agent_id)) return false;
        return existing.runtime.isHealthy();
    }

    fn hasHealthyRuntimeForProject(self: *AgentRuntimeRegistry, project_id: ?[]const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const runtime_key = runtimeMapKeyForProject(project_id);
        const existing = self.by_agent.getPtr(runtime_key) orelse return false;
        return existing.runtime.isHealthy();
    }

    fn runtimeBindingKey(self: *AgentRuntimeRegistry, agent_id: []const u8, project_id: ?[]const u8) ![]u8 {
        _ = agent_id;
        return self.allocator.dupe(u8, runtimeMapKeyForProject(project_id));
    }

    fn runtimeAttachSnapshotByKey(self: *AgentRuntimeRegistry, binding_key: []const u8) SessionAttachStateSnapshot {
        self.runtime_warmups_mutex.lock();
        defer self.runtime_warmups_mutex.unlock();
        if (self.runtime_warmups.getPtr(binding_key)) |state| {
            return state.snapshotOwned(self.allocator) catch .{
                .state = state.state,
                .runtime_ready = state.runtime_ready,
                .mount_ready = state.mount_ready,
                .updated_at_ms = state.updated_at_ms,
            };
        }
        return .{
            .state = .warming,
            .runtime_ready = false,
            .mount_ready = false,
            .updated_at_ms = std.time.milliTimestamp(),
        };
    }

    fn runtimeAttachSnapshot(self: *AgentRuntimeRegistry, agent_id: []const u8, project_id: ?[]const u8) SessionAttachStateSnapshot {
        if (!self.runtime_config.sandbox_enabled) {
            return .{
                .state = .ready,
                .runtime_ready = true,
                .mount_ready = true,
                .updated_at_ms = std.time.milliTimestamp(),
            };
        }
        const binding_key = self.runtimeBindingKey(agent_id, project_id) catch {
            return .{
                .state = .warming,
                .runtime_ready = false,
                .mount_ready = false,
                .updated_at_ms = std.time.milliTimestamp(),
            };
        };
        defer self.allocator.free(binding_key);

        // Read warmup state first so callers don't block on runtime mutex while
        // a background warmup is in-flight.
        var warmup_snapshot: ?SessionAttachStateSnapshot = null;
        self.runtime_warmups_mutex.lock();
        if (self.runtime_warmups.getPtr(binding_key)) |state| {
            warmup_snapshot = state.snapshotOwned(self.allocator) catch .{
                .state = state.state,
                .runtime_ready = state.runtime_ready,
                .mount_ready = state.mount_ready,
                .updated_at_ms = state.updated_at_ms,
            };
        }
        self.runtime_warmups_mutex.unlock();

        if (warmup_snapshot) |snapshot| {
            if (snapshot.state != .ready) {
                return snapshot;
            }
            var ready_snapshot = snapshot;
            ready_snapshot.deinit(self.allocator);
            warmup_snapshot = null;
        }

        const has_runtime = self.hasRuntimeForBinding(agent_id, project_id);
        if (has_runtime) {
            return .{
                .state = .ready,
                .runtime_ready = true,
                .mount_ready = true,
                .updated_at_ms = std.time.milliTimestamp(),
            };
        }

        if (warmup_snapshot) |snapshot| return snapshot;
        return .{
            .state = .warming,
            .runtime_ready = false,
            .mount_ready = false,
            .updated_at_ms = std.time.milliTimestamp(),
        };
    }

    fn touchRuntimeAttachState(self: *AgentRuntimeRegistry, agent_id: []const u8, project_id: ?[]const u8) void {
        if (!self.runtime_config.sandbox_enabled) return;

        const binding_key = self.runtimeBindingKey(agent_id, project_id) catch return;
        defer self.allocator.free(binding_key);

        const has_runtime = self.hasRuntimeForBinding(agent_id, project_id);
        const now_ms = std.time.milliTimestamp();
        var snapshot = SessionAttachStateSnapshot{
            .state = if (has_runtime) .ready else .warming,
            .runtime_ready = has_runtime,
            .mount_ready = has_runtime,
            .updated_at_ms = now_ms,
        };
        defer snapshot.deinit(self.allocator);

        self.runtime_warmups_mutex.lock();
        if (self.runtime_warmups.getPtr(binding_key)) |state| {
            if (has_runtime) {
                state.state = .ready;
                state.runtime_ready = true;
                state.mount_ready = true;
                state.updated_at_ms = now_ms;
                state.in_flight = false;
                if (state.error_code) |value| {
                    self.allocator.free(value);
                    state.error_code = null;
                }
                if (state.error_message) |value| {
                    self.allocator.free(value);
                    state.error_message = null;
                }
            }
            snapshot.deinit(self.allocator);
            snapshot = state.snapshotOwned(self.allocator) catch .{
                .state = if (has_runtime) .ready else state.state,
                .runtime_ready = if (has_runtime) true else state.runtime_ready,
                .mount_ready = if (has_runtime) true else state.mount_ready,
                .updated_at_ms = if (has_runtime) now_ms else state.updated_at_ms,
            };
        } else if (has_runtime) {
            const owned_key = self.allocator.dupe(u8, binding_key) catch {
                self.runtime_warmups_mutex.unlock();
                return;
            };
            const state = RuntimeWarmupState{
                .state = .ready,
                .runtime_ready = true,
                .mount_ready = true,
                .updated_at_ms = now_ms,
                .in_flight = false,
            };
            self.runtime_warmups.put(self.allocator, owned_key, state) catch {
                self.allocator.free(owned_key);
            };
        }
        self.runtime_warmups_mutex.unlock();

        if (has_runtime) self.emitSessionAttachStateDebugEvent(binding_key, snapshot);
    }

    const RuntimeWarmupErrorInfo = struct {
        code: []const u8,
        message: []const u8,
    };

    fn mapRuntimeWarmupError(err: anyerror) RuntimeWarmupErrorInfo {
        return switch (err) {
            error.InvalidAgentId => .{
                .code = "invalid_payload",
                .message = "invalid agent_id",
            },
            error.InvalidProjectId => .{
                .code = "invalid_payload",
                .message = "invalid project_id",
            },
            error.RuntimeLimitReached => .{
                .code = "queue_saturated",
                .message = "project runtime limit reached",
            },
            error.ProcessFdQuotaExceeded => .{
                .code = "runtime_resource_exhausted",
                .message = "sandbox runtime hit process fd quota",
            },
            error.ProjectRequired => .{
                .code = "sandbox_mount_missing",
                .message = "sandbox requires a project binding",
            },
            error.ProjectMountsMissing => .{
                .code = "project_mounts_missing",
                .message = "project has no workspace mounts configured",
            },
            error.SandboxMountUnavailable => .{
                .code = "sandbox_mount_unavailable",
                .message = "sandbox mount is unavailable",
            },
            error.InvalidSandboxConfig => .{
                .code = "sandbox_invalid_config",
                .message = "sandbox config is invalid",
            },
            error.ProjectResolutionFailed => .{
                .code = "sandbox_mount_unavailable",
                .message = "sandbox project resolution failed",
            },
            else => .{
                .code = "execution_failed",
                .message = @errorName(err),
            },
        };
    }

    fn emitSessionAttachStateDebugEvent(
        self: *AgentRuntimeRegistry,
        binding_key: []const u8,
        state: SessionAttachStateSnapshot,
    ) void {
        _ = self;
        _ = binding_key;
        _ = state;
    }

    fn markRuntimeWarmupReady(self: *AgentRuntimeRegistry, binding_key: []const u8) void {
        var snapshot = SessionAttachStateSnapshot{
            .state = .ready,
            .runtime_ready = true,
            .mount_ready = true,
            .updated_at_ms = std.time.milliTimestamp(),
        };
        defer snapshot.deinit(self.allocator);
        self.runtime_warmups_mutex.lock();
        if (self.runtime_warmups.getPtr(binding_key)) |state| {
            state.setReady(self.allocator);
            state.in_flight = false;
            snapshot.deinit(self.allocator);
            snapshot = state.snapshotOwned(self.allocator) catch .{
                .state = .ready,
                .runtime_ready = true,
                .mount_ready = true,
                .updated_at_ms = std.time.milliTimestamp(),
            };
        }
        self.runtime_warmups_mutex.unlock();
        self.emitSessionAttachStateDebugEvent(binding_key, snapshot);
    }

    fn markRuntimeWarmupError(self: *AgentRuntimeRegistry, binding_key: []const u8, code: []const u8, message: []const u8) void {
        var snapshot = SessionAttachStateSnapshot{
            .state = .err,
            .runtime_ready = false,
            .mount_ready = false,
            .updated_at_ms = std.time.milliTimestamp(),
        };
        snapshot.error_code = self.allocator.dupe(u8, code) catch null;
        snapshot.error_message = self.allocator.dupe(u8, message) catch null;
        defer snapshot.deinit(self.allocator);
        self.runtime_warmups_mutex.lock();
        if (self.runtime_warmups.getPtr(binding_key)) |state| {
            state.setError(self.allocator, code, message) catch {
                if (state.error_code) |value| self.allocator.free(value);
                if (state.error_message) |value| self.allocator.free(value);
                state.error_code = null;
                state.error_message = null;
                state.state = .err;
                state.runtime_ready = false;
                state.mount_ready = false;
                state.updated_at_ms = std.time.milliTimestamp();
            };
            state.in_flight = false;
            snapshot.deinit(self.allocator);
            snapshot = state.snapshotOwned(self.allocator) catch .{
                .state = .err,
                .runtime_ready = false,
                .mount_ready = false,
                .updated_at_ms = std.time.milliTimestamp(),
            };
            if (snapshot.error_code == null) {
                snapshot.error_code = self.allocator.dupe(u8, code) catch null;
            }
            if (snapshot.error_message == null) {
                snapshot.error_message = self.allocator.dupe(u8, message) catch null;
            }
        } else {
            const owned_key = self.allocator.dupe(u8, binding_key) catch {
                self.runtime_warmups_mutex.unlock();
                self.emitSessionAttachStateDebugEvent(binding_key, snapshot);
                return;
            };
            var state = RuntimeWarmupState{};
            state.setError(self.allocator, code, message) catch {
                if (state.error_code) |value| self.allocator.free(value);
                if (state.error_message) |value| self.allocator.free(value);
                state.error_code = null;
                state.error_message = null;
                state.state = .err;
                state.runtime_ready = false;
                state.mount_ready = false;
                state.updated_at_ms = std.time.milliTimestamp();
            };
            state.in_flight = false;
            self.runtime_warmups.put(self.allocator, owned_key, state) catch {
                var cleanup = state;
                cleanup.deinit(self.allocator);
                self.allocator.free(owned_key);
                self.runtime_warmups_mutex.unlock();
                self.emitSessionAttachStateDebugEvent(binding_key, snapshot);
                return;
            };
            if (self.runtime_warmups.getPtr(binding_key)) |inserted| {
                snapshot.deinit(self.allocator);
                snapshot = inserted.snapshotOwned(self.allocator) catch .{
                    .state = .err,
                    .runtime_ready = false,
                    .mount_ready = false,
                    .updated_at_ms = std.time.milliTimestamp(),
                };
                if (snapshot.error_code == null) {
                    snapshot.error_code = self.allocator.dupe(u8, code) catch null;
                }
                if (snapshot.error_message == null) {
                    snapshot.error_message = self.allocator.dupe(u8, message) catch null;
                }
            }
        }
        self.runtime_warmups_mutex.unlock();
        self.emitSessionAttachStateDebugEvent(binding_key, snapshot);
    }

    fn beginRuntimeWarmupThread(self: *AgentRuntimeRegistry) !void {
        self.runtime_warmup_lifecycle_mutex.lock();
        defer self.runtime_warmup_lifecycle_mutex.unlock();
        if (self.runtime_warmup_stopping) return error.ShuttingDown;
        self.runtime_warmup_inflight += 1;
    }

    fn finishRuntimeWarmupThread(self: *AgentRuntimeRegistry) void {
        self.runtime_warmup_lifecycle_mutex.lock();
        if (self.runtime_warmup_inflight > 0) {
            self.runtime_warmup_inflight -= 1;
        }
        if (self.runtime_warmup_stopping and self.runtime_warmup_inflight == 0) {
            self.runtime_warmup_lifecycle_cond.broadcast();
        } else if (self.runtime_warmup_inflight == 0) {
            self.runtime_warmup_lifecycle_cond.signal();
        }
        self.runtime_warmup_lifecycle_mutex.unlock();
    }

    fn spawnRuntimeWarmupThread(
        self: *AgentRuntimeRegistry,
        binding_key: []const u8,
        agent_id: []const u8,
        project_id: ?[]const u8,
        project_token: ?[]const u8,
    ) !void {
        try self.beginRuntimeWarmupThread();
        errdefer self.finishRuntimeWarmupThread();

        const ctx = try self.allocator.create(RuntimeWarmupThreadContext);
        ctx.* = .{
            .allocator = self.allocator,
            .runtime_registry = self,
            .binding_key = null,
            .agent_id = null,
            .project_id = null,
            .project_token = null,
        };
        errdefer ctx.deinit();

        ctx.binding_key = try self.allocator.dupe(u8, binding_key);
        ctx.agent_id = try self.allocator.dupe(u8, agent_id);
        if (project_id) |value| {
            ctx.project_id = try self.allocator.dupe(u8, value);
        }
        if (project_token) |value| {
            ctx.project_token = try self.allocator.dupe(u8, value);
        }

        const thread = try std.Thread.spawn(.{}, runtimeWarmupThreadMain, .{ctx});
        thread.detach();
    }

    fn ensureRuntimeWarmup(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        project_id: ?[]const u8,
        project_token: ?[]const u8,
        retry_on_error: bool,
    ) !SessionAttachStateSnapshot {
        if (!self.runtime_config.sandbox_enabled) {
            return .{
                .state = .ready,
                .runtime_ready = true,
                .mount_ready = true,
                .updated_at_ms = std.time.milliTimestamp(),
            };
        }
        if (project_id) |value| {
            if (!self.control_plane.projectHasMounts(value)) {
                const binding_key = try self.runtimeBindingKey(agent_id, project_id);
                defer self.allocator.free(binding_key);
                self.markRuntimeWarmupError(
                    binding_key,
                    "project_mounts_missing",
                    "project has no workspace mounts configured",
                );
                return self.runtimeAttachSnapshotByKey(binding_key);
            }
        }
        _ = self.dropUnhealthyRuntimeForBinding(
            agent_id,
            project_id,
            "runtime_unhealthy",
            "project runtime became unhealthy",
        );
        if (self.hasRuntimeForBinding(agent_id, project_id)) {
            return .{
                .state = .ready,
                .runtime_ready = true,
                .mount_ready = true,
                .updated_at_ms = std.time.milliTimestamp(),
            };
        }

        const binding_key = try self.runtimeBindingKey(agent_id, project_id);
        defer self.allocator.free(binding_key);

        var should_spawn = false;
        const now_ms = std.time.milliTimestamp();
        {
            self.runtime_warmups_mutex.lock();
            defer self.runtime_warmups_mutex.unlock();
            if (self.runtime_warmups.getPtr(binding_key)) |state| {
                if (state.in_flight and state.state == .warming and state.updated_at_ms > 0 and
                    (now_ms - state.updated_at_ms) >= runtime_warmup_stale_timeout_ms)
                {
                    state.in_flight = false;
                    state.setError(self.allocator, "runtime_warmup_timeout", "sandbox runtime warmup timed out") catch {
                        if (state.error_code) |value| self.allocator.free(value);
                        if (state.error_message) |value| self.allocator.free(value);
                        state.error_code = null;
                        state.error_message = null;
                        state.state = .err;
                        state.runtime_ready = false;
                        state.mount_ready = false;
                        state.updated_at_ms = std.time.milliTimestamp();
                    };
                }
                if (!state.in_flight) {
                    if (state.state == .err and !retry_on_error) {
                        // Preserve sticky error state for read-only status probes so callers can
                        // surface the real failure instead of oscillating forever in "warming".
                    } else if (state.state == .err and state.retry_after_ms > now_ms) {
                        // Back off after a terminal warmup failure so attach/status/presence
                        // probes do not immediately recreate the same broken runtime.
                    } else {
                        // Runtime is currently absent/unhealthy, so move the warmup state back
                        // to warming even if a stale "ready" snapshot is present.
                        state.setWarming(self.allocator);
                        state.in_flight = true;
                        should_spawn = true;
                    }
                }
            } else {
                const owned_key = try self.allocator.dupe(u8, binding_key);
                errdefer self.allocator.free(owned_key);
                var state = RuntimeWarmupState{};
                state.setWarming(self.allocator);
                state.in_flight = true;
                try self.runtime_warmups.put(self.allocator, owned_key, state);
                should_spawn = true;
            }
        }

        if (should_spawn) {
            self.spawnRuntimeWarmupThread(binding_key, agent_id, project_id, project_token) catch |spawn_err| {
                self.markRuntimeWarmupError(
                    binding_key,
                    "execution_failed",
                    @errorName(spawn_err),
                );
            };
        }

        return self.runtimeAttachSnapshotByKey(binding_key);
    }

    fn getFirstAgentId(self: *AgentRuntimeRegistry) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.by_agent.keyIterator();
        const first = it.next() orelse return null;
        return first.*;
    }

    fn maybeLogDebugFrame(self: *AgentRuntimeRegistry, agent_id: []const u8, payload: []const u8) void {
        self.debug_stream_sink.append(agent_id, payload);
        self.control_plane.appendDebugStreamEvent(agent_id, payload);
    }

    fn appendAuditRecordName(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        control_type_name: []const u8,
        scope: ControlMutationScope,
        correlation_id: ?[]const u8,
        succeeded: bool,
        error_code: ?[]const u8,
    ) void {
        self.audit_records_mutex.lock();
        defer self.audit_records_mutex.unlock();

        while (self.audit_records.items.len >= 2048) {
            var removed = self.audit_records.orderedRemove(0);
            removed.deinit(self.allocator);
        }

        const record = AuditRecord{
            .id = self.next_audit_record_id,
            .timestamp_ms = std.time.milliTimestamp(),
            .agent_id = self.allocator.dupe(u8, agent_id) catch return,
            .control_type = self.allocator.dupe(u8, control_type_name) catch return,
            .scope = scope,
            .correlation_id = if (correlation_id) |value| self.allocator.dupe(u8, value) catch return else null,
            .result = self.allocator.dupe(u8, if (succeeded) "ok" else "error") catch return,
            .error_code = if (error_code) |value| self.allocator.dupe(u8, value) catch return else null,
        };
        self.audit_records.append(self.allocator, record) catch {
            var cleanup = record;
            cleanup.deinit(self.allocator);
            return;
        };
        self.next_audit_record_id +%= 1;
        if (self.next_audit_record_id == 0) self.next_audit_record_id = 1;
    }

    fn appendAuditRecord(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        control_type: unified.ControlType,
        scope: ControlMutationScope,
        correlation_id: ?[]const u8,
        succeeded: bool,
        error_code: ?[]const u8,
    ) void {
        self.appendAuditRecordName(
            agent_id,
            unified.controlTypeName(control_type),
            scope,
            correlation_id,
            succeeded,
            error_code,
        );
    }

    fn appendSecurityAuditAndDebug(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        control_type: unified.ControlType,
        role: ConnectionRole,
        correlation_id: ?[]const u8,
        event_name: []const u8,
        succeeded: bool,
        error_code: ?[]const u8,
        message: ?[]const u8,
    ) void {
        self.appendAuditRecord(
            agent_id,
            control_type,
            .none,
            correlation_id,
            succeeded,
            error_code,
        );

        const escaped_event = unified.jsonEscape(self.allocator, event_name) catch return;
        defer self.allocator.free(escaped_event);
        const escaped_control_type = unified.jsonEscape(self.allocator, unified.controlTypeName(control_type)) catch return;
        defer self.allocator.free(escaped_control_type);
        const escaped_role = unified.jsonEscape(self.allocator, connectionRoleName(role)) catch return;
        defer self.allocator.free(escaped_role);
        const escaped_result = unified.jsonEscape(self.allocator, if (succeeded) "ok" else "error") catch return;
        defer self.allocator.free(escaped_result);

        const correlation_json = if (correlation_id) |value| blk: {
            const escaped = unified.jsonEscape(self.allocator, value) catch return;
            defer self.allocator.free(escaped);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(correlation_json);

        const error_json = if (error_code) |value| blk: {
            const escaped = unified.jsonEscape(self.allocator, value) catch return;
            defer self.allocator.free(escaped);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(error_json);

        const message_json = if (message) |value| blk: {
            const escaped = unified.jsonEscape(self.allocator, value) catch return;
            defer self.allocator.free(escaped);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(message_json);

        const payload_json = std.fmt.allocPrint(
            self.allocator,
            "{{\"event\":\"{s}\",\"control_type\":\"{s}\",\"role\":\"{s}\",\"result\":\"{s}\",\"correlation_id\":{s},\"error_code\":{s},\"message\":{s},\"ts_ms\":{d}}}",
            .{
                escaped_event,
                escaped_control_type,
                escaped_role,
                escaped_result,
                correlation_json,
                error_json,
                message_json,
                std.time.milliTimestamp(),
            },
        ) catch return;
        defer self.allocator.free(payload_json);

        const debug_json = protocol.buildDebugEvent(
            self.allocator,
            correlation_id orelse "security",
            "control.security",
            payload_json,
        ) catch return;
        defer self.allocator.free(debug_json);
        self.maybeLogDebugFrame(agent_id, debug_json);
    }

    fn buildAuditTailPayload(self: *AgentRuntimeRegistry, payload_json: ?[]const u8) ![]u8 {
        var limit: usize = 50;
        var filter_agent: ?[]const u8 = null;
        if (payload_json) |raw| {
            var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
            defer parsed.deinit();
            if (parsed.value != .object) return error.InvalidPayload;
            if (parsed.value.object.get("limit")) |limit_val| {
                if (limit_val != .integer or limit_val.integer < 0) return error.InvalidPayload;
                limit = @intCast(limit_val.integer);
                if (limit > 500) limit = 500;
            }
            if (parsed.value.object.get("agent_id")) |agent_val| {
                if (agent_val != .string or agent_val.string.len == 0) return error.InvalidPayload;
                filter_agent = agent_val.string;
            }
        }

        self.audit_records_mutex.lock();
        defer self.audit_records_mutex.unlock();

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"audit\":[");

        var emitted: usize = 0;
        var idx = self.audit_records.items.len;
        while (idx > 0 and emitted < limit) {
            idx -= 1;
            const record = self.audit_records.items[idx];
            if (filter_agent) |agent| {
                if (!std.mem.eql(u8, agent, record.agent_id)) continue;
            }
            if (emitted != 0) try out.append(self.allocator, ',');
            emitted += 1;
            try appendAuditRecordJson(self.allocator, &out, record);
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    fn clearNodeServiceEventHistory(self: *AgentRuntimeRegistry) void {
        self.node_service_event_history_mutex.lock();
        defer self.node_service_event_history_mutex.unlock();
        for (self.node_service_event_history.items) |*record| {
            record.deinit(self.allocator);
        }
        self.node_service_event_history.deinit(self.allocator);
        self.node_service_event_history = .{};
    }

    fn appendNodeServiceEventHistoryRecord(
        self: *AgentRuntimeRegistry,
        record: NodeServiceEventRecord,
    ) void {
        self.node_service_event_history_mutex.lock();
        defer self.node_service_event_history_mutex.unlock();
        while (self.node_service_event_history.items.len >= self.node_service_event_history_max and
            self.node_service_event_history.items.len > 0)
        {
            var dropped = self.node_service_event_history.orderedRemove(0);
            dropped.deinit(self.allocator);
        }
        self.node_service_event_history.append(self.allocator, record) catch {
            var cleanup = record;
            cleanup.deinit(self.allocator);
        };
    }

    fn persistNodeServiceEventRecord(
        self: *AgentRuntimeRegistry,
        timestamp_ms: i64,
        node_id: ?[]const u8,
        payload_json: []const u8,
    ) void {
        const path = self.node_service_event_log_path orelse return;
        const escaped_payload = unified.jsonEscape(self.allocator, payload_json) catch return;
        defer self.allocator.free(escaped_payload);
        const line = if (node_id) |value| blk: {
            const escaped_node = unified.jsonEscape(self.allocator, value) catch return;
            defer self.allocator.free(escaped_node);
            break :blk std.fmt.allocPrint(
                self.allocator,
                "{{\"timestamp_ms\":{d},\"node_id\":\"{s}\",\"payload_json\":\"{s}\"}}\n",
                .{ timestamp_ms, escaped_node, escaped_payload },
            ) catch return;
        } else std.fmt.allocPrint(
            self.allocator,
            "{{\"timestamp_ms\":{d},\"node_id\":null,\"payload_json\":\"{s}\"}}\n",
            .{ timestamp_ms, escaped_payload },
        ) catch return;
        defer self.allocator.free(line);

        var file = openOrCreateAppendFile(path) catch |err| {
            std.log.warn("failed opening node service event log {s}: {s}", .{ path, @errorName(err) });
            return;
        };
        defer file.close();
        file.seekFromEnd(0) catch |err| {
            std.log.warn("failed seeking node service event log {s}: {s}", .{ path, @errorName(err) });
            return;
        };
        file.writeAll(line) catch |err| {
            std.log.warn("failed appending node service event log {s}: {s}", .{ path, @errorName(err) });
        };
        self.maybeRotateNodeServiceEventLog();
    }

    fn maybeRotateNodeServiceEventLog(self: *AgentRuntimeRegistry) void {
        const path = self.node_service_event_log_path orelse return;
        if (self.node_service_event_log_rotate_max_bytes == 0) return;

        const size = fileSize(path) catch |err| switch (err) {
            error.FileNotFound => return,
            else => {
                std.log.warn("failed reading node service event log size for {s}: {s}", .{ path, @errorName(err) });
                return;
            },
        };
        if (size <= self.node_service_event_log_rotate_max_bytes) return;

        const archive_path = allocateArchivePathWithPrefix(
            self.allocator,
            path,
            node_service_event_archive_prefix,
        ) catch |err| {
            std.log.warn("failed creating node service archive path for {s}: {s}", .{ path, @errorName(err) });
            return;
        };
        defer self.allocator.free(archive_path);

        renamePath(path, archive_path) catch |err| {
            std.log.warn("failed rotating node service event log {s} -> {s}: {s}", .{
                path,
                archive_path,
                @errorName(err),
            });
            return;
        };

        if (self.node_service_event_log_gzip_available) {
            compressArchiveGzip(self.allocator, archive_path) catch |err| {
                std.log.warn("failed to gzip node service archive {s}: {s}", .{
                    archive_path,
                    @errorName(err),
                });
            };
        }

        pruneArchivesWithPrefix(
            self.allocator,
            path,
            node_service_event_archive_prefix,
            self.node_service_event_log_archive_keep,
        ) catch |err| {
            std.log.warn("failed pruning node service archives for {s}: {s}", .{
                path,
                @errorName(err),
            });
        };

        var file = openOrCreateAppendFile(path) catch |err| {
            std.log.warn("failed recreating node service event log {s}: {s}", .{ path, @errorName(err) });
            return;
        };
        defer file.close();
        file.seekFromEnd(0) catch |err| {
            std.log.warn("failed finalizing node service event log {s}: {s}", .{ path, @errorName(err) });
        };
    }

    fn recordNodeServiceEvent(
        self: *AgentRuntimeRegistry,
        node_id: ?[]const u8,
        payload_json: []const u8,
    ) void {
        const timestamp_ms = std.time.milliTimestamp();
        const payload_copy = self.allocator.dupe(u8, payload_json) catch return;
        const node_copy = if (node_id) |value|
            self.allocator.dupe(u8, value) catch {
                self.allocator.free(payload_copy);
                return;
            }
        else
            null;
        self.appendNodeServiceEventHistoryRecord(.{
            .timestamp_ms = timestamp_ms,
            .node_id = node_copy,
            .payload_json = payload_copy,
        });
        self.persistNodeServiceEventRecord(timestamp_ms, node_id, payload_json);
    }

    fn loadNodeServiceEventHistory(self: *AgentRuntimeRegistry) !void {
        const path = self.node_service_event_log_path orelse return;
        const raw = std.fs.cwd().readFileAlloc(self.allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.allocator.free(raw);

        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r");
            if (line.len == 0) continue;

            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;
            const obj = parsed.value.object;
            const payload_value = obj.get("payload_json") orelse continue;
            if (payload_value != .string or payload_value.string.len == 0) continue;
            const timestamp_ms = if (obj.get("timestamp_ms")) |value| switch (value) {
                .integer => value.integer,
                else => std.time.milliTimestamp(),
            } else std.time.milliTimestamp();

            var node_copy: ?[]u8 = null;
            if (obj.get("node_id")) |value| {
                if (value == .string and isValidNodeIdentifier(value.string)) {
                    node_copy = self.allocator.dupe(u8, value.string) catch null;
                }
            }

            const payload_copy = self.allocator.dupe(u8, payload_value.string) catch {
                if (node_copy) |value| self.allocator.free(value);
                continue;
            };
            self.appendNodeServiceEventHistoryRecord(.{
                .timestamp_ms = timestamp_ms,
                .node_id = node_copy,
                .payload_json = payload_copy,
            });
        }
    }

    fn snapshotNodeServiceEventMetrics(self: *AgentRuntimeRegistry) NodeServiceEventMetricsSnapshot {
        var snapshot = NodeServiceEventMetricsSnapshot{};
        self.node_service_event_history_mutex.lock();
        snapshot.retained_events = self.node_service_event_history.items.len;
        snapshot.retained_capacity = self.node_service_event_history_max;
        if (self.node_service_event_history.items.len > 0) {
            snapshot.retained_oldest_ms = self.node_service_event_history.items[0].timestamp_ms;
            snapshot.retained_newest_ms = self.node_service_event_history.items[self.node_service_event_history.items.len - 1].timestamp_ms;
            const oldest = snapshot.retained_oldest_ms.?;
            const newest = snapshot.retained_newest_ms.?;
            if (newest >= oldest) {
                snapshot.retained_window_ms = @intCast(newest - oldest);
            }
        }
        self.node_service_event_history_mutex.unlock();
        return snapshot;
    }

    fn appendNodeServiceEventMetricsJson(
        self: *AgentRuntimeRegistry,
        out: *std.ArrayListUnmanaged(u8),
        snapshot: NodeServiceEventMetricsSnapshot,
    ) !void {
        try out.writer(self.allocator).print(
            "{{\"retained\":{{\"events\":{d},\"capacity\":{d},\"oldest_ms\":",
            .{
                snapshot.retained_events,
                snapshot.retained_capacity,
            },
        );
        if (snapshot.retained_oldest_ms) |value| {
            try out.writer(self.allocator).print("{d}", .{value});
        } else {
            try out.appendSlice(self.allocator, "null");
        }
        try out.appendSlice(self.allocator, ",\"newest_ms\":");
        if (snapshot.retained_newest_ms) |value| {
            try out.writer(self.allocator).print("{d}", .{value});
        } else {
            try out.appendSlice(self.allocator, "null");
        }
        try out.writer(self.allocator).print(",\"window_ms\":{d}}}", .{snapshot.retained_window_ms});
    }

    fn metricsJson(self: *AgentRuntimeRegistry) ![]u8 {
        const base = try self.control_plane.metricsJson();
        defer self.allocator.free(base);

        const snapshot = self.snapshotNodeServiceEventMetrics();
        const trimmed = std.mem.trimRight(u8, base, " \t\r\n");
        if (trimmed.len == 0 or trimmed[trimmed.len - 1] != '}') {
            return self.allocator.dupe(u8, base);
        }

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, trimmed[0 .. trimmed.len - 1]);
        try out.appendSlice(self.allocator, ",\"node_service_events\":");
        try self.appendNodeServiceEventMetricsJson(&out, snapshot);
        try out.append(self.allocator, '}');
        return out.toOwnedSlice(self.allocator);
    }

    fn metricsPrometheus(self: *AgentRuntimeRegistry) ![]u8 {
        const base = try self.control_plane.metricsPrometheus();
        defer self.allocator.free(base);

        const snapshot = self.snapshotNodeServiceEventMetrics();
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, base);
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') {
            try out.append(self.allocator, '\n');
        }
        try out.writer(self.allocator).print(
            \\# TYPE spiderweb_node_service_events_retained_events gauge
            \\spiderweb_node_service_events_retained_events {d}
            \\# TYPE spiderweb_node_service_events_retained_capacity gauge
            \\spiderweb_node_service_events_retained_capacity {d}
            \\# TYPE spiderweb_node_service_events_retained_window_ms gauge
            \\spiderweb_node_service_events_retained_window_ms {d}
            \\
        ,
            .{
                snapshot.retained_events,
                snapshot.retained_capacity,
                snapshot.retained_window_ms,
            },
        );
        return out.toOwnedSlice(self.allocator);
    }

    fn emitNodeServiceEvent(
        self: *AgentRuntimeRegistry,
        node_id: ?[]const u8,
        payload_json: []const u8,
    ) void {
        self.recordNodeServiceEvent(node_id, payload_json);
    }

    fn pruneLegacySystemCapabilityMounts(self: *AgentRuntimeRegistry) void {
        const legacy_paths = [_][]const u8{
            legacy_local_node_mount_agents_self_capabilities,
            legacy_local_node_mount_projects_system_agents_self_capabilities,
        };
        for (legacy_paths) |mount_path| {
            const escaped_project = unified.jsonEscape(self.allocator, system_project_id) catch continue;
            defer self.allocator.free(escaped_project);
            const escaped_mount = unified.jsonEscape(self.allocator, mount_path) catch continue;
            defer self.allocator.free(escaped_mount);
            const payload = std.fmt.allocPrint(
                self.allocator,
                "{{\"project_id\":\"{s}\",\"mount_path\":\"{s}\"}}",
                .{ escaped_project, escaped_mount },
            ) catch continue;
            defer self.allocator.free(payload);

            const result = self.control_plane.removeProjectMountWithRole(payload, true) catch |err| switch (err) {
                fs_control_plane.ControlPlaneError.MountNotFound => continue,
                else => {
                    std.log.warn(
                        "failed pruning legacy system mount {s}: {s}",
                        .{ mount_path, @errorName(err) },
                    );
                    continue;
                },
            };
            self.allocator.free(result);
            std.log.info("pruned legacy system mount path: {s}", .{mount_path});
        }
    }

    fn maybeInitLocalFsNode(self: *AgentRuntimeRegistry, bind_addr: []const u8, port: u16) !void {
        self.mutex.lock();
        const existing_node = self.local_fs_node;
        self.mutex.unlock();
        if (existing_node != null) return;

        const export_path_owned = std.process.getEnvVarOwned(self.allocator, local_node_export_path_env) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (export_path_owned) |value| self.allocator.free(value);
        const configured_export_path = std.mem.trim(u8, self.runtime_config.spider_web_root, " \t\r\n");
        const export_path = if (export_path_owned) |value| blk: {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) break :blk trimmed;
            break :blk configured_export_path;
        } else blk: {
            break :blk configured_export_path;
        };
        if (std.mem.eql(u8, export_path, "/")) {
            std.log.warn(
                "local fs export scope is host filesystem root '/' (set {s} or runtime.spider_web_root to restrict scope)",
                .{local_node_export_path_env},
            );
        }
        if (export_path.len == 0) {
            std.log.warn(
                "local fs node disabled: both {s} and runtime.spider_web_root are empty",
                .{local_node_export_path_env},
            );
            return;
        }
        const mounts_root_trimmed = std.mem.trim(u8, self.runtime_config.sandbox_mounts_root, " \t\r\n");
        const runtime_root_trimmed = std.mem.trim(u8, self.runtime_config.sandbox_runtime_root, " \t\r\n");
        const overlaps_mounts_root = pathIsAncestorOrEqual(export_path, mounts_root_trimmed) or
            pathIsAncestorOrEqual(mounts_root_trimmed, export_path);
        const overlaps_runtime_root = pathIsAncestorOrEqual(export_path, runtime_root_trimmed) or
            pathIsAncestorOrEqual(runtime_root_trimmed, export_path);
        const watch_overlaps_sandbox = overlaps_mounts_root or overlaps_runtime_root;
        const watcher_requested = parseBoolEnv(self.allocator, local_node_watcher_enabled_env, false);
        if (watcher_requested and watch_overlaps_sandbox) {
            std.log.warn(
                "local fs node watcher disabled: export path {s} overlaps sandbox roots mounts={s} runtime={s}",
                .{ export_path, mounts_root_trimmed, runtime_root_trimmed },
            );
        }

        const export_name_owned = std.process.getEnvVarOwned(self.allocator, local_node_export_name_env) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (export_name_owned) |value| self.allocator.free(value);
        const workspace_export_name = if (export_name_owned) |value|
            if (std.mem.trim(u8, value, " \t\r\n").len > 0) std.mem.trim(u8, value, " \t\r\n") else local_node_default_workspace_export_name
        else
            local_node_default_workspace_export_name;

        const export_ro = parseBoolEnv(self.allocator, local_node_export_ro_env, false);

        const node_name_owned = std.process.getEnvVarOwned(self.allocator, local_node_name_env) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (node_name_owned) |value| self.allocator.free(value);
        const node_name = if (node_name_owned) |value|
            if (std.mem.trim(u8, value, " \t\r\n").len > 0) std.mem.trim(u8, value, " \t\r\n") else "spiderweb-local"
        else
            "spiderweb-local";

        const fs_url_owned = std.process.getEnvVarOwned(self.allocator, local_node_fs_url_env) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (fs_url_owned) |value| self.allocator.free(value);
        const fs_url = if (fs_url_owned) |value| blk: {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len == 0) break :blk try formatInternalWsUrl(self.allocator, bind_addr, port, "/v2/fs");
            break :blk try self.allocator.dupe(u8, trimmed);
        } else try formatInternalWsUrl(self.allocator, bind_addr, port, "/v2/fs");
        defer self.allocator.free(fs_url);

        const lease_ttl_ms = parseUnsignedEnv(self.allocator, local_node_lease_ttl_env, 15 * 60 * 1000);
        var heartbeat_ms = parseUnsignedEnv(self.allocator, local_node_heartbeat_ms_env, lease_ttl_ms / 2);
        if (heartbeat_ms == 0) heartbeat_ms = 1_000;
        if (heartbeat_ms > lease_ttl_ms) heartbeat_ms = lease_ttl_ms;

        const export_specs = [_]fs_node_ops.ExportSpec{
            .{
                .name = workspace_export_name,
                .path = export_path,
                .ro = export_ro,
                .desc = "spiderweb-workspace-export",
            },
            .{
                .name = local_node_agents_export_name,
                .path = "agents",
                .ro = false,
                .desc = "spiderweb-agents-export",
            },
            .{
                .name = local_node_meta_export_name,
                .path = "meta",
                .ro = true,
                .desc = "spiderweb-meta-export",
                .source_kind = .namespace,
                .source_id = "meta",
            },
            .{
                .name = local_node_chat_export_name,
                .path = "chat",
                // chat/control/input and chat/control/reply must accept writes.
                // Per-node writable flags still enforce read-only for docs/meta files.
                .ro = false,
                .desc = "spiderweb-chat-export",
                .source_kind = .namespace,
                .source_id = "capabilities",
            },
            .{
                .name = local_node_jobs_export_name,
                .path = "jobs",
                .ro = false,
                .desc = "spiderweb-jobs-export",
                .source_kind = .namespace,
                .source_id = "jobs",
            },
        };
        const mount_specs = [_]fs_control_plane.SpiderWebMountSpec{
            .{ .mount_path = local_node_mount_agents_root, .export_name = local_node_agents_export_name },
            .{ .mount_path = local_node_mount_meta, .export_name = local_node_meta_export_name },
            .{ .mount_path = local_node_mount_agents_self_chat, .export_name = local_node_chat_export_name },
            .{ .mount_path = local_node_mount_agents_self_jobs, .export_name = local_node_jobs_export_name },
            .{ .mount_path = local_node_mount_nodes_local_fs, .export_name = workspace_export_name },
            .{ .mount_path = local_node_mount_projects_system_agents_root, .export_name = local_node_agents_export_name },
            .{ .mount_path = local_node_mount_projects_system_meta, .export_name = local_node_meta_export_name },
            .{ .mount_path = local_node_mount_projects_system_agents_self_chat, .export_name = local_node_chat_export_name },
            .{ .mount_path = local_node_mount_projects_system_agents_self_jobs, .export_name = local_node_jobs_export_name },
            .{ .mount_path = local_node_mount_projects_system_nodes_local_fs, .export_name = workspace_export_name },
            .{ .mount_path = local_node_mount_projects_system_fs_local, .export_name = workspace_export_name },
        };

        const local_node = try LocalFsNode.create(
            self.allocator,
            self,
            &export_specs,
            &mount_specs,
            node_name,
            fs_url,
            lease_ttl_ms,
            heartbeat_ms,
            watcher_requested and !watch_overlaps_sandbox,
        );
        errdefer local_node.deinit(&self.control_plane);
        try local_node.startRegistrationAndHeartbeat(&self.control_plane);
        self.pruneLegacySystemCapabilityMounts();

        var installed = false;
        self.mutex.lock();
        if (self.local_fs_node == null) {
            self.local_fs_node = local_node;
            installed = true;
        }
        self.mutex.unlock();
        if (!installed) {
            local_node.deinit(&self.control_plane);
            return;
        }

        std.log.info(
            "local fs node enabled at {s} workspace={s}:{s} ({s}) namespace=synthetic",
            .{ fs_url, workspace_export_name, export_path, if (export_ro) "ro" else "rw" },
        );
    }
};

fn sessionAttachStateName(state: SessionAttachState) []const u8 {
    return switch (state) {
        .warming => "warming",
        .ready => "ready",
        .err => "error",
    };
}

const RuntimeWarmupThreadContext = struct {
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    binding_key: ?[]u8 = null,
    agent_id: ?[]u8 = null,
    project_id: ?[]u8 = null,
    project_token: ?[]u8 = null,

    fn deinit(self: *RuntimeWarmupThreadContext) void {
        if (self.binding_key) |value| self.allocator.free(value);
        if (self.agent_id) |value| self.allocator.free(value);
        if (self.project_id) |value| self.allocator.free(value);
        if (self.project_token) |value| self.allocator.free(value);
        self.allocator.destroy(self);
    }
};

fn runtimeWarmupThreadMain(ctx: *RuntimeWarmupThreadContext) void {
    defer ctx.deinit();
    defer ctx.runtime_registry.finishRuntimeWarmupThread();
    const binding_key = ctx.binding_key orelse return;
    const agent_id = ctx.agent_id orelse return;

    const runtime = ctx.runtime_registry.getOrCreate(
        agent_id,
        ctx.project_id,
        ctx.project_token,
    ) catch |err| {
        std.log.warn("runtime warmup thread failed: agent={s} project={s} err={s}", .{
            agent_id,
            ctx.project_id orelse "__auto__",
            @errorName(err),
        });
        const info = AgentRuntimeRegistry.mapRuntimeWarmupError(err);
        ctx.runtime_registry.markRuntimeWarmupError(
            binding_key,
            info.code,
            info.message,
        );
        return;
    };
    runtime.release();

    ctx.runtime_registry.markRuntimeWarmupReady(binding_key);
}

const LocalFsBootstrapContext = struct {
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    bind_addr: []u8,
    port: u16,
};

fn startLocalFsBootstrapThread(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    bind_addr: []const u8,
    port: u16,
) void {
    const bind_addr_owned = allocator.dupe(u8, bind_addr) catch |err| {
        std.log.warn("local fs node bootstrap disabled: {s}", .{@errorName(err)});
        return;
    };
    errdefer allocator.free(bind_addr_owned);

    const ctx = allocator.create(LocalFsBootstrapContext) catch |err| {
        allocator.free(bind_addr_owned);
        std.log.warn("local fs node bootstrap disabled: {s}", .{@errorName(err)});
        return;
    };
    ctx.* = .{
        .allocator = allocator,
        .runtime_registry = runtime_registry,
        .bind_addr = bind_addr_owned,
        .port = port,
    };

    const thread = std.Thread.spawn(.{}, localFsBootstrapThreadMain, .{ctx}) catch |err| {
        allocator.free(bind_addr_owned);
        allocator.destroy(ctx);
        std.log.warn("local fs node bootstrap thread failed: {s}", .{@errorName(err)});
        return;
    };
    thread.detach();
}

fn localFsBootstrapThreadMain(ctx: *LocalFsBootstrapContext) void {
    defer {
        ctx.allocator.free(ctx.bind_addr);
        ctx.allocator.destroy(ctx);
    }

    ctx.runtime_registry.maybeInitLocalFsNode(ctx.bind_addr, ctx.port) catch |err| {
        std.log.warn("local fs node setup skipped: {s}", .{@errorName(err)});
    };
}

fn ensureMotherAgentScaffoldBestEffort(allocator: std.mem.Allocator, runtime_config: Config.RuntimeConfig) void {
    ensureMotherAgentScaffold(allocator, runtime_config) catch |err| {
        std.log.warn("mother scaffold ensure failed: {s}", .{@errorName(err)});
    };
}

fn ensureMotherAgentScaffold(allocator: std.mem.Allocator, runtime_config: Config.RuntimeConfig) !void {
    const agents_dir_trimmed = std.mem.trim(u8, runtime_config.agents_dir, " \t\r\n");
    if (agents_dir_trimmed.len == 0) return error.InvalidPath;

    try std.fs.cwd().makePath(agents_dir_trimmed);

    const mother_dir = try std.fs.path.join(allocator, &.{ agents_dir_trimmed, system_agent_id });
    defer allocator.free(mother_dir);
    try std.fs.cwd().makePath(mother_dir);

    const mother_json_path = try std.fs.path.join(allocator, &.{ mother_dir, "agent.json" });
    defer allocator.free(mother_json_path);

    if (std.fs.cwd().openFile(mother_json_path, .{ .mode = .read_only })) |file| {
        file.close();
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    try std.fs.cwd().writeFile(.{
        .sub_path = mother_json_path,
        .data =
        \\{
        \\  "name": "Mother",
        \\  "description": "System orchestration and bootstrap guardian",
        \\  "is_default": true,
        \\  "capabilities": ["chat","plan","code","research"]
        \\}
        ,
    });
}

fn reconcileWorkerMain(runtime_registry: *AgentRuntimeRegistry) void {
    while (true) {
        if (runtime_registry.shouldStopReconcileWorker()) return;

        const maybe_payload = runtime_registry.control_plane.runReconcileCycle(false) catch |err| {
            std.log.warn("control-plane reconcile worker error: {s}", .{@errorName(err)});
            if (runtime_registry.shouldStopReconcileWorker()) return;
            std.Thread.sleep(runtime_registry.reconcile_worker_interval_ms * std.time.ns_per_ms);
            continue;
        };
        if (maybe_payload) |payload| {
            defer runtime_registry.allocator.free(payload);
        }

        std.Thread.sleep(runtime_registry.reconcile_worker_interval_ms * std.time.ns_per_ms);
    }
}

fn servicePresenceWorkerMain(runtime_registry: *AgentRuntimeRegistry) void {
    while (true) {
        runtime_registry.service_presence_worker_mutex.lock();
        while (runtime_registry.service_presence_jobs.items.len == 0 and !runtime_registry.service_presence_worker_stop) {
            runtime_registry.service_presence_worker_cond.wait(&runtime_registry.service_presence_worker_mutex);
        }
        if (runtime_registry.service_presence_worker_stop and runtime_registry.service_presence_jobs.items.len == 0) {
            runtime_registry.service_presence_worker_mutex.unlock();
            return;
        }
        var job = runtime_registry.service_presence_jobs.orderedRemove(0);
        runtime_registry.service_presence_worker_mutex.unlock();
        defer job.deinit(runtime_registry.allocator);

        runtime_registry.dispatchRuntimeAgentControlForTarget(
            job.agent_id,
            job.project_id,
            "service.event",
            job.payload_json,
        ) catch |err| {
            std.log.warn(
                "service presence sync failed: agent={s} session={s} status={s} err={s}",
                .{
                    job.agent_id,
                    job.session_key,
                    if (job.attached) "attached" else "detached",
                    @errorName(err),
                },
            );
        };
    }
}

fn runtimeResidencyWorkerMain(runtime_registry: *AgentRuntimeRegistry) void {
    while (true) {
        if (runtime_registry.shouldStopRuntimeResidencyWorker()) return;

        // Keep mount/runtime failures sticky until an explicit attach retry.
        // Aggressive background retries can flood the control socket pool.
        runtime_registry.ensureActiveRuntimeResidency(false) catch |err| {
            std.log.warn("runtime residency worker error: {s}", .{@errorName(err)});
        };

        std.Thread.sleep(runtime_registry.runtime_residency_worker_interval_ms * std.time.ns_per_ms);
    }
}

pub fn run(
    allocator: std.mem.Allocator,
    bind_addr: []const u8,
    port: u16,
    provider_config: Config.ProviderConfig,
    runtime_config: Config.RuntimeConfig,
) !void {
    var runtime_registry = AgentRuntimeRegistry.init(allocator, runtime_config, provider_config);
    defer runtime_registry.deinit();

    ensureMotherAgentScaffoldBestEffort(allocator, runtime_registry.runtime_config);

    runtime_registry.workspace_url = try formatInternalWsUrl(allocator, bind_addr, port, "/");
    try runtime_registry.startServicePresenceWorker();
    try runtime_registry.startReconcileWorker();

    const metrics_port_raw = parseUnsignedEnv(allocator, metrics_port_env, 0);
    if (metrics_port_raw > 0) {
        if (metrics_port_raw > std.math.maxInt(u16)) {
            std.log.warn("ignoring {s}={d}: out of range", .{ metrics_port_env, metrics_port_raw });
        } else {
            const metrics_port: u16 = @intCast(metrics_port_raw);
            const metrics_address = try std.net.Address.parseIp(bind_addr, metrics_port);
            const listener_ptr = try allocator.create(std.net.Server);
            errdefer allocator.destroy(listener_ptr);
            listener_ptr.* = try metrics_address.listen(.{ .reuse_address = true });
            // Listener intentionally lives for process lifetime; metrics thread owns accept loop.
            errdefer listener_ptr.deinit();

            const metrics_thread = try std.Thread.spawn(
                .{},
                runMetricsHttpServer,
                .{ allocator, &runtime_registry, listener_ptr },
            );
            metrics_thread.detach();
            std.log.info(
                "Metrics HTTP endpoint listening at http://{s}:{d}/metrics",
                .{ bind_addr, metrics_port },
            );
        }
    }

    const address = try std.net.Address.parseIp(bind_addr, port);
    var tcp_server = try address.listen(.{ .reuse_address = true });
    defer tcp_server.deinit();

    const configured_connection_workers = runtime_config.connection_worker_threads;
    const effective_connection_workers = @max(configured_connection_workers, min_connection_worker_threads);
    if (effective_connection_workers != configured_connection_workers) {
        std.log.warn(
            "runtime.connection_worker_threads={d} is too low for fsrpc endpoint fan-out; using {d}",
            .{ configured_connection_workers, effective_connection_workers },
        );
    }

    const dispatcher = try connection_dispatcher.ConnectionDispatcher.create(
        allocator,
        effective_connection_workers,
        runtime_config.connection_queue_max,
        workerHandleConnection,
        &runtime_registry,
    );
    defer dispatcher.destroy();

    std.log.info(
        "Runtime websocket server listening at ws://{s}:{d}",
        .{ bind_addr, port },
    );
    startLocalFsBootstrapThread(allocator, &runtime_registry, bind_addr, port);
    runtime_registry.ensureActiveRuntimeResidency(true) catch |err| {
        std.log.warn("initial runtime residency warmup failed: {s}", .{@errorName(err)});
    };
    try runtime_registry.startRuntimeResidencyWorker();

    while (true) {
        var connection = tcp_server.accept() catch |err| {
            std.log.err("accept failed: {s}", .{@errorName(err)});
            continue;
        };

        const accepted = dispatcher.enqueue(connection.stream) catch |err| {
            std.log.err("failed to enqueue connection: {s}", .{@errorName(err)});
            sendServiceUnavailable(&connection.stream) catch {};
            connection.stream.close();
            continue;
        };
        if (!accepted) {
            sendServiceUnavailable(&connection.stream) catch {};
            connection.stream.close();
        }
    }
}

fn workerHandleConnection(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    ctx: ?*anyopaque,
) !void {
    const runtime_registry: *AgentRuntimeRegistry = @ptrCast(@alignCast(ctx orelse return error.InvalidContext));
    try handleWebSocketConnection(allocator, runtime_registry, stream);
}

fn handleWebSocketConnection(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    stream: *std.net.Stream,
) !void {
    var handshake = try websocket_transport.performHandshakeWithInfo(allocator, stream);
    defer handshake.deinit(allocator);

    if (std.mem.eql(u8, handshake.path, "/v2/fs")) {
        const local_node = runtime_registry.getLocalFsNode() orelse {
            try sendWebSocketErrorAndClose(allocator, stream, .invalid_envelope, "local /v2/fs endpoint is disabled");
            return;
        };
        try handleLocalFsConnection(allocator, local_node, stream);
        return;
    }

    if (isNodeTunnelPath(handshake.path)) {
        try handleNodeTunnelConnection(allocator, runtime_registry, stream);
        return;
    }

    const maybe_node_fs_route = parseNodeFsRoute(handshake.path);

    if (maybe_node_fs_route == null) {
        _ = resolveAgentIdFromConnectionPath(handshake.path, runtime_registry.default_agent_id) orelse {
            try sendWebSocketErrorAndClose(allocator, stream, .invalid_envelope, "invalid websocket path");
            return;
        };
    }

    if (maybe_node_fs_route) |node_id| {
        try handleRoutedNodeFsConnection(
            allocator,
            runtime_registry,
            node_id,
            stream,
        );
        return;
    }

    const principal = runtime_registry.authenticateConnection(handshake.authorization) orelse {
        try sendWebSocketErrorAndClose(allocator, stream, .provider_auth_failed, "forbidden");
        return;
    };

    var session_bindings: std.StringHashMapUnmanaged(SessionBinding) = .{};
    defer deinitSessionBindings(allocator, &session_bindings);

    var initial_binding = try runtime_registry.buildInitialSessionBinding(principal.role);
    defer initial_binding.binding.deinit(allocator);
    var connect_gate_error = initial_binding.connect_gate_error;
    var bootstrap_only_mode = initial_binding.bootstrap_only;
    try upsertSessionBinding(
        allocator,
        &session_bindings,
        "main",
        initial_binding.binding.agent_id,
        defaultActorTypeForRole(principal.role),
        defaultActorIdForPrincipal(principal),
        initial_binding.binding.project_id,
        initial_binding.binding.project_token,
    );
    var active_session_key = try allocator.dupe(u8, "main");
    defer allocator.free(active_session_key);
    var fsrpc: ?fsrpc_session.Session = null;
    defer if (fsrpc) |*session| session.deinit();
    var fsrpc_bound_session_key = try allocator.dupe(u8, "main");
    defer allocator.free(fsrpc_bound_session_key);
    var control_protocol_negotiated = false;
    var runtime_fsrpc_version_negotiated = false;
    var connection_write_mutex: std.Thread.Mutex = .{};
    const connection_service_id = try std.fmt.allocPrint(
        allocator,
        "ws.{s}.{d}",
        .{ connectionRoleName(principal.role), std.time.nanoTimestamp() },
    );
    defer allocator.free(connection_service_id);
    var control_service_attached = false;
    defer {
        if (control_service_attached) {
            if (session_bindings.get(active_session_key)) |binding| {
                runtime_registry.publishServicePresenceForBinding(
                    principal.role,
                    binding,
                    active_session_key,
                    connection_service_id,
                    false,
                );
            }
        }
    }

    while (true) {
        var frame = websocket_transport.readFrame(
            allocator,
            stream,
            websocket_transport.default_max_ws_frame_payload_bytes,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = unified.parseMessage(allocator, frame.payload) catch |err| {
                    const response = try unified.buildControlError(
                        allocator,
                        null,
                        "unsupported_legacy_api",
                        @errorName(err),
                    );
                    defer allocator.free(response);
                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                    continue;
                };
                defer parsed.deinit(allocator);

                switch (parsed.channel) {
                    .control => {
                        const control_type = parsed.control_type orelse {
                            const response = try unified.buildControlError(
                                allocator,
                                parsed.id,
                                "invalid_type",
                                "missing control type",
                            );
                            defer allocator.free(response);
                            try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                            continue;
                        };

                        if (!control_protocol_negotiated and control_type != .version) {
                            const response = try unified.buildControlError(
                                allocator,
                                parsed.id,
                                "protocol_mismatch",
                                "control.version must be negotiated first",
                            );
                            defer allocator.free(response);
                            try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                            try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                            return;
                        }
                        if (connect_gate_error != null and
                            control_type != .version and
                            control_type != .connect and
                            control_type != .session_attach and
                            control_type != .session_restore and
                            control_type != .session_history and
                            control_type != .agent_list and
                            control_type != .agent_get and
                            control_type != .project_list and
                            control_type != .project_get)
                        {
                            const gate = connect_gate_error.?;
                            const response = try unified.buildControlError(
                                allocator,
                                parsed.id,
                                gate.code,
                                gate.message,
                            );
                            defer allocator.free(response);
                            try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                            continue;
                        }

                        switch (control_type) {
                            .version => {
                                validateControlVersionPayload(allocator, parsed.payload_json) catch |err| {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "protocol_mismatch",
                                        @errorName(err),
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                                    return;
                                };
                                control_protocol_negotiated = true;
                                const payload = try std.fmt.allocPrint(
                                    allocator,
                                    "{{\"protocol\":\"{s}\",\"fsrpc_runtime\":\"{s}\",\"fsrpc_node\":\"{s}\",\"fsrpc_node_proto\":{d}}}",
                                    .{
                                        control_protocol_version,
                                        fsrpc_runtime_protocol_version,
                                        fsrpc_node_protocol_version,
                                        fsrpc_node_proto_id,
                                    },
                                );
                                defer allocator.free(payload);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .version_ack,
                                    parsed.id,
                                    payload,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .connect => {
                                const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                var project_setup = try runtime_registry.projectSetupHint(
                                    principal.role,
                                    active_binding,
                                    bootstrap_only_mode,
                                );
                                defer project_setup.deinit(allocator);
                                const escaped_role = switch (principal.role) {
                                    .admin => "admin",
                                    .user => "user",
                                };
                                const escaped_actor_type = try unified.jsonEscape(allocator, active_binding.actor_type);
                                defer allocator.free(escaped_actor_type);
                                const escaped_actor_id = try unified.jsonEscape(allocator, active_binding.actor_id);
                                defer allocator.free(escaped_actor_id);
                                const project_json = if (active_binding.project_id) |project_id| blk: {
                                    const escaped_project = try unified.jsonEscape(allocator, project_id);
                                    defer allocator.free(escaped_project);
                                    break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_project});
                                } else try allocator.dupe(u8, "null");
                                defer allocator.free(project_json);
                                const bootstrap_message_json = if (bootstrap_only_mode and principal.role == .admin) blk: {
                                    const escaped_bootstrap = try unified.jsonEscape(
                                        allocator,
                                        "Bootstrap required: chat with Mother to define the first project vision and first non-system agent.",
                                    );
                                    defer allocator.free(escaped_bootstrap);
                                    break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_bootstrap});
                                } else try allocator.dupe(u8, "null");
                                defer allocator.free(bootstrap_message_json);
                                const project_setup_message_json = if (project_setup.message) |setup_message| blk: {
                                    const escaped_message = try unified.jsonEscape(allocator, setup_message);
                                    defer allocator.free(escaped_message);
                                    break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_message});
                                } else try allocator.dupe(u8, "null");
                                defer allocator.free(project_setup_message_json);
                                const project_setup_project_id_json = if (project_setup.project_id) |setup_project_id| blk: {
                                    const escaped_project_id = try unified.jsonEscape(allocator, setup_project_id);
                                    defer allocator.free(escaped_project_id);
                                    break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_project_id});
                                } else try allocator.dupe(u8, "null");
                                defer allocator.free(project_setup_project_id_json);
                                const project_setup_vision_json = if (project_setup.project_vision) |setup_vision| blk: {
                                    const escaped_vision = try unified.jsonEscape(allocator, setup_vision);
                                    defer allocator.free(escaped_vision);
                                    break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_vision});
                                } else try allocator.dupe(u8, "null");
                                defer allocator.free(project_setup_vision_json);
                                const connect_gate_json = if (connect_gate_error) |gate| blk: {
                                    const escaped_code = try unified.jsonEscape(allocator, gate.code);
                                    defer allocator.free(escaped_code);
                                    const escaped_message = try unified.jsonEscape(allocator, gate.message);
                                    defer allocator.free(escaped_message);
                                    break :blk try std.fmt.allocPrint(
                                        allocator,
                                        "{{\"code\":\"{s}\",\"message\":\"{s}\"}}",
                                        .{ escaped_code, escaped_message },
                                    );
                                } else try allocator.dupe(u8, "null");
                                defer allocator.free(connect_gate_json);
                                const workspace_json = try buildWorkspaceStatusPayloadForBinding(
                                    allocator,
                                    runtime_registry,
                                    active_binding,
                                    principal.role == .admin,
                                );
                                defer allocator.free(workspace_json);
                                const payload = try std.fmt.allocPrint(
                                    allocator,
                                    "{{\"agent_id\":\"{s}\",\"actor_type\":\"{s}\",\"actor_id\":\"{s}\",\"project_id\":{s},\"workspace\":{s},\"session\":\"{s}\",\"protocol\":\"{s}\",\"role\":\"{s}\",\"bootstrap_only\":{},\"bootstrap_message\":{s},\"project_setup_required\":{},\"project_setup_message\":{s},\"project_setup_project_id\":{s},\"project_setup_project_vision\":{s},\"requires_session_attach\":{},\"connect_gate\":{s}}}",
                                    .{
                                        active_binding.agent_id,
                                        escaped_actor_type,
                                        escaped_actor_id,
                                        project_json,
                                        workspace_json,
                                        active_session_key,
                                        control_protocol_version,
                                        escaped_role,
                                        bootstrap_only_mode,
                                        bootstrap_message_json,
                                        project_setup.required,
                                        project_setup_message_json,
                                        project_setup_project_id_json,
                                        project_setup_vision_json,
                                        connect_gate_error != null,
                                        connect_gate_json,
                                    },
                                );
                                defer allocator.free(payload);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .connect_ack,
                                    parsed.id,
                                    payload,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                control_service_attached = true;
                                runtime_registry.publishServicePresenceForBinding(
                                    principal.role,
                                    active_binding,
                                    active_session_key,
                                    connection_service_id,
                                    true,
                                );
                                continue;
                            },
                            .ping => {
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .pong,
                                    parsed.id,
                                    "{}",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .metrics => {
                                if (principal.role != .admin) {
                                    const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        active_binding.agent_id,
                                        .metrics,
                                        principal.role,
                                        parsed.correlation_id orelse parsed.id,
                                        "metrics_forbidden",
                                        false,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const payload = try runtime_registry.metricsJson();
                                defer allocator.free(payload);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .metrics,
                                    parsed.id,
                                    payload,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .auth_status => {
                                if (principal.role != .admin) {
                                    const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        active_binding.agent_id,
                                        .auth_status,
                                        principal.role,
                                        parsed.correlation_id orelse parsed.id,
                                        "auth_status_forbidden",
                                        false,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const payload = try runtime_registry.authStatusJson();
                                defer allocator.free(payload);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .auth_status,
                                    parsed.id,
                                    payload,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .auth_rotate => {
                                if (principal.role != .admin) {
                                    const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        active_binding.agent_id,
                                        .auth_rotate,
                                        principal.role,
                                        parsed.correlation_id orelse parsed.id,
                                        "auth_rotate_forbidden",
                                        false,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                var payload = try parseControlPayloadObject(allocator, parsed.payload_json);
                                defer payload.deinit();
                                if (payload.value != .object) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "auth_rotate payload must be an object",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const role_name = getRequiredStringField(payload.value.object, "role") catch {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "missing_field",
                                        "role is required",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                const role: ConnectionRole = if (std.mem.eql(u8, role_name, "admin"))
                                    .admin
                                else if (std.mem.eql(u8, role_name, "user"))
                                    .user
                                else {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "role must be 'admin' or 'user'",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                const rotated = runtime_registry.rotateAuthToken(role) catch |err| {
                                    const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        active_binding.agent_id,
                                        .auth_rotate,
                                        principal.role,
                                        parsed.correlation_id orelse parsed.id,
                                        "auth_rotate_persist_failed",
                                        false,
                                        "storage_error",
                                        @errorName(err),
                                    );
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "storage_error",
                                        @errorName(err),
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                defer runtime_registry.allocator.free(rotated);
                                const escaped_token = try unified.jsonEscape(allocator, rotated);
                                defer allocator.free(escaped_token);
                                const payload_json = try std.fmt.allocPrint(
                                    allocator,
                                    "{{\"role\":\"{s}\",\"token\":\"{s}\"}}",
                                    .{
                                        if (role == .admin) "admin" else "user",
                                        escaped_token,
                                    },
                                );
                                defer allocator.free(payload_json);
                                const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                runtime_registry.appendSecurityAuditAndDebug(
                                    active_binding.agent_id,
                                    .auth_rotate,
                                    principal.role,
                                    parsed.correlation_id orelse parsed.id,
                                    if (role == .admin) "auth_rotate_admin_success" else "auth_rotate_user_success",
                                    true,
                                    null,
                                    null,
                                );
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .auth_rotate,
                                    parsed.id,
                                    payload_json,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .session_attach => {
                                var payload = try parseControlPayloadObject(allocator, parsed.payload_json);
                                defer payload.deinit();
                                if (payload.value != .object) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "session_attach payload must be an object",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }

                                const session_key = getRequiredStringField(payload.value.object, "session_key") catch {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "missing_field",
                                        "session_key is required",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                const attach_agent_id = getRequiredStringField(payload.value.object, "agent_id") catch {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "missing_field",
                                        "agent_id is required",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                const attach_project_id = getRequiredStringField(payload.value.object, "project_id") catch {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "missing_field",
                                        "project_id is required",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                var attach_project_token = getOptionalStringField(payload.value.object, "project_token");
                                var attach_actor_type = getOptionalStringField(payload.value.object, "actor_type");
                                var attach_actor_id = getOptionalStringField(payload.value.object, "actor_id");
                                const current_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                var previous_active_binding = try cloneSessionBinding(allocator, current_binding);
                                defer previous_active_binding.deinit(allocator);
                                const security_correlation = parsed.correlation_id orelse parsed.id;

                                if (!isValidSessionKey(session_key)) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "invalid session_key",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                if (!AgentRuntimeRegistry.isValidAgentId(attach_agent_id)) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "invalid agent_id",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                if (!AgentRuntimeRegistry.isValidProjectId(attach_project_id)) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "invalid project_id",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }

                                const existing_binding = session_bindings.get(session_key);
                                if (existing_binding != null and std.mem.eql(u8, existing_binding.?.agent_id, attach_agent_id) and attach_project_token == null) {
                                    attach_project_token = existing_binding.?.project_token;
                                }
                                if (existing_binding != null and attach_actor_type == null) {
                                    attach_actor_type = existing_binding.?.actor_type;
                                }
                                if (existing_binding != null and attach_actor_id == null) {
                                    attach_actor_id = existing_binding.?.actor_id;
                                }
                                if (attach_actor_type == null) attach_actor_type = defaultActorTypeForRole(principal.role);
                                if (attach_actor_id == null) attach_actor_id = defaultActorIdForPrincipal(principal);
                                if (!isValidActorType(attach_actor_type.?)) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "invalid actor_type",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                if (!isValidActorId(attach_actor_id.?)) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "invalid actor_id",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                if (principal.role == .user and
                                    (!std.mem.eql(u8, attach_actor_type.?, defaultActorTypeForRole(principal.role)) or
                                        !std.mem.eql(u8, attach_actor_id.?, defaultActorIdForPrincipal(principal))))
                                {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "user role cannot override actor identity",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }

                                if (principal.role == .user and std.mem.eql(u8, attach_agent_id, system_agent_id)) {
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        current_binding.agent_id,
                                        .session_attach,
                                        principal.role,
                                        security_correlation,
                                        "session_attach_forbidden_system_agent",
                                        false,
                                        "forbidden",
                                        "user role cannot attach to mother agent",
                                    );
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "user role cannot attach to mother agent",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                if (principal.role == .user and std.mem.eql(u8, attach_project_id, system_project_id)) {
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        current_binding.agent_id,
                                        .session_attach,
                                        principal.role,
                                        security_correlation,
                                        "session_attach_forbidden_system_project",
                                        false,
                                        "forbidden",
                                        "user role cannot attach to system project",
                                    );
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "user role cannot attach to system project",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                if (std.mem.eql(u8, attach_agent_id, system_agent_id) and
                                    !std.mem.eql(u8, attach_project_id, system_project_id))
                                {
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        current_binding.agent_id,
                                        .session_attach,
                                        principal.role,
                                        security_correlation,
                                        "session_attach_forbidden_primary_project",
                                        false,
                                        "forbidden",
                                        "mother can only attach to system project",
                                    );
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "mother can only attach to system project",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const rebind_requested = if (existing_binding) |binding|
                                    !std.mem.eql(u8, binding.agent_id, attach_agent_id) or
                                        !optionalStringsEqual(binding.project_id, attach_project_id)
                                else
                                    false;

                                if (rebind_requested) {
                                    if (try runtime_registry.job_index.hasInFlightForAgent(existing_binding.?.agent_id)) {
                                        runtime_registry.appendSecurityAuditAndDebug(
                                            current_binding.agent_id,
                                            .session_attach,
                                            principal.role,
                                            security_correlation,
                                            "session_attach_rebind_session_busy",
                                            false,
                                            "session_busy",
                                            "cannot rebind session while current agent has in-flight jobs",
                                        );
                                        const response = try unified.buildControlError(
                                            allocator,
                                            parsed.id,
                                            "session_busy",
                                            "cannot rebind session while current agent has in-flight jobs",
                                        );
                                        defer allocator.free(response);
                                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                        continue;
                                    }
                                }

                                if (try runtime_registry.job_index.hasInFlightForAgent(attach_agent_id)) {
                                    const same_existing_binding = if (existing_binding) |binding|
                                        std.mem.eql(u8, binding.agent_id, attach_agent_id) and optionalStringsEqual(binding.project_id, attach_project_id)
                                    else
                                        false;
                                    const same_runtime_binding = runtime_registry.hasRuntimeForBinding(attach_agent_id, attach_project_id);

                                    if (!same_existing_binding and !same_runtime_binding) {
                                        runtime_registry.appendSecurityAuditAndDebug(
                                            current_binding.agent_id,
                                            .session_attach,
                                            principal.role,
                                            security_correlation,
                                            "session_attach_project_change_session_busy",
                                            false,
                                            "session_busy",
                                            "cannot change project while agent has in-flight jobs",
                                        );
                                        const response = try unified.buildControlError(
                                            allocator,
                                            parsed.id,
                                            "session_busy",
                                            "cannot change project while agent has in-flight jobs",
                                        );
                                        defer allocator.free(response);
                                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                        continue;
                                    }
                                }

                                const activate_payload = try buildProjectActivatePayload(allocator, attach_project_id, attach_project_token);
                                defer allocator.free(activate_payload);
                                _ = runtime_registry.control_plane.activateProjectWithRole(
                                    attach_agent_id,
                                    activate_payload,
                                    principal.role == .admin,
                                ) catch |activate_err| {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        controlPlaneErrorCode(activate_err),
                                        @errorName(activate_err),
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };

                                const previous_session_key = try allocator.dupe(u8, active_session_key);
                                defer allocator.free(previous_session_key);
                                try upsertSessionBinding(
                                    allocator,
                                    &session_bindings,
                                    session_key,
                                    attach_agent_id,
                                    attach_actor_type.?,
                                    attach_actor_id.?,
                                    attach_project_id,
                                    attach_project_token,
                                );
                                allocator.free(active_session_key);
                                active_session_key = try allocator.dupe(u8, session_key);

                                const active_binding = session_bindings.get(session_key) orelse return error.InvalidState;
                                var attach_state = runtime_registry.ensureRuntimeWarmup(
                                    active_binding.agent_id,
                                    active_binding.project_id,
                                    active_binding.project_token,
                                    true,
                                ) catch |warm_err| {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "execution_failed",
                                        @errorName(warm_err),
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                // Keep session_attach responsive even when runtime warmup is in-flight.
                                // Clients can poll control.session_status for warmup progression.
                                defer attach_state.deinit(allocator);
                                const attach_json = try buildSessionAttachStateJson(allocator, attach_state);
                                defer allocator.free(attach_json);
                                const workspace_json = try buildWorkspaceStatusPayloadForBinding(
                                    allocator,
                                    runtime_registry,
                                    active_binding,
                                    principal.role == .admin,
                                );
                                defer allocator.free(workspace_json);
                                const ack_payload = try buildSessionAttachAckPayload(
                                    allocator,
                                    session_key,
                                    active_binding.agent_id,
                                    active_binding.actor_type,
                                    active_binding.actor_id,
                                    active_binding.project_id,
                                    workspace_json,
                                    attach_json,
                                );
                                defer allocator.free(ack_payload);

                                const response = try unified.buildControlAck(
                                    allocator,
                                    .session_attach,
                                    parsed.id,
                                    ack_payload,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                connect_gate_error = null;
                                bootstrap_only_mode = runtime_registry.isBootstrapMotherOnlyState();
                                runtime_registry.rememberPrincipalSession(
                                    principal,
                                    session_key,
                                    active_binding.agent_id,
                                    active_binding.project_id,
                                );
                                if (control_service_attached) {
                                    const runtime_binding_changed = !std.mem.eql(u8, previous_active_binding.agent_id, active_binding.agent_id) or
                                        !optionalStringsEqual(previous_active_binding.project_id, active_binding.project_id);
                                    if (runtime_binding_changed) {
                                        runtime_registry.publishServicePresenceForBinding(
                                            principal.role,
                                            previous_active_binding,
                                            previous_session_key,
                                            connection_service_id,
                                            false,
                                        );
                                    }
                                    runtime_registry.publishServicePresenceForBinding(
                                        principal.role,
                                        active_binding,
                                        session_key,
                                        connection_service_id,
                                        true,
                                    );
                                }
                                continue;
                            },
                            .session_status => {
                                var payload = try parseControlPayloadObject(allocator, parsed.payload_json);
                                defer payload.deinit();
                                if (payload.value != .object) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "session_status payload must be an object",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }

                                const payload_session_key = getOptionalStringField(payload.value.object, "session_key");
                                const session_key = if (payload_session_key) |value| value else active_session_key;
                                const heartbeat = getOptionalBoolField(payload.value.object, "heartbeat") orelse false;
                                const binding = session_bindings.get(session_key) orelse {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "not_found",
                                        "session_key not found",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };

                                if (heartbeat) {
                                    runtime_registry.rememberPrincipalSession(
                                        principal,
                                        session_key,
                                        binding.agent_id,
                                        binding.project_id,
                                    );
                                    runtime_registry.touchRuntimeAttachState(binding.agent_id, binding.project_id);
                                }

                                var attach_state = runtime_registry.ensureRuntimeWarmup(
                                    binding.agent_id,
                                    binding.project_id,
                                    binding.project_token,
                                    false,
                                ) catch |warm_err| {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "execution_failed",
                                        @errorName(warm_err),
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                defer attach_state.deinit(allocator);

                                const attach_json = try buildSessionAttachStateJson(allocator, attach_state);
                                defer allocator.free(attach_json);
                                const now_ms = std.time.milliTimestamp();
                                const session_last_active_ms = runtime_registry.auth_tokens.sessionLastActiveMs(principal.role, session_key) orelse 0;
                                const session_stale = session_last_active_ms > 0 and (now_ms - session_last_active_ms) > session_heartbeat_ttl_ms;
                                const agent_last_heartbeat_ms = attach_state.updated_at_ms;
                                const agent_stale = agent_last_heartbeat_ms > 0 and (now_ms - agent_last_heartbeat_ms) > agent_heartbeat_ttl_ms;
                                const payload_json = try buildSessionStatusPayload(
                                    allocator,
                                    session_key,
                                    binding.agent_id,
                                    binding.actor_type,
                                    binding.actor_id,
                                    binding.project_id,
                                    attach_json,
                                    session_last_active_ms,
                                    session_stale,
                                    agent_last_heartbeat_ms,
                                    agent_stale,
                                );
                                defer allocator.free(payload_json);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .session_status,
                                    parsed.id,
                                    payload_json,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .session_resume => {
                                var payload = try parseControlPayloadObject(allocator, parsed.payload_json);
                                defer payload.deinit();
                                if (payload.value != .object) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "session_resume payload must be an object",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const session_key = getRequiredStringField(payload.value.object, "session_key") catch {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "missing_field",
                                        "session_key is required",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                const binding = session_bindings.get(session_key) orelse {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "not_found",
                                        "session_key not found",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };

                                const previous_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                const previous_session_key = try allocator.dupe(u8, active_session_key);
                                defer allocator.free(previous_session_key);
                                allocator.free(active_session_key);
                                active_session_key = try allocator.dupe(u8, session_key);
                                var attach_state = runtime_registry.ensureRuntimeWarmup(
                                    binding.agent_id,
                                    binding.project_id,
                                    binding.project_token,
                                    true,
                                ) catch |warm_err| {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "execution_failed",
                                        @errorName(warm_err),
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                defer attach_state.deinit(allocator);
                                const attach_json = try buildSessionAttachStateJson(allocator, attach_state);
                                defer allocator.free(attach_json);
                                const workspace_json = try buildWorkspaceStatusPayloadForBinding(
                                    allocator,
                                    runtime_registry,
                                    binding,
                                    principal.role == .admin,
                                );
                                defer allocator.free(workspace_json);
                                const ack_payload = try buildSessionAttachAckPayload(
                                    allocator,
                                    session_key,
                                    binding.agent_id,
                                    binding.actor_type,
                                    binding.actor_id,
                                    binding.project_id,
                                    workspace_json,
                                    attach_json,
                                );
                                defer allocator.free(ack_payload);

                                const response = try unified.buildControlAck(
                                    allocator,
                                    .session_resume,
                                    parsed.id,
                                    ack_payload,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                runtime_registry.rememberPrincipalSession(
                                    principal,
                                    session_key,
                                    binding.agent_id,
                                    binding.project_id,
                                );
                                if (control_service_attached) {
                                    const runtime_binding_changed = !std.mem.eql(u8, previous_binding.agent_id, binding.agent_id) or
                                        !optionalStringsEqual(previous_binding.project_id, binding.project_id);
                                    if (runtime_binding_changed) {
                                        runtime_registry.publishServicePresenceForBinding(
                                            principal.role,
                                            previous_binding,
                                            previous_session_key,
                                            connection_service_id,
                                            false,
                                        );
                                    }
                                    runtime_registry.publishServicePresenceForBinding(
                                        principal.role,
                                        binding,
                                        session_key,
                                        connection_service_id,
                                        true,
                                    );
                                }
                                continue;
                            },
                            .session_list => {
                                const payload_json = try buildSessionListPayload(allocator, &session_bindings, active_session_key);
                                defer allocator.free(payload_json);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .session_list,
                                    parsed.id,
                                    payload_json,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .session_restore => {
                                var payload = try parseControlPayloadObject(allocator, parsed.payload_json);
                                defer payload.deinit();
                                if (payload.value != .object) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "session_restore payload must be an object",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const agent_filter = getOptionalStringField(payload.value.object, "agent_id");
                                var restored = try runtime_registry.auth_tokens.latestSessionOwned(principal.role, agent_filter);
                                defer if (restored) |*entry| entry.deinit(allocator);

                                const payload_json = try buildSessionRestorePayload(allocator, restored);
                                defer allocator.free(payload_json);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .session_restore,
                                    parsed.id,
                                    payload_json,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .session_history => {
                                var payload = try parseControlPayloadObject(allocator, parsed.payload_json);
                                defer payload.deinit();
                                if (payload.value != .object) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "session_history payload must be an object",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const agent_filter = getOptionalStringField(payload.value.object, "agent_id");
                                const limit = blk: {
                                    const value = payload.value.object.get("limit") orelse break :blk @as(usize, 10);
                                    if (value != .integer or value.integer < 0) {
                                        const response = try unified.buildControlError(
                                            allocator,
                                            parsed.id,
                                            "invalid_payload",
                                            "limit must be a non-negative integer",
                                        );
                                        defer allocator.free(response);
                                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                        continue;
                                    }
                                    if (value.integer > 100) break :blk @as(usize, 100);
                                    break :blk @as(usize, @intCast(value.integer));
                                };
                                var history = try runtime_registry.auth_tokens.sessionHistoryOwned(
                                    principal.role,
                                    agent_filter,
                                    limit,
                                );
                                defer {
                                    for (history.items) |*entry| entry.deinit(allocator);
                                    history.deinit(allocator);
                                }

                                const payload_json = try buildSessionHistoryPayload(allocator, history.items);
                                defer allocator.free(payload_json);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .session_history,
                                    parsed.id,
                                    payload_json,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .session_close => {
                                var payload = try parseControlPayloadObject(allocator, parsed.payload_json);
                                defer payload.deinit();
                                if (payload.value != .object) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "invalid_payload",
                                        "session_close payload must be an object",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const session_key = getRequiredStringField(payload.value.object, "session_key") catch {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "missing_field",
                                        "session_key is required",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                if (std.mem.eql(u8, session_key, "main")) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "forbidden",
                                        "main session cannot be closed",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                var previous_active_binding: ?SessionBinding = null;
                                defer if (previous_active_binding) |*value| value.deinit(allocator);
                                var previous_active_session_key: ?[]u8 = null;
                                defer if (previous_active_session_key) |value| allocator.free(value);
                                if (control_service_attached and std.mem.eql(u8, active_session_key, session_key)) {
                                    const active_binding_before_close = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                    previous_active_binding = try cloneSessionBinding(allocator, active_binding_before_close);
                                    previous_active_session_key = try allocator.dupe(u8, active_session_key);
                                }
                                if (session_bindings.fetchRemove(session_key)) |removed| {
                                    allocator.free(removed.key);
                                    var binding = removed.value;
                                    binding.deinit(allocator);
                                } else {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "not_found",
                                        "session_key not found",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }

                                if (std.mem.eql(u8, active_session_key, session_key)) {
                                    allocator.free(active_session_key);
                                    active_session_key = try allocator.dupe(u8, "main");
                                    if (fsrpc) |*session| {
                                        const main_binding = session_bindings.get("main") orelse return error.InvalidState;
                                        const main_runtime = runtime_registry.getOrCreate(
                                            main_binding.agent_id,
                                            main_binding.project_id,
                                            main_binding.project_token,
                                        ) catch |err| switch (err) {
                                            error.InvalidAgentId => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "invalid_payload",
                                                    "invalid agent_id",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            error.InvalidProjectId => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "invalid_payload",
                                                    "invalid project_id",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            error.RuntimeLimitReached => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "queue_saturated",
                                                    "agent runtime limit reached",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            error.ProjectRequired => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "sandbox_mount_missing",
                                                    "sandbox requires a project binding",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            error.ProjectMountsMissing => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "project_mounts_missing",
                                                    "project has no workspace mounts configured",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            error.SandboxMountUnavailable => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "sandbox_mount_unavailable",
                                                    "sandbox mount is unavailable",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            error.ProcessFdQuotaExceeded => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "runtime_resource_exhausted",
                                                    "sandbox runtime hit process fd quota",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            error.InvalidSandboxConfig => {
                                                const response = try unified.buildControlError(
                                                    allocator,
                                                    parsed.id,
                                                    "sandbox_invalid_config",
                                                    "sandbox config is invalid",
                                                );
                                                defer allocator.free(response);
                                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                                continue;
                                            },
                                            else => return err,
                                        };
                                        defer main_runtime.release();
                                        try session.setRuntimeBindingWithOptions(
                                            main_runtime,
                                            main_binding.agent_id,
                                            .{
                                                .project_id = main_binding.project_id,
                                                .project_token = main_binding.project_token,
                                                .agents_dir = runtime_registry.runtime_config.agents_dir,
                                                .assets_dir = runtime_registry.runtime_config.assets_dir,
                                                .projects_dir = "projects",
                                                .control_plane = &runtime_registry.control_plane,
                                                .actor_type = main_binding.actor_type,
                                                .actor_id = main_binding.actor_id,
                                                .is_admin = principal.role == .admin,
                                            },
                                        );
                                    }
                                }
                                if (control_service_attached and previous_active_binding != null and previous_active_session_key != null) {
                                    const main_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                    const old_binding = previous_active_binding.?;
                                    const runtime_binding_changed = !std.mem.eql(u8, old_binding.agent_id, main_binding.agent_id) or
                                        !optionalStringsEqual(old_binding.project_id, main_binding.project_id);
                                    if (runtime_binding_changed) {
                                        runtime_registry.publishServicePresenceForBinding(
                                            principal.role,
                                            old_binding,
                                            previous_active_session_key.?,
                                            connection_service_id,
                                            false,
                                        );
                                    }
                                    runtime_registry.publishServicePresenceForBinding(
                                        principal.role,
                                        main_binding,
                                        active_session_key,
                                        connection_service_id,
                                        true,
                                    );
                                }

                                const payload_json = try std.fmt.allocPrint(
                                    allocator,
                                    "{{\"session_key\":\"{s}\",\"closed\":true,\"active_session\":\"{s}\"}}",
                                    .{ session_key, active_session_key },
                                );
                                defer allocator.free(payload_json);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .session_close,
                                    parsed.id,
                                    payload_json,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .node_invite_create,
                            .node_join_request,
                            .node_join_pending_list,
                            .node_join_approve,
                            .node_join_deny,
                            .node_join,
                            .node_lease_refresh,
                            .node_service_upsert,
                            .node_service_get,
                            .agent_list,
                            .agent_get,
                            .node_list,
                            .node_get,
                            .node_delete,
                            .project_create,
                            .project_update,
                            .project_delete,
                            .project_list,
                            .project_get,
                            .project_mount_set,
                            .project_mount_remove,
                            .project_mount_list,
                            .project_token_rotate,
                            .project_token_revoke,
                            .project_activate,
                            .workspace_status,
                            .reconcile_status,
                            .project_up,
                            .audit_tail,
                            => {
                                const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                const control_agent_id = active_binding.agent_id;
                                const correlation_id = parsed.correlation_id orelse parsed.id;
                                if (principal.role == .user and isControlAdminOnly(control_type)) {
                                    runtime_registry.appendSecurityAuditAndDebug(
                                        control_agent_id,
                                        control_type,
                                        principal.role,
                                        correlation_id,
                                        "admin_only_forbidden",
                                        false,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    const response = try buildControlErrorWithCorrelation(
                                        allocator,
                                        parsed.id,
                                        correlation_id,
                                        "forbidden",
                                        "operation requires admin token",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                const scope = controlMutationScope(control_type);
                                if (scope != .none and correlation_id == null) {
                                    const response = try buildControlErrorWithCorrelation(
                                        allocator,
                                        parsed.id,
                                        null,
                                        "correlation_required",
                                        "missing correlation_id on mutating control operation",
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                }
                                if (scope != .none) {
                                    validateControlScopeTokens(allocator, runtime_registry, control_type, parsed.payload_json) catch |err| {
                                        const code = switch (err) {
                                            error.MissingField => "missing_field",
                                            error.InvalidPayload => "invalid_payload",
                                            else => "operator_auth_failed",
                                        };
                                        runtime_registry.appendAuditRecord(
                                            control_agent_id,
                                            control_type,
                                            scope,
                                            correlation_id,
                                            false,
                                            code,
                                        );
                                        const response = try buildControlErrorWithCorrelation(
                                            allocator,
                                            parsed.id,
                                            correlation_id,
                                            code,
                                            @errorName(err),
                                        );
                                        defer allocator.free(response);
                                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                        continue;
                                    };
                                }
                                const availability_before = runtime_registry.control_plane.availabilitySnapshot();
                                const payload_json = handleControlPlaneCommand(
                                    runtime_registry,
                                    control_type,
                                    control_agent_id,
                                    principal.role == .admin,
                                    parsed.payload_json,
                                ) catch |err| {
                                    const code = controlPlaneErrorCode(err);
                                    if (scope != .none) {
                                        runtime_registry.appendAuditRecord(
                                            control_agent_id,
                                            control_type,
                                            scope,
                                            correlation_id,
                                            false,
                                            code,
                                        );
                                    }
                                    const response = try buildControlErrorWithCorrelation(
                                        allocator,
                                        parsed.id,
                                        correlation_id,
                                        code,
                                        @errorName(err),
                                    );
                                    defer allocator.free(response);
                                    try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                    continue;
                                };
                                defer allocator.free(payload_json);

                                if (scope != .none) {
                                    runtime_registry.appendAuditRecord(
                                        control_agent_id,
                                        control_type,
                                        scope,
                                        correlation_id,
                                        true,
                                        null,
                                    );
                                }

                                const response = try unified.buildControlAck(
                                    allocator,
                                    control_type,
                                    parsed.id,
                                    payload_json,
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                if (control_type == .node_service_upsert) {
                                    const event_node_id = extractNodeIdFromControlPayload(allocator, payload_json) catch null;
                                    defer if (event_node_id) |value| allocator.free(value);
                                    runtime_registry.emitNodeServiceEvent(
                                        if (event_node_id) |value| value else null,
                                        payload_json,
                                    );
                                }
                                const availability_after = runtime_registry.control_plane.availabilitySnapshot();
                                const topology_mutation = isWorkspaceTopologyMutation(control_type);
                                const availability_changed = !fs_control_plane.ControlPlane.AvailabilitySnapshot.eql(
                                    availability_before,
                                    availability_after,
                                );
                                if (topology_mutation or availability_changed) {
                                    runtime_registry.control_plane.requestReconcile();
                                }
                                if (topology_mutation) {
                                    runtime_registry.ensureActiveRuntimeResidency(true) catch |err| {
                                        std.log.warn("runtime residency refresh failed after topology mutation: {s}", .{@errorName(err)});
                                    };
                                }
                                continue;
                            },
                            else => {
                                const response = try unified.buildControlError(
                                    allocator,
                                    parsed.id,
                                    "unsupported",
                                    "unsupported control operation",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                        }
                    },
                    .acheron => {
                        if (connect_gate_error) |gate| {
                            const response = try unified.buildFsrpcError(
                                allocator,
                                parsed.tag,
                                gate.code,
                                gate.message,
                            );
                            defer allocator.free(response);
                            try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                            continue;
                        }
                        const fsrpc_type = parsed.acheron_type orelse {
                            const response = try unified.buildFsrpcError(
                                allocator,
                                parsed.tag,
                                "invalid_type",
                                "missing fsrpc message type",
                            );
                            defer allocator.free(response);
                            try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                            try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                            return;
                        };
                        if (!runtime_fsrpc_version_negotiated) {
                            if (fsrpc_type != .t_version) {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "protocol_mismatch",
                                    "acheron.t_version must be negotiated first",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                                return;
                            }
                            if (parsed.version == null or !std.mem.eql(u8, parsed.version.?, fsrpc_runtime_protocol_version)) {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "protocol_mismatch",
                                    "unsupported fsrpc runtime version",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                                return;
                            }
                            runtime_fsrpc_version_negotiated = true;
                        } else if (fsrpc_type == .t_version) {
                            if (parsed.version == null or !std.mem.eql(u8, parsed.version.?, fsrpc_runtime_protocol_version)) {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "protocol_mismatch",
                                    "unsupported fsrpc runtime version",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                                return;
                            }
                        }
                        if (fsrpc_type == .t_version) {
                            const negotiated_msize = parsed.msize orelse 1_048_576;
                            const payload = try std.fmt.allocPrint(
                                allocator,
                                "{{\"msize\":{d},\"version\":\"{s}\"}}",
                                .{ negotiated_msize, fsrpc_runtime_protocol_version },
                            );
                            defer allocator.free(payload);
                            const response = try unified.buildFsrpcResponse(
                                allocator,
                                .r_version,
                                parsed.tag,
                                payload,
                            );
                            defer allocator.free(response);
                            try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                            continue;
                        }

                        const target_session_key = parsed.session_key orelse active_session_key;
                        const target_binding = session_bindings.get(target_session_key) orelse {
                            const response = try unified.buildFsrpcError(
                                allocator,
                                parsed.tag,
                                "session_not_found",
                                "unknown session_key",
                            );
                            defer allocator.free(response);
                            try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                            continue;
                        };
                        if (fsrpc_type == .t_write and target_binding.project_id != null) {
                            runtime_registry.auth_tokens.recordSessionActivity(
                                principal.role,
                                target_session_key,
                                target_binding.agent_id,
                                target_binding.project_id.?,
                                1,
                            ) catch |history_err| {
                                std.log.warn("session activity update failed: {s}", .{@errorName(history_err)});
                            };
                        }
                        var attach_state = runtime_registry.runtimeAttachSnapshot(
                            target_binding.agent_id,
                            target_binding.project_id,
                        );
                        defer attach_state.deinit(allocator);
                        if (attach_state.state != .ready) {
                            const warmed_attach_state = runtime_registry.ensureRuntimeWarmup(
                                target_binding.agent_id,
                                target_binding.project_id,
                                target_binding.project_token,
                                true,
                            ) catch |warm_err| {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "execution_failed",
                                    @errorName(warm_err),
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            };
                            attach_state.deinit(allocator);
                            attach_state = warmed_attach_state;

                            if (attach_state.state == .warming) {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "runtime_warming",
                                    "sandbox attach is still preparing for this project",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            }
                            if (attach_state.state == .err) {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    attach_state.error_code orelse "runtime_unavailable",
                                    attach_state.error_message orelse "runtime is unavailable",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            }
                        }
                        const target_runtime = runtime_registry.getOrCreate(
                            target_binding.agent_id,
                            target_binding.project_id,
                            target_binding.project_token,
                        ) catch |err| switch (err) {
                            error.InvalidAgentId => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "invalid_agent",
                                    "invalid session agent",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            error.InvalidProjectId => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "invalid_project",
                                    "invalid session project",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            error.RuntimeLimitReached => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "queue_saturated",
                                    "agent runtime limit reached",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            error.ProjectRequired => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "sandbox_mount_missing",
                                    "sandbox requires a project binding",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            error.ProjectMountsMissing => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "project_mounts_missing",
                                    "project has no workspace mounts configured",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            error.SandboxMountUnavailable => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "sandbox_mount_unavailable",
                                    "sandbox mount is unavailable",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            error.InvalidSandboxConfig => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "sandbox_invalid_config",
                                    "sandbox config is invalid",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            error.ProcessFdQuotaExceeded => {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "runtime_resource_exhausted",
                                    "sandbox runtime hit process fd quota",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            else => return err,
                        };
                        defer target_runtime.release();
                        if (fsrpc_type == .t_write and control_service_attached) {
                            runtime_registry.publishServicePresenceForBinding(
                                principal.role,
                                target_binding,
                                target_session_key,
                                connection_service_id,
                                true,
                            );
                        }
                        const local_fs_workspace_root = try runtime_registry.copyLocalFsWorkspaceRoot(allocator);
                        defer if (local_fs_workspace_root) |value| allocator.free(value);
                        if (fsrpc == null) {
                            fsrpc = try fsrpc_session.Session.initWithOptions(
                                allocator,
                                target_runtime,
                                &runtime_registry.job_index,
                                target_binding.agent_id,
                                .{
                                    .project_id = target_binding.project_id,
                                    .project_token = target_binding.project_token,
                                    .agents_dir = runtime_registry.runtime_config.agents_dir,
                                    .assets_dir = runtime_registry.runtime_config.assets_dir,
                                    .projects_dir = "projects",
                                    .local_fs_export_root = local_fs_workspace_root,
                                    .control_plane = &runtime_registry.control_plane,
                                    .actor_type = target_binding.actor_type,
                                    .actor_id = target_binding.actor_id,
                                    .is_admin = principal.role == .admin,
                                },
                            );
                            const next_bound_session_key = try allocator.dupe(u8, target_session_key);
                            allocator.free(fsrpc_bound_session_key);
                            fsrpc_bound_session_key = next_bound_session_key;
                        } else {
                            const needs_rebind = !std.mem.eql(u8, fsrpc_bound_session_key, target_session_key) or
                                !std.mem.eql(u8, fsrpc.?.agent_id, target_binding.agent_id);
                            if (needs_rebind) {
                                try fsrpc.?.setRuntimeBindingWithOptions(
                                    target_runtime,
                                    target_binding.agent_id,
                                    .{
                                        .project_id = target_binding.project_id,
                                        .project_token = target_binding.project_token,
                                        .agents_dir = runtime_registry.runtime_config.agents_dir,
                                        .assets_dir = runtime_registry.runtime_config.assets_dir,
                                        .projects_dir = "projects",
                                        .local_fs_export_root = local_fs_workspace_root,
                                        .control_plane = &runtime_registry.control_plane,
                                        .actor_type = target_binding.actor_type,
                                        .actor_id = target_binding.actor_id,
                                        .is_admin = principal.role == .admin,
                                    },
                                );
                                const next_bound_session_key = try allocator.dupe(u8, target_session_key);
                                allocator.free(fsrpc_bound_session_key);
                                fsrpc_bound_session_key = next_bound_session_key;
                            }
                        }
                        const response = try fsrpc.?.handle(&parsed);
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                        continue;
                    },
                }
            },
            0x8 => {
                try writeFrameLocked(stream, &connection_write_mutex, "", .close);
                return;
            },
            0x9 => {
                try writeFrameLocked(stream, &connection_write_mutex, frame.payload, .pong);
            },
            0xA => {},
            else => {},
        }
    }
}

fn deinitSessionBindings(allocator: std.mem.Allocator, map: *std.StringHashMapUnmanaged(SessionBinding)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        var binding = entry.value_ptr.*;
        binding.deinit(allocator);
    }
    map.deinit(allocator);
    map.* = .{};
}

fn cloneSessionBinding(allocator: std.mem.Allocator, binding: SessionBinding) !SessionBinding {
    var out = SessionBinding{
        .agent_id = try allocator.dupe(u8, binding.agent_id),
        .actor_type = try allocator.dupe(u8, binding.actor_type),
        .actor_id = try allocator.dupe(u8, binding.actor_id),
        .project_id = null,
        .project_token = null,
    };
    errdefer out.deinit(allocator);
    if (binding.project_id) |value| out.project_id = try allocator.dupe(u8, value);
    if (binding.project_token) |value| out.project_token = try allocator.dupe(u8, value);
    return out;
}

fn upsertSessionBinding(
    allocator: std.mem.Allocator,
    map: *std.StringHashMapUnmanaged(SessionBinding),
    session_key: []const u8,
    agent_id: []const u8,
    actor_type: []const u8,
    actor_id: []const u8,
    project_id: ?[]const u8,
    project_token: ?[]const u8,
) !void {
    if (map.getPtr(session_key)) |existing| {
        const next_agent_id = try allocator.dupe(u8, agent_id);
        errdefer allocator.free(next_agent_id);
        const next_actor_type = try allocator.dupe(u8, actor_type);
        errdefer allocator.free(next_actor_type);
        const next_actor_id = try allocator.dupe(u8, actor_id);
        errdefer allocator.free(next_actor_id);
        const next_project_id: ?[]u8 = if (project_id) |value| try allocator.dupe(u8, value) else null;
        errdefer if (next_project_id) |value| allocator.free(value);
        const next_project_token: ?[]u8 = if (project_token) |value| try allocator.dupe(u8, value) else null;
        errdefer if (next_project_token) |value| allocator.free(value);

        existing.deinit(allocator);
        existing.* = .{
            .agent_id = next_agent_id,
            .actor_type = next_actor_type,
            .actor_id = next_actor_id,
            .project_id = next_project_id,
            .project_token = next_project_token,
        };
        return;
    }

    try map.put(
        allocator,
        try allocator.dupe(u8, session_key),
        .{
            .agent_id = try allocator.dupe(u8, agent_id),
            .actor_type = try allocator.dupe(u8, actor_type),
            .actor_id = try allocator.dupe(u8, actor_id),
            .project_id = if (project_id) |value| try allocator.dupe(u8, value) else null,
            .project_token = if (project_token) |value| try allocator.dupe(u8, value) else null,
        },
    );
}

fn isValidSessionKey(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '-' or char == '_' or char == '.' or char == ':') continue;
        return false;
    }
    return true;
}

fn isValidActorType(value: []const u8) bool {
    if (value.len == 0 or value.len > max_actor_type_len) return false;
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '_' or char == '-') continue;
        return false;
    }
    return true;
}

fn isValidActorId(value: []const u8) bool {
    if (value.len == 0 or value.len > max_actor_id_len) return false;
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '_' or char == '-' or char == '.') continue;
        return false;
    }
    return true;
}

fn defaultActorTypeForRole(role: ConnectionRole) []const u8 {
    _ = role;
    return "user";
}

fn defaultActorIdForPrincipal(principal: ConnectionPrincipal) []const u8 {
    return principal.token_id;
}

fn parseControlPayloadObject(allocator: std.mem.Allocator, payload_json: ?[]const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, payload_json orelse "{}", .{});
}

fn getRequiredStringField(obj: std.json.ObjectMap, field: []const u8) ![]const u8 {
    const value = obj.get(field) orelse return error.MissingField;
    if (value != .string or value.string.len == 0) return error.InvalidPayload;
    return value.string;
}

fn getOptionalStringField(obj: std.json.ObjectMap, field: []const u8) ?[]const u8 {
    const value = obj.get(field) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

fn getOptionalBoolField(obj: std.json.ObjectMap, field: []const u8) ?bool {
    const value = obj.get(field) orelse return null;
    if (value != .bool) return null;
    return value.bool;
}

fn optionalStringsEqual(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null and right == null) return true;
    if (left == null or right == null) return false;
    return std.mem.eql(u8, left.?, right.?);
}

fn buildProjectActivatePayload(
    allocator: std.mem.Allocator,
    project_id: []const u8,
    project_token: ?[]const u8,
) ![]u8 {
    const escaped_project = try unified.jsonEscape(allocator, project_id);
    defer allocator.free(escaped_project);
    if (project_token) |token| {
        const escaped_token = try unified.jsonEscape(allocator, token);
        defer allocator.free(escaped_token);
        return std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
            .{ escaped_project, escaped_token },
        );
    }
    return std.fmt.allocPrint(allocator, "{{\"project_id\":\"{s}\"}}", .{escaped_project});
}

fn buildWorkspaceStatusPayloadForBinding(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    binding: SessionBinding,
    is_admin: bool,
) ![]u8 {
    const status_req = if (binding.project_id) |project_id|
        try buildProjectActivatePayload(allocator, project_id, binding.project_token)
    else
        try allocator.dupe(u8, "{}");
    defer allocator.free(status_req);

    return runtime_registry.control_plane.workspaceStatusWithRole(binding.agent_id, status_req, is_admin) catch |err| {
        std.log.warn(
            "workspace status unavailable for agent={s} project={s}: {s}",
            .{ binding.agent_id, binding.project_id orelse "null", @errorName(err) },
        );
        return try allocator.dupe(u8, "{}");
    };
}

fn buildSessionAttachStateJson(allocator: std.mem.Allocator, state: SessionAttachStateSnapshot) ![]u8 {
    const escaped_state = try unified.jsonEscape(allocator, sessionAttachStateName(state.state));
    defer allocator.free(escaped_state);
    const error_code_json = if (state.error_code) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(error_code_json);
    const error_message_json = if (state.error_message) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(error_message_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"state\":\"{s}\",\"runtime_ready\":{},\"mount_ready\":{},\"error_code\":{s},\"error_message\":{s},\"updated_at_ms\":{d}}}",
        .{
            escaped_state,
            state.runtime_ready,
            state.mount_ready,
            error_code_json,
            error_message_json,
            state.updated_at_ms,
        },
    );
}

fn buildSessionAttachAckPayload(
    allocator: std.mem.Allocator,
    session_key: []const u8,
    agent_id: []const u8,
    actor_type: []const u8,
    actor_id: []const u8,
    project_id: ?[]const u8,
    workspace_json: []const u8,
    attach_json: []const u8,
) ![]u8 {
    const escaped_session = try unified.jsonEscape(allocator, session_key);
    defer allocator.free(escaped_session);
    const escaped_agent = try unified.jsonEscape(allocator, agent_id);
    defer allocator.free(escaped_agent);
    const escaped_actor_type = try unified.jsonEscape(allocator, actor_type);
    defer allocator.free(escaped_actor_type);
    const escaped_actor_id = try unified.jsonEscape(allocator, actor_id);
    defer allocator.free(escaped_actor_id);
    const project_json = if (project_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(project_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"actor_type\":\"{s}\",\"actor_id\":\"{s}\",\"project_id\":{s},\"workspace\":{s},\"attach\":{s}}}",
        .{ escaped_session, escaped_agent, escaped_actor_type, escaped_actor_id, project_json, workspace_json, attach_json },
    );
}

fn buildSessionStatusPayload(
    allocator: std.mem.Allocator,
    session_key: []const u8,
    agent_id: []const u8,
    actor_type: []const u8,
    actor_id: []const u8,
    project_id: ?[]const u8,
    attach_json: []const u8,
    session_last_active_ms: i64,
    session_stale: bool,
    agent_last_heartbeat_ms: i64,
    agent_stale: bool,
) ![]u8 {
    const escaped_session = try unified.jsonEscape(allocator, session_key);
    defer allocator.free(escaped_session);
    const escaped_agent = try unified.jsonEscape(allocator, agent_id);
    defer allocator.free(escaped_agent);
    const escaped_actor_type = try unified.jsonEscape(allocator, actor_type);
    defer allocator.free(escaped_actor_type);
    const escaped_actor_id = try unified.jsonEscape(allocator, actor_id);
    defer allocator.free(escaped_actor_id);
    const project_json = if (project_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(project_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"actor_type\":\"{s}\",\"actor_id\":\"{s}\",\"project_id\":{s},\"attach\":{s},\"session_last_activity_ms\":{d},\"session_stale\":{},\"agent_last_heartbeat_ms\":{d},\"agent_stale\":{},\"recoverable\":true}}",
        .{
            escaped_session,
            escaped_agent,
            escaped_actor_type,
            escaped_actor_id,
            project_json,
            attach_json,
            session_last_active_ms,
            session_stale,
            agent_last_heartbeat_ms,
            agent_stale,
        },
    );
}

fn buildSessionListPayload(
    allocator: std.mem.Allocator,
    map: *const std.StringHashMapUnmanaged(SessionBinding),
    active_session_key: []const u8,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    const escaped_active = try unified.jsonEscape(allocator, active_session_key);
    defer allocator.free(escaped_active);
    try out.writer(allocator).print("{{\"active_session\":\"{s}\",\"sessions\":[", .{escaped_active});

    var first = true;
    var it = map.iterator();
    while (it.next()) |entry| {
        if (!first) try out.append(allocator, ',');
        first = false;
        const escaped_key = try unified.jsonEscape(allocator, entry.key_ptr.*);
        defer allocator.free(escaped_key);
        const escaped_agent = try unified.jsonEscape(allocator, entry.value_ptr.agent_id);
        defer allocator.free(escaped_agent);
        const escaped_actor_type = try unified.jsonEscape(allocator, entry.value_ptr.actor_type);
        defer allocator.free(escaped_actor_type);
        const escaped_actor_id = try unified.jsonEscape(allocator, entry.value_ptr.actor_id);
        defer allocator.free(escaped_actor_id);
        const project_json = if (entry.value_ptr.project_id) |project_id| blk: {
            const escaped_project = try unified.jsonEscape(allocator, project_id);
            defer allocator.free(escaped_project);
            break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_project});
        } else try allocator.dupe(u8, "null");
        defer allocator.free(project_json);
        try out.writer(allocator).print(
            "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"actor_type\":\"{s}\",\"actor_id\":\"{s}\",\"project_id\":{s}}}",
            .{ escaped_key, escaped_agent, escaped_actor_type, escaped_actor_id, project_json },
        );
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn appendSessionHistoryEntryJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    entry: SessionHistoryEntry,
) !void {
    const escaped_session = try unified.jsonEscape(allocator, entry.session_key);
    defer allocator.free(escaped_session);
    const escaped_agent = try unified.jsonEscape(allocator, entry.agent_id);
    defer allocator.free(escaped_agent);
    const escaped_project = try unified.jsonEscape(allocator, entry.project_id);
    defer allocator.free(escaped_project);
    const summary_json = if (entry.summary) |value| blk: {
        const escaped_summary = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped_summary);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_summary});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(summary_json);

    try out.writer(allocator).print(
        "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"last_active_ms\":{d},\"message_count\":{d},\"summary\":{s}}}",
        .{
            escaped_session,
            escaped_agent,
            escaped_project,
            entry.last_active_ms,
            entry.message_count,
            summary_json,
        },
    );
}

fn buildSessionRestorePayload(
    allocator: std.mem.Allocator,
    maybe_entry: ?SessionHistoryEntry,
) ![]u8 {
    if (maybe_entry == null) return allocator.dupe(u8, "{\"found\":false}");
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"found\":true,\"session\":");
    try appendSessionHistoryEntryJson(allocator, &out, maybe_entry.?);
    try out.append(allocator, '}');
    return out.toOwnedSlice(allocator);
}

fn buildSessionHistoryPayload(
    allocator: std.mem.Allocator,
    history: []const SessionHistoryEntry,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"sessions\":[");
    for (history, 0..) |entry, idx| {
        if (idx != 0) try out.append(allocator, ',');
        try appendSessionHistoryEntryJson(allocator, &out, entry);
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn isControlAdminOnly(control_type: unified.ControlType) bool {
    return switch (control_type) {
        .metrics,
        .auth_status,
        .auth_rotate,
        .node_invite_create,
        .node_join_pending_list,
        .node_join_approve,
        .node_join_deny,
        .node_join,
        .node_lease_refresh,
        .node_service_upsert,
        .node_service_get,
        .node_list,
        .node_get,
        .node_delete,
        .audit_tail,
        => true,
        else => false,
    };
}

fn sendWebSocketErrorAndClose(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    code: protocol.ErrorCode,
    message: []const u8,
) !void {
    const payload = try protocol.buildErrorWithCode(allocator, "unknown", code, message);
    defer allocator.free(payload);
    try websocket_transport.writeFrame(stream, payload, .text);
    try websocket_transport.writeFrame(stream, "", .close);
}

fn validateControlVersionPayload(allocator: std.mem.Allocator, payload_json: ?[]const u8) !void {
    const raw = payload_json orelse return error.MissingField;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidType;
    const protocol_value = parsed.value.object.get("protocol") orelse return error.MissingField;
    if (protocol_value != .string) return error.InvalidType;
    if (!std.mem.eql(u8, protocol_value.string, control_protocol_version)) return error.ProtocolMismatch;
}

const FsNodeHelloOptions = struct {
    allow_invalidations: bool = false,
};

fn validateFsNodeHelloPayload(
    allocator: std.mem.Allocator,
    payload_json: ?[]const u8,
    required_auth_token: ?[]const u8,
) !FsNodeHelloOptions {
    const raw = payload_json orelse return error.MissingField;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidType;

    const protocol_value = parsed.value.object.get("protocol") orelse return error.MissingField;
    if (protocol_value != .string) return error.InvalidType;
    if (!std.mem.eql(u8, protocol_value.string, fsrpc_node_protocol_version)) return error.ProtocolMismatch;

    const proto_value = parsed.value.object.get("proto") orelse return error.MissingField;
    if (proto_value != .integer) return error.InvalidType;
    if (proto_value.integer != fsrpc_node_proto_id) return error.ProtocolMismatch;

    if (required_auth_token) |expected| {
        const auth_value = parsed.value.object.get("auth_token") orelse return error.AuthMissing;
        if (auth_value != .string) return error.InvalidType;
        if (!std.mem.eql(u8, auth_value.string, expected)) return error.AuthFailed;
    }

    var opts = FsNodeHelloOptions{};
    if (parsed.value.object.get("subscribe_invalidations")) |value| {
        if (value != .bool) return error.InvalidType;
        opts.allow_invalidations = value.bool;
    }
    return opts;
}

fn writeFrameLocked(
    stream: *std.net.Stream,
    write_mutex: *std.Thread.Mutex,
    payload: []const u8,
    frame_type: websocket_transport.FrameType,
) !void {
    write_mutex.lock();
    defer write_mutex.unlock();
    try websocket_transport.writeFrame(stream, payload, frame_type);
}

fn isWorkspaceTopologyMutation(control_type: unified.ControlType) bool {
    return switch (control_type) {
        .node_join_request,
        .node_join_approve,
        .node_join_deny,
        .node_join,
        .node_delete,
        .project_create,
        .project_update,
        .project_delete,
        .project_mount_set,
        .project_mount_remove,
        .project_activate,
        .project_up,
        => true,
        else => false,
    };
}

fn appendAvailabilitySnapshotJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    snapshot: fs_control_plane.ControlPlane.AvailabilitySnapshot,
) !void {
    try out.appendSlice(allocator, "{\"nodes\":{\"online\":");
    try out.writer(allocator).print("{d}", .{snapshot.nodes_online});
    try out.appendSlice(allocator, ",\"total\":");
    try out.writer(allocator).print("{d}", .{snapshot.nodes_total});
    try out.appendSlice(allocator, "},\"mounts\":{\"online\":");
    try out.writer(allocator).print("{d}", .{snapshot.mounts_online});
    try out.appendSlice(allocator, ",\"degraded\":");
    try out.writer(allocator).print("{d}", .{snapshot.mounts_degraded});
    try out.appendSlice(allocator, ",\"missing\":");
    try out.writer(allocator).print("{d}", .{snapshot.mounts_missing});
    try out.appendSlice(allocator, ",\"total\":");
    try out.writer(allocator).print("{d}", .{snapshot.mounts_total});
    try out.appendSlice(allocator, "},\"project_mount_digest\":");
    try out.writer(allocator).print("{d}", .{snapshot.project_mount_digest});
    try out.appendSlice(allocator, "}");
}

fn extractNodeIdFromControlPayload(allocator: std.mem.Allocator, payload_json: []const u8) !?[]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const node_id = parsed.value.object.get("node_id") orelse return null;
    if (node_id != .string or !isValidNodeIdentifier(node_id.string)) return null;
    const copy = try allocator.dupe(u8, node_id.string);
    return @as(?[]u8, copy);
}

fn extractProjectIdFromControlPayload(allocator: std.mem.Allocator, payload_json: []const u8) !?[]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const project_id = parsed.value.object.get("project_id") orelse return null;
    if (project_id != .string or project_id.string.len == 0) return null;
    const copy = try allocator.dupe(u8, project_id.string);
    return @as(?[]u8, copy);
}

fn extractProjectTokenFromControlPayload(allocator: std.mem.Allocator, payload_json: []const u8) !?[]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const project_token = parsed.value.object.get("project_token") orelse return null;
    if (project_token != .string or project_token.string.len == 0) return null;
    const copy = try allocator.dupe(u8, project_token.string);
    return @as(?[]u8, copy);
}

fn controlMutationScope(control_type: unified.ControlType) ControlMutationScope {
    return switch (control_type) {
        .node_invite_create,
        .node_delete,
        => .node,
        .node_join_pending_list,
        .node_join_approve,
        .node_join_deny,
        => .operator,
        .project_create,
        .project_update,
        .project_delete,
        .project_mount_set,
        .project_mount_remove,
        .project_token_rotate,
        .project_token_revoke,
        .project_activate,
        .project_up,
        => .project,
        else => .none,
    };
}

fn validateControlScopeTokens(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    control_type: unified.ControlType,
    payload_json: ?[]const u8,
) !void {
    const scope = controlMutationScope(control_type);
    if (scope == .none) return;

    const raw = payload_json orelse return error.MissingField;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    if (runtime_registry.control_operator_token) |operator_token| {
        if (obj.get("operator_token")) |token_value| {
            if (token_value != .string or token_value.string.len == 0) return error.InvalidPayload;
            if (!secureTokenEql(operator_token, token_value.string)) return error.OperatorAuthFailed;
            return;
        }
    }

    switch (scope) {
        .project => {
            if (runtime_registry.control_project_scope_token) |token| {
                const field = obj.get("project_scope_token") orelse return error.MissingField;
                if (field != .string or field.string.len == 0) return error.InvalidPayload;
                if (!secureTokenEql(token, field.string)) return error.OperatorAuthFailed;
                return;
            }
        },
        .node => {
            if (runtime_registry.control_node_scope_token) |token| {
                const field = obj.get("node_scope_token") orelse return error.MissingField;
                if (field != .string or field.string.len == 0) return error.InvalidPayload;
                if (!secureTokenEql(token, field.string)) return error.OperatorAuthFailed;
                return;
            }
        },
        .operator, .none => {},
    }

    if (runtime_registry.control_operator_token != null) {
        return error.MissingField;
    }
}

fn secureTokenEql(expected: []const u8, candidate: []const u8) bool {
    if (expected.len != candidate.len) return false;
    var diff: u8 = 0;
    for (expected, candidate) |lhs, rhs| {
        diff |= lhs ^ rhs;
    }
    return diff == 0;
}

fn controlScopeName(scope: ControlMutationScope) []const u8 {
    return switch (scope) {
        .none => "none",
        .node => "node",
        .project => "project",
        .operator => "operator",
    };
}

fn appendAuditRecordJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    record: AuditRecord,
) !void {
    const escaped_agent = try unified.jsonEscape(allocator, record.agent_id);
    defer allocator.free(escaped_agent);
    const escaped_type = try unified.jsonEscape(allocator, record.control_type);
    defer allocator.free(escaped_type);
    const escaped_result = try unified.jsonEscape(allocator, record.result);
    defer allocator.free(escaped_result);
    const correlation_json = if (record.correlation_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(correlation_json);
    const error_json = if (record.error_code) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(error_json);

    try out.writer(allocator).print(
        "{{\"id\":{d},\"timestamp_ms\":{d},\"agent_id\":\"{s}\",\"control_type\":\"{s}\",\"scope\":\"{s}\",\"correlation_id\":{s},\"result\":\"{s}\",\"error_code\":{s}}}",
        .{
            record.id,
            record.timestamp_ms,
            escaped_agent,
            escaped_type,
            controlScopeName(record.scope),
            correlation_json,
            escaped_result,
            error_json,
        },
    );
}

fn buildControlErrorWithCorrelation(
    allocator: std.mem.Allocator,
    id: ?[]const u8,
    correlation_id: ?[]const u8,
    code: []const u8,
    message: []const u8,
) ![]u8 {
    const escaped_code = try unified.jsonEscape(allocator, code);
    defer allocator.free(escaped_code);
    const escaped_message = try unified.jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    const correlation_json = if (correlation_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(correlation_json);

    if (id) |request_id| {
        const escaped_id = try unified.jsonEscape(allocator, request_id);
        defer allocator.free(escaped_id);
        return std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"control\",\"type\":\"control.error\",\"id\":\"{s}\",\"ok\":false,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\",\"correlation_id\":{s}}}}}",
            .{ escaped_id, escaped_code, escaped_message, correlation_json },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.error\",\"ok\":false,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\",\"correlation_id\":{s}}}}}",
        .{ escaped_code, escaped_message, correlation_json },
    );
}

fn handleControlPlaneCommand(
    runtime_registry: *AgentRuntimeRegistry,
    control_type: unified.ControlType,
    agent_id: []const u8,
    is_admin: bool,
    payload_json: ?[]const u8,
) ![]u8 {
    return switch (control_type) {
        .node_invite_create => runtime_registry.control_plane.createNodeInvite(payload_json),
        .node_join_request => runtime_registry.control_plane.nodeJoinRequest(payload_json),
        .node_join_pending_list => runtime_registry.control_plane.listPendingNodeJoins(payload_json),
        .node_join_approve => runtime_registry.control_plane.approvePendingNodeJoin(payload_json),
        .node_join_deny => runtime_registry.control_plane.denyPendingNodeJoin(payload_json),
        .node_join => runtime_registry.control_plane.nodeJoin(payload_json),
        .node_lease_refresh => runtime_registry.control_plane.refreshNodeLease(payload_json),
        .node_service_upsert => runtime_registry.control_plane.nodeServiceUpsert(payload_json),
        .node_service_get => runtime_registry.control_plane.nodeServiceGet(payload_json),
        .agent_list => runtime_registry.listAgentsPayloadWithRole(is_admin),
        .agent_get => runtime_registry.getAgentPayloadWithRole(payload_json, is_admin),
        .node_list => runtime_registry.control_plane.listNodes(),
        .node_get => runtime_registry.control_plane.getNode(payload_json),
        .node_delete => runtime_registry.control_plane.deleteNode(payload_json),
        .project_create => runtime_registry.control_plane.createProject(payload_json),
        .project_update => runtime_registry.control_plane.updateProjectWithRole(payload_json, is_admin),
        .project_delete => runtime_registry.control_plane.deleteProjectWithRole(payload_json, is_admin),
        .project_list => runtime_registry.control_plane.listProjects(),
        .project_get => runtime_registry.control_plane.getProjectWithRole(payload_json, is_admin),
        .project_mount_set => runtime_registry.control_plane.setProjectMountWithRole(payload_json, is_admin),
        .project_mount_remove => runtime_registry.control_plane.removeProjectMountWithRole(payload_json, is_admin),
        .project_mount_list => runtime_registry.control_plane.listProjectMountsWithRole(payload_json, is_admin),
        .project_token_rotate => runtime_registry.control_plane.rotateProjectTokenWithRole(payload_json, is_admin),
        .project_token_revoke => runtime_registry.control_plane.revokeProjectTokenWithRole(payload_json, is_admin),
        .project_activate => runtime_registry.control_plane.activateProjectWithRole(agent_id, payload_json, is_admin),
        .workspace_status => runtime_registry.control_plane.workspaceStatusWithRole(agent_id, payload_json, is_admin),
        .reconcile_status => runtime_registry.control_plane.reconcileStatus(payload_json),
        .project_up => runtime_registry.control_plane.projectUpWithRole(agent_id, payload_json, is_admin),
        .audit_tail => runtime_registry.buildAuditTailPayload(payload_json),
        else => error.UnsupportedControlPlaneOperation,
    };
}

fn controlPlaneErrorCode(err: anyerror) []const u8 {
    return switch (err) {
        fs_control_plane.ControlPlaneError.InvalidPayload => "invalid_payload",
        fs_control_plane.ControlPlaneError.MissingField => "missing_field",
        fs_control_plane.ControlPlaneError.InviteNotFound => "invite_not_found",
        fs_control_plane.ControlPlaneError.InviteExpired => "invite_expired",
        fs_control_plane.ControlPlaneError.InviteRedeemed => "invite_redeemed",
        fs_control_plane.ControlPlaneError.NodeNotFound => "node_not_found",
        error.AgentNotFound => "agent_not_found",
        fs_control_plane.ControlPlaneError.NodeAuthFailed => "node_auth_failed",
        fs_control_plane.ControlPlaneError.PendingJoinNotFound => "pending_join_not_found",
        fs_control_plane.ControlPlaneError.ProjectNotFound => "project_not_found",
        fs_control_plane.ControlPlaneError.ProjectAuthFailed => "project_auth_failed",
        fs_control_plane.ControlPlaneError.ProjectProtected => "project_protected",
        fs_control_plane.ControlPlaneError.ProjectAssignmentForbidden => "project_assignment_forbidden",
        fs_control_plane.ControlPlaneError.ProjectPolicyForbidden => "project_policy_forbidden",
        fs_control_plane.ControlPlaneError.MountConflict => "mount_conflict",
        fs_control_plane.ControlPlaneError.MountNotFound => "mount_not_found",
        else => "control_plane_error",
    };
}

fn parseAgentIdFromPayload(allocator: std.mem.Allocator, payload_json: ?[]const u8) ![]u8 {
    const raw = payload_json orelse return error.MissingField;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const id_val = parsed.value.object.get("agent_id") orelse return error.MissingField;
    if (id_val != .string or id_val.string.len == 0) return error.InvalidPayload;
    return allocator.dupe(u8, id_val.string);
}

fn agentCapabilityName(value: agent_registry_mod.AgentCapability) []const u8 {
    return switch (value) {
        .chat => "chat",
        .code => "code",
        .plan => "plan",
        .research => "research",
    };
}

fn appendAgentInfoJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    agent: agent_registry_mod.AgentInfo,
) !void {
    const escaped_id = try unified.jsonEscape(allocator, agent.id);
    defer allocator.free(escaped_id);
    const escaped_name = try unified.jsonEscape(allocator, agent.name);
    defer allocator.free(escaped_name);
    const escaped_description = try unified.jsonEscape(allocator, agent.description);
    defer allocator.free(escaped_description);

    try out.writer(allocator).print(
        "{{\"id\":\"{s}\",\"name\":\"{s}\",\"description\":\"{s}\",\"is_default\":{s},\"identity_loaded\":{s},\"needs_hatching\":{s},\"capabilities\":[",
        .{
            escaped_id,
            escaped_name,
            escaped_description,
            if (agent.is_default) "true" else "false",
            if (agent.identity_loaded) "true" else "false",
            if (agent.needs_hatching) "true" else "false",
        },
    );

    for (agent.capabilities.items, 0..) |capability, index| {
        if (index > 0) try out.append(allocator, ',');
        const escaped_capability = try unified.jsonEscape(allocator, agentCapabilityName(capability));
        defer allocator.free(escaped_capability);
        try out.writer(allocator).print("\"{s}\"", .{escaped_capability});
    }

    try out.appendSlice(allocator, "]}");
}

fn resolveAgentIdFromConnectionPath(path: []const u8, default_agent_id: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/") or std.mem.startsWith(u8, path, "/?")) {
        return default_agent_id;
    }
    return null;
}

fn sendServiceUnavailable(stream: *std.net.Stream) !void {
    const payload =
        "HTTP/1.1 503 Service Unavailable\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    try stream.writeAll(payload);
}

fn runMetricsHttpServer(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    listener: *std.net.Server,
) void {
    while (true) {
        var connection = listener.accept() catch |err| {
            std.log.err("metrics accept failed: {s}", .{@errorName(err)});
            std.Thread.sleep(250 * std.time.ns_per_ms);
            continue;
        };
        defer connection.stream.close();

        handleMetricsHttpConnection(allocator, runtime_registry, &connection.stream) catch |err| {
            std.log.warn("metrics request failed: {s}", .{@errorName(err)});
        };
    }
}

fn handleMetricsHttpConnection(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    stream: *std.net.Stream,
) !void {
    var request_buf: [16 * 1024]u8 = undefined;
    const request = try readHttpRequestIntoBuffer(stream, &request_buf);
    const request_target = parseHttpRequestPath(request) orelse {
        try writeHttpStatus(stream, "400 Bad Request", "text/plain; charset=utf-8", "bad request\n");
        return;
    };
    const request_path = stripHttpRequestTargetQuery(request_target);

    if (std.mem.eql(u8, request_path, "/livez")) {
        try writeHttpStatus(stream, "200 OK", "text/plain; charset=utf-8", "ok\n");
        return;
    }

    if (std.mem.eql(u8, request_path, "/readyz")) {
        if (runtime_registry.getFirstAgentId() == null) {
            try writeHttpStatus(stream, "503 Service Unavailable", "text/plain; charset=utf-8", "not ready\n");
            return;
        }
        try writeHttpStatus(stream, "200 OK", "text/plain; charset=utf-8", "ready\n");
        return;
    }

    if (std.mem.eql(u8, request_path, "/metrics")) {
        const body = runtime_registry.metricsPrometheus() catch |err| {
            const err_msg = try std.fmt.allocPrint(allocator, "metrics formatter error: {s}\n", .{@errorName(err)});
            defer allocator.free(err_msg);
            try writeHttpStatus(stream, "500 Internal Server Error", "text/plain; charset=utf-8", err_msg);
            return;
        };
        defer allocator.free(body);
        try writeHttpStatus(stream, "200 OK", "text/plain; version=0.0.4; charset=utf-8", body);
        return;
    }

    if (!std.mem.eql(u8, request_path, "/metrics.json")) {
        try writeHttpStatus(stream, "404 Not Found", "text/plain; charset=utf-8", "not found\n");
        return;
    }

    const json_body = runtime_registry.metricsJson() catch |err| {
        const err_msg = try std.fmt.allocPrint(allocator, "{{\"error\":\"{s}\"}}\n", .{@errorName(err)});
        defer allocator.free(err_msg);
        try writeHttpStatus(stream, "500 Internal Server Error", "application/json", err_msg);
        return;
    };
    defer allocator.free(json_body);

    try writeHttpStatus(stream, "200 OK", "application/json", json_body);
}

fn readHttpRequestIntoBuffer(stream: *std.net.Stream, buffer: []u8) ![]const u8 {
    var used: usize = 0;
    while (used < buffer.len) {
        const read_n = try stream.read(buffer[used..]);
        if (read_n == 0) return error.ConnectionClosed;
        used += read_n;
        if (std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n") != null) {
            return buffer[0..used];
        }
    }
    return error.RequestTooLarge;
}

fn parseHttpRequestPath(request: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const line = request[0..line_end];
    if (!std.mem.startsWith(u8, line, "GET ")) return null;
    const path_start = 4;
    const path_end = std.mem.indexOfPos(u8, line, path_start, " ") orelse return null;
    if (path_end <= path_start) return null;
    return line[path_start..path_end];
}

fn stripHttpRequestTargetQuery(target: []const u8) []const u8 {
    const query_start = std.mem.indexOfScalar(u8, target, '?') orelse return target;
    return target[0..query_start];
}

fn writeHttpStatus(
    stream: *std.net.Stream,
    status: []const u8,
    content_type: []const u8,
    body: []const u8,
) !void {
    var header_buf: [256]u8 = undefined;
    const response_headers = try std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status, content_type, body.len },
    );
    try stream.writeAll(response_headers);
    if (body.len > 0) try stream.writeAll(body);
}

const WsTestServerCtx = struct {
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    listener: *std.net.Server,
    err_name: ?[]u8 = null,

    fn deinit(self: *WsTestServerCtx) void {
        if (self.err_name) |name| self.allocator.free(name);
    }
};

fn runSingleWsConnection(ctx: *WsTestServerCtx) void {
    var connection = ctx.listener.accept() catch |err| {
        ctx.err_name = std.fmt.allocPrint(ctx.allocator, "{s}", .{@errorName(err)}) catch null;
        return;
    };
    defer connection.stream.close();

    handleWebSocketConnection(ctx.allocator, ctx.runtime_registry, &connection.stream) catch |err| {
        ctx.err_name = std.fmt.allocPrint(ctx.allocator, "{s}", .{@errorName(err)}) catch null;
    };
}

fn setAuthTokensForTests(
    runtime_registry: *AgentRuntimeRegistry,
    admin_token: []const u8,
    user_token: []const u8,
) !void {
    const allocator = runtime_registry.allocator;
    allocator.free(runtime_registry.auth_tokens.admin_token);
    allocator.free(runtime_registry.auth_tokens.user_token);
    if (runtime_registry.auth_tokens.admin_last_target) |*target| target.deinit(allocator);
    if (runtime_registry.auth_tokens.user_last_target) |*target| target.deinit(allocator);
    for (runtime_registry.auth_tokens.admin_session_history.items) |*entry| entry.deinit(allocator);
    runtime_registry.auth_tokens.admin_session_history.deinit(allocator);
    for (runtime_registry.auth_tokens.user_session_history.items) |*entry| entry.deinit(allocator);
    runtime_registry.auth_tokens.user_session_history.deinit(allocator);
    runtime_registry.auth_tokens.admin_token = try allocator.dupe(u8, admin_token);
    runtime_registry.auth_tokens.user_token = try allocator.dupe(u8, user_token);
    runtime_registry.auth_tokens.admin_last_target = null;
    runtime_registry.auth_tokens.user_last_target = null;
    runtime_registry.auth_tokens.admin_session_history = .{};
    runtime_registry.auth_tokens.user_session_history = .{};
}

fn seedUserRememberedTargetForTests(
    runtime_registry: *AgentRuntimeRegistry,
    agent_id: []const u8,
) !void {
    const allocator = runtime_registry.allocator;
    const project_up = try runtime_registry.control_plane.projectUp(
        agent_id,
        "{\"name\":\"User Seed Project\",\"vision\":\"User Seed Project\",\"activate\":true}",
    );
    defer allocator.free(project_up);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_up, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResult;
    const project_id_value = parsed.value.object.get("project_id") orelse return error.TestExpectedResult;
    if (project_id_value != .string) return error.TestExpectedResult;

    try runtime_registry.auth_tokens.setRememberedTarget(.user, agent_id, project_id_value.string);
}

test "server_piai: admin initial binding stays on mother/system even with remembered target" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    const project_up = try runtime_registry.control_plane.projectUpWithRole(
        system_agent_id,
        "{\"name\":\"Admin Remembered\",\"vision\":\"Remembered target test\",\"activate\":false}",
        true,
    );
    defer allocator.free(project_up);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_up, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResult;
    const project_id_value = parsed.value.object.get("project_id") orelse return error.TestExpectedResult;
    if (project_id_value != .string or project_id_value.string.len == 0) return error.TestExpectedResult;

    var registry = agent_registry_mod.AgentRegistry.init(
        allocator,
        ".",
        runtime_registry.runtime_config.agents_dir,
        runtime_registry.runtime_config.assets_dir,
    );
    defer registry.deinit();
    try registry.scan();
    if (registry.getAgent("roger") == null) {
        try registry.createAgent("roger", null);
    }
    try runtime_registry.auth_tokens.setRememberedTarget(.admin, "roger", project_id_value.string);

    const initial = try runtime_registry.buildInitialSessionBinding(.admin);
    defer {
        var owned = initial.binding;
        owned.deinit(allocator);
    }
    try std.testing.expect(initial.connect_gate_error == null);
    try std.testing.expectEqualStrings(system_agent_id, initial.binding.agent_id);
    try std.testing.expect(initial.binding.project_id != null);
    try std.testing.expectEqualStrings(system_project_id, initial.binding.project_id.?);
}

fn readHttpHeadersAlloc(allocator: std.mem.Allocator, stream: *std.net.Stream, max_bytes: usize) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var buf: [1024]u8 = undefined;
    while (out.items.len < max_bytes) {
        const read_n = try stream.read(&buf);
        if (read_n == 0) return error.EndOfStream;
        try out.appendSlice(allocator, buf[0..read_n]);
        if (std.mem.indexOf(u8, out.items, "\r\n\r\n") != null) {
            return out.toOwnedSlice(allocator);
        }
    }

    return error.HeaderTooLarge;
}

fn writeClientTextFrameMasked(stream: *std.net.Stream, payload: []const u8) !void {
    var header: [10]u8 = undefined;
    var header_len: usize = 2;
    header[0] = 0x81;

    if (payload.len < 126) {
        header[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len < 65536) {
        header[1] = 0x80 | 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        std.mem.writeInt(u64, header[2..10], payload.len, .big);
        header_len = 10;
    }

    const mask_key = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    try stream.writeAll(header[0..header_len]);
    try stream.writeAll(&mask_key);

    const masked_payload = try std.heap.page_allocator.alloc(u8, payload.len);
    defer std.heap.page_allocator.free(masked_payload);
    for (payload, 0..) |byte, idx| {
        masked_payload[idx] = byte ^ mask_key[idx % 4];
    }
    try stream.writeAll(masked_payload);
}

const TestServerFrame = struct {
    opcode: u8,
    payload: []u8,

    fn deinit(self: *TestServerFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
};

fn readServerFrame(allocator: std.mem.Allocator, stream: *std.net.Stream) !TestServerFrame {
    var header: [2]u8 = undefined;
    try readExactFromStream(stream, &header);

    const fin = (header[0] & 0x80) != 0;
    if (!fin) return error.UnsupportedFragmentation;

    const opcode = header[0] & 0x0F;
    const masked = (header[1] & 0x80) != 0;
    if (masked) return error.UnexpectedMaskedServerFrame;

    var payload_len: usize = header[1] & 0x7F;
    if (payload_len == 126) {
        var ext: [2]u8 = undefined;
        try readExactFromStream(stream, &ext);
        payload_len = std.mem.readInt(u16, &ext, .big);
    } else if (payload_len == 127) {
        var ext: [8]u8 = undefined;
        try readExactFromStream(stream, &ext);
        payload_len = @intCast(std.mem.readInt(u64, &ext, .big));
    }

    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);
    if (payload_len > 0) {
        try readExactFromStream(stream, payload);
    }

    return .{ .opcode = opcode, .payload = payload };
}

fn readServerFrameForProtocolTest(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
) !TestServerFrame {
    return readServerFrame(allocator, stream);
}

fn readExactFromStream(stream: *std.net.Stream, out: []u8) !void {
    var read_total: usize = 0;
    while (read_total < out.len) {
        const read_n = try stream.read(out[read_total..]);
        if (read_n == 0) return error.EndOfStream;
        read_total += read_n;
    }
}

fn performClientHandshake(
    allocator: std.mem.Allocator,
    client: *std.net.Stream,
    path: []const u8,
) !void {
    try performClientHandshakeWithAuthorization(allocator, client, path, null);
}

fn performClientHandshakeWithBearerToken(
    allocator: std.mem.Allocator,
    client: *std.net.Stream,
    path: []const u8,
    token: []const u8,
) !void {
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
    defer allocator.free(auth_header);
    try performClientHandshakeWithAuthorization(allocator, client, path, auth_header);
}

fn performClientHandshakeWithAuthorization(
    allocator: std.mem.Allocator,
    client: *std.net.Stream,
    path: []const u8,
    authorization: ?[]const u8,
) !void {
    const auth_line = if (authorization) |value|
        try std.fmt.allocPrint(allocator, "Authorization: {s}\r\n", .{value})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(auth_line);

    const handshake = try std.fmt.allocPrint(
        allocator,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "{s}" ++
            "\r\n",
        .{ path, auth_line },
    );
    defer allocator.free(handshake);
    try client.writeAll(handshake);

    const handshake_response = try readHttpHeadersAlloc(allocator, client, 16 * 1024);
    defer allocator.free(handshake_response);
    try std.testing.expect(std.mem.indexOf(u8, handshake_response, "101 Switching Protocols") != null);
}

fn fsrpcConnectAndAttach(allocator: std.mem.Allocator, client: *std.net.Stream, connect_id: []const u8) !void {
    try writeClientTextFrameMasked(client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, client);
    defer version_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), version_ack.opcode);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    const connect_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"{s}\"}}",
        .{connect_id},
    );
    defer allocator.free(connect_req);
    try writeClientTextFrameMasked(client, connect_req);

    var connect_ack = try readServerFrame(allocator, client);
    defer connect_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), connect_ack.opcode);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"ok\":true") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_version\",\"tag\":1,\"msize\":1048576,\"version\":\"acheron-1\"}");
    var version = try readServerFrame(allocator, client);
    defer version.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version.payload, "\"type\":\"acheron.r_version\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_attach\",\"tag\":2,\"fid\":1}");
    var attach = try readServerFrame(allocator, client);
    defer attach.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach.payload, "\"type\":\"acheron.r_attach\"") != null);
}

fn fsrpcWriteChatInput(
    allocator: std.mem.Allocator,
    client: *std.net.Stream,
    content: []const u8,
) ![]u8 {
    const encoded = try unified.encodeDataB64(allocator, content);
    defer allocator.free(encoded);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_walk\",\"tag\":10,\"fid\":1,\"newfid\":2,\"path\":[\"capabilities\",\"chat\",\"control\",\"input\"]}");
    var walk = try readServerFrameForProtocolTest(allocator, client);
    defer walk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, walk.payload, "\"type\":\"acheron.r_walk\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_open\",\"tag\":11,\"fid\":2,\"mode\":\"rw\"}");
    var open = try readServerFrameForProtocolTest(allocator, client);
    defer open.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, open.payload, "\"type\":\"acheron.r_open\"") != null);

    const write_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_write\",\"tag\":12,\"fid\":2,\"offset\":0,\"data_b64\":\"{s}\"}}",
        .{encoded},
    );
    defer allocator.free(write_req);
    try writeClientTextFrameMasked(client, write_req);
    var write = try readServerFrameForProtocolTest(allocator, client);
    defer write.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, write.payload, "\"type\":\"acheron.r_write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, write.payload, "\"job\":\"job-") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, write.payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResponse;
    const payload = parsed.value.object.get("payload") orelse return error.TestExpectedResponse;
    if (payload != .object) return error.TestExpectedResponse;
    const job = payload.object.get("job") orelse return error.TestExpectedResponse;
    if (job != .string) return error.TestExpectedResponse;
    const job_name = try allocator.dupe(u8, job.string);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_clunk\",\"tag\":13,\"fid\":2}");
    var clunk = try readServerFrameForProtocolTest(allocator, client);
    defer clunk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, clunk.payload, "\"type\":\"acheron.r_clunk\"") != null);

    return job_name;
}

fn fsrpcReadJobResult(allocator: std.mem.Allocator, client: *std.net.Stream, job_name: []const u8) ![]u8 {
    const escaped_job = try unified.jsonEscape(allocator, job_name);
    defer allocator.free(escaped_job);

    const walk_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_walk\",\"tag\":20,\"fid\":1,\"newfid\":3,\"path\":[\"jobs\",\"{s}\",\"result.txt\"]}}",
        .{escaped_job},
    );
    defer allocator.free(walk_req);
    try writeClientTextFrameMasked(client, walk_req);
    var walk = try readServerFrameForProtocolTest(allocator, client);
    defer walk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, walk.payload, "\"type\":\"acheron.r_walk\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_open\",\"tag\":21,\"fid\":3,\"mode\":\"r\"}");
    var open = try readServerFrameForProtocolTest(allocator, client);
    defer open.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, open.payload, "\"type\":\"acheron.r_open\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_read\",\"tag\":22,\"fid\":3,\"offset\":0,\"count\":1048576}");
    var read = try readServerFrameForProtocolTest(allocator, client);
    defer read.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, read.payload, "\"type\":\"acheron.r_read\"") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, read.payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResponse;
    const payload = parsed.value.object.get("payload") orelse return error.TestExpectedResponse;
    if (payload != .object) return error.TestExpectedResponse;
    const data_b64 = payload.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (data_b64 != .string) return error.TestExpectedResponse;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(data_b64.string) catch return error.TestExpectedResponse;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    _ = std.base64.standard.Decoder.decode(decoded, data_b64.string) catch return error.TestExpectedResponse;

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_clunk\",\"tag\":23,\"fid\":3}");
    var clunk = try readServerFrameForProtocolTest(allocator, client);
    defer clunk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, clunk.payload, "\"type\":\"acheron.r_clunk\"") != null);

    return decoded;
}

const WorkspaceScopeSnapshot = struct {
    project_id: []u8,
    workspace_root: []u8,
    mount_paths: std.ArrayListUnmanaged([]u8) = .{},

    fn deinit(self: *WorkspaceScopeSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.project_id);
        allocator.free(self.workspace_root);
        for (self.mount_paths.items) |path| allocator.free(path);
        self.mount_paths.deinit(allocator);
        self.* = undefined;
    }
};

fn parseWorkspaceScopeSnapshotFromControlFrame(
    allocator: std.mem.Allocator,
    frame_payload: []const u8,
) !WorkspaceScopeSnapshot {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame_payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResponse;

    const payload = parsed.value.object.get("payload") orelse return error.TestExpectedResponse;
    if (payload != .object) return error.TestExpectedResponse;

    const project_id_value = payload.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_id_value != .string or project_id_value.string.len == 0) return error.TestExpectedResponse;

    const workspace_value = payload.object.get("workspace") orelse return error.TestExpectedResponse;
    if (workspace_value != .object) return error.TestExpectedResponse;

    const workspace_root_value = workspace_value.object.get("workspace_root") orelse return error.TestExpectedResponse;
    if (workspace_root_value != .string or workspace_root_value.string.len == 0) return error.TestExpectedResponse;

    var snapshot = WorkspaceScopeSnapshot{
        .project_id = try allocator.dupe(u8, project_id_value.string),
        .workspace_root = try allocator.dupe(u8, workspace_root_value.string),
    };
    errdefer snapshot.deinit(allocator);

    const mounts_value = workspace_value.object.get("mounts") orelse return error.TestExpectedResponse;
    if (mounts_value != .array) return error.TestExpectedResponse;
    for (mounts_value.array.items) |mount_item| {
        if (mount_item != .object) continue;
        const mount_path = mount_item.object.get("mount_path") orelse continue;
        if (mount_path != .string or mount_path.string.len == 0) continue;
        try snapshot.mount_paths.append(allocator, try allocator.dupe(u8, mount_path.string));
    }
    std.mem.sort([]u8, snapshot.mount_paths.items, {}, struct {
        fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);

    return snapshot;
}

fn expectWorkspaceScopeSnapshotsEqual(
    lhs: *const WorkspaceScopeSnapshot,
    rhs: *const WorkspaceScopeSnapshot,
) !void {
    try std.testing.expectEqualStrings(lhs.project_id, rhs.project_id);
    try std.testing.expectEqualStrings(lhs.workspace_root, rhs.workspace_root);
    try std.testing.expectEqual(lhs.mount_paths.items.len, rhs.mount_paths.items.len);
    for (lhs.mount_paths.items, rhs.mount_paths.items) |left_path, right_path| {
        try std.testing.expectEqualStrings(left_path, right_path);
    }
}

test "server_piai: base websocket path handles unified control/acheron chat flow and rejects legacy session.send" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");
    try seedUserRememberedTargetForTests(&runtime_registry, "user-auth");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();

    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

    try fsrpcConnectAndAttach(allocator, &client, "req-connect");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.ping\",\"id\":\"req-ping\"}");
    var pong = try readServerFrame(allocator, &client);
    defer pong.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, pong.payload, "\"type\":\"control.pong\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pong.payload, "\"payload\":{}") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.metrics\",\"id\":\"req-metrics\"}");
    var metrics = try readServerFrame(allocator, &client);
    defer metrics.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, metrics.payload, "\"type\":\"control.metrics\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics.payload, "\"nodes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics.payload, "\"projects\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics.payload, "\"node_service_events\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.debug_subscribe\",\"id\":\"req-debug-sub\"}");
    var debug_sub = try readServerFrame(allocator, &client);
    defer debug_sub.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"code\":\"unsupported_legacy_api\"") != null);

    const job_name = try fsrpcWriteChatInput(allocator, &client, "hello");
    defer allocator.free(job_name);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.debug_unsubscribe\",\"id\":\"req-debug-unsub\"}");
    var debug_unsub = try readServerFrame(allocator, &client);
    defer debug_unsub.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"code\":\"unsupported_legacy_api\"") != null);

    const result = try fsrpcReadJobResult(allocator, &client, job_name);
    defer allocator.free(result);
    try std.testing.expect(result.len > 0);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-chat\",\"type\":\"session.send\",\"content\":\"legacy\"}");
    var legacy_reply = try readServerFrame(allocator, &client);
    defer legacy_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), legacy_reply.opcode);
    try std.testing.expect(std.mem.indexOf(u8, legacy_reply.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, legacy_reply.payload, "\"code\":\"unsupported_legacy_api\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: workspace namespace stays project-scoped across user session agent switches" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var registry = agent_registry_mod.AgentRegistry.init(
        allocator,
        ".",
        runtime_registry.runtime_config.agents_dir,
        runtime_registry.runtime_config.assets_dir,
    );
    defer registry.deinit();
    try registry.scan();
    if (registry.getAgent("alice") == null) try registry.createAgent("alice", null);
    if (registry.getAgent("bob") == null) try registry.createAgent("bob", null);

    const project_up = try runtime_registry.control_plane.projectUpWithRole(
        system_agent_id,
        "{\"name\":\"Scope Test\",\"vision\":\"Project-scoped namespace\",\"activate\":false}",
        true,
    );
    defer allocator.free(project_up);

    const project_id = (try extractProjectIdFromControlPayload(allocator, project_up)) orelse return error.TestExpectedResult;
    defer allocator.free(project_id);

    try runtime_registry.auth_tokens.setRememberedTarget(.user, "alice", project_id);

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "user-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"scope-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"scope-connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, project_id) != null);

    const attach_alice = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"scope-attach-alice\",\"payload\":{{\"session_key\":\"scope-a\",\"agent_id\":\"alice\",\"project_id\":\"{s}\"}}}}",
        .{project_id},
    );
    defer allocator.free(attach_alice);
    try writeClientTextFrameMasked(&client, attach_alice);
    var attach_alice_ack = try readServerFrame(allocator, &client);
    defer attach_alice_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach_alice_ack.payload, "\"type\":\"control.session_attach\"") != null);
    var alice_scope = try parseWorkspaceScopeSnapshotFromControlFrame(allocator, attach_alice_ack.payload);
    defer alice_scope.deinit(allocator);

    const attach_bob = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"scope-attach-bob\",\"payload\":{{\"session_key\":\"scope-b\",\"agent_id\":\"bob\",\"project_id\":\"{s}\"}}}}",
        .{project_id},
    );
    defer allocator.free(attach_bob);
    try writeClientTextFrameMasked(&client, attach_bob);
    var attach_bob_ack = try readServerFrame(allocator, &client);
    defer attach_bob_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach_bob_ack.payload, "\"type\":\"control.session_attach\"") != null);
    var bob_scope = try parseWorkspaceScopeSnapshotFromControlFrame(allocator, attach_bob_ack.payload);
    defer bob_scope.deinit(allocator);

    try expectWorkspaceScopeSnapshotsEqual(&alice_scope, &bob_scope);
    try std.testing.expect(std.mem.indexOf(u8, attach_alice_ack.payload, "\"mount_path\":\"/nodes/local/fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_bob_ack.payload, "\"mount_path\":\"/nodes/local/fs\"") != null);

    try writeClientTextFrameMasked(
        &client,
        "{\"channel\":\"control\",\"type\":\"control.session_history\",\"id\":\"scope-history\",\"payload\":{\"limit\":5}}",
    );
    var history = try readServerFrame(allocator, &client);
    defer history.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, history.payload, "\"type\":\"control.session_history\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history.payload, "\"session_key\":\"scope-a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history.payload, "\"session_key\":\"scope-b\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: control.agent_list and control.agent_get expose registry metadata" {
    const allocator = std.testing.allocator;
    const nonce = std.crypto.random.int(u64);
    const root = try std.fmt.allocPrint(allocator, ".tmp-agent-registry-{d}", .{nonce});
    defer allocator.free(root);
    defer std.fs.cwd().deleteTree(root) catch {};
    try std.fs.cwd().makePath(root);

    const agents_dir = try std.fs.path.join(allocator, &.{ root, "agents" });
    defer allocator.free(agents_dir);
    try std.fs.cwd().makePath(agents_dir);

    const mother_dir = try std.fs.path.join(allocator, &.{ agents_dir, "mother" });
    defer allocator.free(mother_dir);
    try std.fs.cwd().makePath(mother_dir);
    const mother_json_path = try std.fs.path.join(allocator, &.{ mother_dir, "agent.json" });
    defer allocator.free(mother_json_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = mother_json_path,
        .data =
        \\{
        \\  "name": "Mother",
        \\  "description": "Primary orchestrator",
        \\  "is_default": true,
        \\  "capabilities": ["chat","plan"]
        \\}
        ,
    });

    const bob_dir = try std.fs.path.join(allocator, &.{ agents_dir, "bob" });
    defer allocator.free(bob_dir);
    try std.fs.cwd().makePath(bob_dir);
    const bob_json_path = try std.fs.path.join(allocator, &.{ bob_dir, "agent.json" });
    defer allocator.free(bob_json_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = bob_json_path,
        .data =
        \\{
        \\  "name": "Bob",
        \\  "description": "Worker agent",
        \\  "capabilities": ["chat","code"]
        \\}
        ,
    });

    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
        .agents_dir = agents_dir,
        .assets_dir = root,
        .default_agent_id = "mother",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");
    try seedUserRememberedTargetForTests(&runtime_registry, "user-auth");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"agent-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"agent-connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.agent_list\",\"id\":\"agent-list\"}");
    var list_reply = try readServerFrame(allocator, &client);
    defer list_reply.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, list_reply.payload, "\"type\":\"control.agent_list\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_reply.payload, "\"id\":\"mother\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_reply.payload, "\"id\":\"bob\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_reply.payload, "\"capabilities\":[\"chat\",\"plan\"]") != null);

    try writeClientTextFrameMasked(
        &client,
        "{\"channel\":\"control\",\"type\":\"control.agent_get\",\"id\":\"agent-get\",\"payload\":{\"agent_id\":\"bob\"}}",
    );
    var get_reply = try readServerFrame(allocator, &client);
    defer get_reply.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, get_reply.payload, "\"type\":\"control.agent_get\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_reply.payload, "\"id\":\"bob\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_reply.payload, "\"name\":\"Bob\"") != null);
}

test "server_piai: operator token gate protects control mutations" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");
    if (runtime_registry.control_operator_token) |token| {
        allocator.free(token);
    }
    runtime_registry.control_operator_token = try allocator.dupe(u8, "operator-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"v1\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"c1\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.project_create\",\"id\":\"p-missing\",\"payload\":{\"name\":\"NoToken\",\"vision\":\"NoToken\"}}");
    var missing_token = try readServerFrame(allocator, &client);
    defer missing_token.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, missing_token.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, missing_token.payload, "\"code\":\"missing_field\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.project_create\",\"id\":\"p-bad\",\"payload\":{\"name\":\"BadToken\",\"vision\":\"BadToken\",\"operator_token\":\"wrong\"}}");
    var bad_token = try readServerFrame(allocator, &client);
    defer bad_token.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, bad_token.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bad_token.payload, "\"code\":\"operator_auth_failed\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.project_create\",\"id\":\"p-good\",\"payload\":{\"name\":\"GoodToken\",\"vision\":\"GoodToken\",\"operator_token\":\"operator-secret\"}}");
    var good = try readServerFrame(allocator, &client);
    defer good.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, good.payload, "\"type\":\"control.project_create\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, good.payload, "\"project_id\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: fsrpc fid state survives across frames for unchanged binding" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();

    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");
    try fsrpcConnectAndAttach(allocator, &client, "fid-survive");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_walk\",\"tag\":30,\"fid\":1,\"newfid\":2,\"path\":[\"capabilities\",\"chat\"]}");
    var walk = try readServerFrame(allocator, &client);
    defer walk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, walk.payload, "\"type\":\"acheron.r_walk\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: auth matrix gates admin endpoints and handshake tokens" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var admin_client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer admin_client.close();
        try performClientHandshakeWithBearerToken(allocator, &admin_client, "/", "admin-secret");

        try writeClientTextFrameMasked(&admin_client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"admin-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
        var version_ack = try readServerFrame(allocator, &admin_client);
        defer version_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

        try writeClientTextFrameMasked(&admin_client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"admin-connect\"}");
        var connect_ack = try readServerFrame(allocator, &admin_client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"role\":\"admin\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"project_setup_required\":true") != null);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"project_setup_message\":\"Project setup required") != null);

        try writeClientTextFrameMasked(&admin_client, "{\"channel\":\"control\",\"type\":\"control.auth_status\",\"id\":\"admin-auth-status\"}");
        var auth_status = try readServerFrame(allocator, &admin_client);
        defer auth_status.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, auth_status.payload, "\"type\":\"control.auth_status\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, auth_status.payload, "\"admin_token\":\"admin-secret\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, auth_status.payload, "\"user_token\":\"user-secret\"") != null);

        try writeClientTextFrameMasked(&admin_client, "{\"channel\":\"control\",\"type\":\"control.auth_rotate\",\"id\":\"admin-auth-rotate\",\"payload\":{\"role\":\"admin\"}}");
        var auth_rotate = try readServerFrame(allocator, &admin_client);
        defer auth_rotate.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, auth_rotate.payload, "\"type\":\"control.auth_rotate\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, auth_rotate.payload, "\"role\":\"admin\"") != null);

        try writeClientTextFrameMasked(
            &admin_client,
            "{\"channel\":\"control\",\"type\":\"control.audit_tail\",\"id\":\"admin-audit\",\"payload\":{\"limit\":10}}",
        );
        var admin_audit = try readServerFrame(allocator, &admin_client);
        defer admin_audit.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, admin_audit.payload, "\"type\":\"control.audit_tail\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, admin_audit.payload, "\"control_type\":\"control.auth_rotate\"") != null);

        try websocket_transport.writeFrame(&admin_client, "", .close);
        var close_reply = try readServerFrame(allocator, &admin_client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var user_client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer user_client.close();
        try performClientHandshakeWithBearerToken(allocator, &user_client, "/", "user-secret");

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"user-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
        var version_ack = try readServerFrame(allocator, &user_client);
        defer version_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"user-connect\"}");
        var connect_ack = try readServerFrame(allocator, &user_client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"role\":\"user\"") != null);

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.metrics\",\"id\":\"user-metrics\"}");
        var forbidden_metrics = try readServerFrame(allocator, &user_client);
        defer forbidden_metrics.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_metrics.payload, "\"type\":\"control.error\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_metrics.payload, "\"code\":\"forbidden\"") != null);

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.auth_status\",\"id\":\"user-auth-status\"}");
        var forbidden_status = try readServerFrame(allocator, &user_client);
        defer forbidden_status.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_status.payload, "\"type\":\"control.error\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_status.payload, "\"code\":\"forbidden\"") != null);

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.auth_rotate\",\"id\":\"user-auth-rotate\",\"payload\":{\"role\":\"user\"}}");
        var forbidden_rotate = try readServerFrame(allocator, &user_client);
        defer forbidden_rotate.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_rotate.payload, "\"type\":\"control.error\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_rotate.payload, "\"code\":\"forbidden\"") != null);

        const attach_default = try std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"user-attach-default\",\"payload\":{{\"session_key\":\"main\",\"agent_id\":\"{s}\"}}}}",
            .{runtime_registry.default_agent_id},
        );
        defer allocator.free(attach_default);
        try writeClientTextFrameMasked(&user_client, attach_default);
        var forbidden_attach = try readServerFrame(allocator, &user_client);
        defer forbidden_attach.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_attach.payload, "\"type\":\"control.error\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_attach.payload, "\"code\":\"missing_field\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, forbidden_attach.payload, "project_id is required") != null);

        try websocket_transport.writeFrame(&user_client, "", .close);
        var close_reply = try readServerFrame(allocator, &user_client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var bad_client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer bad_client.close();
        try performClientHandshakeWithBearerToken(allocator, &bad_client, "/", "wrong-secret");

        var auth_error = try readServerFrame(allocator, &bad_client);
        defer auth_error.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, auth_error.payload, "\"code\":\"provider_auth_failed\"") != null);

        var close_reply = try readServerFrame(allocator, &bad_client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var missing_client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer missing_client.close();
        try performClientHandshake(allocator, &missing_client, "/");

        var auth_error = try readServerFrame(allocator, &missing_client);
        defer auth_error.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, auth_error.payload, "\"code\":\"provider_auth_failed\"") != null);

        var close_reply = try readServerFrame(allocator, &missing_client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: user connect advertises provisioning gate when no remembered non-system target exists" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var user_client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer user_client.close();
    try performClientHandshakeWithBearerToken(allocator, &user_client, "/", "user-secret");

    try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"user-avoid-primary-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &user_client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"user-avoid-primary-connect\"}");
    var connect_ack = try readServerFrame(allocator, &user_client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"requires_session_attach\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"connect_gate\":{\"code\":\"provisioning_required\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"project_setup_required\":false") != null);

    const attach_primary = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"user-attach-primary-user-id\",\"payload\":{{\"session_key\":\"main\",\"agent_id\":\"{s}\"}}}}",
        .{runtime_registry.default_agent_id},
    );
    defer allocator.free(attach_primary);
    try writeClientTextFrameMasked(&user_client, attach_primary);
    var attach_forbidden = try readServerFrame(allocator, &user_client);
    defer attach_forbidden.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach_forbidden.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_forbidden.payload, "\"code\":\"missing_field\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_forbidden.payload, "project_id is required") != null);

    try websocket_transport.writeFrame(&user_client, "", .close);
    var close_reply = try readServerFrame(allocator, &user_client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: connect and session_status expose actor identity metadata" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "user-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"actor-meta-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"actor-meta-connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"actor_type\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"actor_id\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"workspace\":{") != null);

    try writeClientTextFrameMasked(
        &client,
        "{\"channel\":\"control\",\"type\":\"control.session_status\",\"id\":\"actor-meta-status\",\"payload\":{\"session_key\":\"main\"}}",
    );
    var status_ack = try readServerFrame(allocator, &client);
    defer status_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, status_ack.payload, "\"type\":\"control.session_status\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_ack.payload, "\"actor_type\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_ack.payload, "\"actor_id\":\"user\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: user session_attach forbids actor identity override" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");
    try seedUserRememberedTargetForTests(&runtime_registry, runtime_registry.default_agent_id);
    const remembered_target = runtime_registry.auth_tokens.user_last_target orelse return error.TestExpectedResult;
    const remembered_project_id = remembered_target.project_id;

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "user-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"actor-guard-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"actor-guard-connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    const override_attach = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"actor-guard-override\",\"payload\":{{\"session_key\":\"main\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"actor_type\":\"agent\",\"actor_id\":\"intruder\"}}}}",
        .{ runtime_registry.default_agent_id, remembered_project_id },
    );
    defer allocator.free(override_attach);
    try writeClientTextFrameMasked(&client, override_attach);
    var override_error = try readServerFrame(allocator, &client);
    defer override_error.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, override_error.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, override_error.payload, "\"code\":\"forbidden\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, override_error.payload, "cannot override actor identity") != null);

    const valid_attach = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"actor-guard-valid\",\"payload\":{{\"session_key\":\"main\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\"}}}}",
        .{ runtime_registry.default_agent_id, remembered_project_id },
    );
    defer allocator.free(valid_attach);
    try writeClientTextFrameMasked(&client, valid_attach);
    var attach_ack = try readServerFrame(allocator, &client);
    defer attach_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach_ack.payload, "\"type\":\"control.session_attach\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_ack.payload, "\"actor_type\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_ack.payload, "\"actor_id\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_ack.payload, "\"workspace\":{") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: control.session_history and control.session_restore survive reconnect" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");
    try seedUserRememberedTargetForTests(&runtime_registry, runtime_registry.default_agent_id);
    const remembered_target = runtime_registry.auth_tokens.user_last_target orelse return error.TestExpectedResult;
    const remembered_project_id = remembered_target.project_id;

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var user_client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer user_client.close();
        try performClientHandshakeWithBearerToken(allocator, &user_client, "/", "user-secret");

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"history-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
        var version_ack = try readServerFrame(allocator, &user_client);
        defer version_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"history-connect\"}");
        var connect_ack = try readServerFrame(allocator, &user_client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

        const attach_payload = try std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"history-attach\",\"payload\":{{\"session_key\":\"work-1\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\"}}}}",
            .{ runtime_registry.default_agent_id, remembered_project_id },
        );
        defer allocator.free(attach_payload);
        try writeClientTextFrameMasked(&user_client, attach_payload);
        var attach_ack = try readServerFrame(allocator, &user_client);
        defer attach_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, attach_ack.payload, "\"type\":\"control.session_attach\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, attach_ack.payload, "\"workspace\":{") != null);

        try writeClientTextFrameMasked(
            &user_client,
            "{\"channel\":\"control\",\"type\":\"control.session_history\",\"id\":\"history-list\",\"payload\":{\"limit\":5}}",
        );
        var history = try readServerFrame(allocator, &user_client);
        defer history.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, history.payload, "\"type\":\"control.session_history\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, history.payload, "\"session_key\":\"work-1\"") != null);

        try websocket_transport.writeFrame(&user_client, "", .close);
        var close_reply = try readServerFrame(allocator, &user_client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var user_client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer user_client.close();
        try performClientHandshakeWithBearerToken(allocator, &user_client, "/", "user-secret");

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"restore-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
        var version_ack = try readServerFrame(allocator, &user_client);
        defer version_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

        try writeClientTextFrameMasked(&user_client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"restore-connect\"}");
        var connect_ack = try readServerFrame(allocator, &user_client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

        const restore_payload = try std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"control\",\"type\":\"control.session_restore\",\"id\":\"restore-last\",\"payload\":{{\"agent_id\":\"{s}\"}}}}",
            .{runtime_registry.default_agent_id},
        );
        defer allocator.free(restore_payload);
        try writeClientTextFrameMasked(&user_client, restore_payload);
        var restore = try readServerFrame(allocator, &user_client);
        defer restore.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, restore.payload, "\"type\":\"control.session_restore\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, restore.payload, "\"found\":true") != null);
        try std.testing.expect(std.mem.indexOf(u8, restore.payload, "\"session_key\":\"work-1\"") != null);

        try websocket_transport.writeFrame(&user_client, "", .close);
        var close_reply = try readServerFrame(allocator, &user_client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: control.auth_rotate reports storage_error when token persistence fails" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    if (runtime_registry.auth_tokens.path) |path| allocator.free(path);
    runtime_registry.auth_tokens.path = try allocator.dupe(u8, "/");
    const previous_admin = try allocator.dupe(u8, runtime_registry.auth_tokens.admin_token);
    defer allocator.free(previous_admin);

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"rotate-fail-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"rotate-fail-connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.auth_rotate\",\"id\":\"rotate-fail\",\"payload\":{\"role\":\"admin\"}}");
    var rotate_error = try readServerFrame(allocator, &client);
    defer rotate_error.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, rotate_error.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rotate_error.payload, "\"code\":\"storage_error\"") != null);

    try std.testing.expectEqualStrings(previous_admin, runtime_registry.auth_tokens.admin_token);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.ping\",\"id\":\"rotate-fail-ping\"}");
    var pong = try readServerFrame(allocator, &client);
    defer pong.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, pong.payload, "\"type\":\"control.pong\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: session_attach rejects project changes while jobs are in-flight" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    const busy_job = try runtime_registry.job_index.createJob(runtime_registry.default_agent_id, null);
    defer allocator.free(busy_job);
    try runtime_registry.job_index.markRunning(busy_job);

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"busy-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"busy-connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    const attach_request = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"busy-attach\",\"payload\":{{\"session_key\":\"main\",\"agent_id\":\"{s}\",\"project_id\":\"proj-busy\"}}}}",
        .{runtime_registry.default_agent_id},
    );
    defer allocator.free(attach_request);
    try writeClientTextFrameMasked(&client, attach_request);

    var attach_error = try readServerFrame(allocator, &client);
    defer attach_error.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach_error.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_error.payload, "\"code\":\"session_busy\"") != null);

    try writeClientTextFrameMasked(
        &client,
        "{\"channel\":\"control\",\"type\":\"control.audit_tail\",\"id\":\"busy-audit\",\"payload\":{\"limit\":10}}",
    );
    var audit_reply = try readServerFrame(allocator, &client);
    defer audit_reply.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, audit_reply.payload, "\"type\":\"control.audit_tail\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_reply.payload, "\"control_type\":\"control.session_attach\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_reply.payload, "\"error_code\":\"session_busy\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: session_attach forbids mother on non-system project" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    const project_up_payload = "{\"name\":\"NonSystem\",\"vision\":\"non-system\",\"activate\":false}";
    const project_up_result = try runtime_registry.control_plane.projectUpWithRole(system_agent_id, project_up_payload, true);
    defer allocator.free(project_up_result);

    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, project_up_result, .{});
    defer parsed_project.deinit();
    if (parsed_project.value != .object) return error.TestExpectedResult;
    const project_id_val = parsed_project.value.object.get("project_id") orelse return error.TestExpectedResult;
    if (project_id_val != .string or project_id_val.string.len == 0) return error.TestExpectedResult;
    const non_system_project_id = project_id_val.string;

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"mother-guard-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"mother-guard-connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    const attach_request = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.session_attach\",\"id\":\"mother-guard-attach\",\"payload\":{{\"session_key\":\"main\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\"}}}}",
        .{ system_agent_id, non_system_project_id },
    );
    defer allocator.free(attach_request);
    try writeClientTextFrameMasked(&client, attach_request);

    var attach_error = try readServerFrame(allocator, &client);
    defer attach_error.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach_error.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_error.payload, "\"code\":\"forbidden\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, attach_error.payload, "mother can only attach to system project") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: debug subscription control operations are unsupported in acheron-native mode" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");
    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"ver\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var version_ack = try readServerFrame(allocator, &client);
    defer version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);
    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"conn\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.debug_subscribe\",\"id\":\"sub\"}");
    var subscribe = try readServerFrame(allocator, &client);
    defer subscribe.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, subscribe.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, subscribe.payload, "\"code\":\"unsupported_legacy_api\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.debug_unsubscribe\",\"id\":\"unsub\"}");
    var unsubscribe = try readServerFrame(allocator, &client);
    defer unsubscribe.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, unsubscribe.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, unsubscribe.payload, "\"code\":\"unsupported_legacy_api\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: node service watch control path is deprecated" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var subscriber = try std.net.tcpConnectToAddress(listener.listen_address);
    defer subscriber.close();
    try performClientHandshakeWithBearerToken(allocator, &subscriber, "/", "admin-secret");
    try writeClientTextFrameMasked(&subscriber, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"sub-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var sub_version_ack = try readServerFrame(allocator, &subscriber);
    defer sub_version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, sub_version_ack.payload, "\"type\":\"control.version_ack\"") != null);
    try writeClientTextFrameMasked(&subscriber, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"sub-connect\"}");
    var sub_connect_ack = try readServerFrame(allocator, &subscriber);
    defer sub_connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, sub_connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    try writeClientTextFrameMasked(&subscriber, "{\"channel\":\"control\",\"type\":\"control.node_service_watch\",\"id\":\"sub-watch\",\"payload\":{}}");
    var sub_watch_ack = try readServerFrame(allocator, &subscriber);
    defer sub_watch_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, sub_watch_ack.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sub_watch_ack.payload, "\"code\":\"unsupported_legacy_api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sub_watch_ack.payload, "UnsupportedType") != null);

    try websocket_transport.writeFrame(&subscriber, "", .close);
    var sub_close = try readServerFrame(allocator, &subscriber);
    defer sub_close.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), sub_close.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: base path routes all connections to default runtime" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer client.close();
        try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

        try fsrpcConnectAndAttach(allocator, &client, "a-connect");
        const alpha_job = try fsrpcWriteChatInput(allocator, &client, "alpha hello");
        defer allocator.free(alpha_job);

        try websocket_transport.writeFrame(&client, "", .close);
        var close_reply = try readServerFrame(allocator, &client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer client.close();
        try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

        try fsrpcConnectAndAttach(allocator, &client, "b-connect");
        const beta_job = try fsrpcWriteChatInput(allocator, &client, "beta hello");
        defer allocator.free(beta_job);

        try websocket_transport.writeFrame(&client, "", .close);
        var close_reply = try readServerFrame(allocator, &client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    const runtime = try runtime_registry.getOrCreate(runtime_registry.default_agent_id, null, null);
    defer runtime.release();
    try std.testing.expect(runtime.kind == .local);
    const snapshot = try runtime.local.?.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "alpha hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "beta hello") != null);
    try std.testing.expectEqual(@as(usize, 1), runtime_registry.by_agent.count());

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: runtime cap does not block repeated base-path reconnects" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.initWithLimits(
        allocator,
        .{ .ltm_directory = "", .ltm_filename = "" },
        null,
        1,
    );
    defer runtime_registry.deinit();
    try setAuthTokensForTests(&runtime_registry, "admin-secret", "user-secret");

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer client.close();
        try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

        try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"alpha-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
        var version_ack = try readServerFrame(allocator, &client);
        defer version_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

        try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"alpha-connect\"}");
        var connect_ack = try readServerFrame(allocator, &client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

        try websocket_transport.writeFrame(&client, "", .close);
        var close_reply = try readServerFrame(allocator, &client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer client.close();
        try performClientHandshakeWithBearerToken(allocator, &client, "/", "admin-secret");

        try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"beta-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
        var version_ack = try readServerFrame(allocator, &client);
        defer version_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, version_ack.payload, "\"type\":\"control.version_ack\"") != null);

        try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"beta-connect\"}");
        var connect_ack = try readServerFrame(allocator, &client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

        var close_reply = try readServerFrame(allocator, &client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    try std.testing.expectEqual(@as(usize, 1), runtime_registry.by_agent.count());
    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: project runtime switches persona when agent changes" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.initWithLimits(
        allocator,
        .{ .ltm_directory = "", .ltm_filename = "" },
        null,
        1,
    );
    defer runtime_registry.deinit();

    const project_id = "proj-persona-switch";
    const first_runtime = try runtime_registry.getOrCreate(runtime_registry.default_agent_id, project_id, null);
    defer first_runtime.release();
    try std.testing.expect(runtime_registry.hasRuntimeForBinding(runtime_registry.default_agent_id, project_id));
    try std.testing.expectEqual(@as(usize, 1), runtime_registry.by_agent.count());

    const second_runtime = try runtime_registry.getOrCreate(system_agent_id, project_id, null);
    defer second_runtime.release();
    try std.testing.expect(second_runtime != first_runtime);
    try std.testing.expect(!runtime_registry.hasRuntimeForBinding(runtime_registry.default_agent_id, project_id));
    try std.testing.expect(runtime_registry.hasRuntimeForBinding(system_agent_id, project_id));
    try std.testing.expectEqual(@as(usize, 1), runtime_registry.by_agent.count());

    const stale_lookup = runtime_registry.getRuntimeForBindingIfReady(runtime_registry.default_agent_id, project_id);
    try std.testing.expect(stale_lookup == null);

    const active_lookup = runtime_registry.getRuntimeForBindingIfReady(system_agent_id, project_id) orelse return error.TestExpectedResult;
    active_lookup.release();

    runtime_registry.mutex.lock();
    defer runtime_registry.mutex.unlock();
    const active_entry = runtime_registry.by_agent.getPtr(project_id) orelse return error.TestExpectedResult;
    try std.testing.expectEqualStrings(system_agent_id, active_entry.runtime_agent_id);
}

test "server_piai: getOrCreate replaces unhealthy runtime for same agent" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.initWithLimits(
        allocator,
        .{ .ltm_directory = "", .ltm_filename = "" },
        null,
        1,
    );
    defer runtime_registry.deinit();

    const project_id = "proj-unhealthy-runtime";
    const first_runtime = try runtime_registry.getOrCreate(runtime_registry.default_agent_id, project_id, null);
    runtime_registry.mutex.lock();
    {
        const entry = runtime_registry.by_agent.getPtr(project_id) orelse return error.TestExpectedResult;
        entry.runtime.kind = .local_sandbox;
        entry.runtime.sandbox = null;
    }
    runtime_registry.mutex.unlock();

    const second_runtime = try runtime_registry.getOrCreate(runtime_registry.default_agent_id, project_id, null);
    defer second_runtime.release();
    defer first_runtime.release();

    try std.testing.expect(second_runtime != first_runtime);
    try std.testing.expect(runtime_registry.hasRuntimeForBinding(runtime_registry.default_agent_id, project_id));
    try std.testing.expectEqual(@as(usize, 1), runtime_registry.by_agent.count());
}

test "server_piai: ready runtime lookup rejects unhealthy binding" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.initWithLimits(
        allocator,
        .{ .ltm_directory = "", .ltm_filename = "" },
        null,
        1,
    );
    defer runtime_registry.deinit();

    const project_id = "proj-unhealthy-ready-lookup";
    const runtime = try runtime_registry.getOrCreate(runtime_registry.default_agent_id, project_id, null);
    defer runtime.release();

    runtime_registry.mutex.lock();
    {
        const entry = runtime_registry.by_agent.getPtr(project_id) orelse return error.TestExpectedResult;
        entry.runtime.kind = .local_sandbox;
        entry.runtime.sandbox = null;
    }
    runtime_registry.mutex.unlock();

    const ready = runtime_registry.getRuntimeForBindingIfReady(runtime_registry.default_agent_id, project_id);
    try std.testing.expect(ready == null);
    try std.testing.expect(!runtime_registry.hasRuntimeForBinding(runtime_registry.default_agent_id, project_id));
    try std.testing.expectEqual(@as(usize, 0), runtime_registry.by_agent.count());
}

test "server_piai: unhealthy binding drop marks warmup error" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.initWithLimits(
        allocator,
        .{ .ltm_directory = "", .ltm_filename = "" },
        null,
        1,
    );
    defer runtime_registry.deinit();

    const project_id = "proj-unhealthy-warmup-error";
    const runtime = try runtime_registry.getOrCreate(runtime_registry.default_agent_id, project_id, null);
    defer runtime.release();

    runtime_registry.mutex.lock();
    {
        const entry = runtime_registry.by_agent.getPtr(project_id) orelse return error.TestExpectedResult;
        entry.runtime.kind = .local_sandbox;
        entry.runtime.sandbox = null;
    }
    runtime_registry.mutex.unlock();

    try std.testing.expect(runtime_registry.dropUnhealthyRuntimeForBinding(
        runtime_registry.default_agent_id,
        project_id,
        "runtime_unhealthy",
        "project runtime became unhealthy",
    ));

    const binding_key = try runtime_registry.runtimeBindingKey(runtime_registry.default_agent_id, project_id);
    defer allocator.free(binding_key);

    const snapshot = runtime_registry.runtimeAttachSnapshotByKey(binding_key);
    defer snapshot.deinit(allocator);

    try std.testing.expectEqual(SessionAttachState.err, snapshot.state);
    try std.testing.expectEqualStrings("runtime_unhealthy", snapshot.error_code orelse "");
    try std.testing.expect(!runtime_registry.hasRuntimeForBinding(runtime_registry.default_agent_id, project_id));
}

test "server_piai: websocket rejects unsupported route version" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_registry = &runtime_registry,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();
    try performClientHandshake(allocator, &client, "/v1/agents/default/stream");

    var invalid_path_error = try readServerFrame(allocator, &client);
    defer invalid_path_error.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), invalid_path_error.opcode);
    try std.testing.expect(std.mem.indexOf(u8, invalid_path_error.payload, "\"code\":\"invalid_envelope\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, invalid_path_error.payload, "invalid websocket path") != null);

    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: resolve connection path maps base URL to default agent" {
    const resolved_root = resolveAgentIdFromConnectionPath("/", "default") orelse return error.TestExpectedAgent;
    try std.testing.expectEqualStrings("default", resolved_root);
    const resolved_query = resolveAgentIdFromConnectionPath("/?session=main", "default") orelse return error.TestExpectedAgent;
    try std.testing.expectEqualStrings("default", resolved_query);
    try std.testing.expect(resolveAgentIdFromConnectionPath("/v2/agents/default/stream", "default") == null);
    try std.testing.expect(resolveAgentIdFromConnectionPath("/v1/agents/default/stream", "default") == null);
}

test "server_piai: pathMatchesControlTarget only matches control namespace root path" {
    try std.testing.expect(pathMatchesControlTarget("global/projects/control/up.json", "global/projects/control/up.json"));
    try std.testing.expect(pathMatchesControlTarget("/global/projects/control/up.json", "global/projects/control/up.json"));
    try std.testing.expect(pathMatchesControlTarget("/global/projects/control/up.json/", "global/projects/control/up.json"));
    try std.testing.expect(!pathMatchesControlTarget("workspace/global/projects/control/up.json", "global/projects/control/up.json"));
}

test "server_piai: runtime dispatch synthetic service docs are discoverable" {
    const services_index = runtimeDispatchSyntheticReadContent("/global/services/SERVICES.json") orelse return error.TestExpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, services_index, "\"service_id\":\"projects\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index, "\"service_id\":\"agents\"") != null);

    const projects_schema = runtimeDispatchSyntheticReadContent("/global/projects/SCHEMA.json") orelse return error.TestExpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, projects_schema, "\"service_id\":\"projects\"") != null);
}

test "server_piai: projects control path matcher is global-only" {
    try std.testing.expect(isProjectsControlPath("/global/projects/control/up.json"));
    try std.testing.expect(isProjectsControlPath("global/projects/control/list.json"));
    try std.testing.expect(!isProjectsControlPath("/agents/self/projects/control/invoke.json"));
    try std.testing.expect(!isProjectsControlPath("/global/mounts/control/up.json"));
}

test "server_piai: agents control path matcher is global-only" {
    try std.testing.expect(isAgentsControlPath("/global/agents/control/create.json"));
    try std.testing.expect(isAgentsControlPath("global/agents/control/list.json"));
    try std.testing.expect(!isAgentsControlPath("/agents/self/agents/control/invoke.json"));
    try std.testing.expect(!isAgentsControlPath("/global/projects/control/create.json"));
}

test "server_piai: parseHttpRequestPath parses GET line" {
    const request =
        "GET /metrics HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "\r\n";
    const path = parseHttpRequestPath(request) orelse return error.TestExpectedPath;
    try std.testing.expectEqualStrings("/metrics", path);
}

test "server_piai: stripHttpRequestTargetQuery removes query string" {
    try std.testing.expectEqualStrings("/metrics", stripHttpRequestTargetQuery("/metrics?format=json"));
    try std.testing.expectEqualStrings("/readyz", stripHttpRequestTargetQuery("/readyz"));
}

test "server_piai: metrics include retained node service event telemetry" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();

    const metrics_json = try runtime_registry.metricsJson();
    defer allocator.free(metrics_json);
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "\"node_service_events\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "\"retained\"") != null);

    const metrics_prom = try runtime_registry.metricsPrometheus();
    defer allocator.free(metrics_prom);
    try std.testing.expect(std.mem.indexOf(u8, metrics_prom, "spiderweb_node_service_events_retained_events") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics_prom, "spiderweb_node_service_events_retained_window_ms") != null);
}

test "server_piai: extract project payload helpers parse id and token" {
    const allocator = std.testing.allocator;
    const payload = "{\"project_id\":\"proj-7\",\"project_token\":\"proj-token-7\"}";

    const project_id = try extractProjectIdFromControlPayload(allocator, payload);
    defer if (project_id) |value| allocator.free(value);
    try std.testing.expect(project_id != null);
    try std.testing.expectEqualStrings("proj-7", project_id.?);

    const project_token = try extractProjectTokenFromControlPayload(allocator, payload);
    defer if (project_token) |value| allocator.free(value);
    try std.testing.expect(project_token != null);
    try std.testing.expectEqualStrings("proj-token-7", project_token.?);

    const token_missing = try extractProjectTokenFromControlPayload(allocator, "{\"project_id\":\"proj-7\"}");
    try std.testing.expect(token_missing == null);
}

test "server_piai: extract node id helper parses valid payload" {
    const allocator = std.testing.allocator;
    const payload = "{\"node_id\":\"node-7\",\"service_delta\":{\"changed\":true}}";
    const node_id = try extractNodeIdFromControlPayload(allocator, payload);
    defer if (node_id) |value| allocator.free(value);
    try std.testing.expect(node_id != null);
    try std.testing.expectEqualStrings("node-7", node_id.?);

    const missing = try extractNodeIdFromControlPayload(allocator, "{\"service_delta\":{}}");
    try std.testing.expect(missing == null);
}

test "server_piai: user node service visibility is project mounted-node scoped" {
    const allocator = std.testing.allocator;
    var runtime_registry = AgentRuntimeRegistry.init(allocator, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, null);
    defer runtime_registry.deinit();

    const join_payload = try runtime_registry.control_plane.ensureNode("node-a", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(join_payload);
    const node_registration = try parseNodeRegistrationFromJoinPayload(allocator, join_payload);
    defer {
        allocator.free(node_registration.node_id);
        allocator.free(node_registration.node_secret);
    }

    const project_created = try runtime_registry.control_plane.createProject(
        "{\"name\":\"ScopedProject\",\"vision\":\"ScopedProject\",\"access_policy\":{\"actions\":{\"observe\":\"open\"}}}",
    );
    defer allocator.free(project_created);
    const project_id = try extractProjectIdFromControlPayload(allocator, project_created);
    defer if (project_id) |value| allocator.free(value);
    try std.testing.expect(project_id != null);

    const mount_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"mount_path\":\"/nodes/node-a/fs\",\"node_id\":\"{s}\",\"export_name\":\"fs\"}}",
        .{ project_id.?, node_registration.node_id },
    );
    defer allocator.free(mount_payload);
    const mount_result = try runtime_registry.control_plane.setProjectMountWithRole(mount_payload, false);
    defer allocator.free(mount_result);

    try std.testing.expect(runtime_registry.control_plane.projectAllowsNodeServiceEvent(
        project_id.?,
        "bob",
        null,
        node_registration.node_id,
        false,
    ));
    try std.testing.expect(!runtime_registry.control_plane.projectAllowsNodeServiceEvent(
        project_id.?,
        "bob",
        null,
        "node-missing",
        false,
    ));
    try std.testing.expect(!runtime_registry.control_plane.projectAllowsNodeServiceEvent(
        project_id.?,
        "bob",
        null,
        "node-other",
        false,
    ));
}

test "server_piai: validateFsNodeHelloPayload enforces optional auth_token" {
    const allocator = std.testing.allocator;
    _ = try validateFsNodeHelloPayload(
        allocator,
        "{\"protocol\":\"unified-v2-fs\",\"proto\":2}",
        null,
    );
    _ = try validateFsNodeHelloPayload(
        allocator,
        "{\"protocol\":\"unified-v2-fs\",\"proto\":2,\"auth_token\":\"secret\"}",
        "secret",
    );
    try std.testing.expectError(
        error.AuthMissing,
        validateFsNodeHelloPayload(
            allocator,
            "{\"protocol\":\"unified-v2-fs\",\"proto\":2}",
            "secret",
        ),
    );
    try std.testing.expectError(
        error.AuthFailed,
        validateFsNodeHelloPayload(
            allocator,
            "{\"protocol\":\"unified-v2-fs\",\"proto\":2,\"auth_token\":\"wrong\"}",
            "secret",
        ),
    );
}

test "server_piai: node fs route parser extracts node id" {
    const route = parseNodeFsRoute("/v2/fs/node/node-17") orelse return error.TestExpectedResponse;
    try std.testing.expectEqualStrings("node-17", route);
    const route_q = parseNodeFsRoute("/v2/fs/node/node_17?session=a") orelse return error.TestExpectedResponse;
    try std.testing.expectEqualStrings("node_17", route_q);
    try std.testing.expect(parseNodeFsRoute("/v2/fs/node/") == null);
    try std.testing.expect(parseNodeFsRoute("/v2/fs/node/node:bad") == null);
}

test "server_piai: rewriteAcheronTag rewrites top-level tag" {
    const allocator = std.testing.allocator;
    const raw = "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":7,\"payload\":{\"name\":\"a\"}}";
    const rewritten = try rewriteAcheronTag(allocator, raw, 99);
    defer allocator.free(rewritten);
    try std.testing.expect(std.mem.indexOf(u8, rewritten, "\"tag\":99") != null);
    try std.testing.expect(std.mem.indexOf(u8, rewritten, "\"type\":\"acheron.t_fs_lookup\"") != null);
}

test "server_piai: agent id validation allows safe identifiers only" {
    try std.testing.expect(AgentRuntimeRegistry.isValidAgentId("alpha-1"));
    try std.testing.expect(AgentRuntimeRegistry.isValidAgentId("agent_2"));
    try std.testing.expect(!AgentRuntimeRegistry.isValidAgentId("."));
    try std.testing.expect(!AgentRuntimeRegistry.isValidAgentId("agent:bad"));
    try std.testing.expect(!AgentRuntimeRegistry.isValidAgentId(""));
}

test "server_piai: project id validation rejects traversal-like values" {
    try std.testing.expect(AgentRuntimeRegistry.isValidProjectId("proj-1"));
    try std.testing.expect(AgentRuntimeRegistry.isValidProjectId("proj.alpha_2"));
    try std.testing.expect(!AgentRuntimeRegistry.isValidProjectId(""));
    try std.testing.expect(!AgentRuntimeRegistry.isValidProjectId("."));
    try std.testing.expect(!AgentRuntimeRegistry.isValidProjectId(".."));
    try std.testing.expect(!AgentRuntimeRegistry.isValidProjectId("proj/../../etc"));
}

test "server_piai: invalid configured default agent falls back to built-in default" {
    const allocator = std.testing.allocator;
    var cfg = Config.RuntimeConfig{};
    cfg.default_agent_id = ".";

    const registry = AgentRuntimeRegistry.initWithLimits(allocator, cfg, null, 8);
    try std.testing.expectEqualStrings(system_agent_id, registry.default_agent_id);
}

test "server_piai: parseArchiveTimestamp accepts rotated debug archive names" {
    try std.testing.expectEqual(@as(?u64, 1771674073992), parseArchiveTimestamp("debug-stream-1771674073992.ndjson"));
    try std.testing.expectEqual(@as(?u64, 1771674073992), parseArchiveTimestamp("debug-stream-1771674073992.ndjson.gz"));
    try std.testing.expectEqual(@as(?u64, 1771674073992), parseArchiveTimestamp("debug-stream-1771674073992-1.ndjson"));
    try std.testing.expectEqual(@as(?u64, null), parseArchiveTimestamp("debug-stream.ndjson"));
    try std.testing.expectEqual(@as(?u64, null), parseArchiveTimestamp("debug-stream-abc.ndjson"));
}
