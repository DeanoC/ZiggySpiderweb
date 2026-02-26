const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const connection_dispatcher = @import("connection_dispatcher.zig");
const memory = @import("ziggy-memory-store").memory;
const protocol = @import("ziggy-spider-protocol").protocol;
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
const unified = @import("ziggy-spider-protocol").unified;

pub const RuntimeServer = runtime_server_mod.RuntimeServer;

const default_max_agent_runtimes: usize = 64;
const max_agent_id_len: usize = 64;
const max_project_id_len: usize = 128;
const debug_stream_log_filename = "debug-stream.ndjson";
const debug_stream_archive_prefix = "debug-stream-";
const debug_stream_archive_suffix = ".ndjson";
const debug_stream_archive_suffix_gz = ".ndjson.gz";
const debug_stream_rotate_max_bytes: u64 = 8 * 1024 * 1024;
const debug_stream_archive_keep: usize = 8;
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
const local_node_meta_export_name = "system-meta";
const local_node_capabilities_export_name = "system-capabilities";
const local_node_jobs_export_name = "system-jobs";
const local_node_mount_meta = "/meta";
const local_node_mount_capabilities = "/capabilities";
const local_node_mount_jobs = "/jobs";
const local_node_mount_workspace = "/workspace";
const control_operator_token_env = "SPIDERWEB_CONTROL_OPERATOR_TOKEN";
const control_project_scope_token_env = "SPIDERWEB_CONTROL_PROJECT_SCOPE_TOKEN";
const control_node_scope_token_env = "SPIDERWEB_CONTROL_NODE_SCOPE_TOKEN";
const metrics_port_env = "SPIDERWEB_METRICS_PORT";
const control_protocol_version = "unified-v2";
const fsrpc_runtime_protocol_version = "acheron-1";
const fsrpc_node_protocol_version = "unified-v2-fs";
const fsrpc_node_proto_id: i64 = 2;
const min_connection_worker_threads: usize = 16;
const runtime_warmup_wait_timeout_ms: i64 = 12_000;
const runtime_warmup_stale_timeout_ms: i64 = 30_000;
const runtime_warmup_poll_interval_ms: u64 = 100;

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

fn parseArchiveTimestamp(name: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, name, debug_stream_archive_prefix)) return null;
    var tail = name[debug_stream_archive_prefix.len..];

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

const ControlTopologySubscriber = struct {
    id: u64,
    stream: *std.net.Stream,
    write_mutex: *std.Thread.Mutex,
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

    fn create(
        allocator: std.mem.Allocator,
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
            .service = try fs_node_service.NodeService.init(allocator, export_specs),
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
};

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
    project_id: ?[]u8 = null,
    project_token: ?[]u8 = null,

    fn deinit(self: *SessionBinding, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        if (self.project_id) |value| allocator.free(value);
        if (self.project_token) |value| allocator.free(value);
        self.* = undefined;
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

const AuthTokenStore = struct {
    const PersistedTarget = struct {
        agent_id: ?[]const u8 = null,
        project_id: ?[]const u8 = null,
    };

    const Persisted = struct {
        schema: u32 = 2,
        admin_token: []const u8,
        user_token: []const u8,
        admin_last_target: ?PersistedTarget = null,
        user_last_target: ?PersistedTarget = null,
        updated_at_ms: i64,
    };

    allocator: std.mem.Allocator,
    path: ?[]u8 = null,
    admin_token: []u8,
    user_token: []u8,
    admin_last_target: ?RememberedTarget = null,
    user_last_target: ?RememberedTarget = null,
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

        self.mutex.lock();
        defer self.mutex.unlock();
        const previous_admin = self.admin_token;
        const previous_user = self.user_token;
        var previous_admin_target = self.admin_last_target;
        var previous_user_target = self.user_last_target;
        self.admin_token = next_admin;
        self.user_token = next_user;
        self.admin_last_target = next_admin_target;
        self.user_last_target = next_user_target;
        self.allocator.free(previous_admin);
        self.allocator.free(previous_user);
        if (previous_admin_target) |*target| target.deinit(self.allocator);
        if (previous_user_target) |*target| target.deinit(self.allocator);
        return true;
    }

    fn persistCurrentStateLocked(self: *AuthTokenStore) !void {
        const path = self.path orelse return error.AuthTokenPathUnavailable;
        const payload = Persisted{
            .schema = 2,
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

    fn deinit(self: *AgentRuntimeEntry, allocator: std.mem.Allocator) void {
        self.runtime.destroy();
        allocator.free(self.project_id);
        self.* = undefined;
    }
};

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
    workspace_url: ?[]u8 = null,
    mutex: std.Thread.Mutex = .{},
    by_agent: std.StringHashMapUnmanaged(AgentRuntimeEntry) = .{},
    runtime_warmups_mutex: std.Thread.Mutex = .{},
    runtime_warmups: std.StringHashMapUnmanaged(RuntimeWarmupState) = .{},
    runtime_warmup_lifecycle_mutex: std.Thread.Mutex = .{},
    runtime_warmup_lifecycle_cond: std.Thread.Condition = .{},
    runtime_warmup_inflight: usize = 0,
    runtime_warmup_stopping: bool = false,
    topology_subscribers_mutex: std.Thread.Mutex = .{},
    topology_subscribers: std.ArrayListUnmanaged(ControlTopologySubscriber) = .{},
    next_topology_subscriber_id: u64 = 1,
    audit_records_mutex: std.Thread.Mutex = .{},
    audit_records: std.ArrayListUnmanaged(AuditRecord) = .{},
    next_audit_record_id: u64 = 1,
    reconcile_worker_thread: ?std.Thread = null,
    reconcile_worker_stop: bool = false,
    reconcile_worker_mutex: std.Thread.Mutex = .{},
    reconcile_worker_interval_ms: u64 = 250,

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
        const configured_default = if (runtime_config.default_agent_id.len == 0)
            system_agent_id
        else
            runtime_config.default_agent_id;
        const effective_default = if (isValidAgentId(configured_default))
            configured_default
        else
            system_agent_id;
        if (!isValidAgentId(configured_default)) {
            std.log.warn(
                "Invalid default_agent_id '{s}', falling back to '{s}'",
                .{ configured_default, effective_default },
            );
        }
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

        return .{
            .allocator = allocator,
            .runtime_config = runtime_config,
            .provider_config = provider_config,
            .default_agent_id = effective_default,
            .max_runtimes = if (max_runtimes == 0) 1 else max_runtimes,
            .debug_stream_sink = debug_stream_sink,
            .control_plane = fs_control_plane.ControlPlane.initWithPersistenceOptions(
                allocator,
                runtime_config.ltm_directory,
                runtime_config.ltm_filename,
                .{
                    .primary_agent_id = effective_default,
                    .spider_web_root = runtime_config.spider_web_root,
                },
            ),
            .job_index = chat_job_index.ChatJobIndex.init(
                allocator,
                runtime_config.ltm_directory,
            ),
            .auth_tokens = AuthTokenStore.init(allocator, runtime_config),
            .control_operator_token = operator_token,
            .control_project_scope_token = project_scope_token,
            .control_node_scope_token = node_scope_token,
        };
    }

    fn deinit(self: *AgentRuntimeRegistry) void {
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
        defer self.mutex.unlock();

        var it = self.by_agent.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var runtime_entry = entry.value_ptr.*;
            runtime_entry.deinit(self.allocator);
        }
        self.by_agent.deinit(self.allocator);
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
        self.clearTopologySubscribers();
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

    fn getLocalFsNode(self: *AgentRuntimeRegistry) ?*LocalFsNode {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.local_fs_node;
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
    };

    fn projectExists(self: *AgentRuntimeRegistry, project_id: []const u8) bool {
        const escaped_project = unified.jsonEscape(self.allocator, project_id) catch return false;
        defer self.allocator.free(escaped_project);
        const payload = std.fmt.allocPrint(self.allocator, "{{\"project_id\":\"{s}\"}}", .{escaped_project}) catch return false;
        defer self.allocator.free(payload);
        const result = self.control_plane.getProject(payload) catch return false;
        self.allocator.free(result);
        return true;
    }

    fn canPrincipalUseTarget(self: *AgentRuntimeRegistry, role: ConnectionRole, agent_id: []const u8, project_id: []const u8) bool {
        if (!isValidAgentId(agent_id)) return false;
        if (!isValidProjectId(project_id)) return false;
        if (!self.projectExists(project_id)) return false;
        if (role == .user and std.mem.eql(u8, agent_id, system_agent_id)) return false;
        if (role == .user and std.mem.eql(u8, project_id, system_project_id)) return false;
        return true;
    }

    fn clearRememberedTargetForRole(self: *AgentRuntimeRegistry, role: ConnectionRole) void {
        self.auth_tokens.clearRememberedTarget(role) catch |err| {
            std.log.warn("failed to clear invalid remembered target for {s}: {s}", .{ connectionRoleName(role), @errorName(err) });
        };
    }

    fn buildInitialSessionBinding(self: *AgentRuntimeRegistry, role: ConnectionRole) !InitialSessionBinding {
        var remembered = try self.auth_tokens.rememberedTargetOwned(role);
        defer if (remembered) |*target| target.deinit(self.allocator);

        if (remembered) |target| {
            if (self.canPrincipalUseTarget(role, target.agent_id, target.project_id)) {
                return .{
                    .binding = .{
                        .agent_id = try self.allocator.dupe(u8, target.agent_id),
                        .project_id = try self.allocator.dupe(u8, target.project_id),
                        .project_token = null,
                    },
                };
            }
            self.clearRememberedTargetForRole(role);
            if (role == .user) {
                return .{
                    .binding = .{
                        .agent_id = try self.allocator.dupe(u8, system_agent_id),
                        .project_id = try self.allocator.dupe(u8, system_project_id),
                        .project_token = null,
                    },
                    .connect_gate_error = .{
                        .code = "last_target_invalid",
                        .message = "last remembered project/agent target is unavailable; ask an admin to provision a project",
                    },
                };
            }
        }

        if (role == .admin) {
            return .{
                .binding = .{
                    .agent_id = try self.allocator.dupe(u8, system_agent_id),
                    .project_id = try self.allocator.dupe(u8, system_project_id),
                    .project_token = null,
                },
            };
        }

        return .{
            .binding = .{
                .agent_id = try self.allocator.dupe(u8, system_agent_id),
                .project_id = try self.allocator.dupe(u8, system_project_id),
                .project_token = null,
            },
            .connect_gate_error = .{
                .code = "provisioning_required",
                .message = "no non-system project/agent is available for this user token; ask an admin to provision one",
            },
        };
    }

    fn rememberPrincipalTarget(self: *AgentRuntimeRegistry, principal: ConnectionPrincipal, agent_id: []const u8, project_id: ?[]const u8) void {
        const concrete_project = project_id orelse return;
        if (std.mem.eql(u8, concrete_project, system_project_id)) return;
        self.auth_tokens.setRememberedTarget(principal.role, agent_id, concrete_project) catch |err| {
            std.log.warn("failed to persist last target for {s}: {s}", .{ connectionRoleName(principal.role), @errorName(err) });
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

    fn requestReconcileWorkerStop(self: *AgentRuntimeRegistry) void {
        self.reconcile_worker_mutex.lock();
        self.reconcile_worker_stop = true;
        self.reconcile_worker_mutex.unlock();
    }

    fn shouldStopReconcileWorker(self: *AgentRuntimeRegistry) bool {
        self.reconcile_worker_mutex.lock();
        defer self.reconcile_worker_mutex.unlock();
        return self.reconcile_worker_stop;
    }

    const RemovedRuntimeEntry = struct {
        key: []const u8,
        entry: AgentRuntimeEntry,
    };

    fn takeUnhealthyRuntimeLocked(self: *AgentRuntimeRegistry, agent_id: []const u8) ?RemovedRuntimeEntry {
        const existing = self.by_agent.getPtr(agent_id) orelse return null;
        if (existing.runtime.isHealthy()) return null;
        const removed = self.by_agent.fetchRemove(agent_id) orelse return null;
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
        errdefer self.allocator.free(resolved_project_id);

        var removed_unhealthy: ?RemovedRuntimeEntry = null;
        defer if (removed_unhealthy) |removed| self.deinitRemovedRuntime(removed);

        self.mutex.lock();
        removed_unhealthy = self.takeUnhealthyRuntimeLocked(agent_id);
        if (removed_unhealthy == null) {
            if (self.by_agent.getPtr(agent_id)) |existing| {
                if (std.mem.eql(u8, existing.project_id, resolved_project_id)) {
                    const runtime = existing.runtime;
                    runtime.retain();
                    self.mutex.unlock();
                    return runtime;
                }
            } else if (self.by_agent.count() >= self.max_runtimes) {
                self.mutex.unlock();
                return error.RuntimeLimitReached;
            }
        }
        self.mutex.unlock();

        const entry = try self.createRuntimeEntry(
            agent_id,
            resolved_project_id,
            requested_project_token,
        );
        self.allocator.free(resolved_project_id);
        var entry_installed = false;
        errdefer if (!entry_installed) {
            var cleanup = entry;
            cleanup.deinit(self.allocator);
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_agent.getPtr(agent_id)) |existing| {
            if (std.mem.eql(u8, existing.project_id, entry.project_id)) {
                var cleanup = entry;
                cleanup.deinit(self.allocator);
                entry_installed = true;
                const runtime = existing.runtime;
                runtime.retain();
                return runtime;
            }
            var replaced = existing.*;
            existing.* = entry;
            entry_installed = true;
            const runtime = existing.runtime;
            runtime.retain();
            replaced.deinit(self.allocator);
            return runtime;
        }

        if (self.by_agent.count() >= self.max_runtimes) return error.RuntimeLimitReached;

        const owned_agent = try self.allocator.dupe(u8, agent_id);
        errdefer self.allocator.free(owned_agent);

        try self.by_agent.put(self.allocator, owned_agent, entry);
        entry_installed = true;
        const runtime = self.by_agent.getPtr(owned_agent).?.runtime;
        runtime.retain();
        return runtime;
    }

    fn createRuntimeEntry(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        project_id: []const u8,
        project_token: ?[]const u8,
    ) !AgentRuntimeEntry {
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
                    else => return error.InvalidSandboxConfig,
                }
            };
            errdefer sandbox_runtime.destroy();

            const runtime_server = if (self.provider_config) |provider_cfg|
                try RuntimeServer.createWithProviderAndToolDispatch(
                    self.allocator,
                    agent_id,
                    self.runtime_config,
                    provider_cfg,
                    sandbox_runtime,
                    sandbox_runtime_mod.SandboxRuntime.dispatchWorldTool,
                )
            else
                try RuntimeServer.createWithToolDispatch(
                    self.allocator,
                    agent_id,
                    self.runtime_config,
                    sandbox_runtime,
                    sandbox_runtime_mod.SandboxRuntime.dispatchWorldTool,
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
            return self.allocator.dupe(u8, project_id);
        }

        if (!self.runtime_config.sandbox_enabled) {
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
        var removed_unhealthy: ?RemovedRuntimeEntry = null;
        var has_binding = false;
        self.mutex.lock();
        removed_unhealthy = self.takeUnhealthyRuntimeLocked(agent_id);
        if (removed_unhealthy == null) {
            if (self.by_agent.getPtr(agent_id)) |existing| {
                has_binding = if (project_id) |project|
                    std.mem.eql(u8, existing.project_id, project)
                else
                    true;
            }
        }
        self.mutex.unlock();

        if (removed_unhealthy) |removed| {
            self.deinitRemovedRuntime(removed);
            return false;
        }
        return has_binding;
    }

    fn runtimeBindingKey(self: *AgentRuntimeRegistry, agent_id: []const u8, project_id: ?[]const u8) ![]u8 {
        const project = project_id orelse "__auto__";
        return std.fmt.allocPrint(self.allocator, "{s}\x1F{s}", .{ agent_id, project });
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
        if (self.hasRuntimeForBinding(agent_id, project_id)) {
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
        return self.runtimeAttachSnapshotByKey(binding_key);
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
                .message = "agent runtime limit reached",
            },
            error.ProjectRequired => .{
                .code = "sandbox_mount_missing",
                .message = "sandbox requires a project binding",
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
        const escaped_binding = unified.jsonEscape(self.allocator, binding_key) catch return;
        defer self.allocator.free(escaped_binding);
        const escaped_state = unified.jsonEscape(self.allocator, sessionAttachStateName(state.state)) catch return;
        defer self.allocator.free(escaped_state);

        const error_code_json = if (state.error_code) |value| blk: {
            const escaped = unified.jsonEscape(self.allocator, value) catch return;
            defer self.allocator.free(escaped);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(error_code_json);

        const error_message_json = if (state.error_message) |value| blk: {
            const escaped = unified.jsonEscape(self.allocator, value) catch return;
            defer self.allocator.free(escaped);
            break :blk std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped}) catch return;
        } else self.allocator.dupe(u8, "null") catch return;
        defer self.allocator.free(error_message_json);

        const payload_json = std.fmt.allocPrint(
            self.allocator,
            "{{\"binding\":\"{s}\",\"state\":\"{s}\",\"runtime_ready\":{},\"mount_ready\":{},\"error_code\":{s},\"error_message\":{s},\"updated_at_ms\":{d}}}",
            .{
                escaped_binding,
                escaped_state,
                state.runtime_ready,
                state.mount_ready,
                error_code_json,
                error_message_json,
                state.updated_at_ms,
            },
        ) catch return;
        defer self.allocator.free(payload_json);

        self.broadcastTopologyDebugEvent("control.session_attach_state", payload_json);
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
                    } else if (state.state != .ready) {
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

    fn waitForRuntimeWarmup(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        project_id: ?[]const u8,
        timeout_ms: i64,
    ) SessionAttachStateSnapshot {
        var snapshot = self.runtimeAttachSnapshot(agent_id, project_id);
        if (snapshot.state != .warming or timeout_ms <= 0) return snapshot;

        const started_ms = std.time.milliTimestamp();
        while (snapshot.state == .warming) {
            const elapsed_ms = std.time.milliTimestamp() - started_ms;
            if (elapsed_ms >= timeout_ms) break;
            std.Thread.sleep(runtime_warmup_poll_interval_ms * std.time.ns_per_ms);
            snapshot.deinit(self.allocator);
            snapshot = self.runtimeAttachSnapshot(agent_id, project_id);
        }
        return snapshot;
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

    fn clearTopologySubscribers(self: *AgentRuntimeRegistry) void {
        self.topology_subscribers_mutex.lock();
        defer self.topology_subscribers_mutex.unlock();
        self.topology_subscribers.deinit(self.allocator);
        self.topology_subscribers = .{};
        self.next_topology_subscriber_id = 1;
    }

    fn registerTopologySubscriber(
        self: *AgentRuntimeRegistry,
        stream: *std.net.Stream,
        write_mutex: *std.Thread.Mutex,
    ) !u64 {
        self.topology_subscribers_mutex.lock();
        defer self.topology_subscribers_mutex.unlock();
        const id = self.next_topology_subscriber_id;
        self.next_topology_subscriber_id +%= 1;
        if (self.next_topology_subscriber_id == 0) self.next_topology_subscriber_id = 1;
        try self.topology_subscribers.append(self.allocator, .{
            .id = id,
            .stream = stream,
            .write_mutex = write_mutex,
        });
        return id;
    }

    fn unregisterTopologySubscriber(self: *AgentRuntimeRegistry, subscriber_id: u64) void {
        self.topology_subscribers_mutex.lock();
        defer self.topology_subscribers_mutex.unlock();
        var idx: usize = 0;
        while (idx < self.topology_subscribers.items.len) : (idx += 1) {
            if (self.topology_subscribers.items[idx].id != subscriber_id) continue;
            _ = self.topology_subscribers.swapRemove(idx);
            return;
        }
    }

    fn emitWorkspaceTopologyChanged(self: *AgentRuntimeRegistry, reason: []const u8) void {
        const escaped_reason = unified.jsonEscape(self.allocator, reason) catch return;
        defer self.allocator.free(escaped_reason);
        const payload_json = std.fmt.allocPrint(
            self.allocator,
            "{{\"event\":\"workspace_topology_changed\",\"reason\":\"{s}\",\"ts_ms\":{d}}}",
            .{ escaped_reason, std.time.milliTimestamp() },
        ) catch return;
        defer self.allocator.free(payload_json);
        self.broadcastTopologyDebugEvent("control.workspace_topology", payload_json);
    }

    fn emitWorkspaceTopologyProjectDelta(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        reason: []const u8,
        control_request_payload_json: ?[]const u8,
        control_response_payload_json: []const u8,
    ) void {
        const response_project_id = extractProjectIdFromControlPayload(self.allocator, control_response_payload_json) catch return;
        defer if (response_project_id) |value| self.allocator.free(value);
        const request_project_id = if (control_request_payload_json) |value|
            extractProjectIdFromControlPayload(self.allocator, value) catch return
        else
            null;
        defer if (request_project_id) |value| self.allocator.free(value);
        const selected_project = response_project_id orelse request_project_id orelse return;

        const response_project_token = extractProjectTokenFromControlPayload(self.allocator, control_response_payload_json) catch return;
        defer if (response_project_token) |value| self.allocator.free(value);
        const request_project_token = if (control_request_payload_json) |value|
            extractProjectTokenFromControlPayload(self.allocator, value) catch return
        else
            null;
        defer if (request_project_token) |value| self.allocator.free(value);
        const selected_project_token = response_project_token orelse request_project_token;

        const escaped_project = unified.jsonEscape(self.allocator, selected_project) catch return;
        defer self.allocator.free(escaped_project);
        const status_req = if (selected_project_token) |project_token| blk: {
            const escaped_token = unified.jsonEscape(self.allocator, project_token) catch return;
            defer self.allocator.free(escaped_token);
            break :blk std.fmt.allocPrint(
                self.allocator,
                "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
                .{ escaped_project, escaped_token },
            ) catch return;
        } else std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\"}}",
            .{escaped_project},
        ) catch return;
        defer self.allocator.free(status_req);

        const status_json = self.control_plane.workspaceStatus(agent_id, status_req) catch return;
        defer self.allocator.free(status_json);
        if (std.mem.indexOf(u8, status_json, "\"project_id\":null") != null) return;

        const escaped_reason = unified.jsonEscape(self.allocator, reason) catch return;
        defer self.allocator.free(escaped_reason);
        const escaped_agent = unified.jsonEscape(self.allocator, agent_id) catch return;
        defer self.allocator.free(escaped_agent);

        const payload_json = std.fmt.allocPrint(
            self.allocator,
            "{{\"event\":\"workspace_topology_delta\",\"reason\":\"{s}\",\"agent_id\":\"{s}\",\"status\":{s},\"ts_ms\":{d}}}",
            .{ escaped_reason, escaped_agent, status_json, std.time.milliTimestamp() },
        ) catch return;
        defer self.allocator.free(payload_json);

        self.broadcastTopologyDebugEvent("control.workspace_topology_delta", payload_json);
    }

    fn emitWorkspaceAvailabilityRollupChanged(
        self: *AgentRuntimeRegistry,
        reason: []const u8,
        before: fs_control_plane.ControlPlane.AvailabilitySnapshot,
        after: fs_control_plane.ControlPlane.AvailabilitySnapshot,
    ) void {
        const escaped_reason = unified.jsonEscape(self.allocator, reason) catch return;
        defer self.allocator.free(escaped_reason);
        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);
        payload.appendSlice(self.allocator, "{\"event\":\"workspace_availability_changed\",\"reason\":\"") catch return;
        payload.appendSlice(self.allocator, escaped_reason) catch return;
        payload.appendSlice(self.allocator, "\",\"before\":") catch return;
        appendAvailabilitySnapshotJson(self.allocator, &payload, before) catch return;
        payload.appendSlice(self.allocator, ",\"after\":") catch return;
        appendAvailabilitySnapshotJson(self.allocator, &payload, after) catch return;
        payload.appendSlice(self.allocator, ",\"ts_ms\":") catch return;
        payload.writer(self.allocator).print("{d}", .{std.time.milliTimestamp()}) catch return;
        payload.append(self.allocator, '}') catch return;

        const payload_json = payload.toOwnedSlice(self.allocator) catch return;
        defer self.allocator.free(payload_json);
        self.broadcastTopologyDebugEvent("control.workspace_availability", payload_json);
    }

    fn broadcastTopologyDebugEvent(
        self: *AgentRuntimeRegistry,
        category: []const u8,
        payload_json: []const u8,
    ) void {
        const event_json = protocol.buildDebugEvent(
            self.allocator,
            "workspace-topology",
            category,
            payload_json,
        ) catch return;
        defer self.allocator.free(event_json);

        self.topology_subscribers_mutex.lock();
        defer self.topology_subscribers_mutex.unlock();

        var idx: usize = 0;
        while (idx < self.topology_subscribers.items.len) {
            const subscriber = self.topology_subscribers.items[idx];
            subscriber.write_mutex.lock();
            const write_result = websocket_transport.writeFrame(subscriber.stream, event_json, .text);
            subscriber.write_mutex.unlock();
            if (write_result) |_| {
                idx += 1;
            } else |_| {
                _ = self.topology_subscribers.swapRemove(idx);
            }
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
        const cwd_owned = std.process.getCwdAlloc(self.allocator) catch null;
        defer if (cwd_owned) |value| self.allocator.free(value);
        const cwd_trimmed = if (cwd_owned) |value| std.mem.trim(u8, value, " \t\r\n") else "";
        const export_path = if (export_path_owned) |value| blk: {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) break :blk trimmed;
            if (std.mem.eql(u8, configured_export_path, "/") and cwd_trimmed.len > 0 and !std.mem.eql(u8, cwd_trimmed, "/")) {
                break :blk cwd_trimmed;
            }
            break :blk configured_export_path;
        } else blk: {
            if (std.mem.eql(u8, configured_export_path, "/") and cwd_trimmed.len > 0 and !std.mem.eql(u8, cwd_trimmed, "/")) {
                break :blk cwd_trimmed;
            }
            break :blk configured_export_path;
        };
        const using_workdir_export_default = export_path_owned == null and
            std.mem.eql(u8, configured_export_path, "/") and
            cwd_trimmed.len > 0 and
            !std.mem.eql(u8, cwd_trimmed, "/");
        if (using_workdir_export_default) {
            std.log.warn(
                "local fs export defaulting to service working directory {s} because runtime.spider_web_root='/' (set runtime.spider_web_root or {s} to override)",
                .{ export_path, local_node_export_path_env },
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
                .name = local_node_meta_export_name,
                .path = "meta",
                .ro = true,
                .desc = "spiderweb-meta-export",
                .source_kind = .namespace,
                .source_id = "meta",
            },
            .{
                .name = local_node_capabilities_export_name,
                .path = "capabilities",
                .ro = true,
                .desc = "spiderweb-capabilities-export",
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
            .{ .mount_path = local_node_mount_meta, .export_name = local_node_meta_export_name },
            .{ .mount_path = local_node_mount_capabilities, .export_name = local_node_capabilities_export_name },
            .{ .mount_path = local_node_mount_jobs, .export_name = local_node_jobs_export_name },
            .{ .mount_path = local_node_mount_workspace, .export_name = workspace_export_name },
        };

        const local_node = try LocalFsNode.create(
            self.allocator,
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
            runtime_registry.broadcastTopologyDebugEvent("control.reconcile", payload);
        }

        std.Thread.sleep(runtime_registry.reconcile_worker_interval_ms * std.time.ns_per_ms);
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

    runtime_registry.workspace_url = try formatInternalWsUrl(allocator, bind_addr, port, "/");
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

    _ = resolveAgentIdFromConnectionPath(handshake.path, runtime_registry.default_agent_id) orelse {
        try sendWebSocketErrorAndClose(allocator, stream, .invalid_envelope, "invalid websocket path");
        return;
    };

    const principal = runtime_registry.authenticateConnection(handshake.authorization) orelse {
        try sendWebSocketErrorAndClose(allocator, stream, .provider_auth_failed, "forbidden");
        return;
    };

    var session_bindings: std.StringHashMapUnmanaged(SessionBinding) = .{};
    defer deinitSessionBindings(allocator, &session_bindings);

    var initial_binding = try runtime_registry.buildInitialSessionBinding(principal.role);
    defer initial_binding.binding.deinit(allocator);
    var connect_gate_error = initial_binding.connect_gate_error;
    try upsertSessionBinding(
        allocator,
        &session_bindings,
        "main",
        initial_binding.binding.agent_id,
        initial_binding.binding.project_id,
        initial_binding.binding.project_token,
    );
    var initial_warmup_snapshot = if (connect_gate_error == null)
        runtime_registry.ensureRuntimeWarmup(
            initial_binding.binding.agent_id,
            initial_binding.binding.project_id,
            initial_binding.binding.project_token,
            true,
        ) catch |err| blk: {
            std.log.warn("default session warmup failed: {s}", .{@errorName(err)});
            break :blk SessionAttachStateSnapshot{};
        }
    else
        SessionAttachStateSnapshot{};
    defer initial_warmup_snapshot.deinit(allocator);

    var active_session_key = try allocator.dupe(u8, "main");
    defer allocator.free(active_session_key);
    var fsrpc: ?fsrpc_session.Session = null;
    defer if (fsrpc) |*session| session.deinit();
    var fsrpc_bound_session_key = try allocator.dupe(u8, "main");
    defer allocator.free(fsrpc_bound_session_key);
    var debug_stream_enabled = false;
    var control_protocol_negotiated = false;
    var runtime_fsrpc_version_negotiated = false;
    var connection_write_mutex: std.Thread.Mutex = .{};
    var topology_subscriber_id: ?u64 = null;
    defer if (topology_subscriber_id) |subscriber_id| {
        runtime_registry.unregisterTopologySubscriber(subscriber_id);
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
                    if (try tryHandleLegacySessionSendFrame(
                        allocator,
                        runtime_registry,
                        stream,
                        &connection_write_mutex,
                        frame.payload,
                        &session_bindings,
                        active_session_key,
                        connect_gate_error,
                        debug_stream_enabled,
                    )) {
                        continue;
                    }
                    const response = try unified.buildControlError(
                        allocator,
                        null,
                        "invalid_envelope",
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
                            control_type != .session_attach)
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
                                if (connect_gate_error) |gate| {
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
                                const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                const escaped_role = switch (principal.role) {
                                    .admin => "admin",
                                    .user => "user",
                                };
                                const payload = try std.fmt.allocPrint(
                                    allocator,
                                    "{{\"agent_id\":\"{s}\",\"session\":\"{s}\",\"protocol\":\"{s}\",\"role\":\"{s}\"}}",
                                    .{ active_binding.agent_id, active_session_key, control_protocol_version, escaped_role },
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
                                const payload = try runtime_registry.control_plane.metricsJson();
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
                                var attach_project_id = getOptionalStringField(payload.value.object, "project_id");
                                var attach_project_token = getOptionalStringField(payload.value.object, "project_token");
                                const current_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
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
                                if (attach_project_id) |project_id| {
                                    if (!AgentRuntimeRegistry.isValidProjectId(project_id)) {
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
                                }

                                const existing_binding = session_bindings.get(session_key);
                                if (attach_project_id == null and existing_binding != null and std.mem.eql(u8, existing_binding.?.agent_id, attach_agent_id)) {
                                    attach_project_id = existing_binding.?.project_id;
                                    attach_project_token = existing_binding.?.project_token;
                                }
                                if (attach_project_id == null and principal.role == .admin and std.mem.eql(u8, attach_agent_id, system_agent_id)) {
                                    attach_project_id = system_project_id;
                                }
                                if (attach_project_id == null and principal.role == .user) {
                                    const response = try unified.buildControlError(
                                        allocator,
                                        parsed.id,
                                        "provisioning_required",
                                        "no non-system project/agent is available for this user token; ask an admin to provision one",
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
                                if (principal.role == .user and attach_project_id != null and std.mem.eql(u8, attach_project_id.?, system_project_id)) {
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

                                if (attach_project_id != null and try runtime_registry.job_index.hasInFlightForAgent(attach_agent_id)) {
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

                                if (attach_project_id) |project_id| {
                                    const activate_payload = try buildProjectActivatePayload(allocator, project_id, attach_project_token);
                                    defer allocator.free(activate_payload);
                                    _ = runtime_registry.control_plane.activateProject(attach_agent_id, activate_payload) catch |activate_err| {
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
                                }

                                try upsertSessionBinding(
                                    allocator,
                                    &session_bindings,
                                    session_key,
                                    attach_agent_id,
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
                                defer attach_state.deinit(allocator);
                                const attach_json = try buildSessionAttachStateJson(allocator, attach_state);
                                defer allocator.free(attach_json);
                                const ack_payload = try buildSessionAttachAckPayload(
                                    allocator,
                                    session_key,
                                    active_binding.agent_id,
                                    active_binding.project_id,
                                    "{}",
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
                                runtime_registry.rememberPrincipalTarget(
                                    principal,
                                    active_binding.agent_id,
                                    active_binding.project_id,
                                );
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
                                const payload_json = try buildSessionStatusPayload(
                                    allocator,
                                    session_key,
                                    binding.agent_id,
                                    binding.project_id,
                                    attach_json,
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
                                const ack_payload = try buildSessionAttachAckPayload(
                                    allocator,
                                    session_key,
                                    binding.agent_id,
                                    binding.project_id,
                                    "{}",
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
                                                .agents_dir = runtime_registry.runtime_config.agents_dir,
                                                .projects_dir = "projects",
                                                .control_plane = &runtime_registry.control_plane,
                                            },
                                        );
                                    }
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
                            .debug_subscribe, .debug_unsubscribe => {
                                debug_stream_enabled = control_type == .debug_subscribe;
                                if (fsrpc) |*session| {
                                    session.setDebugStreamEnabled(debug_stream_enabled);
                                }
                                if (debug_stream_enabled) {
                                    if (topology_subscriber_id == null) {
                                        topology_subscriber_id = try runtime_registry.registerTopologySubscriber(
                                            stream,
                                            &connection_write_mutex,
                                        );
                                    }
                                } else if (topology_subscriber_id) |subscriber_id| {
                                    runtime_registry.unregisterTopologySubscriber(subscriber_id);
                                    topology_subscriber_id = null;
                                }
                                const request_id = parsed.id orelse "generated";
                                const payload_json = if (debug_stream_enabled)
                                    "{\"enabled\":true}"
                                else
                                    "{\"enabled\":false}";
                                const ack = try protocol.buildDebugEvent(
                                    allocator,
                                    request_id,
                                    "control.subscription",
                                    payload_json,
                                );
                                defer allocator.free(ack);
                                try writeFrameLocked(stream, &connection_write_mutex, ack, .text);
                                const active_binding = session_bindings.get(active_session_key) orelse return error.InvalidState;
                                runtime_registry.maybeLogDebugFrame(active_binding.agent_id, ack);
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
                                const availability_after = runtime_registry.control_plane.availabilitySnapshot();
                                const topology_mutation = isWorkspaceTopologyMutation(control_type);
                                const availability_changed = !fs_control_plane.ControlPlane.AvailabilitySnapshot.eql(
                                    availability_before,
                                    availability_after,
                                );
                                if (topology_mutation or availability_changed) {
                                    runtime_registry.control_plane.requestReconcile();
                                    const reason = if (availability_changed and !topology_mutation)
                                        "availability_changed"
                                    else
                                        unified.controlTypeName(control_type);
                                    runtime_registry.emitWorkspaceTopologyChanged(reason);
                                    runtime_registry.emitWorkspaceTopologyProjectDelta(
                                        control_agent_id,
                                        reason,
                                        parsed.payload_json,
                                        payload_json,
                                    );
                                    if (availability_changed) {
                                        runtime_registry.emitWorkspaceAvailabilityRollupChanged(
                                            reason,
                                            availability_before,
                                            availability_after,
                                        );
                                    }
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
                                attach_state.deinit(allocator);
                                attach_state = runtime_registry.waitForRuntimeWarmup(
                                    target_binding.agent_id,
                                    target_binding.project_id,
                                    runtime_warmup_wait_timeout_ms,
                                );
                            }
                            if (attach_state.state == .warming) {
                                const response = try unified.buildFsrpcError(
                                    allocator,
                                    parsed.tag,
                                    "runtime_warming",
                                    "runtime is warming",
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
                            else => return err,
                        };
                        defer target_runtime.release();
                        if (fsrpc == null) {
                            fsrpc = try fsrpc_session.Session.initWithOptions(
                                allocator,
                                target_runtime,
                                &runtime_registry.job_index,
                                target_binding.agent_id,
                                .{
                                    .project_id = target_binding.project_id,
                                    .agents_dir = runtime_registry.runtime_config.agents_dir,
                                    .projects_dir = "projects",
                                    .control_plane = &runtime_registry.control_plane,
                                },
                            );
                            fsrpc.?.setDebugStreamEnabled(debug_stream_enabled);
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
                                        .agents_dir = runtime_registry.runtime_config.agents_dir,
                                        .projects_dir = "projects",
                                        .control_plane = &runtime_registry.control_plane,
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

                        const debug_frames = try fsrpc.?.drainPendingDebugFrames();
                        if (debug_frames.len > 0) {
                            defer allocator.free(debug_frames);
                            var idx: usize = 0;
                            while (idx < debug_frames.len) : (idx += 1) {
                                const payload = debug_frames[idx];
                                writeFrameLocked(stream, &connection_write_mutex, payload, .text) catch |err| {
                                    allocator.free(payload);
                                    var rest = idx + 1;
                                    while (rest < debug_frames.len) : (rest += 1) {
                                        allocator.free(debug_frames[rest]);
                                    }
                                    return err;
                                };
                                runtime_registry.maybeLogDebugFrame(target_binding.agent_id, payload);
                                allocator.free(payload);
                            }
                        }
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

fn upsertSessionBinding(
    allocator: std.mem.Allocator,
    map: *std.StringHashMapUnmanaged(SessionBinding),
    session_key: []const u8,
    agent_id: []const u8,
    project_id: ?[]const u8,
    project_token: ?[]const u8,
) !void {
    if (map.getPtr(session_key)) |existing| {
        existing.deinit(allocator);
        existing.* = .{
            .agent_id = try allocator.dupe(u8, agent_id),
            .project_id = if (project_id) |value| try allocator.dupe(u8, value) else null,
            .project_token = if (project_token) |value| try allocator.dupe(u8, value) else null,
        };
        return;
    }

    try map.put(
        allocator,
        try allocator.dupe(u8, session_key),
        .{
            .agent_id = try allocator.dupe(u8, agent_id),
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
    project_id: ?[]const u8,
    workspace_json: []const u8,
    attach_json: []const u8,
) ![]u8 {
    const escaped_session = try unified.jsonEscape(allocator, session_key);
    defer allocator.free(escaped_session);
    const escaped_agent = try unified.jsonEscape(allocator, agent_id);
    defer allocator.free(escaped_agent);
    const project_json = if (project_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(project_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"project_id\":{s},\"workspace\":{s},\"attach\":{s}}}",
        .{ escaped_session, escaped_agent, project_json, workspace_json, attach_json },
    );
}

fn buildSessionStatusPayload(
    allocator: std.mem.Allocator,
    session_key: []const u8,
    agent_id: []const u8,
    project_id: ?[]const u8,
    attach_json: []const u8,
) ![]u8 {
    const escaped_session = try unified.jsonEscape(allocator, session_key);
    defer allocator.free(escaped_session);
    const escaped_agent = try unified.jsonEscape(allocator, agent_id);
    defer allocator.free(escaped_agent);
    const project_json = if (project_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(project_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"project_id\":{s},\"attach\":{s}}}",
        .{ escaped_session, escaped_agent, project_json, attach_json },
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
        const project_json = if (entry.value_ptr.project_id) |project_id| blk: {
            const escaped_project = try unified.jsonEscape(allocator, project_id);
            defer allocator.free(escaped_project);
            break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_project});
        } else try allocator.dupe(u8, "null");
        defer allocator.free(project_json);
        try out.writer(allocator).print(
            "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"project_id\":{s}}}",
            .{ escaped_key, escaped_agent, project_json },
        );
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn parseSessionKeyFromLegacyMessage(allocator: std.mem.Allocator, raw_json: []const u8) ?[]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    if (parsed.value.object.get("session_key")) |session_value| {
        if (session_value == .string and session_value.string.len > 0) {
            return allocator.dupe(u8, session_value.string) catch null;
        }
    }
    if (parsed.value.object.get("sessionKey")) |session_value| {
        if (session_value == .string and session_value.string.len > 0) {
            return allocator.dupe(u8, session_value.string) catch null;
        }
    }
    return null;
}

fn decorateSessionReceiveFrame(
    allocator: std.mem.Allocator,
    frame_payload: []const u8,
    session_key: []const u8,
) ![]u8 {
    if (std.mem.indexOf(u8, frame_payload, "\"type\":\"session.receive\"") == null) {
        return allocator.dupe(u8, frame_payload);
    }
    if (std.mem.indexOf(u8, frame_payload, "\"session_key\"") != null) {
        return allocator.dupe(u8, frame_payload);
    }

    const trimmed = std.mem.trimRight(u8, frame_payload, " \t\r\n");
    if (trimmed.len == 0 or trimmed[trimmed.len - 1] != '}') {
        return allocator.dupe(u8, frame_payload);
    }
    const escaped_session = try unified.jsonEscape(allocator, session_key);
    defer allocator.free(escaped_session);
    return std.fmt.allocPrint(
        allocator,
        "{s},\"session_key\":\"{s}\"}}",
        .{ trimmed[0 .. trimmed.len - 1], escaped_session },
    );
}

fn tryHandleLegacySessionSendFrame(
    allocator: std.mem.Allocator,
    runtime_registry: *AgentRuntimeRegistry,
    stream: *std.net.Stream,
    write_mutex: *std.Thread.Mutex,
    raw_payload: []const u8,
    session_bindings: *std.StringHashMapUnmanaged(SessionBinding),
    active_session_key: []const u8,
    connect_gate_error: ?AgentRuntimeRegistry.ConnectGateError,
    emit_debug: bool,
) !bool {
    var legacy = protocol.parseMessage(allocator, raw_payload) catch return false;
    defer protocol.deinitParsedMessage(allocator, &legacy);
    if (legacy.msg_type != .session_send) return false;
    if (connect_gate_error) |gate| {
        const response = try protocol.buildErrorWithCode(
            allocator,
            legacy.id orelse "generated",
            .execution_failed,
            gate.message,
        );
        defer allocator.free(response);
        try writeFrameLocked(stream, write_mutex, response, .text);
        return true;
    }

    const session_key = parseSessionKeyFromLegacyMessage(allocator, raw_payload) orelse try allocator.dupe(u8, active_session_key);
    defer allocator.free(session_key);
    const binding = session_bindings.get(session_key) orelse {
        const response = try protocol.buildErrorWithCode(allocator, legacy.id orelse "generated", .invalid_envelope, "unknown session_key");
        defer allocator.free(response);
        try writeFrameLocked(stream, write_mutex, response, .text);
        return true;
    };
    var attach_state = runtime_registry.runtimeAttachSnapshot(
        binding.agent_id,
        binding.project_id,
    );
    defer attach_state.deinit(allocator);
    if (attach_state.state != .ready) {
        const warmed_attach_state = runtime_registry.ensureRuntimeWarmup(
            binding.agent_id,
            binding.project_id,
            binding.project_token,
            true,
        ) catch |warm_err| {
            const response = try protocol.buildErrorWithCode(
                allocator,
                legacy.id orelse "generated",
                .execution_failed,
                @errorName(warm_err),
            );
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        };
        attach_state.deinit(allocator);
        attach_state = warmed_attach_state;

        if (attach_state.state == .warming) {
            attach_state.deinit(allocator);
            attach_state = runtime_registry.waitForRuntimeWarmup(
                binding.agent_id,
                binding.project_id,
                runtime_warmup_wait_timeout_ms,
            );
        }
        if (attach_state.state == .warming) {
            const response = try protocol.buildErrorWithCode(
                allocator,
                legacy.id orelse "generated",
                .execution_failed,
                "runtime is warming",
            );
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        }
        if (attach_state.state == .err) {
            const response = try protocol.buildErrorWithCode(
                allocator,
                legacy.id orelse "generated",
                .execution_failed,
                attach_state.error_message orelse "runtime is unavailable",
            );
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        }
    }

    const runtime_server = runtime_registry.getOrCreate(
        binding.agent_id,
        binding.project_id,
        binding.project_token,
    ) catch |err| switch (err) {
        error.InvalidAgentId => {
            const response = try protocol.buildErrorWithCode(allocator, legacy.id orelse "generated", .invalid_envelope, "invalid session agent");
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        },
        error.InvalidProjectId => {
            const response = try protocol.buildErrorWithCode(allocator, legacy.id orelse "generated", .invalid_envelope, "invalid session project");
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        },
        error.RuntimeLimitReached => {
            const response = try protocol.buildErrorWithCode(allocator, legacy.id orelse "generated", .queue_saturated, "agent runtime limit reached");
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        },
        error.ProjectRequired => {
            const response = try protocol.buildErrorWithCode(allocator, legacy.id orelse "generated", .execution_failed, "sandbox requires a project binding");
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        },
        error.SandboxMountUnavailable => {
            const response = try protocol.buildErrorWithCode(allocator, legacy.id orelse "generated", .execution_failed, "sandbox mount is unavailable");
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        },
        error.InvalidSandboxConfig => {
            const response = try protocol.buildErrorWithCode(allocator, legacy.id orelse "generated", .execution_failed, "sandbox config is invalid");
            defer allocator.free(response);
            try writeFrameLocked(stream, write_mutex, response, .text);
            return true;
        },
        else => return err,
    };
    defer runtime_server.release();

    const responses = runtime_server.handleMessageFramesWithDebug(raw_payload, emit_debug) catch |err| {
        const response = try runtime_server.buildRuntimeErrorResponse(legacy.id orelse "generated", err);
        defer allocator.free(response);
        try writeFrameLocked(stream, write_mutex, response, .text);
        return true;
    };
    defer {
        for (responses) |item| allocator.free(item);
        allocator.free(responses);
    }

    for (responses) |item| {
        const decorated = try decorateSessionReceiveFrame(allocator, item, session_key);
        defer allocator.free(decorated);
        try writeFrameLocked(stream, write_mutex, decorated, .text);
        runtime_registry.maybeLogDebugFrame(binding.agent_id, decorated);
    }
    return true;
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
        .node_list => runtime_registry.control_plane.listNodes(),
        .node_get => runtime_registry.control_plane.getNode(payload_json),
        .node_delete => runtime_registry.control_plane.deleteNode(payload_json),
        .project_create => runtime_registry.control_plane.createProject(payload_json),
        .project_update => runtime_registry.control_plane.updateProject(payload_json),
        .project_delete => runtime_registry.control_plane.deleteProject(payload_json),
        .project_list => runtime_registry.control_plane.listProjects(),
        .project_get => runtime_registry.control_plane.getProject(payload_json),
        .project_mount_set => runtime_registry.control_plane.setProjectMount(payload_json),
        .project_mount_remove => runtime_registry.control_plane.removeProjectMount(payload_json),
        .project_mount_list => runtime_registry.control_plane.listProjectMounts(payload_json),
        .project_token_rotate => runtime_registry.control_plane.rotateProjectToken(payload_json),
        .project_token_revoke => runtime_registry.control_plane.revokeProjectToken(payload_json),
        .project_activate => runtime_registry.control_plane.activateProject(agent_id, payload_json),
        .workspace_status => runtime_registry.control_plane.workspaceStatus(agent_id, payload_json),
        .reconcile_status => runtime_registry.control_plane.reconcileStatus(payload_json),
        .project_up => runtime_registry.control_plane.projectUp(agent_id, payload_json),
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
        fs_control_plane.ControlPlaneError.NodeAuthFailed => "node_auth_failed",
        fs_control_plane.ControlPlaneError.PendingJoinNotFound => "pending_join_not_found",
        fs_control_plane.ControlPlaneError.ProjectNotFound => "project_not_found",
        fs_control_plane.ControlPlaneError.ProjectAuthFailed => "project_auth_failed",
        fs_control_plane.ControlPlaneError.ProjectProtected => "project_protected",
        fs_control_plane.ControlPlaneError.ProjectAssignmentForbidden => "project_assignment_forbidden",
        fs_control_plane.ControlPlaneError.MountConflict => "mount_conflict",
        fs_control_plane.ControlPlaneError.MountNotFound => "mount_not_found",
        else => "control_plane_error",
    };
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
        const body = runtime_registry.control_plane.metricsPrometheus() catch |err| {
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

    const json_body = runtime_registry.control_plane.metricsJson() catch |err| {
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
    runtime_registry.auth_tokens.admin_token = try allocator.dupe(u8, admin_token);
    runtime_registry.auth_tokens.user_token = try allocator.dupe(u8, user_token);
    runtime_registry.auth_tokens.admin_last_target = null;
    runtime_registry.auth_tokens.user_last_target = null;
}

fn seedUserRememberedTargetForTests(
    runtime_registry: *AgentRuntimeRegistry,
    agent_id: []const u8,
) !void {
    const allocator = runtime_registry.allocator;
    const project_up = try runtime_registry.control_plane.projectUp(
        agent_id,
        "{\"name\":\"User Seed Project\",\"activate\":true}",
    );
    defer allocator.free(project_up);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_up, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResult;
    const project_id_value = parsed.value.object.get("project_id") orelse return error.TestExpectedResult;
    if (project_id_value != .string) return error.TestExpectedResult;

    try runtime_registry.auth_tokens.setRememberedTarget(.user, agent_id, project_id_value.string);
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

fn readServerFrameSkippingDebug(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    debug_events_seen: ?*usize,
) !TestServerFrame {
    while (true) {
        var frame = try readServerFrame(allocator, stream);
        if (frame.opcode != 0x1 or std.mem.indexOf(u8, frame.payload, "\"type\":\"debug.event\"") == null) {
            return frame;
        }
        if (debug_events_seen) |count| count.* += 1;
        frame.deinit(allocator);
    }
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
    debug_events_seen: ?*usize,
) ![]u8 {
    const encoded = try unified.encodeDataB64(allocator, content);
    defer allocator.free(encoded);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_walk\",\"tag\":10,\"fid\":1,\"newfid\":2,\"path\":[\"capabilities\",\"chat\",\"control\",\"input\"]}");
    var walk = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
    defer walk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, walk.payload, "\"type\":\"acheron.r_walk\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_open\",\"tag\":11,\"fid\":2,\"mode\":\"rw\"}");
    var open = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
    defer open.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, open.payload, "\"type\":\"acheron.r_open\"") != null);

    const write_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_write\",\"tag\":12,\"fid\":2,\"offset\":0,\"data_b64\":\"{s}\"}}",
        .{encoded},
    );
    defer allocator.free(write_req);
    try writeClientTextFrameMasked(client, write_req);
    var write = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
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
    var clunk = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
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
    var walk = try readServerFrameSkippingDebug(allocator, client, null);
    defer walk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, walk.payload, "\"type\":\"acheron.r_walk\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_open\",\"tag\":21,\"fid\":3,\"mode\":\"r\"}");
    var open = try readServerFrameSkippingDebug(allocator, client, null);
    defer open.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, open.payload, "\"type\":\"acheron.r_open\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"acheron\",\"type\":\"acheron.t_read\",\"tag\":22,\"fid\":3,\"offset\":0,\"count\":1048576}");
    var read = try readServerFrameSkippingDebug(allocator, client, null);
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
    var clunk = try readServerFrameSkippingDebug(allocator, client, null);
    defer clunk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, clunk.payload, "\"type\":\"acheron.r_clunk\"") != null);

    return decoded;
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

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.debug_subscribe\",\"id\":\"req-debug-sub\"}");
    var debug_sub = try readServerFrame(allocator, &client);
    defer debug_sub.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"category\":\"control.subscription\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"enabled\":true") != null);

    var debug_events_seen: usize = 0;
    const job_name = try fsrpcWriteChatInput(allocator, &client, "hello", &debug_events_seen);
    defer allocator.free(job_name);
    try std.testing.expect(debug_events_seen > 0);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.debug_unsubscribe\",\"id\":\"req-debug-unsub\"}");
    var debug_unsub = try readServerFrame(allocator, &client);
    defer debug_unsub.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"category\":\"control.subscription\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"enabled\":false") != null);

    const result = try fsrpcReadJobResult(allocator, &client, job_name);
    defer allocator.free(result);
    try std.testing.expect(result.len > 0);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-chat\",\"type\":\"session.send\",\"content\":\"legacy\"}");
    var legacy_reply = try readServerFrame(allocator, &client);
    defer legacy_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), legacy_reply.opcode);
    try std.testing.expect(std.mem.indexOf(u8, legacy_reply.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, legacy_reply.payload, "\"code\":\"invalid_envelope\"") != null);

    try websocket_transport.writeFrame(&client, "", .close);
    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
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

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.project_create\",\"id\":\"p-missing\",\"payload\":{\"name\":\"NoToken\"}}");
    var missing_token = try readServerFrame(allocator, &client);
    defer missing_token.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, missing_token.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, missing_token.payload, "\"code\":\"missing_field\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.project_create\",\"id\":\"p-bad\",\"payload\":{\"name\":\"BadToken\",\"operator_token\":\"wrong\"}}");
    var bad_token = try readServerFrame(allocator, &client);
    defer bad_token.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, bad_token.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bad_token.payload, "\"code\":\"operator_auth_failed\"") != null);

    try writeClientTextFrameMasked(&client, "{\"channel\":\"control\",\"type\":\"control.project_create\",\"id\":\"p-good\",\"payload\":{\"name\":\"GoodToken\",\"operator_token\":\"operator-secret\"}}");
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
        try std.testing.expect(std.mem.indexOf(u8, forbidden_attach.payload, "\"code\":\"provisioning_required\"") != null);

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

test "server_piai: user connect is rejected when no remembered non-system target exists" {
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
    var connect_err = try readServerFrame(allocator, &user_client);
    defer connect_err.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, connect_err.payload, "\"type\":\"control.error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, connect_err.payload, "\"code\":\"provisioning_required\"") != null);

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
    try std.testing.expect(std.mem.indexOf(u8, attach_forbidden.payload, "\"code\":\"provisioning_required\"") != null);

    try websocket_transport.writeFrame(&user_client, "", .close);
    var close_reply = try readServerFrame(allocator, &user_client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

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

test "server_piai: workspace topology mutations are pushed to debug subscribers" {
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

    const sub_server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer sub_server_thread.join();
    const mut_server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer mut_server_thread.join();

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

    try writeClientTextFrameMasked(&subscriber, "{\"channel\":\"control\",\"type\":\"control.debug_subscribe\",\"id\":\"sub-debug\"}");
    var sub_debug_ack = try readServerFrame(allocator, &subscriber);
    defer sub_debug_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, sub_debug_ack.payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sub_debug_ack.payload, "\"category\":\"control.subscription\"") != null);

    var mutator = try std.net.tcpConnectToAddress(listener.listen_address);
    defer mutator.close();
    try performClientHandshakeWithBearerToken(allocator, &mutator, "/", "admin-secret");
    try writeClientTextFrameMasked(&mutator, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"mut-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var mut_version_ack = try readServerFrame(allocator, &mutator);
    defer mut_version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, mut_version_ack.payload, "\"type\":\"control.version_ack\"") != null);
    try writeClientTextFrameMasked(&mutator, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"mut-connect\"}");
    var mut_connect_ack = try readServerFrame(allocator, &mutator);
    defer mut_connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, mut_connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    try writeClientTextFrameMasked(
        &mutator,
        "{\"channel\":\"control\",\"type\":\"control.project_create\",\"id\":\"mut-project\",\"payload\":{\"name\":\"Topology Test\"}}",
    );
    var project_created = try readServerFrame(allocator, &mutator);
    defer project_created.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, project_created.payload, "\"type\":\"control.project_create\"") != null);

    var pushed = try readServerFrame(allocator, &subscriber);
    defer pushed.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, pushed.payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pushed.payload, "\"category\":\"control.workspace_topology\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pushed.payload, "workspace_topology_changed") != null);

    try websocket_transport.writeFrame(&mutator, "", .close);
    var mut_close = try readServerFrame(allocator, &mutator);
    defer mut_close.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), mut_close.opcode);

    try websocket_transport.writeFrame(&subscriber, "", .close);
    var sub_close = try readServerFrame(allocator, &subscriber);
    defer sub_close.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), sub_close.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: workspace availability changes are pushed to debug subscribers" {
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

    const sub_server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer sub_server_thread.join();
    const mut_server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer mut_server_thread.join();

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

    try writeClientTextFrameMasked(&subscriber, "{\"channel\":\"control\",\"type\":\"control.debug_subscribe\",\"id\":\"sub-debug\"}");
    var sub_debug_ack = try readServerFrame(allocator, &subscriber);
    defer sub_debug_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, sub_debug_ack.payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sub_debug_ack.payload, "\"category\":\"control.subscription\"") != null);

    var mutator = try std.net.tcpConnectToAddress(listener.listen_address);
    defer mutator.close();
    try performClientHandshakeWithBearerToken(allocator, &mutator, "/", "admin-secret");
    try writeClientTextFrameMasked(&mutator, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"mut-version\",\"payload\":{\"protocol\":\"unified-v2\"}}");
    var mut_version_ack = try readServerFrame(allocator, &mutator);
    defer mut_version_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, mut_version_ack.payload, "\"type\":\"control.version_ack\"") != null);
    try writeClientTextFrameMasked(&mutator, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"mut-connect\"}");
    var mut_connect_ack = try readServerFrame(allocator, &mutator);
    defer mut_connect_ack.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, mut_connect_ack.payload, "\"type\":\"control.connect_ack\"") != null);

    try writeClientTextFrameMasked(
        &mutator,
        "{\"channel\":\"control\",\"type\":\"control.node_invite_create\",\"id\":\"mut-invite\"}",
    );
    var invite_created = try readServerFrame(allocator, &mutator);
    defer invite_created.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, invite_created.payload, "\"type\":\"control.node_invite_create\"") != null);

    var invite_json = try std.json.parseFromSlice(std.json.Value, allocator, invite_created.payload, .{});
    defer invite_json.deinit();
    const invite_payload = invite_json.value.object.get("payload") orelse return error.TestExpectedResponse;
    if (invite_payload != .object) return error.TestExpectedResponse;
    const invite_token_val = invite_payload.object.get("invite_token") orelse return error.TestExpectedResponse;
    if (invite_token_val != .string) return error.TestExpectedResponse;
    const escaped_invite_token = try unified.jsonEscape(allocator, invite_token_val.string);
    defer allocator.free(escaped_invite_token);

    const join_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.node_join\",\"id\":\"mut-join\",\"payload\":{{\"invite_token\":\"{s}\",\"node_name\":\"ephemeral\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\",\"lease_ttl_ms\":1}}}}",
        .{escaped_invite_token},
    );
    defer allocator.free(join_req);
    try writeClientTextFrameMasked(&mutator, join_req);
    var joined = try readServerFrame(allocator, &mutator);
    defer joined.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, joined.payload, "\"type\":\"control.node_join\"") != null);

    var pushed_join_topology = try readServerFrame(allocator, &subscriber);
    defer pushed_join_topology.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, pushed_join_topology.payload, "\"category\":\"control.workspace_topology\"") != null);

    var pushed_join_availability = try readServerFrame(allocator, &subscriber);
    defer pushed_join_availability.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, pushed_join_availability.payload, "\"category\":\"control.workspace_availability\"") != null);

    std.Thread.sleep(10 * std.time.ns_per_ms);

    try writeClientTextFrameMasked(
        &mutator,
        "{\"channel\":\"control\",\"type\":\"control.workspace_status\",\"id\":\"mut-status\",\"payload\":{}}",
    );
    var status = try readServerFrame(allocator, &mutator);
    defer status.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, status.payload, "\"type\":\"control.workspace_status\"") != null);

    var pushed_reap_topology = try readServerFrame(allocator, &subscriber);
    defer pushed_reap_topology.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, pushed_reap_topology.payload, "\"category\":\"control.workspace_topology\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pushed_reap_topology.payload, "availability_changed") != null);

    var pushed_reap_availability = try readServerFrame(allocator, &subscriber);
    defer pushed_reap_availability.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, pushed_reap_availability.payload, "\"category\":\"control.workspace_availability\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pushed_reap_availability.payload, "workspace_availability_changed") != null);

    try websocket_transport.writeFrame(&mutator, "", .close);
    var mut_close = try readServerFrame(allocator, &mutator);
    defer mut_close.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), mut_close.opcode);

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
        const alpha_job = try fsrpcWriteChatInput(allocator, &client, "alpha hello", null);
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
        const beta_job = try fsrpcWriteChatInput(allocator, &client, "beta hello", null);
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

test "server_piai: validateFsNodeHelloPayload enforces optional auth_token" {
    const allocator = std.testing.allocator;
    try validateFsNodeHelloPayload(
        allocator,
        "{\"protocol\":\"unified-v2-fs\",\"proto\":2}",
        null,
    );
    try validateFsNodeHelloPayload(
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
