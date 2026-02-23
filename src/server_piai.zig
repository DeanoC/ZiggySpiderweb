const std = @import("std");
const Config = @import("config.zig");
const connection_dispatcher = @import("connection_dispatcher.zig");
const memory = @import("ziggy-memory-store").memory;
const protocol = @import("ziggy-spider-protocol").protocol;
const runtime_server_mod = @import("runtime_server.zig");
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
const local_node_default_export_name = "spider-web-root";
const control_operator_token_env = "SPIDERWEB_CONTROL_OPERATOR_TOKEN";
const control_project_scope_token_env = "SPIDERWEB_CONTROL_PROJECT_SCOPE_TOKEN";
const control_node_scope_token_env = "SPIDERWEB_CONTROL_NODE_SCOPE_TOKEN";
const metrics_port_env = "SPIDERWEB_METRICS_PORT";
const control_protocol_version = "unified-v2";
const fsrpc_runtime_protocol_version = "styx-lite-1";
const fsrpc_node_protocol_version = "unified-v2-fs";
const fsrpc_node_proto_id: i64 = 2;

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

    fn register(self: *FsConnectionHub, stream: *std.net.Stream) !*FsHubConnection {
        const conn = try self.allocator.create(FsHubConnection);
        errdefer self.allocator.destroy(conn);

        self.mutex.lock();
        defer self.mutex.unlock();
        conn.* = .{
            .id = self.next_id,
            .stream = stream,
        };
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
            conn.write_mutex.lock();
            websocket_transport.writeFrame(conn.stream, payload, .text) catch {
                conn.stream.close();
            };
            conn.write_mutex.unlock();
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

const LocalFsNode = struct {
    allocator: std.mem.Allocator,
    service: fs_node_service.NodeService,
    hub: FsConnectionHub,
    node_name: []u8,
    export_name: []u8,
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
        export_spec: fs_node_ops.ExportSpec,
        node_name: []const u8,
        fs_url: []const u8,
        lease_ttl_ms: u64,
        heartbeat_interval_ms: u64,
    ) !*LocalFsNode {
        const endpoint = try allocator.create(LocalFsNode);
        errdefer allocator.destroy(endpoint);

        endpoint.* = .{
            .allocator = allocator,
            .service = try fs_node_service.NodeService.init(allocator, &[_]fs_node_ops.ExportSpec{export_spec}),
            .hub = .{ .allocator = allocator },
            .node_name = try allocator.dupe(u8, node_name),
            .export_name = try allocator.dupe(u8, export_spec.name),
            .fs_url = try allocator.dupe(u8, fs_url),
            .lease_ttl_ms = lease_ttl_ms,
            .heartbeat_interval_ms = heartbeat_interval_ms,
        };
        errdefer {
            endpoint.hub.deinit();
            endpoint.service.deinit();
            allocator.free(endpoint.node_name);
            allocator.free(endpoint.export_name);
            allocator.free(endpoint.fs_url);
        }

        if (fs_watch_runtime.spawnDetached(
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
        self.allocator.free(self.export_name);
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
                try control_plane.ensureSpiderWebMount(mount_node_id, self.export_name);
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
        try control_plane.ensureSpiderWebMount(mount_node_id, self.export_name);
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

                if (!fsrpc_negotiated) {
                    if (parsed.channel != .fsrpc or parsed.fsrpc_type != .fs_t_hello) {
                        const response = try unified.buildFsrpcFsError(
                            allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            "fsrpc.t_fs_hello must be negotiated first",
                        );
                        defer allocator.free(response);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, response, .text);
                        try writeFsHubFrameMaybe(connection, stream, &connection_write_mutex, "", .close);
                        return;
                    }
                    validateFsNodeHelloPayload(allocator, parsed.payload_json, required_auth_token) catch |err| {
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
                    connection = try local_node.hub.register(stream);
                    fsrpc_negotiated = true;
                } else if (parsed.fsrpc_type == .fs_t_hello) {
                    validateFsNodeHelloPayload(allocator, parsed.payload_json, required_auth_token) catch |err| {
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
                const live_connection = connection orelse return error.InvalidConnectionState;

                for (handled.events) |event| {
                    const event_json = try fs_node_service.buildInvalidationEventJson(allocator, event);
                    defer allocator.free(event_json);
                    try writeFsHubFrame(live_connection, event_json, .text);
                }

                if (handled.events.len > 0) {
                    local_node.hub.broadcastInvalidations(live_connection.id, handled.events);
                }
                try writeFsHubFrame(live_connection, handled.response_json, .text);
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

const AgentRuntimeRegistry = struct {
    allocator: std.mem.Allocator,
    runtime_config: Config.RuntimeConfig,
    provider_config: ?Config.ProviderConfig,
    default_agent_id: []const u8,
    max_runtimes: usize,
    debug_stream_sink: DebugStreamFileSink,
    control_plane: fs_control_plane.ControlPlane,
    job_index: chat_job_index.ChatJobIndex,
    control_operator_token: ?[]u8 = null,
    control_project_scope_token: ?[]u8 = null,
    control_node_scope_token: ?[]u8 = null,
    local_fs_node: ?*LocalFsNode = null,
    mutex: std.Thread.Mutex = .{},
    by_agent: std.StringHashMapUnmanaged(*RuntimeServer) = .{},
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
            runtime_server_mod.default_agent_id
        else
            runtime_config.default_agent_id;
        const effective_default = if (isValidAgentId(configured_default))
            configured_default
        else
            runtime_server_mod.default_agent_id;
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

        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.by_agent.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.destroy();
        }
        self.by_agent.deinit(self.allocator);
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
        self.audit_records_mutex.lock();
        for (self.audit_records.items) |*record| record.deinit(self.allocator);
        self.audit_records.deinit(self.allocator);
        self.audit_records = .{};
        self.next_audit_record_id = 1;
        self.audit_records_mutex.unlock();
        self.job_index.deinit();
        self.control_plane.deinit();
        self.debug_stream_sink.deinit();
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

    fn getOrCreate(self: *AgentRuntimeRegistry, agent_id: []const u8) !*RuntimeServer {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_agent.get(agent_id)) |existing| return existing;
        if (!isValidAgentId(agent_id)) return error.InvalidAgentId;
        if (self.by_agent.count() >= self.max_runtimes) return error.RuntimeLimitReached;

        const owned_agent = try self.allocator.dupe(u8, agent_id);
        errdefer self.allocator.free(owned_agent);

        const runtime_server = if (self.provider_config) |provider_cfg|
            try RuntimeServer.createWithProvider(
                self.allocator,
                owned_agent,
                self.runtime_config,
                provider_cfg,
            )
        else
            try RuntimeServer.create(
                self.allocator,
                owned_agent,
                self.runtime_config,
            );
        errdefer runtime_server.destroy();

        try self.by_agent.put(self.allocator, owned_agent, runtime_server);
        return runtime_server;
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

    fn appendAuditRecord(
        self: *AgentRuntimeRegistry,
        agent_id: []const u8,
        control_type: unified.ControlType,
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
            .control_type = self.allocator.dupe(u8, unified.controlTypeName(control_type)) catch return,
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
        } else configured_export_path;
        if (export_path.len == 0) {
            std.log.warn(
                "local fs node disabled: both {s} and runtime.spider_web_root are empty",
                .{local_node_export_path_env},
            );
            return;
        }

        const export_name_owned = std.process.getEnvVarOwned(self.allocator, local_node_export_name_env) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (export_name_owned) |value| self.allocator.free(value);
        const export_name = if (export_name_owned) |value|
            if (std.mem.trim(u8, value, " \t\r\n").len > 0) std.mem.trim(u8, value, " \t\r\n") else local_node_default_export_name
        else
            local_node_default_export_name;

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
            if (trimmed.len == 0) break :blk try std.fmt.allocPrint(self.allocator, "ws://{s}:{d}/v2/fs", .{ bind_addr, port });
            break :blk try self.allocator.dupe(u8, trimmed);
        } else try std.fmt.allocPrint(self.allocator, "ws://{s}:{d}/v2/fs", .{ bind_addr, port });
        defer self.allocator.free(fs_url);

        const lease_ttl_ms = parseUnsignedEnv(self.allocator, local_node_lease_ttl_env, 15 * 60 * 1000);
        var heartbeat_ms = parseUnsignedEnv(self.allocator, local_node_heartbeat_ms_env, lease_ttl_ms / 2);
        if (heartbeat_ms == 0) heartbeat_ms = 1_000;
        if (heartbeat_ms > lease_ttl_ms) heartbeat_ms = lease_ttl_ms;

        const local_node = try LocalFsNode.create(
            self.allocator,
            .{
                .name = export_name,
                .path = export_path,
                .ro = export_ro,
                .desc = "spiderweb-local-export",
            },
            node_name,
            fs_url,
            lease_ttl_ms,
            heartbeat_ms,
        );
        errdefer local_node.deinit(&self.control_plane);
        try local_node.startRegistrationAndHeartbeat(&self.control_plane);

        self.local_fs_node = local_node;
        std.log.info(
            "local fs node enabled at ws://{s}:{d}/v2/fs export={s}:{s} ({s})",
            .{ bind_addr, port, export_name, export_path, if (export_ro) "ro" else "rw" },
        );
    }
};

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

    _ = try runtime_registry.getOrCreate(runtime_registry.default_agent_id);
    runtime_registry.maybeInitLocalFsNode(bind_addr, port) catch |err| {
        std.log.warn("local fs node setup skipped: {s}", .{@errorName(err)});
    };
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

    const dispatcher = try connection_dispatcher.ConnectionDispatcher.create(
        allocator,
        runtime_config.connection_worker_threads,
        runtime_config.connection_queue_max,
        workerHandleConnection,
        &runtime_registry,
    );
    defer dispatcher.destroy();

    std.log.info(
        "Runtime websocket server listening at ws://{s}:{d}",
        .{ bind_addr, port },
    );

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
        const local_node = runtime_registry.local_fs_node orelse {
            try sendWebSocketErrorAndClose(allocator, stream, .invalid_envelope, "local /v2/fs endpoint is disabled");
            return;
        };
        try handleLocalFsConnection(allocator, local_node, stream);
        return;
    }

    const agent_id = resolveAgentIdFromConnectionPath(handshake.path, runtime_registry.default_agent_id) orelse {
        try sendWebSocketErrorAndClose(allocator, stream, .invalid_envelope, "invalid websocket path");
        return;
    };
    const runtime_server = runtime_registry.getOrCreate(agent_id) catch |err| switch (err) {
        error.InvalidAgentId => {
            try sendWebSocketErrorAndClose(allocator, stream, .invalid_envelope, "invalid agent id");
            return;
        },
        error.RuntimeLimitReached => {
            try sendWebSocketErrorAndClose(allocator, stream, .queue_saturated, "agent runtime limit reached");
            return;
        },
        else => return err,
    };
    var fsrpc = try fsrpc_session.Session.init(allocator, runtime_server, &runtime_registry.job_index, agent_id);
    defer fsrpc.deinit();
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
                                const payload = try std.fmt.allocPrint(
                                    allocator,
                                    "{{\"agent_id\":\"{s}\",\"session\":\"main\",\"protocol\":\"{s}\"}}",
                                    .{ agent_id, control_protocol_version },
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
                            .session_attach, .session_resume => {
                                const response = try unified.buildControlAck(
                                    allocator,
                                    control_type,
                                    parsed.id,
                                    "{\"session\":\"main\"}",
                                );
                                defer allocator.free(response);
                                try writeFrameLocked(stream, &connection_write_mutex, response, .text);
                                continue;
                            },
                            .debug_subscribe, .debug_unsubscribe => {
                                debug_stream_enabled = control_type == .debug_subscribe;
                                fsrpc.setDebugStreamEnabled(debug_stream_enabled);
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
                                runtime_registry.maybeLogDebugFrame(agent_id, ack);
                                continue;
                            },
                            .node_invite_create,
                            .node_join,
                            .node_lease_refresh,
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
                                const scope = controlMutationScope(control_type);
                                const correlation_id = parsed.correlation_id orelse parsed.id;
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
                                            agent_id,
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
                                const payload_json = handleControlPlaneCommand(
                                    runtime_registry,
                                    control_type,
                                    agent_id,
                                    parsed.payload_json,
                                ) catch |err| {
                                    const code = controlPlaneErrorCode(err);
                                    if (scope != .none) {
                                        runtime_registry.appendAuditRecord(
                                            agent_id,
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
                                        agent_id,
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
                                if (isWorkspaceTopologyMutation(control_type)) {
                                    runtime_registry.control_plane.requestReconcile();
                                    const reason = unified.controlTypeName(control_type);
                                    runtime_registry.emitWorkspaceTopologyChanged(reason);
                                    runtime_registry.emitWorkspaceTopologyProjectDelta(
                                        agent_id,
                                        reason,
                                        parsed.payload_json,
                                        payload_json,
                                    );
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
                    .fsrpc => {
                        const fsrpc_type = parsed.fsrpc_type orelse {
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
                                    "fsrpc.t_version must be negotiated first",
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

                        const response = try fsrpc.handle(&parsed);
                        defer allocator.free(response);
                        try writeFrameLocked(stream, &connection_write_mutex, response, .text);

                        const debug_frames = try fsrpc.drainPendingDebugFrames();
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
                                runtime_registry.maybeLogDebugFrame(agent_id, payload);
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

fn validateFsNodeHelloPayload(
    allocator: std.mem.Allocator,
    payload_json: ?[]const u8,
    required_auth_token: ?[]const u8,
) !void {
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
        .node_join,
        .node_lease_refresh,
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
        .node_join => runtime_registry.control_plane.nodeJoin(payload_json),
        .node_lease_refresh => runtime_registry.control_plane.refreshNodeLease(payload_json),
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

fn performClientHandshake(allocator: std.mem.Allocator, client: *std.net.Stream, path: []const u8) !void {
    const handshake = try std.fmt.allocPrint(
        allocator,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
        .{path},
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

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_version\",\"tag\":1,\"msize\":1048576,\"version\":\"styx-lite-1\"}");
    var version = try readServerFrame(allocator, client);
    defer version.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, version.payload, "\"type\":\"fsrpc.r_version\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_attach\",\"tag\":2,\"fid\":1}");
    var attach = try readServerFrame(allocator, client);
    defer attach.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, attach.payload, "\"type\":\"fsrpc.r_attach\"") != null);
}

fn fsrpcWriteChatInput(
    allocator: std.mem.Allocator,
    client: *std.net.Stream,
    content: []const u8,
    debug_events_seen: ?*usize,
) ![]u8 {
    const encoded = try unified.encodeDataB64(allocator, content);
    defer allocator.free(encoded);

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_walk\",\"tag\":10,\"fid\":1,\"newfid\":2,\"path\":[\"capabilities\",\"chat\",\"control\",\"input\"]}");
    var walk = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
    defer walk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, walk.payload, "\"type\":\"fsrpc.r_walk\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_open\",\"tag\":11,\"fid\":2,\"mode\":\"rw\"}");
    var open = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
    defer open.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, open.payload, "\"type\":\"fsrpc.r_open\"") != null);

    const write_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_write\",\"tag\":12,\"fid\":2,\"offset\":0,\"data_b64\":\"{s}\"}}",
        .{encoded},
    );
    defer allocator.free(write_req);
    try writeClientTextFrameMasked(client, write_req);
    var write = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
    defer write.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, write.payload, "\"type\":\"fsrpc.r_write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, write.payload, "\"job\":\"job-") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, write.payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResponse;
    const payload = parsed.value.object.get("payload") orelse return error.TestExpectedResponse;
    if (payload != .object) return error.TestExpectedResponse;
    const job = payload.object.get("job") orelse return error.TestExpectedResponse;
    if (job != .string) return error.TestExpectedResponse;
    const job_name = try allocator.dupe(u8, job.string);

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_clunk\",\"tag\":13,\"fid\":2}");
    var clunk = try readServerFrameSkippingDebug(allocator, client, debug_events_seen);
    defer clunk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, clunk.payload, "\"type\":\"fsrpc.r_clunk\"") != null);

    return job_name;
}

fn fsrpcReadJobResult(allocator: std.mem.Allocator, client: *std.net.Stream, job_name: []const u8) ![]u8 {
    const escaped_job = try unified.jsonEscape(allocator, job_name);
    defer allocator.free(escaped_job);

    const walk_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_walk\",\"tag\":20,\"fid\":1,\"newfid\":3,\"path\":[\"jobs\",\"{s}\",\"result.txt\"]}}",
        .{escaped_job},
    );
    defer allocator.free(walk_req);
    try writeClientTextFrameMasked(client, walk_req);
    var walk = try readServerFrameSkippingDebug(allocator, client, null);
    defer walk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, walk.payload, "\"type\":\"fsrpc.r_walk\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_open\",\"tag\":21,\"fid\":3,\"mode\":\"r\"}");
    var open = try readServerFrameSkippingDebug(allocator, client, null);
    defer open.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, open.payload, "\"type\":\"fsrpc.r_open\"") != null);

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_read\",\"tag\":22,\"fid\":3,\"offset\":0,\"count\":1048576}");
    var read = try readServerFrameSkippingDebug(allocator, client, null);
    defer read.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, read.payload, "\"type\":\"fsrpc.r_read\"") != null);

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

    try writeClientTextFrameMasked(client, "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_clunk\",\"tag\":23,\"fid\":3}");
    var clunk = try readServerFrameSkippingDebug(allocator, client, null);
    defer clunk.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, clunk.payload, "\"type\":\"fsrpc.r_clunk\"") != null);

    return decoded;
}

test "server_piai: base websocket path handles unified control/fsrpc chat flow and rejects legacy session.send" {
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

    try performClientHandshake(allocator, &client, "/");

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
    try performClientHandshake(allocator, &client, "/");

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

test "server_piai: workspace topology mutations are pushed to debug subscribers" {
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

    const sub_server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer sub_server_thread.join();
    const mut_server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer mut_server_thread.join();

    var subscriber = try std.net.tcpConnectToAddress(listener.listen_address);
    defer subscriber.close();
    try performClientHandshake(allocator, &subscriber, "/");
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
    try performClientHandshake(allocator, &mutator, "/");
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

test "server_piai: base path routes all connections to default runtime" {
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

    {
        const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
        defer server_thread.join();

        var client = try std.net.tcpConnectToAddress(listener.listen_address);
        defer client.close();
        try performClientHandshake(allocator, &client, "/");

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
        try performClientHandshake(allocator, &client, "/");

        try fsrpcConnectAndAttach(allocator, &client, "b-connect");
        const beta_job = try fsrpcWriteChatInput(allocator, &client, "beta hello", null);
        defer allocator.free(beta_job);

        try websocket_transport.writeFrame(&client, "", .close);
        var close_reply = try readServerFrame(allocator, &client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    const runtime = try runtime_registry.getOrCreate(runtime_registry.default_agent_id);
    const snapshot = try runtime.runtime.active_memory.snapshotActive(allocator, "primary");
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
        try performClientHandshake(allocator, &client, "/");

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
        try performClientHandshake(allocator, &client, "/");

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

test "server_piai: invalid configured default agent falls back to built-in default" {
    const allocator = std.testing.allocator;
    var cfg = Config.RuntimeConfig{};
    cfg.default_agent_id = ".";

    const registry = AgentRuntimeRegistry.initWithLimits(allocator, cfg, null, 8);
    try std.testing.expectEqualStrings(runtime_server_mod.default_agent_id, registry.default_agent_id);
}

test "server_piai: parseArchiveTimestamp accepts rotated debug archive names" {
    try std.testing.expectEqual(@as(?u64, 1771674073992), parseArchiveTimestamp("debug-stream-1771674073992.ndjson"));
    try std.testing.expectEqual(@as(?u64, 1771674073992), parseArchiveTimestamp("debug-stream-1771674073992.ndjson.gz"));
    try std.testing.expectEqual(@as(?u64, 1771674073992), parseArchiveTimestamp("debug-stream-1771674073992-1.ndjson"));
    try std.testing.expectEqual(@as(?u64, null), parseArchiveTimestamp("debug-stream.ndjson"));
    try std.testing.expectEqual(@as(?u64, null), parseArchiveTimestamp("debug-stream-abc.ndjson"));
}
