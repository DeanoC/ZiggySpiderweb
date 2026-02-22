const std = @import("std");
const Config = @import("config.zig");
const connection_dispatcher = @import("connection_dispatcher.zig");
const memory = @import("ziggy-memory-store").memory;
const protocol = @import("ziggy-spider-protocol").protocol;
const runtime_server_mod = @import("runtime_server.zig");
const websocket_transport = @import("websocket_transport.zig");
const fsrpc_session = @import("fsrpc_session.zig");
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

const AgentRuntimeRegistry = struct {
    allocator: std.mem.Allocator,
    runtime_config: Config.RuntimeConfig,
    provider_config: ?Config.ProviderConfig,
    default_agent_id: []const u8,
    max_runtimes: usize,
    debug_stream_sink: DebugStreamFileSink,
    mutex: std.Thread.Mutex = .{},
    by_agent: std.StringHashMapUnmanaged(*RuntimeServer) = .{},

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

        return .{
            .allocator = allocator,
            .runtime_config = runtime_config,
            .provider_config = provider_config,
            .default_agent_id = effective_default,
            .max_runtimes = if (max_runtimes == 0) 1 else max_runtimes,
            .debug_stream_sink = debug_stream_sink,
        };
    }

    fn deinit(self: *AgentRuntimeRegistry) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.by_agent.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.destroy();
        }
        self.by_agent.deinit(self.allocator);
        self.debug_stream_sink.deinit();
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
};

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
        "Runtime websocket server listening at ws://{s}:{d}/v2/agents/{s}/stream",
        .{ bind_addr, port, runtime_registry.default_agent_id },
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

    const agent_id = parseAgentIdFromStreamPath(handshake.path) orelse {
        try sendWebSocketErrorAndClose(allocator, stream, .invalid_envelope, "invalid stream path");
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
    var fsrpc = try fsrpc_session.Session.init(allocator, runtime_server, agent_id);
    defer fsrpc.deinit();
    var debug_stream_enabled = false;

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
                    try websocket_transport.writeFrame(stream, response, .text);
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
                            try websocket_transport.writeFrame(stream, response, .text);
                            continue;
                        };

                        switch (control_type) {
                            .connect => {
                                const payload = try std.fmt.allocPrint(
                                    allocator,
                                    "{{\"agent_id\":\"{s}\",\"session\":\"main\",\"protocol\":\"v2\"}}",
                                    .{agent_id},
                                );
                                defer allocator.free(payload);
                                const response = try unified.buildControlAck(
                                    allocator,
                                    .connect_ack,
                                    parsed.id,
                                    payload,
                                );
                                defer allocator.free(response);
                                try websocket_transport.writeFrame(stream, response, .text);
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
                                try websocket_transport.writeFrame(stream, response, .text);
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
                                try websocket_transport.writeFrame(stream, response, .text);
                                continue;
                            },
                            .debug_subscribe, .debug_unsubscribe => {
                                debug_stream_enabled = control_type == .debug_subscribe;
                                fsrpc.setDebugStreamEnabled(debug_stream_enabled);
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
                                try websocket_transport.writeFrame(stream, ack, .text);
                                runtime_registry.maybeLogDebugFrame(agent_id, ack);
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
                                try websocket_transport.writeFrame(stream, response, .text);
                                continue;
                            },
                        }
                    },
                    .fsrpc => {
                        const response = try fsrpc.handle(&parsed);
                        defer allocator.free(response);
                        try websocket_transport.writeFrame(stream, response, .text);

                        const debug_frames = try fsrpc.drainPendingDebugFrames();
                        if (debug_frames.len > 0) {
                            defer allocator.free(debug_frames);
                            for (debug_frames) |payload| {
                                defer allocator.free(payload);
                                try websocket_transport.writeFrame(stream, payload, .text);
                                runtime_registry.maybeLogDebugFrame(agent_id, payload);
                            }
                        }
                        continue;
                    },
                }
            },
            0x8 => {
                try websocket_transport.writeFrame(stream, "", .close);
                return;
            },
            0x9 => {
                try websocket_transport.writeFrame(stream, frame.payload, .pong);
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

fn parseAgentIdFromStreamPath(path: []const u8) ?[]const u8 {
    const prefix = "/v2/agents/";
    const stream_suffix = "/stream";
    if (!std.mem.startsWith(u8, path, prefix)) return null;

    const after_prefix = path[prefix.len..];
    const suffix_at = std.mem.indexOf(u8, after_prefix, stream_suffix) orelse return null;
    if (suffix_at == 0) return null;

    const agent_id = after_prefix[0..suffix_at];
    if (std.mem.indexOfScalar(u8, agent_id, '/') != null) return null;

    const trailing = after_prefix[suffix_at + stream_suffix.len ..];
    if (trailing.len != 0 and !std.mem.startsWith(u8, trailing, "?")) return null;
    return agent_id;
}

fn sendServiceUnavailable(stream: *std.net.Stream) !void {
    const payload =
        "HTTP/1.1 503 Service Unavailable\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    try stream.writeAll(payload);
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

test "server_piai: websocket path handles unified control/fsrpc chat flow and rejects legacy session.send" {
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

    try performClientHandshake(allocator, &client, "/v2/agents/default/stream");

    try fsrpcConnectAndAttach(allocator, &client, "req-connect");

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

test "server_piai: route path agent id isolates runtime state across connections" {
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
        try performClientHandshake(allocator, &client, "/v2/agents/alpha/stream");

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
        try performClientHandshake(allocator, &client, "/v2/agents/beta/stream");

        try fsrpcConnectAndAttach(allocator, &client, "b-connect");
        const beta_job = try fsrpcWriteChatInput(allocator, &client, "beta hello", null);
        defer allocator.free(beta_job);

        try websocket_transport.writeFrame(&client, "", .close);
        var close_reply = try readServerFrame(allocator, &client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

    const alpha_runtime = try runtime_registry.getOrCreate("alpha");
    const beta_runtime = try runtime_registry.getOrCreate("beta");

    const alpha_snapshot = try alpha_runtime.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, alpha_snapshot);
    const alpha_json = try memory.toActiveMemoryJson(allocator, "primary", alpha_snapshot);
    defer allocator.free(alpha_json);

    const beta_snapshot = try beta_runtime.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, beta_snapshot);
    const beta_json = try memory.toActiveMemoryJson(allocator, "primary", beta_snapshot);
    defer allocator.free(beta_json);

    try std.testing.expect(std.mem.indexOf(u8, alpha_json, "alpha hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpha_json, "beta hello") == null);
    try std.testing.expect(std.mem.indexOf(u8, beta_json, "beta hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, beta_json, "alpha hello") == null);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: runtime creation is capped to avoid unbounded per-agent growth" {
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
        try performClientHandshake(allocator, &client, "/v2/agents/alpha/stream");

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
        try performClientHandshake(allocator, &client, "/v2/agents/beta/stream");

        var limit_error = try readServerFrame(allocator, &client);
        defer limit_error.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, limit_error.payload, "\"code\":\"queue_saturated\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, limit_error.payload, "agent runtime limit reached") != null);

        var close_reply = try readServerFrame(allocator, &client);
        defer close_reply.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);
    }

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
    try std.testing.expect(std.mem.indexOf(u8, invalid_path_error.payload, "invalid stream path") != null);

    var close_reply = try readServerFrame(allocator, &client);
    defer close_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8), close_reply.opcode);

    try std.testing.expect(server_ctx.err_name == null);
}

test "server_piai: parse route path extracts agent id" {
    const path = parseAgentIdFromStreamPath("/v2/agents/alpha/stream") orelse return error.TestExpectedAgent;
    try std.testing.expectEqualStrings("alpha", path);
    try std.testing.expect(parseAgentIdFromStreamPath("/v2/agents/alpha/stream?x=1") != null);
    try std.testing.expect(parseAgentIdFromStreamPath("/v2/agents//stream") == null);
    try std.testing.expect(parseAgentIdFromStreamPath("/v2/agents/alpha/not-stream") == null);
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
