const std = @import("std");
const Config = @import("config.zig");
const connection_dispatcher = @import("connection_dispatcher.zig");
const memory = @import("memory.zig");
const protocol = @import("protocol.zig");
const runtime_server_mod = @import("runtime_server.zig");
const websocket_transport = @import("websocket_transport.zig");

pub const RuntimeServer = runtime_server_mod.RuntimeServer;

const default_max_agent_runtimes: usize = 64;
const max_agent_id_len: usize = 64;

const AgentRuntimeRegistry = struct {
    allocator: std.mem.Allocator,
    runtime_config: Config.RuntimeConfig,
    provider_config: ?Config.ProviderConfig,
    default_agent_id: []const u8,
    max_runtimes: usize,
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

        return .{
            .allocator = allocator,
            .runtime_config = runtime_config,
            .provider_config = provider_config,
            .default_agent_id = effective_default,
            .max_runtimes = if (max_runtimes == 0) 1 else max_runtimes,
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
        "Runtime websocket server listening at ws://{s}:{d}/v1/agents/{s}/stream",
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

    const agent_id = parseAgentIdFromStreamPath(handshake.path) orelse runtime_registry.getFirstAgentId() orelse runtime_registry.default_agent_id;
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
                const msg_type = protocol.parseMessageType(frame.payload);
                if (msg_type == .connect) {
                    var parsed_connect = protocol.parseMessage(allocator, frame.payload) catch {
                        const invalid = try protocol.buildErrorWithCode(
                            allocator,
                            "unknown",
                            .invalid_envelope,
                            "invalid request envelope",
                        );
                        defer allocator.free(invalid);
                        try websocket_transport.writeFrame(stream, invalid, .text);
                        continue;
                    };
                    defer protocol.deinitParsedMessage(allocator, &parsed_connect);

                    const request_id = parsed_connect.id orelse "generated";
                    const connect_ack = try protocol.buildConnectAck(allocator, request_id);
                    defer allocator.free(connect_ack);
                    try websocket_transport.writeFrame(stream, connect_ack, .text);

                    const bootstrap_responses = runtime_server.handleConnectBootstrapFrames(request_id) catch |err| blk: {
                        const fallback = try protocol.buildErrorWithCode(
                            allocator,
                            request_id,
                            .execution_failed,
                            @errorName(err),
                        );
                        const wrapped = try allocator.alloc([]u8, 1);
                        wrapped[0] = fallback;
                        break :blk wrapped;
                    };
                    defer runtime_server_mod.deinitResponseFrames(allocator, bootstrap_responses);
                    for (bootstrap_responses) |response| {
                        try websocket_transport.writeFrame(stream, response, .text);
                    }
                    continue;
                }

                if (msg_type == .agent_control) {
                    var parsed_control = protocol.parseMessage(allocator, frame.payload) catch {
                        const invalid = try protocol.buildErrorWithCode(
                            allocator,
                            "unknown",
                            .invalid_envelope,
                            "invalid request envelope",
                        );
                        defer allocator.free(invalid);
                        try websocket_transport.writeFrame(stream, invalid, .text);
                        continue;
                    };
                    defer protocol.deinitParsedMessage(allocator, &parsed_control);

                    const action = parsed_control.action orelse "";
                    if (std.mem.eql(u8, action, "debug.subscribe") or std.mem.eql(u8, action, "debug.unsubscribe")) {
                        debug_stream_enabled = std.mem.eql(u8, action, "debug.subscribe");
                        const request_id = parsed_control.id orelse "generated";
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
                        continue;
                    }
                }

                const responses = runtime_server.handleMessageFramesWithDebug(frame.payload, debug_stream_enabled) catch |err| blk: {
                    const fallback = try protocol.buildErrorWithCode(
                        allocator,
                        "unknown",
                        .execution_failed,
                        @errorName(err),
                    );
                    const wrapped = try allocator.alloc([]u8, 1);
                    wrapped[0] = fallback;
                    break :blk wrapped;
                };
                defer runtime_server_mod.deinitResponseFrames(allocator, responses);
                for (responses) |response| {
                    try websocket_transport.writeFrame(stream, response, .text);
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
    const prefix = "/v1/agents/";
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

test "server_piai: websocket path handles connect/session.send and rejects chat.send" {
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

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-connect\",\"type\":\"connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), connect_ack.opcode);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"connect.ack\"") != null);
    var bootstrap_frame = try readServerFrame(allocator, &client);
    defer bootstrap_frame.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, bootstrap_frame.payload, "\"type\":\"session.receive\"") != null);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-session\",\"type\":\"session.send\",\"content\":\"hello\"}");
    var session_frame = try readServerFrame(allocator, &client);
    defer session_frame.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), session_frame.opcode);
    try std.testing.expect(std.mem.indexOf(u8, session_frame.payload, "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, session_frame.payload, "\"type\":\"tool.event\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, session_frame.payload, "\"type\":\"memory.event\"") == null);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-debug-sub\",\"type\":\"agent.control\",\"action\":\"debug.subscribe\"}");
    var debug_sub = try readServerFrame(allocator, &client);
    defer debug_sub.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"category\":\"control.subscription\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_sub.payload, "\"enabled\":true") != null);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-debug-unsub\",\"type\":\"agent.control\",\"action\":\"debug.unsubscribe\"}");
    var debug_unsub = try readServerFrame(allocator, &client);
    defer debug_unsub.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"category\":\"control.subscription\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, debug_unsub.payload, "\"enabled\":false") != null);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-chat\",\"type\":\"chat.send\",\"content\":\"legacy\"}");
    var legacy_reply = try readServerFrame(allocator, &client);
    defer legacy_reply.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), legacy_reply.opcode);
    try std.testing.expect(std.mem.indexOf(u8, legacy_reply.payload, "\"code\":\"unsupported_message_type\"") != null);

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
        try performClientHandshake(allocator, &client, "/v1/agents/alpha/stream");

        try writeClientTextFrameMasked(&client, "{\"id\":\"a-connect\",\"type\":\"connect\"}");
        var connect_ack = try readServerFrame(allocator, &client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"connect.ack\"") != null);
        var bootstrap_frame = try readServerFrame(allocator, &client);
        defer bootstrap_frame.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, bootstrap_frame.payload, "\"type\":\"session.receive\"") != null);

        try writeClientTextFrameMasked(&client, "{\"id\":\"a-msg\",\"type\":\"session.send\",\"content\":\"alpha hello\"}");
        var alpha_reply = try readServerFrame(allocator, &client);
        defer alpha_reply.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, alpha_reply.payload, "\"type\":\"session.receive\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alpha_reply.payload, "alpha hello") != null);

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
        try performClientHandshake(allocator, &client, "/v1/agents/beta/stream");

        try writeClientTextFrameMasked(&client, "{\"id\":\"b-connect\",\"type\":\"connect\"}");
        var connect_ack = try readServerFrame(allocator, &client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"connect.ack\"") != null);
        var bootstrap_frame = try readServerFrame(allocator, &client);
        defer bootstrap_frame.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, bootstrap_frame.payload, "\"type\":\"session.receive\"") != null);

        try writeClientTextFrameMasked(&client, "{\"id\":\"b-msg\",\"type\":\"session.send\",\"content\":\"beta hello\"}");
        var beta_reply = try readServerFrame(allocator, &client);
        defer beta_reply.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, beta_reply.payload, "\"type\":\"session.receive\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, beta_reply.payload, "beta hello") != null);

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
        try performClientHandshake(allocator, &client, "/v1/agents/alpha/stream");

        try writeClientTextFrameMasked(&client, "{\"id\":\"alpha-connect\",\"type\":\"connect\"}");
        var connect_ack = try readServerFrame(allocator, &client);
        defer connect_ack.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"connect.ack\"") != null);
        var bootstrap_frame = try readServerFrame(allocator, &client);
        defer bootstrap_frame.deinit(allocator);
        try std.testing.expect(std.mem.indexOf(u8, bootstrap_frame.payload, "\"type\":\"session.receive\"") != null);

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
        try performClientHandshake(allocator, &client, "/v1/agents/beta/stream");

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

test "server_piai: parse route path extracts agent id" {
    const path = parseAgentIdFromStreamPath("/v1/agents/alpha/stream") orelse return error.TestExpectedAgent;
    try std.testing.expectEqualStrings("alpha", path);
    try std.testing.expect(parseAgentIdFromStreamPath("/v1/agents/alpha/stream?x=1") != null);
    try std.testing.expect(parseAgentIdFromStreamPath("/v1/agents//stream") == null);
    try std.testing.expect(parseAgentIdFromStreamPath("/v1/agents/alpha/not-stream") == null);
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
