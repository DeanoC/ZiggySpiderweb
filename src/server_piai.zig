const std = @import("std");
const ziggy_piai = @import("ziggy-piai");
const Config = @import("config.zig");
const protocol = @import("protocol.zig");
const posix = std.posix;
const linux = std.os.linux;

const ServerState = struct {
    allocator: std.mem.Allocator,
    rng: std.Random.DefaultPrng,
    model_registry: ziggy_piai.models.ModelRegistry,
    api_registry: ziggy_piai.api_registry.ApiRegistry,
    http_client: std.http.Client,
    provider_config: Config.ProviderConfig,
};

const ConnectionState = enum {
    handshake,
    websocket,
    closing,
};

const Connection = struct {
    fd: posix.socket_t,
    state: ConnectionState,
    agent_id: []u8,
    read_buf: std.ArrayListUnmanaged(u8),
    write_buf: std.ArrayListUnmanaged(u8),
    messages: std.ArrayListUnmanaged(ziggy_piai.types.Message),

    fn init(fd: posix.socket_t) Connection {
        return .{
            .fd = fd,
            .state = .handshake,
            .agent_id = &[_]u8{},
            .read_buf = .{},
            .write_buf = .{},
            .messages = .{},
        };
    }

    fn deinit(self: *Connection, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        self.read_buf.deinit(allocator);
        self.write_buf.deinit(allocator);
        for (self.messages.items) |msg| {
            allocator.free(msg.content);
        }
        self.messages.deinit(allocator);
        posix.close(self.fd);
    }
};

const Event = struct {
    fd: posix.socket_t,
    read: bool,
    write: bool,
    err: bool,
    hup: bool,
};

const EventLoop = struct {
    fd: posix.fd_t,

    fn init() !EventLoop {
        const fd = try posix.epoll_create1(linux.EPOLL.CLOEXEC);
        return .{ .fd = fd };
    }

    fn deinit(self: EventLoop) void {
        posix.close(self.fd);
    }

    fn add(self: EventLoop, fd: posix.socket_t, events: u32) !void {
        var ev = linux.epoll_event{
            .events = events,
            .data = .{ .fd = fd },
        };
        try posix.epoll_ctl(self.fd, linux.EPOLL.CTL_ADD, fd, &ev);
    }

    fn remove(self: EventLoop, fd: posix.socket_t) void {
        posix.epoll_ctl(self.fd, linux.EPOLL.CTL_DEL, fd, null) catch {};
    }

    fn wait(self: EventLoop, events_out: []Event) usize {
        var epoll_events: [64]linux.epoll_event = undefined;
        const n = posix.epoll_wait(self.fd, &epoll_events, -1);
        for (epoll_events[0..n], 0..) |ee, i| {
            events_out[i] = .{
                .fd = ee.data.fd,
                .read = (ee.events & linux.EPOLL.IN) != 0,
                .write = (ee.events & linux.EPOLL.OUT) != 0,
                .err = (ee.events & linux.EPOLL.ERR) != 0,
                .hup = (ee.events & (linux.EPOLL.HUP | linux.EPOLL.RDHUP)) != 0,
            };
        }
        return n;
    }
};

pub fn run(allocator: std.mem.Allocator, bind_addr: []const u8, port: u16, provider_config: Config.ProviderConfig) !void {
    // Initialize Pi AI components
    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator, .n_jobs = std.Thread.getCpuCount() catch 4 });
    defer pool.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp())),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = provider_config,
    };

    const addr = try std.net.Address.parseIp(bind_addr, port);
    const sockfd = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    defer posix.close(sockfd);

    try posix.setsockopt(sockfd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());
    try posix.listen(sockfd, 128);

    var loop = try EventLoop.init();
    defer loop.deinit();

    try loop.add(sockfd, linux.EPOLL.IN);

    var connections = std.AutoHashMap(posix.socket_t, *Connection).init(allocator);
    defer {
        var it = connections.valueIterator();
        while (it.next()) |conn| {
            conn.*.deinit(allocator);
            allocator.destroy(conn.*);
        }
        connections.deinit();
    }

    std.log.info("ZiggySpiderweb v0.4.0 (Abstract EventLoop) listening on {s}:{d}", .{ bind_addr, port });

    var events: [64]Event = undefined;
    while (true) {
        const n = loop.wait(&events);
        for (events[0..n]) |ev| {
            if (ev.fd == sockfd) {
                while (true) {
                    const conn_fd = posix.accept(sockfd, null, null, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC) catch |err| {
                        if (err == error.WouldBlock) break;
                        std.log.err("Accept failed: {s}", .{@errorName(err)});
                        break;
                    };

                    const conn = try allocator.create(Connection);
                    conn.* = Connection.init(conn_fd);
                    try connections.put(conn_fd, conn);

                    try loop.add(conn_fd, linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.ET);
                    std.log.info("New connection: fd={d}", .{conn_fd});
                }
            } else {
                const conn_fd = ev.fd;
                const conn = connections.get(conn_fd) orelse continue;

                if (ev.read) {
                    handleRead(allocator, &state, &pool, conn) catch |err| {
                        std.log.err("Read error on fd {d}: {s}", .{ conn_fd, @errorName(err) });
                        _ = connections.remove(conn_fd);
                        loop.remove(conn_fd);
                        conn.deinit(allocator);
                        allocator.destroy(conn);
                        continue;
                    };
                }

                if (ev.write) {
                    handleWrite(allocator, conn) catch |err| {
                        std.log.err("Write error on fd {d}: {s}", .{ conn_fd, @errorName(err) });
                        _ = connections.remove(conn_fd);
                        loop.remove(conn_fd);
                        conn.deinit(allocator);
                        allocator.destroy(conn);
                        continue;
                    };
                }

                if (ev.hup or ev.err) {
                    std.log.info("Closing connection fd={d}", .{conn_fd});
                    _ = connections.remove(conn_fd);
                    loop.remove(conn_fd);
                    conn.deinit(allocator);
                    allocator.destroy(conn);
                }
            }
        }
    }
}

fn handleRead(allocator: std.mem.Allocator, state: *ServerState, pool: *std.Thread.Pool, conn: *Connection) !void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(conn.fd, &buf) catch |err| {
            if (err == error.WouldBlock) return;
            return err;
        };
        if (n == 0) return error.ConnectionClosed;
        try conn.read_buf.appendSlice(allocator, buf[0..n]);

        switch (conn.state) {
            .handshake => try processHandshake(allocator, state, conn),
            .websocket => try processWebSocket(allocator, state, pool, conn),
            else => {},
        }
    }
}

fn handleWrite(allocator: std.mem.Allocator, conn: *Connection) !void {
    if (conn.write_buf.items.len == 0) return;
    const n = posix.write(conn.fd, conn.write_buf.items) catch |err| {
        if (err == error.WouldBlock) return;
        return err;
    };
    conn.write_buf.replaceRange(allocator, 0, @min(n, conn.write_buf.items.len), &.{}) catch {};
}

fn processHandshake(allocator: std.mem.Allocator, state: *ServerState, conn: *Connection) !void {
    const request = conn.read_buf.items;
    if (std.mem.indexOf(u8, request, "\r\n\r\n")) |_| {
        if (!std.mem.containsAtLeast(u8, request, 1, "Upgrade: websocket") and
            !std.mem.containsAtLeast(u8, request, 1, "upgrade: websocket"))
        {
            try conn.write_buf.appendSlice(allocator, "HTTP/1.1 400 Bad Request\r\n\r\n");
            conn.state = .closing;
            return;
        }

        const agent_id = parseAgentId(request) orelse "default";
        conn.agent_id = try allocator.dupe(u8, agent_id);

        const accept_key = try generateWsAcceptKey(state, request);
        defer allocator.free(accept_key);

        const response = try std.fmt.allocPrint(allocator, "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n" ++
            "\r\n", .{accept_key});
        defer allocator.free(response);

        try conn.write_buf.appendSlice(allocator, response);
        conn.read_buf.clearRetainingCapacity();
        conn.state = .websocket;

        const session_key = try generateSessionKey(state);
        defer allocator.free(session_key);
        const ack_msg = try std.fmt.allocPrint(allocator, "{{\"type\":\"session.ack\",\"sessionKey\":\"{s}\",\"agentId\":\"{s}\"}}", .{ session_key, agent_id });
        defer allocator.free(ack_msg);

        try appendWsFrame(allocator, &conn.write_buf, ack_msg, .text);
    }
}

fn processWebSocket(allocator: std.mem.Allocator, state: *ServerState, pool: *std.Thread.Pool, conn: *Connection) !void {
    while (conn.read_buf.items.len >= 2) {
        std.log.debug("processWebSocket: waiting for header (2 bytes)", .{});
        const header = conn.read_buf.items[0..2];
        const fin = (header[0] & 0x80) != 0;
        const opcode = header[0] & 0x0F;
        const masked = (header[1] & 0x80) != 0;
        var payload_len: usize = header[1] & 0x7F;
        var header_len: usize = 2;

        if (payload_len == 126) {
            if (conn.read_buf.items.len < 4) return;
            std.log.debug("processWebSocket: payload_len=126, reading 2-byte ext", .{});
            payload_len = std.mem.readInt(u16, conn.read_buf.items[2..4], .big);
            header_len = 4;
        } else if (payload_len == 127) {
            if (conn.read_buf.items.len < 10) return;
            std.log.debug("processWebSocket: payload_len=127, reading 8-byte ext", .{});
            payload_len = @intCast(std.mem.readInt(u64, conn.read_buf.items[2..10], .big));
            header_len = 10;
        }

        if (masked) {
            std.log.debug("processWebSocket: reading mask_key (4 bytes)", .{});
            header_len += 4;
        }
        if (conn.read_buf.items.len < header_len + payload_len) return;

        std.log.debug("processWebSocket: reading payload ({d} bytes)", .{payload_len});
        const frame_data = conn.read_buf.items[0 .. header_len + payload_len];
        const payload = try allocator.alloc(u8, payload_len);
        defer allocator.free(payload);
        @memcpy(payload, frame_data[header_len..]);

        if (masked) {
            const mask_key = frame_data[header_len - 4 .. header_len];
            for (payload, 0..) |*b, i| b.* ^= mask_key[i % 4];
        }

        switch (opcode) {
            0x8 => { conn.state = .closing; return; },
            0x9 => try appendWsFrame(allocator, &conn.write_buf, payload, .binary),
            0x1 => try handleUserMessage(allocator, state, pool, conn, payload),
            else => {},
        }
        _ = fin;
        conn.read_buf.replaceRange(allocator, 0, header_len + payload_len, &.{}) catch {};
    }
}

const AiTaskArgs = struct { allocator: std.mem.Allocator, state: *ServerState, conn: *Connection };

fn handleUserMessage(allocator: std.mem.Allocator, state: *ServerState, pool: *std.Thread.Pool, conn: *Connection, msg: []const u8) !void {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, msg, .{}) catch return;
    defer parsed.deinit();

    if (parsed.value != .object) return;
    const msg_type = parsed.value.object.get("type") orelse return;
    if (msg_type != .string) return;

    if (std.mem.eql(u8, msg_type.string, "ping")) {
        const pong = try protocol.buildPong(allocator);
        defer allocator.free(pong);
        try appendWsFrame(allocator, &conn.write_buf, pong, .text);
        return;
    }

    const is_chat_send = std.mem.eql(u8, msg_type.string, "chat.send") or std.mem.eql(u8, msg_type.string, "session.send");
    if (!is_chat_send) return;

    const content = blk: {
        if (parsed.value.object.get("content")) |c| if (c == .string) break :blk c.string;
        if (parsed.value.object.get("text")) |t| if (t == .string) break :blk t.string;
        return;
    };

    try conn.messages.append(allocator, .{
        .role = .user,
        .content = try allocator.dupe(u8, content),
    });

    const args = try allocator.create(AiTaskArgs);
    args.* = .{ .allocator = allocator, .state = state, .conn = conn };

    pool.spawn(runAiTask, .{args}) catch |err| {
        std.log.err("Failed to spawn AI task: {s}", .{@errorName(err)});
        allocator.destroy(args);
    };
}

fn runAiTask(args: *AiTaskArgs) void {
    processAiStreaming(args.allocator, args.state, args.conn) catch |err| {
        std.log.err("AI Task failed: {s}", .{@errorName(err)});
    };
    args.allocator.destroy(args);
}

fn processAiStreaming(allocator: std.mem.Allocator, state: *ServerState, conn: *Connection) !void {
    var model: ?ziggy_piai.types.Model = null;
    for (state.model_registry.models.items) |m| {
        if (std.mem.eql(u8, m.provider, state.provider_config.name)) {
            model = m;
            break;
        }
    }
    if (model == null) return;

    const context = ziggy_piai.types.Context{ .messages = conn.messages.items };
    var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(allocator);
    defer events.deinit();

    const api_key: []const u8 = blk: {
        if (state.provider_config.api_key) |key| {
            break :blk try allocator.dupe(u8, key);
        }
        if (ziggy_piai.env_api_keys.getEnvApiKey(allocator, model.?.provider)) |key| {
            break :blk key;
        }
        std.log.err("No API key found for provider: {s}", .{model.?.provider});
        try sendErrorJson(allocator, &conn.write_buf, "No API key configured");
        return;
    };
    defer allocator.free(api_key);

    try ziggy_piai.stream.streamByModel(allocator, &state.http_client, &state.api_registry, model.?, context, .{ .api_key = api_key }, &events);

    var response_text = std.ArrayListUnmanaged(u8){};
    defer response_text.deinit(allocator);

    var response_sent = false;
    for (events.items) |event| {
        switch (event) {
            .text_delta => |delta| try response_text.appendSlice(allocator, delta.delta),
            .done => |done| {
                std.log.info("Response complete: {d} tokens", .{done.usage.total_tokens});
                const final_text = if (done.text.len > 0) done.text else response_text.items;
                if (final_text.len == 0) continue;

                try conn.messages.append(allocator, .{ .role = .assistant, .content = try allocator.dupe(u8, final_text) });
                try sendSessionReceive(allocator, &conn.write_buf, final_text);
                response_sent = true;
            },
            .err => |err_msg| {
                std.log.err("Pi AI error: {s}", .{err_msg});
                try sendErrorJson(allocator, &conn.write_buf, err_msg);
            },
            else => {},
        }
    }

    if (!response_sent and response_text.items.len > 0) {
        try conn.messages.append(allocator, .{
            .role = .assistant,
            .content = try allocator.dupe(u8, response_text.items),
        });
        try sendSessionReceive(allocator, &conn.write_buf, response_text.items);
    }
}

fn sendSessionReceive(allocator: std.mem.Allocator, write_buf: *std.ArrayListUnmanaged(u8), content: []const u8) !void {
    const escaped = try protocol.jsonEscape(allocator, content);
    defer allocator.free(escaped);

    const response_json = try std.fmt.allocPrint(allocator, "{{\"type\":\"session.receive\",\"content\":\"{s}\"}}", .{escaped});
    defer allocator.free(response_json);

    try appendWsFrame(allocator, write_buf, response_json, .text);
}

fn sendErrorJson(allocator: std.mem.Allocator, write_buf: *std.ArrayListUnmanaged(u8), message: []const u8) !void {
    const escaped = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped);

    const response_json = try std.fmt.allocPrint(allocator, "{{\"type\":\"error\",\"message\":\"{s}\"}}", .{escaped});
    defer allocator.free(response_json);

    try appendWsFrame(allocator, write_buf, response_json, .text);
}

fn appendWsFrame(allocator: std.mem.Allocator, write_buf: *std.ArrayListUnmanaged(u8), payload: []const u8, comptime frame_type: enum { text, binary }) !void {
    const opcode: u8 = switch (frame_type) {
        .text => 0x81,
        .binary => 0x82,
    };
    var header: [10]u8 = undefined;
    var header_len: usize = 2;
    header[0] = opcode;
    if (payload.len < 126) {
        header[1] = @intCast(payload.len);
    } else if (payload.len < 65536) {
        header[1] = 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len = 4;
    } else {
        header[1] = 127;
        std.mem.writeInt(u64, header[2..10], payload.len, .big);
        header_len = 10;
    }
    try write_buf.appendSlice(allocator, header[0..header_len]);
    try write_buf.appendSlice(allocator, payload);
}

fn parseAgentId(request: []const u8) ?[]const u8 {
    const prefix = "/v1/agents/";
    const start = std.mem.indexOf(u8, request, prefix) orelse return null;
    const after_agent = start + prefix.len;
    const end = std.mem.indexOfPos(u8, request, after_agent, "/stream") orelse return null;
    return request[after_agent..end];
}

fn generateWsAcceptKey(state: *ServerState, request: []const u8) ![]u8 {
    const key_headers = [_][]const u8{ "Sec-WebSocket-Key: ", "sec-websocket-key: " };
    var key_start: ?usize = null;
    var key_header_len: usize = 0;
    for (key_headers) |header| {
        if (std.mem.indexOf(u8, request, header)) |idx| {
            key_start = idx;
            key_header_len = header.len;
            break;
        }
    }
    const start = key_start orelse return error.NoKey;
    const after_key = start + key_header_len;
    const key_end = std.mem.indexOfPos(u8, request, after_key, "\r\n") orelse return error.NoKey;
    const client_key = std.mem.trim(u8, request[after_key..key_end], " \t");
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const combined = try std.fmt.allocPrint(state.allocator, "{s}{s}", .{ client_key, magic });
    defer state.allocator.free(combined);
    var hash: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(combined, &hash, .{});
    const encoded_len = std.base64.standard.Encoder.calcSize(hash.len);
    const encoded = try state.allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, &hash);
    return encoded;
}

fn generateSessionKey(state: *ServerState) ![]u8 {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var key: [32]u8 = undefined;
    for (&key) |*c| c.* = chars[state.rng.random().int(u8) % chars.len];
    return state.allocator.dupe(u8, &key);
}
