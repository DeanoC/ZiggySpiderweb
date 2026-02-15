const std = @import("std");
const ziggy_piai = @import("ziggy-piai");
const Config = @import("config.zig");
const protocol = @import("protocol.zig");
const memory = @import("memory.zig");
const posix = std.posix;
const builtin = @import("builtin");
const linux = if (builtin.os.tag == .linux) std.os.linux else struct {
    pub const epoll_event = extern struct {
        events: u32,
        data: extern union {
            ptr: ?*anyopaque,
            fd: posix.socket_t,
            u32: u32,
            u64: u64,
        },
    };
    pub const EPOLL = struct {
        pub const IN: u32 = 0x001;
        pub const OUT: u32 = 0x004;
        pub const ERR: u32 = 0x008;
        pub const HUP: u32 = 0x010;
        pub const RDHUP: u32 = 0x2000;
        pub const ET: u32 = 1 << 31;
        pub const CTL_ADD: i32 = 1;
        pub const CTL_DEL: i32 = 2;
        pub const CLOEXEC: u32 = 0o2000000;
    };
};

const SESSION_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MAX_CONTEXT_MESSAGES = 64;
const MAX_CONTEXT_BYTES = 16 * 1024;
const MAX_INBOUND_MESSAGE_BYTES = 4 * 1024;
const REQUEST_ID_LEN = 16;

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

const SessionError = error{ MessageTooLarge };

const SessionContext = struct {
    ram: memory.RamContext,
    session_id: []u8,

    fn init(allocator: std.mem.Allocator) SessionContext {
        return .{
            .ram = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES),
            .session_id = &[_]u8{},
        };
    }

    fn deinit(self: *SessionContext, allocator: std.mem.Allocator) void {
        self.ram.deinit();
        if (self.session_id.len > 0) allocator.free(self.session_id);
        self.session_id = &[_]u8{};
    }

    fn setSessionId(self: *SessionContext, allocator: std.mem.Allocator, id: []const u8) !void {
        if (self.session_id.len > 0) allocator.free(self.session_id);
        self.session_id = try allocator.dupe(u8, id);
    }

    fn appendMessage(self: *SessionContext, allocator: std.mem.Allocator, role: ziggy_piai.types.MessageRole, content: []const u8) !memory.MemoryID {
        _ = allocator;
        return self.ram.update(role, content);
    }

    fn appendUserMessage(self: *SessionContext, allocator: std.mem.Allocator, role: ziggy_piai.types.MessageRole, content: []const u8) !memory.MemoryID {
        if (content.len > MAX_INBOUND_MESSAGE_BYTES) return error.MessageTooLarge;
        _ = allocator;
        return self.ram.update(role, content);
    }

    fn contextMessages(self: *SessionContext, allocator: std.mem.Allocator) ![]const ziggy_piai.types.Message {
        return self.ram.load(allocator);
    }

};

const Connection = struct {
    fd: posix.socket_t,
    state: ConnectionState,
    agent_id: []u8,
    read_buf: std.ArrayListUnmanaged(u8),
    write_buf: std.ArrayListUnmanaged(u8),
    session: SessionContext,

    fn init(allocator: std.mem.Allocator, fd: posix.socket_t) Connection {
        return .{
            .fd = fd,
            .state = .handshake,
            .agent_id = &[_]u8{},
            .read_buf = .{},
            .write_buf = .{},
            .session = SessionContext.init(allocator),
        };
    }

    fn deinit(self: *Connection, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        self.read_buf.deinit(allocator);
        self.write_buf.deinit(allocator);
        self.session.deinit(allocator);
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

const EventLoop = if (builtin.os.tag == .linux) struct {
    fd: posix.fd_t,

    fn init(allocator: std.mem.Allocator) !EventLoop {
        _ = allocator;
        const fd = try posix.epoll_create1(linux.EPOLL.CLOEXEC);
        return .{ .fd = fd };
    }

    fn deinit(self: *EventLoop) void {
        posix.close(self.fd);
    }

    fn add(self: *EventLoop, fd: posix.socket_t, events: u32) !void {
        var ev = linux.epoll_event{
            .events = events,
            .data = .{ .fd = fd },
        };
        try posix.epoll_ctl(self.fd, linux.EPOLL.CTL_ADD, fd, &ev);
    }

    fn remove(self: *EventLoop, fd: posix.socket_t) void {
        posix.epoll_ctl(self.fd, linux.EPOLL.CTL_DEL, fd, null) catch {};
    }

    fn wait(self: *EventLoop, events_out: []Event) usize {
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
} else struct {
    pollfds: std.ArrayListUnmanaged(posix.pollfd),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !EventLoop {
        return .{
            .pollfds = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *EventLoop) void {
        self.pollfds.deinit(self.allocator);
    }

    fn add(self: *EventLoop, fd: posix.socket_t, events: u32) !void {
        var poll_events: i16 = 0;
        if (events & linux.EPOLL.IN != 0) poll_events |= posix.POLL.IN;
        if (events & linux.EPOLL.OUT != 0) poll_events |= posix.POLL.OUT;

        try self.pollfds.append(self.allocator, .{
            .fd = fd,
            .events = poll_events,
            .revents = 0,
        });
    }

    fn remove(self: *EventLoop, fd: posix.socket_t) void {
        for (self.pollfds.items, 0..) |pfd, i| {
            if (pfd.fd == fd) {
                _ = self.pollfds.swapRemove(i);
                return;
            }
        }
    }

    fn wait(self: *EventLoop, events_out: []Event) usize {
        const n = posix.poll(self.pollfds.items, -1) catch return 0;
        if (n == 0) return 0;

        var count: usize = 0;
        for (self.pollfds.items) |pfd| {
            if (pfd.revents != 0) {
                events_out[count] = .{
                    .fd = pfd.fd,
                    .read = (pfd.revents & posix.POLL.IN) != 0,
                    .write = (pfd.revents & posix.POLL.OUT) != 0,
                    .err = (pfd.revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0,
                    .hup = (pfd.revents & posix.POLL.HUP) != 0,
                };
                count += 1;
                if (count == events_out.len) break;
            }
        }
        return count;
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
    const sock_flags = posix.SOCK.STREAM | (if (builtin.os.tag == .linux) posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC else 0);
    const sockfd = try posix.socket(addr.any.family, sock_flags, posix.IPPROTO.TCP);
    defer posix.close(sockfd);

    if (builtin.os.tag != .linux) {
        if (builtin.os.tag == .windows) {
            var mode: u32 = 1;
            if (std.os.windows.ws2_32.ioctlsocket(sockfd, std.os.windows.ws2_32.FIONBIO, &mode) != 0) {
                return error.SystemResources;
            }
        } else {
            const flags = try posix.fcntl(sockfd, posix.F.GETFL, 0);
            _ = try posix.fcntl(sockfd, posix.F.SETFL, flags | posix.O.NONBLOCK);
        }
    }

    try posix.setsockopt(sockfd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());
    try posix.listen(sockfd, 128);

    var loop = try EventLoop.init(allocator);
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
                    const accept_flags = if (builtin.os.tag == .linux) posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC else 0;
                    const conn_fd = posix.accept(sockfd, null, null, accept_flags) catch |err| {
                        if (err == error.WouldBlock) break;
                        std.log.err("Accept failed: {s}", .{@errorName(err)});
                        break;
                    };

                    if (builtin.os.tag != .linux) {
                        if (builtin.os.tag == .windows) {
                            var mode: u32 = 1;
                            if (std.os.windows.ws2_32.ioctlsocket(conn_fd, std.os.windows.ws2_32.FIONBIO, &mode) != 0) {
                                return error.SystemResources;
                            }
                        } else {
                            const flags = try posix.fcntl(conn_fd, posix.F.GETFL, 0);
                            _ = try posix.fcntl(conn_fd, posix.F.SETFL, flags | posix.O.NONBLOCK);
                        }
                    }

                    const conn = try allocator.create(Connection);
                    conn.* = Connection.init(allocator, conn_fd);
                    try connections.put(conn_fd, conn);

                    try loop.add(conn_fd, linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.ET);
                    std.log.info("New connection: fd={any}", .{conn_fd});
                }
            } else {
                const conn_fd = ev.fd;
                const conn = connections.get(conn_fd) orelse continue;

                if (ev.read) {
                    handleRead(allocator, &state, &pool, conn) catch |err| {
                        std.log.err("Read error on fd {any} session={s}: {s}", .{
                            conn_fd,
                            conn.session.session_id,
                            @errorName(err),
                        });
                        _ = connections.remove(conn_fd);
                        loop.remove(conn_fd);
                        conn.deinit(allocator);
                        allocator.destroy(conn);
                        continue;
                    };
                }

                if (ev.write) {
                    handleWrite(allocator, conn) catch |err| {
                        std.log.err("Write error on fd {any} session={s}: {s}", .{
                            conn_fd,
                            conn.session.session_id,
                            @errorName(err),
                        });
                        _ = connections.remove(conn_fd);
                        loop.remove(conn_fd);
                        conn.deinit(allocator);
                        allocator.destroy(conn);
                        continue;
                    };
                }

                if (ev.hup or ev.err) {
                    std.log.info("Closing connection fd={any} session={s}", .{ conn_fd, conn.session.session_id });
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
        try conn.session.setSessionId(allocator, session_key);
        const ack_msg = try std.fmt.allocPrint(allocator, "{{\"type\":\"session.ack\",\"sessionKey\":\"{s}\",\"agentId\":\"{s}\"}}", .{ session_key, agent_id });
        defer allocator.free(ack_msg);

        std.log.info("Session established: fd={any} sessionKey={s}", .{ conn.fd, session_key });

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

const AiTaskArgs = struct {
    allocator: std.mem.Allocator,
    state: *ServerState,
    conn: *Connection,
    request_id: []const u8,
};

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

    const request_id = blk: {
        if (parsed.value.object.get("id")) |id| {
            if (id == .string) break :blk try allocator.dupe(u8, id.string);
        }
        break :blk try generateRequestId(state);
    };
    var request_id_owned = request_id;
    defer if (request_id_owned.len != 0) allocator.free(request_id_owned);

    const content = blk: {
        if (parsed.value.object.get("content")) |c| if (c == .string) break :blk c.string;
        if (parsed.value.object.get("text")) |t| if (t == .string) break :blk t.string;
        return;
    };

    _ = conn.session.appendUserMessage(allocator, .user, content) catch |err| {
        if (err == SessionError.MessageTooLarge) {
            std.log.warn("Dropping oversized user message: session={s} request={s} bytes={d}", .{ conn.session.session_id, request_id, content.len });
            try sendErrorJson(allocator, &conn.write_buf, "Message too large for active context");
            return;
        }
        return err;
    };

    std.log.info("Accepted message: session={s} request={s} bytes={d}", .{
        conn.session.session_id,
        request_id,
        content.len,
    });

    const args = try allocator.create(AiTaskArgs);
    args.* = .{
        .allocator = allocator,
        .state = state,
        .conn = conn,
        .request_id = request_id,
    };

    pool.spawn(runAiTask, .{args}) catch |err| {
        std.log.err("Failed to spawn AI task: {s} session={s} request={s}", .{ @errorName(err), conn.session.session_id, request_id_owned });
        allocator.destroy(args);
        return;
    };
    args.request_id = request_id_owned;
    request_id_owned = "";
}

fn runAiTask(args: *AiTaskArgs) void {
    processAiStreaming(args.allocator, args.state, args.conn, args.request_id) catch |err| {
        std.log.err("AI Task failed: {s} session={s} request={s}", .{
            @errorName(err),
            args.conn.session.session_id,
            args.request_id,
        });
    };
    args.allocator.free(args.request_id);
    args.allocator.destroy(args);
}

fn processAiStreaming(allocator: std.mem.Allocator, state: *ServerState, conn: *Connection, request_id: []const u8) !void {
    var model: ?ziggy_piai.types.Model = null;
    for (state.model_registry.models.items) |m| {
        if (std.mem.eql(u8, m.provider, state.provider_config.name)) {
            model = m;
            break;
        }
    }
    if (model == null) {
        std.log.err("No model found for provider: {s} session={s} request={s}", .{
            state.provider_config.name,
            conn.session.session_id,
            request_id,
        });
        return;
    }

    const context_messages = try conn.session.contextMessages(allocator);
    defer freeContextMessages(allocator, context_messages);
    const context = ziggy_piai.types.Context{ .messages = context_messages };
    var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(allocator);
    defer events.deinit();

    const api_key: []const u8 = blk: {
        if (state.provider_config.api_key) |key| {
            break :blk try allocator.dupe(u8, key);
        }
        if (ziggy_piai.env_api_keys.getEnvApiKey(allocator, model.?.provider)) |key| {
            break :blk key;
        }
        std.log.err("No API key found for provider: {s} session={s} request={s}", .{
            model.?.provider,
            conn.session.session_id,
            request_id,
        });
        try sendErrorJson(allocator, &conn.write_buf, "No API key configured");
        return;
    };
    defer allocator.free(api_key);

    try ziggy_piai.stream.streamByModel(allocator, &state.http_client, &state.api_registry, model.?, context, .{ .api_key = api_key }, &events);
    std.log.info("AI stream started: session={s} request={s}", .{ conn.session.session_id, request_id });

    var response_text = std.ArrayListUnmanaged(u8){};
    defer response_text.deinit(allocator);

    var response_sent = false;
    for (events.items) |event| {
        switch (event) {
            .text_delta => |delta| try response_text.appendSlice(allocator, delta.delta),
            .done => |done| {
                std.log.info("Response complete: session={s} request={s} tokens={d}", .{
                    conn.session.session_id,
                    request_id,
                    done.usage.total_tokens,
                });
                const final_text = if (done.text.len > 0) done.text else response_text.items;
                if (final_text.len == 0) continue;

                _ = try conn.session.appendMessage(allocator, .assistant, final_text);
                try sendSessionReceive(allocator, &conn.write_buf, request_id, final_text);
                response_sent = true;
            },
            .err => |err_msg| {
                std.log.err("Pi AI error: {s} session={s} request={s}", .{ err_msg, conn.session.session_id, request_id });
                try sendErrorJson(allocator, &conn.write_buf, err_msg);
            },
            else => {},
        }
    }

    if (!response_sent and response_text.items.len > 0) {
        _ = try conn.session.appendMessage(allocator, .assistant, response_text.items);
        try sendSessionReceive(allocator, &conn.write_buf, request_id, response_text.items);
    }
}

fn freeContextMessages(allocator: std.mem.Allocator, context_messages: []const ziggy_piai.types.Message) void {
    for (context_messages) |msg| {
        allocator.free(msg.content);
    }
    allocator.free(context_messages);
}

fn sendSessionReceive(allocator: std.mem.Allocator, write_buf: *std.ArrayListUnmanaged(u8), request_id: []const u8, content: []const u8) !void {
    _ = request_id;
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
    return generateRandomId(state, 32);
}

fn generateRequestId(state: *ServerState) ![]u8 {
    return generateRandomId(state, REQUEST_ID_LEN);
}

fn generateRandomId(state: *ServerState, len: usize) ![]u8 {
    const key = try state.allocator.alloc(u8, len);
    for (key) |*c| c.* = SESSION_ID_ALPHABET[state.rng.random().int(u8) % SESSION_ID_ALPHABET.len];
    return key;
}
