const std = @import("std");
const ziggy_piai = @import("ziggy-piai");
const Config = @import("config.zig");
const protocol = @import("protocol.zig");
const memory = @import("memory.zig");
const ltm_index = @import("ltm_index.zig");
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
const SESSION_STATE_PATH = ".spiderweb-session-state.json";
const SESSION_STATE_VERSION = 1;
const LONG_TERM_ARCHIVE_DIR = ".spiderweb-ltm";
const LTM_INDEX_FILENAME = "archive-index.ndjson";
const LONG_TERM_ARCHIVE_VERSION = 1;

const PersistedSession = struct {
    session_id: []u8,
    ram: memory.RamContext,
};

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

    fn resetRam(self: *SessionContext, allocator: std.mem.Allocator) void {
        self.ram.deinit();
        self.ram = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES);
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

    var persisted_sessions = try loadPersistedSessions(allocator);

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
    defer deinitPersistedSessions(allocator, &persisted_sessions);
    defer savePersistedSessions(allocator, &persisted_sessions, &connections) catch |err| {
        std.log.err("Failed to save session state: {s}", .{@errorName(err)});
    };

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
                    handleRead(allocator, &state, &pool, &persisted_sessions, conn) catch |err| {
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

fn handleRead(
    allocator: std.mem.Allocator,
    state: *ServerState,
    pool: *std.Thread.Pool,
    persisted_sessions: *std.ArrayListUnmanaged(PersistedSession),
    conn: *Connection,
) !void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(conn.fd, &buf) catch |err| {
            if (err == error.WouldBlock) return;
            return err;
        };
        if (n == 0) return error.ConnectionClosed;
        try conn.read_buf.appendSlice(allocator, buf[0..n]);

        switch (conn.state) {
            .handshake => try processHandshake(allocator, state, persisted_sessions, conn),
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

fn processHandshake(
    allocator: std.mem.Allocator,
    state: *ServerState,
    persisted_sessions: *std.ArrayListUnmanaged(PersistedSession),
    conn: *Connection,
) !void {
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

        const requested_session_id = parseSessionIdFromRequest(request);
        if (requested_session_id) |requested| {
            restoreSessionFromPersistedWithId(allocator, persisted_sessions, &conn.session, requested) catch |err| {
                if (err != error.SessionNotFound) {
                    return err;
                }
                const restored_from_archive = restoreSessionFromLatestArchive(allocator, &conn.session, requested) catch |archive_err| {
                    std.log.err("Session archive restore failed: {s} session={s}", .{ @errorName(archive_err), requested });
                    false
                };
                if (restored_from_archive) {
                    std.log.info("Session restored from archive: session={s}", .{requested});
                }
            };
        }

        if (conn.session.session_id.len == 0) {
            const session_key = try generateSessionKey(state);
            defer allocator.free(session_key);
            try conn.session.setSessionId(allocator, session_key);
        }

        const ack_msg = try std.fmt.allocPrint(
            allocator,
            "{{\"type\":\"session.ack\",\"sessionKey\":\"{s}\",\"agentId\":\"{s}\"}}",
            .{ conn.session.session_id, agent_id },
        );
        defer allocator.free(ack_msg);

        std.log.info("Session established: fd={any} sessionKey={s}", .{ conn.fd, conn.session.session_id });

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

    const request_id = blk: {
        if (parsed.value.object.get("id")) |id| {
            if (id == .string) break :blk try allocator.dupe(u8, id.string);
        }
        break :blk try generateRequestId(state);
    };
    var request_id_owned = request_id;
    defer if (request_id_owned.len != 0) allocator.free(request_id_owned);

    const is_session_reset = std.mem.eql(u8, msg_type.string, "session.reset") or std.mem.eql(u8, msg_type.string, "session.new");
    if (is_session_reset) {
        const response_type = if (std.mem.eql(u8, msg_type.string, "session.new")) "session.new" else "session.reset";
        const should_archive = if (parsed.value.object.get("archive")) |archive| switch (archive) {
            .bool => archive.bool,
            else => true,
        } else true;

        const reason = if (parsed.value.object.get("reason")) |reason_value| reason_blk: {
            if (reason_value == .string) break :reason_blk reason_value.string;
            break :reason_blk "manual-reset";
        } else "manual-reset";

        const archived = handleSessionReset(allocator, conn, should_archive, reason) catch |err| blk: {
            std.log.err("Session reset failed: {s} session={s}", .{ @errorName(err), conn.session.session_id });
            try sendErrorJson(allocator, &conn.write_buf, "session.reset failed");
            break :blk false;
        };

        const response = try std.fmt.allocPrint(
            allocator,
            "{{\"type\":\"{s}\",\"request\":\"{s}\",\"sessionKey\":\"{s}\",\"archived\":{s}}}",
            .{ response_type, request_id, conn.session.session_id, if (archived) "true" else "false" },
        );
        defer allocator.free(response);
        try appendWsFrame(allocator, &conn.write_buf, response, .text);
        std.log.info("Session reset: session={s} request={s} archived={s} reason={s}", .{ conn.session.session_id, request_id, if (archived) "true" else "false", reason });
        return;
    }

    const is_memory_recall = std.mem.eql(u8, msg_type.string, "memory.recall");
    if (is_memory_recall) {
        const limit = if (parsed.value.object.get("limit")) |limit_value| parsePositiveInteger(limit_value) orelse 25 else 25;
        const include_archived = if (parsed.value.object.get("include_archived")) |include| switch (include) {
            .bool => include.bool,
            else => true,
        } else true;
        const include_full = if (parsed.value.object.get("include_full")) |full| switch (full) {
            .bool => full.bool,
            else => false,
        } else false;

        handleMemoryRecall(allocator, conn, request_id, limit, include_archived, include_full) catch |err| {
            std.log.err("memory.recall failed: {s} session={s} request={s}", .{
                @errorName(err),
                conn.session.session_id,
                request_id,
            });
            try sendErrorJson(allocator, &conn.write_buf, "memory.recall failed");
        };
        return;
    }

    const is_memory_query = std.mem.eql(u8, msg_type.string, "memory.query");
    if (is_memory_query) {
        const limit = if (parsed.value.object.get("limit")) |limit_value| parsePositiveInteger(limit_value) orelse 25 else 25;
        const include_archived = if (parsed.value.object.get("include_archived")) |include| switch (include) {
            .bool => include.bool,
            else => true,
        } else true;
        const query_kind = if (parsed.value.object.get("kind")) |value| switch (value) {
            .string => if (std.mem.eql(u8, value.string, "summary"))
                MemoryQueryKind.summary
            else if (std.mem.eql(u8, value.string, "entry"))
                MemoryQueryKind.entry
            else
                MemoryQueryKind.all,
            else => MemoryQueryKind.all,
        } else MemoryQueryKind.all;

        const topic = if (parsed.value.object.get("topic")) |topic_value| if (topic_value == .string) topic_value.string else null else null;

        var query_ids = std.ArrayListUnmanaged(memory.MemoryID){};
        defer query_ids.deinit(allocator);

        if (parsed.value.object.get("memoryId")) |memory_id_value| {
            if (parsePositiveInteger(memory_id_value)) |id| {
                try query_ids.append(allocator, id);
            }
        }

        if (parsed.value.object.get("memoryIds")) |memory_ids| {
            if (memory_ids == .array) {
                for (memory_ids.array.items) |id_value| {
                    if (parsePositiveInteger(id_value)) |id| {
                        try query_ids.append(allocator, id);
                    }
                }
            }
        }

        handleMemoryQuery(
            allocator,
            conn,
            request_id,
            limit,
            include_archived,
            topic,
            query_ids.items,
            query_kind,
        ) catch |err| {
            std.log.err("memory.query failed: {s} session={s} request={s}", .{
                @errorName(err),
                conn.session.session_id,
                request_id,
            });
            try sendErrorJson(allocator, &conn.write_buf, "memory.query failed");
        };
        return;
    }

    const is_chat_send = std.mem.eql(u8, msg_type.string, "chat.send") or std.mem.eql(u8, msg_type.string, "session.send");
    if (!is_chat_send) return;

    const content = blk: {
        if (parsed.value.object.get("content")) |c| if (c == .string) break :blk c.string;
        if (parsed.value.object.get("text")) |t| if (t == .string) break :blk t.string;
        return;
    };

    if (std.mem.eql(u8, content, "/new")) {
        const archived = handleSessionReset(allocator, conn, true, "slash-new") catch |err| blk: {
            std.log.err("Session reset via /new failed: {s} session={s}", .{ @errorName(err), conn.session.session_id });
            try sendErrorJson(allocator, &conn.write_buf, "session.reset failed");
            break :blk false;
        };

        const response = try std.fmt.allocPrint(
            allocator,
            "{{\"type\":\"session.new\",\"request\":\"{s}\",\"sessionKey\":\"{s}\",\"archived\":{s}}}",
            .{ request_id, conn.session.session_id, if (archived) "true" else "false" },
        );
        defer allocator.free(response);
        try appendWsFrame(allocator, &conn.write_buf, response, .text);
        std.log.info("Session reset via /new: session={s} request={s} archived={s}", .{
            conn.session.session_id,
            request_id,
            if (archived) "true" else "false",
        });
        return;
    }

    const user_msg_id = conn.session.appendUserMessage(allocator, .user, content) catch |err| {
        if (err == SessionError.MessageTooLarge) {
            std.log.warn("Dropping oversized user message: session={s} request={s} bytes={d}", .{ conn.session.session_id, request_id, content.len });
            try sendErrorJson(allocator, &conn.write_buf, "Message too large for active context");
            return;
        }
        return err;
    };

    std.log.info("Accepted message: session={s} request={s} memoryId={d} bytes={d}", .{
        conn.session.session_id,
        request_id,
        user_msg_id,
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

                const assistant_msg_id = try conn.session.appendMessage(allocator, .assistant, final_text);
                try sendSessionReceive(allocator, &conn.write_buf, request_id, final_text, assistant_msg_id);
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
        const assistant_msg_id = try conn.session.appendMessage(allocator, .assistant, response_text.items);
        try sendSessionReceive(allocator, &conn.write_buf, request_id, response_text.items, assistant_msg_id);
    }
}

fn freeContextMessages(allocator: std.mem.Allocator, context_messages: []const ziggy_piai.types.Message) void {
    for (context_messages) |msg| {
        allocator.free(msg.content);
    }
    allocator.free(context_messages);
}

fn sendSessionReceive(
    allocator: std.mem.Allocator,
    write_buf: *std.ArrayListUnmanaged(u8),
    request_id: []const u8,
    content: []const u8,
    memory_id: memory.MemoryID,
) !void {
    _ = request_id;
    const escaped = try protocol.jsonEscape(allocator, content);
    defer allocator.free(escaped);

    const memory_id_str = try std.fmt.allocPrint(allocator, "{d}", .{memory_id});
    defer allocator.free(memory_id_str);

    const response_json = try std.mem.concat(
        allocator,
        u8,
        &.{ "{\"type\":\"session.receive\",\"content\":\"", escaped, "\",\"memoryId\":", memory_id_str, "}" },
    );
    defer allocator.free(response_json);

    try appendWsFrame(allocator, write_buf, response_json, .text);
}

const MemoryQueryKind = enum { all, summary, entry };

fn handleMemoryQuery(
    allocator: std.mem.Allocator,
    conn: *Connection,
    request_id: []const u8,
    requested_limit: u64,
    include_archived: bool,
    topic: ?[]const u8,
    query_ids: []const memory.MemoryID,
    kind_filter: MemoryQueryKind,
) !void {
    const limit = if (requested_limit == 0 or requested_limit > 128) 128 else requested_limit;
    var remaining = @as(usize, limit);
    var emitted = std.ArrayListUnmanaged(u8){};
    defer emitted.deinit(allocator);

    const escaped_topic = if (topic) |value| try protocol.jsonEscape(allocator, value) else null;
    defer if (escaped_topic) |value| allocator.free(value);

    try emitted.appendSlice(allocator, "{\"type\":\"memory.query\",\"request\":\"");
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    try emitted.appendSlice(allocator, escaped_request_id);
    try emitted.appendSlice(allocator, "\",\"sessionKey\":\"");
    try emitted.appendSlice(allocator, conn.session.session_id);
    if (escaped_topic) |topic_value| {
        try emitted.appendSlice(allocator, "\",\"topic\":\"");
        try emitted.appendSlice(allocator, topic_value);
    } else {
        try emitted.appendSlice(allocator, "\",\"topic\":null");
    }
    try emitted.appendSlice(allocator, "\",\"items\":[");

    var first_item = true;

    conn.session.ram.mutex.lock();
    defer conn.session.ram.mutex.unlock();

    if (kind_filter != .entry) {
        var idx: usize = conn.session.ram.summaries.items.len;
        while (idx > 0 and remaining > 0) {
            idx -= 1;
            const summary = conn.session.ram.summaries.items[idx];
            if (!queryMatchesId(summary.id, query_ids)) continue;
            if (!queryMatchesTopic(summary.text, topic)) continue;
            try appendRecallSummaryItem(
                allocator,
                &emitted,
                &first_item,
                "summary",
                "ram",
                summary.id,
                summary.source_id,
                summary.text,
                summary.created_at_ms,
            );
            if (remaining > 0) remaining -= 1;
        }
    }

    if (kind_filter != .summary and remaining > 0) {
        var idx: usize = conn.session.ram.entries.items.len;
        while (idx > 0 and remaining > 0) {
            idx -= 1;
            const entry = conn.session.ram.entries.items[idx];
            if (!queryMatchesId(entry.id, query_ids)) continue;
            if (!queryMatchesTopic(entry.message.content, topic)) continue;

            try appendRecallEntryItem(
                allocator,
                &emitted,
                &first_item,
                "entry",
                "ram",
                if (entry.state == .active) "active" else "tombstone",
                entry.message.role,
                entry.id,
                entry.related_to,
                entry.message.content,
            );
            if (remaining > 0) remaining -= 1;
        }
    }

    if (include_archived) {
        const archive = findLatestArchiveForSession(allocator, conn.session.session_id) catch null;
        if (archive) |latest| {
            try appendLatestArchiveToQueryResponse(
                allocator,
                &emitted,
                latest.archive_path,
                &first_item,
                &remaining,
                topic,
                query_ids,
                kind_filter,
            );
            allocator.free(latest.archive_path);
            allocator.free(latest.reason);
        }
    }

    try emitted.appendSlice(allocator, "]}");
    try appendWsFrame(allocator, &conn.write_buf, emitted.items, .text);
}

fn queryMatchesId(item_id: memory.MemoryID, query_ids: []const memory.MemoryID) bool {
    if (query_ids.len == 0) return true;

    for (query_ids) |id| {
        if (id == item_id) return true;
    }
    return false;
}

fn queryMatchesTopic(value: []const u8, topic: ?[]const u8) bool {
    if (topic == null) return true;
    return std.mem.indexOf(u8, value, topic.?) != null;
}

fn appendLatestArchiveToQueryResponse(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    archive_path: []const u8,
    first_item: *bool,
    remaining: *usize,
    topic: ?[]const u8,
    query_ids: []const memory.MemoryID,
    kind_filter: MemoryQueryKind,
) !void {
    const file = std.fs.cwd().openFile(archive_path, .{ .mode = .read_only }) catch return;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(data);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return;

    if (kind_filter != .entry) {
        if (parsed.value.object.get("summaries")) |summaries| {
            if (summaries == .array) {
                var idx = summaries.array.items.len;
                while (idx > 0 and remaining.* > 0) {
                    idx -= 1;
                    const summary_value = summaries.array.items[idx];
                    if (summary_value != .object) continue;

                    const summary_obj = summary_value.object;
                    const id = parsePositiveInteger(summary_obj.get("id") orelse continue) orelse continue;
                    const source_id = parsePositiveInteger(summary_obj.get("source_id") orelse continue) orelse continue;
                    const text = summary_obj.get("text") orelse continue;
                    if (text != .string) continue;
                    const created_at_ms = if (summary_obj.get("created_at_ms")) |ts| parseCreatedAtMs(ts) else 0;

                    if (!queryMatchesId(id, query_ids)) continue;
                    if (!queryMatchesTopic(text.string, topic)) continue;

                    try appendRecallSummaryItem(
                        allocator,
                        out,
                        first_item,
                        "summary",
                        "ltm",
                        id,
                        source_id,
                        text.string,
                        created_at_ms,
                    );
                    if (remaining.* > 0) remaining.* -= 1;
                }
            }
        }
    }

    if (kind_filter != .summary and remaining.* > 0) {
        if (parsed.value.object.get("entries")) |entries| {
            if (entries == .array) {
                var idx = entries.array.items.len;
                while (idx > 0 and remaining.* > 0) {
                    idx -= 1;
                    const entry_value = entries.array.items[idx];
                    if (entry_value != .object) continue;

                    const entry_obj = entry_value.object;
                    const entry_id = parsePositiveInteger(entry_obj.get("id") orelse continue) orelse continue;
                    const role = if (entry_obj.get("role")) |value| blk: {
                        if (value != .string) break :blk null;
                        break :blk parseRole(value.string);
                    } else null;
                    if (role == null) continue;

                    const state = if (entry_obj.get("state")) |state_value|
                        if (state_value == .string and std.mem.eql(u8, state_value.string, "active")) "active" else "tombstone"
                    else
                        "unknown";
                    const content = if (entry_obj.get("content")) |value| if (value == .string) value.string else continue else continue;

                    if (!queryMatchesId(entry_id, query_ids)) continue;
                    if (!queryMatchesTopic(content, topic)) continue;

                    try appendRecallEntryItem(
                        allocator,
                        out,
                        first_item,
                        "entry",
                        "ltm",
                        state,
                        role.?,
                        entry_id,
                        if (entry_obj.get("related_to")) |value| blk: {
                            if (value == .null) break :blk null;
                            break :blk parsePositiveInteger(value);
                        } else null,
                        content,
                    );
                    if (remaining.* > 0) remaining.* -= 1;
                }
            }
        }
    }
}

fn handleMemoryRecall(
    allocator: std.mem.Allocator,
    conn: *Connection,
    request_id: []const u8,
    requested_limit: u64,
    include_archived: bool,
    include_full_from_archive: bool,
) !void {
    const limit = if (requested_limit == 0 or requested_limit > 128) 128 else requested_limit;
    var remaining = @as(usize, limit);
    var emitted = std.ArrayListUnmanaged(u8){};
    defer emitted.deinit(allocator);

    try emitted.appendSlice(allocator, "{\"type\":\"memory.recall\",\"request\":\"");
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    try emitted.appendSlice(allocator, escaped_request_id);
    try emitted.appendSlice(allocator, "\",\"sessionKey\":\"");
    try emitted.appendSlice(allocator, conn.session.session_id);
    try emitted.appendSlice(allocator, "\",\"items\":[");

    var first_item = true;

    conn.session.ram.mutex.lock();
    defer conn.session.ram.mutex.unlock();

    if (conn.session.ram.summaries.items.len > 0) {
        var idx: usize = conn.session.ram.summaries.items.len;
        while (idx > 0 and remaining > 0) {
            idx -= 1;
            const summary = conn.session.ram.summaries.items[idx];
            try appendRecallSummaryItem(
                allocator,
                &emitted,
                &first_item,
                "summary",
                "ram",
                summary.id,
                summary.source_id,
                summary.text,
                summary.created_at_ms,
            );
            remaining -= 1;
        }
    }
    {
        var idx: usize = conn.session.ram.entries.items.len;
        while (idx > 0 and remaining > 0) {
            idx -= 1;
            const entry = conn.session.ram.entries.items[idx];
            if (entry.state != .active) continue;
            try appendRecallEntryItem(
                allocator,
                &emitted,
                &first_item,
                "entry",
                "ram",
                "active",
                entry.message.role,
                entry.id,
                entry.related_to,
                entry.message.content,
            );
            remaining -= 1;
        }
    }

    if (include_archived) {
        const archive = findLatestArchiveForSession(allocator, conn.session.session_id) catch null;
        if (archive) |latest| {
            try appendLatestArchiveToResponse(
                allocator,
                &emitted,
                latest.archive_path,
                &first_item,
                &remaining,
                include_full_from_archive,
            );
            allocator.free(latest.archive_path);
            allocator.free(latest.reason);
        }
    }

    try emitted.appendSlice(allocator, "]}");
    try appendWsFrame(allocator, &conn.write_buf, emitted.items, .text);
}

const LatestArchiveRef = struct {
    timestamp_ms: i64,
    reason: []u8,
    archive_path: []u8,
};

fn findLatestArchiveForSession(
    allocator: std.mem.Allocator,
    session_id: []const u8,
) !?LatestArchiveRef {
    var index_path_buf: [256]u8 = undefined;
    const index_path = try std.fmt.bufPrint(&index_path_buf, "{s}/{s}", .{ LONG_TERM_ARCHIVE_DIR, LTM_INDEX_FILENAME });

    const file = std.fs.cwd().openFile(index_path, .{ .mode = .read_only }) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(data);
    var best_ts: ?i64 = null;
    var best_reason: ?[]u8 = null;
    var best_path: ?[]u8 = null;

    var lines = std.mem.splitSequence(u8, data, "\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch continue;
        defer parsed.deinit();
        if (parsed.value != .object) continue;

        const value_session = parsed.value.object.get("session_id") orelse continue;
        if (value_session != .string) continue;
        if (!std.mem.eql(u8, value_session.string, session_id)) continue;

        const timestamp = parseCreatedAtMs(parsed.value.object.get("timestamp_ms") orelse continue) orelse continue;
        const reason = parsed.value.object.get("reason") orelse continue;
        if (reason != .string) continue;
        const archive_path_value = parsed.value.object.get("archive_path") orelse continue;
        if (archive_path_value != .string) continue;

        if (best_ts == null or timestamp > best_ts.?) {
            if (best_reason) |old| allocator.free(old);
            if (best_path) |old| allocator.free(old);

            best_reason = try allocator.dupe(u8, reason.string);
            best_path = try allocator.dupe(u8, archive_path_value.string);
            best_ts = timestamp;
        }
    }

    if (best_ts == null or best_reason == null or best_path == null) {
        if (best_reason) |best| allocator.free(best);
        if (best_path) |best| allocator.free(best);
        return null;
    }

    return LatestArchiveRef{
        .timestamp_ms = best_ts.?,
        .reason = best_reason.?,
        .archive_path = best_path.?,
    };
}

fn appendLatestArchiveToResponse(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    archive_path: []const u8,
    first_item: *bool,
    remaining: *usize,
    include_full_from_archive: bool,
) !void {
    const file = std.fs.cwd().openFile(archive_path, .{ .mode = .read_only }) catch return;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(data);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return;

    if (parsed.value.object.get("summaries")) |summaries| {
        if (summaries != .array) return;
        var idx = summaries.array.items.len;
        while (idx > 0 and remaining.* > 0) {
            idx -= 1;
            const summary_value = summaries.array.items[idx];
            if (summary_value != .object) continue;

            const summary_obj = summary_value.object;
            const id = parsePositiveInteger(summary_obj.get("id") orelse continue) orelse continue;
            const source_id = parsePositiveInteger(summary_obj.get("source_id") orelse continue) orelse continue;
            const text = summary_obj.get("text") orelse continue;
            if (text != .string) continue;
            const created_at_ms = if (summary_obj.get("created_at_ms")) |ts| parseCreatedAtMs(ts) else 0;

            try appendRecallSummaryItem(
                allocator,
                out,
                first_item,
                "summary",
                "ltm",
                id,
                source_id,
                text.string,
                created_at_ms,
            );
            if (remaining.* > 0) remaining.* -= 1;
        }
    }

    if (!include_full_from_archive) return;

    if (parsed.value.object.get("entries")) |entries| {
        if (entries != .array) return;
        var idx = entries.array.items.len;
        while (idx > 0 and remaining.* > 0) {
            idx -= 1;
            const entry_value = entries.array.items[idx];
            if (entry_value != .object) continue;

            const entry_obj = entry_value.object;
            const entry_id = parsePositiveInteger(entry_obj.get("id") orelse continue) orelse continue;
            const role = if (entry_obj.get("role")) |value| blk: {
                if (value != .string) break :blk null;
                break :blk parseRole(value.string);
            } else null;
            if (role == null) continue;

            const state = if (entry_obj.get("state")) |state_value|
                if (state_value == .string and std.mem.eql(u8, state_value.string, "active")) "active" else "tombstone"
            else
                "unknown";
            const content = if (entry_obj.get("content")) |value| if (value == .string) value.string else continue else continue;
            const related_to = if (entry_obj.get("related_to")) |value| blk: {
                if (value == .null) break :blk null;
                break :blk parsePositiveInteger(value);
            } else null;

            if (remaining.* == 0) break;

            try appendRecallEntryItem(
                allocator,
                out,
                first_item,
                "entry",
                "ltm",
                state,
                role.?,
                entry_id,
                related_to,
                content,
            );
            if (remaining.* > 0) remaining.* -= 1;
        }
    }
}

fn appendRecallSummaryItem(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    first_item: *bool,
    kind: []const u8,
    source: []const u8,
    summary_id: memory.MemoryID,
    source_id: memory.MemoryID,
    text: []const u8,
    created_at_ms: i64,
) !void {
    if (!first_item.*) try out.appendSlice(allocator, ",");
    first_item.* = false;
    const escaped_text = try protocol.jsonEscape(allocator, text);
    defer allocator.free(escaped_text);
    const entry = try std.fmt.allocPrint(
        allocator,
        "{{\"kind\":\"{s}\",\"source\":\"{s}\",\"id\":{d},\"source_id\":{d},\"created_at_ms\":{d},\"text\":\"{s}\"}}",
        .{ kind, source, summary_id, source_id, created_at_ms, escaped_text },
    );
    defer allocator.free(entry);
    try out.appendSlice(allocator, entry);
}

fn appendRecallEntryItem(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    first_item: *bool,
    kind: []const u8,
    source: []const u8,
    state: []const u8,
    role: ziggy_piai.types.MessageRole,
    id: memory.MemoryID,
    related_to: ?memory.MemoryID,
    content: []const u8,
) !void {
    if (!first_item.*) try out.appendSlice(allocator, ",");
    first_item.* = false;

    const escaped_content = try protocol.jsonEscape(allocator, content);
    defer allocator.free(escaped_content);

    const role_name = switch (role) {
        .user => "user",
        .assistant => "assistant",
        .system => "system",
        .tool => "tool",
        .tool_result => "tool_result",
    };

    const item = if (related_to) |related_id| try std.fmt.allocPrint(
        allocator,
        "{{\"kind\":\"{s}\",\"source\":\"{s}\",\"id\":{d},\"role\":\"{s}\",\"state\":\"{s}\",\"related_to\":{d},\"content\":\"{s}\"}}",
        .{ kind, source, id, role_name, state, related_id, escaped_content },
    ) else try std.fmt.allocPrint(
        allocator,
        "{{\"kind\":\"{s}\",\"source\":\"{s}\",\"id\":{d},\"role\":\"{s}\",\"state\":\"{s}\",\"related_to\":null,\"content\":\"{s}\"}}",
        .{ kind, source, id, role_name, state, escaped_content },
    );
    defer allocator.free(item);

    try out.appendSlice(allocator, item);
}

fn restoreSessionFromLatestArchive(
    allocator: std.mem.Allocator,
    session: *SessionContext,
    session_id: []const u8,
) !bool {
    const latest = try findLatestArchiveForSession(allocator, session_id);
    const archive = latest orelse return false;
    defer {
        allocator.free(archive.archive_path);
        allocator.free(archive.reason);
    }

    const file = std.fs.cwd().openFile(archive.archive_path, .{ .mode = .read_only }) catch return false;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(data);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    session.resetRam(allocator);
    try session.setSessionId(allocator, session_id);

    const next_id = if (parsed.value.object.get("next_id")) |next_id_value|
        parsePositiveInteger(next_id_value) orelse 1
    else
        1;
    session.ram.setNextId(next_id);

    if (parsed.value.object.get("summaries")) |summaries| {
        if (summaries == .array) {
            for (summaries.array.items) |summary_value| {
                if (summary_value != .object) continue;
                const summary_obj = summary_value.object;

                const summary_id = parsePositiveInteger(summary_obj.get("id") orelse continue) orelse continue;
                const source_id = parsePositiveInteger(summary_obj.get("source_id") orelse continue) orelse continue;

                const summary_text = summary_obj.get("text") orelse continue;
                if (summary_text != .string) continue;

                const created_at_ms = if (summary_obj.get("created_at_ms")) |ts|
                    (parseCreatedAtMs(ts) orelse 0)
                else
                    0;

                try session.ram.restoreSummary(summary_id, source_id, summary_text.string, created_at_ms);
            }
        }
    }

    const ArchivedEntry = struct {
        id: memory.MemoryID,
        role: ziggy_piai.types.MessageRole,
        related_to: ?memory.MemoryID,
        content: []const u8,
    };

    var restored_entries = std.ArrayListUnmanaged(ArchivedEntry){};
    defer restored_entries.deinit(allocator);

    if (parsed.value.object.get("entries")) |entries| {
        if (entries == .array) {
            var idx = entries.array.items.len;
            var projected_bytes: usize = 0;

            while (idx > 0) {
                idx -= 1;
                const entry_value = entries.array.items[idx];
                if (entry_value != .object) continue;

                const entry_obj = entry_value.object;
                const state_value = entry_obj.get("state") orelse continue;
                if (state_value != .string or !std.mem.eql(u8, state_value.string, "active")) continue;

                const entry_id = parsePositiveInteger(entry_obj.get("id") orelse continue) orelse continue;
                const role = if (entry_obj.get("role")) |role_value| blk: {
                    if (role_value != .string) break :blk null;
                    break :blk parseRole(role_value.string);
                } else null;
                if (role == null) continue;

                const content = if (entry_value.object.get("content")) |content_value|
                    if (content_value == .string) content_value.string else continue
                else
                    continue;
                const content_len = content.len;

                const related_to = if (entry_obj.get("related_to")) |related_value| blk: {
                    if (related_value == .null) break :blk null;
                    if (related_value != .integer) break :blk null;
                    break :blk parsePositiveInteger(related_value);
                } else null;

                if (projected_bytes + content_len > MAX_CONTEXT_BYTES) continue;
                if (restored_entries.items.len >= MAX_CONTEXT_MESSAGES) continue;

                try restored_entries.append(allocator, .{
                    .id = entry_id,
                    .role = role.?,
                    .related_to = related_to,
                    .content = content,
                });
                projected_bytes += content_len;
            }
        }
    }

    if (restored_entries.items.len > 0) {
        var reverse_index = restored_entries.items.len;
        while (reverse_index > 0) {
            reverse_index -= 1;
            const restored_entry = restored_entries.items[reverse_index];
            try session.ram.restoreEntry(
                restored_entry.id,
                restored_entry.role,
                .active,
                restored_entry.related_to,
                restored_entry.content,
            );
        }
    }

    if (session.ram.summaries.items.len == 0 and session.ram.entries.items.len == 0) return false;
    return true;
}

fn handleSessionReset(
    allocator: std.mem.Allocator,
    conn: *Connection,
    archive_old_state: bool,
    reason: []const u8,
) !bool {
    var archived = false;

    if (archive_old_state) {
        archived = archiveSessionRamToLongTerm(allocator, &conn.session, reason) catch false;
    }

    conn.session.resetRam(allocator);
    return archived;
}

fn archiveSessionRamToLongTerm(
    allocator: std.mem.Allocator,
    session: *SessionContext,
    reason: []const u8,
) !bool {
    if (session.ram.entries.items.len == 0 and session.ram.summaries.items.len == 0) {
        return false;
    }

    var ltm_dir = try std.fs.cwd().makeOpenPath(LONG_TERM_ARCHIVE_DIR, .{});
    defer ltm_dir.close();

    const session_name = if (session.session_id.len > 0) session.session_id else "unbound-session";
    const timestamp = std.time.milliTimestamp();
    const filename = try std.fmt.allocPrint(allocator, "{s}-{d}.json", .{ session_name, timestamp });
    defer allocator.free(filename);
    const archive_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ LONG_TERM_ARCHIVE_DIR, filename });
    defer allocator.free(archive_path);

    var file = try ltm_dir.createFile(filename, .{ .truncate = true });
    defer file.close();

    try writeFormatted(
        allocator,
        file,
        "{{\"version\":{d},\"timestamp_ms\":{d},\"session_id\":",
        .{ LONG_TERM_ARCHIVE_VERSION, timestamp },
    );
    try writeJsonEscaped(allocator, file, session_name);
    try file.writeAll(",\"reason\":");
    try writeJsonEscaped(allocator, file, reason);
    try writeFormatted(allocator, file, ",\"next_id\":{d},\"entries\":[", .{session.ram.next_id});

    for (session.ram.entries.items, 0..) |entry, idx| {
        if (idx > 0) try file.writeAll(",");
        const role_name: []const u8 = switch (entry.message.role) {
            .user => "user",
            .assistant => "assistant",
            .system => "system",
            .tool => "tool",
            .tool_result => "tool_result",
        };

        const state_name: []const u8 = if (entry.state == .active) "active" else "tombstone";
        try writeFormatted(allocator, file, "{{\"id\":{d},\"role\":", .{entry.id});
        try writeJsonEscaped(allocator, file, role_name);
        try writeFormatted(allocator, file, ",\"state\":\"{s}\",\"content\":", .{state_name});
        try writeJsonEscaped(allocator, file, entry.message.content);
        if (entry.related_to) |related_to| {
            try writeFormatted(allocator, file, ",\"related_to\":{d}", .{related_to});
        } else {
            try file.writeAll(",\"related_to\":null");
        }
        try file.writeAll("}");
    }

    try writeFormatted(allocator, file, "],\"summaries\":[", .{});
    for (session.ram.summaries.items, 0..) |summary, idx| {
        if (idx > 0) try file.writeAll(",");
        try writeFormatted(
            allocator,
            file,
            "{{\"id\":{d},\"source_id\":{d},\"text\":",
            .{ summary.id, summary.source_id },
        );
        try writeJsonEscaped(allocator, file, summary.text);
        try writeFormatted(allocator, file, ",\"created_at_ms\":{d}}}", .{summary.created_at_ms});
    }

    try file.writeAll("]}");
    try ltm_index.appendArchiveIndex(allocator, LONG_TERM_ARCHIVE_DIR, .{
        .version = ltm_index.LtmIndexVersion,
        .timestamp_ms = timestamp,
        .session_id = session_name,
        .reason = reason,
        .archive_path = archive_path,
        .next_id = session.ram.next_id,
        .entry_count = session.ram.entries.items.len,
        .summary_count = session.ram.summaries.items.len,
    });
    return true;
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

fn deinitPersistedSessions(allocator: std.mem.Allocator, sessions: *std.ArrayListUnmanaged(PersistedSession)) void {
    for (sessions.items) |*session| {
        session.ram.deinit();
        allocator.free(session.session_id);
    }
    sessions.deinit(allocator);
}

fn copyRamContext(
    allocator: std.mem.Allocator,
    source: *const memory.RamContext,
    target: *memory.RamContext,
) !void {
    target.deinit();
    target.* = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES);
    target.setNextId(source.next_id);

    for (source.entries.items) |entry| {
        try target.restoreEntry(
            entry.id,
            entry.message.role,
            entry.state,
            entry.related_to,
            entry.message.content,
        );
    }

    for (source.summaries.items) |summary| {
        try target.restoreSummary(summary.id, summary.source_id, summary.text, summary.created_at_ms);
    }
}

fn upsertPersistedSession(allocator: std.mem.Allocator, persisted_sessions: *std.ArrayListUnmanaged(PersistedSession), session: *SessionContext) !void {
    if (session.session_id.len == 0) return;

    for (persisted_sessions.items) |*persisted| {
        if (std.mem.eql(u8, persisted.session_id, session.session_id)) {
            try copyRamContext(allocator, &session.ram, &persisted.ram);
            return;
        }
    }

    var restored = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES);
    try copyRamContext(allocator, &session.ram, &restored);
    try persisted_sessions.append(allocator, .{
        .session_id = try allocator.dupe(u8, session.session_id),
        .ram = restored,
    });
}

fn writeJsonEscaped(allocator: std.mem.Allocator, file: std.fs.File, value: []const u8) !void {
    const escaped = try protocol.jsonEscape(allocator, value);
    defer allocator.free(escaped);
    try file.writeAll("\"");
    try file.writeAll(escaped);
    try file.writeAll("\"");
}

fn writeFormatted(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    comptime format: []const u8,
    args: anytype,
) !void {
    const text = try std.fmt.allocPrint(allocator, format, args);
    defer allocator.free(text);
    try file.writeAll(text);
}

fn savePersistedSessions(
    allocator: std.mem.Allocator,
    persisted_sessions: *std.ArrayListUnmanaged(PersistedSession),
    connections: *std.AutoHashMap(posix.socket_t, *Connection),
) !void {
    var conn_it = connections.valueIterator();
    while (conn_it.next()) |conn| {
        try upsertPersistedSession(allocator, persisted_sessions, &conn.*.session);
    }

    const file = try std.fs.cwd().createFile(SESSION_STATE_PATH, .{ .truncate = true });
    defer file.close();

    try writeFormatted(allocator, file, "{{\"version\":{d},\"sessions\":[", .{SESSION_STATE_VERSION});

    var first_session = true;
    for (persisted_sessions.items) |session| {
        if (session.session_id.len == 0) continue;
        if (session.ram.entries.items.len == 0 and session.ram.summaries.items.len == 0) continue;

        if (!first_session) try file.writeAll(",");
        first_session = false;

        try file.writeAll("{\"session_id\":");
        try writeJsonEscaped(allocator, file, session.session_id);
        try writeFormatted(allocator, file, ",\"next_id\":{d},\"entries\":[", .{session.ram.next_id});

        var first_entry = true;
        for (session.ram.entries.items) |entry| {
            if (!first_entry) try file.writeAll(",");
            first_entry = false;

            const state: []const u8 = if (entry.state == .active) "active" else "tombstone";

            try writeFormatted(allocator, file, "{{\"id\":{d},\"role\":", .{entry.id});
            const role_name: []const u8 = switch (entry.message.role) {
                .user => "user",
                .assistant => "assistant",
                .system => "system",
                .tool => "tool",
                .tool_result => "tool_result",
            };
            try writeJsonEscaped(allocator, file, role_name);
            try writeFormatted(allocator, file, ",\"state\":\"{s}\",\"content\":", .{state});
            try writeJsonEscaped(allocator, file, entry.message.content);
            if (entry.related_to) |related| {
                try writeFormatted(allocator, file, ",\"related_to\":{d}", .{related});
            } else {
                try file.writeAll(",\"related_to\":null");
            }
            try file.writeAll("}");
        }

        try file.writeAll("],\"summaries\":[");
        var first_summary = true;
        for (session.ram.summaries.items) |summary| {
            if (!first_summary) try file.writeAll(",");
            first_summary = false;
            try writeFormatted(allocator, file, "{{\"id\":{d},\"source_id\":{d},\"text\":", .{ summary.id, summary.source_id });
            try writeJsonEscaped(allocator, file, summary.text);
            try writeFormatted(allocator, file, ",\"created_at_ms\":{d}}}", .{summary.created_at_ms});
        }
        try file.writeAll("]}");
    }
    try file.writeAll("]}");
}

fn parseRole(text: []const u8) ?ziggy_piai.types.MessageRole {
    if (std.mem.eql(u8, text, "user")) return .user;
    if (std.mem.eql(u8, text, "assistant")) return .assistant;
    if (std.mem.eql(u8, text, "system")) return .system;
    if (std.mem.eql(u8, text, "tool")) return .tool;
    if (std.mem.eql(u8, text, "tool_result")) return .tool_result;
    return null;
}

fn parseRamEntryState(text: []const u8) ?memory.RamEntryState {
    if (std.mem.eql(u8, text, "active")) return .active;
    if (std.mem.eql(u8, text, "tombstone")) return .tombstone;
    return null;
}

fn parsePositiveInteger(value: std.json.Value) ?u64 {
    if (value == .integer) {
        if (value.integer < 0) return null;
        return @intCast(value.integer);
    }
    return null;
}

fn parseCreatedAtMs(value: std.json.Value) ?i64 {
    if (value == .integer) return value.integer;
    return null;
}

fn loadPersistedSessions(allocator: std.mem.Allocator) !std.ArrayListUnmanaged(PersistedSession) {
    var sessions = std.ArrayListUnmanaged(PersistedSession){};

    const file = std.fs.cwd().openFile(SESSION_STATE_PATH, .{ .mode = .read_only }) catch |err| {
        if (err == error.FileNotFound) return sessions;
        return err;
    };
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, contents, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return sessions;
    const version = if (parsed.value.object.get("version")) |v| parsePositiveInteger(v) orelse SESSION_STATE_VERSION else SESSION_STATE_VERSION;
    if (version != SESSION_STATE_VERSION) return sessions;

    const sessions_value = parsed.value.object.get("sessions") orelse return sessions;
    if (sessions_value != .array) return sessions;

    for (sessions_value.array.items) |session_value| {
        if (session_value != .object) continue;
        const session_obj = session_value.object;

        const session_id_value = session_obj.get("session_id") orelse continue;
        if (session_id_value != .string) continue;

        var context = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES);
        if (session_obj.get("next_id")) |next_id| {
            if (parsePositiveInteger(next_id)) |next_value| context.setNextId(next_value);
        }

        if (session_obj.get("entries")) |entries_value| {
            if (entries_value == .array) {
                for (entries_value.array.items) |entry_value| {
                    if (entry_value != .object) continue;
                    const entry_obj = entry_value.object;
                    const entry_id = parsePositiveInteger(entry_obj.get("id") orelse continue) orelse continue;
                    const role_str = entry_obj.get("role") orelse continue;
                    if (role_str != .string) continue;
                    const role = parseRole(role_str.string) orelse continue;

                    const state_str = entry_obj.get("state") orelse continue;
                    if (state_str != .string) continue;
                    const state_enum = parseRamEntryState(state_str.string) orelse continue;

                    const content_value = entry_obj.get("content") orelse continue;
                    if (content_value != .string) continue;

                    const related_to = blk: {
                        if (entry_obj.get("related_to")) |related_to_value| {
                            if (related_to_value == .null) break :blk null;
                            if (related_to_value == .integer) break :blk parsePositiveInteger(related_to_value);
                            break :blk null;
                        }
                        break :blk null;
                    };

                    try context.restoreEntry(entry_id, role, state_enum, related_to, content_value.string);
                }
            }
        }

        if (session_obj.get("summaries")) |summaries_value| {
            if (summaries_value == .array) {
                for (summaries_value.array.items) |summary_value| {
                    if (summary_value != .object) continue;
                    const summary_obj = summary_value.object;

                    const summary_id = parsePositiveInteger(summary_obj.get("id") orelse continue) orelse continue;
                    const source_id = parsePositiveInteger(summary_obj.get("source_id") orelse continue) orelse continue;

                    const summary_text = summary_obj.get("text") orelse continue;
                    if (summary_text != .string) continue;

                    const created_at_ms = if (summary_obj.get("created_at_ms")) |ts|
                        (parseCreatedAtMs(ts) orelse 0)
                    else
                        0;
                    try context.restoreSummary(summary_id, source_id, summary_text.string, created_at_ms);
                }
            }
        }

        try sessions.append(allocator, .{
            .session_id = try allocator.dupe(u8, session_id_value.string),
            .ram = context,
        });
    }

    return sessions;
}

fn restoreSessionFromPersistedWithId(
    allocator: std.mem.Allocator,
    persisted_sessions: *std.ArrayListUnmanaged(PersistedSession),
    session: *SessionContext,
    requested_session_id: []const u8,
) !void {
    for (persisted_sessions.items, 0..) |*persisted, i| {
        if (!std.mem.eql(u8, persisted.session_id, requested_session_id)) continue;

        session.ram.deinit();
        if (session.session_id.len > 0) allocator.free(session.session_id);

        const recovered = persisted_sessions.orderedRemove(i);
        session.ram = recovered.ram;
        session.session_id = recovered.session_id;
        std.log.info("Restored session state: {s}", .{session.session_id});
        return;
    }

    return error.SessionNotFound;
}

fn parseSessionIdFromRequest(request: []const u8) ?[]const u8 {
    const request_line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const request_line = request[0..request_line_end];
    const first_space = std.mem.indexOf(u8, request_line, " ") orelse return null;
    const second_space = std.mem.indexOfPos(u8, request_line, first_space + 1, " ") orelse return null;
    const path = request_line[first_space + 1 .. second_space];

    const query_start = std.mem.indexOf(u8, path, "?") orelse return null;
    const query = path[query_start + 1 ..];

    var params = std.mem.splitSequence(u8, query, "&");
    while (params.next()) |param| {
        const eq = std.mem.indexOf(u8, param, "=") orelse continue;
        const key = param[0..eq];
        const value = param[eq + 1 ..];
        if (value.len == 0) continue;

        if (std.mem.eql(u8, key, "session") or
            std.mem.eql(u8, key, "sessionId") or
            std.mem.eql(u8, key, "session_id") or
            std.mem.eql(u8, key, "sessionKey") or
            std.mem.eql(u8, key, "session-key"))
        {
            return value;
        }
    }

    return null;
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
