const std = @import("std");
const ziggy_piai = @import("ziggy-piai");
const Config = @import("config.zig");
const protocol = @import("protocol.zig");
const memory = @import("memory.zig");
const identity = @import("identity.zig");
const orchestrator = @import("orchestrator.zig");
const workers = @import("workers.zig");
const ltm_store = @import("ltm_store.zig");
const ltm_index = @import("ltm_index.zig");
const agent_registry = @import("agent_registry.zig");
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
const SESSION_STATE_VERSION = 2;
const LONG_TERM_ARCHIVE_DIR = ".spiderweb-ltm";
const LTM_INDEX_FILENAME = "archive-index.ndjson";
const LONG_TERM_ARCHIVE_VERSION = 1;
const LTM_DB_FILENAME = "memory.db";
const LTM_RETENTION_MAX_SNAPSHOTS_DEFAULT: usize = 24;
const LTM_RETENTION_MAX_AGE_DAYS_DEFAULT: u64 = 30;
const LTM_RETENTION_KEEP_SNAPSHOTS_ENV = "SPIDERWEB_LTM_KEEP_SNAPSHOTS";
const LTM_RETENTION_KEEP_DAYS_ENV = "SPIDERWEB_LTM_KEEP_DAYS";
const AGENT_GOAL_PREFIX = "/goal ";
const WORKER_MAX_PARALLELISM = 2;
const WORKER_MAX_TASKS_PER_DISPATCH = 4;
const WORKER_BACKPRESSURE_WARNING_MS: i64 = 30 * 1000;
const WORKER_RECONNECTION_PROGRESS_ID = "session-restore";
const MEMORY_MANAGER_SUMMARY_TRIGGER_NUM = 3;
const MEMORY_MANAGER_SUMMARY_TRIGGER_DEN = 4;
const MEMORY_MANAGER_SUMMARIES_PER_TICK = 2;
const MEMORY_MANAGER_SNAPSHOT_REASON = "memory-manager auto snapshot";
const HEARTBEAT_INTERVAL_MS: i64 = 30 * 1000;
const HEARTBEAT_SWEEP_INTERVAL_MS: i64 = 5 * 1000;
const HEARTBEAT_SWEEP_REQUEST_ID = "heartbeat-sweep";
const StreamByModelFn = *const fn (
    std.mem.Allocator,
    *std.http.Client,
    *ziggy_piai.api_registry.ApiRegistry,
    ziggy_piai.types.Model,
    ziggy_piai.types.Context,
    ziggy_piai.types.StreamOptions,
    *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void;

var streamByModelFn: StreamByModelFn = ziggy_piai.stream.streamByModel;

const PersistedSession = struct {
    session_id: []u8,
    ram: memory.RamContext,
    worker_queue_depth: usize,
    worker_active_tasks: usize,
    worker_mode: WorkerControlMode,
    worker_dropped_tasks: usize,
    worker_last_saturation_ms: i64,
    worker_backpressure_notified: bool,
    worker_last_goal: []const u8,
};

const ServerState = struct {
    allocator: std.mem.Allocator,
    rng: std.Random.DefaultPrng,
    model_registry: ziggy_piai.models.ModelRegistry,
    api_registry: ziggy_piai.api_registry.ApiRegistry,
    http_client: std.http.Client,
    provider_config: Config.ProviderConfig,
    ltm_store: ?ltm_store.Store,
    agent_registry: agent_registry.AgentRegistry,
};

const ConnectionState = enum {
    handshake,
    websocket,
    closing,
};

const WorkerControlMode = enum {
    running,
    paused,
    cancelled,
};

const SessionError = error{ MessageTooLarge };

const SessionContext = struct {
    ram: memory.RamContext,
    session_id: []u8,
    identity_prompt: []u8,
    worker_mode: WorkerControlMode,
    worker_queue_depth: usize,
    worker_active_tasks: usize,
    last_goal: []const u8,
    last_heartbeat_ms: i64,
    worker_dropped_tasks: usize,
    worker_last_saturation_ms: i64,
    worker_backpressure_notified: bool,

    fn init(allocator: std.mem.Allocator) SessionContext {
        return .{
            .ram = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES),
            .session_id = &[_]u8{},
            .identity_prompt = &[_]u8{},
            .worker_mode = .running,
            .worker_queue_depth = 0,
            .worker_active_tasks = 0,
            .last_goal = &[_]u8{},
            .last_heartbeat_ms = 0,
            .worker_dropped_tasks = 0,
            .worker_last_saturation_ms = 0,
            .worker_backpressure_notified = false,
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
        if (self.identity_prompt.len > 0) allocator.free(self.identity_prompt);
        self.identity_prompt = &[_]u8{};
        if (self.last_goal.len > 0) allocator.free(self.last_goal);
        self.last_goal = &[_]u8{};
        self.worker_mode = .running;
        self.worker_queue_depth = 0;
        self.worker_active_tasks = 0;
        self.last_heartbeat_ms = 0;
        self.worker_dropped_tasks = 0;
        self.worker_last_saturation_ms = 0;
        self.worker_backpressure_notified = false;
    }

    fn setLastGoal(self: *SessionContext, allocator: std.mem.Allocator, goal: []const u8) !void {
        if (self.last_goal.len > 0) allocator.free(self.last_goal);
        self.last_goal = try allocator.dupe(u8, goal);
    }

    fn setWorkerMode(self: *SessionContext, mode: WorkerControlMode) void {
        self.worker_mode = mode;
    }

    fn markWorkerSaturation(self: *SessionContext, dropped_tasks: usize) void {
        self.worker_dropped_tasks = dropped_tasks;
        self.worker_last_saturation_ms = if (dropped_tasks == 0) 0 else std.time.milliTimestamp();
        self.worker_backpressure_notified = false;
    }

    fn resetWorkerState(self: *SessionContext, allocator: std.mem.Allocator) void {
        if (self.last_goal.len > 0) allocator.free(self.last_goal);
        self.last_goal = &[_]u8{};
        self.worker_mode = .running;
        self.worker_queue_depth = 0;
        self.worker_active_tasks = 0;
        self.last_heartbeat_ms = 0;
        self.worker_dropped_tasks = 0;
        self.worker_last_saturation_ms = 0;
        self.worker_backpressure_notified = false;
    }

    fn setIdentityPrompt(self: *SessionContext, allocator: std.mem.Allocator, prompt: []const u8) !void {
        if (self.identity_prompt.len > 0) allocator.free(self.identity_prompt);
        self.identity_prompt = try allocator.dupe(u8, prompt);
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
    // Atomic flag to indicate connection is being closed (for thread safety)
    closing: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn init(allocator: std.mem.Allocator, fd: posix.socket_t) Connection {
        return .{
            .fd = fd,
            .state = .handshake,
            .agent_id = &[_]u8{},
            .read_buf = .{},
            .write_buf = .{},
            .session = SessionContext.init(allocator),
            .closing = std.atomic.Value(bool).init(false),
        };
    }

    fn deinit(self: *Connection, allocator: std.mem.Allocator) void {
        self.closing.store(true, .release);
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

    fn wait(self: *EventLoop, events_out: []Event, timeout_ms: i32) usize {
        var epoll_events: [64]linux.epoll_event = undefined;
        const n = posix.epoll_wait(self.fd, &epoll_events, timeout_ms);
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

    fn wait(self: *EventLoop, events_out: []Event, timeout_ms: i32) usize {
        const n = posix.poll(self.pollfds.items, timeout_ms) catch return 0;
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

    const ltm_storage = ltm_store.Store.open(allocator, LONG_TERM_ARCHIVE_DIR, LTM_DB_FILENAME) catch |err| blk: {
        std.log.warn("LTM sqlite unavailable, using legacy archive files: {s}", .{@errorName(err)});
        break :blk null;
    };

    var persisted_sessions = try loadPersistedSessions(allocator);

    var registry = agent_registry.AgentRegistry.init(allocator, ".");
    try registry.scan();
    defer registry.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp())),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = provider_config,
        .ltm_store = ltm_storage,
        .agent_registry = registry,
    };
    defer if (state.ltm_store) |*store| store.close();

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

    if (state.ltm_store) |*store| {
        const legacy_index_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ LONG_TERM_ARCHIVE_DIR, LTM_INDEX_FILENAME });
        defer allocator.free(legacy_index_path);

        const migrated = store.migrateLegacyArchives(legacy_index_path) catch |err| blk: {
            std.log.warn("Legacy LTM migration failed: {s}", .{@errorName(err)});
            break :blk 0;
        };
        if (migrated > 0) {
            std.log.info("Migrated {d} legacy long-term archives into sqlite", .{migrated});
        }

        const keep_snapshots = parseRetentionKeepLimit(allocator);
        const max_age_ms = parseRetentionMaxAgeMs(allocator);
        if (keep_snapshots > 0 or max_age_ms != null) {
            const pruned = store.pruneSnapshots(max_age_ms, @as(?usize, keep_snapshots)) catch |err| blk: {
                std.log.warn("LTM retention prune failed: {s}", .{@errorName(err)});
                break :blk 0;
            };
            if (pruned > 0) {
                std.log.info("Pruned {d} old LTM snapshots", .{pruned});
            }
        }
    }

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
    var next_heartbeat_check_ms = std.time.milliTimestamp() + HEARTBEAT_SWEEP_INTERVAL_MS;
    while (true) {
        const now_ms = std.time.milliTimestamp();
        const wait_ms = if (next_heartbeat_check_ms <= now_ms)
            0
        else
            @as(i32, @intCast(next_heartbeat_check_ms - now_ms));

        const n = loop.wait(&events, wait_ms);
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

        const after_loop_ms = std.time.milliTimestamp();
        if (after_loop_ms >= next_heartbeat_check_ms) {
            runHeartbeatSweep(allocator, &connections);
            next_heartbeat_check_ms = after_loop_ms + HEARTBEAT_SWEEP_INTERVAL_MS;
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
        const prompt = identity.loadMergedPrompt(allocator, ".", agent_id) catch |err| blk: {
            std.log.warn("Identity load failed for agent={s}: {s}", .{ agent_id, @errorName(err) });
            break :blk try allocator.dupe(u8, "You are a helpful AI assistant.");
        };
        try conn.session.setIdentityPrompt(allocator, prompt);
        if (prompt.ptr != conn.session.identity_prompt.ptr) {
            allocator.free(prompt);
        }

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
        var restored_session = false;
        if (requested_session_id) |requested| {
            if (restoreSessionFromPersistedWithId(allocator, persisted_sessions, &conn.session, requested)) {
                restored_session = true;
            } else |err| {
                if (err != error.SessionNotFound) {
                    return err;
                }
                var restored_from_archive: bool = false;
                if (restoreSessionFromLatestArchive(allocator, state, &conn.session, requested)) |archive_restored| {
                    restored_from_archive = archive_restored;
                } else |archive_err| {
                    std.log.err("Session archive restore failed: {s} session={s}", .{ @errorName(archive_err), requested });
                }
                if (restored_from_archive) {
                    std.log.info("Session restored from archive: session={s}", .{requested});
                    restored_session = true;
                }
            }
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

        if (restored_session) {
            const has_backlog = conn.session.worker_queue_depth > 0 or conn.session.worker_active_tasks > 0 or conn.session.worker_dropped_tasks > 0;
            const reconnect_status = if (has_backlog) "backpressure_resumed" else "state_restored";
            const reconnect_message = if (has_backlog)
                try std.fmt.allocPrint(
                    allocator,
                    "Session restored with backlog: {d} queued, {d} active, {d} dropped tasks from previous run.",
                    .{
                        conn.session.worker_queue_depth,
                        conn.session.worker_active_tasks,
                        conn.session.worker_dropped_tasks,
                    },
                )
            else
                try std.fmt.allocPrint(
                    allocator,
                    "Session restored from previous process state: {s}",
                    .{conn.session.last_goal},
                );
            defer allocator.free(reconnect_message);
            try sendAgentProgress(
                allocator,
                &conn.write_buf,
                WORKER_RECONNECTION_PROGRESS_ID,
                conn.session.session_id,
                "reconnect",
                reconnect_status,
                reconnect_message,
            );
        }
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
    is_planned_goal: bool = false,
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

        const archived = handleSessionReset(state, allocator, conn, should_archive, reason) catch |err| blk: {
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

            handleMemoryRecall(state, allocator, conn, request_id, limit, include_archived, include_full) catch |err| {
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
            state,
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
    const is_agent_control = std.mem.eql(u8, msg_type.string, "agent.control");
    const is_agent_heartbeat = std.mem.eql(u8, msg_type.string, "agent.heartbeat");
    const is_agent_list = std.mem.eql(u8, msg_type.string, "agent.list");
    const is_agent_get = std.mem.eql(u8, msg_type.string, "agent.get");

    if (is_agent_list) {
        try handleAgentList(allocator, state, conn, request_id);
        return;
    }

    if (is_agent_get) {
        const agent_id = if (parsed.value.object.get("agent_id")) |id|
            if (id == .string) id.string else null
        else
            null;
        try handleAgentGet(allocator, state, conn, request_id, agent_id);
        return;
    }

    const is_session_restore = std.mem.eql(u8, msg_type.string, "session.restore");
    const is_session_history = std.mem.eql(u8, msg_type.string, "session.history");

    if (is_session_restore) {
        const agent_id = if (parsed.value.object.get("agent_id")) |id|
            if (id == .string) id.string else "default"
        else
            "default";
        try handleSessionRestore(allocator, state, conn, request_id, agent_id);
        return;
    }

    if (is_session_history) {
        const agent_id = if (parsed.value.object.get("agent_id")) |id|
            if (id == .string) id.string else "default"
        else
            "default";
        const limit = if (parsed.value.object.get("limit")) |l|
            if (l == .integer and l.integer >= 0) @min(l.integer, 20) else 5
        else
            5;
        try handleSessionHistory(allocator, state, conn, request_id, agent_id, @intCast(limit));
        return;
    }

    if (!is_chat_send and !is_agent_control and !is_agent_heartbeat) return;

    const control_action = blk: {
        if (is_agent_control) {
            if (parsed.value.object.get("action")) |action_value| {
                if (action_value == .string) break :blk action_value.string;
            }
            break :blk null;
        }
        break :blk null;
    };

    if (is_agent_control) {
        if (control_action) |action| {
            if (std.mem.eql(u8, action, "state") or std.mem.eql(u8, action, "status")) {
                try sendAgentState(
                    allocator,
                    &conn.write_buf,
                    request_id,
                    conn.session.session_id,
                    workerModeLabel(conn.session.worker_mode),
                    conn.session.worker_queue_depth,
                    conn.session.worker_active_tasks,
                    conn.session.last_goal,
                );
                return;
            }

            if (std.mem.eql(u8, action, "heartbeat")) {
                try runHeartbeatCheck(allocator, conn, request_id, true);
                return;
            }

            if (std.mem.eql(u8, action, "pause")) {
                conn.session.setWorkerMode(.paused);
                try sendAgentState(
                    allocator,
                    &conn.write_buf,
                    request_id,
                    conn.session.session_id,
                    "workers.paused",
                    conn.session.worker_queue_depth,
                    conn.session.worker_active_tasks,
                    conn.session.last_goal,
                );
                return;
            }

            if (std.mem.eql(u8, action, "resume")) {
                conn.session.setWorkerMode(.running);
                try sendAgentState(
                    allocator,
                    &conn.write_buf,
                    request_id,
                    conn.session.session_id,
                    "workers.running",
                    conn.session.worker_queue_depth,
                    conn.session.worker_active_tasks,
                    conn.session.last_goal,
                );
                return;
            }

            if (std.mem.eql(u8, action, "cancel")) {
                conn.session.setWorkerMode(.cancelled);
                try sendAgentState(
                    allocator,
                    &conn.write_buf,
                    request_id,
                    conn.session.session_id,
                    "workers.cancelled",
                    conn.session.worker_queue_depth,
                    conn.session.worker_active_tasks,
                    conn.session.last_goal,
                );
                return;
            }

            if (!std.mem.eql(u8, action, "goal") and !std.mem.eql(u8, action, "plan")) {
                std.log.warn("agent.control unsupported action: {s}", .{action});
                try sendErrorJson(allocator, &conn.write_buf, "agent.control unsupported action");
                return;
            }
        }
    }

    if (is_agent_heartbeat) {
        try runHeartbeatCheck(allocator, conn, request_id, true);
        return;
    }

    const content = blk: {
        if (parsed.value.object.get("content")) |c| if (c == .string) break :blk c.string;
        if (parsed.value.object.get("text")) |t| if (t == .string) break :blk t.string;
        if (is_agent_control) {
            if (parsed.value.object.get("goal")) |goal| if (goal == .string) break :blk goal.string;
        }
        return;
    };

    var plan_goal: ?[]const u8 = null;
    if (is_chat_send and std.mem.startsWith(u8, content, AGENT_GOAL_PREFIX)) {
        const trimmed_goal = std.mem.trim(u8, content[AGENT_GOAL_PREFIX.len..], " \t\r\n");
        if (trimmed_goal.len > 0) {
            plan_goal = trimmed_goal;
        } else {
            std.log.warn("goal command missing content: session={s} request={s}", .{ conn.session.session_id, request_id });
            try sendErrorJson(allocator, &conn.write_buf, "Goal command requires text after /goal");
            return;
        }
    } else if (is_agent_control) {
        if (parsed.value.object.get("goal")) |goal| {
            if (goal == .string) {
                const trimmed_goal = std.mem.trim(u8, goal.string, " \t\r\n");
                if (trimmed_goal.len > 0) plan_goal = trimmed_goal;
            }
        } else {
            const trimmed_goal = std.mem.trim(u8, content, " \t\r\n");
            if (trimmed_goal.len > 0) plan_goal = trimmed_goal;
        }
    }

    if (is_chat_send and std.mem.eql(u8, content, "/new")) {
        const archived = handleSessionReset(state, allocator, conn, true, "slash-new") catch |err| blk: {
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

    var is_planned_goal = false;
    if (plan_goal) |goal| {
        var plan = orchestrator.buildPlan(allocator, goal) catch |err| {
            std.log.err("Failed to build goal plan: {s} session={s} request={s}", .{
                @errorName(err),
                conn.session.session_id,
                request_id,
            });
            try sendErrorJson(allocator, &conn.write_buf, "Failed to build Primary Brain plan");
            return;
        };
        defer orchestrator.deinitPlan(allocator, &plan);

        is_planned_goal = true;
        const max_workers = if (WORKER_MAX_PARALLELISM == 0) 1 else WORKER_MAX_PARALLELISM;
        const accepted_task_count = @min(plan.tasks.items.len, WORKER_MAX_TASKS_PER_DISPATCH);
        const dropped_task_count = plan.tasks.items.len - accepted_task_count;
        conn.session.worker_queue_depth = if (accepted_task_count > max_workers)
            accepted_task_count - max_workers
        else
            0;
        conn.session.worker_active_tasks = @min(accepted_task_count, max_workers);
        conn.session.markWorkerSaturation(dropped_task_count);
        try conn.session.setLastGoal(allocator, goal);
        const plan_memory = try orchestrator.formatPlanMemoryText(allocator, &plan);
        defer allocator.free(plan_memory);
        const executed_tasks = plan.tasks.items[0..accepted_task_count];

        try sendAgentProgress(allocator, &conn.write_buf, request_id, conn.session.session_id, "planner", "received", "Planning request received");
        try sendAgentPlan(allocator, &conn.write_buf, request_id, conn.session.session_id, plan.goal, plan.tasks);
        try sendAgentProgress(allocator, &conn.write_buf, request_id, conn.session.session_id, "planner", "ready", plan.response_text);
        if (dropped_task_count > 0) {
            const saturation_msg = try std.fmt.allocPrint(
                allocator,
                "Worker queue saturation: accepted {d}/{d} plan tasks; {d} dropped",
                .{ accepted_task_count, plan.tasks.items.len, dropped_task_count },
            );
            defer allocator.free(saturation_msg);
            try sendAgentProgressWithBackpressure(
                allocator,
                &conn.write_buf,
                request_id,
                conn.session.session_id,
                "planner",
                "saturated",
                saturation_msg,
                accepted_task_count,
                plan.tasks.items.len,
                dropped_task_count,
                conn.session.worker_queue_depth,
                conn.session.worker_active_tasks,
            );
        }
        try sendAgentProgress(
            allocator,
            &conn.write_buf,
            request_id,
            conn.session.session_id,
            "workers",
            "queued",
            "Delegating plan tasks to local workers",
        );
        try sendAgentState(
            allocator,
            &conn.write_buf,
            request_id,
            conn.session.session_id,
            "workers.dispatching",
            conn.session.worker_queue_depth,
            conn.session.worker_active_tasks,
            conn.session.last_goal,
        );

        var worker_exec_ok = true;
        if (conn.session.worker_mode != .running) {
            try sendAgentProgress(
                allocator,
                &conn.write_buf,
                request_id,
                conn.session.session_id,
                "workers",
                "skipped",
                if (conn.session.worker_mode == .paused) "Workers currently paused" else "Workers cancelled",
            );
            try sendAgentState(
                allocator,
                &conn.write_buf,
                request_id,
                conn.session.session_id,
                workerModeLabel(conn.session.worker_mode),
                0,
                0,
                conn.session.last_goal,
            );
        } else {
            var worker_results = std.ArrayListUnmanaged(workers.WorkerResult){};
            defer worker_results.deinit(allocator);

            workers.executePlanWorkers(
                allocator,
                executed_tasks,
                max_workers,
                &worker_results,
            ) catch |err| {
                std.log.err("Worker execution failed: {s} session={s} request={s}", .{
                    @errorName(err),
                    conn.session.session_id,
                    request_id,
                });
                worker_exec_ok = false;
            };
            if (!worker_exec_ok) {
                try sendAgentProgress(
                    allocator,
                    &conn.write_buf,
                    request_id,
                    conn.session.session_id,
                    "workers",
                    "failed",
                    "Worker delegation failed",
                );
            } else {
                for (worker_results.items) |result| {
                    const worker_name = workers.workerTypeLabel(result.worker);
                    const message = try std.fmt.allocPrint(
                        allocator,
                        "{s} worker complete for task {d}: {s}",
                        .{ worker_name, result.task_id, result.detailSlice() },
                    );
                    defer allocator.free(message);

                    try sendAgentProgress(
                        allocator,
                        &conn.write_buf,
                        request_id,
                        conn.session.session_id,
                        worker_name,
                        result.statusSlice(),
                        message,
                    );
                    try sendAgentStatus(
                        allocator,
                        &conn.write_buf,
                        request_id,
                        conn.session.session_id,
                        result.task_id,
                        worker_name,
                        result.statusSlice(),
                        result.detailSlice(),
                    );
                }
                try sendAgentProgress(
                    allocator,
                    &conn.write_buf,
                    request_id,
                    conn.session.session_id,
                    "workers",
                    "ready",
                    "Worker pre-processing complete",
                );
                try sendAgentState(
                    allocator,
                    &conn.write_buf,
                    request_id,
                    conn.session.session_id,
                    "workers.ready",
                    0,
                    0,
                    conn.session.last_goal,
                );
            }
        }
        _ = try conn.session.appendMessage(allocator, .system, plan_memory);
    } else if (is_agent_control) {
        std.log.warn("agent.control requires goal payload: session={s} request={s}", .{ conn.session.session_id, request_id });
        try sendErrorJson(allocator, &conn.write_buf, "agent.control requires goal field or text");
        return;
    }

    const user_content = if (plan_goal) |goal| goal else content;
    const user_msg_id = conn.session.appendUserMessage(allocator, .user, user_content) catch |err| {
        if (err == SessionError.MessageTooLarge) {
            std.log.warn(
                "Dropping oversized user message: session={s} request={s} bytes={d}",
                .{ conn.session.session_id, request_id, user_content.len },
            );
            try sendErrorJson(allocator, &conn.write_buf, "Message too large for active context");
            return;
        }
        return err;
    };

    runMemoryManager(allocator, state, conn, request_id) catch |err| {
        std.log.warn("memory manager maintenance failed: {s} session={s} request={s}", .{
            @errorName(err),
            conn.session.session_id,
            request_id,
        });
    };
    runHeartbeatCheck(allocator, conn, request_id, false) catch |err| {
        std.log.warn("heartbeat check failed: {s} session={s} request={s}", .{
            @errorName(err),
            conn.session.session_id,
            request_id,
        });
    };

    std.log.info("Accepted message: session={s} request={s} memoryId={d} bytes={d}", .{
        conn.session.session_id,
        request_id,
        user_msg_id,
        user_content.len,
    });

    // Update session metadata for restore functionality
    if (state.ltm_store) |*store| {
        store.updateSessionMetadata(
            conn.session.session_id,
            conn.agent_id,
            @intCast(conn.session.ram.entries.items.len),
        ) catch |err| {
            std.log.warn("Failed to update session metadata: {s}", .{@errorName(err)});
        };
    }

    const args = try allocator.create(AiTaskArgs);
    args.* = .{
        .allocator = allocator,
        .state = state,
        .conn = conn,
        .request_id = request_id,
        .is_planned_goal = is_planned_goal,
    };

    pool.spawn(runAiTask, .{args}) catch |err| {
        std.log.err("Failed to spawn AI task: {s} session={s} request={s}", .{ @errorName(err), conn.session.session_id, request_id_owned });
        allocator.destroy(args);
        return;
    };
    args.request_id = request_id_owned;
    request_id_owned = "";
}

fn sendDirect(
    allocator: std.mem.Allocator,
    conn: *Connection,
    payload: []const u8,
) !void {
    // Write directly to socket, bypassing write_buf
    // This is used by AI tasks to ensure data is sent immediately
    var frame_buf = std.ArrayListUnmanaged(u8){};
    defer frame_buf.deinit(allocator);

    const opcode: u8 = 0x81; // text frame, final
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

    try frame_buf.appendSlice(allocator, header[0..header_len]);
    try frame_buf.appendSlice(allocator, payload);

    // Write directly to socket
    const n = posix.write(conn.fd, frame_buf.items) catch |err| {
        std.log.err("Direct write failed: {s}", .{@errorName(err)});
        return err;
    };

    if (n < frame_buf.items.len) {
        std.log.warn("Direct write incomplete: {d}/{d} bytes", .{ n, frame_buf.items.len });
    }
}

fn sendSessionReceiveDirect(
    allocator: std.mem.Allocator,
    conn: *Connection,
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

    try sendDirect(allocator, conn, response_json);
}

fn runAiTask(args: *AiTaskArgs) void {
    processAiStreaming(args.allocator, args.state, args.conn, args.request_id, args.is_planned_goal) catch |err| {
        std.log.err("AI Task failed: {s} session={s} request={s}", .{
            @errorName(err),
            args.conn.session.session_id,
            args.request_id,
        });
    };
    args.allocator.free(args.request_id);
    args.allocator.destroy(args);
}

fn runMemoryManager(
    allocator: std.mem.Allocator,
    state: *ServerState,
    conn: *Connection,
    request_id: []const u8,
) !void {
    const trigger_count = memoryManagerActiveThreshold(conn.session.ram.max_messages);
    if (!shouldRunMemoryManagement(&conn.session.ram, trigger_count)) return;

    var summaries_performed: usize = 0;
    while (summaries_performed < MEMORY_MANAGER_SUMMARIES_PER_TICK and
        shouldRunMemoryManagement(&conn.session.ram, trigger_count))
    {
        try conn.session.ram.summarize();
        summaries_performed += 1;
    }

    if (summaries_performed == 0) return;

    var snapshot_taken = false;
    if (conn.session.session_id.len > 0) {
        if (state.ltm_store) |*store| {
            if (store.archiveRamSnapshot(conn.session.session_id, MEMORY_MANAGER_SNAPSHOT_REASON, &conn.session.ram) catch false) {
                snapshot_taken = true;
            }
        }
    }

    const message = if (snapshot_taken)
        try std.fmt.allocPrint(allocator, "summarized {d} stale RAM entries and persisted snapshot", .{summaries_performed})
    else
        try std.fmt.allocPrint(allocator, "summarized {d} stale RAM entries", .{summaries_performed});
    defer allocator.free(message);

    try sendMemoryEvent(
        allocator,
        &conn.write_buf,
        request_id,
        conn.session.session_id,
        "summarize",
        if (snapshot_taken) "snapshot" else "summarized",
        summaries_performed,
        message,
    );
}

fn runHeartbeatSweep(allocator: std.mem.Allocator, connections: *std.AutoHashMap(posix.socket_t, *Connection)) void {
    var it = connections.valueIterator();
    while (it.next()) |conn_ptr| {
        const conn = conn_ptr.*;
        if (conn.state != .websocket) continue;
        runHeartbeatCheck(allocator, conn, HEARTBEAT_SWEEP_REQUEST_ID, false) catch |err| {
            std.log.warn("heartbeat sweep failed: {s} session={s}", .{
                @errorName(err),
                conn.session.session_id,
            });
        };
    }
}

fn runHeartbeatCheck(
    allocator: std.mem.Allocator,
    conn: *Connection,
    request_id: []const u8,
    force: bool,
) !void {
    const now = std.time.milliTimestamp();
    if (!force and conn.session.last_heartbeat_ms != 0) {
        if ((now - conn.session.last_heartbeat_ms) < HEARTBEAT_INTERVAL_MS) return;
    }

    if (conn.session.last_heartbeat_ms == 0) {
        conn.session.last_heartbeat_ms = now;
        if (!force) return;
    } else {
        conn.session.last_heartbeat_ms = now;
    }

    const active_tasks = conn.session.worker_active_tasks;
    const queued_tasks = conn.session.worker_queue_depth;
    if (queued_tasks == 0 and active_tasks == 0) return;
    if (conn.session.last_goal.len == 0) return;
    const dropped_tasks = conn.session.worker_dropped_tasks;

    if (dropped_tasks > 0 and
        !conn.session.worker_backpressure_notified and
        conn.session.worker_last_saturation_ms > 0 and
        (now - conn.session.worker_last_saturation_ms) >= WORKER_BACKPRESSURE_WARNING_MS)
    {
        const alert_message = try std.fmt.allocPrint(
            allocator,
            "Backpressure persisted for the last {d}ms; {d} dropped tasks were deferred on prior dispatch.",
            .{ now - conn.session.worker_last_saturation_ms, dropped_tasks },
        );
        defer allocator.free(alert_message);
        conn.session.worker_backpressure_notified = true;
        const accepted = queued_tasks + active_tasks;
        try sendAgentProgressWithBackpressure(
            allocator,
            &conn.write_buf,
            request_id,
            conn.session.session_id,
            "planner",
            "prolonged_saturation",
            alert_message,
            accepted,
            accepted + dropped_tasks,
            dropped_tasks,
            queued_tasks,
            active_tasks,
        );
    }

    if (conn.session.worker_mode == .cancelled) return;

    if (conn.session.worker_mode == .paused) {
        const status = "blocked";
        const message = try std.fmt.allocPrint(
            allocator,
            "Heartbeat detected {d} queued and {d} active tasks are blocked by pause state.",
            .{ queued_tasks, active_tasks },
        );
        defer allocator.free(message);
        try sendAgentProgress(
            allocator,
            &conn.write_buf,
            request_id,
            conn.session.session_id,
            "heartbeat",
            status,
            message,
        );
        return;
    }

    const message = try std.fmt.allocPrint(
        allocator,
        "Heartbeat status: {d} queued + {d} active worker tasks remain for the current goal.",
        .{ queued_tasks, active_tasks },
    );
    defer allocator.free(message);
    try sendAgentProgress(
        allocator,
        &conn.write_buf,
        request_id,
        conn.session.session_id,
        "heartbeat",
        "watching",
        message,
    );
}

fn memoryManagerActiveThreshold(max_messages: usize) usize {
    if (max_messages == 0) return 1;
    if (max_messages < MEMORY_MANAGER_SUMMARY_TRIGGER_DEN) return 1;
    const threshold = (max_messages * MEMORY_MANAGER_SUMMARY_TRIGGER_NUM) / MEMORY_MANAGER_SUMMARY_TRIGGER_DEN;
    return if (threshold == 0) 1 else threshold;
}

fn shouldRunMemoryManagement(ram: *const memory.RamContext, trigger_count: usize) bool {
    if (ram.total_message_bytes > ram.max_bytes) return true;

    var active_count: usize = 0;
    for (ram.entries.items) |entry| {
        if (entry.state == .active) active_count += 1;
    }

    return active_count > trigger_count;
}

fn processAiStreaming(
    allocator: std.mem.Allocator,
    state: *ServerState,
    conn: *Connection,
    request_id: []const u8,
    is_planned_goal: bool,
) !void {
    // Check if connection is already closing
    if (conn.closing.load(.acquire)) {
        std.log.warn("AI Task skipped: connection closing session={s} request={s}", .{
            conn.session.session_id,
            request_id,
        });
        return error.ConnectionClosed;
    }

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
    if (is_planned_goal) {
        if (conn.closing.load(.acquire)) return error.ConnectionClosed;
        try sendAgentProgress(allocator, &conn.write_buf, request_id, conn.session.session_id, "execution", "started", "Primary Brain invoking model");
    }

    const base_messages = try conn.session.contextMessages(allocator);
    var context_messages = base_messages;
    var owned_context: ?[]ziggy_piai.types.Message = null;
    if (conn.session.identity_prompt.len > 0) {
        const merged = try allocator.alloc(ziggy_piai.types.Message, base_messages.len + 1);
        merged[0] = .{
            .role = .system,
            .content = try allocator.dupe(u8, conn.session.identity_prompt),
        };
        if (base_messages.len > 0) {
            @memcpy(merged[1..], base_messages);
        }
        context_messages = merged;
        owned_context = merged;
    }
    defer {
        if (owned_context) |context| {
            freeContextMessages(allocator, context);
            allocator.free(base_messages);
        } else {
            freeContextMessages(allocator, base_messages);
        }
    }

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

    try streamByModelFn(allocator, &state.http_client, &state.api_registry, model.?, context, .{ .api_key = api_key }, &events);
    std.log.info("AI stream started: session={s} request={s}", .{ conn.session.session_id, request_id });

    var response_text = std.ArrayListUnmanaged(u8){};
    defer response_text.deinit(allocator);

    var response_sent = false;
    var execution_completed = false;
    for (events.items) |event| {
        // Check if connection closed before processing each event
        if (conn.closing.load(.acquire)) {
            std.log.warn("AI Task: connection closed mid-stream session={s} request={s}", .{
                conn.session.session_id,
                request_id,
            });
            return error.ConnectionClosed;
        }

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
                try sendSessionReceiveDirect(allocator, conn, request_id, final_text, assistant_msg_id);
                response_sent = true;
                execution_completed = true;
            },
            .err => |err_msg| {
                std.log.err("Pi AI error: {s} session={s} request={s}", .{ err_msg, conn.session.session_id, request_id });
                try sendErrorJson(allocator, &conn.write_buf, err_msg);
            },
            else => {},
        }
    }

    if (!response_sent and response_text.items.len > 0) {
        if (conn.closing.load(.acquire)) return error.ConnectionClosed;
        const assistant_msg_id = try conn.session.appendMessage(allocator, .assistant, response_text.items);
        try sendSessionReceiveDirect(allocator, conn, request_id, response_text.items, assistant_msg_id);
        execution_completed = true;
    }

    if (is_planned_goal) {
        if (conn.closing.load(.acquire)) return error.ConnectionClosed;
        if (execution_completed) {
            try sendAgentProgress(allocator, &conn.write_buf, request_id, conn.session.session_id, "execution", "complete", "Primary Brain response emitted");
        } else {
            try sendAgentProgress(allocator, &conn.write_buf, request_id, conn.session.session_id, "execution", "failed", "Primary Brain produced no assistant output");
        }
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

fn sendAgentProgress(
    allocator: std.mem.Allocator,
    write_buf: *std.ArrayListUnmanaged(u8),
    request_id: []const u8,
    session_id: []const u8,
    phase: []const u8,
    status: []const u8,
    message: []const u8,
) !void {
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const escaped_session_id = try protocol.jsonEscape(allocator, session_id);
    defer allocator.free(escaped_session_id);
    const escaped_phase = try protocol.jsonEscape(allocator, phase);
    defer allocator.free(escaped_phase);
    const escaped_status = try protocol.jsonEscape(allocator, status);
    defer allocator.free(escaped_status);
    const escaped_message = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.progress\",\"request\":\"{s}\",\"sessionKey\":\"{s}\",\"phase\":\"{s}\",\"status\":\"{s}\",\"message\":\"{s}\"}}",
        .{ escaped_request_id, escaped_session_id, escaped_phase, escaped_status, escaped_message },
    );
    defer allocator.free(payload);

    try appendWsFrame(allocator, write_buf, payload, .text);
}

fn sendAgentProgressWithBackpressure(
    allocator: std.mem.Allocator,
    write_buf: *std.ArrayListUnmanaged(u8),
    request_id: []const u8,
    session_id: []const u8,
    phase: []const u8,
    status: []const u8,
    message: []const u8,
    accepted: usize,
    total: usize,
    dropped: usize,
    queued: usize,
    active: usize,
) !void {
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const escaped_session_id = try protocol.jsonEscape(allocator, session_id);
    defer allocator.free(escaped_session_id);
    const escaped_phase = try protocol.jsonEscape(allocator, phase);
    defer allocator.free(escaped_phase);
    const escaped_status = try protocol.jsonEscape(allocator, status);
    defer allocator.free(escaped_status);
    const escaped_message = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.progress\",\"request\":\"{s}\",\"sessionKey\":\"{s}\",\"phase\":\"{s}\",\"status\":\"{s}\",\"message\":\"{s}\",\"accepted\":{d},\"total\":{d},\"dropped\":{d},\"queued\":{d},\"active\":{d}}}",
        .{
            escaped_request_id,
            escaped_session_id,
            escaped_phase,
            escaped_status,
            escaped_message,
            accepted,
            total,
            dropped,
            queued,
            active,
        },
    );
    defer allocator.free(payload);

    try appendWsFrame(allocator, write_buf, payload, .text);
}

fn workerModeLabel(mode: WorkerControlMode) []const u8 {
    return switch (mode) {
        .running => "workers.running",
        .paused => "workers.paused",
        .cancelled => "workers.cancelled",
    };
}

fn workerModeName(mode: WorkerControlMode) []const u8 {
    return switch (mode) {
        .running => "running",
        .paused => "paused",
        .cancelled => "cancelled",
    };
}

fn handleAgentList(
    allocator: std.mem.Allocator,
    state: *ServerState,
    conn: *Connection,
    request_id: []const u8,
) !void {
    const agents = state.agent_registry.listAgents();

    var json = std.ArrayListUnmanaged(u8){};
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "{\"type\":\"agent.list.response\",\"request\":\"");
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    try json.appendSlice(allocator, escaped_request_id);
    try json.appendSlice(allocator, "\",\"agents\":[");

    for (agents, 0..) |agent, idx| {
        if (idx > 0) try json.appendSlice(allocator, ",");

        const escaped_id = try protocol.jsonEscape(allocator, agent.id);
        defer allocator.free(escaped_id);
        const escaped_name = try protocol.jsonEscape(allocator, agent.name);
        defer allocator.free(escaped_name);
        const escaped_desc = try protocol.jsonEscape(allocator, agent.description);
        defer allocator.free(escaped_desc);

        try json.appendSlice(allocator, "{\"id\":\"");
        try json.appendSlice(allocator, escaped_id);
        try json.appendSlice(allocator, "\",\"name\":\"");
        try json.appendSlice(allocator, escaped_name);
        try json.appendSlice(allocator, "\",\"description\":\"");
        try json.appendSlice(allocator, escaped_desc);
        try json.appendSlice(allocator, "\",\"is_default\":");
        try json.appendSlice(allocator, if (agent.is_default) "true" else "false");
        try json.appendSlice(allocator, ",\"identity_loaded\":");
        try json.appendSlice(allocator, if (agent.identity_loaded) "true" else "false");
        try json.appendSlice(allocator, "}");
    }

    try json.appendSlice(allocator, "]}");

    try sendDirect(allocator, conn, json.items);
}

fn handleAgentGet(
    allocator: std.mem.Allocator,
    state: *ServerState,
    conn: *Connection,
    request_id: []const u8,
    agent_id: ?[]const u8,
) !void {
    const agent = if (agent_id) |id|
        state.agent_registry.getAgent(id) orelse state.agent_registry.getDefaultAgent()
    else
        state.agent_registry.getDefaultAgent();

    if (agent == null) {
        try sendErrorJsonDirect(allocator, conn, "No agents available");
        return;
    }

    const a = agent.?;

    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const escaped_id = try protocol.jsonEscape(allocator, a.id);
    defer allocator.free(escaped_id);
    const escaped_name = try protocol.jsonEscape(allocator, a.name);
    defer allocator.free(escaped_name);
    const escaped_desc = try protocol.jsonEscape(allocator, a.description);
    defer allocator.free(escaped_desc);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.info\",\"request\":\"{s}\",\"agent\":{{\"id\":\"{s}\",\"name\":\"{s}\",\"description\":\"{s}\",\"is_default\":{s},\"identity_loaded\":{s}}}}}",
        .{
            escaped_request_id,
            escaped_id,
            escaped_name,
            escaped_desc,
            if (a.is_default) "true" else "false",
            if (a.identity_loaded) "true" else "false",
        },
    );
    defer allocator.free(payload);

    try sendDirect(allocator, conn, payload);
}

fn sendErrorJsonDirect(
    allocator: std.mem.Allocator,
    conn: *Connection,
    message: []const u8,
) !void {
    const escaped = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped);

    const payload = try std.fmt.allocPrint(allocator, "{{\"type\":\"error\",\"message\":\"{s}\"}}", .{escaped});
    defer allocator.free(payload);

    try sendDirect(allocator, conn, payload);
}

fn handleSessionRestore(
    allocator: std.mem.Allocator,
    state: *ServerState,
    conn: *Connection,
    request_id: []const u8,
    agent_id: []const u8,
) !void {
    if (state.ltm_store) |*store| {
        const session = store.getLastActiveSession(agent_id) catch |err| {
            std.log.err("Failed to get last active session: {s}", .{@errorName(err)});
            try sendErrorJsonDirect(allocator, conn, "Failed to retrieve session");
            return;
        };

        if (session) |s| {
            defer {
                var mutable = s;
                mutable.deinit(allocator);
            }

            const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
            defer allocator.free(escaped_request_id);
            const escaped_session_id = try protocol.jsonEscape(allocator, s.session_id);
            defer allocator.free(escaped_session_id);
            const escaped_agent_id = try protocol.jsonEscape(allocator, s.agent_id);
            defer allocator.free(escaped_agent_id);
            const escaped_summary = if (s.summary) |sum|
                try protocol.jsonEscape(allocator, sum)
            else
                try allocator.dupe(u8, "");
            defer if (s.summary != null) allocator.free(escaped_summary);

            const payload = try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"session.restore.response\",\"request\":\"{s}\",\"found\":true,\"session\":{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"last_active_ms\":{d},\"message_count\":{d},\"summary\":\"{s}\"}}}}",
                .{
                    escaped_request_id,
                    escaped_session_id,
                    escaped_agent_id,
                    s.last_active_ms,
                    s.message_count,
                    escaped_summary,
                },
            );
            defer allocator.free(payload);

            try sendDirect(allocator, conn, payload);
        } else {
            const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
            defer allocator.free(escaped_request_id);

            const payload = try std.fmt.allocPrint(
                allocator,
                "{{\"type\":\"session.restore.response\",\"request\":\"{s}\",\"found\":false}}",
                .{escaped_request_id},
            );
            defer allocator.free(payload);

            try sendDirect(allocator, conn, payload);
        }
    } else {
        try sendErrorJsonDirect(allocator, conn, "LTM store not available");
    }
}

fn handleSessionHistory(
    allocator: std.mem.Allocator,
    state: *ServerState,
    conn: *Connection,
    request_id: []const u8,
    agent_id: []const u8,
    limit: usize,
) !void {
    if (state.ltm_store) |*store| {
        var sessions = store.listRecentSessions(agent_id, limit) catch |err| {
            std.log.err("Failed to list recent sessions: {s}", .{@errorName(err)});
            try sendErrorJsonDirect(allocator, conn, "Failed to retrieve session history");
            return;
        };
        defer {
            for (sessions.items) |*s| {
                s.deinit(allocator);
            }
            sessions.deinit(allocator);
        }

        var json = std.ArrayListUnmanaged(u8){};
        defer json.deinit(allocator);

        try json.appendSlice(allocator, "{\"type\":\"session.history.response\",\"request\":\"");
        const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
        defer allocator.free(escaped_request_id);
        try json.appendSlice(allocator, escaped_request_id);
        try json.appendSlice(allocator, "\",\"sessions\":[");

        for (sessions.items, 0..) |session, idx| {
            if (idx > 0) try json.appendSlice(allocator, ",");

            const escaped_session_id = try protocol.jsonEscape(allocator, session.session_id);
            defer allocator.free(escaped_session_id);
            const escaped_summary = if (session.summary) |sum|
                try protocol.jsonEscape(allocator, sum)
            else
                try allocator.dupe(u8, "");
            defer if (session.summary != null) allocator.free(escaped_summary);

            try json.appendSlice(allocator, "{\"session_key\":\"");
            try json.appendSlice(allocator, escaped_session_id);
            try json.appendSlice(allocator, "\",\"last_active_ms\":");
            const last_active = try std.fmt.allocPrint(allocator, "{d}", .{session.last_active_ms});
            defer allocator.free(last_active);
            try json.appendSlice(allocator, last_active);
            try json.appendSlice(allocator, ",\"message_count\":");
            const msg_count = try std.fmt.allocPrint(allocator, "{d}", .{session.message_count});
            defer allocator.free(msg_count);
            try json.appendSlice(allocator, msg_count);
            try json.appendSlice(allocator, ",\"summary\":\"");
            try json.appendSlice(allocator, escaped_summary);
            try json.appendSlice(allocator, "\"}");
        }

        try json.appendSlice(allocator, "]}");

        try sendDirect(allocator, conn, json.items);
    } else {
        try sendErrorJsonDirect(allocator, conn, "LTM store not available");
    }
}

fn sendAgentState(
    allocator: std.mem.Allocator,
    write_buf: *std.ArrayListUnmanaged(u8),
    request_id: []const u8,
    session_id: []const u8,
    phase: []const u8,
    queued_tasks: usize,
    active_tasks: usize,
    last_goal: []const u8,
) !void {
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const escaped_session_id = try protocol.jsonEscape(allocator, session_id);
    defer allocator.free(escaped_session_id);
    const escaped_phase = try protocol.jsonEscape(allocator, phase);
    defer allocator.free(escaped_phase);
    const escaped_last_goal = try protocol.jsonEscape(allocator, last_goal);
    defer allocator.free(escaped_last_goal);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.state\",\"request\":\"{s}\",\"sessionKey\":\"{s}\",\"phase\":\"{s}\",\"queuedTasks\":{d},\"activeTasks\":{d},\"lastGoal\":\"{s}\"}}",
        .{ escaped_request_id, escaped_session_id, escaped_phase, queued_tasks, active_tasks, escaped_last_goal },
    );
    defer allocator.free(payload);

    try appendWsFrame(allocator, write_buf, payload, .text);
}

fn sendMemoryEvent(
    allocator: std.mem.Allocator,
    write_buf: *std.ArrayListUnmanaged(u8),
    request_id: []const u8,
    session_id: []const u8,
    event: []const u8,
    status: []const u8,
    count: usize,
    message: []const u8,
) !void {
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const escaped_session_id = try protocol.jsonEscape(allocator, session_id);
    defer allocator.free(escaped_session_id);
    const escaped_event = try protocol.jsonEscape(allocator, event);
    defer allocator.free(escaped_event);
    const escaped_status = try protocol.jsonEscape(allocator, status);
    defer allocator.free(escaped_status);
    const escaped_message = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"memory.event\",\"request\":\"{s}\",\"sessionKey\":\"{s}\",\"event\":\"{s}\",\"status\":\"{s}\",\"count\":{d},\"message\":\"{s}\"}}",
        .{ escaped_request_id, escaped_session_id, escaped_event, escaped_status, count, escaped_message },
    );
    defer allocator.free(payload);

    try appendWsFrame(allocator, write_buf, payload, .text);
}

fn sendAgentStatus(
    allocator: std.mem.Allocator,
    write_buf: *std.ArrayListUnmanaged(u8),
    request_id: []const u8,
    session_id: []const u8,
    task_id: usize,
    worker: []const u8,
    status: []const u8,
    message: []const u8,
) !void {
    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const escaped_session_id = try protocol.jsonEscape(allocator, session_id);
    defer allocator.free(escaped_session_id);
    const escaped_worker = try protocol.jsonEscape(allocator, worker);
    defer allocator.free(escaped_worker);
    const escaped_status = try protocol.jsonEscape(allocator, status);
    defer allocator.free(escaped_status);
    const escaped_message = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.status\",\"request\":\"{s}\",\"sessionKey\":\"{s}\",\"taskId\":{d},\"worker\":\"{s}\",\"status\":\"{s}\",\"message\":\"{s}\"}}",
        .{ escaped_request_id, escaped_session_id, task_id, escaped_worker, escaped_status, escaped_message },
    );
    defer allocator.free(payload);

    try appendWsFrame(allocator, write_buf, payload, .text);
}

fn sendAgentPlan(
    allocator: std.mem.Allocator,
    write_buf: *std.ArrayListUnmanaged(u8),
    request_id: []const u8,
    session_id: []const u8,
    goal: []const u8,
    tasks: std.ArrayListUnmanaged([]const u8),
) !void {
    var payload = std.ArrayListUnmanaged(u8){};
    defer payload.deinit(allocator);

    const escaped_request_id = try protocol.jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const escaped_session_id = try protocol.jsonEscape(allocator, session_id);
    defer allocator.free(escaped_session_id);
    const escaped_goal = try protocol.jsonEscape(allocator, goal);
    defer allocator.free(escaped_goal);

    try payload.appendSlice(allocator, "{\"type\":\"agent.plan\",\"request\":\"");
    try payload.appendSlice(allocator, escaped_request_id);
    try payload.appendSlice(allocator, "\",\"sessionKey\":\"");
    try payload.appendSlice(allocator, escaped_session_id);
    try payload.appendSlice(allocator, "\",\"goal\":\"");
    try payload.appendSlice(allocator, escaped_goal);
    try payload.appendSlice(allocator, "\",\"tasks\":[");

    for (tasks.items, 0..) |task, idx| {
        if (idx > 0) try payload.appendSlice(allocator, ",");
        const escaped_task = try protocol.jsonEscape(allocator, task);
        defer allocator.free(escaped_task);

        const item = try std.fmt.allocPrint(
            allocator,
            "{{\"id\":{d},\"title\":\"{s}\",\"status\":\"queued\"}}",
            .{ idx + 1, escaped_task },
        );
        defer allocator.free(item);
        try payload.appendSlice(allocator, item);
    }

    try payload.appendSlice(allocator, "]}");
    try appendWsFrame(allocator, write_buf, payload.items, .text);
}

const MemoryQueryKind = enum { all, summary, entry };

fn handleMemoryQuery(
    state: *ServerState,
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
        var used_store = false;
        if (state.ltm_store) |*store| {
            const appended = appendLatestStoreSnapshotToQuery(
                allocator,
                &emitted,
                store,
                conn.session.session_id,
                &first_item,
                &remaining,
                topic,
                query_ids,
                kind_filter,
            ) catch |err| blk: {
                std.log.warn("LTM store query fallback failed: {s} session={s}", .{ @errorName(err), conn.session.session_id });
                break :blk false;
            };
            if (appended) {
                used_store = appended;
            }
        }

        if (!used_store) {
            const archive = findLatestArchiveForSessionJson(allocator, conn.session.session_id) catch null;
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

fn containsMemoryId(ids: []const memory.MemoryID, id: memory.MemoryID) bool {
    for (ids) |candidate| {
        if (candidate == id) return true;
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
                    const created_at_ms = if (summary_obj.get("created_at_ms")) |ts| (parseCreatedAtMs(ts) orelse 0) else 0;

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
    state: *ServerState,
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
        var used_store = false;
        if (state.ltm_store) |*store| {
            const appended = appendLatestStoreSnapshotToRecall(
                allocator,
                &emitted,
                store,
                conn.session.session_id,
                &first_item,
                &remaining,
                include_full_from_archive,
            ) catch |err| blk: {
                std.log.warn("LTM store recall fallback failed: {s} session={s}", .{ @errorName(err), conn.session.session_id });
                break :blk false;
            };
            if (appended) {
                used_store = appended;
            }
        }

        if (!used_store) {
            const archive = findLatestArchiveForSessionJson(allocator, conn.session.session_id) catch null;
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
    }

    try emitted.appendSlice(allocator, "]}");
    try appendWsFrame(allocator, &conn.write_buf, emitted.items, .text);
}

fn appendLatestStoreSnapshotToRecall(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    store: *ltm_store.Store,
    session_id: []const u8,
    first_item: *bool,
    remaining: *usize,
    include_full_from_archive: bool,
) !bool {
    var snapshots = try store.loadSnapshotsForSession(session_id, null);
    defer {
        for (snapshots.items) |*snapshot| snapshot.deinit(allocator);
        snapshots.deinit(allocator);
    }
    if (snapshots.items.len == 0) return false;

    var seen_summary_ids = std.ArrayListUnmanaged(memory.MemoryID){};
    defer seen_summary_ids.deinit(allocator);
    var seen_entry_ids = std.ArrayListUnmanaged(memory.MemoryID){};
    defer seen_entry_ids.deinit(allocator);

    for (snapshots.items) |snapshot| {
        if (remaining.* == 0) break;
        for (snapshot.summaries.items) |summary| {
            if (remaining.* == 0) break;
            if (containsMemoryId(seen_summary_ids.items, summary.id)) continue;
            try seen_summary_ids.append(allocator, summary.id);

            try appendRecallSummaryItem(
                allocator,
                out,
                first_item,
                "summary",
                "ltm",
                summary.id,
                summary.source_id,
                summary.text,
                summary.created_at_ms,
            );
            remaining.* -= 1;
        }

        if (!include_full_from_archive or remaining.* == 0) {
            continue;
        }

        for (snapshot.entries.items) |entry| {
            if (remaining.* == 0) break;
            if (containsMemoryId(seen_entry_ids.items, entry.id)) continue;
            const role = parseRole(entry.role) orelse continue;

            try seen_entry_ids.append(allocator, entry.id);
            try appendRecallEntryItem(
                allocator,
                out,
                first_item,
                "entry",
                "ltm",
                entry.state,
                role,
                entry.id,
                entry.related_to,
                entry.content,
            );
            remaining.* -= 1;
        }
    }

    return true;
}

fn appendLatestStoreSnapshotToQuery(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    store: *ltm_store.Store,
    session_id: []const u8,
    first_item: *bool,
    remaining: *usize,
    topic: ?[]const u8,
    query_ids: []const memory.MemoryID,
    kind_filter: MemoryQueryKind,
) !bool {
    var snapshots = try store.loadSnapshotsForSession(session_id, null);
    defer {
        for (snapshots.items) |*snapshot| snapshot.deinit(allocator);
        snapshots.deinit(allocator);
    }
    if (snapshots.items.len == 0) return false;

    var seen_summary_ids = std.ArrayListUnmanaged(memory.MemoryID){};
    defer seen_summary_ids.deinit(allocator);
    var seen_entry_ids = std.ArrayListUnmanaged(memory.MemoryID){};
    defer seen_entry_ids.deinit(allocator);

    for (snapshots.items) |snapshot| {
        if (remaining.* == 0) break;
        if (kind_filter != .entry) {
            for (snapshot.summaries.items) |summary| {
                if (remaining.* == 0) break;
                if (containsMemoryId(seen_summary_ids.items, summary.id)) continue;
                if (!queryMatchesId(summary.id, query_ids)) continue;
                if (!queryMatchesTopic(summary.text, topic)) continue;

                try seen_summary_ids.append(allocator, summary.id);
                try appendRecallSummaryItem(
                    allocator,
                    out,
                    first_item,
                    "summary",
                    "ltm",
                    summary.id,
                    summary.source_id,
                    summary.text,
                    summary.created_at_ms,
                );
                remaining.* -= 1;
            }
        }

        if (kind_filter != .summary and remaining.* > 0) {
            for (snapshot.entries.items) |entry| {
                if (remaining.* == 0) break;
                if (containsMemoryId(seen_entry_ids.items, entry.id)) continue;
                if (!queryMatchesId(entry.id, query_ids)) continue;
                if (!queryMatchesTopic(entry.content, topic)) continue;
                const role = parseRole(entry.role) orelse continue;

                try seen_entry_ids.append(allocator, entry.id);
                try appendRecallEntryItem(
                    allocator,
                    out,
                    first_item,
                    "entry",
                    "ltm",
                    entry.state,
                    role,
                    entry.id,
                    entry.related_to,
                    entry.content,
                );
                remaining.* -= 1;
            }
        }
    }

    return true;
}

const LatestArchiveRef = struct {
    timestamp_ms: i64,
    reason: []u8,
    archive_path: []u8,
};

fn findLatestArchiveForSessionJson(
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
            const created_at_ms = if (summary_obj.get("created_at_ms")) |ts| (parseCreatedAtMs(ts) orelse 0) else 0;

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
    state: *ServerState,
    session: *SessionContext,
    session_id: []const u8,
) !bool {
    if (state.ltm_store) |*store| {
        if (restoreSessionFromLatestDbSnapshot(allocator, store, session, session_id) catch false) {
            return true;
        }
    }
    return restoreSessionFromLatestArchiveJson(allocator, session, session_id);
}

fn restoreSessionFromLatestDbSnapshot(
    allocator: std.mem.Allocator,
    store: *ltm_store.Store,
    session: *SessionContext,
    session_id: []const u8,
) !bool {
    var snapshot = try store.loadLatestSnapshot(session_id) orelse return false;
    defer snapshot.deinit(allocator);

    session.resetRam(allocator);
    try session.setSessionId(allocator, session_id);
    session.ram.setNextId(snapshot.snapshot.next_id);

    for (snapshot.summaries.items) |summary| {
        try session.ram.restoreSummary(summary.id, summary.source_id, summary.text, summary.created_at_ms);
    }

    var restored_entries = std.ArrayListUnmanaged(struct {
        id: memory.MemoryID,
        role: ziggy_piai.types.MessageRole,
        related_to: ?memory.MemoryID,
        content: []const u8,
    }){};
    defer restored_entries.deinit(allocator);

    var projected_bytes: usize = 0;
    for (snapshot.entries.items) |entry| {
        const role = parseRole(entry.role) orelse continue;
        const state = parseRamEntryState(entry.state) orelse continue;
        if (state != .active) continue;
        if (restored_entries.items.len >= MAX_CONTEXT_MESSAGES) continue;
        if (projected_bytes + entry.content.len > MAX_CONTEXT_BYTES) continue;

        try restored_entries.append(allocator, .{
            .id = entry.id,
            .role = role,
            .content = entry.content,
            .related_to = entry.related_to,
        });
        projected_bytes += entry.content.len;
    }

    var restore_index = restored_entries.items.len;
    while (restore_index > 0) {
        restore_index -= 1;
        const restored_entry = restored_entries.items[restore_index];
        try session.ram.restoreEntry(
            restored_entry.id,
            restored_entry.role,
            .active,
            restored_entry.related_to,
            restored_entry.content,
        );
    }

    return true;
}

fn restoreSessionFromLatestArchiveJson(
    allocator: std.mem.Allocator,
    session: *SessionContext,
    session_id: []const u8,
) !bool {
    const latest = try findLatestArchiveForSessionJson(allocator, session_id);
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
    state: *ServerState,
    allocator: std.mem.Allocator,
    conn: *Connection,
    archive_old_state: bool,
    reason: []const u8,
) !bool {
    var archived = false;

    if (archive_old_state) {
        archived = archiveSessionRamToLongTerm(state, allocator, &conn.session, reason) catch false;
    }

    conn.session.resetRam(allocator);
    conn.session.resetWorkerState(allocator);
    return archived;
}

fn archiveSessionRamToLongTerm(
    state: *ServerState,
    allocator: std.mem.Allocator,
    session: *SessionContext,
    reason: []const u8,
) !bool {
    if (state.ltm_store) |*store| {
        if (store.archiveRamSnapshot(session.session_id, reason, &session.ram) catch |err| blk: {
            std.log.warn("LTM sqlite archive failed, falling back to JSON archive: {s} session={s}", .{ @errorName(err), session.session_id });
            break :blk false;
        }) {
            return true;
        }
    }

    return archiveSessionRamToLegacyJson(allocator, session, reason);
}

fn archiveSessionRamToLegacyJson(
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
        if (session.worker_last_goal.len > 0) allocator.free(session.worker_last_goal);
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
            if (persisted.worker_last_goal.len > 0) allocator.free(persisted.worker_last_goal);
            persisted.worker_queue_depth = session.worker_queue_depth;
            persisted.worker_active_tasks = session.worker_active_tasks;
            persisted.worker_mode = session.worker_mode;
            persisted.worker_dropped_tasks = session.worker_dropped_tasks;
            persisted.worker_last_saturation_ms = session.worker_last_saturation_ms;
            persisted.worker_backpressure_notified = session.worker_backpressure_notified;
            persisted.worker_last_goal = if (session.last_goal.len > 0)
                try allocator.dupe(u8, session.last_goal)
            else
                &[_]u8{};
            return;
        }
    }

    var restored = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES);
    try copyRamContext(allocator, &session.ram, &restored);
    try persisted_sessions.append(allocator, .{
        .session_id = try allocator.dupe(u8, session.session_id),
        .ram = restored,
        .worker_queue_depth = session.worker_queue_depth,
        .worker_active_tasks = session.worker_active_tasks,
        .worker_mode = session.worker_mode,
        .worker_dropped_tasks = session.worker_dropped_tasks,
        .worker_last_saturation_ms = session.worker_last_saturation_ms,
        .worker_backpressure_notified = session.worker_backpressure_notified,
        .worker_last_goal = if (session.last_goal.len > 0)
            try allocator.dupe(u8, session.last_goal)
        else
            &[_]u8{},
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
        try writeFormatted(allocator, file, ",\"next_id\":{d}", .{session.ram.next_id});
        try writeFormatted(allocator, file, ",\"workerQueueDepth\":{d}", .{session.worker_queue_depth});
        try writeFormatted(allocator, file, ",\"workerActiveTasks\":{d}", .{session.worker_active_tasks});
        try writeFormatted(allocator, file, ",\"workerMode\":\"{s}\"", .{workerModeName(session.worker_mode)});
        try writeFormatted(allocator, file, ",\"workerDroppedTasks\":{d}", .{session.worker_dropped_tasks});
        try writeFormatted(allocator, file, ",\"workerLastSaturationMs\":{d}", .{session.worker_last_saturation_ms});
        try writeFormatted(allocator, file, ",\"workerBackpressureNotified\":{s}", .{if (session.worker_backpressure_notified) "true" else "false"});
        try file.writeAll(",\"workerLastGoal\":");
        try writeJsonEscaped(allocator, file, session.worker_last_goal);
        try file.writeAll(",\"entries\":[");

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

fn parseWorkerMode(text: []const u8) ?WorkerControlMode {
    if (std.mem.eql(u8, text, "running")) return .running;
    if (std.mem.eql(u8, text, "paused")) return .paused;
    if (std.mem.eql(u8, text, "cancelled")) return .cancelled;
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

fn parseRetentionKeepLimit(allocator: std.mem.Allocator) usize {
    if (std.process.getEnvVarOwned(allocator, LTM_RETENTION_KEEP_SNAPSHOTS_ENV)) |value| {
        defer allocator.free(value);
        const trimmed = std.mem.trim(u8, value, " \t");
        if (trimmed.len == 0) return LTM_RETENTION_MAX_SNAPSHOTS_DEFAULT;
        const limit = std.fmt.parseUnsigned(usize, trimmed, 10) catch {
            return LTM_RETENTION_MAX_SNAPSHOTS_DEFAULT;
        };
        if (limit == 0) return 0;
        return limit;
    } else |_| {}

    return LTM_RETENTION_MAX_SNAPSHOTS_DEFAULT;
}

fn parseRetentionMaxAgeMs(allocator: std.mem.Allocator) ?i64 {
    const days = std.process.getEnvVarOwned(allocator, LTM_RETENTION_KEEP_DAYS_ENV) catch null;
    defer if (days) |value| allocator.free(value);

    const keep_days = if (days) |value| blk: {
        const trimmed = std.mem.trim(u8, value, " \t");
        if (trimmed.len == 0) break :blk LTM_RETENTION_MAX_AGE_DAYS_DEFAULT;
        break :blk (std.fmt.parseUnsigned(u64, trimmed, 10) catch LTM_RETENTION_MAX_AGE_DAYS_DEFAULT);
    } else LTM_RETENTION_MAX_AGE_DAYS_DEFAULT;

    if (keep_days == 0) return null;

    return retentionCutoffFromDays(keep_days);
}

fn retentionCutoffFromDays(days: u64) ?i64 {
    const now_ms = std.time.milliTimestamp();
    if (now_ms <= 0) return null;
    const now_u = @as(u64, @intCast(now_ms));
    const max_age_ms_u = @as(u128, days) * @as(u128, 86_400_000);
    if (max_age_ms_u >= now_u) return 0;
    return @as(i64, @intCast(now_u - max_age_ms_u));
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
    if (version > SESSION_STATE_VERSION or version == 0) return sessions;

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

        const worker_queue_depth = if (session_obj.get("workerQueueDepth")) |value| parsePositiveInteger(value) orelse 0 else 0;
        const worker_active_tasks = if (session_obj.get("workerActiveTasks")) |value| parsePositiveInteger(value) orelse 0 else 0;
        const worker_mode = if (session_obj.get("workerMode")) |value|
            (if (value == .string) parseWorkerMode(value.string) orelse .running else .running)
        else
            .running;
        const worker_dropped_tasks = if (session_obj.get("workerDroppedTasks")) |value| parsePositiveInteger(value) orelse 0 else 0;
        const worker_last_saturation_ms = if (session_obj.get("workerLastSaturationMs")) |value|
            if (value == .integer) value.integer else 0
        else
            0;
        const worker_backpressure_notified = if (session_obj.get("workerBackpressureNotified")) |value|
            if (value == .bool) value.bool else false
        else
            false;
        const worker_last_goal = if (session_obj.get("workerLastGoal")) |value| if (value == .string) value.string else "" else "";

        try sessions.append(allocator, .{
            .session_id = try allocator.dupe(u8, session_id_value.string),
            .ram = context,
            .worker_queue_depth = worker_queue_depth,
            .worker_active_tasks = worker_active_tasks,
            .worker_mode = worker_mode,
            .worker_dropped_tasks = worker_dropped_tasks,
            .worker_last_saturation_ms = worker_last_saturation_ms,
            .worker_backpressure_notified = worker_backpressure_notified,
            .worker_last_goal = try allocator.dupe(u8, worker_last_goal),
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
        session.worker_queue_depth = recovered.worker_queue_depth;
        session.worker_active_tasks = recovered.worker_active_tasks;
        session.worker_mode = recovered.worker_mode;
        session.worker_dropped_tasks = recovered.worker_dropped_tasks;
        session.worker_last_saturation_ms = recovered.worker_last_saturation_ms;
        session.worker_backpressure_notified = recovered.worker_backpressure_notified;
        if (session.last_goal.len > 0) allocator.free(session.last_goal);
        session.last_goal = recovered.worker_last_goal;
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

test "server_piai: sendAgentProgress emits valid outbound agent.progress payload" {
    const allocator = std.testing.allocator;
    var write_buf = std.ArrayListUnmanaged(u8){};
    defer write_buf.deinit(allocator);

    try sendAgentProgress(
        allocator,
        &write_buf,
        "req-123",
        "session-abc",
        "planner",
        "ready",
        "Plan queued",
    );

    try std.testing.expect(write_buf.items.len > 2);
    try std.testing.expectEqual(@as(u8, 0x81), write_buf.items[0]);

    const json_start = std.mem.indexOf(u8, write_buf.items, "{") orelse unreachable;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, write_buf.items[json_start..], .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.progress"));
    try std.testing.expect(std.mem.eql(u8, obj.get("request").?.string, "req-123"));
    try std.testing.expect(std.mem.eql(u8, obj.get("sessionKey").?.string, "session-abc"));
    try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "planner"));
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "ready"));
    try std.testing.expect(std.mem.eql(u8, obj.get("message").?.string, "Plan queued"));
}

test "server_piai: sendAgentStatus emits valid outbound agent.status payload" {
    const allocator = std.testing.allocator;
    var write_buf = std.ArrayListUnmanaged(u8){};
    defer write_buf.deinit(allocator);

    try sendAgentStatus(
        allocator,
        &write_buf,
        "req-321",
        "session-xyz",
        2,
        "research",
        "complete",
        "research: found 3 items",
    );

    try std.testing.expect(write_buf.items.len > 2);
    try std.testing.expectEqual(@as(u8, 0x81), write_buf.items[0]);

    const json_start = std.mem.indexOf(u8, write_buf.items, "{") orelse unreachable;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, write_buf.items[json_start..], .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.status"));
    try std.testing.expect(std.mem.eql(u8, obj.get("request").?.string, "req-321"));
    try std.testing.expect(std.mem.eql(u8, obj.get("sessionKey").?.string, "session-xyz"));
    const task_id = obj.get("taskId").?.integer;
    try std.testing.expectEqual(@as(i64, 2), task_id);
    try std.testing.expect(std.mem.eql(u8, obj.get("worker").?.string, "research"));
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "complete"));
    try std.testing.expect(std.mem.eql(u8, obj.get("message").?.string, "research: found 3 items"));
}

test "server_piai: sendMemoryEvent emits valid outbound memory.event payload" {
    const allocator = std.testing.allocator;
    var write_buf = std.ArrayListUnmanaged(u8){};
    defer write_buf.deinit(allocator);

    try sendMemoryEvent(
        allocator,
        &write_buf,
        "req-500",
        "session-memory",
        "summarize",
        "summarized",
        3,
        "summarized stale RAM entries",
    );

    try std.testing.expect(write_buf.items.len > 2);
    try std.testing.expectEqual(@as(u8, 0x81), write_buf.items[0]);

    const json_start = std.mem.indexOf(u8, write_buf.items, "{") orelse unreachable;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, write_buf.items[json_start..], .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "memory.event"));
    try std.testing.expect(std.mem.eql(u8, obj.get("request").?.string, "req-500"));
    try std.testing.expect(std.mem.eql(u8, obj.get("sessionKey").?.string, "session-memory"));
    try std.testing.expect(std.mem.eql(u8, obj.get("event").?.string, "summarize"));
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "summarized"));
    try std.testing.expectEqual(@as(i64, 3), obj.get("count").?.integer);
    try std.testing.expect(std.mem.eql(u8, obj.get("message").?.string, "summarized stale RAM entries"));
}

test "server_piai: runMemoryManager summarizes overfull RAM and emits memory.event" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-memory-manager-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    for (0..70) |_| {
        _ = try conn.session.appendMessage(allocator, .user, "memory-manager input for backpressure smoke test");
    }

    try runMemoryManager(allocator, &state, &conn, "req-mm");

    const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "memory.event"));
    try std.testing.expect(std.mem.eql(u8, obj.get("event").?.string, "summarize"));
    try std.testing.expect(obj.get("count").?.integer > 0);
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "summarized"));
}

test "server_piai: runHeartbeatCheck emits heartbeat progress for running backlog" {
    const allocator = std.testing.allocator;

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    try conn.session.setSessionId(allocator, "session-heartbeat-1");
    try conn.session.setLastGoal(allocator, "summarize findings from logs");
    conn.session.worker_queue_depth = 2;
    conn.session.worker_active_tasks = 1;
    conn.session.last_heartbeat_ms = std.time.milliTimestamp() - HEARTBEAT_INTERVAL_MS - 10;
    conn.session.setWorkerMode(.running);

    try runHeartbeatCheck(allocator, &conn, "req-heartbeat", false);

    const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.progress"));
    try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "heartbeat"));
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "watching"));
}

test "server_piai: runHeartbeatCheck emits prolonged saturation progress after warning period" {
    const allocator = std.testing.allocator;

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    const now = std.time.milliTimestamp();
    try conn.session.setSessionId(allocator, "session-heartbeat-saturation-1");
    try conn.session.setLastGoal(allocator, "replay dropped plan tasks");
    conn.session.worker_queue_depth = 4;
    conn.session.worker_active_tasks = 1;
    conn.session.worker_dropped_tasks = 3;
    conn.session.worker_last_saturation_ms = now - WORKER_BACKPRESSURE_WARNING_MS - 250;
    conn.session.last_heartbeat_ms = now - HEARTBEAT_INTERVAL_MS - 10;

    try runHeartbeatCheck(allocator, &conn, "req-heartbeat", false);

    const payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    var saw_prolonged_saturation = false;
    var saw_watching = false;
    for (payloads.items) |payload| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        const message_type = obj.get("type") orelse continue;
        if (!std.mem.eql(u8, message_type.string, "agent.progress")) continue;
        const phase = obj.get("phase") orelse continue;
        if (std.mem.eql(u8, phase.string, "planner")) {
            const status = obj.get("status") orelse continue;
            if (std.mem.eql(u8, status.string, "prolonged_saturation")) {
                saw_prolonged_saturation = true;
                const accepted = obj.get("accepted").?.integer;
                const total = obj.get("total").?.integer;
                const dropped = obj.get("dropped").?.integer;
                const queued = obj.get("queued").?.integer;
                const active = obj.get("active").?.integer;
                try std.testing.expectEqual(@as(i64, 5), accepted);
                try std.testing.expectEqual(@as(i64, 8), total);
                try std.testing.expectEqual(@as(i64, 3), dropped);
                try std.testing.expectEqual(@as(i64, 4), queued);
                try std.testing.expectEqual(@as(i64, 1), active);
            }
            continue;
        }
        if (std.mem.eql(u8, phase.string, "heartbeat")) {
            saw_watching = true;
        }
    }

    try std.testing.expect(saw_prolonged_saturation);
    try std.testing.expect(saw_watching);
}

test "server_piai: agent.control heartbeat action emits heartbeat progress" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    try conn.session.setSessionId(allocator, "session-heartbeat-control-1");
    try conn.session.setLastGoal(allocator, "follow up on pending tasks");
    conn.session.worker_queue_depth = 3;
    conn.session.worker_active_tasks = 1;
    conn.session.setWorkerMode(.paused);
    conn.session.last_heartbeat_ms = 0;

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-hb-002\",\"type\":\"agent.control\",\"action\":\"heartbeat\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }

    const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.progress"));
    try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "heartbeat"));
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "blocked"));
}

test "server_piai: heartbeat sweep emits heartbeat progress for websocket sessions with backlog" {
    const allocator = std.testing.allocator;

    var connections = std.AutoHashMap(posix.socket_t, *Connection).init(allocator);
    defer connections.deinit();

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    conn.state = .websocket;
    try conn.session.setSessionId(allocator, "session-heartbeat-sweep-1");
    try conn.session.setLastGoal(allocator, "periodic progress check");
    conn.session.worker_queue_depth = 2;
    conn.session.worker_active_tasks = 1;
    conn.session.last_heartbeat_ms = std.time.milliTimestamp() - HEARTBEAT_INTERVAL_MS - 10;

    try connections.put(0, &conn);
    runHeartbeatSweep(allocator, &connections);

    const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.progress"));
    try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "heartbeat"));
}

fn decodeFirstWebSocketPayload(frame_data: []const u8) ![]const u8 {
    if (frame_data.len < 2) return error.InvalidFrame;

    const mask_and_len = frame_data[1];
    var payload_len = @as(usize, mask_and_len & 0x7F);
    var header_len: usize = 2;

    if (payload_len == 126) {
        if (frame_data.len < 4) return error.InvalidFrame;
        payload_len = std.mem.readInt(u16, frame_data[2..4], .big);
        header_len = 4;
    } else if (payload_len == 127) {
        if (frame_data.len < 10) return error.InvalidFrame;
        payload_len = @intCast(std.mem.readInt(u64, frame_data[2..10], .big));
        header_len = 10;
    }

    if (frame_data.len < header_len + payload_len) return error.InvalidFrame;
    return frame_data[header_len .. header_len + payload_len];
}

fn collectWebSocketPayloads(
    allocator: std.mem.Allocator,
    frame_data: []const u8,
) !std.ArrayListUnmanaged([]const u8) {
    var payloads = std.ArrayListUnmanaged([]const u8){};
    var idx: usize = 0;
    while (idx < frame_data.len) {
        if (frame_data.len - idx < 2) return error.InvalidFrame;

        const mask_and_len = frame_data[idx + 1];
        var payload_len = @as(usize, mask_and_len & 0x7F);
        var header_len: usize = 2;

        if (payload_len == 126) {
            if (frame_data.len - idx < 4) return error.InvalidFrame;
            payload_len = std.mem.readInt(u16, frame_data[idx + 2 .. idx + 4], .big);
            header_len = 4;
        } else if (payload_len == 127) {
            if (frame_data.len - idx < 10) return error.InvalidFrame;
            payload_len = @intCast(std.mem.readInt(u64, frame_data[idx + 2 .. idx + 10], .big));
            header_len = 10;
        }

        const frame_end = idx + header_len + payload_len;
        if (frame_end > frame_data.len) return error.InvalidFrame;

        try payloads.append(allocator, try allocator.dupe(u8, frame_data[idx + header_len .. frame_end]));
        idx = frame_end;
    }
    return payloads;
}

fn buildMaskedTextFrame(
    allocator: std.mem.Allocator,
    payload: []const u8,
    mask_key: [4]u8,
) ![]u8 {
    if (payload.len >= 126) return error.InvalidFrame;
    const frame_len = 2 + 4 + payload.len;
    var frame = try allocator.alloc(u8, frame_len);
    frame[0] = 0x81;
    frame[1] = 0x80 | @as(u8, @truncate(payload.len));
    @memcpy(frame[2..6], &mask_key);
    for (payload, 0..) |value, i| {
        frame[6 + i] = value ^ mask_key[i % 4];
    }
    return frame;
}

fn mockStreamByModel(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) !void {
    _ = allocator;
    try events.append(.{
        .text_delta = .{ .content_index = 0, .delta = "mock " },
    });
    try events.append(.{
        .done = .{
            .text = "mocked model reply",
            .api = "mock-api",
            .provider = "openai",
            .model = "gpt-4o-mini",
            .usage = .{ .total_tokens = 5 },
        },
    });
}

fn mockStreamByModelError(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) !void {
    _ = allocator;
    try events.append(.{
        .err = "mock stream unavailable",
    });
}

test "server_piai: handshake restores persisted session context on matching session key" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    var restored_ram = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES);
    _ = try restored_ram.update(.user, "restored content");

    var persisted_sessions = std.ArrayListUnmanaged(PersistedSession){};
    defer deinitPersistedSessions(allocator, &persisted_sessions);
    try persisted_sessions.append(allocator, .{
        .session_id = try allocator.dupe(u8, "restored-session-1"),
        .ram = restored_ram,
        .worker_queue_depth = 0,
        .worker_active_tasks = 0,
        .worker_mode = .running,
        .worker_dropped_tasks = 0,
        .worker_last_saturation_ms = 0,
        .worker_backpressure_notified = false,
        .worker_last_goal = &[_]u8{},
    });

    const handshake = "GET /v1/agents/default/stream?session=restored-session-1 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    try conn.read_buf.appendSlice(allocator, handshake);

    try processHandshake(allocator, &state, &persisted_sessions, &conn);
    try std.testing.expectEqual(ConnectionState.websocket, conn.state);
    try std.testing.expect(std.mem.eql(u8, conn.session.session_id, "restored-session-1"));
    try std.testing.expect(persisted_sessions.items.len == 0);
}

test "server_piai: handshake restores session context from LTM db snapshot" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    const ltm_dir = try std.fmt.allocPrint(allocator, ".tmp-ltm-restore-{d}", .{std.time.milliTimestamp()});
    defer allocator.free(ltm_dir);
    std.fs.cwd().makePath(ltm_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };
    state.ltm_store = try ltm_store.Store.open(allocator, ltm_dir, LTM_DB_FILENAME);
    defer {
        if (state.ltm_store) |*store| {
            store.close();
        }
        std.fs.cwd().deleteTree(ltm_dir) catch {};
    }

    var persisted_conn = Connection.init(allocator, 0);
    try persisted_conn.session.setSessionId(allocator, "ltm-session-restore-1");
    defer {
        persisted_conn.read_buf.deinit(allocator);
        persisted_conn.write_buf.deinit(allocator);
        persisted_conn.session.deinit(allocator);
    }

    _ = try persisted_conn.session.appendMessage(allocator, .user, "restored user message");
    _ = try persisted_conn.session.appendMessage(allocator, .assistant, "restored assistant message");
    try std.testing.expect(archiveSessionRamToLongTerm(&state, allocator, &persisted_conn.session, "manual pre-stop snapshot"));

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    var persisted_sessions = std.ArrayListUnmanaged(PersistedSession){};
    defer deinitPersistedSessions(allocator, &persisted_sessions);

    const handshake = "GET /v1/agents/default/stream?session=ltm-session-restore-1 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    try conn.read_buf.appendSlice(allocator, handshake);

    try processHandshake(allocator, &state, &persisted_sessions, &conn);
    try std.testing.expectEqual(ConnectionState.websocket, conn.state);
    try std.testing.expect(std.mem.eql(u8, conn.session.session_id, "ltm-session-restore-1"));
    try std.testing.expect(conn.session.ram.entries.items.len == 2);
    try std.testing.expect(conn.session.ram.summaries.items.len == 0);

    var saw_restored_user = false;
    var saw_restored_assistant = false;
    for (conn.session.ram.entries.items) |entry| {
        if (entry.message.role == .user and std.mem.eql(u8, entry.message.content, "restored user message")) {
            saw_restored_user = true;
        }
        if (entry.message.role == .assistant and std.mem.eql(u8, entry.message.content, "restored assistant message")) {
            saw_restored_assistant = true;
        }
    }
    try std.testing.expect(saw_restored_user);
    try std.testing.expect(saw_restored_assistant);
}

test "server_piai: processWebSocket handles masked chat.send and emits session.receive" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer { streamByModelFn = original_stream_fn; }
    streamByModelFn = mockStreamByModel;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    conn.state = .websocket;
    conn.agent_id = try allocator.dupe(u8, "default");
    try conn.session.setSessionId(allocator, "session-ws-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
        allocator.free(conn.agent_id);
    }

    const inbound = "{\"id\":\"req-ws-001\",\"type\":\"chat.send\",\"content\":\"hello websocket\"}";
    const frame = try buildMaskedTextFrame(allocator, inbound, .{ 0x12, 0x34, 0x56, 0x78 });
    defer allocator.free(frame);
    try conn.read_buf.appendSlice(allocator, frame);

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        try processWebSocket(allocator, &state, &pool, &conn);
    }

    var payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    var saw_session_receive = false;
    for (payloads.items) |payload| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        const message_type = obj.get("type") orelse continue;
        if (!std.mem.eql(u8, message_type.string, "session.receive")) continue;
        try std.testing.expect(std.mem.eql(u8, obj.get("content").?.string, "mocked model reply"));
        saw_session_receive = true;
        break;
    }
    try std.testing.expect(saw_session_receive);
}

test "server_piai: handshake + chat flow emits session.ack then session.receive with mock provider" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer { streamByModelFn = original_stream_fn; }
    streamByModelFn = mockStreamByModel;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    var persisted_sessions = std.ArrayListUnmanaged(PersistedSession){};
    defer deinitPersistedSessions(allocator, &persisted_sessions);

    const handshake = "GET /v1/agents/default/stream?session=flow-session-1 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    try conn.read_buf.appendSlice(allocator, handshake);

    try processHandshake(allocator, &state, &persisted_sessions, &conn);
    try std.testing.expectEqual(ConnectionState.websocket, conn.state);
    try std.testing.expect(conn.session.session_id.len > 0);
    try std.testing.expect(std.mem.eql(u8, conn.session.session_id, "flow-session-1"));

    const frame_start = std.mem.indexOfScalar(u8, conn.write_buf.items, 0x81) orelse {
        return error.InvalidFrame;
    };
    const ack_payload = try decodeFirstWebSocketPayload(conn.write_buf.items[frame_start..]);
    const parsed_ack = try std.json.parseFromSlice(std.json.Value, allocator, ack_payload, .{});
    defer parsed_ack.deinit();
    const ack_obj = parsed_ack.value.object;
    try std.testing.expect(std.mem.eql(u8, ack_obj.get("type").?.string, "session.ack"));
    try std.testing.expect(std.mem.eql(u8, ack_obj.get("sessionKey").?.string, "flow-session-1"));

    const inbound = "{\"id\":\"req-flow\",\"type\":\"chat.send\",\"content\":\"hello from websocket\"}";
    const frame = try buildMaskedTextFrame(allocator, inbound, .{ 0x12, 0x34, 0x56, 0x78 });
    defer allocator.free(frame);
    conn.read_buf.clearRetainingCapacity();
    try conn.read_buf.appendSlice(allocator, frame);

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        try processWebSocket(allocator, &state, &pool, &conn);
    }

    var payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items[frame_start..]);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    var saw_receive = false;
    for (payloads.items) |payload| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;

        const message_type = obj.get("type") orelse continue;
        if (std.mem.eql(u8, message_type.string, "session.receive")) {
            try std.testing.expect(std.mem.eql(u8, obj.get("content").?.string, "mocked model reply"));
            saw_receive = true;
        }
    }

    try std.testing.expect(saw_receive);
}

test "server_piai: handleUserMessage with chat.send runs mocked stream and emits session.receive" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer { streamByModelFn = original_stream_fn; }
    streamByModelFn = mockStreamByModel;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-mock-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-001\",\"type\":\"chat.send\",\"content\":\"hello from client\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }

    const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "session.receive"));
    try std.testing.expect(std.mem.eql(u8, obj.get("content").?.string, "mocked model reply"));
    try std.testing.expect(obj.get("memoryId").?.integer > 0);
}

test "server_piai: mocked provider stream error emits error payload" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer { streamByModelFn = original_stream_fn; }
    streamByModelFn = mockStreamByModelError;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-mock-error");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    try processAiStreaming(allocator, &state, &conn, "req-err-001", false);

    const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "error"));
    try std.testing.expect(std.mem.eql(u8, obj.get("message").?.string, "mock stream unavailable"));
}

test "server_piai: agent.control action state emits agent.state snapshot" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-control-state-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-003\",\"type\":\"agent.control\",\"action\":\"state\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }

    const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.state"));
    try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "workers.running"));
    try std.testing.expect(std.mem.eql(u8, obj.get("lastGoal").?.string, ""));
    try std.testing.expect(obj.get("queuedTasks").?.integer >= 0);
    try std.testing.expect(obj.get("activeTasks").?.integer >= 0);
}

test "server_piai: agent.control action pause and resume emit updated worker state" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-control-pause-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-010\",\"type\":\"agent.control\",\"action\":\"pause\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }
    {
        const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.state"));
        try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "workers.paused"));
    }

    conn.write_buf.clearRetainingCapacity();
    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-011\",\"type\":\"agent.control\",\"action\":\"resume\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }
    {
        const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.state"));
        try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "workers.running"));
    }

    conn.write_buf.clearRetainingCapacity();
    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-012\",\"type\":\"agent.control\",\"action\":\"cancel\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }
    {
        const payload = try decodeFirstWebSocketPayload(conn.write_buf.items);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.state"));
        try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "workers.cancelled"));
    }
}

test "server_piai: paused worker mode skips plan delegation but emits state snapshot with queued work depth" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer { streamByModelFn = original_stream_fn; }
    streamByModelFn = mockStreamByModel;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-control-paused-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    conn.session.setWorkerMode(.paused);

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound =
            "{\"id\":\"req-020\",\"type\":\"agent.control\",\"goal\":\"Find open PRs and summarize findings and propose next steps\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }

    var payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    var saw_worker_state = false;
    var saw_worker_skip = false;
    var saw_plan = false;
    var queue_depth: ?i64 = null;

    for (payloads.items) |payload| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;

        const message_type = obj.get("type") orelse continue;
        if (std.mem.eql(u8, message_type.string, "agent.plan")) {
            saw_plan = true;
            continue;
        }
        if (std.mem.eql(u8, message_type.string, "agent.progress")) {
            const status = obj.get("status") orelse continue;
            if (std.mem.eql(u8, status.string, "skipped")) saw_worker_skip = true;
            continue;
        }
        if (std.mem.eql(u8, message_type.string, "agent.state")) {
            saw_worker_state = true;
            try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "workers.paused"));
            if (obj.get("queuedTasks")) |q| queue_depth = q.integer;
            continue;
        }
    }

    try std.testing.expect(saw_plan);
    try std.testing.expect(saw_worker_state);
    try std.testing.expect(saw_worker_skip);
    try std.testing.expect(queue_depth != null);
    try std.testing.expect(queue_depth.? > 0);
}

test "server_piai: agent.control goal emits plan and worker events" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer { streamByModelFn = original_stream_fn; }
    streamByModelFn = mockStreamByModel;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-control-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-002\",\"type\":\"agent.control\",\"goal\":\"Build a small dashboard\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }

    var payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    var saw_plan = false;
    var saw_planner_received = false;
    var saw_worker_status = false;
    var saw_worker_progress = false;
    var saw_status = false;
    var worker_status_count: usize = 0;

    for (payloads.items) |payload| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;

        const message_type = obj.get("type") orelse continue;
        if (!std.mem.eql(u8, message_type.string, "agent.plan") and
            !std.mem.eql(u8, message_type.string, "agent.progress") and
            !std.mem.eql(u8, message_type.string, "agent.status") and
            !std.mem.eql(u8, message_type.string, "session.receive"))
        {
            continue;
        }

        if (std.mem.eql(u8, message_type.string, "agent.plan")) {
            saw_plan = true;
            continue;
        }

        if (std.mem.eql(u8, message_type.string, "agent.status")) {
            saw_status = true;
            worker_status_count += 1;
            const task_id = obj.get("taskId") orelse unreachable;
            try std.testing.expect(task_id.integer > 0);
            continue;
        }

        if (std.mem.eql(u8, message_type.string, "agent.progress")) {
            saw_worker_progress = true;
            const phase = obj.get("phase") orelse continue;
            if (std.mem.eql(u8, phase.string, "planner")) {
                const status = obj.get("status") orelse continue;
                if (std.mem.eql(u8, status.string, "received")) saw_planner_received = true;
            }
            if (phase.string.len > 0) {
                saw_worker_status = true;
            }
            continue;
        }
    }

    try std.testing.expect(saw_plan);
    try std.testing.expect(saw_planner_received);
    try std.testing.expect(saw_worker_status);
    try std.testing.expect(saw_worker_progress);
    try std.testing.expect(saw_status);
    try std.testing.expect(worker_status_count > 0);
}

test "server_piai: plan task admission applies worker dispatch saturation cap" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer { streamByModelFn = original_stream_fn; }
    streamByModelFn = mockStreamByModel;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    try conn.session.setSessionId(allocator, "session-control-saturate-1");
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator });
        defer pool.deinit();

        const inbound = "{\"id\":\"req-030\",\"type\":\"agent.control\",\"goal\":\"a; b; c; d; e\"}";
        try handleUserMessage(allocator, &state, &pool, &conn, inbound);
    }

    var payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    var saw_saturated = false;
    var worker_status_count: usize = 0;
    for (payloads.items) |payload| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;

        const message_type = obj.get("type") orelse continue;
        if (std.mem.eql(u8, message_type.string, "agent.progress")) {
            const phase = obj.get("phase") orelse continue;
            if (std.mem.eql(u8, phase.string, "planner")) {
                const status = obj.get("status") orelse continue;
                if (std.mem.eql(u8, status.string, "saturated")) {
                    saw_saturated = true;
                    const accepted = obj.get("accepted").?.integer;
                    const total = obj.get("total").?.integer;
                    const dropped = obj.get("dropped").?.integer;
                    const queued = obj.get("queued").?.integer;
                    const active = obj.get("active").?.integer;
                    try std.testing.expectEqual(@as(i64, 4), accepted);
                    try std.testing.expectEqual(@as(i64, 5), total);
                    try std.testing.expectEqual(@as(i64, 1), dropped);
                    try std.testing.expectEqual(@as(i64, 2), queued);
                    try std.testing.expectEqual(@as(i64, 2), active);
                }
            }
            continue;
        }

        if (std.mem.eql(u8, message_type.string, "agent.status")) {
            worker_status_count += 1;
            continue;
        }
    }

    try std.testing.expect(saw_saturated);
    try std.testing.expect(worker_status_count > 0);
    try std.testing.expect(worker_status_count < 5);
}

test "server_piai: handshake restore emits reconnect progress for restored session state" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    var persisted_ram = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES);
    _ = try persisted_ram.update(.user, "restored content");

    var persisted_sessions = std.ArrayListUnmanaged(PersistedSession){};
    defer deinitPersistedSessions(allocator, &persisted_sessions);
    try persisted_sessions.append(allocator, .{
        .session_id = try allocator.dupe(u8, "restored-session-2"),
        .ram = persisted_ram,
        .worker_queue_depth = 0,
        .worker_active_tasks = 0,
        .worker_mode = .running,
        .worker_dropped_tasks = 0,
        .worker_last_saturation_ms = 0,
        .worker_backpressure_notified = false,
        .worker_last_goal = try allocator.dupe(u8, "continue where we left off"),
    });

    const handshake = "GET /v1/agents/default/stream?session=restored-session-2 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    try conn.read_buf.appendSlice(allocator, handshake);

    try processHandshake(allocator, &state, &persisted_sessions, &conn);

    const payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    try std.testing.expect(payloads.items.len >= 2);
    const reconnect = payloads.items[1];
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, reconnect, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.progress"));
    try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "reconnect"));
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "state_restored"));
    const message = obj.get("message") orelse return error.InvalidPayload;
    try std.testing.expect(std.mem.indexOf(u8, message.string, "continue where we left off") != null);
}

test "server_piai: handshake restore emits backlog-aware reconnect progress" {
    const allocator = std.testing.allocator;

    var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
    defer model_registry.deinit();
    try ziggy_piai.models.registerDefaultModels(&model_registry);

    var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
    defer api_registry.deinit();
    try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(0xBADC0FFEE),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = .{
            .name = "openai",
            .model = "gpt-4o-mini",
            .api_key = "mock-api-key",
            .base_url = "https://example.invalid",
        },
        .ltm_store = null,
    };

    var conn = Connection.init(allocator, 0);
    defer {
        conn.read_buf.deinit(allocator);
        conn.write_buf.deinit(allocator);
        conn.session.deinit(allocator);
    }

    var persisted_sessions = std.ArrayListUnmanaged(PersistedSession){};
    defer deinitPersistedSessions(allocator, &persisted_sessions);
    try persisted_sessions.append(allocator, .{
        .session_id = try allocator.dupe(u8, "restored-session-3"),
        .ram = memory.RamContext.init(allocator, MAX_CONTEXT_MESSAGES, MAX_CONTEXT_BYTES),
        .worker_queue_depth = 2,
        .worker_active_tasks = 1,
        .worker_mode = .running,
        .worker_dropped_tasks = 3,
        .worker_last_saturation_ms = std.time.milliTimestamp() - 1,
        .worker_backpressure_notified = false,
        .worker_last_goal = try allocator.dupe(u8, "resume backlog"),
    });

    const handshake = "GET /v1/agents/default/stream?session=restored-session-3 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    try conn.read_buf.appendSlice(allocator, handshake);

    try processHandshake(allocator, &state, &persisted_sessions, &conn);

    const payloads = try collectWebSocketPayloads(allocator, conn.write_buf.items);
    defer {
        for (payloads.items) |payload| allocator.free(payload);
        payloads.deinit(allocator);
    }

    const reconnect = payloads.items[1];
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, reconnect, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expect(std.mem.eql(u8, obj.get("type").?.string, "agent.progress"));
    try std.testing.expect(std.mem.eql(u8, obj.get("phase").?.string, "reconnect"));
    try std.testing.expect(std.mem.eql(u8, obj.get("status").?.string, "backpressure_resumed"));
    const message = obj.get("message") orelse return error.InvalidPayload;
    try std.testing.expect(std.mem.indexOf(u8, message.string, "2 queued") != null);
    try std.testing.expect(std.mem.indexOf(u8, message.string, "1 active") != null);
    try std.testing.expect(std.mem.indexOf(u8, message.string, "3 dropped") != null);
}
