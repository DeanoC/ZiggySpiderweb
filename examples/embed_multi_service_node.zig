const std = @import("std");
const fs = @import("spiderweb_fs");
const websocket_transport = @import("websocket_transport");
const fs_watch_runtime = fs.watch_runtime;
const unified = @import("ziggy-spider-protocol").unified;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var bind_addr: []const u8 = "127.0.0.1";
    var port: u16 = 19910;
    var exports = std.ArrayListUnmanaged(fs.ExportSpec){};
    defer exports.deinit(allocator);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--bind")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            bind_addr = args[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--export")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            try exports.append(allocator, try parseExportFlag(args[i]));
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp();
            return;
        } else {
            std.log.err("unknown argument: {s}", .{arg});
            try printHelp();
            return error.InvalidArguments;
        }
    }

    if (exports.items.len == 0) {
        try exports.append(allocator, .{
            .name = "work",
            .path = ".",
            .ro = false,
            .desc = "multi-service embedded export",
        });
    }

    var service = try fs.NodeService.init(allocator, exports.items);
    defer service.deinit();
    var hub = ConnectionHub{
        .allocator = allocator,
    };
    defer hub.deinit();

    if (fs_watch_runtime.spawnDetached(
        allocator,
        &service,
        emitWatcherEvents,
        @ptrCast(&hub),
        .{},
    )) |backend| {
        std.log.info("embedded fs watcher backend active: {s}", .{@tagName(backend)});
    } else |err| {
        std.log.warn("embedded fs watcher disabled: {s}", .{@errorName(err)});
    }

    const address = try std.net.Address.parseIp(bind_addr, port);
    var tcp_server = try address.listen(.{ .reuse_address = true });
    defer tcp_server.deinit();

    std.log.info("embed-multi-service-node listening on ws://{s}:{d}", .{ bind_addr, port });
    std.log.info("services: /v2/fs, /v1/health, /v1/echo", .{});

    while (true) {
        var connection = tcp_server.accept() catch |err| {
            std.log.err("accept failed: {s}", .{@errorName(err)});
            continue;
        };
        const ctx = allocator.create(ConnectionContext) catch |err| {
            std.log.err("alloc connection context failed: {s}", .{@errorName(err)});
            connection.stream.close();
            continue;
        };
        ctx.* = .{
            .allocator = allocator,
            .stream = connection.stream,
            .service = &service,
            .hub = &hub,
        };

        const thread = std.Thread.spawn(.{}, connectionThreadMain, .{ctx}) catch |err| {
            std.log.err("spawn connection thread failed: {s}", .{@errorName(err)});
            connection.stream.close();
            allocator.destroy(ctx);
            continue;
        };
        thread.detach();
    }
}

const ConnectionContext = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    service: *fs.NodeService,
    hub: *ConnectionHub,
};

fn connectionThreadMain(ctx: *ConnectionContext) void {
    defer ctx.allocator.destroy(ctx);
    defer ctx.stream.close();

    handleConnection(ctx.allocator, &ctx.stream, ctx.service, ctx.hub) catch |err| {
        std.log.warn("connection closed: {s}", .{@errorName(err)});
    };
}

fn emitWatcherEvents(ctx: ?*anyopaque, events: []const fs.protocol.InvalidationEvent) void {
    const raw = ctx orelse return;
    const hub: *ConnectionHub = @ptrCast(@alignCast(raw));
    hub.broadcastInvalidations(0, events);
}

const HubConnection = struct {
    id: u64,
    stream: *std.net.Stream,
    write_mutex: std.Thread.Mutex = .{},
};

const ConnectionHub = struct {
    allocator: std.mem.Allocator,
    connections: std.ArrayListUnmanaged(*HubConnection) = .{},
    mutex: std.Thread.Mutex = .{},
    next_id: u64 = 1,

    fn deinit(self: *ConnectionHub) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.connections.items) |conn| self.allocator.destroy(conn);
        self.connections.deinit(self.allocator);
    }

    fn register(self: *ConnectionHub, stream: *std.net.Stream) !*HubConnection {
        const conn = try self.allocator.create(HubConnection);
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

    fn unregister(self: *ConnectionHub, conn: *HubConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.connections.items, 0..) |item, idx| {
            if (item != conn) continue;
            _ = self.connections.swapRemove(idx);
            self.allocator.destroy(conn);
            return;
        }
    }

    fn broadcastInvalidations(self: *ConnectionHub, origin_id: u64, events: []const fs.protocol.InvalidationEvent) void {
        for (events) |event| {
            const payload = fs.node_service.buildInvalidationEventJson(self.allocator, event) catch continue;
            defer self.allocator.free(payload);
            self.broadcastText(origin_id, payload);
        }
    }

    fn broadcastText(self: *ConnectionHub, origin_id: u64, payload: []const u8) void {
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

fn writeConnectionFrame(conn: *HubConnection, payload: []const u8, frame_type: websocket_transport.FrameType) !void {
    conn.write_mutex.lock();
    defer conn.write_mutex.unlock();
    try websocket_transport.writeFrame(conn.stream, payload, frame_type);
}

fn handleConnection(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    service: *fs.NodeService,
    hub: *ConnectionHub,
) !void {
    var handshake = try websocket_transport.performHandshakeWithInfo(allocator, stream);
    defer handshake.deinit(allocator);

    if (std.mem.startsWith(u8, handshake.path, "/v2/fs")) {
        const connection = try hub.register(stream);
        defer hub.unregister(connection);
        try serveFs(allocator, connection, service, hub);
        return;
    }

    if (std.mem.startsWith(u8, handshake.path, "/v1/health")) {
        try serveHealth(allocator, stream);
        return;
    }

    if (std.mem.startsWith(u8, handshake.path, "/v1/echo")) {
        try serveEcho(allocator, stream);
        return;
    }

    const payload = "{\"type\":\"error\",\"error\":\"unknown service path\"}";
    try websocket_transport.writeFrame(stream, payload, .text);
    try websocket_transport.writeFrame(stream, "", .close);
    return error.UnknownPath;
}

fn serveFs(
    allocator: std.mem.Allocator,
    connection: *HubConnection,
    service: *fs.NodeService,
    hub: *ConnectionHub,
) !void {
    while (true) {
        var frame = websocket_transport.readFrame(
            allocator,
            connection.stream,
            4 * 1024 * 1024,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var handled = service.handleRequestJsonWithEvents(frame.payload) catch |err| blk: {
                    const fallback_response = try unified.buildFsrpcFsError(
                        allocator,
                        null,
                        fs.protocol.Errno.EIO,
                        @errorName(err),
                    );
                    const empty_events = try allocator.alloc(fs.protocol.InvalidationEvent, 0);
                    break :blk fs.NodeService.HandledRequest{
                        .response_json = fallback_response,
                        .events = empty_events,
                    };
                };
                defer handled.deinit(allocator);
                for (handled.events) |event| {
                    const event_json = try fs.node_service.buildInvalidationEventJson(allocator, event);
                    defer allocator.free(event_json);
                    try writeConnectionFrame(connection, event_json, .text);
                }
                if (handled.events.len > 0) {
                    hub.broadcastInvalidations(connection.id, handled.events);
                }
                try writeConnectionFrame(connection, handled.response_json, .text);
            },
            0x8 => {
                writeConnectionFrame(connection, "", .close) catch {};
                return;
            },
            0x9 => try writeConnectionFrame(connection, frame.payload, .pong),
            0xA => {},
            else => {},
        }
    }
}

fn serveHealth(allocator: std.mem.Allocator, stream: *std.net.Stream) !void {
    const ready = "{\"type\":\"health\",\"ok\":true,\"service\":\"embed-multi-service-node\"}";
    try websocket_transport.writeFrame(stream, ready, .text);

    while (true) {
        var frame = websocket_transport.readFrame(
            allocator,
            stream,
            256 * 1024,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x8 => {
                try websocket_transport.writeFrame(stream, "", .close);
                return;
            },
            0x9 => try websocket_transport.writeFrame(stream, frame.payload, .pong),
            0x1 => try websocket_transport.writeFrame(stream, ready, .text),
            0xA => {},
            else => {},
        }
    }
}

fn serveEcho(allocator: std.mem.Allocator, stream: *std.net.Stream) !void {
    const welcome = "{\"type\":\"echo\",\"ready\":true}";
    try websocket_transport.writeFrame(stream, welcome, .text);

    while (true) {
        var frame = websocket_transport.readFrame(
            allocator,
            stream,
            1024 * 1024,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => try websocket_transport.writeFrame(stream, frame.payload, .text),
            0x8 => {
                try websocket_transport.writeFrame(stream, "", .close);
                return;
            },
            0x9 => try websocket_transport.writeFrame(stream, frame.payload, .pong),
            0xA => {},
            else => {},
        }
    }
}

fn parseExportFlag(raw: []const u8) !fs.ExportSpec {
    const eq_index = std.mem.indexOfScalar(u8, raw, '=') orelse return error.InvalidFormat;
    const name = raw[0..eq_index];
    if (name.len == 0) return error.InvalidFormat;

    const rhs = raw[eq_index + 1 ..];
    if (rhs.len == 0) return error.InvalidFormat;

    var ro = false;
    var path = rhs;
    if (std.mem.endsWith(u8, rhs, ":ro")) {
        ro = true;
        path = rhs[0 .. rhs.len - 3];
    } else if (std.mem.endsWith(u8, rhs, ":rw")) {
        ro = false;
        path = rhs[0 .. rhs.len - 3];
    }
    if (path.len == 0) return error.InvalidFormat;

    return .{
        .name = name,
        .path = path,
        .ro = ro,
        .desc = "multi-service export",
    };
}

fn printHelp() !void {
    const help =
        \\embed-multi-service-node - Example multi-service process with embedded spiderweb_fs
        \\
        \\Usage:
        \\  embed-multi-service-node [--bind <addr>] [--port <port>] [--export <name>=<path>[:ro|:rw]]
        \\
        \\WebSocket services:
        \\  /v2/fs      - distributed filesystem request/response JSON
        \\  /v1/health  - health status service
        \\  /v1/echo    - simple echo service
        \\
        \\Example:
        \\  embed-multi-service-node --port 19910 --export work=.:rw
        \\
    ;
    try std.fs.File.stdout().writeAll(help);
}
