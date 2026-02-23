const std = @import("std");
const websocket_transport = @import("websocket_transport.zig");
const fs_protocol = @import("fs_protocol.zig");
const fs_node_ops = @import("fs_node_ops.zig");
const fs_node_service = @import("fs_node_service.zig");
const fs_watch_runtime = @import("fs_watch_runtime.zig");
const unified = @import("ziggy-spider-protocol").unified;
const fsrpc_node_protocol_version = "unified-v2-fs";
const fsrpc_node_proto_id: i64 = 2;

pub fn run(
    allocator: std.mem.Allocator,
    bind_addr: []const u8,
    port: u16,
    export_specs: []const fs_node_ops.ExportSpec,
    required_auth_token: ?[]const u8,
) !void {
    var service = try fs_node_service.NodeService.init(allocator, export_specs);
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
        std.log.info("fs watcher backend active: {s}", .{@tagName(backend)});
    } else |err| {
        std.log.warn("fs watcher disabled: {s}", .{@errorName(err)});
    }

    const address = try std.net.Address.parseIp(bind_addr, port);
    var tcp_server = try address.listen(.{ .reuse_address = true });
    defer tcp_server.deinit();

    std.log.info("FS node websocket server listening at ws://{s}:{d}/v2/fs", .{ bind_addr, port });

    while (true) {
        var connection = tcp_server.accept() catch |err| {
            std.log.err("fs node accept failed: {s}", .{@errorName(err)});
            continue;
        };
        const ctx = allocator.create(ConnectionContext) catch |err| {
            std.log.err("fs node alloc connection context failed: {s}", .{@errorName(err)});
            connection.stream.close();
            continue;
        };
        ctx.* = .{
            .allocator = allocator,
            .stream = connection.stream,
            .service = &service,
            .hub = &hub,
            .required_auth_token = required_auth_token,
        };

        const thread = std.Thread.spawn(.{}, connectionThreadMain, .{ctx}) catch |err| {
            std.log.err("fs node spawn connection thread failed: {s}", .{@errorName(err)});
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
    service: *fs_node_service.NodeService,
    hub: *ConnectionHub,
    required_auth_token: ?[]const u8,
};

fn connectionThreadMain(ctx: *ConnectionContext) void {
    defer ctx.allocator.destroy(ctx);
    defer ctx.stream.close();

    handleConnection(ctx) catch |err| {
        std.log.warn("fs node connection ended: {s}", .{@errorName(err)});
    };
}

fn emitWatcherEvents(ctx: ?*anyopaque, events: []const fs_protocol.InvalidationEvent) void {
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

    fn broadcastInvalidations(
        self: *ConnectionHub,
        origin_id: u64,
        events: []const fs_protocol.InvalidationEvent,
    ) void {
        for (events) |event| {
            const payload = fs_node_service.buildInvalidationEventJson(self.allocator, event) catch continue;
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

fn handleConnection(ctx: *ConnectionContext) !void {
    var handshake = try websocket_transport.performHandshakeWithInfo(ctx.allocator, &ctx.stream);
    defer handshake.deinit(ctx.allocator);

    if (!(std.mem.eql(u8, handshake.path, "/v2/fs") or std.mem.eql(u8, handshake.path, "/"))) {
        const response = try unified.buildFsrpcFsError(
            ctx.allocator,
            null,
            fs_protocol.Errno.EINVAL,
            "invalid FS endpoint path",
        );
        defer ctx.allocator.free(response);
        try websocket_transport.writeFrame(&ctx.stream, response, .text);
        try websocket_transport.writeFrame(&ctx.stream, "", .close);
        return error.InvalidPath;
    }

    const connection = try ctx.hub.register(&ctx.stream);
    defer ctx.hub.unregister(connection);
    var fsrpc_negotiated = false;

    while (true) {
        var frame = websocket_transport.readFrame(
            ctx.allocator,
            &ctx.stream,
            4 * 1024 * 1024,
        ) catch |err| switch (err) {
            error.EndOfStream, websocket_transport.Error.ConnectionClosed => return,
            else => return err,
        };
        defer frame.deinit(ctx.allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = unified.parseMessage(ctx.allocator, frame.payload) catch |err| {
                    const response = try unified.buildFsrpcFsError(
                        ctx.allocator,
                        null,
                        fs_protocol.Errno.EINVAL,
                        @errorName(err),
                    );
                    defer ctx.allocator.free(response);
                    try writeConnectionFrame(connection, response, .text);
                    try writeConnectionFrame(connection, "", .close);
                    return;
                };
                defer parsed.deinit(ctx.allocator);

                if (!fsrpc_negotiated) {
                    if (parsed.channel != .fsrpc or parsed.fsrpc_type != .fs_t_hello) {
                        const response = try unified.buildFsrpcFsError(
                            ctx.allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            "fsrpc.t_fs_hello must be negotiated first",
                        );
                        defer ctx.allocator.free(response);
                        try writeConnectionFrame(connection, response, .text);
                        try writeConnectionFrame(connection, "", .close);
                        return;
                    }
                    validateFsNodeHelloPayload(ctx.allocator, parsed.payload_json, ctx.required_auth_token) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            ctx.allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer ctx.allocator.free(response);
                        try writeConnectionFrame(connection, response, .text);
                        try writeConnectionFrame(connection, "", .close);
                        return;
                    };
                    fsrpc_negotiated = true;
                } else if (parsed.fsrpc_type == .fs_t_hello) {
                    validateFsNodeHelloPayload(ctx.allocator, parsed.payload_json, ctx.required_auth_token) catch |err| {
                        const response = try unified.buildFsrpcFsError(
                            ctx.allocator,
                            parsed.tag,
                            fs_protocol.Errno.EINVAL,
                            @errorName(err),
                        );
                        defer ctx.allocator.free(response);
                        try writeConnectionFrame(connection, response, .text);
                        try writeConnectionFrame(connection, "", .close);
                        return;
                    };
                }

                var handled = ctx.service.handleRequestJsonWithEvents(frame.payload) catch |err| blk: {
                    const fallback_response = try unified.buildFsrpcFsError(
                        ctx.allocator,
                        null,
                        fs_protocol.Errno.EIO,
                        @errorName(err),
                    );
                    const empty_events = try ctx.allocator.alloc(fs_protocol.InvalidationEvent, 0);
                    break :blk fs_node_service.NodeService.HandledRequest{
                        .response_json = fallback_response,
                        .events = empty_events,
                    };
                };
                defer handled.deinit(ctx.allocator);

                // Preserve existing response-stream ordering for the caller connection.
                for (handled.events) |event| {
                    const event_json = try fs_node_service.buildInvalidationEventJson(ctx.allocator, event);
                    defer ctx.allocator.free(event_json);
                    try writeConnectionFrame(connection, event_json, .text);
                }

                // Fan out mutation invalidations to all other connected FS clients.
                if (handled.events.len > 0) {
                    ctx.hub.broadcastInvalidations(connection.id, handled.events);
                }
                try writeConnectionFrame(connection, handled.response_json, .text);
            },
            0x8 => {
                writeConnectionFrame(connection, "", .close) catch {};
                return;
            },
            0x9 => {
                try writeConnectionFrame(connection, frame.payload, .pong);
            },
            0xA => {},
            else => {
                const response = try unified.buildFsrpcFsError(
                    ctx.allocator,
                    null,
                    fs_protocol.Errno.EINVAL,
                    "unsupported websocket opcode",
                );
                defer ctx.allocator.free(response);
                try writeConnectionFrame(connection, response, .text);
            },
        }
    }
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
