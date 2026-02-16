const std = @import("std");
const Config = @import("config.zig");
const connection_dispatcher = @import("connection_dispatcher.zig");
const protocol = @import("protocol.zig");
const runtime_server_mod = @import("runtime_server.zig");
const websocket_transport = @import("websocket_transport.zig");

pub const RuntimeServer = runtime_server_mod.RuntimeServer;

pub fn run(
    allocator: std.mem.Allocator,
    bind_addr: []const u8,
    port: u16,
    provider_config: Config.ProviderConfig,
    runtime_config: Config.RuntimeConfig,
) !void {
    const runtime_server = try RuntimeServer.createWithProvider(
        allocator,
        runtime_server_mod.default_agent_id,
        runtime_config,
        provider_config,
    );
    defer runtime_server.destroy();

    const address = try std.net.Address.parseIp(bind_addr, port);
    var tcp_server = try address.listen(.{ .reuse_address = true });
    defer tcp_server.deinit();

    const dispatcher = try connection_dispatcher.ConnectionDispatcher.create(
        allocator,
        runtime_config.connection_worker_threads,
        runtime_config.connection_queue_max,
        workerHandleConnection,
        runtime_server,
    );
    defer dispatcher.destroy();

    std.log.info(
        "Runtime websocket server listening at ws://{s}:{d}/v1/agents/{s}/stream",
        .{ bind_addr, port, runtime_server_mod.default_agent_id },
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
    const runtime_server: *RuntimeServer = @ptrCast(@alignCast(ctx orelse return error.InvalidContext));
    try handleWebSocketConnection(allocator, runtime_server, stream);
}

fn handleWebSocketConnection(
    allocator: std.mem.Allocator,
    runtime_server: *RuntimeServer,
    stream: *std.net.Stream,
) !void {
    try websocket_transport.performHandshake(allocator, stream);

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
                const responses = runtime_server.handleMessageFrames(frame.payload) catch |err| blk: {
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
    runtime_server: *RuntimeServer,
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

    handleWebSocketConnection(ctx.allocator, ctx.runtime_server, &connection.stream) catch |err| {
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

test "server_piai: websocket path handles connect/session.send and rejects chat.send" {
    const allocator = std.testing.allocator;
    const runtime_server = try RuntimeServer.create(allocator, runtime_server_mod.default_agent_id, .{
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer runtime_server.destroy();

    var listener = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{ .reuse_address = true });
    defer listener.deinit();

    var server_ctx = WsTestServerCtx{
        .allocator = allocator,
        .runtime_server = runtime_server,
        .listener = &listener,
    };
    defer server_ctx.deinit();

    const server_thread = try std.Thread.spawn(.{}, runSingleWsConnection, .{&server_ctx});
    defer server_thread.join();

    var client = try std.net.tcpConnectToAddress(listener.listen_address);
    defer client.close();

    const handshake =
        "GET /v1/agents/default/stream HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    try client.writeAll(handshake);

    const handshake_response = try readHttpHeadersAlloc(allocator, &client, 16 * 1024);
    defer allocator.free(handshake_response);
    try std.testing.expect(std.mem.indexOf(u8, handshake_response, "101 Switching Protocols") != null);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-connect\",\"type\":\"connect\"}");
    var connect_ack = try readServerFrame(allocator, &client);
    defer connect_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x1), connect_ack.opcode);
    try std.testing.expect(std.mem.indexOf(u8, connect_ack.payload, "\"type\":\"connect.ack\"") != null);

    try writeClientTextFrameMasked(&client, "{\"id\":\"req-session\",\"type\":\"session.send\",\"content\":\"hello\"}");
    var saw_session_receive = false;
    var saw_tool_event = false;
    var saw_memory_event = false;
    var frame_count: usize = 0;
    while (frame_count < 4) : (frame_count += 1) {
        var session_frame = try readServerFrame(allocator, &client);
        defer session_frame.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0x1), session_frame.opcode);
        if (std.mem.indexOf(u8, session_frame.payload, "\"type\":\"session.receive\"") != null) saw_session_receive = true;
        if (std.mem.indexOf(u8, session_frame.payload, "\"type\":\"tool.event\"") != null) saw_tool_event = true;
        if (std.mem.indexOf(u8, session_frame.payload, "\"type\":\"memory.event\"") != null) saw_memory_event = true;
    }
    try std.testing.expect(saw_session_receive);
    try std.testing.expect(saw_tool_event);
    try std.testing.expect(saw_memory_event);

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
