const std = @import("std");

const protocol = @import("protocol.zig");

const ServerState = struct {
    allocator: std.mem.Allocator,
    rng: std.Random.DefaultPrng,
};

pub fn run(allocator: std.mem.Allocator, bind_addr: []const u8, port: u16) !void {
    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp())),
    };

    const addr = try std.net.Address.parseIp(bind_addr, port);
    var tcp_server = try addr.listen(.{
        .reuse_address = true,
        .kernel_backlog = 128,
    });
    defer tcp_server.deinit();

    std.log.info("Server listening on {s}:{d}", .{ bind_addr, port });

    while (true) {
        const conn = try tcp_server.accept();
        std.log.info("Connection from {any}", .{conn.address});

        // Spawn handler for each connection
        const t = try std.Thread.spawn(.{}, handleConnection, .{ &state, conn });
        t.detach();
    }
}

fn handleConnection(state: *ServerState, conn: std.net.Server.Connection) void {
    defer conn.stream.close();

    // Read HTTP upgrade request
    var buf: [4096]u8 = undefined;
    const n = conn.stream.read(&buf) catch |err| {
        std.log.err("Failed to read request: {s}", .{@errorName(err)});
        return;
    };

    const request = buf[0..n];
    std.log.debug("Request: {s}", .{request});

    // Simple WebSocket upgrade check (case-insensitive)
    if (!std.mem.containsAtLeast(u8, request, 1, "Upgrade: websocket") and
        !std.mem.containsAtLeast(u8, request, 1, "upgrade: websocket")) {
        _ = conn.stream.write("HTTP/1.1 400 Bad Request\r\n\r\n") catch {};
        return;
    }

    // Extract agent ID from path
    const agent_id = parseAgentId(request) orelse "default";
    std.log.info("Agent ID: {s}", .{agent_id});

    // Send WebSocket upgrade response
    const accept_key = generateWsAcceptKey(state, request) catch {
        std.log.err("Failed to generate accept key", .{});
        return;
    };
    defer state.allocator.free(accept_key);

    const response = std.fmt.allocPrint(state.allocator,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n" ++
        "\r\n",
        .{accept_key}
    ) catch {
        std.log.err("Failed to format response", .{});
        return;
    };
    defer state.allocator.free(response);

    _ = conn.stream.write(response) catch |err| {
        std.log.err("Failed to write response: {s}", .{@errorName(err)});
        return;
    };

    std.log.info("WebSocket upgrade successful", .{});

    // Handle WebSocket frames
    handleWebSocket(state, conn) catch |err| {
        std.log.err("WebSocket error: {s}", .{@errorName(err)});
    };
}

fn parseAgentId(request: []const u8) ?[]const u8 {
    // Find /v1/agents/{agentId}/stream
    const prefix = "/v1/agents/";
    const start = std.mem.indexOf(u8, request, prefix) orelse return null;
    const after_agent = start + prefix.len;
    
    const end = std.mem.indexOfPos(u8, request, after_agent, "/stream") orelse return null;
    return request[after_agent..end];
}

fn generateWsAcceptKey(state: *ServerState, request: []const u8) ![]u8 {
    // Find Sec-WebSocket-Key (case-insensitive)
    const key_headers = [_][]const u8{"Sec-WebSocket-Key: ", "sec-websocket-key: "};
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

    // Magic string
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const combined = try std.fmt.allocPrint(state.allocator, "{s}{s}", .{ client_key, magic });
    defer state.allocator.free(combined);

    // SHA-1 hash
    var hash: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(combined, &hash, .{});

    // Base64 encode
    const encoded_len = std.base64.standard.Encoder.calcSize(hash.len);
    const encoded = try state.allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, &hash);

    return encoded;
}

fn handleWebSocket(state: *ServerState, conn: std.net.Server.Connection) !void {
    var frame_buf: [65536]u8 = undefined;

    // Send initial session ACK
    const session_key = try generateSessionKey(state);
    defer state.allocator.free(session_key);

    const ack_msg = try std.fmt.allocPrint(state.allocator,
        "{{\"type\":\"session.ack\",\"sessionKey\":\"{s}\",\"agentId\":\"echo\"}}",
        .{session_key}
    );
    defer state.allocator.free(ack_msg);

    try sendWsFrame(conn.stream, ack_msg, .text);
    std.log.info("Sent session.ack: {s}", .{ack_msg});

    // Echo loop
    while (true) {
        const msg = try readWsFrame(conn.stream, &frame_buf);
        if (msg.len == 0) continue;

        std.log.debug("Received: {s}", .{msg});

        // Parse and echo
        const echoed = try processMessage(state, msg);
        defer if (echoed.ptr != msg.ptr) state.allocator.free(echoed);

        try sendWsFrame(conn.stream, echoed, .text);
        std.log.debug("Echoed: {s}", .{echoed});
    }
}

fn processMessage(state: *ServerState, msg: []const u8) ![]const u8 {
    // Simple echo with prefix for now
    // TODO: Parse OpenClaw protocol properly
    return std.fmt.allocPrint(state.allocator, "Echo: {s}", .{msg});
}

fn readWsFrame(stream: std.net.Stream, buf: []u8) ![]const u8 {
    // Simplified WebSocket frame reading
    var header: [2]u8 = undefined;
    _ = try stream.read(&header);

    _ = (header[0] & 0x80) != 0; // fin
    const opcode = header[0] & 0x0F;
    const masked = (header[1] & 0x80) != 0;
    var payload_len: usize = header[1] & 0x7F;

    if (payload_len == 126) {
        var ext: [2]u8 = undefined;
        _ = try stream.read(&ext);
        payload_len = std.mem.readInt(u16, &ext, .big);
    } else if (payload_len == 127) {
        var ext: [8]u8 = undefined;
        _ = try stream.read(&ext);
        payload_len = std.mem.readInt(u64, &ext, .big);
    }

    if (opcode == 8) return error.ConnectionClosed; // Close frame
    if (opcode == 9) {
        // Ping - should send pong
        return &[_]u8{};
    }

    var mask_key: [4]u8 = undefined;
    if (masked) {
        _ = try stream.read(&mask_key);
    }

    if (payload_len > buf.len) return error.BufferTooSmall;

    const payload = buf[0..payload_len];
    _ = try stream.read(payload);

    if (masked) {
        for (payload, 0..) |*b, i| {
            b.* ^= mask_key[i % 4];
        }
    }

    return payload;
}

fn sendWsFrame(stream: std.net.Stream, payload: []const u8, comptime frame_type: enum { text, binary }) !void {
    const opcode: u8 = switch (frame_type) {
        .text => 0x81, // FIN + text
        .binary => 0x82, // FIN + binary
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

    _ = try stream.write(header[0..header_len]);
    _ = try stream.write(payload);
}

fn generateSessionKey(state: *ServerState) ![]u8 {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var key: [32]u8 = undefined;
    for (&key) |*c| {
        c.* = chars[state.rng.random().int(u8) % chars.len];
    }
    return state.allocator.dupe(u8, &key);
}