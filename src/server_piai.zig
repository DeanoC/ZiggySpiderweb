const std = @import("std");
const ziggy_piai = @import("ziggy-piai");
const Config = @import("config.zig");
const protocol = @import("protocol.zig");

const ServerState = struct {
    allocator: std.mem.Allocator,
    rng: std.Random.DefaultPrng,
    model_registry: ziggy_piai.models.ModelRegistry,
    api_registry: ziggy_piai.api_registry.ApiRegistry,
    http_client: std.http.Client,
    provider_config: Config.ProviderConfig,
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

    var state = ServerState{
        .allocator = allocator,
        .rng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp())),
        .model_registry = model_registry,
        .api_registry = api_registry,
        .http_client = http_client,
        .provider_config = provider_config,
    };

    const addr = try std.net.Address.parseIp(bind_addr, port);
    var tcp_server = try addr.listen(.{
        .reuse_address = true,
        .kernel_backlog = 128,
    });
    defer tcp_server.deinit();

    std.log.info("ZiggySpiderweb v0.2.0 (Pi AI) listening on {s}:{d}", .{ bind_addr, port });
    std.log.info("Available models: {d}", .{model_registry.models.items.len});

    while (true) {
        const conn = tcp_server.accept() catch |err| {
            std.log.err("Accept failed: {s}", .{@errorName(err)});
            continue;
        };
        std.log.info("Connection from {any}", .{conn.address});

        const t = std.Thread.spawn(.{}, handleConnection, .{ &state, conn }) catch |err| {
            std.log.err("Failed to spawn connection thread: {s}", .{@errorName(err)});
            conn.stream.close();
            continue;
        };
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

    // WebSocket upgrade check (case-insensitive)
    if (!std.mem.containsAtLeast(u8, request, 1, "Upgrade: websocket") and
        !std.mem.containsAtLeast(u8, request, 1, "upgrade: websocket"))
    {
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

    const response = std.fmt.allocPrint(state.allocator, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n" ++
        "\r\n", .{accept_key}) catch {
        std.log.err("Failed to format response", .{});
        return;
    };
    defer state.allocator.free(response);

    _ = conn.stream.write(response) catch |err| {
        std.log.err("Failed to write response: {s}", .{@errorName(err)});
        return;
    };

    std.log.info("WebSocket upgrade successful", .{});

    // Handle WebSocket frames with Pi AI
    handleWebSocketPiAI(state, conn, agent_id) catch |err| {
        if (isConnectionClosedError(err)) {
            std.log.info("WebSocket connection closed: {s}", .{@errorName(err)});
            return;
        }

        if (isNetworkError(err)) {
            std.log.warn("WebSocket network error: {s}", .{@errorName(err)});
            return;
        }

        if (isWebSocketFrameError(err)) {
            std.log.warn("WebSocket frame error: {s}", .{@errorName(err)});
            return;
        }

        std.log.err("WebSocket handler error: {s}", .{@errorName(err)});
    };
}

fn handleWebSocketPiAI(state: *ServerState, conn: std.net.Server.Connection, agent_id: []const u8) !void {
    var frame_buf: [65536]u8 = undefined;

    // Send initial session ACK
    const session_key = try generateSessionKey(state);
    defer state.allocator.free(session_key);

    const ack_msg = try std.fmt.allocPrint(state.allocator, "{{\"type\":\"session.ack\",\"sessionKey\":\"{s}\",\"agentId\":\"{s}\"}}", .{ session_key, agent_id });
    defer state.allocator.free(ack_msg);

    try sendWsFrame(conn.stream, ack_msg, .text);
    std.log.info("Sent session.ack: {s}", .{ack_msg});

    // Get model from config, fallback to first available
    var model: ?ziggy_piai.types.Model = null;

    // Try to find model matching config
    for (state.model_registry.models.items) |m| {
        const provider_match = std.mem.eql(u8, m.provider, state.provider_config.name);

        if (state.provider_config.model) |config_model| {
            if (provider_match and std.mem.eql(u8, m.id, config_model)) {
                model = m;
                break;
            }
        } else if (provider_match) {
            model = m;
            break;
        }
    }

    // Fallback to first available
    if (model == null and state.model_registry.models.items.len > 0) {
        model = state.model_registry.models.items[0];
    }

    if (model == null) {
        std.log.err("No models available in registry", .{});
        return error.NoModels;
    }

    std.log.info("Using model: {s} ({s}) from provider: {s}", .{ model.?.name, model.?.id, model.?.provider });

    // Message loop - accumulate conversation
    var messages: std.array_list.Managed(ziggy_piai.types.Message) = .{ .items = &.{}, .capacity = 0, .allocator = state.allocator };
    defer {
        for (messages.items) |message| {
            state.allocator.free(message.content);
        }
        messages.deinit();
    }

    while (true) {
        const frame = try readWsFrame(conn.stream, &frame_buf);

        // WebSocket control frames
        switch (frame.opcode) {
            0x8 => {
                // close -> mirror close frame and end connection gracefully
                sendWsControlFrame(conn.stream, 0x08, frame.payload) catch {};
                return error.ConnectionClosed;
            },
            0x9 => {
                // ping -> pong
                try sendWsControlFrame(conn.stream, 0x0A, frame.payload);
                continue;
            },
            0xA => continue, // pong
            0x1, 0x2 => {}, // text/binary
            else => continue,
        }

        const msg = frame.payload;
        if (msg.len == 0) continue;

        std.log.debug("Received: {s}", .{msg});

        const parsed = std.json.parseFromSlice(std.json.Value, state.allocator, msg, .{}) catch |err| {
            std.log.warn("Failed to parse message: {s}", .{@errorName(err)});
            continue;
        };
        defer parsed.deinit();

        if (parsed.value != .object) continue;

        const msg_type = parsed.value.object.get("type") orelse continue;
        if (msg_type != .string) continue;

        // App-level heartbeat
        if (std.mem.eql(u8, msg_type.string, "ping")) {
            const pong = try protocol.buildPong(state.allocator);
            defer state.allocator.free(pong);
            try sendWsFrame(conn.stream, pong, .text);
            continue;
        }

        const is_chat_send = std.mem.eql(u8, msg_type.string, "chat.send") or std.mem.eql(u8, msg_type.string, "session.send");
        if (!is_chat_send) continue;

        const content = blk: {
            if (parsed.value.object.get("content")) |c| {
                if (c == .string) break :blk c.string;
            }
            if (parsed.value.object.get("text")) |t| {
                if (t == .string) break :blk t.string;
            }
            if (parsed.value.object.get("message")) |m| {
                if (m == .object) {
                    if (m.object.get("content")) |mc| {
                        if (mc == .string) break :blk mc.string;
                    }
                    if (m.object.get("text")) |mt| {
                        if (mt == .string) break :blk mt.string;
                    }
                }
            }
            continue;
        };

        std.log.info("User message: {s}", .{content});

        try messages.append(.{
            .role = .user,
            .content = try state.allocator.dupe(u8, content),
        });

        const context = ziggy_piai.types.Context{
            .messages = messages.items,
        };

        var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(state.allocator);
        defer events.deinit();

        const api_key: []const u8 = blk: {
            if (state.provider_config.api_key) |key| {
                break :blk try state.allocator.dupe(u8, key);
            }
            if (ziggy_piai.env_api_keys.getEnvApiKey(state.allocator, model.?.provider)) |key| {
                break :blk key;
            }
            std.log.err("No API key found for provider: {s}", .{model.?.provider});
            try sendErrorJson(state.allocator, conn.stream, "No API key configured");
            continue;
        };
        defer state.allocator.free(api_key);

        ziggy_piai.stream.streamByModel(
            state.allocator,
            &state.http_client,
            &state.api_registry,
            model.?,
            context,
            .{ .api_key = api_key },
            &events,
        ) catch |err| {
            std.log.err("Stream error: {s}", .{@errorName(err)});
            const err_msg = try std.fmt.allocPrint(state.allocator, "Stream failed: {s}", .{@errorName(err)});
            defer state.allocator.free(err_msg);
            try sendErrorJson(state.allocator, conn.stream, err_msg);
            continue;
        };

        var response_text: std.ArrayList(u8) = .empty;
        defer response_text.deinit(state.allocator);

        var response_sent = false;

        for (events.items) |event| {
            switch (event) {
                .text_delta => |delta| {
                    try response_text.appendSlice(state.allocator, delta.delta);
                },
                .done => |done| {
                    std.log.info("Response complete: {d} tokens", .{done.usage.total_tokens});

                    const final_text = if (done.text.len > 0) done.text else response_text.items;
                    if (final_text.len == 0) continue;

                    try messages.append(.{
                        .role = .assistant,
                        .content = try state.allocator.dupe(u8, final_text),
                    });

                    try sendSessionReceive(state.allocator, conn.stream, final_text);
                    response_sent = true;
                },
                .err => |err_msg| {
                    std.log.err("Pi AI error: {s}", .{err_msg});
                    try sendErrorJson(state.allocator, conn.stream, err_msg);
                },
                else => {},
            }
        }

        // Fallback if provider emitted deltas but no .done event
        if (!response_sent and response_text.items.len > 0) {
            try messages.append(.{
                .role = .assistant,
                .content = try state.allocator.dupe(u8, response_text.items),
            });
            try sendSessionReceive(state.allocator, conn.stream, response_text.items);
        }
    }
}

fn sendSessionReceive(allocator: std.mem.Allocator, stream: std.net.Stream, content: []const u8) !void {
    const escaped = try protocol.jsonEscape(allocator, content);
    defer allocator.free(escaped);

    const response_json = try std.fmt.allocPrint(allocator, "{{\"type\":\"session.receive\",\"content\":\"{s}\"}}", .{escaped});
    defer allocator.free(response_json);

    try sendWsFrame(stream, response_json, .text);
}

fn sendErrorJson(allocator: std.mem.Allocator, stream: std.net.Stream, message: []const u8) !void {
    const escaped = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped);

    const response_json = try std.fmt.allocPrint(allocator, "{{\"type\":\"error\",\"message\":\"{s}\"}}", .{escaped});
    defer allocator.free(response_json);

    try sendWsFrame(stream, response_json, .text);
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

const WsFrame = struct {
    opcode: u8,
    payload: []const u8,
};

fn isConnectionClosedError(err: anyerror) bool {
    const name = @errorName(err);
    return std.mem.eql(u8, name, "ConnectionClosed") or
        std.mem.eql(u8, name, "EndOfStream");
}

fn isNetworkError(err: anyerror) bool {
    const name = @errorName(err);
    return std.mem.eql(u8, name, "BrokenPipe") or
        std.mem.eql(u8, name, "ConnectionResetByPeer") or
        std.mem.eql(u8, name, "ConnectionTimedOut") or
        std.mem.eql(u8, name, "SocketNotConnected") or
        std.mem.eql(u8, name, "NotOpenForReading") or
        std.mem.eql(u8, name, "NotOpenForWriting") or
        std.mem.eql(u8, name, "Unexpected");
}

fn isWebSocketFrameError(err: anyerror) bool {
    const name = @errorName(err);
    return std.mem.eql(u8, name, "BufferTooSmall") or
        std.mem.eql(u8, name, "ControlFrameTooLarge") or
        std.mem.eql(u8, name, "InvalidOpcode") or
        std.mem.eql(u8, name, "ClientFrameNotMasked") or
        std.mem.eql(u8, name, "ReservedBitsNotZero") or
        std.mem.eql(u8, name, "FragmentedFramesUnsupported") or
        std.mem.eql(u8, name, "FragmentedControlFrame");
}

fn readExact(stream: std.net.Stream, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try stream.read(buf[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

fn writeExact(stream: std.net.Stream, buf: []const u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try stream.write(buf[offset..]);
        if (n == 0) return error.BrokenPipe;
        offset += n;
    }
}

fn readWsFrame(stream: std.net.Stream, buf: []u8) !WsFrame {
    var header: [2]u8 = undefined;
    try readExact(stream, &header);

    const fin = (header[0] & 0x80) != 0;
    if ((header[0] & 0x70) != 0) return error.ReservedBitsNotZero;

    const opcode = header[0] & 0x0F;
    if (!isValidOpcode(opcode)) return error.InvalidOpcode;

    const masked = (header[1] & 0x80) != 0;
    var payload_len: usize = header[1] & 0x7F;

    if (payload_len == 126) {
        var ext: [2]u8 = undefined;
        try readExact(stream, &ext);
        payload_len = std.mem.readInt(u16, &ext, .big);
    } else if (payload_len == 127) {
        var ext: [8]u8 = undefined;
        try readExact(stream, &ext);
        payload_len = @intCast(std.mem.readInt(u64, &ext, .big));
    }

    if (!masked) return error.ClientFrameNotMasked;

    if (isControlOpcode(opcode)) {
        if (!fin) return error.FragmentedControlFrame;
        if (payload_len > 125) return error.ControlFrameTooLarge;
    } else {
        if (!fin or opcode == 0x0) return error.FragmentedFramesUnsupported;
    }

    var mask_key: [4]u8 = undefined;
    try readExact(stream, &mask_key);

    if (payload_len > buf.len) return error.BufferTooSmall;

    const payload = buf[0..payload_len];
    try readExact(stream, payload);

    for (payload, 0..) |*b, i| {
        b.* ^= mask_key[i % 4];
    }

    return .{ .opcode = opcode, .payload = payload };
}

fn isValidOpcode(opcode: u8) bool {
    return opcode == 0x0 or opcode == 0x1 or opcode == 0x2 or
        opcode == 0x8 or opcode == 0x9 or opcode == 0xA;
}

fn isControlOpcode(opcode: u8) bool {
    return opcode == 0x8 or opcode == 0x9 or opcode == 0xA;
}

fn sendWsControlFrame(stream: std.net.Stream, opcode: u8, payload: []const u8) !void {
    if (payload.len > 125) return error.ControlFrameTooLarge;

    var header: [2]u8 = .{ 0x80 | opcode, @intCast(payload.len) };
    try writeExact(stream, &header);
    try writeExact(stream, payload);
}

fn sendWsFrame(stream: std.net.Stream, payload: []const u8, comptime frame_type: enum { text, binary }) !void {
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

    try writeExact(stream, header[0..header_len]);
    try writeExact(stream, payload);
}

fn generateSessionKey(state: *ServerState) ![]u8 {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var key: [32]u8 = undefined;
    for (&key) |*c| {
        c.* = chars[state.rng.random().int(u8) % chars.len];
    }
    return state.allocator.dupe(u8, &key);
}
