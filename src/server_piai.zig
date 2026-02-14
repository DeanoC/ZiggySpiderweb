const std = @import("std");
const ziggy_piai = @import("ziggy-piai");

const ServerState = struct {
    allocator: std.mem.Allocator,
    rng: std.Random.DefaultPrng,
    model_registry: ziggy_piai.models.ModelRegistry,
    api_registry: ziggy_piai.api_registry.ApiRegistry,
    http_client: std.http.Client,
};

pub fn run(allocator: std.mem.Allocator, bind_addr: []const u8, port: u16) !void {
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
        const conn = try tcp_server.accept();
        std.log.info("Connection from {any}", .{conn.address});

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

    // Handle WebSocket frames with Pi AI
    handleWebSocketPiAI(state, conn, agent_id) catch |err| {
        std.log.err("WebSocket error: {s}", .{@errorName(err)});
    };
}

fn handleWebSocketPiAI(state: *ServerState, conn: std.net.Server.Connection, agent_id: []const u8) !void {
    var frame_buf: [65536]u8 = undefined;

    // Send initial session ACK
    const session_key = try generateSessionKey(state);
    defer state.allocator.free(session_key);

    const ack_msg = try std.fmt.allocPrint(state.allocator,
        "{{\"type\":\"session.ack\",\"sessionKey\":\"{s}\",\"agentId\":\"{s}\"}}",
        .{ session_key, agent_id }
    );
    defer state.allocator.free(ack_msg);

    try sendWsFrame(conn.stream, ack_msg, .text);
    std.log.info("Sent session.ack: {s}", .{ack_msg});

    // Get default model (use first available)
    const model = if (state.model_registry.models.items.len > 0)
        state.model_registry.models.items[0]
    else {
        std.log.err("No models available in registry", .{});
        return error.NoModels;
    };

    std.log.info("Using model: {s} ({s})", .{ model.name, model.id });

    // Message loop - accumulate conversation
    var messages: std.array_list.Managed(ziggy_piai.types.Message) = .{ .items = &.{}, .capacity = 0, .allocator = state.allocator };
    defer messages.deinit();

    while (true) {
        const msg = try readWsFrame(conn.stream, &frame_buf);
        if (msg.len == 0) continue;

        std.log.debug("Received: {s}", .{msg});

        // Parse OpenClaw message
        const parsed = std.json.parseFromSlice(std.json.Value, state.allocator, msg, .{}) catch |err| {
            std.log.warn("Failed to parse message: {s}", .{@errorName(err)});
            continue;
        };
        defer parsed.deinit();

        if (parsed.value != .object) continue;

        const msg_type = parsed.value.object.get("type") orelse continue;
        if (msg_type != .string) continue;

        if (std.mem.eql(u8, msg_type.string, "session.send")) {
            // Extract content from session.send
            const content = blk: {
                if (parsed.value.object.get("content")) |c| {
                    if (c == .string) break :blk c.string;
                }
                // Try text field as fallback
                if (parsed.value.object.get("text")) |t| {
                    if (t == .string) break :blk t.string;
                }
                continue;
            };

            std.log.info("User message: {s}", .{content});

            // Add user message to context
            try messages.append(.{
                .role = .user,
                .content = try state.allocator.dupe(u8, content),
            });

            // Create context
            const context = ziggy_piai.types.Context{
                .messages = messages.items,
            };

            // Stream response from Pi AI
            var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(state.allocator);
            defer events.deinit();

            // Get API key from environment
            const api_key = ziggy_piai.env_api_keys.getEnvApiKey(state.allocator, model.provider) orelse {
                std.log.err("No API key found for provider: {s}", .{model.provider});
                const err_msg = "{\"type\":\"error\",\"message\":\"No API key configured\"}";
                try sendWsFrame(conn.stream, err_msg, .text);
                continue;
            };
            defer state.allocator.free(api_key);

            // Stream from model
            ziggy_piai.stream.streamByModel(
                state.allocator,
                &state.http_client,
                &state.api_registry,
                model,
                context,
                .{ .api_key = api_key },
                &events,
            ) catch |err| {
                std.log.err("Stream error: {s}", .{@errorName(err)});
                const err_msg = try std.fmt.allocPrint(state.allocator,
                    "{{\"type\":\"error\",\"message\":\"Stream failed: {s}\"}}",
                    .{@errorName(err)}
                );
                defer state.allocator.free(err_msg);
                try sendWsFrame(conn.stream, err_msg, .text);
                continue;
            };

            // Process events and build response
            var response_text: std.ArrayList(u8) = .empty;
            defer response_text.deinit(state.allocator);

            for (events.items) |event| {
                switch (event) {
                    .text_delta => |delta| {
                        try response_text.appendSlice(state.allocator, delta.delta);
                    },
                    .done => |done| {
                        std.log.info("Response complete: {d} tokens", .{done.usage.total_tokens});

                        // Add assistant response to conversation history
                        try messages.append(.{
                            .role = .assistant,
                            .content = try state.allocator.dupe(u8, done.text),
                        });

                        // Send as OpenClaw message
                        const response_json = try std.fmt.allocPrint(state.allocator,
                            "{{\"type\":\"session.receive\",\"content\":\"{s}\"}}",
                            .{std.mem.replaceOwned(u8, state.allocator, done.text, "\"", "\\\"") catch done.text}
                        );
                        defer state.allocator.free(response_json);

                        try sendWsFrame(conn.stream, response_json, .text);
                    },
                    .err => |err_msg| {
                        std.log.err("Pi AI error: {s}", .{err_msg});
                        const err_json = try std.fmt.allocPrint(state.allocator,
                            "{{\"type\":\"error\",\"message\":\"{s}\"}}",
                            .{err_msg}
                        );
                        defer state.allocator.free(err_json);
                        try sendWsFrame(conn.stream, err_json, .text);
                    },
                    else => {},
                }
            }
        }
    }
}

fn parseAgentId(request: []const u8) ?[]const u8 {
    const prefix = "/v1/agents/";
    const start = std.mem.indexOf(u8, request, prefix) orelse return null;
    const after_agent = start + prefix.len;

    const end = std.mem.indexOfPos(u8, request, after_agent, "/stream") orelse return null;
    return request[after_agent..end];
}

fn generateWsAcceptKey(state: *ServerState, request: []const u8) ![]u8 {
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

fn readWsFrame(stream: std.net.Stream, buf: []u8) ![]const u8 {
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

    if (opcode == 8) return error.ConnectionClosed;
    if (opcode == 9) return &[_]u8{};

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
