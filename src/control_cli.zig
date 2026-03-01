const std = @import("std");

const default_ws_url = "ws://127.0.0.1:18790/";

const ParsedWsUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

const WsFrame = struct {
    opcode: u8,
    payload: []u8,

    fn deinit(self: *WsFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var url: []const u8 = default_ws_url;
    var operator_token: ?[]const u8 = null;
    var auth_token: ?[]const u8 = null;
    var op_arg: ?[]const u8 = null;
    var payload_arg: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--url")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            url = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--operator-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            operator_token = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--auth-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            auth_token = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp();
            return;
        }

        if (op_arg == null) {
            op_arg = arg;
            continue;
        }
        if (payload_arg == null) {
            payload_arg = arg;
            continue;
        }
        return error.InvalidArguments;
    }

    const op_input = op_arg orelse {
        try printHelp();
        return error.InvalidArguments;
    };

    const op_type = try normalizeControlType(allocator, op_input);
    defer allocator.free(op_type);

    const payload_json = try buildPayloadJson(allocator, op_type, payload_arg, operator_token);
    defer allocator.free(payload_json);

    const parsed_url = try parseWsUrlWithDefaultPath(url, "/");
    var stream = try std.net.tcpConnectToHost(allocator, parsed_url.host, parsed_url.port);
    defer stream.close();

    const connect_auth_token = auth_token orelse std.process.getEnvVarOwned(allocator, "SPIDERWEB_AUTH_TOKEN") catch null;
    defer if (auth_token == null) {
        if (connect_auth_token) |value| allocator.free(value);
    };
    try performClientHandshake(
        allocator,
        &stream,
        parsed_url.host,
        parsed_url.port,
        parsed_url.path,
        connect_auth_token,
    );

    try sendControlMessage(
        allocator,
        &stream,
        .{
            .request_id = "control-cli-version",
            .msg_type = "control.version",
            .payload_json = "{\"protocol\":\"unified-v2\"}",
        },
    );
    const version_reply = try readControlReplyForId(allocator, &stream, "control-cli-version");
    defer allocator.free(version_reply);
    try ensureControlReplyType(allocator, version_reply, "control.version_ack");

    try sendControlMessage(
        allocator,
        &stream,
        .{
            .request_id = "control-cli-connect",
            .msg_type = "control.connect",
            .payload_json = "{}",
        },
    );
    const connect_reply = try readControlReplyForId(allocator, &stream, "control-cli-connect");
    defer allocator.free(connect_reply);
    try ensureControlReplyType(allocator, connect_reply, "control.connect_ack");

    try sendControlMessage(
        allocator,
        &stream,
        .{
            .request_id = "control-cli-op",
            .msg_type = op_type,
            .payload_json = payload_json,
        },
    );
    const op_reply = try readControlReplyForId(allocator, &stream, "control-cli-op");
    defer allocator.free(op_reply);

    const reply_type = try controlReplyType(allocator, op_reply);
    defer allocator.free(reply_type);

    if (std.mem.eql(u8, reply_type, "control.error")) {
        const err_line = try std.fmt.allocPrint(allocator, "{s}\n", .{op_reply});
        defer allocator.free(err_line);
        try std.fs.File.stderr().writeAll(err_line);
        return error.ControlError;
    }

    const line = try std.fmt.allocPrint(allocator, "{s}\n", .{op_reply});
    defer allocator.free(line);
    try std.fs.File.stdout().writeAll(line);
}

fn normalizeControlType(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidArguments;
    if (std.mem.startsWith(u8, trimmed, "control.")) return allocator.dupe(u8, trimmed);
    return std.fmt.allocPrint(allocator, "control.{s}", .{trimmed});
}

fn buildPayloadJson(
    allocator: std.mem.Allocator,
    op_type: []const u8,
    payload_arg: ?[]const u8,
    operator_token: ?[]const u8,
) ![]u8 {
    const base = std.mem.trim(u8, payload_arg orelse "{}", " \t\r\n");
    if (base.len == 0) return allocator.dupe(u8, "{}");

    if (operator_token == null or !isOperatorTokenProtectedMutation(op_type)) {
        return allocator.dupe(u8, base);
    }

    if (std.mem.indexOf(u8, base, "\"operator_token\"") != null) {
        return allocator.dupe(u8, base);
    }

    if (base.len < 2 or base[0] != '{' or base[base.len - 1] != '}') {
        return error.InvalidPayload;
    }

    const escaped_token = try jsonEscape(allocator, operator_token.?);
    defer allocator.free(escaped_token);

    const inner = std.mem.trim(u8, base[1 .. base.len - 1], " \t\r\n");
    if (inner.len == 0) {
        return std.fmt.allocPrint(allocator, "{{\"operator_token\":\"{s}\"}}", .{escaped_token});
    }
    return std.fmt.allocPrint(allocator, "{{{s},\"operator_token\":\"{s}\"}}", .{ inner, escaped_token });
}

fn isOperatorTokenProtectedMutation(op_type: []const u8) bool {
    return std.mem.eql(u8, op_type, "control.node_invite_create") or
        std.mem.eql(u8, op_type, "control.node_join_pending_list") or
        std.mem.eql(u8, op_type, "control.node_join_approve") or
        std.mem.eql(u8, op_type, "control.node_join_deny") or
        std.mem.eql(u8, op_type, "control.node_delete") or
        std.mem.eql(u8, op_type, "control.project_create") or
        std.mem.eql(u8, op_type, "control.project_update") or
        std.mem.eql(u8, op_type, "control.project_delete") or
        std.mem.eql(u8, op_type, "control.project_activate") or
        std.mem.eql(u8, op_type, "control.project_up") or
        std.mem.eql(u8, op_type, "control.project_mount_set") or
        std.mem.eql(u8, op_type, "control.project_mount_remove") or
        std.mem.eql(u8, op_type, "control.project_token_rotate") or
        std.mem.eql(u8, op_type, "control.project_token_revoke");
}

test "control_cli: operator token mutation whitelist includes project activate and up" {
    try std.testing.expect(isOperatorTokenProtectedMutation("control.project_activate"));
    try std.testing.expect(isOperatorTokenProtectedMutation("control.project_up"));
    try std.testing.expect(isOperatorTokenProtectedMutation("control.node_join_approve"));
    try std.testing.expect(!isOperatorTokenProtectedMutation("control.workspace_status"));
}

const ControlSend = struct {
    request_id: []const u8,
    msg_type: []const u8,
    payload_json: []const u8,
};

fn sendControlMessage(allocator: std.mem.Allocator, stream: *std.net.Stream, msg: ControlSend) !void {
    const escaped_id = try jsonEscape(allocator, msg.request_id);
    defer allocator.free(escaped_id);
    const escaped_type = try jsonEscape(allocator, msg.msg_type);
    defer allocator.free(escaped_type);

    const frame = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"{s}\",\"id\":\"{s}\",\"payload\":{s}}}",
        .{ escaped_type, escaped_id, msg.payload_json },
    );
    defer allocator.free(frame);

    try writeClientFrameMasked(stream, 0x1, frame);
}

fn ensureControlReplyType(allocator: std.mem.Allocator, raw: []const u8, expected_type: []const u8) !void {
    const msg_type = try controlReplyType(allocator, raw);
    defer allocator.free(msg_type);

    if (std.mem.eql(u8, msg_type, expected_type)) return;

    if (std.mem.eql(u8, msg_type, "control.error")) {
        const line = try std.fmt.allocPrint(allocator, "control error reply: {s}\n", .{raw});
        defer allocator.free(line);
        try std.fs.File.stderr().writeAll(line);
        return error.ControlError;
    }

    return error.InvalidResponse;
}

fn controlReplyType(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;

    const channel = parsed.value.object.get("channel") orelse return error.InvalidResponse;
    if (channel != .string or !std.mem.eql(u8, channel.string, "control")) return error.InvalidResponse;

    const type_val = parsed.value.object.get("type") orelse return error.InvalidResponse;
    if (type_val != .string or type_val.string.len == 0) return error.InvalidResponse;
    return allocator.dupe(u8, type_val.string);
}

fn readControlReplyForId(allocator: std.mem.Allocator, stream: *std.net.Stream, request_id: []const u8) ![]u8 {
    while (true) {
        var frame = try readServerFrame(allocator, stream, 4 * 1024 * 1024);

        switch (frame.opcode) {
            0x1 => {
                const matched = isControlReplyForId(allocator, frame.payload, request_id) catch false;
                if (matched) {
                    return frame.payload;
                }
                frame.deinit(allocator);
            },
            0x8 => {
                frame.deinit(allocator);
                return error.ConnectionClosed;
            },
            0x9 => {
                try writeClientFrameMasked(stream, 0xA, frame.payload);
                frame.deinit(allocator);
            },
            0xA => {
                frame.deinit(allocator);
            },
            else => {
                frame.deinit(allocator);
            },
        }
    }
}

fn isControlReplyForId(allocator: std.mem.Allocator, payload: []const u8, request_id: []const u8) !bool {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    const channel = parsed.value.object.get("channel") orelse return false;
    if (channel != .string or !std.mem.eql(u8, channel.string, "control")) return false;

    const id_value = parsed.value.object.get("id") orelse return false;
    if (id_value != .string) return false;

    return std.mem.eql(u8, id_value.string, request_id);
}

fn parseWsUrlWithDefaultPath(url: []const u8, default_path: []const u8) !ParsedWsUrl {
    const prefix = "ws://";
    if (!std.mem.startsWith(u8, url, prefix)) return error.InvalidUrl;
    const rest = url[prefix.len..];

    const slash_idx = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..slash_idx];
    const path = if (slash_idx < rest.len) rest[slash_idx..] else default_path;
    if (host_port.len == 0) return error.InvalidUrl;

    if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |colon_idx| {
        const host = host_port[0..colon_idx];
        const port_str = host_port[colon_idx + 1 ..];
        if (host.len == 0 or port_str.len == 0) return error.InvalidUrl;
        const port = try std.fmt.parseInt(u16, port_str, 10);
        return .{ .host = host, .port = port, .path = path };
    }
    return .{ .host = host_port, .port = 80, .path = path };
}

fn performClientHandshake(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    host: []const u8,
    port: u16,
    path: []const u8,
    auth_token: ?[]const u8,
) !void {
    const auth_line = if (auth_token) |token| blk: {
        break :blk try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}\r\n", .{token});
    } else try allocator.dupe(u8, "");
    defer allocator.free(auth_line);

    const handshake = try std.fmt.allocPrint(
        allocator,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: c3BpZGVyd2ViLWNvbnRyb2wtY2xp\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "{s}" ++
            "\r\n",
        .{ path, host, port, auth_line },
    );
    defer allocator.free(handshake);

    try stream.writeAll(handshake);

    const response = try readHttpHeadersAlloc(allocator, stream, 16 * 1024);
    defer allocator.free(response);
    if (std.mem.indexOf(u8, response, " 101 ") == null and
        std.mem.indexOf(u8, response, " 101\r\n") == null)
    {
        return error.HandshakeRejected;
    }
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

fn writeClientFrameMasked(stream: *std.net.Stream, opcode: u8, payload: []const u8) !void {
    var header: [10]u8 = undefined;
    var header_len: usize = 2;

    header[0] = 0x80 | opcode;
    if (payload.len < 126) {
        header[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len < 65536) {
        header[1] = 0x80 | 126;
        std.mem.writeInt(u16, header[2..4], @as(u16, @intCast(payload.len)), .big);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        std.mem.writeInt(u64, header[2..10], payload.len, .big);
        header_len = 10;
    }

    var mask_key: [4]u8 = undefined;
    std.crypto.random.bytes(&mask_key);

    try stream.writeAll(header[0..header_len]);
    try stream.writeAll(&mask_key);

    const masked = try std.heap.page_allocator.alloc(u8, payload.len);
    defer std.heap.page_allocator.free(masked);
    for (payload, 0..) |byte, idx| {
        masked[idx] = byte ^ mask_key[idx % 4];
    }
    try stream.writeAll(masked);
}

fn readServerFrame(allocator: std.mem.Allocator, stream: *std.net.Stream, max_payload_len: usize) !WsFrame {
    var header: [2]u8 = undefined;
    try readExact(stream, &header);

    const fin = (header[0] & 0x80) != 0;
    if (!fin) return error.UnsupportedFragmentation;

    const opcode = header[0] & 0x0F;
    const masked = (header[1] & 0x80) != 0;
    if (masked) return error.UnexpectedMaskedServerFrame;

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

    if (payload_len > max_payload_len) return error.PayloadTooLarge;

    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);

    if (payload_len > 0) {
        try readExact(stream, payload);
    }

    return .{ .opcode = opcode, .payload = payload };
}

fn readExact(stream: *std.net.Stream, out: []u8) !void {
    var read_total: usize = 0;
    while (read_total < out.len) {
        const read_n = try stream.read(out[read_total..]);
        if (read_n == 0) return error.EndOfStream;
        read_total += read_n;
    }
}

fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    for (input) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (char < 0x20) {
                    try out.writer(allocator).print("\\u00{x:0>2}", .{char});
                } else {
                    try out.append(allocator, char);
                }
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

fn printHelp() !void {
    const help =
        \\spiderweb-control - Unified v2 control-plane CLI
        \\
        \\Usage:
        \\  spiderweb-control [--url <ws-url>] [--auth-token <token>] [--operator-token <token>] <operation> [payload-json]
        \\
        \\Notes:
        \\  - Automatically negotiates control.version and control.connect before the operation.
        \\  - Provide auth via --auth-token or SPIDERWEB_AUTH_TOKEN.
        \\  - <operation> may be passed as either "workspace_status" or "control.workspace_status".
        \\  - Prints the full control reply envelope as JSON.
        \\
        \\Examples:
        \\  spiderweb-control workspace_status
        \\  spiderweb-control --auth-token sw-admin-... auth_status
        \\  spiderweb-control project_list
        \\  spiderweb-control project_create '{"name":"Demo","vision":"Track and deliver demo milestones"}'
        \\  spiderweb-control --operator-token mytoken project_create '{"name":"Secure","vision":"Harden service auth and policy"}'
        \\  spiderweb-control --url ws://127.0.0.1:28790/ project_get '{"project_id":"proj-1"}'
        \\
    ;
    try std.fs.File.stdout().writeAll(help);
}
