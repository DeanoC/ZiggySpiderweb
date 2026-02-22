const std = @import("std");
const fs_protocol = @import("fs_protocol.zig");

pub const ClientResponse = struct {
    ok: bool,
    err_no: i32 = fs_protocol.Errno.SUCCESS,
    err_msg: []u8 = &.{},
    result_json: []u8 = &.{},

    pub fn deinit(self: ClientResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.err_msg);
        allocator.free(self.result_json);
    }
};

pub const EventCallback = *const fn (ctx: ?*anyopaque, event: fs_protocol.InvalidationEvent) void;

pub const FsClient = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    next_id: u32 = 1,

    pub fn connect(allocator: std.mem.Allocator, url: []const u8) !FsClient {
        const parsed = try parseWsUrl(url);
        var stream = try std.net.tcpConnectToHost(allocator, parsed.host, parsed.port);
        errdefer stream.close();

        try performClientHandshake(allocator, &stream, parsed.host, parsed.port, parsed.path);

        return .{
            .allocator = allocator,
            .stream = stream,
            .next_id = 1,
        };
    }

    pub fn deinit(self: *FsClient) void {
        self.stream.close();
        self.* = undefined;
    }

    pub fn call(
        self: *FsClient,
        op: fs_protocol.Op,
        node: ?u64,
        handle: ?u64,
        args_json: ?[]const u8,
        on_event: ?EventCallback,
        on_event_ctx: ?*anyopaque,
    ) !ClientResponse {
        const req_id = self.next_id;
        self.next_id +%= 1;

        const payload = try buildRequestJson(self.allocator, req_id, op, node, handle, args_json);
        defer self.allocator.free(payload);
        try writeClientTextFrame(self.allocator, &self.stream, payload);

        while (true) {
            var frame = try readServerFrame(self.allocator, &self.stream, 4 * 1024 * 1024);
            defer frame.deinit(self.allocator);

            switch (frame.opcode) {
                0x1 => {
                    if (try fs_protocol.parseMaybeInvalidationEvent(self.allocator, frame.payload)) |event| {
                        if (on_event) |callback| callback(on_event_ctx, event);
                        continue;
                    }
                    return parseResponse(self.allocator, req_id, frame.payload);
                },
                0x8 => return error.ConnectionClosed,
                0x9 => {
                    try writeClientPongFrame(self.allocator, &self.stream, frame.payload);
                    continue;
                },
                0xA => continue,
                else => return error.InvalidFrameOpcode,
            }
        }
    }

    pub fn pumpEvents(
        self: *FsClient,
        timeout_ms: i32,
        on_event: ?EventCallback,
        on_event_ctx: ?*anyopaque,
    ) !void {
        if (timeout_ms < -1) return error.InvalidTimeout;
        if (!try waitForReadable(&self.stream, timeout_ms)) return;

        while (true) {
            var frame = try readServerFrame(self.allocator, &self.stream, 4 * 1024 * 1024);
            defer frame.deinit(self.allocator);

            switch (frame.opcode) {
                0x1 => {
                    if (try fs_protocol.parseMaybeInvalidationEvent(self.allocator, frame.payload)) |event| {
                        if (on_event) |callback| callback(on_event_ctx, event);
                    }
                },
                0x8 => return error.ConnectionClosed,
                0x9 => try writeClientPongFrame(self.allocator, &self.stream, frame.payload),
                0xA => {},
                else => return error.InvalidFrameOpcode,
            }

            if (!try waitForReadable(&self.stream, 0)) break;
        }
    }
};

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

const Frame = struct {
    opcode: u8,
    payload: []u8,

    fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

fn parseWsUrl(url: []const u8) !ParsedUrl {
    const prefix = "ws://";
    if (!std.mem.startsWith(u8, url, prefix)) return error.InvalidUrl;
    const rest = url[prefix.len..];

    const slash_idx = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..slash_idx];
    const path = if (slash_idx < rest.len) rest[slash_idx..] else "/v1/fs";
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
) !void {
    var nonce: [16]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var encoded_nonce: [std.base64.standard.Encoder.calcSize(nonce.len)]u8 = undefined;
    const key = std.base64.standard.Encoder.encode(&encoded_nonce, &nonce);

    const request = try std.fmt.allocPrint(
        allocator,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n\r\n",
        .{ path, host, port, key },
    );
    defer allocator.free(request);

    try stream.writeAll(request);

    const response = try readHttpResponse(allocator, stream, 8 * 1024);
    defer allocator.free(response);
    if (std.mem.indexOf(u8, response, " 101 ") == null and std.mem.indexOf(u8, response, " 101\r\n") == null) {
        return error.HandshakeRejected;
    }
}

fn readHttpResponse(allocator: std.mem.Allocator, stream: *std.net.Stream, max_bytes: usize) ![]u8 {
    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(allocator);

    var chunk: [512]u8 = undefined;
    while (buffer.items.len < max_bytes) {
        const n = try stream.read(&chunk);
        if (n == 0) return error.ConnectionClosed;
        try buffer.appendSlice(allocator, chunk[0..n]);
        if (std.mem.indexOf(u8, buffer.items, "\r\n\r\n") != null) {
            return buffer.toOwnedSlice(allocator);
        }
    }

    return error.ResponseTooLarge;
}

fn buildRequestJson(
    allocator: std.mem.Allocator,
    req_id: u32,
    op: fs_protocol.Op,
    node: ?u64,
    handle: ?u64,
    args_json: ?[]const u8,
) ![]u8 {
    const args = args_json orelse "{}";
    var payload = std.ArrayListUnmanaged(u8){};
    errdefer payload.deinit(allocator);

    try payload.writer(allocator).print("{{\"t\":\"req\",\"id\":{d},\"op\":\"{s}\"", .{ req_id, fs_protocol.opName(op) });
    if (node) |node_id| {
        try payload.writer(allocator).print(",\"node\":{d}", .{node_id});
    }
    if (handle) |handle_id| {
        try payload.writer(allocator).print(",\"h\":{d}", .{handle_id});
    }
    try payload.writer(allocator).print(",\"a\":{s}}}", .{args});

    return payload.toOwnedSlice(allocator);
}

fn parseResponse(allocator: std.mem.Allocator, expected_id: u32, payload: []const u8) !ClientResponse {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidResponse;
    const root = parsed.value.object;
    const t = root.get("t") orelse return error.InvalidResponse;
    if (t != .string or !std.mem.eql(u8, t.string, "res")) return error.InvalidResponse;

    const id = root.get("id") orelse return error.InvalidResponse;
    if (id != .integer or id.integer < 0 or id.integer > std.math.maxInt(u32)) return error.InvalidResponse;
    if (@as(u32, @intCast(id.integer)) != expected_id) return error.RequestIdMismatch;

    const ok = root.get("ok") orelse return error.InvalidResponse;
    if (ok != .bool) return error.InvalidResponse;

    if (!ok.bool) {
        const err = root.get("err") orelse return error.InvalidResponse;
        if (err != .object) return error.InvalidResponse;
        const no = err.object.get("no") orelse return error.InvalidResponse;
        const msg = err.object.get("msg") orelse return error.InvalidResponse;
        if (no != .integer or msg != .string) return error.InvalidResponse;

        return .{
            .ok = false,
            .err_no = @intCast(no.integer),
            .err_msg = try allocator.dupe(u8, msg.string),
            .result_json = try allocator.dupe(u8, ""),
        };
    }

    const result_value = root.get("r") orelse return .{
        .ok = true,
        .err_msg = try allocator.dupe(u8, ""),
        .result_json = try allocator.dupe(u8, "{}"),
    };
    const result_json = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(result_value, .{})});
    return .{
        .ok = true,
        .err_msg = try allocator.dupe(u8, ""),
        .result_json = result_json,
    };
}

fn readServerFrame(allocator: std.mem.Allocator, stream: *std.net.Stream, max_payload_bytes: usize) !Frame {
    var header: [2]u8 = undefined;
    try readExact(stream, &header);

    const fin = (header[0] & 0x80) != 0;
    if (!fin) return error.UnsupportedFragmentation;

    const opcode = header[0] & 0x0F;
    const masked = (header[1] & 0x80) != 0;
    if (masked) return error.UnexpectedMaskedFrame;

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
    if (payload_len > max_payload_bytes) return error.FrameTooLarge;

    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);
    if (payload_len > 0) {
        try readExact(stream, payload);
    }

    return .{
        .opcode = opcode,
        .payload = payload,
    };
}

fn writeClientTextFrame(allocator: std.mem.Allocator, stream: *std.net.Stream, payload: []const u8) !void {
    try writeClientFrame(allocator, stream, payload, 0x1);
}

fn writeClientPongFrame(allocator: std.mem.Allocator, stream: *std.net.Stream, payload: []const u8) !void {
    try writeClientFrame(allocator, stream, payload, 0xA);
}

fn writeClientFrame(allocator: std.mem.Allocator, stream: *std.net.Stream, payload: []const u8, opcode: u8) !void {
    var header: [14]u8 = undefined;
    var header_len: usize = 2;
    header[0] = 0x80 | opcode;

    if (payload.len < 126) {
        header[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len <= std.math.maxInt(u16)) {
        header[1] = 0x80 | 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        std.mem.writeInt(u64, header[2..10], payload.len, .big);
        header_len = 10;
    }

    var mask_key: [4]u8 = undefined;
    std.crypto.random.bytes(&mask_key);
    @memcpy(header[header_len .. header_len + 4], &mask_key);
    header_len += 4;

    const masked_payload = try allocator.alloc(u8, payload.len);
    defer allocator.free(masked_payload);
    for (payload, 0..) |byte, idx| {
        masked_payload[idx] = byte ^ mask_key[idx % 4];
    }

    try stream.writeAll(header[0..header_len]);
    if (masked_payload.len > 0) {
        try stream.writeAll(masked_payload);
    }
}

fn readExact(stream: *std.net.Stream, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const n = try stream.read(out[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

fn waitForReadable(stream: *std.net.Stream, timeout_ms: i32) !bool {
    var fds = [_]std.posix.pollfd{
        .{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        },
    };
    const ready = try std.posix.poll(&fds, timeout_ms);
    if (ready == 0) return false;

    const revents = fds[0].revents;
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) {
        return error.ConnectionClosed;
    }
    return (revents & std.posix.POLL.IN) != 0;
}

test "fs_client: parseWsUrl supports explicit port" {
    const parsed = try parseWsUrl("ws://127.0.0.1:18891/v1/fs");
    try std.testing.expectEqualStrings("127.0.0.1", parsed.host);
    try std.testing.expectEqual(@as(u16, 18891), parsed.port);
    try std.testing.expectEqualStrings("/v1/fs", parsed.path);
}

test "fs_client: parseWsUrl defaults path and port" {
    const parsed = try parseWsUrl("ws://localhost");
    try std.testing.expectEqualStrings("localhost", parsed.host);
    try std.testing.expectEqual(@as(u16, 80), parsed.port);
    try std.testing.expectEqualStrings("/v1/fs", parsed.path);
}

test "fs_client: parseResponse rejects id above u32 range" {
    const allocator = std.testing.allocator;
    const payload = "{\"t\":\"res\",\"id\":4294967296,\"ok\":true,\"r\":{}}";
    try std.testing.expectError(error.InvalidResponse, parseResponse(allocator, 1, payload));
}
