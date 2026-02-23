const std = @import("std");

pub const default_max_http_request_bytes: usize = 16 * 1024;
pub const default_max_ws_frame_payload_bytes: usize = 256 * 1024;

const WEBSOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Error = error{
    InvalidHandshake,
    NoWebSocketKey,
    FrameTooLarge,
    UnsupportedFragmentation,
    UnexpectedUnmaskedFrame,
    ConnectionClosed,
};

pub const FrameType = enum {
    text,
    pong,
    close,
};

pub const Frame = struct {
    opcode: u8,
    payload: []u8,

    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const HandshakeInfo = struct {
    path: []u8,
    authorization: ?[]u8 = null,

    pub fn deinit(self: *HandshakeInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        if (self.authorization) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub fn performHandshake(allocator: std.mem.Allocator, stream: *std.net.Stream) !void {
    var info = try performHandshakeWithInfo(allocator, stream);
    defer info.deinit(allocator);
}

pub fn performHandshakeWithInfo(allocator: std.mem.Allocator, stream: *std.net.Stream) !HandshakeInfo {
    const request = try readHttpRequest(allocator, stream, default_max_http_request_bytes);
    defer allocator.free(request);

    const has_upgrade = std.mem.indexOf(u8, request, "Upgrade: websocket") != null or
        std.mem.indexOf(u8, request, "upgrade: websocket") != null;
    if (!has_upgrade) return Error.InvalidHandshake;

    const request_path = extractRequestPath(request) orelse return Error.InvalidHandshake;
    const owned_path = try allocator.dupe(u8, request_path);
    errdefer allocator.free(owned_path);
    const authorization = if (extractAuthorizationHeader(request)) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (authorization) |value| allocator.free(value);

    const ws_key = extractWebSocketKey(request) orelse return Error.NoWebSocketKey;
    const accept_key = try computeWebSocketAcceptKey(allocator, ws_key);
    defer allocator.free(accept_key);

    const response = try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept_key},
    );
    defer allocator.free(response);

    try stream.writeAll(response);
    return .{ .path = owned_path, .authorization = authorization };
}

pub fn readFrame(allocator: std.mem.Allocator, stream: *std.net.Stream, max_payload_bytes: usize) !Frame {
    var header: [2]u8 = undefined;
    try readExact(stream, &header);

    const fin = (header[0] & 0x80) != 0;
    if (!fin) return Error.UnsupportedFragmentation;

    const opcode = header[0] & 0x0F;
    const masked = (header[1] & 0x80) != 0;
    if (!masked and opcode != 0x8) return Error.UnexpectedUnmaskedFrame;

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

    if (payload_len > max_payload_bytes) return Error.FrameTooLarge;

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        try readExact(stream, &mask_key);
    }

    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);

    if (payload_len > 0) {
        try readExact(stream, payload);
    }

    if (masked) {
        for (payload, 0..) |*byte, index| {
            byte.* ^= mask_key[index % 4];
        }
    }

    return .{
        .opcode = opcode,
        .payload = payload,
    };
}

pub fn writeFrame(stream: *std.net.Stream, payload: []const u8, frame_type: FrameType) !void {
    const first_byte: u8 = switch (frame_type) {
        .text => 0x81,
        .pong => 0x8A,
        .close => 0x88,
    };

    var header: [10]u8 = undefined;
    var header_len: usize = 2;
    header[0] = first_byte;

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

    try stream.writeAll(header[0..header_len]);
    if (payload.len > 0) {
        try stream.writeAll(payload);
    }
}

fn readHttpRequest(allocator: std.mem.Allocator, stream: *std.net.Stream, max_bytes: usize) ![]u8 {
    var request = std.ArrayListUnmanaged(u8){};
    errdefer request.deinit(allocator);

    var chunk: [1024]u8 = undefined;
    while (request.items.len < max_bytes) {
        const read_count = try stream.read(&chunk);
        if (read_count == 0) return Error.ConnectionClosed;

        try request.appendSlice(allocator, chunk[0..read_count]);
        if (std.mem.indexOf(u8, request.items, "\r\n\r\n") != null) {
            return request.toOwnedSlice(allocator);
        }
    }

    return Error.InvalidHandshake;
}

fn extractWebSocketKey(request: []const u8) ?[]const u8 {
    const key_headers = [_][]const u8{ "Sec-WebSocket-Key: ", "sec-websocket-key: " };
    for (key_headers) |header| {
        if (std.mem.indexOf(u8, request, header)) |idx| {
            const key_start = idx + header.len;
            const key_end = std.mem.indexOfPos(u8, request, key_start, "\r\n") orelse return null;
            return std.mem.trim(u8, request[key_start..key_end], " \t");
        }
    }
    return null;
}

fn extractRequestPath(request: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const line = request[0..line_end];
    if (!std.mem.startsWith(u8, line, "GET ")) return null;

    const path_start = 4;
    const path_end = std.mem.indexOfPos(u8, line, path_start, " ") orelse return null;
    if (path_end <= path_start) return null;
    return line[path_start..path_end];
}

fn extractAuthorizationHeader(request: []const u8) ?[]const u8 {
    const prefixes = [_][]const u8{
        "\r\nAuthorization:",
        "\r\nauthorization:",
        "Authorization:",
        "authorization:",
    };

    for (prefixes) |prefix| {
        if (std.mem.indexOf(u8, request, prefix)) |idx| {
            var value_start = idx + prefix.len;
            while (value_start < request.len and (request[value_start] == ' ' or request[value_start] == '\t')) : (value_start += 1) {}
            const value_end = std.mem.indexOfPos(u8, request, value_start, "\r\n") orelse request.len;
            const value = std.mem.trim(u8, request[value_start..value_end], " \t");
            if (value.len > 0) return value;
        }
    }
    return null;
}

fn computeWebSocketAcceptKey(allocator: std.mem.Allocator, client_key: []const u8) ![]u8 {
    const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ client_key, WEBSOCKET_MAGIC });
    defer allocator.free(combined);

    var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(combined, &hash, .{});

    var encoded: [std.base64.standard.Encoder.calcSize(hash.len)]u8 = undefined;
    const encoded_slice = std.base64.standard.Encoder.encode(&encoded, &hash);
    return allocator.dupe(u8, encoded_slice);
}

fn readExact(stream: *std.net.Stream, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try stream.read(buf[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

test "websocket_transport: compute accept key from RFC sample" {
    const allocator = std.testing.allocator;
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = try computeWebSocketAcceptKey(allocator, key);
    defer allocator.free(accept);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "websocket_transport: extract request path from handshake line" {
    const request =
        "GET /v2/agents/alpha/stream HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "\r\n";

    const path = extractRequestPath(request) orelse return error.TestExpectedPath;
    try std.testing.expectEqualStrings("/v2/agents/alpha/stream", path);
}
