const std = @import("std");

// OpenClaw protocol message types
pub const MessageType = enum {
    // Connection lifecycle
    connect,
    connect_ack,
    session_ack,
    disconnect,
    
    // Messaging
    session_send,
    session_receive,
    
    // Heartbeat
    ping,
    pong,
    
    // Errors
    err,
};

// Connect payload from client
pub const ConnectPayload = struct {
    agentId: []const u8,
    auth: ?AuthPayload = null,
    sessionKey: ?[]const u8 = null,
};

pub const AuthPayload = struct {
    deviceKey: []const u8,
    deviceAuth: []const u8,
};

// Session message envelope
pub const SessionMessage = struct {
    id: []const u8,
    content: []const u8,
    role: []const u8 = "user",
    timestamp: ?i64 = null,
};

// Parse JSON message type
pub fn parseMessageType(json: []const u8) ?MessageType {
    // Simple string search for type field
    if (std.mem.indexOf(u8, json, "\"type\":\"connect\"") != null) return .connect;
    if (std.mem.indexOf(u8, json, "\"type\":\"session.send\"") != null) return .session_send;
    if (std.mem.indexOf(u8, json, "\"type\":\"ping\"") != null) return .ping;
    if (std.mem.indexOf(u8, json, "\"type\":\"pong\"") != null) return .pong;
    if (std.mem.indexOf(u8, json, "\"type\":\"disconnect\"") != null) return .disconnect;
    return null;
}

// Build session.receive response
pub fn buildSessionReceive(allocator: std.mem.Allocator, request_id: []const u8, content: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        "{{\"type\":\"session.receive\",\"id\":\"{s}\",\"content\":\"{s}\",\"timestamp\":{d}}}",
        .{ request_id, content, std.time.milliTimestamp() }
    );
}

// Build pong response
pub fn buildPong(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator,
        "{{\"type\":\"pong\",\"timestamp\":{d}}}",
        .{std.time.milliTimestamp()}
    );
}

// Simple JSON escape (for echo content)
pub fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    // Count extra space needed
    var extra: usize = 0;
    for (input) |c| {
        switch (c) {
            '"', '\\', 0x08, 0x0C, '\n', '\r', '\t' => extra += 1,
            else => {},
        }
    }

    const result = try allocator.alloc(u8, input.len + extra);
    var i: usize = 0;
    for (input) |c| {
        switch (c) {
            '"' => { result[i] = '\\'; i += 1; result[i] = '"'; },
            '\\' => { result[i] = '\\'; i += 1; result[i] = '\\'; },
            0x08 => { result[i] = '\\'; i += 1; result[i] = 'b'; },
            0x0C => { result[i] = '\\'; i += 1; result[i] = 'f'; },
            '\n' => { result[i] = '\\'; i += 1; result[i] = 'n'; },
            '\r' => { result[i] = '\\'; i += 1; result[i] = 'r'; },
            '\t' => { result[i] = '\\'; i += 1; result[i] = 't'; },
            else => result[i] = c,
        }
        i += 1;
    }

    return result;
}