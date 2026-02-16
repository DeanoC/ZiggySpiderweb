const std = @import("std");
const types = @import("protocol_types.zig");

pub fn parseMessageType(raw_json: []const u8) types.MessageType {
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"connect\"") != null) return .connect;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"session.send\"") != null) return .session_send;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"agent.control\"") != null) return .agent_control;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"agent.progress\"") != null) return .agent_progress;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"agent.state\"") != null) return .agent_state;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"memory.event\"") != null) return .memory_event;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"tool.event\"") != null) return .tool_event;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"ping\"") != null) return .ping;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"pong\"") != null) return .pong;
    if (std.mem.indexOf(u8, raw_json, "\"type\":\"error\"") != null) return .err;
    return .unknown;
}

pub fn parseMessage(allocator: std.mem.Allocator, raw_json: []const u8) !types.ParsedMessage {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidEnvelope;
    const obj = parsed.value.object;

    const msg_type = if (obj.get("type")) |value|
        if (value == .string) parseMessageType(raw_json) else types.MessageType.unknown
    else
        types.MessageType.unknown;

    const id = if (obj.get("id")) |value|
        if (value == .string) value.string else null
    else
        null;

    const content = if (obj.get("content")) |value|
        if (value == .string) value.string else null
    else if (obj.get("text")) |value|
        if (value == .string) value.string else null
    else if (obj.get("goal")) |value|
        if (value == .string) value.string else null
    else
        null;

    const action = if (obj.get("action")) |value|
        if (value == .string) value.string else null
    else
        null;

    return .{
        .msg_type = msg_type,
        .id = if (id) |value| try allocator.dupe(u8, value) else null,
        .content = if (content) |value| try allocator.dupe(u8, value) else null,
        .action = if (action) |value| try allocator.dupe(u8, value) else null,
    };
}

test "protocol_request: parseMessageType recognizes runtime-native message model" {
    try std.testing.expectEqual(types.MessageType.connect, parseMessageType("{\"type\":\"connect\"}"));
    try std.testing.expectEqual(types.MessageType.session_send, parseMessageType("{\"type\":\"session.send\"}"));
    try std.testing.expectEqual(types.MessageType.agent_control, parseMessageType("{\"type\":\"agent.control\"}"));
    try std.testing.expectEqual(types.MessageType.unknown, parseMessageType("{\"type\":\"chat.send\"}"));
    try std.testing.expectEqual(types.MessageType.unknown, parseMessageType("{\"type\":\"mystery\"}"));
}

test "protocol_request: parseMessage extracts id/content/action" {
    const allocator = std.testing.allocator;
    var parsed = try parseMessage(allocator, "{\"id\":\"r1\",\"type\":\"agent.control\",\"action\":\"pause\"}");
    defer types.deinitParsedMessage(allocator, &parsed);

    try std.testing.expectEqual(types.MessageType.agent_control, parsed.msg_type);
    try std.testing.expectEqualStrings("r1", parsed.id.?);
    try std.testing.expectEqualStrings("pause", parsed.action.?);
}
