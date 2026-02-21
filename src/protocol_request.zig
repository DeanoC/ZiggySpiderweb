const std = @import("std");
const types = @import("protocol_types.zig");

pub fn parseMessageType(raw_json: []const u8) types.MessageType {
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, raw_json, .{}) catch {
        return .unknown;
    };
    defer parsed.deinit();

    if (parsed.value != .object) return .unknown;
    const raw_type = parsed.value.object.get("type") orelse return .unknown;
    if (raw_type != .string) return .unknown;
    return parseMessageTypeString(raw_type.string);
}

fn parseMessageTypeString(raw_type: []const u8) types.MessageType {
    if (std.mem.eql(u8, raw_type, "connect")) return .connect;
    if (std.mem.eql(u8, raw_type, "session.send")) return .session_send;
    if (std.mem.eql(u8, raw_type, "agent.run.start")) return .agent_run_start;
    if (std.mem.eql(u8, raw_type, "agent.run.step")) return .agent_run_step;
    if (std.mem.eql(u8, raw_type, "agent.run.resume")) return .agent_run_resume;
    if (std.mem.eql(u8, raw_type, "agent.run.pause")) return .agent_run_pause;
    if (std.mem.eql(u8, raw_type, "agent.run.cancel")) return .agent_run_cancel;
    if (std.mem.eql(u8, raw_type, "agent.run.status")) return .agent_run_status;
    if (std.mem.eql(u8, raw_type, "agent.run.events")) return .agent_run_events;
    if (std.mem.eql(u8, raw_type, "agent.run.list")) return .agent_run_list;
    if (std.mem.eql(u8, raw_type, "agent.control")) return .agent_control;
    if (std.mem.eql(u8, raw_type, "agent.progress")) return .agent_progress;
    if (std.mem.eql(u8, raw_type, "agent.state")) return .agent_state;
    if (std.mem.eql(u8, raw_type, "agent.run.ack")) return .agent_run_ack;
    if (std.mem.eql(u8, raw_type, "agent.run.state")) return .agent_run_state;
    if (std.mem.eql(u8, raw_type, "agent.run.event")) return .agent_run_event;
    if (std.mem.eql(u8, raw_type, "memory.event")) return .memory_event;
    if (std.mem.eql(u8, raw_type, "tool.event")) return .tool_event;
    if (std.mem.eql(u8, raw_type, "ping")) return .ping;
    if (std.mem.eql(u8, raw_type, "pong")) return .pong;
    if (std.mem.eql(u8, raw_type, "error")) return .err;
    return .unknown;
}

pub fn parseMessage(allocator: std.mem.Allocator, raw_json: []const u8) !types.ParsedMessage {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidEnvelope;
    const obj = parsed.value.object;
    const payload_obj = if (obj.get("payload")) |value|
        if (value == .object) value.object else null
    else
        null;

    const msg_type = if (obj.get("type")) |value|
        if (value == .string) parseMessageTypeString(value.string) else types.MessageType.unknown
    else
        types.MessageType.unknown;

    const id = blk: {
        if (obj.get("id")) |value| {
            if (value == .string) break :blk value.string;
        }
        if (obj.get("request_id")) |value| {
            if (value == .string) break :blk value.string;
        }
        if (payload_obj) |payload| {
            if (payload.get("id")) |value| {
                if (value == .string) break :blk value.string;
            }
            if (payload.get("request_id")) |value| {
                if (value == .string) break :blk value.string;
            }
        }
        break :blk null;
    };

    const content = if (obj.get("content")) |value|
        if (value == .string) value.string else null
    else if (obj.get("text")) |value|
        if (value == .string) value.string else null
    else if (obj.get("goal")) |value|
        if (value == .string) value.string else null
    else if (payload_obj) |payload|
        if (payload.get("content")) |value|
            if (value == .string) value.string else null
        else if (payload.get("text")) |value|
            if (value == .string) value.string else null
        else if (payload.get("goal")) |value|
            if (value == .string) value.string else null
        else
            null
    else
        null;

    const action = blk: {
        if (obj.get("action")) |value| {
            if (value == .string) break :blk value.string;
        }
        if (obj.get("run_id")) |value| {
            if (value == .string) break :blk value.string;
        }
        if (payload_obj) |payload| {
            if (payload.get("action")) |value| {
                if (value == .string) break :blk value.string;
            }
            if (payload.get("run_id")) |value| {
                if (value == .string) break :blk value.string;
            }
        }
        break :blk null;
    };

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
    try std.testing.expectEqual(types.MessageType.session_send, parseMessageType("{\"type\": \"session.send\"}"));
    try std.testing.expectEqual(types.MessageType.agent_run_start, parseMessageType("{\"type\":\"agent.run.start\"}"));
    try std.testing.expectEqual(types.MessageType.agent_run_status, parseMessageType("{\"type\":\"agent.run.status\"}"));
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

test "protocol_request: parseMessage ignores embedded type fragments in content" {
    const allocator = std.testing.allocator;
    var parsed = try parseMessage(
        allocator,
        "{\"id\":\"r2\",\"type\":\"agent.control\",\"action\":\"state\",\"content\":\"{\\\"type\\\":\\\"session.send\\\"}\"}",
    );
    defer types.deinitParsedMessage(allocator, &parsed);

    try std.testing.expectEqual(types.MessageType.agent_control, parsed.msg_type);
    try std.testing.expectEqualStrings("state", parsed.action.?);
}

test "protocol_request: parseMessage supports payload wrapped action and request id" {
    const allocator = std.testing.allocator;
    var parsed = try parseMessage(
        allocator,
        "{\"type\":\"agent.control\",\"payload\":{\"request_id\":\"r3\",\"action\":\"debug.subscribe\"}}",
    );
    defer types.deinitParsedMessage(allocator, &parsed);

    try std.testing.expectEqual(types.MessageType.agent_control, parsed.msg_type);
    try std.testing.expectEqualStrings("r3", parsed.id.?);
    try std.testing.expectEqualStrings("debug.subscribe", parsed.action.?);
}

test "protocol_request: parseMessage falls back to payload action when top-level action is not string" {
    const allocator = std.testing.allocator;
    var parsed = try parseMessage(
        allocator,
        "{\"type\":\"agent.control\",\"action\":null,\"payload\":{\"request_id\":\"r4\",\"action\":\"debug.subscribe\"}}",
    );
    defer types.deinitParsedMessage(allocator, &parsed);

    try std.testing.expectEqual(types.MessageType.agent_control, parsed.msg_type);
    try std.testing.expectEqualStrings("r4", parsed.id.?);
    try std.testing.expectEqualStrings("debug.subscribe", parsed.action.?);
}

test "protocol_request: parseMessage falls back to payload request id when top-level request id is not string" {
    const allocator = std.testing.allocator;
    var parsed = try parseMessage(
        allocator,
        "{\"type\":\"agent.control\",\"request_id\":null,\"payload\":{\"request_id\":\"r5\",\"action\":\"debug.subscribe\"}}",
    );
    defer types.deinitParsedMessage(allocator, &parsed);

    try std.testing.expectEqual(types.MessageType.agent_control, parsed.msg_type);
    try std.testing.expectEqualStrings("r5", parsed.id.?);
    try std.testing.expectEqualStrings("debug.subscribe", parsed.action.?);
}

test "protocol_request: parseMessage maps run_id to action for run messages" {
    const allocator = std.testing.allocator;
    var parsed = try parseMessage(
        allocator,
        "{\"id\":\"r6\",\"type\":\"agent.run.step\",\"run_id\":\"run-123\",\"content\":\"continue\"}",
    );
    defer types.deinitParsedMessage(allocator, &parsed);

    try std.testing.expectEqual(types.MessageType.agent_run_step, parsed.msg_type);
    try std.testing.expectEqualStrings("run-123", parsed.action.?);
    try std.testing.expectEqualStrings("continue", parsed.content.?);
}
