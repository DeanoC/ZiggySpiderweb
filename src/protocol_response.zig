const std = @import("std");
const types = @import("protocol_types.zig");

pub fn buildConnectAck(allocator: std.mem.Allocator, request_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"connect.ack\",\"request\":\"{s}\",\"timestamp\":{d}}}",
        .{ request_id, std.time.milliTimestamp() },
    );
}

pub fn buildSessionReceive(allocator: std.mem.Allocator, request_id: []const u8, content: []const u8) ![]u8 {
    const escaped = try jsonEscape(allocator, content);
    defer allocator.free(escaped);

    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"session.receive\",\"request\":\"{s}\",\"role\":\"assistant\",\"content\":\"{s}\",\"timestamp\":{d}}}",
        .{ request_id, escaped, std.time.milliTimestamp() },
    );
}

pub fn buildAgentProgress(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    phase: []const u8,
    status: []const u8,
    detail: []const u8,
) ![]u8 {
    const phase_escaped = try jsonEscape(allocator, phase);
    defer allocator.free(phase_escaped);
    const status_escaped = try jsonEscape(allocator, status);
    defer allocator.free(status_escaped);
    const detail_escaped = try jsonEscape(allocator, detail);
    defer allocator.free(detail_escaped);

    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.progress\",\"request\":\"{s}\",\"phase\":\"{s}\",\"status\":\"{s}\",\"detail\":\"{s}\",\"timestamp\":{d}}}",
        .{ request_id, phase_escaped, status_escaped, detail_escaped, std.time.milliTimestamp() },
    );
}

pub fn buildAgentState(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    state: []const u8,
    checkpoint: u64,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.state\",\"request\":\"{s}\",\"state\":\"{s}\",\"checkpoint\":{d},\"timestamp\":{d}}}",
        .{ request_id, state, checkpoint, std.time.milliTimestamp() },
    );
}

pub fn buildMemoryEvent(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    payload_json: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"memory.event\",\"request\":\"{s}\",\"payload\":{s}}}",
        .{ request_id, payload_json },
    );
}

pub fn buildToolEvent(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    payload_json: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"tool.event\",\"request\":\"{s}\",\"payload\":{s}}}",
        .{ request_id, payload_json },
    );
}

pub fn buildPong(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"pong\",\"timestamp\":{d}}}",
        .{std.time.milliTimestamp()},
    );
}

pub fn buildError(allocator: std.mem.Allocator, request_id: []const u8, message: []const u8) ![]u8 {
    return buildErrorWithCode(allocator, request_id, .execution_failed, message);
}

pub fn buildErrorWithCode(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    code: types.ErrorCode,
    message: []const u8,
) ![]u8 {
    const escaped = try jsonEscape(allocator, message);
    defer allocator.free(escaped);

    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"error\",\"request\":\"{s}\",\"code\":\"{s}\",\"message\":\"{s}\",\"timestamp\":{d}}}",
        .{ request_id, @tagName(code), escaped, std.time.milliTimestamp() },
    );
}

pub fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    for (input) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, char),
        }
    }

    return out.toOwnedSlice(allocator);
}

test "protocol_response: buildErrorWithCode includes deterministic error code" {
    const allocator = std.testing.allocator;
    const payload = try buildErrorWithCode(allocator, "req-1", .queue_saturated, "queue full");
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"code\":\"queue_saturated\"") != null);
}
