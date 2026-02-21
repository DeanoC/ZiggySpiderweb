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
    const escaped_request = try jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request);
    const escaped = try jsonEscape(allocator, content);
    defer allocator.free(escaped);

    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"session.receive\",\"request\":\"{s}\",\"role\":\"assistant\",\"content\":\"{s}\",\"timestamp\":{d}}}",
        .{ escaped_request, escaped, std.time.milliTimestamp() },
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

pub fn buildAgentRunAck(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    run_id: []const u8,
    state: []const u8,
    step_count: u64,
    checkpoint_seq: u64,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.run.ack\",\"request\":\"{s}\",\"run_id\":\"{s}\",\"state\":\"{s}\",\"step_count\":{d},\"checkpoint_seq\":{d},\"timestamp\":{d}}}",
        .{ request_id, run_id, state, step_count, checkpoint_seq, std.time.milliTimestamp() },
    );
}

pub fn buildAgentRunState(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    run_id: []const u8,
    state: []const u8,
    step_count: u64,
    checkpoint_seq: u64,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.run.state\",\"request\":\"{s}\",\"run_id\":\"{s}\",\"state\":\"{s}\",\"step_count\":{d},\"checkpoint_seq\":{d},\"timestamp\":{d}}}",
        .{ request_id, run_id, state, step_count, checkpoint_seq, std.time.milliTimestamp() },
    );
}

pub fn buildAgentRunEvent(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    run_id: []const u8,
    event_type: []const u8,
    payload_json: []const u8,
) ![]u8 {
    const escaped_event_type = try jsonEscape(allocator, event_type);
    defer allocator.free(escaped_event_type);
    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"agent.run.event\",\"request\":\"{s}\",\"run_id\":\"{s}\",\"event_type\":\"{s}\",\"payload\":{s},\"timestamp\":{d}}}",
        .{ request_id, run_id, escaped_event_type, payload_json, std.time.milliTimestamp() },
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

pub fn buildDebugEvent(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    category: []const u8,
    payload_json: []const u8,
) ![]u8 {
    const escaped_category = try jsonEscape(allocator, category);
    defer allocator.free(escaped_category);

    return std.fmt.allocPrint(
        allocator,
        "{{\"type\":\"debug.event\",\"request\":\"{s}\",\"category\":\"{s}\",\"payload\":{s},\"timestamp\":{d}}}",
        .{ request_id, escaped_category, payload_json, std.time.milliTimestamp() },
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

    const hex = "0123456789abcdef";
    if (std.unicode.Utf8View.init(input)) |view| {
        var iter = view.iterator();
        while (iter.nextCodepoint()) |codepoint| {
            switch (codepoint) {
                '\\' => try out.appendSlice(allocator, "\\\\"),
                '"' => try out.appendSlice(allocator, "\\\""),
                0x08 => try out.appendSlice(allocator, "\\b"),
                0x0C => try out.appendSlice(allocator, "\\f"),
                '\n' => try out.appendSlice(allocator, "\\n"),
                '\r' => try out.appendSlice(allocator, "\\r"),
                '\t' => try out.appendSlice(allocator, "\\t"),
                else => {
                    if (codepoint < 0x20) {
                        const cp_byte: u8 = @intCast(codepoint);
                        try out.appendSlice(allocator, "\\u00");
                        try out.append(allocator, hex[(cp_byte >> 4) & 0x0F]);
                        try out.append(allocator, hex[cp_byte & 0x0F]);
                    } else {
                        var buf: [4]u8 = undefined;
                        const wrote = try std.unicode.utf8Encode(codepoint, &buf);
                        try out.appendSlice(allocator, buf[0..wrote]);
                    }
                },
            }
        }
    } else |_| {
        // Fallback for malformed UTF-8: escape byte-for-byte so envelopes remain valid JSON text.
        for (input) |char| {
            switch (char) {
                '\\' => try out.appendSlice(allocator, "\\\\"),
                '"' => try out.appendSlice(allocator, "\\\""),
                '\x08' => try out.appendSlice(allocator, "\\b"),
                '\x0C' => try out.appendSlice(allocator, "\\f"),
                '\n' => try out.appendSlice(allocator, "\\n"),
                '\r' => try out.appendSlice(allocator, "\\r"),
                '\t' => try out.appendSlice(allocator, "\\t"),
                else => {
                    if (char < 0x20 or char >= 0x80) {
                        try out.appendSlice(allocator, "\\u00");
                        try out.append(allocator, hex[(char >> 4) & 0x0F]);
                        try out.append(allocator, hex[char & 0x0F]);
                    } else {
                        try out.append(allocator, char);
                    }
                },
            }
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

test "protocol_response: buildAgentRunState emits run metadata" {
    const allocator = std.testing.allocator;
    const payload = try buildAgentRunState(allocator, "req-run", "run-1", "running", 3, 2);
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"type\":\"agent.run.state\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"run_id\":\"run-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"step_count\":3") != null);
}

test "protocol_response: buildDebugEvent includes category and payload" {
    const allocator = std.testing.allocator;
    const payload = try buildDebugEvent(allocator, "req-d", "provider.request", "{\"x\":1}");
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"category\":\"provider.request\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"payload\":{\"x\":1}") != null);
}

test "protocol_response: jsonEscape handles all control characters" {
    const allocator = std.testing.allocator;
    const input = [_]u8{ 'a', 0x01, '\x08', '\x0C', '\n', '\r', '\t', 'z' };
    const escaped = try jsonEscape(allocator, &input);
    defer allocator.free(escaped);

    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\u0001") != null);
    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\b") != null);
    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\f") != null);
    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\r") != null);
    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\t") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, escaped, 0x01) == null);
}

test "protocol_response: jsonEscape emits parse-safe unicode escapes" {
    const allocator = std.testing.allocator;
    const escaped = try jsonEscape(allocator, "Hello! 👋");
    defer allocator.free(escaped);

    try std.testing.expect(std.mem.indexOf(u8, escaped, "Hello! 👋") != null);
}

test "protocol_response: buildSessionReceive escapes request id" {
    const allocator = std.testing.allocator;
    const payload = try buildSessionReceive(allocator, "req\"x", "hello");
    defer allocator.free(payload);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    try std.testing.expectEqualStrings("req\"x", parsed.value.object.get("request").?.string);
    try std.testing.expectEqualStrings("hello", parsed.value.object.get("content").?.string);
}

test "protocol_response: jsonEscape byte-fallback escapes invalid utf8 bytes" {
    const allocator = std.testing.allocator;
    const invalid = [_]u8{ 'A', 0xFF, 'B' };
    const escaped = try jsonEscape(allocator, &invalid);
    defer allocator.free(escaped);

    try std.testing.expect(std.mem.indexOf(u8, escaped, "A\\u00ffB") != null);
}
