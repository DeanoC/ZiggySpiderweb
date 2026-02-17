const types = @import("protocol_types.zig");
const request = @import("protocol_request.zig");
const response = @import("protocol_response.zig");

pub const MessageType = types.MessageType;
pub const ErrorCode = types.ErrorCode;
pub const ParsedMessage = types.ParsedMessage;

pub const parseMessageType = request.parseMessageType;
pub const parseMessage = request.parseMessage;
pub const deinitParsedMessage = types.deinitParsedMessage;

pub const buildConnectAck = response.buildConnectAck;
pub const buildSessionReceive = response.buildSessionReceive;
pub const buildAgentProgress = response.buildAgentProgress;
pub const buildAgentState = response.buildAgentState;
pub const buildMemoryEvent = response.buildMemoryEvent;
pub const buildToolEvent = response.buildToolEvent;
pub const buildPong = response.buildPong;
pub const buildError = response.buildError;
pub const buildErrorWithCode = response.buildErrorWithCode;
pub const jsonEscape = response.jsonEscape;

test "protocol facade: request + response modules are wired" {
    const allocator = @import("std").testing.allocator;

    var parsed = try parseMessage(allocator, "{\"id\":\"abc\",\"type\":\"session.send\",\"content\":\"hi\"}");
    defer deinitParsedMessage(allocator, &parsed);
    try @import("std").testing.expectEqual(MessageType.session_send, parsed.msg_type);

    const err_payload = try buildErrorWithCode(allocator, "abc", .queue_saturated, "busy");
    defer allocator.free(err_payload);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, err_payload, "queue_saturated") != null);
}
