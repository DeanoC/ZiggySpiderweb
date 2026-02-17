const std = @import("std");

pub const MessageType = enum {
    connect,
    connect_ack,
    session_send,
    session_receive,
    agent_control,
    agent_progress,
    agent_state,
    memory_event,
    tool_event,
    ping,
    pong,
    err,
    unknown,
};

pub const ErrorCode = enum {
    invalid_envelope,
    unsupported_message_type,
    missing_content,
    queue_saturated,
    runtime_paused,
    runtime_cancelled,
    runtime_timeout,
    execution_failed,
};

pub const ParsedMessage = struct {
    msg_type: MessageType,
    id: ?[]const u8,
    content: ?[]const u8,
    action: ?[]const u8,
};

pub fn deinitParsedMessage(allocator: std.mem.Allocator, message: *ParsedMessage) void {
    if (message.id) |id| allocator.free(id);
    if (message.content) |content| allocator.free(content);
    if (message.action) |action| allocator.free(action);
    message.* = undefined;
}
