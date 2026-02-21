const std = @import("std");

pub const MessageType = enum {
    connect,
    connect_ack,
    session_send,
    session_receive,
    agent_run_start,
    agent_run_step,
    agent_run_resume,
    agent_run_pause,
    agent_run_cancel,
    agent_run_status,
    agent_run_events,
    agent_run_list,
    agent_control,
    agent_progress,
    agent_state,
    agent_run_ack,
    agent_run_state,
    agent_run_event,
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
    provider_rate_limited,
    provider_auth_failed,
    provider_request_invalid,
    provider_timeout,
    provider_unavailable,
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
