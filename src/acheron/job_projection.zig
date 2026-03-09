const std = @import("std");
const unified = @import("spider-protocol").unified;

const chat_job_index = @import("../agents/chat_job_index.zig");

pub fn buildJobWaitEventPayload(
    allocator: std.mem.Allocator,
    event_id: u64,
    source_path: []const u8,
    event_path: []const u8,
    view: chat_job_index.JobView,
) ![]u8 {
    const source_path_escaped = try unified.jsonEscape(allocator, source_path);
    defer allocator.free(source_path_escaped);
    const event_path_escaped = try unified.jsonEscape(allocator, event_path);
    defer allocator.free(event_path_escaped);
    const job_id_escaped = try unified.jsonEscape(allocator, view.job_id);
    defer allocator.free(job_id_escaped);
    const state_escaped = try unified.jsonEscape(allocator, chat_job_index.jobStateName(view.state));
    defer allocator.free(state_escaped);
    const status_path = try std.fmt.allocPrint(allocator, "/global/jobs/{s}/status.json", .{view.job_id});
    defer allocator.free(status_path);
    const result_path = try std.fmt.allocPrint(allocator, "/global/jobs/{s}/result.txt", .{view.job_id});
    defer allocator.free(result_path);
    const status_path_escaped = try unified.jsonEscape(allocator, status_path);
    defer allocator.free(status_path_escaped);
    const result_path_escaped = try unified.jsonEscape(allocator, result_path);
    defer allocator.free(result_path_escaped);

    const correlation_json = if (view.correlation_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(correlation_json);

    const result_json = if (view.result_text) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(result_json);

    const error_json = if (view.error_text) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(error_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"configured\":true,\"waiting\":false,\"event_id\":{d},\"source_path\":\"{s}\",\"event_path\":\"{s}\",\"updated_at_ms\":{d},\"job\":{{\"job_id\":\"{s}\",\"state\":\"{s}\",\"correlation_id\":{s},\"status_path\":\"{s}\",\"result_path\":\"{s}\",\"result\":{s},\"error\":{s}}}}}",
        .{
            event_id,
            source_path_escaped,
            event_path_escaped,
            view.updated_at_ms,
            job_id_escaped,
            state_escaped,
            correlation_json,
            status_path_escaped,
            result_path_escaped,
            result_json,
            error_json,
        },
    );
}

pub fn buildTerminalJobWaitEventPayload(
    allocator: std.mem.Allocator,
    event_id: u64,
    source_path: []const u8,
    event_path: []const u8,
    event: chat_job_index.JobTerminalEventView,
) ![]u8 {
    const source_path_escaped = try unified.jsonEscape(allocator, source_path);
    defer allocator.free(source_path_escaped);
    const event_path_escaped = try unified.jsonEscape(allocator, event_path);
    defer allocator.free(event_path_escaped);
    const job_id_escaped = try unified.jsonEscape(allocator, event.job_id);
    defer allocator.free(job_id_escaped);
    const state_escaped = try unified.jsonEscape(allocator, chat_job_index.jobStateName(event.state));
    defer allocator.free(state_escaped);
    const status_path = try std.fmt.allocPrint(allocator, "/global/jobs/{s}/status.json", .{event.job_id});
    defer allocator.free(status_path);
    const result_path = try std.fmt.allocPrint(allocator, "/global/jobs/{s}/result.txt", .{event.job_id});
    defer allocator.free(result_path);
    const status_path_escaped = try unified.jsonEscape(allocator, status_path);
    defer allocator.free(status_path_escaped);
    const result_path_escaped = try unified.jsonEscape(allocator, result_path);
    defer allocator.free(result_path_escaped);

    const correlation_json = if (event.correlation_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(correlation_json);

    const result_json = if (event.result_text) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(result_json);

    const error_json = if (event.error_text) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(error_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"configured\":true,\"waiting\":false,\"event_id\":{d},\"source_path\":\"{s}\",\"event_path\":\"{s}\",\"updated_at_ms\":{d},\"job\":{{\"job_id\":\"{s}\",\"state\":\"{s}\",\"correlation_id\":{s},\"status_path\":\"{s}\",\"result_path\":\"{s}\",\"result\":{s},\"error\":{s}}}}}",
        .{
            event_id,
            source_path_escaped,
            event_path_escaped,
            event.created_at_ms,
            job_id_escaped,
            state_escaped,
            correlation_json,
            status_path_escaped,
            result_path_escaped,
            result_json,
            error_json,
        },
    );
}
