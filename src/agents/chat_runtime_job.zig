const std = @import("std");
const runtime_server_mod = @import("runtime_server.zig");
const runtime_handle_mod = @import("runtime_handle.zig");
const chat_job_index = @import("chat_job_index.zig");
const shared_exec = @import("spiderweb_node").chat_runtime_exec;

pub const max_internal_retries = shared_exec.max_internal_retries;
pub const ExecutionResult = shared_exec.ExecutionResult;
pub const NormalizedRuntimeFailure = shared_exec.NormalizedRuntimeFailure;

pub const ExecuteOptions = struct {
    allocator: std.mem.Allocator,
    runtime_handle: *runtime_handle_mod.RuntimeHandle,
    job_index: *chat_job_index.ChatJobIndex,
    job_id: []const u8,
    input: []const u8,
    correlation_id: ?[]const u8 = null,
    emit_debug: bool = false,
    max_retries: usize = max_internal_retries,
};

pub fn execute(options: ExecuteOptions) !ExecutionResult {
    var outcome = try shared_exec.execute(.{
        .allocator = options.allocator,
        .executor = .{
            .ctx = @ptrCast(options.runtime_handle),
            .execute = executeWithRuntimeHandle,
            .deinit_frames = deinitRuntimeFrames,
        },
        .request_id = options.job_id,
        .input = options.input,
        .correlation_id = options.correlation_id,
        .emit_debug = options.emit_debug,
        .max_retries = options.max_retries,
    });
    errdefer outcome.deinit(options.allocator);

    try options.job_index.markCompleted(
        options.job_id,
        outcome.succeeded,
        outcome.result_text,
        outcome.error_text,
        outcome.log_text,
    );
    return outcome;
}

pub fn normalizeRuntimeFailureForAgent(code: []const u8, message: []const u8) NormalizedRuntimeFailure {
    return shared_exec.normalizeRuntimeFailureForAgent(code, message);
}

pub fn normalizeRuntimeFailure(code: []const u8, message: []const u8) NormalizedRuntimeFailure {
    return shared_exec.normalizeRuntimeFailure(code, message);
}

pub fn isInternalRuntimeLoopGuardText(text: []const u8) bool {
    return shared_exec.isInternalRuntimeLoopGuardText(text);
}

fn executeWithRuntimeHandle(
    raw_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    request_json: []const u8,
    emit_debug: bool,
) ![][]u8 {
    _ = allocator;
    const runtime_handle: *runtime_handle_mod.RuntimeHandle = @ptrCast(@alignCast(raw_ctx orelse return error.InvalidContext));
    return runtime_handle.handleMessageFramesWithDebug(request_json, emit_debug);
}

fn deinitRuntimeFrames(_: ?*anyopaque, allocator: std.mem.Allocator, frames: [][]u8) void {
    runtime_server_mod.deinitResponseFrames(allocator, frames);
}

test "chat_runtime_job: execute completes job index from runtime session.send" {
    const allocator = std.testing.allocator;
    const runtime = try runtime_server_mod.RuntimeServer.create(
        allocator,
        "chat-runtime-job-test",
        .{ .ltm_directory = "", .ltm_filename = "" },
    );
    defer runtime.destroy();

    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime);
    defer runtime_handle.destroy();

    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    const job_id = try job_index.createJob("chat-runtime-job-test", "corr-helper");
    defer allocator.free(job_id);
    try job_index.markRunning(job_id);

    var result = try execute(.{
        .allocator = allocator,
        .runtime_handle = runtime_handle,
        .job_index = &job_index,
        .job_id = job_id,
        .input = "hello runtime",
        .correlation_id = "corr-helper",
    });
    defer result.deinit(allocator);

    try std.testing.expect(result.succeeded);
    try std.testing.expect(std.mem.indexOf(u8, result.result_text, "hello runtime") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.log_text, "\"type\":\"session.receive\"") != null);

    var view = (try job_index.getJob(allocator, job_id)).?;
    defer view.deinit(allocator);
    try std.testing.expectEqual(chat_job_index.JobState.done, view.state);
    try std.testing.expect(view.error_text == null);
    try std.testing.expect(view.result_text != null);
    try std.testing.expect(std.mem.indexOf(u8, view.result_text.?, "hello runtime") != null);
}

test "chat_runtime_job: normalization redacts internal loop guard failures" {
    const normalized = normalizeRuntimeFailureForAgent(
        "execution_failed",
        "provider tool loop exceeded limits",
    );
    try std.testing.expectEqualStrings("runtime_protocol_error", normalized.code);

    const internal_limit = normalizeRuntimeFailureForAgent(
        "provider_request_invalid",
        "provider request invalid",
    );
    try std.testing.expectEqualStrings("runtime_internal_limit", internal_limit.code);
    try std.testing.expect(isInternalRuntimeLoopGuardText(
        "I hit an internal reasoning loop while preparing that response. Please retry.",
    ));
}
