const std = @import("std");
const protocol = @import("spider-protocol").protocol;

pub const RuntimeVTable = struct {
    destroy: *const fn (?*anyopaque, std.mem.Allocator) void,
    handle_message_frames_with_debug: *const fn (?*anyopaque, std.mem.Allocator, []const u8, bool) anyerror![][]u8,
    is_healthy: *const fn (?*anyopaque) bool,
    health_summary: *const fn (?*anyopaque, std.mem.Allocator) anyerror![]u8,
    build_runtime_error_response: ?*const fn (?*anyopaque, std.mem.Allocator, []const u8, anyerror) anyerror![]u8 = null,
};

const UnavailableRuntime = struct {
    code: []u8,
    message: []u8,

    fn destroy(raw_ctx: ?*anyopaque, allocator: std.mem.Allocator) void {
        const ctx: *UnavailableRuntime = @ptrCast(@alignCast(raw_ctx orelse return));
        allocator.free(ctx.code);
        allocator.free(ctx.message);
        allocator.destroy(ctx);
    }

    fn handleMessageFramesWithDebug(
        raw_ctx: ?*anyopaque,
        allocator: std.mem.Allocator,
        raw_json: []const u8,
        emit_debug: bool,
    ) ![][]u8 {
        _ = emit_debug;
        const ctx: *UnavailableRuntime = @ptrCast(@alignCast(raw_ctx orelse return error.InvalidContext));
        const request_id = parseRequestId(allocator, raw_json) catch null;
        defer if (request_id) |value| allocator.free(value);
        const response = try protocol.buildErrorWithCode(
            allocator,
            request_id orelse "unknown",
            .execution_failed,
            ctx.message,
        );
        var frames = try allocator.alloc([]u8, 1);
        frames[0] = response;
        return frames;
    }

    fn isHealthy(_: ?*anyopaque) bool {
        return true;
    }

    fn healthSummary(raw_ctx: ?*anyopaque, allocator: std.mem.Allocator) ![]u8 {
        const ctx: *UnavailableRuntime = @ptrCast(@alignCast(raw_ctx orelse return error.InvalidContext));
        return allocator.dupe(u8, ctx.message);
    }

    fn buildRuntimeErrorResponse(
        raw_ctx: ?*anyopaque,
        allocator: std.mem.Allocator,
        request_id: []const u8,
        _: anyerror,
    ) ![]u8 {
        const ctx: *UnavailableRuntime = @ptrCast(@alignCast(raw_ctx orelse return error.InvalidContext));
        return protocol.buildErrorWithCode(allocator, request_id, .execution_failed, ctx.message);
    }
};

pub const RuntimeHandle = struct {
    allocator: std.mem.Allocator,
    ctx: ?*anyopaque,
    vtable: RuntimeVTable,
    ref_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn init(
        allocator: std.mem.Allocator,
        ctx: ?*anyopaque,
        vtable: RuntimeVTable,
    ) !*RuntimeHandle {
        const handle = try allocator.create(RuntimeHandle);
        handle.* = .{
            .allocator = allocator,
            .ctx = ctx,
            .vtable = vtable,
            .ref_count = std.atomic.Value(u32).init(1),
        };
        return handle;
    }

    pub fn createUnavailable(allocator: std.mem.Allocator, code: []const u8, message: []const u8) !*RuntimeHandle {
        const ctx = try allocator.create(UnavailableRuntime);
        errdefer allocator.destroy(ctx);
        ctx.* = .{
            .code = try allocator.dupe(u8, code),
            .message = try allocator.dupe(u8, message),
        };
        errdefer {
            allocator.free(ctx.code);
            allocator.free(ctx.message);
        }
        return init(allocator, ctx, .{
            .destroy = UnavailableRuntime.destroy,
            .handle_message_frames_with_debug = UnavailableRuntime.handleMessageFramesWithDebug,
            .is_healthy = UnavailableRuntime.isHealthy,
            .health_summary = UnavailableRuntime.healthSummary,
            .build_runtime_error_response = UnavailableRuntime.buildRuntimeErrorResponse,
        });
    }

    pub fn retain(self: *RuntimeHandle) void {
        const previous = self.ref_count.fetchAdd(1, .monotonic);
        std.debug.assert(previous > 0);
    }

    pub fn release(self: *RuntimeHandle) void {
        const previous = self.ref_count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) self.destroyOwned();
    }

    pub fn destroy(self: *RuntimeHandle) void {
        self.release();
    }

    fn destroyOwned(self: *RuntimeHandle) void {
        self.vtable.destroy(self.ctx, self.allocator);
        self.allocator.destroy(self);
    }

    pub fn handleMessageFramesWithDebug(
        self: *RuntimeHandle,
        raw_json: []const u8,
        emit_debug: bool,
    ) ![][]u8 {
        return self.vtable.handle_message_frames_with_debug(self.ctx, self.allocator, raw_json, emit_debug);
    }

    pub fn buildRuntimeErrorResponse(self: *RuntimeHandle, request_id: []const u8, err: anyerror) ![]u8 {
        if (self.vtable.build_runtime_error_response) |func| {
            return func(self.ctx, self.allocator, request_id, err);
        }
        const message = try std.fmt.allocPrint(self.allocator, "runtime error: {s}", .{@errorName(err)});
        defer self.allocator.free(message);
        return protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, message);
    }

    pub fn isHealthy(self: *RuntimeHandle) bool {
        return self.vtable.is_healthy(self.ctx);
    }

    pub fn healthSummary(self: *RuntimeHandle, allocator: std.mem.Allocator) ![]u8 {
        return self.vtable.health_summary(self.ctx, allocator);
    }
};

fn parseRequestId(allocator: std.mem.Allocator, raw_json: []const u8) !?[]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const value = parsed.value.object.get("id") orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return @as(?[]u8, try allocator.dupe(u8, value.string));
}
