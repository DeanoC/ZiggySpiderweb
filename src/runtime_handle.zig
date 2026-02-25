const std = @import("std");
const protocol = @import("ziggy-spider-protocol").protocol;
const runtime_server_mod = @import("runtime_server.zig");
const sandbox_runtime = @import("sandbox_runtime.zig");

pub const Kind = enum {
    local,
    local_sandbox,
    sandbox,
};

pub const RuntimeHandle = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    local: ?*runtime_server_mod.RuntimeServer = null,
    sandbox: ?*sandbox_runtime.SandboxRuntime = null,
    ref_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    pub fn createLocal(
        allocator: std.mem.Allocator,
        runtime: *runtime_server_mod.RuntimeServer,
    ) !*RuntimeHandle {
        const handle = try allocator.create(RuntimeHandle);
        handle.* = .{
            .allocator = allocator,
            .kind = .local,
            .local = runtime,
            .sandbox = null,
            .ref_count = std.atomic.Value(u32).init(1),
        };
        return handle;
    }

    pub fn createSandbox(
        allocator: std.mem.Allocator,
        runtime: *sandbox_runtime.SandboxRuntime,
    ) !*RuntimeHandle {
        const handle = try allocator.create(RuntimeHandle);
        handle.* = .{
            .allocator = allocator,
            .kind = .sandbox,
            .local = null,
            .sandbox = runtime,
            .ref_count = std.atomic.Value(u32).init(1),
        };
        return handle;
    }

    pub fn createLocalWithSandbox(
        allocator: std.mem.Allocator,
        runtime: *runtime_server_mod.RuntimeServer,
        sandbox: *sandbox_runtime.SandboxRuntime,
    ) !*RuntimeHandle {
        const handle = try allocator.create(RuntimeHandle);
        handle.* = .{
            .allocator = allocator,
            .kind = .local_sandbox,
            .local = runtime,
            .sandbox = sandbox,
            .ref_count = std.atomic.Value(u32).init(1),
        };
        return handle;
    }

    fn destroyOwned(self: *RuntimeHandle) void {
        switch (self.kind) {
            .local => {
                if (self.local) |runtime| runtime.destroy();
            },
            .local_sandbox => {
                if (self.local) |runtime| runtime.destroy();
                if (self.sandbox) |runtime| runtime.destroy();
            },
            .sandbox => {
                if (self.sandbox) |runtime| runtime.destroy();
            },
        }
        self.allocator.destroy(self);
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

    pub fn handleMessageFramesWithDebug(
        self: *RuntimeHandle,
        raw_json: []const u8,
        emit_debug: bool,
    ) ![][]u8 {
        return switch (self.kind) {
            .local => self.local.?.handleMessageFramesWithDebug(raw_json, emit_debug),
            .local_sandbox => self.local.?.handleMessageFramesWithDebug(raw_json, emit_debug),
            .sandbox => self.sandbox.?.handleMessageFramesWithDebug(raw_json, emit_debug),
        };
    }

    pub fn buildRuntimeErrorResponse(self: *RuntimeHandle, request_id: []const u8, err: anyerror) ![]u8 {
        return switch (self.kind) {
            .local => self.local.?.buildRuntimeErrorResponse(request_id, err),
            .local_sandbox => self.local.?.buildRuntimeErrorResponse(request_id, err),
            .sandbox => blk: {
                const message = try std.fmt.allocPrint(self.allocator, "sandbox runtime error: {s}", .{@errorName(err)});
                defer self.allocator.free(message);
                break :blk protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, message);
            },
        };
    }

    pub fn isHealthy(self: *RuntimeHandle) bool {
        return switch (self.kind) {
            .local => true,
            .local_sandbox => if (self.sandbox) |runtime| runtime.isHealthy() else false,
            .sandbox => if (self.sandbox) |runtime| runtime.isHealthy() else false,
        };
    }
};
