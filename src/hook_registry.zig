const std = @import("std");
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const brain_tools = @import("brain_tools.zig");
const primitives = @import("ziggy-runtime-hooks").hook_primitives;
const engine = @import("ziggy-runtime-hooks").hook_registry_engine;

pub const HookPhase = primitives.HookPhase;
pub const HookError = primitives.HookError;
pub const HookPriority = primitives.HookPriority;
pub const CoreEntry = primitives.CoreEntry;
pub const RomEntry = primitives.RomEntry;
pub const CorePrompt = primitives.CorePrompt;
pub const Rom = primitives.Rom;

/// Data passed to hooks varies by phase
pub const HookData = union(HookPhase) {
    pre_observe: *CorePrompt,
    post_observe: *ObserveResult,
    pre_mutate: *PendingTools,
    post_mutate: *ToolResults,
    pre_results: *ResultsData,
    post_results: *CheckpointData,
};

/// Context passed to every hook
pub const HookContext = struct {
    runtime: *AgentRuntime,
    brain_name: []const u8,
    phase: HookPhase,
    tick: u64,

    /// Scratch space for hooks to communicate (single tick only)
    scratch: std.StringHashMapUnmanaged([]const u8),

    /// Logging/metrics accumulator
    trace: std.ArrayListUnmanaged([]const u8),

    pub fn init(runtime: *AgentRuntime, brain_name: []const u8, tick: u64) HookContext {
        return .{
            .runtime = runtime,
            .brain_name = brain_name,
            .phase = .pre_observe,
            .tick = tick,
            .scratch = .{},
            .trace = .{},
        };
    }

    pub fn deinit(self: *HookContext, allocator: std.mem.Allocator) void {
        var scratch_it = self.scratch.iterator();
        while (scratch_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.scratch.deinit(allocator);

        for (self.trace.items) |entry| {
            allocator.free(entry);
        }
        self.trace.deinit(allocator);
    }

    pub fn setScratch(self: *HookContext, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
        const owned_key = try allocator.dupe(u8, key);
        errdefer allocator.free(owned_key);

        const owned_value = try allocator.dupe(u8, value);
        errdefer allocator.free(owned_value);

        if (self.scratch.fetchRemove(key)) |old_entry| {
            allocator.free(old_entry.key);
            allocator.free(old_entry.value);
        }

        try self.scratch.put(allocator, owned_key, owned_value);
    }

    pub fn getScratch(self: *const HookContext, key: []const u8) ?[]const u8 {
        return self.scratch.get(key);
    }

    pub fn tracef(self: *HookContext, allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
        const message = try std.fmt.allocPrint(allocator, fmt, args);
        errdefer allocator.free(message);
        try self.trace.append(allocator, message);
    }
};

pub const ObserveResult = struct {
    core: *const CorePrompt,
    inbox_count: usize,
};

pub const PendingTools = primitives.PendingTools;

pub const ToolResults = struct {
    results: []const brain_tools.ToolResult,
};

pub const ResultsData = struct {
    tool_results: *const ToolResults,
};

pub const CheckpointData = struct {
    tick: u64,
    artifacts_count: usize,
};

pub const HookFn = *const fn (
    ctx: *HookContext,
    data: HookData,
) HookError!void;

pub const Hook = engine.Hook(HookContext, HookData);
const HookRegistryEngine = engine.HookRegistry(HookContext, HookData);

/// Adapter layer: Spiderweb-specific context/data types around shared engine.
pub const HookRegistry = struct {
    inner: HookRegistryEngine,

    pub fn init(allocator: std.mem.Allocator) HookRegistry {
        return .{ .inner = HookRegistryEngine.init(allocator) };
    }

    pub fn deinit(self: *HookRegistry) void {
        self.inner.deinit();
    }

    pub fn register(self: *HookRegistry, phase: HookPhase, hook: Hook) !void {
        try self.inner.register(phase, hook);
    }

    pub fn execute(self: *HookRegistry, phase: HookPhase, ctx: *HookContext, data: HookData) !void {
        // Preserve existing runtime behavior: context phase is updated per execution pass.
        ctx.phase = phase;
        try self.inner.execute(phase, ctx, data);
    }

    pub fn countForPhase(self: *const HookRegistry, phase: HookPhase) usize {
        return self.inner.countForPhase(phase);
    }
};

test "HookContext: scratch space" {
    const allocator = std.testing.allocator;

    var ctx = HookContext.init(undefined, "test", 1);
    defer ctx.deinit(allocator);

    try ctx.setScratch(allocator, "key1", "value1");
    try std.testing.expectEqualStrings("value1", ctx.getScratch("key1").?);

    try ctx.setScratch(allocator, "key1", "value2");
    try std.testing.expectEqualStrings("value2", ctx.getScratch("key1").?);
}

test "HookRegistry adapter: priority ordering" {
    const allocator = std.testing.allocator;

    var registry = HookRegistry.init(allocator);
    defer registry.deinit();

    var core = CorePrompt.init(allocator);
    defer core.deinit();

    var ctx = HookContext.init(undefined, "test", 42);
    defer ctx.deinit(allocator);

    const State = struct {
        var order: [8]u8 = undefined;
        var len: usize = 0;
    };
    State.len = 0;

    const Hooks = struct {
        fn middle(_: *HookContext, _: HookData) HookError!void {
            State.order[State.len] = 2;
            State.len += 1;
        }
        fn first(_: *HookContext, _: HookData) HookError!void {
            State.order[State.len] = 1;
            State.len += 1;
        }
        fn last(_: *HookContext, _: HookData) HookError!void {
            State.order[State.len] = 3;
            State.len += 1;
        }
    };

    try registry.register(.pre_observe, .{ .name = "middle", .priority = 0, .callback = Hooks.middle });
    try registry.register(.pre_observe, .{ .name = "first", .priority = -100, .callback = Hooks.first });
    try registry.register(.pre_observe, .{ .name = "last", .priority = 100, .callback = Hooks.last });

    try registry.execute(.pre_observe, &ctx, .{ .pre_observe = &core });

    try std.testing.expectEqual(HookPhase.pre_observe, ctx.phase);
    try std.testing.expectEqual(@as(usize, 3), State.len);
    try std.testing.expectEqual(@as(u8, 1), State.order[0]);
    try std.testing.expectEqual(@as(u8, 2), State.order[1]);
    try std.testing.expectEqual(@as(u8, 3), State.order[2]);
}

test "HookRegistry adapter: failure propagation and stop-on-error" {
    const allocator = std.testing.allocator;

    var registry = HookRegistry.init(allocator);
    defer registry.deinit();

    var core = CorePrompt.init(allocator);
    defer core.deinit();

    var ctx = HookContext.init(undefined, "test", 99);
    defer ctx.deinit(allocator);

    const State = struct {
        var order: [8]u8 = undefined;
        var len: usize = 0;
    };
    State.len = 0;

    const Hooks = struct {
        fn first(_: *HookContext, _: HookData) HookError!void {
            State.order[State.len] = 1;
            State.len += 1;
        }
        fn fail(_: *HookContext, _: HookData) HookError!void {
            State.order[State.len] = 2;
            State.len += 1;
            return HookError.HookFailed;
        }
        fn should_not_run(_: *HookContext, _: HookData) HookError!void {
            State.order[State.len] = 3;
            State.len += 1;
        }
    };

    try registry.register(.pre_observe, .{ .name = "first", .priority = -100, .callback = Hooks.first });
    try registry.register(.pre_observe, .{ .name = "fail", .priority = 0, .callback = Hooks.fail });
    try registry.register(.pre_observe, .{ .name = "later", .priority = 100, .callback = Hooks.should_not_run });

    try std.testing.expectError(HookError.HookFailed, registry.execute(.pre_observe, &ctx, .{ .pre_observe = &core }));

    try std.testing.expectEqual(HookPhase.pre_observe, ctx.phase);
    try std.testing.expectEqual(@as(usize, 2), State.len);
    try std.testing.expectEqual(@as(u8, 1), State.order[0]);
    try std.testing.expectEqual(@as(u8, 2), State.order[1]);
}
