const std = @import("std");
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const brain_tools = @import("brain_tools.zig");
const primitives = @import("ziggy-runtime-hooks").hook_primitives;

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
        // Free scratch values
        var scratch_it = self.scratch.iterator();
        while (scratch_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.scratch.deinit(allocator);

        // Free trace entries
        for (self.trace.items) |entry| {
            allocator.free(entry);
        }
        self.trace.deinit(allocator);
    }

    /// Set a scratch value for inter-hook communication
    pub fn setScratch(self: *HookContext, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
        // Allocate new key and value first
        const owned_key = try allocator.dupe(u8, key);
        errdefer allocator.free(owned_key);

        const owned_value = try allocator.dupe(u8, value);
        errdefer allocator.free(owned_value);

        // Check if entry exists - if so, remove and free old entry
        if (self.scratch.fetchRemove(key)) |old_entry| {
            allocator.free(old_entry.key);
            allocator.free(old_entry.value);
        }

        try self.scratch.put(allocator, owned_key, owned_value);
    }

    /// Get a scratch value
    pub fn getScratch(self: *const HookContext, key: []const u8) ?[]const u8 {
        return self.scratch.get(key);
    }

    /// Add a trace entry
    pub fn tracef(self: *HookContext, allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
        const message = try std.fmt.allocPrint(allocator, fmt, args);
        errdefer allocator.free(message);
        try self.trace.append(allocator, message);
    }
};

/// Result of Observe phase
pub const ObserveResult = struct {
    core: *const CorePrompt,
    inbox_count: usize,
    // TODO: Add more observe data as needed
};

/// Pending tool calls before execution
pub const PendingTools = primitives.PendingTools;

/// Results from tool execution
pub const ToolResults = struct {
    results: []const brain_tools.ToolResult,
};

/// Results before being stored as memory artifacts
pub const ResultsData = struct {
    tool_results: *const ToolResults,
    // TODO: Add other result data
};

/// Checkpoint data for PostResults
pub const CheckpointData = struct {
    tick: u64,
    artifacts_count: usize,
    // TODO: Add more checkpoint data
};

/// Hook function signature
pub const HookFn = *const fn (
    ctx: *HookContext,
    data: HookData,
) HookError!void;

/// Individual hook registration
pub const Hook = struct {
    name: []const u8, // For debugging/logging
    priority: i16, // Lower = earlier in pipeline
    callback: HookFn,
};

/// Registry for all hooks, organized by phase
pub const HookRegistry = struct {
    allocator: std.mem.Allocator,

    // Sorted arrays (maintained in priority order)
    pre_observe: std.ArrayListUnmanaged(Hook),
    post_observe: std.ArrayListUnmanaged(Hook),
    pre_mutate: std.ArrayListUnmanaged(Hook),
    post_mutate: std.ArrayListUnmanaged(Hook),
    pre_results: std.ArrayListUnmanaged(Hook),
    post_results: std.ArrayListUnmanaged(Hook),

    pub fn init(allocator: std.mem.Allocator) HookRegistry {
        return .{
            .allocator = allocator,
            .pre_observe = .{},
            .post_observe = .{},
            .pre_mutate = .{},
            .post_mutate = .{},
            .pre_results = .{},
            .post_results = .{},
        };
    }

    pub fn deinit(self: *HookRegistry) void {
        self.pre_observe.deinit(self.allocator);
        self.post_observe.deinit(self.allocator);
        self.pre_mutate.deinit(self.allocator);
        self.post_mutate.deinit(self.allocator);
        self.pre_results.deinit(self.allocator);
        self.post_results.deinit(self.allocator);
    }

    /// Register a hook for a specific phase (inserted in priority order)
    pub fn register(self: *HookRegistry, phase: HookPhase, hook: Hook) !void {
        const list = self.listForPhase(phase);

        // Find insertion point (maintain sorted order by priority)
        var insert_idx: usize = list.items.len;
        for (list.items, 0..) |existing, i| {
            if (hook.priority < existing.priority) {
                insert_idx = i;
                break;
            }
        }

        try list.insert(self.allocator, insert_idx, hook);
    }

    /// Execute all hooks for a phase in priority order
    pub fn execute(self: *HookRegistry, phase: HookPhase, ctx: *HookContext, data: HookData) !void {
        const list = self.listForPhase(phase);

        // Update context phase before invoking callbacks
        ctx.phase = phase;

        for (list.items) |hook| {
            hook.callback(ctx, data) catch |err| {
                std.log.err("Hook '{s}' failed in {s}: {s}", .{ hook.name, @tagName(phase), @errorName(err) });
                return HookError.HookFailed;
            };
        }
    }

    /// Get the hook list for a phase
    fn listForPhase(self: *HookRegistry, phase: HookPhase) *std.ArrayListUnmanaged(Hook) {
        return switch (phase) {
            .pre_observe => &self.pre_observe,
            .post_observe => &self.post_observe,
            .pre_mutate => &self.pre_mutate,
            .post_mutate => &self.post_mutate,
            .pre_results => &self.pre_results,
            .post_results => &self.post_results,
        };
    }

    /// Get hook count for a phase (for debugging)
    pub fn countForPhase(self: *const HookRegistry, phase: HookPhase) usize {
        return switch (phase) {
            .pre_observe => self.pre_observe.items.len,
            .post_observe => self.post_observe.items.len,
            .pre_mutate => self.pre_mutate.items.len,
            .post_mutate => self.post_mutate.items.len,
            .pre_results => self.pre_results.items.len,
            .post_results => self.post_results.items.len,
        };
    }
};

// Tests

test "Rom: set and get" {
    const allocator = std.testing.allocator;

    var rom = Rom.init(allocator);
    defer rom.deinit();

    try rom.set("key1", "value1");
    try std.testing.expectEqualStrings("value1", rom.get("key1").?);

    // Overwrite
    try rom.set("key1", "value2");
    try std.testing.expectEqualStrings("value2", rom.get("key1").?);

    // Missing key
    try std.testing.expect(rom.get("missing") == null);
}

test "HookRegistry: priority ordering" {
    const allocator = std.testing.allocator;

    var registry = HookRegistry.init(allocator);
    defer registry.deinit();

    const HookA = struct {
        fn callback(_: *HookContext, _: HookData) HookError!void {}
    };

    const HookB = struct {
        fn callback(_: *HookContext, _: HookData) HookError!void {}
    };

    const HookC = struct {
        fn callback(_: *HookContext, _: HookData) HookError!void {}
    };

    // Register out of order
    try registry.register(.pre_observe, .{ .name = "middle", .priority = 0, .callback = HookA.callback });
    try registry.register(.pre_observe, .{ .name = "first", .priority = -100, .callback = HookB.callback });
    try registry.register(.pre_observe, .{ .name = "last", .priority = 100, .callback = HookC.callback });

    // Verify insertion order (should be sorted)
    try std.testing.expectEqual(@as(i16, -100), registry.pre_observe.items[0].priority);
    try std.testing.expectEqual(@as(i16, 0), registry.pre_observe.items[1].priority);
    try std.testing.expectEqual(@as(i16, 100), registry.pre_observe.items[2].priority);
}

test "HookContext: scratch space" {
    const allocator = std.testing.allocator;

    var ctx = HookContext.init(undefined, "test", 1);
    defer ctx.deinit(allocator);

    try ctx.setScratch(allocator, "key1", "value1");
    try std.testing.expectEqualStrings("value1", ctx.getScratch("key1").?);

    // Overwrite
    try ctx.setScratch(allocator, "key1", "value2");
    try std.testing.expectEqualStrings("value2", ctx.getScratch("key1").?);
}
