const std = @import("std");
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const brain_tools = @import("brain_tools.zig");

pub const HookPhase = enum {
    pre_observe,
    post_observe,
    pre_mutate,
    post_mutate,
    pre_results,
    post_results,
};

pub const HookError = error{
    HookFailed,
    InvalidPhase,
    OutOfMemory,
};

pub const HookPriority = enum(i16) {
    /// System-first hooks (ROM loading, validation)
    system_first = -1000,

    /// Default priority for brain specializations
    normal = 0,

    /// System-last hooks (metrics, cleanup)
    system_last = 1000,
};

/// ROM entry for PreObserve hook pipeline
pub const RomEntry = struct {
    key: []const u8,
    value: []const u8,
    mutable: bool = true,
};

/// Simple ROM structure for PreObserve pipeline
pub const Rom = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMapUnmanaged(RomEntry),

    pub fn init(allocator: std.mem.Allocator) Rom {
        return .{
            .allocator = allocator,
            .entries = .{},
        };
    }

    pub fn deinit(self: *Rom) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.value);
        }
        self.entries.deinit(self.allocator);
    }

    /// Set a key-value pair in ROM (always mutable during PreObserve)
    pub fn set(self: *Rom, key: []const u8, value: []const u8) !void {
        // Check if entry exists
        if (self.entries.getEntry(key)) |existing| {
            // Update existing entry - free old value, keep key
            const old_value = existing.value_ptr.value;
            const new_value = try self.allocator.dupe(u8, value);
            existing.value_ptr.value = new_value;
            self.allocator.free(old_value);
            return;
        }

        // New entry - allocate both key and value
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        try self.entries.put(self.allocator, owned_key, .{
            .key = owned_key,
            .value = owned_value,
            .mutable = true,
        });
    }

    /// Get a value from ROM
    pub fn get(self: *const Rom, key: []const u8) ?[]const u8 {
        const entry = self.entries.get(key) orelse return null;
        return entry.value;
    }

    /// Check if key exists
    pub fn has(self: *const Rom, key: []const u8) bool {
        return self.entries.contains(key);
    }

    /// Get all keys (for debugging)
    pub fn keys(self: *const Rom, allocator: std.mem.Allocator) ![][]const u8 {
        var result = std.ArrayList([]const u8).init(allocator);
        errdefer result.deinit();

        var it = self.entries.keyIterator();
        while (it.next()) |key| {
            try result.append(key.*);
        }

        return result.toOwnedSlice();
    }
};

/// Data passed to hooks varies by phase
pub const HookData = union(HookPhase) {
    pre_observe: *Rom,
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
    rom: *const Rom,
    inbox_count: usize,
    // TODO: Add more observe data as needed
};

/// Pending tool calls before execution
pub const PendingTools = struct {
    tools: std.ArrayListUnmanaged(ToolCall),

    pub const ToolCall = struct {
        name: []const u8,
        args_json: []const u8,
    };

    pub fn init() PendingTools {
        return .{ .tools = .{} };
    }

    pub fn deinit(self: *PendingTools, allocator: std.mem.Allocator) void {
        for (self.tools.items) |*tool| {
            allocator.free(tool.name);
            allocator.free(tool.args_json);
        }
        self.tools.deinit(allocator);
    }

    pub fn add(self: *PendingTools, allocator: std.mem.Allocator, name: []const u8, args_json: []const u8) !void {
        const owned_name = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_name);

        const owned_args = try allocator.dupe(u8, args_json);
        errdefer allocator.free(owned_args);

        try self.tools.append(allocator, .{
            .name = owned_name,
            .args_json = owned_args,
        });
    }
};

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
    name: []const u8,  // For debugging/logging
    priority: i16,     // Lower = earlier in pipeline
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

        for (list.items) |hook| {
            hook.callback(ctx, data) catch |err| {
                std.log.err("Hook '{s}' failed in {s}: {s}", .{
                    hook.name, @tagName(phase), @errorName(err)
                });
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
