const std = @import("std");
const hook_registry = @import("hook_registry.zig");
const HookContext = hook_registry.HookContext;
const HookData = hook_registry.HookData;
const HookError = hook_registry.HookError;
const Rom = hook_registry.Rom;
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;

/// Load shared/base ROM from identity files
pub fn loadSharedRomHook(ctx: *HookContext, data: HookData) HookError!void {
    const rom = data.pre_observe;
    const allocator = ctx.runtime.allocator;
    
    // Load SOUL.md
    const soul_content = loadIdentityFile(allocator, ctx.runtime, ctx.brain_name, "SOUL.md") catch |err| {
        std.log.warn("Failed to load SOUL.md for {s}: {s}", .{ ctx.brain_name, @errorName(err) });
        // Continue without soul - not fatal
        return;
    };
    defer if (soul_content) |c| allocator.free(c);
    
    if (soul_content) |content| {
        try rom.set("identity:soul", content);
    }
    
    // Load AGENT.md
    const agent_content = loadIdentityFile(allocator, ctx.runtime, ctx.brain_name, "AGENT.md") catch |err| {
        std.log.warn("Failed to load AGENT.md for {s}: {s}", .{ ctx.brain_name, @errorName(err) });
        return;
    };
    defer if (agent_content) |c| allocator.free(c);
    
    if (agent_content) |content| {
        try rom.set("identity:agent", content);
    }
    
    // Load IDENTITY.md (primary brains only)
    const identity_content = loadIdentityFile(allocator, ctx.runtime, ctx.brain_name, "IDENTITY.md") catch |err| {
        // Optional file, not an error if missing
        if (err != error.FileNotFound) {
            std.log.warn("Failed to load IDENTITY.md for {s}: {s}", .{ ctx.brain_name, @errorName(err) });
        }
        return;
    };
    defer if (identity_content) |c| allocator.free(c);
    
    if (identity_content) |content| {
        try rom.set("identity:public", content);
    }
    
    // Load agent.json for capabilities
    const agent_json = loadAgentJson(allocator, ctx.runtime, ctx.brain_name) catch |err| {
        std.log.warn("Failed to load agent.json for {s}: {s}", .{ ctx.brain_name, @errorName(err) });
        return;
    };
    defer if (agent_json) |c| allocator.free(c);
    
    if (agent_json) |content| {
        try rom.set("system:capabilities", content);
    }
    
    // System constants
    try rom.set("system:agent_id", ctx.runtime.agent_id);
    try rom.set("system:brain_name", ctx.brain_name);
    
    const tick_str = std.fmt.allocPrint(allocator, "{d}", .{ctx.tick}) catch return HookError.OutOfMemory;
    defer allocator.free(tick_str);
    try rom.set("system:tick", tick_str);
    
    // Brain type detection
    const is_primary = std.mem.eql(u8, ctx.brain_name, "primary");
    try rom.set("system:is_primary", if (is_primary) "true" else "false");
}

/// Inject runtime status into ROM
pub fn injectRuntimeStatusHook(ctx: *HookContext, data: HookData) HookError!void {
    const rom = data.pre_observe;
    const allocator = ctx.runtime.allocator;
    
    // Queue depths
    const inbound_count = ctx.runtime.bus.pendingCount();
    const inbound_str = std.fmt.allocPrint(allocator, "{d}", .{inbound_count}) catch return HookError.OutOfMemory;
    defer allocator.free(inbound_str);
    try rom.set("status:inbound_queue", inbound_str);
    
    // Tick queue depth
    const tick_count = ctx.runtime.tick_queue.items.len;
    const tick_str = std.fmt.allocPrint(allocator, "{d}", .{tick_count}) catch return HookError.OutOfMemory;
    defer allocator.free(tick_str);
    try rom.set("status:tick_queue", tick_str);
    
    // Runtime state
    try rom.set("status:runtime_state", @tagName(ctx.runtime.state));
    
    // Timestamp
    const now = std.time.timestamp();
    const time_str = std.fmt.allocPrint(allocator, "{d}", .{now}) catch return HookError.OutOfMemory;
    defer allocator.free(time_str);
    try rom.set("status:timestamp", time_str);
}

/// Persist LTM after results (PostResults hook)
pub fn persistLtmHook(ctx: *HookContext, data: HookData) HookError!void {
    const checkpoint = data.post_results;
    _ = checkpoint;
    
    // TODO: Implement actual persistence
    // For now, just log
    std.log.debug("PostResults: Persisting LTM for {s} tick {d}", .{ ctx.brain_name, ctx.tick });
    
    // Trigger checkpoint in active memory
    // ctx.runtime.active_memory.checkpoint(ctx.tick) catch |err| {
    //     std.log.err("Failed to checkpoint: {s}", .{@errorName(err)});
    //     return HookError.HookFailed;
    // };
}

/// Log hook execution for debugging (PostObserve)
pub fn logObserveHook(ctx: *HookContext, data: HookData) HookError!void {
    const result = data.post_observe;
    
    std.log.debug("Observe: brain={s} tick={d} inbox={d}", .{
        ctx.brain_name,
        ctx.tick,
        result.inbox_count,
    });
}

/// Log tool execution (PostMutate)
pub fn logMutateHook(ctx: *HookContext, data: HookData) HookError!void {
    const results = data.post_mutate;
    
    std.log.debug("Mutate: brain={s} tick={d} tools={d}", .{
        ctx.brain_name,
        ctx.tick,
        results.results.len,
    });
    
    for (results.results) |result| {
        const status = if (result.success) "OK" else "FAIL";
        std.log.debug("  {s}: {s}", .{ result.tool_name, status });
    }
}

// Helper functions

fn loadIdentityFile(
    allocator: std.mem.Allocator,
    runtime: *AgentRuntime,
    brain_name: []const u8,
    filename: []const u8,
) !?[]u8 {
    // Construct path: agents/{agent_id}/{brain_name}/{filename}
    // For primary brain, use agent root; for sub-brains, use sub-directory
    const path = try std.fs.path.join(allocator, &.{
        runtime.agent_id,
        if (std.mem.eql(u8, brain_name, "primary")) "" else brain_name,
        filename,
    });
    defer allocator.free(path);
    
    // Clean up double slashes
    const clean_path = try std.fs.path.resolve(allocator, &.{path});
    defer allocator.free(clean_path);
    
    const content = std.fs.cwd().readFileAlloc(allocator, clean_path, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    
    return content;
}

fn loadAgentJson(
    allocator: std.mem.Allocator,
    runtime: *AgentRuntime,
    brain_name: []const u8,
) !?[]u8 {
    return loadIdentityFile(allocator, runtime, brain_name, "agent.json");
}

/// Register all system hooks
pub fn registerSystemHooks(registry: *hook_registry.HookRegistry) !void {
    // PRE_OBSERVE: ROM loading pipeline
    try registry.register(.pre_observe, .{
        .name = "system:load-shared-rom",
        .priority = @intFromEnum(hook_registry.HookPriority.system_first),
        .callback = loadSharedRomHook,
    });
    
    // Brain specializations go here (priority 0)
    
    try registry.register(.pre_observe, .{
        .name = "system:inject-runtime-status",
        .priority = @intFromEnum(hook_registry.HookPriority.system_last) - 1,
        .callback = injectRuntimeStatusHook,
    });
    
    // POST_OBSERVE: Logging
    try registry.register(.post_observe, .{
        .name = "system:log-observe",
        .priority = @intFromEnum(hook_registry.HookPriority.system_last),
        .callback = logObserveHook,
    });
    
    // POST_MUTATE: Logging
    try registry.register(.post_mutate, .{
        .name = "system:log-mutate",
        .priority = @intFromEnum(hook_registry.HookPriority.system_last),
        .callback = logMutateHook,
    });
    
    // POST_RESULTS: Persistence
    try registry.register(.post_results, .{
        .name = "system:persist-ltm",
        .priority = @intFromEnum(hook_registry.HookPriority.system_last),
        .callback = persistLtmHook,
    });
}

// Brain specialization hook factory
pub fn createBrainSpecializationHook(
    allocator: std.mem.Allocator,
    brain_name: []const u8,
    allowed_tools: ?[]const []const u8,
    additional_rom: ?[]const hook_registry.RomEntry,
) !hook_registry.HookFn {
    _ = allocator;
    _ = brain_name;
    _ = allowed_tools;
    _ = additional_rom;
    
    // TODO: Store specialization data and return a hook that applies it
    return struct {
        fn callback(ctx: *HookContext, data: HookData) HookError!void {
            const rom = data.pre_observe;
            _ = rom;
            _ = ctx;
            // Apply brain-specific ROM overlays
        }
    }.callback;
}
