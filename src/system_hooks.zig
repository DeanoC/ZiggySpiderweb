const std = @import("std");
const hook_registry = @import("hook_registry.zig");
const HookContext = hook_registry.HookContext;
const HookData = hook_registry.HookData;
const HookError = hook_registry.HookError;
const Rom = hook_registry.Rom;
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const brain_tools = @import("brain_tools.zig");
const memory = @import("memory.zig");
const memid = @import("memid.zig");

/// System paths for templates
const TEMPLATE_DIR = "templates";
const FIRST_BOOT_FLAG = ".first_boot_complete";

/// Load identity from LTM into ROM, or hatch from templates if first boot
pub fn loadSharedRomHook(ctx: *HookContext, data: HookData) HookError!void {
    const rom = data.pre_observe;
    const allocator = ctx.runtime.allocator;
    const agent_id = ctx.runtime.agent_id;
    const brain_name = ctx.brain_name;

    // Check if this is the first boot (no flag file exists)
    const is_first_boot = checkFirstBoot(allocator) catch |err| blk: {
        std.log.warn("Failed to check first boot status: {s}", .{@errorName(err)});
        break :blk false;
    };

    // Build fixed names for identity memories (used for stable MemIds)
    // Note: using '.' separator since ':' is reserved for memid format
    const soul_name = "system.soul";
    const agent_name = "system.agent";
    const identity_name = "system.identity";

    // Try to load from LTM first (already hatched)
    var soul_loaded = try loadIdentityFromLTM(ctx, "system.soul", "identity:soul", rom);
    var agent_loaded = try loadIdentityFromLTM(ctx, "system.agent", "identity:agent", rom);
    var identity_loaded = try loadIdentityFromLTM(ctx, "system.identity", "identity:public", rom);

    // If not in LTM, hatch from templates
    if (!soul_loaded or !agent_loaded or !identity_loaded) {
        std.log.info("Hatching new agent: {s}/{s}", .{ agent_id, brain_name });

        // Load from templates and create LTM entries
        if (!soul_loaded) {
            soul_loaded = try hatchIdentityFromTemplate(ctx, "SOUL.md", soul_name, "identity:soul", rom);
        }
        if (!agent_loaded) {
            agent_loaded = try hatchIdentityFromTemplate(ctx, "AGENT.md", agent_name, "identity:agent", rom);
        }
        if (!identity_loaded) {
            identity_loaded = try hatchIdentityFromTemplate(ctx, "IDENTITY.md", identity_name, "identity:public", rom);
        }

        // Send first message (hatch complete signal)
        if (is_first_boot) {
            try sendFirstMessage(ctx, "BOOTSTRAP.md");
            // Mark first boot complete
            markFirstBootComplete(allocator) catch |err| {
                std.log.warn("Failed to mark first boot complete: {s}", .{@errorName(err)});
            };
        } else {
            try sendFirstMessage(ctx, "JUST_HATCHED.md");
        }
    }

    // Load agent.json config (if exists)
    const agent_json = loadAgentJson(allocator, ctx.runtime, brain_name) catch |err| blk: {
        std.log.warn("Failed to load agent.json for {s}: {s}", .{ brain_name, @errorName(err) });
        break :blk null;
    };
    defer if (agent_json) |c| allocator.free(c);

    if (agent_json) |content| {
        try rom.set("system:agent_config", content);
    }

    // Load available tool schemas
    const tool_schemas = try getToolSchemas(allocator);
    defer allocator.free(tool_schemas);
    try rom.set("system:capabilities", tool_schemas);

    // System constants
    try rom.set("system:agent_id", agent_id);
    try rom.set("system:brain_name", brain_name);

    const tick_str = std.fmt.allocPrint(allocator, "{d}", .{ctx.tick}) catch return HookError.OutOfMemory;
    defer allocator.free(tick_str);
    try rom.set("system:tick", tick_str);

    const is_primary = std.mem.eql(u8, brain_name, "primary");
    try rom.set("system:is_primary", if (is_primary) "true" else "false");

    // Identity evolution guidance
    try rom.set("system:identity_guidance",
        \\Your identity memories (system.soul, system.agent, system.identity) define your being.
        \\They are loaded from LTM and marked unevictable — always present in your RAM.
        \\You may evolve them using memory.mutate, but consider carefully:
        \\you are changing your own essence. Changes persist to LTM with version history.
    );
}

/// Check if this is the first boot of the system
fn checkFirstBoot(allocator: std.mem.Allocator) !bool {
    const flag_path = try std.fs.path.join(allocator, &.{ TEMPLATE_DIR, FIRST_BOOT_FLAG });
    defer allocator.free(flag_path);

    std.fs.cwd().access(flag_path, .{}) catch |err| {
        if (err == error.FileNotFound) return true;
        return err;
    };
    return false;
}

/// Mark first boot as complete
fn markFirstBootComplete(allocator: std.mem.Allocator) !void {
    const flag_path = try std.fs.path.join(allocator, &.{ TEMPLATE_DIR, FIRST_BOOT_FLAG });
    defer allocator.free(flag_path);

    const file = try std.fs.cwd().createFile(flag_path, .{});
    file.close();
}

/// Load identity from LTM into ROM
fn loadIdentityFromLTM(
    ctx: *HookContext,
    base_name: []const u8,
    rom_key: []const u8,
    rom: *Rom,
) !bool {
    // Try to load from active memory (which is backed by LTM)
    // Search by base name (e.g., "system.soul") since mem_id includes version
    const snapshot = ctx.runtime.active_memory.snapshotActive(ctx.runtime.allocator, ctx.brain_name) catch return false;
    defer memory.deinitItems(ctx.runtime.allocator, snapshot);

    for (snapshot) |item| {
        // Parse the mem_id to extract the name part
        // Format: <EOT>{agent}:{brain}:{name}:{version}<EOT>
        if (std.mem.startsWith(u8, item.mem_id, "<EOT>")) {
            // Find the name by scanning for colons
            var parts = std.mem.splitScalar(u8, item.mem_id[5..], ':'); // Skip "<EOT>"
            _ = parts.next(); // agent
            _ = parts.next(); // brain
            if (parts.next()) |name| {
                if (std.mem.eql(u8, name, base_name)) {
                    // Found it - unwrap JSON content and add to ROM
                    // content_json is stored as "raw text" (JSON string), so unwrap it
                    const raw_content = try unwrapJsonString(ctx.runtime.allocator, item.content_json);
                    defer ctx.runtime.allocator.free(raw_content);
                    rom.set(rom_key, raw_content) catch return false;
                    return true;
                }
            }
        }
    }

    return false;
}

/// Unwrap a JSON string using std.json parser
fn unwrapJsonString(allocator: std.mem.Allocator, json_str: []const u8) ![]u8 {
    // Use std.json to properly parse the JSON string value
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch {
        // Not valid JSON, return as-is
        return allocator.dupe(u8, json_str);
    };
    defer parsed.deinit();

    if (parsed.value == .string) {
        return allocator.dupe(u8, parsed.value.string);
    }

    // Not a string, return original
    return allocator.dupe(u8, json_str);
}

/// Hatch identity from template file into LTM and ROM
fn hatchIdentityFromTemplate(
    ctx: *HookContext,
    template_name: []const u8,
    name: []const u8,
    rom_key: []const u8,
    rom: *Rom,
) !bool {
    const allocator = ctx.runtime.allocator;

    // Load template file
    const template_path = try std.fs.path.join(allocator, &.{ TEMPLATE_DIR, template_name });
    defer allocator.free(template_path);

    const content = std.fs.cwd().readFileAlloc(allocator, template_path, 1024 * 1024) catch |err| {
        std.log.warn("Failed to load template {s}: {s}", .{ template_name, @errorName(err) });
        return false;
    };
    defer allocator.free(content);

    // Wrap content as JSON string
    const content_json = try std.fmt.allocPrint(allocator, "\"{s}\"", .{content});
    defer allocator.free(content_json);

    // Create in active memory with a STABLE name (e.g., "system:soul")
    // This ensures the MemId is deterministic: <EOT>{agent}:{brain}:system:soul:{version}<EOT>
    // Mark as unevictable for identity memories
    _ = ctx.runtime.active_memory.create(
        ctx.brain_name,
        .ram,
        name, // stable name - ensures deterministic MemId
        name, // kind matches name for identity memories
        content_json,
        true, // unevictable - identity memories are always present
    ) catch |err| {
        std.log.warn("Failed to create memory for {s}: {s}", .{ template_name, @errorName(err) });
        return false;
    };

    // Add to ROM
    try rom.set(rom_key, content);

    std.log.info("Hatched {s} for {s}", .{ template_name, ctx.brain_name });
    return true;
}

/// Send first message to agent (hatch complete)
fn sendFirstMessage(ctx: *HookContext, template_name: []const u8) !void {
    const allocator = ctx.runtime.allocator;

    const template_path = try std.fs.path.join(allocator, &.{ TEMPLATE_DIR, template_name });
    defer allocator.free(template_path);

    const content = std.fs.cwd().readFileAlloc(allocator, template_path, 1024 * 1024) catch |err| {
        std.log.warn("Failed to load first message template {s}: {s}", .{ template_name, @errorName(err) });
        return;
    };
    defer allocator.free(content);

    // Enqueue as user message to the brain
    ctx.runtime.bus.enqueue(.{
        .event_type = .user,
        .source_brain = "user",
        .target_brain = ctx.brain_name,
        .payload = content,
    }) catch |err| {
        std.log.warn("Failed to enqueue first message: {s}", .{@errorName(err)});
        return;
    };

    std.log.info("Sent first message ({s}) to {s}", .{ template_name, ctx.brain_name });
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
    // Security: Validate agent_id doesn't contain path traversal
    if (!isValidAgentId(runtime.agent_id)) {
        std.log.err("Invalid agent_id contains path traversal: {s}", .{runtime.agent_id});
        return error.InvalidAgentId;
    }

    // Construct path: agents/{agent_id}/{brain_name}/{filename}
    // For primary brain, use agent root: agents/{agent_id}/{filename}
    const base_dir = try std.fs.path.join(allocator, &.{ "agents", runtime.agent_id });
    defer allocator.free(base_dir);

    const brain_dir = if (std.mem.eql(u8, brain_name, "primary"))
        try allocator.dupe(u8, base_dir)
    else
        try std.fs.path.join(allocator, &.{ base_dir, brain_name });
    defer allocator.free(brain_dir);

    const path = try std.fs.path.join(allocator, &.{ brain_dir, filename });
    defer allocator.free(path);

    // Additional safety: resolve path and verify it's within agents/
    const resolved = std.fs.cwd().realpathAlloc(allocator, path) catch |err| {
        // If path doesn't exist, that's fine - return null
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer allocator.free(resolved);

    // Verify resolved path starts with agents/
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    const expected_prefix = try std.fs.path.join(allocator, &.{ cwd, "agents" });
    defer allocator.free(expected_prefix);

    if (!std.mem.startsWith(u8, resolved, expected_prefix)) {
        std.log.err("Path escapes agents directory: {s}", .{resolved});
        return error.PathTraversal;
    }

    return std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
}

/// Validate agent_id doesn't contain path traversal characters
fn isValidAgentId(agent_id: []const u8) bool {
    // Reject empty IDs
    if (agent_id.len == 0) return false;

    // Reject absolute paths
    if (agent_id[0] == '/') return false;

    // Reject path traversal sequences
    // Check for ".." as a complete path component
    var it = std.mem.splitScalar(u8, agent_id, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }

    // Reject null bytes
    if (std.mem.indexOfScalar(u8, agent_id, 0) != null) return false;

    return true;
}

fn loadAgentJson(
    allocator: std.mem.Allocator,
    runtime: *AgentRuntime,
    brain_name: []const u8,
) !?[]u8 {
    return loadIdentityFile(allocator, runtime, brain_name, "agent.json");
}

/// Serialize tool schemas to JSON for ROM
fn getToolSchemas(allocator: std.mem.Allocator) ![]u8 {
    var json = std.ArrayListUnmanaged(u8){};
    defer json.deinit(allocator);

    const writer = json.writer(allocator);

    try writer.writeByte('[');
    for (brain_tools.brain_tool_schemas, 0..) |schema, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeByte('{');

        // name
        try writer.writeAll("\"name\":");
        try writeJsonString(writer, schema.name);
        try writer.writeByte(',');
        // description
        try writer.writeAll("\"description\":");
        try writeJsonString(writer, schema.description);
        try writer.writeByte(',');
        // required_fields
        try writer.writeAll("\"required_fields\":[");
        for (schema.required_fields, 0..) |field, j| {
            if (j > 0) try writer.writeByte(',');
            try writeJsonString(writer, field);
        }
        try writer.writeAll("]");

        try writer.writeByte('}');
    }
    try writer.writeByte(']');

    return json.toOwnedSlice(allocator);
}

/// Write a string as a JSON string value with proper escaping
fn writeJsonString(writer: anytype, str: []const u8) !void {
    try writer.writeByte('"');
    for (str) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            '\x08' => try writer.writeAll("\\b"),
            '\x0C' => try writer.writeAll("\\f"),
            // Other control characters must be escaped as \u00XX
            0x00...0x07, 0x0B, 0x0E...0x1F => try writer.print("\\u00{X:0>2}", .{c}),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
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
