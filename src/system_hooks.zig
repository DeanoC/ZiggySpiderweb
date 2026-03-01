const std = @import("std");
const hook_registry = @import("hook_registry.zig");
const HookContext = hook_registry.HookContext;
const HookData = hook_registry.HookData;
const HookError = hook_registry.HookError;
const Rom = hook_registry.Rom;
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const memory = @import("ziggy-memory-store").memory;
const memid = @import("ziggy-memory-store").memid;
const protocol = @import("ziggy-spider-protocol").protocol;
const Config = @import("config.zig");
const memory_schema = @import("memory_schema.zig");

/// System paths for templates
pub const SOUL_MEM_NAME = "system.soul";
pub const AGENT_MEM_NAME = "system.agent";
pub const IDENTITY_MEM_NAME = "system.identity";
pub const BASE_CORE_MEM_NAME = "system.core";
pub const BASE_CORE_ROM_KEY = "system:base_instructions";

/// Load identity from LTM into core prompt memory map, or hatch from templates if first boot
pub fn loadSharedRomHook(ctx: *HookContext, data: HookData) HookError!void {
    const rom = data.pre_observe;
    const allocator = ctx.runtime.allocator;
    const agent_id = ctx.runtime.agent_id;
    const brain_name = ctx.brain_name;

    ensureIdentityMemories(ctx.runtime, brain_name) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed to ensure identity memories for {s}/{s}: {s}", .{ agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };

    _ = loadIdentityFromLTM(ctx, BASE_CORE_MEM_NAME, BASE_CORE_ROM_KEY, rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading base core memory {s} for {s}/{s}: {s}", .{ BASE_CORE_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };
    _ = loadIdentityFromLTM(ctx, SOUL_MEM_NAME, "identity:soul", rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading identity memory {s} for {s}/{s}: {s}", .{ SOUL_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };
    _ = loadIdentityFromLTM(ctx, AGENT_MEM_NAME, "identity:agent", rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading identity memory {s} for {s}/{s}: {s}", .{ AGENT_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };
    _ = loadIdentityFromLTM(ctx, IDENTITY_MEM_NAME, "identity:public", rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading identity memory {s} for {s}/{s}: {s}", .{ IDENTITY_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };
    _ = loadIdentityFromLTM(ctx, memory_schema.POLICY_MEM_NAME, memory_schema.POLICY_ROM_KEY, rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading runtime policy memory {s} for {s}/{s}: {s}", .{ memory_schema.POLICY_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };
    _ = loadIdentityFromLTM(ctx, memory_schema.LOOP_CONTRACT_MEM_NAME, memory_schema.LOOP_CONTRACT_ROM_KEY, rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading loop contract memory {s} for {s}/{s}: {s}", .{ memory_schema.LOOP_CONTRACT_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };
    _ = loadIdentityFromLTM(ctx, memory_schema.TOOL_CONTRACT_MEM_NAME, memory_schema.TOOL_CONTRACT_ROM_KEY, rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading tool contract memory {s} for {s}/{s}: {s}", .{ memory_schema.TOOL_CONTRACT_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };
    _ = loadIdentityFromLTM(ctx, memory_schema.COMPLETION_CONTRACT_MEM_NAME, memory_schema.COMPLETION_CONTRACT_ROM_KEY, rom) catch |err| switch (err) {
        error.OutOfMemory => return HookError.OutOfMemory,
        else => {
            std.log.warn("Failed loading completion contract memory {s} for {s}/{s}: {s}", .{ memory_schema.COMPLETION_CONTRACT_MEM_NAME, agent_id, brain_name, @errorName(err) });
            return HookError.HookFailed;
        },
    };

    // Load agent.json config (if exists)
    const agent_json = loadAgentJson(allocator, ctx.runtime, brain_name) catch |err| blk: {
        std.log.warn("Failed to load agent.json for {s}: {s}", .{ brain_name, @errorName(err) });
        break :blk null;
    };
    defer if (agent_json) |c| allocator.free(c);

    if (agent_json) |content| {
        try rom.set("system:agent_config", content);
    }

    // System constants
    try rom.set("system:agent_id", agent_id);
    try rom.set("system:brain_name", brain_name);

    const tick_str = std.fmt.allocPrint(allocator, "{d}", .{ctx.tick}) catch return HookError.OutOfMemory;
    defer allocator.free(tick_str);
    try rom.set("system:tick", tick_str);

    const is_primary = std.mem.eql(u8, brain_name, "primary");
    try rom.set("system:is_primary", if (is_primary) "true" else "false");
}

/// Load identity from LTM into core prompt memory map
fn loadIdentityFromLTM(
    ctx: *HookContext,
    base_name: []const u8,
    rom_key: []const u8,
    rom: *Rom,
) !bool {
    var loaded = (try loadMemoryByName(ctx.runtime, ctx.brain_name, base_name)) orelse return false;
    defer loaded.deinit(ctx.runtime.allocator);

    const raw_content = try unwrapJsonString(ctx.runtime.allocator, loaded.content_json);
    defer ctx.runtime.allocator.free(raw_content);
    rom.set(rom_key, raw_content) catch return false;
    return true;
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

/// Ensure the identity memories exist for a brain, hatching from templates if needed.
pub fn ensureIdentityMemories(runtime: *AgentRuntime, brain_name: []const u8) !void {
    _ = try ensureMemoryFromTemplate(runtime, brain_name, "CORE.md", BASE_CORE_MEM_NAME);
    _ = try ensureMemoryFromTemplate(runtime, brain_name, "SOUL.md", SOUL_MEM_NAME);
    _ = try ensureMemoryFromTemplate(runtime, brain_name, "AGENT.md", AGENT_MEM_NAME);
    _ = try ensureMemoryFromTemplate(runtime, brain_name, "IDENTITY.md", IDENTITY_MEM_NAME);
    try memory_schema.ensureRuntimeInstructionMemories(runtime, brain_name);
}

pub fn readTemplate(allocator: std.mem.Allocator, runtime: *AgentRuntime, template_name: []const u8) ![]u8 {
    const template_path = try std.fs.path.join(allocator, &.{ runtime.runtime_config.assets_dir, template_name });
    defer allocator.free(template_path);
    return std.fs.cwd().readFileAlloc(allocator, template_path, 1024 * 1024);
}

fn readIdentityTemplateForBrain(
    allocator: std.mem.Allocator,
    runtime: *AgentRuntime,
    brain_name: []const u8,
    template_name: []const u8,
) ![]u8 {
    if (try loadIdentityFile(allocator, runtime, brain_name, template_name)) |content| {
        return content;
    }
    return readTemplate(allocator, runtime, template_name);
}

fn logTemplateLoadFailure(template_name: []const u8, err: anyerror, has_fallback_memory: bool) void {
    if (err == error.FileNotFound) {
        if (has_fallback_memory) {
            std.log.info("Template {s} not found; using persisted memory", .{template_name});
            return;
        }
        std.log.info("Template {s} not found; skipping hatch", .{template_name});
        return;
    }
    std.log.warn("Failed to load template {s}: {s}", .{ template_name, @errorName(err) });
}

fn ensureMemoryFromTemplate(
    runtime: *AgentRuntime,
    brain_name: []const u8,
    template_name: []const u8,
    name: []const u8,
) !bool {
    const allocator = runtime.allocator;
    var existing = try loadMemoryByName(runtime, brain_name, name);
    if (existing) |*item| {
        defer item.deinit(allocator);
        var is_active = try isMemoryActive(runtime, brain_name, name);

        // CORE.md is authoritative and write-protected by policy:
        // always synchronize LTM content with the current template file.
        if (std.mem.eql(u8, name, BASE_CORE_MEM_NAME)) {
            const maybe_content = readIdentityTemplateForBrain(allocator, runtime, brain_name, template_name) catch |err| blk: {
                logTemplateLoadFailure(template_name, err, true);
                break :blk null;
            };
            if (maybe_content) |content| {
                defer allocator.free(content);

                const escaped_content = try protocol.jsonEscape(allocator, content);
                defer allocator.free(escaped_content);
                const template_content_json = try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_content});
                defer allocator.free(template_content_json);

                if (!std.mem.eql(u8, item.content_json, template_content_json)) {
                    if (is_active) {
                        var updated = runtime.active_memory.mutate(item.mem_id, template_content_json) catch |err| {
                            if (err == memory.MemoryError.NotFound) {
                                var recreated = runtime.active_memory.create(
                                    brain_name,
                                    name,
                                    item.kind,
                                    template_content_json,
                                    false,
                                    true,
                                ) catch |create_err| {
                                    std.log.warn("Failed to sync {s} from {s}: {s}", .{ name, template_name, @errorName(create_err) });
                                    return false;
                                };
                                recreated.deinit(allocator);
                                is_active = true;
                                std.log.info("Synced {s} from {s} for {s}/{s}", .{ name, template_name, runtime.agent_id, brain_name });
                                return true;
                            }
                            std.log.warn("Failed to sync {s} from {s}: {s}", .{ name, template_name, @errorName(err) });
                            return false;
                        };
                        updated.deinit(allocator);
                    } else {
                        var synced = runtime.active_memory.create(
                            brain_name,
                            name,
                            item.kind,
                            template_content_json,
                            false,
                            true,
                        ) catch |err| {
                            std.log.warn("Failed to sync {s} from {s}: {s}", .{ name, template_name, @errorName(err) });
                            return false;
                        };
                        synced.deinit(allocator);
                        is_active = true;
                    }

                    std.log.info("Synced {s} from {s} for {s}/{s}", .{ name, template_name, runtime.agent_id, brain_name });
                }
            }
        }

        if (is_active) {
            return true;
        }

        // Rehydrate from latest persisted version.
        var latest = (try loadMemoryByName(runtime, brain_name, name)) orelse return true;
        defer latest.deinit(allocator);
        var recreated = runtime.active_memory.create(
            brain_name,
            name,
            latest.kind,
            latest.content_json,
            false,
            true,
        ) catch |err| {
            std.log.warn("Failed to rehydrate memory {s} for {s}/{s}: {s}", .{ name, runtime.agent_id, brain_name, @errorName(err) });
            return false;
        };
        defer recreated.deinit(allocator);
        return true;
    }

    const content = readIdentityTemplateForBrain(allocator, runtime, brain_name, template_name) catch |err| {
        logTemplateLoadFailure(template_name, err, false);
        return false;
    };
    defer allocator.free(content);

    const escaped_content = try protocol.jsonEscape(allocator, content);
    defer allocator.free(escaped_content);

    const content_json = try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_content});
    defer allocator.free(content_json);

    var created = runtime.active_memory.create(
        brain_name,
        name,
        name,
        content_json,
        false,
        true,
    ) catch |err| {
        std.log.warn("Failed to create memory for {s}: {s}", .{ template_name, @errorName(err) });
        return false;
    };
    defer created.deinit(allocator);

    std.log.info("Hatched {s} for {s}/{s}", .{ template_name, runtime.agent_id, brain_name });
    return true;
}

fn isMemoryActive(runtime: *AgentRuntime, brain_name: []const u8, name: []const u8) !bool {
    const snapshot = try runtime.active_memory.snapshotActive(runtime.allocator, brain_name);
    defer memory.deinitItems(runtime.allocator, snapshot);

    for (snapshot) |item| {
        const parsed = memid.MemId.parse(item.mem_id) catch continue;
        if (std.mem.eql(u8, parsed.name, name)) return true;
    }
    return false;
}

fn loadMemoryByName(runtime: *AgentRuntime, brain_name: []const u8, name: []const u8) !?memory.ActiveMemoryItem {
    const allocator = runtime.allocator;
    const mem_id = try buildLatestMemId(allocator, runtime.agent_id, brain_name, name);
    defer allocator.free(mem_id);

    return runtime.active_memory.load(mem_id, null) catch |err| switch (err) {
        memory.MemoryError.NotFound => null,
        else => err,
    };
}

fn buildLatestMemId(allocator: std.mem.Allocator, agent_id: []const u8, brain_name: []const u8, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}{s}:{s}:{s}:latest{s}",
        .{ memid.EOT_MARKER, agent_id, brain_name, name, memid.EOT_MARKER },
    );
}

/// Inject runtime status into core prompt memory map
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
}

/// Persist LTM after results (PostResults hook)
pub fn persistLtmHook(ctx: *HookContext, data: HookData) HookError!void {
    const checkpoint = data.post_results;
    const store = ctx.runtime.ltm_store orelse return;

    const now_ms = std.time.milliTimestamp();
    const base_id = std.fmt.allocPrint(
        ctx.runtime.allocator,
        "{s}:system_checkpoint:{s}",
        .{ ctx.runtime.agent_id, ctx.brain_name },
    ) catch return;
    defer ctx.runtime.allocator.free(base_id);

    const payload = std.fmt.allocPrint(
        ctx.runtime.allocator,
        "{{\"tick\":{d},\"checkpoint_tick\":{d},\"artifacts_count\":{d},\"created_at_ms\":{d}}}",
        .{ ctx.tick, checkpoint.tick, checkpoint.artifacts_count, now_ms },
    ) catch return;
    defer ctx.runtime.allocator.free(payload);

    _ = store.appendAt(base_id, "runtime_checkpoint", payload, now_ms) catch |err| {
        std.log.warn("PostResults: checkpoint persist failed for {s}/{s}: {s}", .{
            ctx.runtime.agent_id,
            ctx.brain_name,
            @errorName(err),
        });
        return;
    };

    std.log.debug("PostResults: persisted checkpoint for {s}/{s} tick {d}", .{
        ctx.runtime.agent_id,
        ctx.brain_name,
        checkpoint.tick,
    });
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
    const agents_dir = runtime.runtime_config.agents_dir;
    const base_dir = try std.fs.path.join(allocator, &.{ agents_dir, runtime.agent_id });
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
    const expected_prefix = try std.fs.path.join(allocator, &.{ cwd, agents_dir });
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

/// Register all system hooks
pub fn registerSystemHooks(registry: *hook_registry.HookRegistry) !void {
    // PRE_OBSERVE: core prompt loading pipeline
    try registry.register(.pre_observe, .{
        .name = "system:load-shared-core",
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

test "system_hooks: ensureIdentityMemories rehydrates persisted identity into active memory" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const ltm_dir = try std.fs.path.join(allocator, &.{ tmp_root, "ltm" });
    defer allocator.free(ltm_dir);
    try std.fs.cwd().makePath(ltm_dir);
    const cfg = Config.RuntimeConfig{};

    {
        var runtime = try AgentRuntime.initWithPersistence(allocator, "agent-system-hooks", &.{}, ltm_dir, "runtime-memory.db", cfg);
        defer runtime.deinit();

        try ensureIdentityMemories(&runtime, "primary");
    }

    var restarted = try AgentRuntime.initWithPersistence(allocator, "agent-system-hooks", &.{}, ltm_dir, "runtime-memory.db", cfg);
    defer restarted.deinit();

    const before = try restarted.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, before);
    try std.testing.expectEqual(@as(usize, 0), before.len);

    try ensureIdentityMemories(&restarted, "primary");

    const after = try restarted.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, after);

    try std.testing.expect(containsNamedMemory(after, BASE_CORE_MEM_NAME));
    try std.testing.expect(containsNamedMemory(after, SOUL_MEM_NAME));
    try std.testing.expect(containsNamedMemory(after, AGENT_MEM_NAME));
    try std.testing.expect(containsNamedMemory(after, IDENTITY_MEM_NAME));
}

test "system_hooks: ensureIdentityMemories rehydrates persisted CORE when template is unavailable" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const ltm_dir = try std.fs.path.join(allocator, &.{ tmp_root, "ltm" });
    defer allocator.free(ltm_dir);
    try std.fs.cwd().makePath(ltm_dir);

    const assets_dir = try std.fs.path.join(allocator, &.{ tmp_root, "assets" });
    defer allocator.free(assets_dir);

    try std.fs.cwd().makePath(assets_dir);
    inline for (.{ "CORE.md", "SOUL.md", "AGENT.md", "IDENTITY.md" }) |filename| {
        const path = try std.fs.path.join(allocator, &.{ assets_dir, filename });
        defer allocator.free(path);
        try std.fs.cwd().writeFile(.{
            .sub_path = path,
            .data = "template-v1",
        });
    }

    var first_cfg = Config.RuntimeConfig{};
    first_cfg.assets_dir = assets_dir;

    {
        var runtime = try AgentRuntime.initWithPersistence(allocator, "agent-system-hooks-missing-template", &.{}, ltm_dir, "runtime-memory.db", first_cfg);
        defer runtime.deinit();
        try ensureIdentityMemories(&runtime, "primary");
    }

    const missing_assets_dir = try std.fs.path.join(allocator, &.{ tmp_root, "missing-assets" });
    defer allocator.free(missing_assets_dir);

    var second_cfg = Config.RuntimeConfig{};
    second_cfg.assets_dir = missing_assets_dir;

    var restarted = try AgentRuntime.initWithPersistence(allocator, "agent-system-hooks-missing-template", &.{}, ltm_dir, "runtime-memory.db", second_cfg);
    defer restarted.deinit();

    const before = try restarted.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, before);
    try std.testing.expectEqual(@as(usize, 0), before.len);

    try ensureIdentityMemories(&restarted, "primary");

    const after = try restarted.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, after);
    try std.testing.expect(containsNamedMemory(after, BASE_CORE_MEM_NAME));
}

test "system_hooks: ensureIdentityMemories mutates CORE memory on template sync" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const ltm_dir = try std.fs.path.join(allocator, &.{ tmp_root, "ltm" });
    defer allocator.free(ltm_dir);
    try std.fs.cwd().makePath(ltm_dir);

    const assets_dir = try std.fs.path.join(allocator, &.{ tmp_root, "assets" });
    defer allocator.free(assets_dir);

    try std.fs.cwd().makePath(assets_dir);

    const core_v1 =
        \\# CORE.md
        \\base-v1
    ;
    const core_v2 =
        \\# CORE.md
        \\base-v2
    ;
    const identity_template =
        \\# identity
        \\v1
    ;

    const core_path = try std.fs.path.join(allocator, &.{ assets_dir, "CORE.md" });
    defer allocator.free(core_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = core_path,
        .data = core_v1,
    });

    inline for (.{ "SOUL.md", "AGENT.md", "IDENTITY.md" }) |filename| {
        const path = try std.fs.path.join(allocator, &.{ assets_dir, filename });
        defer allocator.free(path);
        try std.fs.cwd().writeFile(.{
            .sub_path = path,
            .data = identity_template,
        });
    }

    var cfg = Config.RuntimeConfig{};
    cfg.assets_dir = assets_dir;

    var runtime = try AgentRuntime.initWithPersistence(allocator, "agent-system-hooks-sync", &.{}, ltm_dir, "runtime-memory.db", cfg);
    defer runtime.deinit();

    try ensureIdentityMemories(&runtime, "primary");

    try std.fs.cwd().writeFile(.{
        .sub_path = core_path,
        .data = core_v2,
    });

    try ensureIdentityMemories(&runtime, "primary");

    const after = try runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, after);

    try std.testing.expectEqual(@as(usize, 1), countNamedMemoryPrefix(after, BASE_CORE_MEM_NAME));

    const synced_opt = try loadMemoryByName(&runtime, "primary", BASE_CORE_MEM_NAME);
    try std.testing.expect(synced_opt != null);
    var synced = synced_opt.?;
    defer synced.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), synced.version orelse 0);

    const content = try unwrapJsonString(allocator, synced.content_json);
    defer allocator.free(content);
    try std.testing.expect(std.mem.eql(u8, content, core_v2));
}

test "system_hooks: ensureIdentityMemories syncs CORE from template across restart" {
    const allocator = std.testing.allocator;
    const nonce = std.time.nanoTimestamp();
    const ltm_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-ltm-restart-sync-{d}", .{nonce});
    defer allocator.free(ltm_dir);
    defer std.fs.cwd().deleteTree(ltm_dir) catch {};
    const assets_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-assets-restart-sync-{d}", .{nonce});
    defer allocator.free(assets_dir);
    defer std.fs.cwd().deleteTree(assets_dir) catch {};

    try std.fs.cwd().makePath(assets_dir);

    const core_v1 =
        \\# CORE.md
        \\restart-v1
    ;
    const core_v2 =
        \\# CORE.md
        \\restart-v2
    ;
    const identity_template =
        \\# identity
        \\v1
    ;

    const core_path = try std.fs.path.join(allocator, &.{ assets_dir, "CORE.md" });
    defer allocator.free(core_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = core_path,
        .data = core_v1,
    });

    inline for (.{ "SOUL.md", "AGENT.md", "IDENTITY.md" }) |filename| {
        const path = try std.fs.path.join(allocator, &.{ assets_dir, filename });
        defer allocator.free(path);
        try std.fs.cwd().writeFile(.{
            .sub_path = path,
            .data = identity_template,
        });
    }

    var cfg = Config.RuntimeConfig{};
    cfg.assets_dir = assets_dir;

    {
        var runtime = try AgentRuntime.initWithPersistence(allocator, "agent-system-hooks-restart-sync", &.{}, ltm_dir, "runtime-memory.db", cfg);
        defer runtime.deinit();
        try ensureIdentityMemories(&runtime, "primary");
    }

    try std.fs.cwd().writeFile(.{
        .sub_path = core_path,
        .data = core_v2,
    });

    var restarted = try AgentRuntime.initWithPersistence(allocator, "agent-system-hooks-restart-sync", &.{}, ltm_dir, "runtime-memory.db", cfg);
    defer restarted.deinit();

    const before = try restarted.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, before);
    try std.testing.expectEqual(@as(usize, 0), before.len);

    try ensureIdentityMemories(&restarted, "primary");

    const after = try restarted.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, after);
    try std.testing.expectEqual(@as(usize, 1), countNamedMemoryPrefix(after, BASE_CORE_MEM_NAME));

    const synced_opt = try loadMemoryByName(&restarted, "primary", BASE_CORE_MEM_NAME);
    try std.testing.expect(synced_opt != null);
    var synced = synced_opt.?;
    defer synced.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), synced.version orelse 0);

    const content = try unwrapJsonString(allocator, synced.content_json);
    defer allocator.free(content);
    try std.testing.expect(std.mem.eql(u8, content, core_v2));
}

test "system_hooks: ensureIdentityMemories prefers and syncs agent-local CORE" {
    const allocator = std.testing.allocator;
    const nonce = std.time.nanoTimestamp();
    const root_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-local-core-{d}", .{nonce});
    defer allocator.free(root_dir);
    defer std.fs.cwd().deleteTree(root_dir) catch {};

    const ltm_dir = try std.fs.path.join(allocator, &.{ root_dir, "ltm" });
    defer allocator.free(ltm_dir);
    const assets_dir = try std.fs.path.join(allocator, &.{ root_dir, "assets" });
    defer allocator.free(assets_dir);
    const agents_dir = try std.fs.path.join(allocator, &.{ root_dir, "agents" });
    defer allocator.free(agents_dir);

    try std.fs.cwd().makePath(ltm_dir);
    try std.fs.cwd().makePath(assets_dir);
    try std.fs.cwd().makePath(agents_dir);

    const global_core =
        \\# CORE.md
        \\global-core
    ;
    const local_core_v1 =
        \\# CORE.md
        \\local-core-v1
    ;
    const local_core_v2 =
        \\# CORE.md
        \\local-core-v2
    ;
    const identity_template =
        \\# identity
        \\v1
    ;

    const core_template_path = try std.fs.path.join(allocator, &.{ assets_dir, "CORE.md" });
    defer allocator.free(core_template_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = core_template_path,
        .data = global_core,
    });

    inline for (.{ "SOUL.md", "AGENT.md", "IDENTITY.md" }) |filename| {
        const path = try std.fs.path.join(allocator, &.{ assets_dir, filename });
        defer allocator.free(path);
        try std.fs.cwd().writeFile(.{
            .sub_path = path,
            .data = identity_template,
        });
    }

    const agent_id = "agent-system-hooks-local-core";
    const agent_dir = try std.fs.path.join(allocator, &.{ agents_dir, agent_id });
    defer allocator.free(agent_dir);
    try std.fs.cwd().makePath(agent_dir);
    const local_core_path = try std.fs.path.join(allocator, &.{ agent_dir, "CORE.md" });
    defer allocator.free(local_core_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = local_core_path,
        .data = local_core_v1,
    });

    var cfg = Config.RuntimeConfig{};
    cfg.assets_dir = assets_dir;
    cfg.agents_dir = agents_dir;

    var runtime = try AgentRuntime.initWithPersistence(allocator, agent_id, &.{}, ltm_dir, "runtime-memory.db", cfg);
    defer runtime.deinit();

    try ensureIdentityMemories(&runtime, "primary");

    {
        const synced_opt = try loadMemoryByName(&runtime, "primary", BASE_CORE_MEM_NAME);
        try std.testing.expect(synced_opt != null);
        var synced = synced_opt.?;
        defer synced.deinit(allocator);
        const content = try unwrapJsonString(allocator, synced.content_json);
        defer allocator.free(content);
        try std.testing.expect(std.mem.eql(u8, content, local_core_v1));
    }

    try std.fs.cwd().writeFile(.{
        .sub_path = local_core_path,
        .data = local_core_v2,
    });
    try ensureIdentityMemories(&runtime, "primary");

    {
        const synced_opt = try loadMemoryByName(&runtime, "primary", BASE_CORE_MEM_NAME);
        try std.testing.expect(synced_opt != null);
        var synced = synced_opt.?;
        defer synced.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 2), synced.version orelse 0);
        const content = try unwrapJsonString(allocator, synced.content_json);
        defer allocator.free(content);
        try std.testing.expect(std.mem.eql(u8, content, local_core_v2));
    }
}

fn containsNamedMemory(items: []const memory.ActiveMemoryItem, name: []const u8) bool {
    for (items) |item| {
        const parsed = memid.MemId.parse(item.mem_id) catch continue;
        if (std.mem.eql(u8, parsed.name, name)) return true;
    }
    return false;
}

fn countNamedMemoryPrefix(items: []const memory.ActiveMemoryItem, prefix: []const u8) usize {
    var count: usize = 0;
    for (items) |item| {
        const parsed = memid.MemId.parse(item.mem_id) catch continue;
        if (std.mem.startsWith(u8, parsed.name, prefix)) count += 1;
    }
    return count;
}
