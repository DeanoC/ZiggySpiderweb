const std = @import("std");
const hook_registry = @import("hook_registry.zig");
const HookContext = hook_registry.HookContext;
const HookData = hook_registry.HookData;
const HookError = hook_registry.HookError;
const Rom = hook_registry.Rom;
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const memory = @import("memory.zig");
const memid = @import("memid.zig");
const protocol = @import("protocol.zig");
const Config = @import("config.zig");

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
}

pub fn readTemplate(allocator: std.mem.Allocator, runtime: *AgentRuntime, template_name: []const u8) ![]u8 {
    const template_path = try std.fs.path.join(allocator, &.{ runtime.runtime_config.assets_dir, template_name });
    defer allocator.free(template_path);
    return std.fs.cwd().readFileAlloc(allocator, template_path, 1024 * 1024);
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

        // CORE.md is authoritative and write-protected by policy:
        // always synchronize LTM content with the current template file.
        if (std.mem.eql(u8, name, BASE_CORE_MEM_NAME)) {
            const maybe_content = readTemplate(allocator, runtime, template_name) catch |err| blk: {
                std.log.warn("Failed to load template {s}: {s}", .{ template_name, @errorName(err) });
                break :blk null;
            };
            if (maybe_content) |content| {
                defer allocator.free(content);

                const escaped_content = try protocol.jsonEscape(allocator, content);
                defer allocator.free(escaped_content);
                const template_content_json = try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped_content});
                defer allocator.free(template_content_json);

                if (!std.mem.eql(u8, item.content_json, template_content_json)) {
                    var updated = runtime.active_memory.mutate(item.mem_id, template_content_json) catch |err| {
                        std.log.warn("Failed to sync {s} from {s}: {s}", .{ name, template_name, @errorName(err) });
                        return false;
                    };
                    updated.deinit(allocator);
                    std.log.info("Synced {s} from {s} for {s}/{s}", .{ name, template_name, runtime.agent_id, brain_name });
                }
            }
        }

        if (try isMemoryActive(runtime, brain_name, name)) {
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

    const content = readTemplate(allocator, runtime, template_name) catch |err| {
        std.log.warn("Failed to load template {s}: {s}", .{ template_name, @errorName(err) });
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
    const ltm_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-ltm-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(ltm_dir);
    defer std.fs.cwd().deleteTree(ltm_dir) catch {};
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
    const nonce = std.time.nanoTimestamp();
    const ltm_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-ltm-missing-template-{d}", .{nonce});
    defer allocator.free(ltm_dir);
    defer std.fs.cwd().deleteTree(ltm_dir) catch {};
    const assets_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-assets-missing-template-{d}", .{nonce});
    defer allocator.free(assets_dir);
    defer std.fs.cwd().deleteTree(assets_dir) catch {};

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

    const missing_assets_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-assets-missing-template-does-not-exist-{d}", .{nonce});
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
    const nonce = std.time.nanoTimestamp();
    const ltm_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-ltm-sync-{d}", .{nonce});
    defer allocator.free(ltm_dir);
    defer std.fs.cwd().deleteTree(ltm_dir) catch {};
    const assets_dir = try std.fmt.allocPrint(allocator, ".tmp-system-hooks-assets-sync-{d}", .{nonce});
    defer allocator.free(assets_dir);
    defer std.fs.cwd().deleteTree(assets_dir) catch {};

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
