const std = @import("std");
const ltm_store = @import("ltm_store.zig");
const memory = @import("memory.zig");
const memid = @import("memid.zig");
const brain_context = @import("brain_context.zig");
const brain_tools = @import("brain_tools.zig");
const event_bus = @import("event_bus.zig");
const tool_registry = @import("tool_registry.zig");
const tool_executor = @import("tool_executor.zig");
const hook_registry = @import("hook_registry.zig");
const system_hooks = @import("system_hooks.zig");
const brain_specialization = @import("brain_specialization.zig");
const Config = @import("config.zig");

pub const RuntimeError = error{
    BrainNotFound,
    QueueSaturated,
    RuntimePaused,
    RuntimeCancelled,
};

pub const RuntimeState = enum {
    running,
    paused,
    cancelled,
};

pub const QueueLimits = struct {
    inbound_events: usize = 512,
    brain_ticks: usize = 256,
    outbound_messages: usize = 512,
    control_events: usize = 128,
};

pub const TickResult = struct {
    brain: []u8,
    observe_json: []u8,
    tool_results: []brain_tools.ToolResult,
    checkpoint: u64,

    pub fn deinit(self: *TickResult, allocator: std.mem.Allocator) void {
        allocator.free(self.brain);
        allocator.free(self.observe_json);
        brain_tools.deinitResults(allocator, self.tool_results);
        self.* = undefined;
    }
};

pub const BrainProviderOverride = struct {
    provider_name: ?[]u8 = null,
    model_name: ?[]u8 = null,
    think_level: ?[]u8 = null,

    pub fn isEmpty(self: BrainProviderOverride) bool {
        return self.provider_name == null and self.model_name == null and self.think_level == null;
    }

    pub fn deinit(self: *BrainProviderOverride, allocator: std.mem.Allocator) void {
        if (self.provider_name) |value| allocator.free(value);
        if (self.model_name) |value| allocator.free(value);
        if (self.think_level) |value| allocator.free(value);
        self.* = .{};
    }
};

pub const BrainProviderOverrideInput = struct {
    provider_name: ?[]const u8 = null,
    model_name: ?[]const u8 = null,
    think_level: ?[]const u8 = null,
};

pub const BrainProviderOverrideView = struct {
    provider_name: ?[]const u8 = null,
    model_name: ?[]const u8 = null,
    think_level: ?[]const u8 = null,
};

pub const AgentRuntime = struct {
    allocator: std.mem.Allocator,
    agent_id: []u8,
    ltm_store: ?*ltm_store.VersionedMemStore = null,
    active_memory: memory.RuntimeMemory,
    bus: event_bus.EventBus,
    world_tools: tool_registry.ToolRegistry,
    brains: std.StringHashMapUnmanaged(brain_context.BrainContext) = .{},
    brain_provider_overrides: std.StringHashMapUnmanaged(BrainProviderOverride) = .{},
    tick_queue: std.ArrayListUnmanaged([]u8) = .{},
    outbound_messages: std.ArrayListUnmanaged([]u8) = .{},
    control_events: std.ArrayListUnmanaged([]u8) = .{},
    state: RuntimeState = .running,
    queue_limits: QueueLimits = .{},
    checkpoint: u64 = 0,
    hooks: hook_registry.HookRegistry,
    runtime_config: Config.RuntimeConfig,

    pub fn init(
        allocator: std.mem.Allocator,
        agent_id: []const u8,
        sub_brains: []const []const u8,
        runtime_config: Config.RuntimeConfig,
    ) !AgentRuntime {
        return initWithPersistence(allocator, agent_id, sub_brains, null, null, runtime_config);
    }

    pub fn initWithPersistence(
        allocator: std.mem.Allocator,
        agent_id: []const u8,
        sub_brains: []const []const u8,
        ltm_directory: ?[]const u8,
        ltm_filename: ?[]const u8,
        runtime_config: Config.RuntimeConfig,
    ) !AgentRuntime {
        var owned_store: ?*ltm_store.VersionedMemStore = null;
        if (ltm_directory) |directory| {
            const store_ptr = try allocator.create(ltm_store.VersionedMemStore);
            errdefer allocator.destroy(store_ptr);
            store_ptr.* = try ltm_store.VersionedMemStore.open(
                allocator,
                directory,
                ltm_filename orelse "runtime-memory.db",
            );
            owned_store = store_ptr;
        }

        var runtime = AgentRuntime{
            .allocator = allocator,
            .agent_id = try allocator.dupe(u8, agent_id),
            .ltm_store = owned_store,
            .active_memory = try memory.RuntimeMemory.initWithStore(allocator, agent_id, owned_store),
            .bus = event_bus.EventBus.init(allocator),
            .world_tools = tool_registry.ToolRegistry.init(allocator),
            .hooks = hook_registry.HookRegistry.init(allocator),
            .runtime_config = try runtime_config.clone(allocator),
        };
        errdefer runtime.deinit();

        try tool_executor.BuiltinTools.registerAll(&runtime.world_tools);

        // Register system hooks
        try system_hooks.registerSystemHooks(&runtime.hooks);

        // Register brain specialization hook (at priority 0)
        try brain_specialization.registerBrainSpecialization(&runtime.hooks, "primary");

        try runtime.addBrain("primary");
        for (sub_brains) |brain_name| {
            if (std.mem.eql(u8, brain_name, "primary")) continue;
            try runtime.addBrain(brain_name);
        }

        return runtime;
    }

    pub fn deinit(self: *AgentRuntime) void {
        var it = self.brains.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.brains.deinit(self.allocator);

        var provider_it = self.brain_provider_overrides.iterator();
        while (provider_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.brain_provider_overrides.deinit(self.allocator);

        for (self.tick_queue.items) |name| self.allocator.free(name);
        self.tick_queue.deinit(self.allocator);

        for (self.outbound_messages.items) |message| self.allocator.free(message);
        self.outbound_messages.deinit(self.allocator);

        for (self.control_events.items) |event| self.allocator.free(event);
        self.control_events.deinit(self.allocator);

        self.hooks.deinit();
        self.bus.deinit();
        self.world_tools.deinit();
        self.active_memory.deinit();
        self.runtime_config.deinit(self.allocator);
        if (self.ltm_store) |store| {
            store.close();
            self.allocator.destroy(store);
            self.ltm_store = null;
        }
        self.allocator.free(self.agent_id);
    }

    pub fn addBrain(self: *AgentRuntime, brain_name: []const u8) !void {
        if (self.brains.contains(brain_name)) return;

        const owned_name = try self.allocator.dupe(u8, brain_name);
        const context = try brain_context.BrainContext.init(self.allocator, brain_name);
        try self.brains.put(self.allocator, owned_name, context);
    }

    pub fn addBrainWithProviderOverride(
        self: *AgentRuntime,
        brain_name: []const u8,
        override: BrainProviderOverrideInput,
    ) !void {
        try self.addBrain(brain_name);
        try self.setBrainProviderOverride(brain_name, override);
    }

    pub fn setBrainProviderOverride(
        self: *AgentRuntime,
        brain_name: []const u8,
        override: BrainProviderOverrideInput,
    ) !void {
        if (!self.brains.contains(brain_name)) return RuntimeError.BrainNotFound;

        var owned = BrainProviderOverride{
            .provider_name = if (override.provider_name) |value| try self.allocator.dupe(u8, value) else null,
            .model_name = if (override.model_name) |value| try self.allocator.dupe(u8, value) else null,
            .think_level = if (override.think_level) |value| try self.allocator.dupe(u8, value) else null,
        };
        errdefer owned.deinit(self.allocator);

        if (owned.isEmpty()) {
            self.clearBrainProviderOverride(brain_name);
            return;
        }

        if (self.brain_provider_overrides.getPtr(brain_name)) |existing| {
            existing.deinit(self.allocator);
            existing.* = owned;
            return;
        }

        const owned_name = try self.allocator.dupe(u8, brain_name);
        try self.brain_provider_overrides.put(self.allocator, owned_name, owned);
    }

    pub fn clearBrainProviderOverride(self: *AgentRuntime, brain_name: []const u8) void {
        const removed = self.brain_provider_overrides.fetchRemove(brain_name) orelse return;
        self.allocator.free(removed.key);
        var value = removed.value;
        value.deinit(self.allocator);
    }

    pub fn getBrainProviderOverride(self: *const AgentRuntime, brain_name: []const u8) ?BrainProviderOverrideView {
        const value = self.brain_provider_overrides.get(brain_name) orelse return null;
        return .{
            .provider_name = value.provider_name,
            .model_name = value.model_name,
            .think_level = value.think_level,
        };
    }

    pub fn setState(self: *AgentRuntime, next_state: RuntimeState) !void {
        if (self.queue_limits.control_events == 0) {
            return RuntimeError.QueueSaturated;
        }

        while (self.control_events.items.len + 1 > self.queue_limits.control_events) {
            const removed = self.control_events.orderedRemove(0);
            self.allocator.free(removed);
        }

        self.state = next_state;
        const event = try std.fmt.allocPrint(self.allocator, "state:{s}", .{@tagName(next_state)});
        try self.control_events.append(self.allocator, event);
    }

    pub fn appendMessageMemory(self: *AgentRuntime, brain_name: []const u8, role: []const u8, content: []const u8) !void {
        const escaped_role = try jsonEscapeAlloc(self.allocator, role);
        defer self.allocator.free(escaped_role);
        const escaped_content = try jsonEscapeAlloc(self.allocator, content);
        defer self.allocator.free(escaped_content);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"role\":\"{s}\",\"content\":\"{s}\"}}",
            .{ escaped_role, escaped_content },
        );
        defer self.allocator.free(payload);

        var created = try self.active_memory.create(brain_name, null, "message", payload, false, false);
        created.deinit(self.allocator);
    }

    pub fn enqueueUserEvent(self: *AgentRuntime, content: []const u8) !void {
        if (self.state == .cancelled) return RuntimeError.RuntimeCancelled;
        if (self.state == .paused) return RuntimeError.RuntimePaused;

        if (self.bus.pendingCount() >= self.queue_limits.inbound_events) {
            return RuntimeError.QueueSaturated;
        }
        if (self.tick_queue.items.len >= self.queue_limits.brain_ticks) {
            return RuntimeError.QueueSaturated;
        }

        try self.bus.enqueue(.{
            .event_type = .user,
            .source_brain = "user",
            .target_brain = "primary",
            .payload = content,
        });

        try self.enqueueTick("primary");
    }

    pub fn queueToolUse(self: *AgentRuntime, brain_name: []const u8, tool_name: []const u8, args_json: []const u8) !void {
        const brain = self.brains.getPtr(brain_name) orelse return RuntimeError.BrainNotFound;
        try brain.queueToolUse(tool_name, args_json);
        errdefer {
            if (brain.pending_tool_uses.pop()) |rolled_back_value| {
                var rolled_back = rolled_back_value;
                rolled_back.deinit(self.allocator);
            }
        }
        try self.enqueueTick(brain_name);
    }

    pub fn refreshCorePrompt(self: *AgentRuntime, brain_name: []const u8) !void {
        if (!self.brains.contains(brain_name)) return RuntimeError.BrainNotFound;

        var ctx = hook_registry.HookContext.init(self, brain_name, self.checkpoint);
        defer ctx.deinit(self.allocator);

        var core = hook_registry.CorePrompt.init(self.allocator);
        defer core.deinit();

        try self.hooks.execute(.pre_observe, &ctx, .{ .pre_observe = &core });
        try self.syncCorePromptMemories(brain_name, &core);
    }

    pub fn rollbackQueuedUserPrimaryWork(self: *AgentRuntime, content: []const u8) void {
        _ = self.bus.removeLatestMatching(.user, "user", "primary", content) catch {};
        _ = self.removeLatestTick("primary");
    }

    pub fn tickNext(self: *AgentRuntime) !?TickResult {
        if (self.state == .cancelled) return RuntimeError.RuntimeCancelled;
        if (self.state == .paused) return RuntimeError.RuntimePaused;
        if (self.tick_queue.items.len == 0) return null;

        const brain_name = self.tick_queue.orderedRemove(0);
        defer self.allocator.free(brain_name);
        return try self.tickBrain(brain_name);
    }

    pub fn tickBrain(self: *AgentRuntime, brain_name: []const u8) !TickResult {
        if (self.state == .cancelled) return RuntimeError.RuntimeCancelled;
        if (self.state == .paused) return RuntimeError.RuntimePaused;

        const brain = self.brains.getPtr(brain_name) orelse return RuntimeError.BrainNotFound;

        // Setup hook context
        self.checkpoint += 1;
        var ctx = hook_registry.HookContext.init(self, brain_name, self.checkpoint);
        defer ctx.deinit(self.allocator);

        // === PRE_OBSERVE ===
        var rom = hook_registry.Rom.init(self.allocator);
        defer rom.deinit();

        try self.hooks.execute(.pre_observe, &ctx, .{ .pre_observe = &rom });
        try self.syncCorePromptMemories(brain_name, &rom);

        // Collect inbox events
        brain.clearInbox();
        const inbound = try self.bus.dequeueForBrain(self.allocator, brain_name);
        defer {
            for (inbound) |*event| event.deinit(self.allocator);
            self.allocator.free(inbound);
        }

        for (inbound) |event| {
            try brain.pushInbox(.{
                .event_type = event.event_type,
                .source_brain = try self.allocator.dupe(u8, event.source_brain),
                .target_brain = try self.allocator.dupe(u8, event.target_brain),
                .talk_id = event.talk_id,
                .payload = try self.allocator.dupe(u8, event.payload),
                .created_at_ms = event.created_at_ms,
            });
        }

        // === OBSERVE ===
        const snapshot = try self.active_memory.snapshotActive(self.allocator, brain_name);
        defer memory.deinitItems(self.allocator, snapshot);

        // Build observe_json from active memory snapshot
        const observe_json = try buildObserveJson(self.allocator, brain_name, snapshot);
        // Note: observe_json is owned by TickResult and freed in TickResult.deinit()

        // === POST_OBSERVE ===
        var observe_result = hook_registry.ObserveResult{
            .core = &rom,
            .inbox_count = brain.inbox.items.len,
        };
        try self.hooks.execute(.post_observe, &ctx, .{ .post_observe = &observe_result });

        // === PRE_MUTATE ===
        var pending_tools = hook_registry.PendingTools.init();
        defer pending_tools.deinit(self.allocator);

        // Convert brain's pending tool uses to hook format
        for (brain.pending_tool_uses.items) |tool_use| {
            try pending_tools.add(self.allocator, tool_use.name, tool_use.args_json);
        }
        try self.hooks.execute(.pre_mutate, &ctx, .{ .pre_mutate = &pending_tools });

        // Sync back to brain (hooks may have modified/removed tools)
        brain.clearPendingTools();
        for (pending_tools.tools.items) |tool| {
            try brain.queueToolUse(tool.name, tool.args_json);
        }

        // === MUTATE ===
        var engine = brain_tools.Engine.initWithWorldTools(self.allocator, &self.active_memory, &self.bus, &self.world_tools);
        const results = try engine.executePending(brain);
        errdefer brain_tools.deinitResults(self.allocator, results);

        // === POST_MUTATE ===
        var tool_results = hook_registry.ToolResults{ .results = results };
        try self.hooks.execute(.post_mutate, &ctx, .{ .post_mutate = &tool_results });

        // Store results as artifacts
        for (results) |result| {
            var artifact = try self.active_memory.create(brain_name, null, "tool_result", result.payload_json, false, false);
            artifact.deinit(self.allocator);
        }

        // === PRE_RESULTS ===
        var results_data = hook_registry.ResultsData{ .tool_results = &tool_results };
        try self.hooks.execute(.pre_results, &ctx, .{ .pre_results = &results_data });

        try self.enqueueTicksForPendingBrainEvents();

        const user_events = try self.bus.dequeueForBrain(self.allocator, "user");
        defer {
            for (user_events) |*event| event.deinit(self.allocator);
            self.allocator.free(user_events);
        }

        for (user_events) |event| {
            if (self.outbound_messages.items.len >= self.queue_limits.outbound_messages) {
                return RuntimeError.QueueSaturated;
            }
            try self.outbound_messages.append(self.allocator, try self.allocator.dupe(u8, event.payload));
        }

        // === POST_RESULTS ===
        var checkpoint_data = hook_registry.CheckpointData{
            .tick = self.checkpoint,
            .artifacts_count = results.len,
        };
        try self.hooks.execute(.post_results, &ctx, .{ .post_results = &checkpoint_data });

        return .{
            .brain = try self.allocator.dupe(u8, brain_name),
            .observe_json = observe_json,
            .tool_results = results,
            .checkpoint = self.checkpoint,
        };
    }

    pub fn drainOutbound(self: *AgentRuntime, allocator: std.mem.Allocator) ![][]u8 {
        var out = try allocator.alloc([]u8, self.outbound_messages.items.len);
        for (self.outbound_messages.items, 0..) |message, index| {
            out[index] = try allocator.dupe(u8, message);
            self.allocator.free(message);
        }
        self.outbound_messages.clearRetainingCapacity();
        return out;
    }

    fn enqueueTick(self: *AgentRuntime, brain_name: []const u8) !void {
        if (self.tick_queue.items.len >= self.queue_limits.brain_ticks) {
            return RuntimeError.QueueSaturated;
        }
        try self.tick_queue.append(self.allocator, try self.allocator.dupe(u8, brain_name));
    }

    fn enqueueTicksForPendingBrainEvents(self: *AgentRuntime) !void {
        var it = self.brains.iterator();
        while (it.next()) |entry| {
            const target_brain = entry.key_ptr.*;
            if (!self.bus.hasPendingForBrain(target_brain)) continue;
            if (self.hasQueuedTick(target_brain)) continue;
            try self.enqueueTick(target_brain);
        }
    }

    fn hasQueuedTick(self: *const AgentRuntime, brain_name: []const u8) bool {
        for (self.tick_queue.items) |queued_name| {
            if (std.mem.eql(u8, queued_name, brain_name)) return true;
        }
        return false;
    }

    fn removeLatestTick(self: *AgentRuntime, brain_name: []const u8) bool {
        var idx = self.tick_queue.items.len;
        while (idx > 0) {
            idx -= 1;
            if (!std.mem.eql(u8, self.tick_queue.items[idx], brain_name)) continue;
            const removed = self.tick_queue.orderedRemove(idx);
            self.allocator.free(removed);
            return true;
        }
        return false;
    }

    fn syncCorePromptMemories(
        self: *AgentRuntime,
        brain_name: []const u8,
        rom: *const hook_registry.Rom,
    ) !void {
        const active_snapshot = try self.active_memory.snapshotActive(self.allocator, brain_name);
        defer memory.deinitItems(self.allocator, active_snapshot);

        var expected_core_names = std.StringHashMapUnmanaged(void){};
        defer {
            var expected_it = expected_core_names.iterator();
            while (expected_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            expected_core_names.deinit(self.allocator);
        }

        var it = rom.entries.iterator();
        while (it.next()) |entry| {
            const core_kind = coreMemoryKindFromKey(entry.key_ptr.*);
            const core_name = try coreMemoryNameFromKey(self.allocator, entry.key_ptr.*);
            defer self.allocator.free(core_name);

            if (!expected_core_names.contains(core_name)) {
                const owned_core_name = try self.allocator.dupe(u8, core_name);
                errdefer self.allocator.free(owned_core_name);
                try expected_core_names.put(self.allocator, owned_core_name, {});
            }

            const escaped_content = try jsonEscapeAlloc(self.allocator, entry.value_ptr.value);
            defer self.allocator.free(escaped_content);
            const content_json = try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_content});
            defer self.allocator.free(content_json);

            if (findActiveByName(active_snapshot, core_name)) |item| {
                if (std.mem.eql(u8, item.content_json, content_json)) continue;

                var updated = self.active_memory.mutate(item.mem_id, content_json) catch |err| switch (err) {
                    memory.MemoryError.NotFound => blk: {
                        const recreated = try self.active_memory.create(
                            brain_name,
                            core_name,
                            core_kind,
                            content_json,
                            false,
                            true,
                        );
                        break :blk recreated;
                    },
                    else => return err,
                };
                updated.deinit(self.allocator);
                continue;
            }

            var created = try self.active_memory.create(
                brain_name,
                core_name,
                core_kind,
                content_json,
                false,
                true,
            );
            created.deinit(self.allocator);
        }

        for (active_snapshot) |item| {
            if (!isManagedCorePromptMemory(item)) continue;
            const parsed = memid.MemId.parse(item.mem_id) catch continue;
            if (expected_core_names.contains(parsed.name)) continue;

            var removed = self.active_memory.removeActive(item.mem_id) catch |err| switch (err) {
                memory.MemoryError.NotFound => continue,
                else => return err,
            };
            removed.deinit(self.allocator);
        }
    }

    fn coreMemoryNameFromKey(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(allocator);

        try out.appendSlice(allocator, "core.");
        for (key) |char| {
            if (std.ascii.isAlphanumeric(char) or char == '_' or char == '-' or char == '.') {
                try out.append(allocator, char);
                continue;
            }
            if (char == ':') {
                try out.append(allocator, '.');
                continue;
            }
            try out.append(allocator, '_');
        }

        return out.toOwnedSlice(allocator);
    }

    fn coreMemoryKindFromKey(key: []const u8) []const u8 {
        if (std.mem.eql(u8, key, system_hooks.BASE_CORE_ROM_KEY)) return "core.base_prompt";
        return "core.system_prompt";
    }

    fn isManagedCorePromptMemory(item: memory.ActiveMemoryItem) bool {
        if (!std.mem.eql(u8, item.kind, "core.system_prompt") and !std.mem.eql(u8, item.kind, "core.base_prompt")) {
            return false;
        }

        const parsed = memid.MemId.parse(item.mem_id) catch return false;
        return std.mem.startsWith(u8, parsed.name, "core.");
    }

    fn findActiveByName(snapshot: []const memory.ActiveMemoryItem, name: []const u8) ?memory.ActiveMemoryItem {
        for (snapshot) |item| {
            const parsed = memid.MemId.parse(item.mem_id) catch continue;
            if (std.mem.eql(u8, parsed.name, name)) return item;
        }
        return null;
    }

    /// Build observe JSON from active memory only
    fn buildObserveJson(
        allocator: std.mem.Allocator,
        brain_name: []const u8,
        snapshot: []const memory.ActiveMemoryItem,
    ) ![]u8 {
        // Start with active memory JSON
        var result = std.ArrayListUnmanaged(u8){};
        defer result.deinit(allocator);

        const writer = result.writer(allocator);

        // Build JSON manually so content can be embedded as JSON
        try writer.writeAll("{");

        // Active memory
        try writer.writeAll("\"brain\":");
        try writeJsonString(writer, brain_name);
        try writer.writeByte(',');
        try writer.writeAll("\"active_memory\":");

        // Serialize snapshot
        try writer.writeByte('[');
        for (snapshot, 0..) |item, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            // Use JSON escaping for all string fields
            try writer.writeAll("\"mem_id\":");
            try writeJsonString(writer, item.mem_id);
            try writer.writeByte(',');
            try writer.print("\"write_protected\":{},", .{!item.mutable});
            try writer.writeAll("\"kind\":");
            try writeJsonString(writer, item.kind);
            try writer.writeByte(',');
            try writer.print("\"unevictable\":{},", .{item.unevictable});
            try writer.writeAll("\"content\":");
            // Validate content_json is valid JSON, otherwise wrap as string
            if (isValidJson(item.content_json)) {
                try writer.writeAll(item.content_json);
            } else {
                try writeJsonString(writer, item.content_json);
            }
            try writer.writeByte('}');
        }
        try writer.writeByte(']');

        try writer.writeByte('}');

        return result.toOwnedSlice(allocator);
    }

    /// Check if a string is valid JSON
    fn isValidJson(str: []const u8) bool {
        // Try to parse as JSON - if it succeeds, it's valid
        const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, str, .{}) catch return false;
        parsed.deinit();
        return true;
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
};

pub fn deinitOutbound(allocator: std.mem.Allocator, messages: [][]u8) void {
    for (messages) |message| allocator.free(message);
    allocator.free(messages);
}

fn hasNamedMemory(items: []const memory.ActiveMemoryItem, name: []const u8) bool {
    for (items) |item| {
        const parsed = memid.MemId.parse(item.mem_id) catch continue;
        if (std.mem.eql(u8, parsed.name, name)) return true;
    }
    return false;
}

test "agent_runtime: create primary + sub brain and execute one tick" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{"research"}, cfg);
    defer runtime.deinit();

    try std.testing.expect(runtime.brains.contains("primary"));
    try std.testing.expect(runtime.brains.contains("research"));

    try runtime.queueToolUse("primary", "memory_create", "{\"kind\":\"message\",\"content\":{\"text\":\"hello\"}}");
    const result = (try runtime.tickNext()).?;
    defer {
        var mutable = result;
        mutable.deinit(allocator);
    }

    try std.testing.expectEqual(@as(u64, 1), result.checkpoint);
    try std.testing.expect(std.mem.indexOf(u8, result.observe_json, "\"active_memory\"") != null);
}

test "agent_runtime: brain provider overrides are mutable and clearable" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{"research"}, cfg);
    defer runtime.deinit();

    try runtime.setBrainProviderOverride("research", .{
        .provider_name = "openai-codex",
        .model_name = "gpt-5.1-codex-mini",
        .think_level = "high",
    });

    const first = runtime.getBrainProviderOverride("research").?;
    try std.testing.expectEqualStrings("openai-codex", first.provider_name.?);
    try std.testing.expectEqualStrings("gpt-5.1-codex-mini", first.model_name.?);
    try std.testing.expectEqualStrings("high", first.think_level.?);

    try runtime.setBrainProviderOverride("research", .{
        .model_name = "gpt-5.2",
    });
    const second = runtime.getBrainProviderOverride("research").?;
    try std.testing.expect(second.provider_name == null);
    try std.testing.expectEqualStrings("gpt-5.2", second.model_name.?);
    try std.testing.expect(second.think_level == null);

    try runtime.setBrainProviderOverride("research", .{});
    try std.testing.expect(runtime.getBrainProviderOverride("research") == null);
}

test "agent_runtime: addBrainWithProviderOverride applies spawn-time model settings" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    try runtime.addBrainWithProviderOverride("delegate", .{
        .provider_name = "openai",
        .model_name = "gpt-4.1-mini",
        .think_level = "medium",
    });

    try std.testing.expect(runtime.brains.contains("delegate"));
    const override = runtime.getBrainProviderOverride("delegate").?;
    try std.testing.expectEqualStrings("openai", override.provider_name.?);
    try std.testing.expectEqualStrings("gpt-4.1-mini", override.model_name.?);
    try std.testing.expectEqualStrings("medium", override.think_level.?);
}

test "agent_runtime: queue saturation returns explicit overload" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    runtime.queue_limits.brain_ticks = 1;
    try runtime.enqueueUserEvent("hello");
    try std.testing.expectError(RuntimeError.QueueSaturated, runtime.enqueueUserEvent("again"));
}

test "agent_runtime: refreshCorePrompt prunes stale managed core memory entries" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    var stale = try runtime.active_memory.create("primary", "core.stale_entry", "core.system_prompt", "\"stale\"", false, true);
    defer stale.deinit(allocator);

    const before = try runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, before);
    try std.testing.expect(hasNamedMemory(before, "core.stale_entry"));

    try runtime.refreshCorePrompt("primary");

    const after = try runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, after);
    try std.testing.expect(!hasNamedMemory(after, "core.stale_entry"));
}

test "agent_runtime: enqueueUserEvent rejects paused/cancelled without queuing work" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    runtime.state = .paused;
    try std.testing.expectError(RuntimeError.RuntimePaused, runtime.enqueueUserEvent("hello"));
    try std.testing.expectEqual(@as(usize, 0), runtime.tick_queue.items.len);
    try std.testing.expectEqual(@as(usize, 0), runtime.bus.pendingCount());

    runtime.state = .cancelled;
    try std.testing.expectError(RuntimeError.RuntimeCancelled, runtime.enqueueUserEvent("hello"));
    try std.testing.expectEqual(@as(usize, 0), runtime.tick_queue.items.len);
    try std.testing.expectEqual(@as(usize, 0), runtime.bus.pendingCount());
}

test "agent_runtime: setState evicts stale control events instead of saturating" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    runtime.queue_limits.control_events = 1;
    try runtime.setState(.paused);
    try runtime.setState(.running);
    try runtime.setState(.cancelled);

    try std.testing.expectEqual(@as(usize, 1), runtime.control_events.items.len);
    try std.testing.expect(std.mem.eql(u8, runtime.control_events.items[0], "state:cancelled"));
}

test "agent_runtime: queueToolUse rollback clears partially queued tool when tick enqueue fails" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    runtime.queue_limits.brain_ticks = 0;
    try std.testing.expectError(RuntimeError.QueueSaturated, runtime.queueToolUse("primary", "talk_user", "{\"message\":\"x\"}"));

    const primary = runtime.brains.getPtr("primary").?;
    try std.testing.expectEqual(@as(usize, 0), primary.pending_tool_uses.items.len);
}

test "agent_runtime: rollbackQueuedUserPrimaryWork removes pending user event and tick" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    try runtime.enqueueUserEvent("hello");
    try std.testing.expectEqual(@as(usize, 1), runtime.tick_queue.items.len);
    try std.testing.expectEqual(@as(usize, 1), runtime.bus.pendingCount());

    runtime.rollbackQueuedUserPrimaryWork("hello");
    try std.testing.expectEqual(@as(usize, 0), runtime.tick_queue.items.len);
    try std.testing.expectEqual(@as(usize, 0), runtime.bus.pendingCount());
}

test "agent_runtime: talk_brain plus wait_for correlates across brains" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{"research"}, cfg);
    defer runtime.deinit();

    try runtime.queueToolUse("primary", "talk_brain", "{\"message\":\"sync\",\"target_brain\":\"research\"}");
    try runtime.queueToolUse("primary", "wait_for", "{\"events\":[{\"event_type\":\"agent\",\"parameter\":\"research\"}]}");

    var primary_tick = (try runtime.tickNext()).?;
    defer primary_tick.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), primary_tick.tool_results.len);
    try std.testing.expect(primary_tick.tool_results[0].success);
    try std.testing.expect(primary_tick.tool_results[1].success);
    try std.testing.expect(std.mem.indexOf(u8, primary_tick.tool_results[1].payload_json, "\"waiting\":true") != null);

    const pending_after_primary = runtime.bus.pendingCount();
    try std.testing.expect(pending_after_primary >= 1);

    var research_tick = try runtime.tickBrain("research");
    defer research_tick.deinit(allocator);

    try std.testing.expect(runtime.bus.pendingCount() <= pending_after_primary);

    try runtime.bus.enqueue(.{
        .event_type = .agent,
        .source_brain = "research",
        .target_brain = "primary",
        .talk_id = 1,
        .payload = "ack",
    });

    var resolve_tick = try runtime.tickBrain("primary");
    defer resolve_tick.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), resolve_tick.tool_results.len);
    try std.testing.expect(resolve_tick.tool_results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, resolve_tick.tool_results[0].payload_json, "\"waiting\":false") != null);
}

test "agent_runtime: talk_brain schedules target brain tick for runtime loop" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agentA", &[_][]const u8{"research"}, cfg);
    defer runtime.deinit();

    try runtime.queueToolUse("primary", "talk_brain", "{\"message\":\"sync\",\"target_brain\":\"research\"}");

    var first_tick = (try runtime.tickNext()).?;
    defer first_tick.deinit(allocator);
    try std.testing.expectEqualStrings("primary", first_tick.brain);
    try std.testing.expectEqual(@as(usize, 1), first_tick.tool_results.len);
    try std.testing.expect(first_tick.tool_results[0].success);

    var second_tick = (try runtime.tickNext()).?;
    defer second_tick.deinit(allocator);
    try std.testing.expectEqualStrings("research", second_tick.brain);
}

test "agent_runtime: memory lifecycle create mutate evict load historical" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    const dir = try std.fmt.allocPrint(allocator, ".tmp-runtime-lifecycle-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var runtime = try AgentRuntime.initWithPersistence(allocator, "agentA", &[_][]const u8{}, dir, "runtime.db", cfg);
    defer runtime.deinit();

    try runtime.queueToolUse("primary", "memory_create", "{\"name\":\"memo\",\"kind\":\"note\",\"content\":{\"text\":\"v1\"}}");
    var create_tick = (try runtime.tickNext()).?;
    defer create_tick.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), create_tick.tool_results.len);
    try std.testing.expect(create_tick.tool_results[0].success);

    var create_payload = try std.json.parseFromSlice(std.json.Value, allocator, create_tick.tool_results[0].payload_json, .{});
    defer create_payload.deinit();
    const created_id = create_payload.value.object.get("mem_id").?.string;
    const created_id_copy = try allocator.dupe(u8, created_id);
    defer allocator.free(created_id_copy);

    const mutate_args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\",\"content\":{{\"text\":\"v2\"}}}}", .{created_id_copy});
    defer allocator.free(mutate_args);
    try runtime.queueToolUse("primary", "memory_mutate", mutate_args);
    var mutate_tick = (try runtime.tickNext()).?;
    defer mutate_tick.deinit(allocator);
    try std.testing.expect(mutate_tick.tool_results[0].success);

    var mutate_payload = try std.json.parseFromSlice(std.json.Value, allocator, mutate_tick.tool_results[0].payload_json, .{});
    defer mutate_payload.deinit();
    const mutated_id = mutate_payload.value.object.get("mem_id").?.string;
    const mutated_id_copy = try allocator.dupe(u8, mutated_id);
    defer allocator.free(mutated_id_copy);

    const evict_args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\"}}", .{mutated_id_copy});
    defer allocator.free(evict_args);
    try runtime.queueToolUse("primary", "memory_evict", evict_args);
    var evict_tick = (try runtime.tickNext()).?;
    defer evict_tick.deinit(allocator);
    try std.testing.expect(evict_tick.tool_results[0].success);

    const parsed = try @import("memid.zig").MemId.parse(mutated_id_copy);
    const latest_alias = try parsed.withVersion(null).format(allocator);
    defer allocator.free(latest_alias);

    const load_args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\",\"version\":1}}", .{latest_alias});
    defer allocator.free(load_args);
    try runtime.queueToolUse("primary", "memory_load", load_args);
    var load_tick = (try runtime.tickNext()).?;
    defer load_tick.deinit(allocator);
    try std.testing.expect(load_tick.tool_results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, load_tick.tool_results[0].payload_json, "\"v1\"") != null);
}

test "agent_runtime: appendMessageMemory escapes JSON control characters" {
    const allocator = std.testing.allocator;
    const cfg = Config.RuntimeConfig{};
    var runtime = try AgentRuntime.init(allocator, "agent-test", &[_][]const u8{}, cfg);
    defer runtime.deinit();

    const control_text = "a\x08b\x0cc\x01d";
    try runtime.appendMessageMemory("primary", "user", control_text);

    const snapshot = try runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(json);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const active = parsed.value.object.get("active_memory").?.object;
    const items = active.get("items").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), items.len);
    const payload = items[0].object.get("content").?.object;
    try std.testing.expectEqualStrings("user", payload.get("role").?.string);
    try std.testing.expectEqualStrings(control_text, payload.get("content").?.string);
}

fn jsonEscapeAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    const hex = "0123456789abcdef";

    for (raw) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            '\x08' => try out.appendSlice(allocator, "\\b"),
            '\x0c' => try out.appendSlice(allocator, "\\f"),
            else => {
                if (char < 0x20) {
                    try out.appendSlice(allocator, "\\u00");
                    try out.append(allocator, hex[@as(usize, (char >> 4) & 0x0f)]);
                    try out.append(allocator, hex[@as(usize, char & 0x0f)]);
                } else {
                    try out.append(allocator, char);
                }
            },
        }
    }
    return out.toOwnedSlice(allocator);
}
