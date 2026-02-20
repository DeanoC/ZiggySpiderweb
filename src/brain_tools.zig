const std = @import("std");
const memory = @import("memory.zig");
const brain_context = @import("brain_context.zig");
const event_bus = @import("event_bus.zig");
const tool_registry = @import("tool_registry.zig");

pub const ToolResult = struct {
    tool_name: []u8,
    success: bool,
    payload_json: []u8,

    pub fn deinit(self: *ToolResult, allocator: std.mem.Allocator) void {
        allocator.free(self.tool_name);
        allocator.free(self.payload_json);
        self.* = undefined;
    }
};

pub const ToolSchema = struct {
    name: []const u8,
    description: []const u8,
    required_fields: []const []const u8,
    optional_fields: []const []const u8 = &.{},
};

pub const brain_tool_schemas = [_]ToolSchema{
    .{ .name = "memory_load", .description = "Load memory by mem_id and optional version", .required_fields = &[_][]const u8{"mem_id"}, .optional_fields = &[_][]const u8{"version"} },
    .{ .name = "memory_evict", .description = "Evict memory by mem_id unless it is marked unevictable", .required_fields = &[_][]const u8{"mem_id"} },
    .{ .name = "memory_mutate", .description = "Mutate memory by mem_id unless it is write_protected", .required_fields = &[_][]const u8{ "mem_id", "content" } },
    .{ .name = "memory_create", .description = "Create memory entry. Optional flags: write_protected, unevictable.", .required_fields = &[_][]const u8{ "kind", "content" }, .optional_fields = &[_][]const u8{ "name", "write_protected", "unevictable" } },
    .{ .name = "memory_search", .description = "Keyword search memory entries", .required_fields = &[_][]const u8{"query"}, .optional_fields = &[_][]const u8{"limit"} },
    .{ .name = "wait_for", .description = "Wait for correlated talk/event", .required_fields = &[_][]const u8{"events"} },
    .{ .name = "talk_user", .description = "Send message to user channel", .required_fields = &[_][]const u8{"message"} },
    .{ .name = "talk_agent", .description = "Send message to another agent channel", .required_fields = &[_][]const u8{ "message", "target_brain" } },
    .{ .name = "talk_brain", .description = "Send message to another brain", .required_fields = &[_][]const u8{ "message", "target_brain" } },
    .{ .name = "talk_log", .description = "Emit runtime log talk event", .required_fields = &[_][]const u8{"message"} },
};

const WaitEventSpec = struct {
    event_type: event_bus.EventType,
    parameter: []u8,
    talk_id: ?event_bus.TalkId,

    fn deinit(self: *WaitEventSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.parameter);
        self.* = undefined;
    }
};

const WaitEvaluation = struct {
    requested_count: usize,
    matched_indices: []usize,

    fn deinit(self: *WaitEvaluation, allocator: std.mem.Allocator) void {
        allocator.free(self.matched_indices);
        self.* = undefined;
    }

    fn isSatisfied(self: *const WaitEvaluation) bool {
        return self.matched_indices.len == self.requested_count;
    }
};

const ExecuteOutcome = struct {
    result: ToolResult,
    blocked_on_wait: bool = false,
    talk_id: ?event_bus.TalkId = null,
};

const TalkOutcome = struct {
    result: ToolResult,
    talk_id: event_bus.TalkId,
};

const PendingWaitResolution = union(enum) {
    none,
    waiting,
    resolved: ToolResult,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    runtime_memory: *memory.RuntimeMemory,
    bus: *event_bus.EventBus,
    world_tools: ?*const tool_registry.ToolRegistry = null,

    pub fn init(
        allocator: std.mem.Allocator,
        runtime_memory: *memory.RuntimeMemory,
        bus: *event_bus.EventBus,
    ) Engine {
        return .{
            .allocator = allocator,
            .runtime_memory = runtime_memory,
            .bus = bus,
        };
    }

    pub fn initWithWorldTools(
        allocator: std.mem.Allocator,
        runtime_memory: *memory.RuntimeMemory,
        bus: *event_bus.EventBus,
        world_tools: ?*const tool_registry.ToolRegistry,
    ) Engine {
        return .{
            .allocator = allocator,
            .runtime_memory = runtime_memory,
            .bus = bus,
            .world_tools = world_tools,
        };
    }

    pub fn executePending(self: *Engine, brain: *brain_context.BrainContext) ![]ToolResult {
        var results = std.ArrayListUnmanaged(ToolResult){};
        errdefer {
            for (results.items) |*result| result.deinit(self.allocator);
            results.deinit(self.allocator);
        }

        switch (try self.resolvePendingWait(brain)) {
            .none => {},
            .waiting => return results.toOwnedSlice(self.allocator),
            .resolved => |resolved| try results.append(self.allocator, resolved),
        }

        var talk_ids = std.ArrayListUnmanaged(event_bus.TalkId){};
        defer talk_ids.deinit(self.allocator);

        while (brain.pending_tool_uses.items.len > 0) {
            var tool_use = brain.pending_tool_uses.orderedRemove(0);
            defer tool_use.deinit(self.allocator);

            const outcome = try self.executeOne(brain, tool_use, talk_ids.items);
            try results.append(self.allocator, outcome.result);
            if (outcome.blocked_on_wait) break;
            if (outcome.talk_id) |talk_id| try talk_ids.append(self.allocator, talk_id);
        }

        return results.toOwnedSlice(self.allocator);
    }

    pub fn generateSchemasJson(self: *Engine) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);

        try out.append(self.allocator, '[');
        for (brain_tool_schemas, 0..) |schema, index| {
            if (index > 0) try out.append(self.allocator, ',');

            try out.appendSlice(self.allocator, "{\"name\":\"");
            try appendJsonEscaped(self.allocator, &out, schema.name);
            try out.appendSlice(self.allocator, "\",\"description\":\"");
            try appendJsonEscaped(self.allocator, &out, schema.description);
            try out.appendSlice(self.allocator, "\",\"required\":[");

            for (schema.required_fields, 0..) |field, field_idx| {
                if (field_idx > 0) try out.append(self.allocator, ',');
                try out.append(self.allocator, '"');
                try appendJsonEscaped(self.allocator, &out, field);
                try out.append(self.allocator, '"');
            }

            try out.appendSlice(self.allocator, "]}");
        }
        try out.append(self.allocator, ']');

        return out.toOwnedSlice(self.allocator);
    }

    fn resolvePendingWait(self: *Engine, brain: *brain_context.BrainContext) !PendingWaitResolution {
        const pending_wait_json = brain.pending_wait_json orelse return .none;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, pending_wait_json, .{}) catch {
            brain.clearPendingWait();
            return .{ .resolved = try self.failure("wait_for", "invalid_state", "pending wait state is invalid") };
        };
        defer parsed.deinit();

        if (parsed.value != .object) {
            brain.clearPendingWait();
            return .{ .resolved = try self.failure("wait_for", "invalid_state", "pending wait state must be an object") };
        }

        const specs = self.parseWaitSpecs(parsed.value.object, null) catch {
            brain.clearPendingWait();
            return .{ .resolved = try self.failure("wait_for", "invalid_state", "pending wait events are invalid") };
        };
        defer deinitWaitSpecs(self.allocator, specs);

        var evaluation = try evaluateWaitSpecs(self.allocator, brain, specs);
        defer evaluation.deinit(self.allocator);

        if (!evaluation.isSatisfied()) {
            return .waiting;
        }

        const payload = try buildWaitPayload(self.allocator, brain, specs, &evaluation, false);
        brain.consumeInboxIndices(evaluation.matched_indices);
        brain.clearPendingWait();
        return .{ .resolved = try self.success("wait_for", payload) };
    }

    fn executeOne(
        self: *Engine,
        brain: *brain_context.BrainContext,
        tool_use: brain_context.ToolUse,
        talk_ids_in_batch: []const event_bus.TalkId,
    ) !ExecuteOutcome {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, tool_use.args_json, .{}) catch {
            return .{ .result = try self.failure(tool_use.name, "invalid_args", "Tool args must be valid JSON object") };
        };
        defer parsed.deinit();

        if (parsed.value != .object) {
            return .{ .result = try self.failure(tool_use.name, "invalid_args", "Tool args must be a JSON object") };
        }
        const args = parsed.value.object;

        if (std.mem.eql(u8, tool_use.name, "memory_create")) {
            return .{ .result = try self.execMemoryCreate(tool_use.name, brain, args) };
        }
        if (std.mem.eql(u8, tool_use.name, "memory_load")) {
            return .{ .result = try self.execMemoryLoad(tool_use.name, args) };
        }
        if (std.mem.eql(u8, tool_use.name, "memory_mutate")) {
            return .{ .result = try self.execMemoryMutate(tool_use.name, args) };
        }
        if (std.mem.eql(u8, tool_use.name, "memory_evict")) {
            return .{ .result = try self.execMemoryEvict(tool_use.name, args) };
        }
        if (std.mem.eql(u8, tool_use.name, "memory_search")) {
            return .{ .result = try self.execMemorySearch(tool_use.name, brain, args) };
        }
        if (std.mem.eql(u8, tool_use.name, "wait_for")) {
            return self.execWaitFor(tool_use.name, brain, args, talk_ids_in_batch);
        }
        if (std.mem.eql(u8, tool_use.name, "talk_user") or
            std.mem.eql(u8, tool_use.name, "talk_agent") or
            std.mem.eql(u8, tool_use.name, "talk_brain") or
            std.mem.eql(u8, tool_use.name, "talk_log"))
        {
            const talk = try self.execTalk(tool_use.name, brain, args);
            return .{ .result = talk.result, .talk_id = talk.talk_id };
        }

        if (self.world_tools != null) {
            return .{ .result = try self.execWorldTool(tool_use.name, args) };
        }

        return .{ .result = try self.failure(tool_use.name, "unsupported_tool", "Unsupported brain tool") };
    }

    fn execWorldTool(self: *Engine, tool_name: []const u8, args: std.json.ObjectMap) !ToolResult {
        const world_tools = self.world_tools orelse return self.failure(tool_name, "unsupported_tool", "Unsupported brain tool");
        const tool_call_id = if (args.get("_tool_call_id")) |value|
            if (value == .string) value.string else null
        else
            null;
        var outcome = world_tools.executeWorld(self.allocator, tool_name, args);
        defer outcome.deinit(self.allocator);

        return switch (outcome) {
            .success => |ok| {
                if (tool_call_id) |call_id| {
                    var wrapped_buf = std.ArrayListUnmanaged(u8){};
                    defer wrapped_buf.deinit(self.allocator);
                    try wrapped_buf.appendSlice(self.allocator, "{\"tool_call_id\":\"");
                    try appendJsonEscaped(self.allocator, &wrapped_buf, call_id);
                    try wrapped_buf.appendSlice(self.allocator, "\",\"result\":");
                    try wrapped_buf.appendSlice(self.allocator, ok.payload_json);
                    try wrapped_buf.append(self.allocator, '}');
                    const wrapped = try wrapped_buf.toOwnedSlice(self.allocator);
                    return self.success(tool_name, wrapped);
                }
                return self.success(tool_name, try self.allocator.dupe(u8, ok.payload_json));
            },
            .failure => |failure_info| {
                if (tool_call_id) |call_id| {
                    var wrapped_buf = std.ArrayListUnmanaged(u8){};
                    defer wrapped_buf.deinit(self.allocator);
                    try wrapped_buf.appendSlice(self.allocator, "{\"tool_call_id\":\"");
                    try appendJsonEscaped(self.allocator, &wrapped_buf, call_id);
                    try wrapped_buf.appendSlice(self.allocator, "\",\"error\":{\"code\":\"");
                    try appendJsonEscaped(self.allocator, &wrapped_buf, @tagName(failure_info.code));
                    try wrapped_buf.appendSlice(self.allocator, "\",\"message\":\"");
                    try appendJsonEscaped(self.allocator, &wrapped_buf, failure_info.message);
                    try wrapped_buf.appendSlice(self.allocator, "\"}}");
                    const wrapped = try wrapped_buf.toOwnedSlice(self.allocator);
                    return .{
                        .tool_name = try self.allocator.dupe(u8, tool_name),
                        .success = false,
                        .payload_json = wrapped,
                    };
                }
                return self.failure(tool_name, @tagName(failure_info.code), failure_info.message);
            },
        };
    }

    fn execMemoryCreate(
        self: *Engine,
        tool_name: []const u8,
        brain: *brain_context.BrainContext,
        args: std.json.ObjectMap,
    ) !ToolResult {
        const kind = getRequiredString(args, "kind") orelse {
            return self.failure(tool_name, "invalid_args", "memory_create requires 'kind'");
        };
        const content_value = args.get("content") orelse {
            return self.failure(tool_name, "invalid_args", "memory_create requires 'content'");
        };
        const content = try jsonValueToOwnedSlice(self.allocator, content_value);
        defer self.allocator.free(content);

        const name = if (args.get("name")) |value|
            if (value == .string) value.string else null
        else
            null;

        const write_protected = if (args.get("write_protected")) |value| blk: {
            if (value == .bool) break :blk value.bool;
            return self.failure(tool_name, "invalid_args", "memory_create write_protected must be a boolean");
        } else false;

        // Parse optional unevictable flag (defaults to false)
        const unevictable = if (args.get("unevictable")) |value| blk: {
            if (value == .bool) break :blk value.bool;
            return self.failure(tool_name, "invalid_args", "memory_create unevictable must be a boolean");
        } else false;

        var created = self.runtime_memory.create(brain.brain_name, name, kind, content, write_protected, unevictable) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };
        defer created.deinit(self.allocator);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"mem_id\":\"{s}\",\"version\":{d},\"write_protected\":{},\"unevictable\":{}}}",
            .{ created.mem_id, created.version orelse 0, !created.mutable, created.unevictable },
        );
        return self.success(tool_name, payload);
    }

    fn execMemoryLoad(self: *Engine, tool_name: []const u8, args: std.json.ObjectMap) !ToolResult {
        const mem_id = getRequiredString(args, "mem_id") orelse {
            return self.failure(tool_name, "invalid_args", "memory_load requires 'mem_id'");
        };
        const version = getOptionalU64(args, "version") catch {
            return self.failure(tool_name, "invalid_args", "memory_load version must be a non-negative integer");
        };

        var loaded = self.runtime_memory.load(mem_id, version) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };
        defer loaded.deinit(self.allocator);

        const rendered_content = try renderJsonValue(self.allocator, loaded.content_json);
        defer self.allocator.free(rendered_content);

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);

        try payload.appendSlice(self.allocator, "{\"mem_id\":\"");
        try appendJsonEscaped(self.allocator, &payload, loaded.mem_id);
        try payload.appendSlice(self.allocator, "\",\"version\":");
        try payload.writer(self.allocator).print("{d}", .{loaded.version orelse 0});
        try payload.appendSlice(self.allocator, ",\"kind\":\"");
        try appendJsonEscaped(self.allocator, &payload, loaded.kind);
        try payload.appendSlice(self.allocator, "\",\"write_protected\":");
        try payload.appendSlice(self.allocator, if (loaded.mutable) "false" else "true");
        try payload.appendSlice(self.allocator, ",\"unevictable\":");
        try payload.appendSlice(self.allocator, if (loaded.unevictable) "true" else "false");
        try payload.appendSlice(self.allocator, ",\"content\":");
        try payload.appendSlice(self.allocator, rendered_content);
        try payload.appendSlice(self.allocator, "}");

        const payload_json = try payload.toOwnedSlice(self.allocator);
        return self.success(tool_name, payload_json);
    }

    fn execMemoryMutate(self: *Engine, tool_name: []const u8, args: std.json.ObjectMap) !ToolResult {
        const mem_id = getRequiredString(args, "mem_id") orelse {
            return self.failure(tool_name, "invalid_args", "memory_mutate requires 'mem_id'");
        };
        const content_value = args.get("content") orelse {
            return self.failure(tool_name, "invalid_args", "memory_mutate requires 'content'");
        };
        const content = try jsonValueToOwnedSlice(self.allocator, content_value);
        defer self.allocator.free(content);

        var mutated = self.runtime_memory.mutate(mem_id, content) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };
        defer mutated.deinit(self.allocator);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"mem_id\":\"{s}\",\"version\":{d}}}",
            .{ mutated.mem_id, mutated.version orelse 0 },
        );
        return self.success(tool_name, payload);
    }

    fn execMemoryEvict(self: *Engine, tool_name: []const u8, args: std.json.ObjectMap) !ToolResult {
        const mem_id = getRequiredString(args, "mem_id") orelse {
            return self.failure(tool_name, "invalid_args", "memory_evict requires 'mem_id'");
        };

        var evicted = self.runtime_memory.evict(mem_id) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };
        defer evicted.deinit(self.allocator);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"mem_id\":\"{s}\",\"version\":{d},\"evicted\":true}}",
            .{ evicted.mem_id, evicted.version orelse 0 },
        );
        return self.success(tool_name, payload);
    }

    fn execMemorySearch(
        self: *Engine,
        tool_name: []const u8,
        brain: *brain_context.BrainContext,
        args: std.json.ObjectMap,
    ) !ToolResult {
        const query = getRequiredString(args, "query") orelse {
            return self.failure(tool_name, "invalid_args", "memory_search requires 'query'");
        };
        const limit = getOptionalUsize(args, "limit") catch {
            return self.failure(tool_name, "invalid_args", "memory_search limit must be a non-negative integer");
        } orelse 25;

        const found = self.runtime_memory.search(self.allocator, brain.brain_name, query, limit) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };
        defer memory.deinitItems(self.allocator, found);

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);

        try payload.appendSlice(self.allocator, "{\"results\":[");
        for (found, 0..) |item, index| {
            if (index > 0) try payload.append(self.allocator, ',');
            const row = try std.fmt.allocPrint(
                self.allocator,
                "{{\"mem_id\":\"{s}\",\"version\":{d},\"kind\":\"{s}\",\"write_protected\":{},\"unevictable\":{}}}",
                .{ item.mem_id, item.version orelse 0, item.kind, !item.mutable, item.unevictable },
            );
            defer self.allocator.free(row);
            try payload.appendSlice(self.allocator, row);
        }
        try payload.appendSlice(self.allocator, "]}");

        return self.success(tool_name, try payload.toOwnedSlice(self.allocator));
    }

    fn execTalk(
        self: *Engine,
        tool_name: []const u8,
        brain: *brain_context.BrainContext,
        args: std.json.ObjectMap,
    ) !TalkOutcome {
        const message = getRequiredString(args, "message") orelse {
            return .{ .result = try self.failure(tool_name, "invalid_args", "talk_* requires 'message'"), .talk_id = 0 };
        };

        const talk_id = brain.nextTalkId();
        var target_brain: []const u8 = "";
        if (std.mem.eql(u8, tool_name, "talk_user")) {
            target_brain = "user";
        } else if (std.mem.eql(u8, tool_name, "talk_log")) {
            target_brain = "log";
        } else if (std.mem.eql(u8, tool_name, "talk_brain")) {
            target_brain = getRequiredString(args, "target_brain") orelse {
                return .{ .result = try self.failure(tool_name, "invalid_args", "talk_brain requires 'target_brain'"), .talk_id = 0 };
            };
        } else if (std.mem.eql(u8, tool_name, "talk_agent")) {
            target_brain = getRequiredString(args, "target_brain") orelse {
                return .{ .result = try self.failure(tool_name, "invalid_args", "talk_agent requires 'target_brain'"), .talk_id = 0 };
            };
            if (target_brain.len == 0 or std.mem.eql(u8, target_brain, "user")) {
                return .{ .result = try self.failure(tool_name, "invalid_args", "talk_agent target_brain must be a non-user brain"), .talk_id = 0 };
            }
        }

        self.bus.enqueue(.{
            .event_type = .talk,
            .source_brain = brain.brain_name,
            .target_brain = target_brain,
            .talk_id = talk_id,
            .payload = message,
        }) catch |err| {
            return .{ .result = try self.failure(tool_name, "execution_failed", @errorName(err)), .talk_id = 0 };
        };

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);
        try payload.appendSlice(self.allocator, "{\"talk_id\":");
        try payload.writer(self.allocator).print("{d}", .{talk_id});
        try payload.appendSlice(self.allocator, ",\"message\":\"");
        try appendJsonEscaped(self.allocator, &payload, message);
        try payload.appendSlice(self.allocator, "\"}");
        return .{ .result = try self.success(tool_name, try payload.toOwnedSlice(self.allocator)), .talk_id = talk_id };
    }

    fn execWaitFor(
        self: *Engine,
        tool_name: []const u8,
        brain: *brain_context.BrainContext,
        args: std.json.ObjectMap,
        talk_ids_in_batch: []const event_bus.TalkId,
    ) !ExecuteOutcome {
        if (talk_ids_in_batch.len == 0) {
            return .{ .result = try self.failure(tool_name, "invalid_sequence", "wait_for requires at least one prior talk_* in the same tool-use list") };
        }

        const default_talk_id = talk_ids_in_batch[talk_ids_in_batch.len - 1];
        const specs = self.parseWaitSpecs(args, default_talk_id) catch {
            return .{ .result = try self.failure(tool_name, "invalid_args", "wait_for requires non-empty 'events' with valid event_type/parameter/talk_id fields") };
        };
        defer deinitWaitSpecs(self.allocator, specs);

        var evaluation = try evaluateWaitSpecs(self.allocator, brain, specs);
        defer evaluation.deinit(self.allocator);

        if (evaluation.isSatisfied()) {
            const payload = try buildWaitPayload(self.allocator, brain, specs, &evaluation, false);
            brain.consumeInboxIndices(evaluation.matched_indices);
            brain.clearPendingWait();
            return .{ .result = try self.success(tool_name, payload) };
        }

        const wait_json = try serializeWaitSpecs(self.allocator, specs);
        defer self.allocator.free(wait_json);
        try brain.setPendingWait(wait_json);

        const waiting_payload = try buildWaitPayload(self.allocator, brain, specs, &evaluation, true);
        return .{
            .result = try self.success(tool_name, waiting_payload),
            .blocked_on_wait = true,
        };
    }

    fn success(self: *Engine, tool_name: []const u8, payload: []u8) !ToolResult {
        return .{
            .tool_name = try self.allocator.dupe(u8, tool_name),
            .success = true,
            .payload_json = payload,
        };
    }

    fn failure(self: *Engine, tool_name: []const u8, code: []const u8, message: []const u8) !ToolResult {
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ code, message },
        );
        return .{
            .tool_name = try self.allocator.dupe(u8, tool_name),
            .success = false,
            .payload_json = payload,
        };
    }

    fn parseWaitSpecs(
        self: *Engine,
        args: std.json.ObjectMap,
        default_talk_id: ?event_bus.TalkId,
    ) ![]WaitEventSpec {
        const events_value = args.get("events") orelse return error.InvalidWait;
        if (events_value != .array or events_value.array.items.len == 0) return error.InvalidWait;

        var specs = std.ArrayListUnmanaged(WaitEventSpec){};
        errdefer {
            for (specs.items) |*spec| spec.deinit(self.allocator);
            specs.deinit(self.allocator);
        }

        for (events_value.array.items) |entry| {
            if (entry != .object) return error.InvalidWait;
            const event_obj = entry.object;

            const event_type_raw = getRequiredString(event_obj, "event_type") orelse return error.InvalidWait;
            const parsed_event_type = parseWaitEventType(event_type_raw) orelse return error.InvalidWait;

            const parameter_raw = if (event_obj.get("parameter")) |value|
                if (value == .string) value.string else return error.InvalidWait
            else
                "";

            var talk_id = default_talk_id;
            if (event_obj.get("talk_id")) |talk_value| {
                if (talk_value == .null) {
                    talk_id = null;
                } else {
                    if (talk_value != .integer or talk_value.integer < 0 or talk_value.integer > std.math.maxInt(event_bus.TalkId)) {
                        return error.InvalidWait;
                    }
                    talk_id = if (talk_value.integer == 0) null else @intCast(talk_value.integer);
                }
            }

            try specs.append(self.allocator, .{
                .event_type = parsed_event_type,
                .parameter = try self.allocator.dupe(u8, parameter_raw),
                .talk_id = talk_id,
            });
        }

        return specs.toOwnedSlice(self.allocator);
    }
};

pub fn deinitResults(allocator: std.mem.Allocator, results: []ToolResult) void {
    for (results) |*result| result.deinit(allocator);
    allocator.free(results);
}

fn evaluateWaitSpecs(
    allocator: std.mem.Allocator,
    brain: *brain_context.BrainContext,
    specs: []const WaitEventSpec,
) !WaitEvaluation {
    var used = std.AutoHashMapUnmanaged(usize, void){};
    defer used.deinit(allocator);

    var matched_indices = std.ArrayListUnmanaged(usize){};
    errdefer matched_indices.deinit(allocator);

    for (specs) |spec| {
        var found: ?usize = null;
        for (brain.inbox.items, 0..) |event, index| {
            if (used.contains(index)) continue;
            if (!waitSpecMatchesEvent(&spec, &event)) continue;
            found = index;
            break;
        }

        if (found) |index| {
            try matched_indices.append(allocator, index);
            try used.put(allocator, index, {});
        } else {
            break;
        }
    }

    return .{
        .requested_count = specs.len,
        .matched_indices = try matched_indices.toOwnedSlice(allocator),
    };
}

fn waitSpecMatchesEvent(spec: *const WaitEventSpec, event: *const event_bus.Event) bool {
    if (!waitEventTypeMatches(spec.event_type, event.event_type)) return false;

    if (spec.talk_id) |required_talk_id| {
        const event_talk_id = event.talk_id orelse return false;
        if (event_talk_id != required_talk_id) return false;
    }

    return waitParameterMatches(spec, event);
}

fn waitEventTypeMatches(spec_type: event_bus.EventType, event_type: event_bus.EventType) bool {
    return switch (spec_type) {
        .user => event_type == .user,
        .agent => event_type == .agent or event_type == .talk,
        .time => event_type == .time,
        .hook => event_type == .hook,
        else => false,
    };
}

fn waitParameterMatches(spec: *const WaitEventSpec, event: *const event_bus.Event) bool {
    if (spec.parameter.len == 0) return true;

    return switch (spec.event_type) {
        .user => true,
        .agent => std.mem.eql(u8, event.source_brain, spec.parameter) or std.mem.eql(u8, event.target_brain, spec.parameter),
        .time => std.mem.eql(u8, event.payload, spec.parameter),
        .hook => std.mem.eql(u8, event.payload, spec.parameter),
        else => false,
    };
}

fn serializeWaitSpecs(allocator: std.mem.Allocator, specs: []const WaitEventSpec) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"events\":[");
    for (specs, 0..) |spec, index| {
        if (index > 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, "{\"event_type\":\"");
        try out.appendSlice(allocator, waitEventTypeName(spec.event_type));
        try out.appendSlice(allocator, "\",\"parameter\":\"");
        try appendJsonEscaped(allocator, &out, spec.parameter);
        try out.appendSlice(allocator, "\",\"talk_id\":");
        if (spec.talk_id) |talk_id| {
            const text = try std.fmt.allocPrint(allocator, "{d}", .{talk_id});
            defer allocator.free(text);
            try out.appendSlice(allocator, text);
        } else {
            try out.appendSlice(allocator, "null");
        }
        try out.append(allocator, '}');
    }
    try out.appendSlice(allocator, "]}");

    return out.toOwnedSlice(allocator);
}

fn buildWaitPayload(
    allocator: std.mem.Allocator,
    brain: *brain_context.BrainContext,
    specs: []const WaitEventSpec,
    evaluation: *const WaitEvaluation,
    waiting: bool,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"waiting\":");
    try out.appendSlice(allocator, if (waiting) "true" else "false");

    const matched_count_text = try std.fmt.allocPrint(allocator, "{d}", .{evaluation.matched_indices.len});
    defer allocator.free(matched_count_text);
    const requested_count_text = try std.fmt.allocPrint(allocator, "{d}", .{specs.len});
    defer allocator.free(requested_count_text);

    try out.appendSlice(allocator, ",\"matched_count\":");
    try out.appendSlice(allocator, matched_count_text);
    try out.appendSlice(allocator, ",\"requested_count\":");
    try out.appendSlice(allocator, requested_count_text);
    try out.appendSlice(allocator, ",\"matches\":[");

    for (evaluation.matched_indices, 0..) |index, match_idx| {
        if (match_idx > 0) try out.append(allocator, ',');

        const event = brain.inbox.items[index];
        try out.appendSlice(allocator, "{\"event_type\":\"");
        try out.appendSlice(allocator, @tagName(event.event_type));
        try out.appendSlice(allocator, "\",\"source\":\"");
        try appendJsonEscaped(allocator, &out, event.source_brain);
        try out.appendSlice(allocator, "\",\"target\":\"");
        try appendJsonEscaped(allocator, &out, event.target_brain);
        try out.appendSlice(allocator, "\",\"talk_id\":");
        if (event.talk_id) |talk_id| {
            const text = try std.fmt.allocPrint(allocator, "{d}", .{talk_id});
            defer allocator.free(text);
            try out.appendSlice(allocator, text);
        } else {
            try out.appendSlice(allocator, "null");
        }
        try out.appendSlice(allocator, ",\"payload\":\"");
        try appendJsonEscaped(allocator, &out, event.payload);
        try out.appendSlice(allocator, "\"}");
    }

    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn deinitWaitSpecs(allocator: std.mem.Allocator, specs: []WaitEventSpec) void {
    for (specs) |*spec| spec.deinit(allocator);
    allocator.free(specs);
}

fn waitEventTypeName(event_type: event_bus.EventType) []const u8 {
    return switch (event_type) {
        .user => "user",
        .agent => "agent",
        .time => "time",
        .hook => "hook",
        .talk => "agent",
        .tool => "hook",
    };
}

fn parseWaitEventType(raw: []const u8) ?event_bus.EventType {
    if (std.ascii.eqlIgnoreCase(raw, "user")) return .user;
    if (std.ascii.eqlIgnoreCase(raw, "agent")) return .agent;
    if (std.ascii.eqlIgnoreCase(raw, "time")) return .time;
    if (std.ascii.eqlIgnoreCase(raw, "hook")) return .hook;
    return null;
}

fn getRequiredString(args: std.json.ObjectMap, field: []const u8) ?[]const u8 {
    const value = args.get(field) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn getOptionalU64(args: std.json.ObjectMap, field: []const u8) !?u64 {
    const value = args.get(field) orelse return null;
    if (value != .integer) return error.InvalidType;
    if (value.integer < 0) return error.InvalidType;
    return @intCast(value.integer);
}

fn getOptionalUsize(args: std.json.ObjectMap, field: []const u8) !?usize {
    const value = args.get(field) orelse return null;
    if (value != .integer) return error.InvalidType;
    if (value.integer < 0) return error.InvalidType;
    return @intCast(value.integer);
}

fn appendJsonEscaped(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), input: []const u8) !void {
    for (input) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, char),
        }
    }
}

fn renderJsonValue(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(allocator);
        try out.append(allocator, '"');
        try appendJsonEscaped(allocator, &out, raw);
        try out.append(allocator, '"');
        return out.toOwnedSlice(allocator);
    };
    defer parsed.deinit();
    return allocator.dupe(u8, raw);
}

fn jsonValueToOwnedSlice(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})});
}

fn testExtractStringField(allocator: std.mem.Allocator, payload_json: []const u8, field: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;

    const value = parsed.value.object.get(field) orelse return error.MissingField;
    if (value != .string) return error.InvalidFieldType;
    return allocator.dupe(u8, value.string);
}

fn testExtractTalkId(allocator: std.mem.Allocator, payload_json: []const u8) !event_bus.TalkId {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;

    const value = parsed.value.object.get("talk_id") orelse return error.MissingField;
    if (value != .integer or value.integer <= 0) return error.InvalidFieldType;
    return @intCast(value.integer);
}

fn deinitEvents(allocator: std.mem.Allocator, events: []event_bus.Event) void {
    for (events) |*event| event.deinit(allocator);
    allocator.free(events);
}

test "brain_tools: wait_for fails without prior talk" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    try brain.queueToolUse("wait_for", "{\"events\":[{\"event_type\":\"agent\",\"parameter\":\"primary\"}]}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "invalid_sequence") != null);
}

test "brain_tools: talk then wait_for blocks until correlated event arrives" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    try brain.queueToolUse("talk_brain", "{\"message\":\"hello\",\"target_brain\":\"delegate\"}");
    try brain.queueToolUse("wait_for", "{\"events\":[{\"event_type\":\"agent\",\"parameter\":\"delegate\"}]}");

    var engine = Engine.init(allocator, &mem, &bus);
    const first_results = try engine.executePending(&brain);
    defer deinitResults(allocator, first_results);

    try std.testing.expectEqual(@as(usize, 2), first_results.len);
    try std.testing.expect(first_results[0].success);
    try std.testing.expect(first_results[1].success);
    try std.testing.expect(std.mem.indexOf(u8, first_results[1].payload_json, "\"waiting\":true") != null);
    try std.testing.expect(brain.hasPendingWait());

    try brain.pushInbox(.{
        .event_type = .agent,
        .source_brain = try allocator.dupe(u8, "delegate"),
        .target_brain = try allocator.dupe(u8, "primary"),
        .talk_id = 1,
        .payload = try allocator.dupe(u8, "ack"),
        .created_at_ms = std.time.milliTimestamp(),
    });

    const second_results = try engine.executePending(&brain);
    defer deinitResults(allocator, second_results);

    try std.testing.expectEqual(@as(usize, 1), second_results.len);
    try std.testing.expect(second_results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, second_results[0].payload_json, "\"waiting\":false") != null);
    try std.testing.expect(!brain.hasPendingWait());
    try std.testing.expectEqual(@as(usize, 0), brain.inbox.items.len);
}

test "brain_tools: memory_mutate requires mem_id" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    try brain.queueToolUse("memory_mutate", "{\"content\":\"{}\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "requires 'mem_id'") != null);
}

test "brain_tools: memory_create then memory_load succeeds" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    try brain.queueToolUse("memory_create", "{\"name\":\"draft\",\"kind\":\"note\",\"content\":{\"text\":\"draft content\"}}");

    var engine = Engine.init(allocator, &mem, &bus);
    const create_results = try engine.executePending(&brain);
    defer deinitResults(allocator, create_results);

    try std.testing.expectEqual(@as(usize, 1), create_results.len);
    try std.testing.expect(create_results[0].success);

    const created_mem_id = try testExtractStringField(allocator, create_results[0].payload_json, "mem_id");
    defer allocator.free(created_mem_id);

    const load_args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\"}}", .{created_mem_id});
    defer allocator.free(load_args);
    try brain.queueToolUse("memory_load", load_args);

    const load_results = try engine.executePending(&brain);
    defer deinitResults(allocator, load_results);

    try std.testing.expectEqual(@as(usize, 1), load_results.len);
    try std.testing.expect(load_results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, load_results[0].payload_json, created_mem_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, load_results[0].payload_json, "draft content") != null);
}

test "brain_tools: memory_load escapes kind in JSON payload" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var created = try mem.create("primary", "escaped_kind", "note \"x\" \\ slash\nline", "{\"text\":\"v\"}", false, false);
    defer created.deinit(allocator);

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    const load_args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\"}}", .{created.mem_id});
    defer allocator.free(load_args);
    try brain.queueToolUse("memory_load", load_args);

    var engine = Engine.init(allocator, &mem, &bus);
    const load_results = try engine.executePending(&brain);
    defer deinitResults(allocator, load_results);

    try std.testing.expectEqual(@as(usize, 1), load_results.len);
    try std.testing.expect(load_results[0].success);

    const loaded_kind = try testExtractStringField(allocator, load_results[0].payload_json, "kind");
    defer allocator.free(loaded_kind);
    try std.testing.expectEqualStrings("note \"x\" \\ slash\nline", loaded_kind);
}

test "brain_tools: memory_mutate success bumps version" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var created = try mem.create("primary", "mutable", "note", "{\"text\":\"v1\"}", false, false);
    defer created.deinit(allocator);

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    const mutate_args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\",\"content\":{{\"text\":\"v2\"}}}}", .{created.mem_id});
    defer allocator.free(mutate_args);
    try brain.queueToolUse("memory_mutate", mutate_args);

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "\"version\":2") != null);
}

test "brain_tools: memory_evict success and missing mem_id failure" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var created = try mem.create("primary", "evictable", "note", "{\"text\":\"bye\"}", false, false);
    defer created.deinit(allocator);

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    const evict_args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\"}}", .{created.mem_id});
    defer allocator.free(evict_args);
    try brain.queueToolUse("memory_evict", evict_args);
    try brain.queueToolUse("memory_evict", "{}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "\"evicted\":true") != null);
    try std.testing.expect(!results[1].success);
    try std.testing.expect(std.mem.indexOf(u8, results[1].payload_json, "requires 'mem_id'") != null);
}

test "brain_tools: memory_search returns matching mem_id set" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var compile_item = try mem.create("primary", "compile_task", "note", "{\"text\":\"compile fix\"}", false, false);
    defer compile_item.deinit(allocator);
    var docs_item = try mem.create("primary", "docs_task", "note", "{\"text\":\"docs update\"}", false, false);
    defer docs_item.deinit(allocator);

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    try brain.queueToolUse("memory_search", "{\"query\":\"compile\",\"limit\":10}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, compile_item.mem_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, docs_item.mem_id) == null);
}

test "brain_tools: talk_user emits user-targeted event" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_user", "{\"message\":\"hello user\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    const talk_id = try testExtractTalkId(allocator, results[0].payload_json);

    const user_events = try bus.dequeueForBrain(allocator, "user");
    defer deinitEvents(allocator, user_events);
    try std.testing.expectEqual(@as(usize, 1), user_events.len);
    try std.testing.expectEqual(event_bus.EventType.talk, user_events[0].event_type);
    try std.testing.expectEqual(@as(?event_bus.TalkId, talk_id), user_events[0].talk_id);
}

test "brain_tools: talk payload preserves JSON validity for escaped content" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_user", "{\"message\":\"quote \\\"line\\\"\\\\path\\nnext\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);

    const payload_message = try testExtractStringField(allocator, results[0].payload_json, "message");
    defer allocator.free(payload_message);
    try std.testing.expectEqualStrings("quote \"line\"\\path\nnext", payload_message);
}

test "brain_tools: talk_agent emits delegated event" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_agent", "{\"message\":\"handoff\",\"target_brain\":\"delegate\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    const talk_id = try testExtractTalkId(allocator, results[0].payload_json);

    const delegate_events = try bus.dequeueForBrain(allocator, "delegate");
    defer deinitEvents(allocator, delegate_events);
    try std.testing.expectEqual(@as(usize, 1), delegate_events.len);
    try std.testing.expectEqual(@as(?event_bus.TalkId, talk_id), delegate_events[0].talk_id);
}

test "brain_tools: talk_agent requires explicit target_brain" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_agent", "{\"message\":\"handoff\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "talk_agent requires 'target_brain'") != null);
    try std.testing.expectEqual(@as(usize, 0), bus.pendingCount());
}

test "brain_tools: talk_agent rejects user target to avoid delivery leak" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_agent", "{\"message\":\"handoff\",\"target_brain\":\"user\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "must be a non-user brain") != null);
    try std.testing.expectEqual(@as(usize, 0), bus.pendingCount());
}

test "brain_tools: talk_log emits log-targeted event" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_log", "{\"message\":\"log line\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    const talk_id = try testExtractTalkId(allocator, results[0].payload_json);

    const log_events = try bus.dequeueForBrain(allocator, "log");
    defer deinitEvents(allocator, log_events);
    try std.testing.expectEqual(@as(usize, 1), log_events.len);
    try std.testing.expectEqual(@as(?event_bus.TalkId, talk_id), log_events[0].talk_id);
}

test "brain_tools: talk_brain requires target_brain" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_brain", "{\"message\":\"missing target\"}");

    var engine = Engine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "talk_brain requires 'target_brain'") != null);
}

test "brain_tools: wait_for honors explicit talk_id correlation" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    brain.next_talk_id = 41;

    try brain.queueToolUse("talk_user", "{\"message\":\"first\"}");
    try brain.queueToolUse("talk_brain", "{\"message\":\"second\",\"target_brain\":\"delegate\"}");
    try brain.queueToolUse("wait_for", "{\"events\":[{\"event_type\":\"agent\",\"parameter\":\"delegate\",\"talk_id\":42}]}");

    var engine = Engine.init(allocator, &mem, &bus);
    const first_results = try engine.executePending(&brain);
    defer deinitResults(allocator, first_results);
    try std.testing.expectEqual(@as(usize, 3), first_results.len);
    try std.testing.expect(std.mem.indexOf(u8, first_results[2].payload_json, "\"waiting\":true") != null);
    try std.testing.expect(brain.hasPendingWait());

    try brain.pushInbox(.{
        .event_type = .agent,
        .source_brain = try allocator.dupe(u8, "delegate"),
        .target_brain = try allocator.dupe(u8, "primary"),
        .talk_id = 41,
        .payload = try allocator.dupe(u8, "wrong"),
        .created_at_ms = std.time.milliTimestamp(),
    });

    const unresolved = try engine.executePending(&brain);
    defer deinitResults(allocator, unresolved);
    try std.testing.expectEqual(@as(usize, 0), unresolved.len);
    try std.testing.expect(brain.hasPendingWait());

    try brain.pushInbox(.{
        .event_type = .agent,
        .source_brain = try allocator.dupe(u8, "delegate"),
        .target_brain = try allocator.dupe(u8, "primary"),
        .talk_id = 42,
        .payload = try allocator.dupe(u8, "right"),
        .created_at_ms = std.time.milliTimestamp(),
    });

    const resolved = try engine.executePending(&brain);
    defer deinitResults(allocator, resolved);
    try std.testing.expectEqual(@as(usize, 1), resolved.len);
    try std.testing.expect(std.mem.indexOf(u8, resolved[0].payload_json, "\"waiting\":false") != null);
    try std.testing.expect(!brain.hasPendingWait());
    try std.testing.expectEqual(@as(usize, 1), brain.inbox.items.len);
}

test "brain_tools: wait_for talk_id zero disables default talk correlation" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    brain.next_talk_id = 41;

    try brain.queueToolUse("talk_user", "{\"message\":\"first\"}");
    try brain.queueToolUse("talk_brain", "{\"message\":\"second\",\"target_brain\":\"delegate\"}");
    try brain.queueToolUse("wait_for", "{\"events\":[{\"event_type\":\"agent\",\"parameter\":\"delegate\",\"talk_id\":0}]}");

    var engine = Engine.init(allocator, &mem, &bus);
    const first_results = try engine.executePending(&brain);
    defer deinitResults(allocator, first_results);
    try std.testing.expectEqual(@as(usize, 3), first_results.len);
    try std.testing.expect(std.mem.indexOf(u8, first_results[2].payload_json, "\"waiting\":true") != null);
    try std.testing.expect(brain.hasPendingWait());

    try brain.pushInbox(.{
        .event_type = .agent,
        .source_brain = try allocator.dupe(u8, "delegate"),
        .target_brain = try allocator.dupe(u8, "primary"),
        .talk_id = 41,
        .payload = try allocator.dupe(u8, "from old talk"),
        .created_at_ms = std.time.milliTimestamp(),
    });

    const resolved = try engine.executePending(&brain);
    defer deinitResults(allocator, resolved);
    try std.testing.expectEqual(@as(usize, 1), resolved.len);
    try std.testing.expect(std.mem.indexOf(u8, resolved[0].payload_json, "\"waiting\":false") != null);
    try std.testing.expect(!brain.hasPendingWait());
}
