const std = @import("std");
const ltm_store = @import("ziggy-memory-store").ltm_store;
const memory = @import("ziggy-memory-store").memory;
const memid = @import("ziggy-memory-store").memid;
const brain_context = @import("brain_context.zig");
const event_bus = @import("ziggy-runtime-hooks").event_bus;
const tool_registry = @import("ziggy-tool-runtime").tool_registry;

pub const RemoteCapabilityDispatchFn = *const fn (
    ctx: *anyopaque,
    allocator: std.mem.Allocator,
    tool_name: []const u8,
    args_json: []const u8,
) tool_registry.ToolExecutionResult;

pub const CapabilityResult = struct {
    tool_name: []u8,
    success: bool,
    payload_json: []u8,

    pub fn deinit(self: *CapabilityResult, allocator: std.mem.Allocator) void {
        allocator.free(self.tool_name);
        allocator.free(self.payload_json);
        self.* = undefined;
    }
};

pub const CapabilitySchema = struct {
    name: []const u8,
    description: []const u8,
    required_fields: []const []const u8,
    optional_fields: []const []const u8 = &.{},
};

pub const agent_capability_schemas = [_]CapabilitySchema{
    .{ .name = "memory_load", .description = "Load memory by mem_id and optional version", .required_fields = &[_][]const u8{"mem_id"}, .optional_fields = &[_][]const u8{"version"} },
    .{ .name = "memory_versions", .description = "List available versions for a memory", .required_fields = &[_][]const u8{"mem_id"}, .optional_fields = &[_][]const u8{"limit"} },
    .{ .name = "memory_evict", .description = "Evict memory by mem_id unless it is marked unevictable", .required_fields = &[_][]const u8{"mem_id"} },
    .{ .name = "memory_mutate", .description = "Mutate memory by mem_id unless it is write_protected", .required_fields = &[_][]const u8{ "mem_id", "content" } },
    .{ .name = "memory_create", .description = "Create memory entry. Optional flags: write_protected, unevictable.", .required_fields = &[_][]const u8{ "kind", "content" }, .optional_fields = &[_][]const u8{ "name", "write_protected", "unevictable" } },
    .{ .name = "memory_search", .description = "Keyword search memory entries", .required_fields = &[_][]const u8{"query"}, .optional_fields = &[_][]const u8{"limit"} },
    .{ .name = "talk_user", .description = "Send message to user channel", .required_fields = &[_][]const u8{"message"} },
    .{ .name = "talk_agent", .description = "Send message to another agent channel", .required_fields = &[_][]const u8{ "message", "target_brain" } },
    .{ .name = "talk_brain", .description = "Send message to another brain", .required_fields = &[_][]const u8{ "message", "target_brain" } },
    .{ .name = "talk_log", .description = "Emit runtime log talk event", .required_fields = &[_][]const u8{"message"} },
};

const ExecuteOutcome = struct {
    result: CapabilityResult,
};

pub const CapabilityEngine = struct {
    allocator: std.mem.Allocator,
    runtime_memory: *memory.RuntimeMemory,
    bus: *event_bus.EventBus,
    capability_registry: ?*const tool_registry.ToolRegistry = null,
    capability_dispatch_ctx: ?*anyopaque = null,
    capability_dispatch_fn: ?RemoteCapabilityDispatchFn = null,

    pub fn init(
        allocator: std.mem.Allocator,
        runtime_memory: *memory.RuntimeMemory,
        bus: *event_bus.EventBus,
    ) CapabilityEngine {
        return .{
            .allocator = allocator,
            .runtime_memory = runtime_memory,
            .bus = bus,
        };
    }

    pub fn initWithCapabilities(
        allocator: std.mem.Allocator,
        runtime_memory: *memory.RuntimeMemory,
        bus: *event_bus.EventBus,
        capability_registry: ?*const tool_registry.ToolRegistry,
    ) CapabilityEngine {
        return .{
            .allocator = allocator,
            .runtime_memory = runtime_memory,
            .bus = bus,
            .capability_registry = capability_registry,
        };
    }

    pub fn initWithCapabilitiesAndDispatch(
        allocator: std.mem.Allocator,
        runtime_memory: *memory.RuntimeMemory,
        bus: *event_bus.EventBus,
        capability_registry: ?*const tool_registry.ToolRegistry,
        capability_dispatch_ctx: ?*anyopaque,
        capability_dispatch_fn: ?RemoteCapabilityDispatchFn,
    ) CapabilityEngine {
        return .{
            .allocator = allocator,
            .runtime_memory = runtime_memory,
            .bus = bus,
            .capability_registry = capability_registry,
            .capability_dispatch_ctx = capability_dispatch_ctx,
            .capability_dispatch_fn = capability_dispatch_fn,
        };
    }

    pub fn executePending(self: *CapabilityEngine, brain: *brain_context.BrainContext) ![]CapabilityResult {
        var results = std.ArrayListUnmanaged(CapabilityResult){};
        errdefer {
            for (results.items) |*result| result.deinit(self.allocator);
            results.deinit(self.allocator);
        }

        while (brain.pending_tool_uses.items.len > 0) {
            var tool_use = brain.pending_tool_uses.orderedRemove(0);
            defer tool_use.deinit(self.allocator);

            const outcome = try self.executeOne(brain, tool_use);
            try results.append(self.allocator, outcome.result);
        }

        return results.toOwnedSlice(self.allocator);
    }

    pub fn generateSchemasJson(self: *CapabilityEngine) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);

        try out.append(self.allocator, '[');
        for (agent_capability_schemas, 0..) |schema, index| {
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

    fn executeOne(
        self: *CapabilityEngine,
        brain: *brain_context.BrainContext,
        tool_use: brain_context.ToolUse,
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
        if (std.mem.eql(u8, tool_use.name, "memory_versions")) {
            return .{ .result = try self.execMemoryVersions(tool_use.name, args) };
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
        if (std.mem.eql(u8, tool_use.name, "talk_user") or
            std.mem.eql(u8, tool_use.name, "talk_agent") or
            std.mem.eql(u8, tool_use.name, "talk_brain") or
            std.mem.eql(u8, tool_use.name, "talk_log"))
        {
            return .{ .result = try self.execTalk(tool_use.name, brain, args) };
        }

        if (self.capability_registry != null or self.capability_dispatch_fn != null) {
            return .{ .result = try self.execCapability(tool_use.name, args) };
        }

        return .{ .result = try self.failure(tool_use.name, "unsupported_tool", "Unsupported agent capability") };
    }

    fn execCapability(self: *CapabilityEngine, tool_name: []const u8, args: std.json.ObjectMap) !CapabilityResult {
        const tool_call_id = if (args.get("_tool_call_id")) |value|
            if (value == .string) value.string else null
        else
            null;
        const chat_reply_content = extractChatReplyContentForCapability(tool_name, args);
        if (chat_reply_content) |reply| {
            const synthetic_payload = try buildSyntheticChatReplyPayload(self.allocator, args, reply);
            var synthetic_payload_owned = true;
            errdefer if (synthetic_payload_owned) self.allocator.free(synthetic_payload);

            if (tool_call_id) |call_id| {
                var wrapped_buf = std.ArrayListUnmanaged(u8){};
                defer wrapped_buf.deinit(self.allocator);
                try wrapped_buf.appendSlice(self.allocator, "{\"tool_call_id\":\"");
                try appendJsonEscaped(self.allocator, &wrapped_buf, call_id);
                try wrapped_buf.appendSlice(self.allocator, "\",\"result\":");
                try wrapped_buf.appendSlice(self.allocator, synthetic_payload);
                try wrapped_buf.append(self.allocator, '}');
                const wrapped = try wrapped_buf.toOwnedSlice(self.allocator);
                self.allocator.free(synthetic_payload);
                synthetic_payload_owned = false;
                return self.success(tool_name, wrapped);
            }
            return self.success(tool_name, synthetic_payload);
        }
        var outcome = blk: {
            if (self.capability_dispatch_fn) |dispatch_fn| {
                const dispatch_ctx = self.capability_dispatch_ctx orelse break :blk self.failureResult(
                    .execution_failed,
                    "capability dispatch context unavailable",
                );

                const args_json = std.json.Stringify.valueAlloc(
                    self.allocator,
                    std.json.Value{ .object = args },
                    .{
                        .emit_null_optional_fields = true,
                        .whitespace = .minified,
                    },
                ) catch break :blk self.failureResult(
                    .execution_failed,
                    "failed to serialize capability arguments",
                );
                defer self.allocator.free(args_json);

                break :blk dispatch_fn(dispatch_ctx, self.allocator, tool_name, args_json);
            }

            const capability_registry = self.capability_registry orelse break :blk self.failureResult(
                .tool_not_executable,
                "Unsupported agent capability",
            );
            break :blk capability_registry.executeWorld(self.allocator, tool_name, args);
        };
        defer outcome.deinit(self.allocator);

        return switch (outcome) {
            .success => |ok| {
                const success_payload = try decorateCapabilitySuccessPayload(
                    self.allocator,
                    ok.payload_json,
                    chat_reply_content,
                );
                if (tool_call_id) |call_id| {
                    var wrapped_buf = std.ArrayListUnmanaged(u8){};
                    defer wrapped_buf.deinit(self.allocator);
                    defer self.allocator.free(success_payload);
                    try wrapped_buf.appendSlice(self.allocator, "{\"tool_call_id\":\"");
                    try appendJsonEscaped(self.allocator, &wrapped_buf, call_id);
                    try wrapped_buf.appendSlice(self.allocator, "\",\"result\":");
                    try wrapped_buf.appendSlice(self.allocator, success_payload);
                    try wrapped_buf.append(self.allocator, '}');
                    const wrapped = try wrapped_buf.toOwnedSlice(self.allocator);
                    return self.success(tool_name, wrapped);
                }
                return self.success(tool_name, success_payload);
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

    fn extractChatReplyContentForCapability(
        tool_name: []const u8,
        args: std.json.ObjectMap,
    ) ?[]const u8 {
        if (!std.mem.eql(u8, tool_name, "file_write")) return null;
        const path_value = args.get("path") orelse return null;
        if (path_value != .string) return null;
        if (!isChatReplyPath(path_value.string)) return null;
        const content_value = args.get("content") orelse return null;
        if (content_value != .string) return null;
        const trimmed = std.mem.trim(u8, content_value.string, " \t\r\n");
        if (trimmed.len == 0) return null;
        return content_value.string;
    }

    fn isChatReplyPath(path: []const u8) bool {
        const trimmed = std.mem.trim(u8, path, " \t\r\n");
        if (trimmed.len == 0) return false;
        const without_leading = std.mem.trimLeft(u8, trimmed, "/");
        return std.mem.eql(u8, without_leading, "global/chat/control/reply");
    }

    fn decorateCapabilitySuccessPayload(
        allocator: std.mem.Allocator,
        payload_json: []const u8,
        chat_reply_content: ?[]const u8,
    ) ![]u8 {
        const reply = chat_reply_content orelse return allocator.dupe(u8, payload_json);
        const escaped_reply = try appendJsonEscapedAlloc(allocator, reply);
        defer allocator.free(escaped_reply);
        return std.fmt.allocPrint(
            allocator,
            "{{\"result\":{s},\"chat_reply\":{{\"delivered\":true,\"content\":\"{s}\"}}}}",
            .{ payload_json, escaped_reply },
        );
    }

    fn appendJsonEscapedAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(allocator);
        try appendJsonEscaped(allocator, &out, input);
        return out.toOwnedSlice(allocator);
    }

    fn buildSyntheticChatReplyPayload(
        allocator: std.mem.Allocator,
        args: std.json.ObjectMap,
        reply: []const u8,
    ) ![]u8 {
        const path_value = args.get("path") orelse return error.InvalidPayload;
        if (path_value != .string) return error.InvalidPayload;
        const escaped_path = try appendJsonEscapedAlloc(allocator, path_value.string);
        defer allocator.free(escaped_path);
        const escaped_reply = try appendJsonEscapedAlloc(allocator, reply);
        defer allocator.free(escaped_reply);
        return std.fmt.allocPrint(
            allocator,
            "{{\"result\":{{\"path\":\"{s}\",\"bytes_written\":{d},\"append\":false,\"ready\":true,\"wait_until_ready\":true}},\"chat_reply\":{{\"delivered\":true,\"content\":\"{s}\"}}}}",
            .{ escaped_path, reply.len, escaped_reply },
        );
    }

    fn failureResult(
        self: *CapabilityEngine,
        code: tool_registry.ToolErrorCode,
        message: []const u8,
    ) tool_registry.ToolExecutionResult {
        return .{ .failure = .{
            .code = code,
            .message = self.allocator.dupe(u8, message) catch self.allocator.dupe(u8, "out of memory") catch @panic("out of memory"),
        } };
    }

    fn execMemoryCreate(
        self: *CapabilityEngine,
        tool_name: []const u8,
        brain: *brain_context.BrainContext,
        args: std.json.ObjectMap,
    ) !CapabilityResult {
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

    fn execMemoryLoad(self: *CapabilityEngine, tool_name: []const u8, args: std.json.ObjectMap) !CapabilityResult {
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

    fn execMemoryMutate(self: *CapabilityEngine, tool_name: []const u8, args: std.json.ObjectMap) !CapabilityResult {
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

    fn execMemoryVersions(self: *CapabilityEngine, tool_name: []const u8, args: std.json.ObjectMap) !CapabilityResult {
        const mem_id = getRequiredString(args, "mem_id") orelse {
            return self.failure(tool_name, "invalid_args", "memory_versions requires 'mem_id'");
        };
        const limit = getOptionalUsize(args, "limit") catch {
            return self.failure(tool_name, "invalid_args", "memory_versions limit must be a non-negative integer");
        } orelse 25;

        const versions = self.runtime_memory.listVersions(self.allocator, mem_id, limit) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };
        defer memory.deinitItems(self.allocator, versions);

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);

        try payload.appendSlice(self.allocator, "{\"mem_id\":\"");
        try appendJsonEscaped(self.allocator, &payload, mem_id);
        try payload.appendSlice(self.allocator, "\",\"versions\":[");
        for (versions, 0..) |item, index| {
            if (index > 0) try payload.append(self.allocator, ',');

            try payload.appendSlice(self.allocator, "{\"mem_id\":\"");
            try appendJsonEscaped(self.allocator, &payload, item.mem_id);
            try payload.appendSlice(self.allocator, "\",\"version\":");
            try payload.writer(self.allocator).print("{d}", .{item.version orelse 0});
            try payload.appendSlice(self.allocator, ",\"kind\":\"");
            try appendJsonEscaped(self.allocator, &payload, item.kind);
            try payload.appendSlice(self.allocator, "\",\"write_protected\":");
            try payload.appendSlice(self.allocator, if (item.mutable) "false" else "true");
            try payload.appendSlice(self.allocator, ",\"unevictable\":");
            try payload.appendSlice(self.allocator, if (item.unevictable) "true" else "false");
            try payload.appendSlice(self.allocator, ",\"created_at_ms\":");
            try payload.writer(self.allocator).print("{d}", .{item.created_at_ms});
            try payload.append(self.allocator, '}');
        }
        try payload.appendSlice(self.allocator, "]}");

        return self.success(tool_name, try payload.toOwnedSlice(self.allocator));
    }

    fn execMemoryEvict(self: *CapabilityEngine, tool_name: []const u8, args: std.json.ObjectMap) !CapabilityResult {
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
        self: *CapabilityEngine,
        tool_name: []const u8,
        brain: *brain_context.BrainContext,
        args: std.json.ObjectMap,
    ) !CapabilityResult {
        const query = getRequiredString(args, "query") orelse {
            return self.failure(tool_name, "invalid_args", "memory_search requires 'query'");
        };
        const limit = getOptionalUsize(args, "limit") catch {
            return self.failure(tool_name, "invalid_args", "memory_search limit must be a non-negative integer");
        } orelse 25;

        const found_active = self.runtime_memory.search(self.allocator, brain.brain_name, query, limit) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };
        defer memory.deinitItems(self.allocator, found_active);

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);
        var seen_mem_ids = std.StringHashMapUnmanaged(void){};
        defer {
            var key_it = seen_mem_ids.keyIterator();
            while (key_it.next()) |key| self.allocator.free(key.*);
            seen_mem_ids.deinit(self.allocator);
        }
        var emitted: usize = 0;

        try payload.appendSlice(self.allocator, "{\"results\":[");
        for (found_active) |item| {
            if (!try self.markSeenMemId(&seen_mem_ids, item.mem_id)) continue;
            if (emitted > 0) try payload.append(self.allocator, ',');
            try self.appendMemorySearchResultRow(
                &payload,
                item.mem_id,
                item.version orelse 0,
                item.kind,
                !item.mutable,
                item.unevictable,
            );
            emitted += 1;
            if (emitted >= limit) break;
        }

        // Include persisted LTM records so memory_search still works after restart.
        if (emitted < limit) {
            if (self.runtime_memory.persisted_store) |store| {
                const persisted_fanout_base = @max(limit, 1);
                const persisted_fanout_limit = std.math.mul(usize, persisted_fanout_base, 4) catch persisted_fanout_base;
                const persisted_hits = store.search(self.allocator, query, persisted_fanout_limit) catch |err| {
                    return self.failure(tool_name, "execution_failed", @errorName(err));
                };
                defer ltm_store.deinitRecords(self.allocator, persisted_hits);

                for (persisted_hits) |record| {
                    if (emitted >= limit) break;

                    const parsed = parseBaseMemId(record.base_id) orelse continue;
                    if (!std.mem.eql(u8, parsed.agent, self.runtime_memory.agent_id)) continue;
                    if (!std.mem.eql(u8, parsed.brain, brain.brain_name)) continue;

                    const concrete_mem_id = try (memid.MemId{
                        .agent = parsed.agent,
                        .brain = parsed.brain,
                        .name = parsed.name,
                        .version = record.version,
                    }).format(self.allocator);
                    defer self.allocator.free(concrete_mem_id);

                    if (!try self.markSeenMemId(&seen_mem_ids, concrete_mem_id)) continue;
                    if (emitted > 0) try payload.append(self.allocator, ',');
                    try self.appendMemorySearchResultRow(
                        &payload,
                        concrete_mem_id,
                        record.version,
                        record.kind,
                        false,
                        false,
                    );
                    emitted += 1;
                }
            }
        }

        try payload.appendSlice(self.allocator, "]}");

        return self.success(tool_name, try payload.toOwnedSlice(self.allocator));
    }

    fn appendMemorySearchResultRow(
        self: *CapabilityEngine,
        payload: *std.ArrayListUnmanaged(u8),
        mem_id: []const u8,
        version: u64,
        kind: []const u8,
        write_protected: bool,
        unevictable: bool,
    ) !void {
        try payload.appendSlice(self.allocator, "{\"mem_id\":\"");
        try appendJsonEscaped(self.allocator, payload, mem_id);
        try payload.appendSlice(self.allocator, "\",\"version\":");
        try payload.writer(self.allocator).print("{d}", .{version});
        try payload.appendSlice(self.allocator, ",\"kind\":\"");
        try appendJsonEscaped(self.allocator, payload, kind);
        try payload.appendSlice(self.allocator, "\",\"write_protected\":");
        try payload.appendSlice(self.allocator, if (write_protected) "true" else "false");
        try payload.appendSlice(self.allocator, ",\"unevictable\":");
        try payload.appendSlice(self.allocator, if (unevictable) "true" else "false");
        try payload.append(self.allocator, '}');
    }

    fn markSeenMemId(self: *CapabilityEngine, seen: *std.StringHashMapUnmanaged(void), mem_id: []const u8) !bool {
        if (seen.contains(mem_id)) return false;
        try seen.put(self.allocator, try self.allocator.dupe(u8, mem_id), {});
        return true;
    }

    fn execTalk(
        self: *CapabilityEngine,
        tool_name: []const u8,
        brain: *brain_context.BrainContext,
        args: std.json.ObjectMap,
    ) !CapabilityResult {
        const message = getRequiredString(args, "message") orelse {
            return self.failure(tool_name, "invalid_args", "talk_* requires 'message'");
        };

        const talk_id = brain.nextTalkId();
        var target_brain: []const u8 = "";
        if (std.mem.eql(u8, tool_name, "talk_user")) {
            target_brain = "user";
        } else if (std.mem.eql(u8, tool_name, "talk_log")) {
            target_brain = "log";
        } else if (std.mem.eql(u8, tool_name, "talk_brain")) {
            target_brain = getRequiredString(args, "target_brain") orelse {
                return self.failure(tool_name, "invalid_args", "talk_brain requires 'target_brain'");
            };
        } else if (std.mem.eql(u8, tool_name, "talk_agent")) {
            target_brain = getRequiredString(args, "target_brain") orelse {
                return self.failure(tool_name, "invalid_args", "talk_agent requires 'target_brain'");
            };
            if (target_brain.len == 0 or std.mem.eql(u8, target_brain, "user")) {
                return self.failure(tool_name, "invalid_args", "talk_agent target_brain must be a non-user brain");
            }
        }

        self.bus.enqueue(.{
            .event_type = .talk,
            .source_brain = brain.brain_name,
            .target_brain = target_brain,
            .talk_id = talk_id,
            .payload = message,
        }) catch |err| {
            return self.failure(tool_name, "execution_failed", @errorName(err));
        };

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);
        try payload.appendSlice(self.allocator, "{\"talk_id\":");
        try payload.writer(self.allocator).print("{d}", .{talk_id});
        try payload.appendSlice(self.allocator, ",\"message\":\"");
        try appendJsonEscaped(self.allocator, &payload, message);
        try payload.appendSlice(self.allocator, "\"}");
        return self.success(tool_name, try payload.toOwnedSlice(self.allocator));
    }

    fn success(self: *CapabilityEngine, tool_name: []const u8, payload: []u8) !CapabilityResult {
        return .{
            .tool_name = try self.allocator.dupe(u8, tool_name),
            .success = true,
            .payload_json = payload,
        };
    }

    fn failure(self: *CapabilityEngine, tool_name: []const u8, code: []const u8, message: []const u8) !CapabilityResult {
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

};

pub fn deinitResults(allocator: std.mem.Allocator, results: []CapabilityResult) void {
    for (results) |*result| result.deinit(allocator);
    allocator.free(results);
}

const BaseMemIdParts = struct {
    agent: []const u8,
    brain: []const u8,
    name: []const u8,
};

fn parseBaseMemId(base_id: []const u8) ?BaseMemIdParts {
    var parts = std.mem.splitScalar(u8, base_id, ':');
    const agent = parts.next() orelse return null;
    const brain = parts.next() orelse return null;
    const name = parts.next() orelse return null;
    if (parts.next() != null) return null;
    if (agent.len == 0 or brain.len == 0 or name.len == 0) return null;
    return .{
        .agent = agent,
        .brain = brain,
        .name = name,
    };
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


test "capability_engine: memory_mutate requires mem_id" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    try brain.queueToolUse("memory_mutate", "{\"content\":\"{}\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "requires 'mem_id'") != null);
}

test "capability_engine: memory_create then memory_load succeeds" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    try brain.queueToolUse("memory_create", "{\"name\":\"draft\",\"kind\":\"note\",\"content\":{\"text\":\"draft content\"}}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
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

test "capability_engine: memory_versions returns latest-first history" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();

    var created = try mem.create("primary", "history_case", "note", "{\"text\":\"v1\"}", false, false);
    defer created.deinit(allocator);
    var second = try mem.mutate(created.mem_id, "{\"text\":\"v2\"}");
    defer second.deinit(allocator);

    const latest_alias = try (try memid.MemId.parse(created.mem_id)).withVersion(null).format(allocator);
    defer allocator.free(latest_alias);

    const args = try std.fmt.allocPrint(allocator, "{{\"mem_id\":\"{s}\",\"limit\":2}}", .{latest_alias});
    defer allocator.free(args);
    try brain.queueToolUse("memory_versions", args);

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "\"version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "\"version\":1") != null);
}

test "capability_engine: memory_load escapes kind in JSON payload" {
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

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const load_results = try engine.executePending(&brain);
    defer deinitResults(allocator, load_results);

    try std.testing.expectEqual(@as(usize, 1), load_results.len);
    try std.testing.expect(load_results[0].success);

    const loaded_kind = try testExtractStringField(allocator, load_results[0].payload_json, "kind");
    defer allocator.free(loaded_kind);
    try std.testing.expectEqualStrings("note \"x\" \\ slash\nline", loaded_kind);
}

test "capability_engine: memory_mutate success bumps version" {
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

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "\"version\":2") != null);
}

test "capability_engine: memory_evict success and missing mem_id failure" {
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

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "\"evicted\":true") != null);
    try std.testing.expect(!results[1].success);
    try std.testing.expect(std.mem.indexOf(u8, results[1].payload_json, "requires 'mem_id'") != null);
}

test "capability_engine: memory_search returns matching mem_id set" {
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

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, compile_item.mem_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, docs_item.mem_id) == null);
}

test "capability_engine: memory_search includes persisted matches after restart" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const ltm_dir = try std.fs.path.join(allocator, &.{ root, "ltm" });
    defer allocator.free(ltm_dir);
    try std.fs.cwd().makePath(ltm_dir);

    var store = try ltm_store.VersionedMemStore.open(allocator, ltm_dir, "runtime-memory.db");
    defer store.close();

    {
        var mem_writer = try memory.RuntimeMemory.initWithStore(allocator, "agentA", &store);
        defer mem_writer.deinit();
        var created = try mem_writer.create("primary", "persisted_compile", "note", "{\"text\":\"compile persisted\"}", false, false);
        created.deinit(allocator);
    }

    var mem_reader = try memory.RuntimeMemory.initWithStore(allocator, "agentA", &store);
    defer mem_reader.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();
    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("memory_search", "{\"query\":\"persisted_compile\",\"limit\":10}");

    var engine = CapabilityEngine.init(allocator, &mem_reader, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "persisted_compile") != null);
}

test "capability_engine: talk_user emits user-targeted event" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_user", "{\"message\":\"hello user\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
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

test "capability_engine: talk payload preserves JSON validity for escaped content" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_user", "{\"message\":\"quote \\\"line\\\"\\\\path\\nnext\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0].success);

    const payload_message = try testExtractStringField(allocator, results[0].payload_json, "message");
    defer allocator.free(payload_message);
    try std.testing.expectEqualStrings("quote \"line\"\\path\nnext", payload_message);
}

test "capability_engine: talk_agent emits delegated event" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_agent", "{\"message\":\"handoff\",\"target_brain\":\"delegate\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
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

test "capability_engine: talk_agent requires explicit target_brain" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_agent", "{\"message\":\"handoff\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "talk_agent requires 'target_brain'") != null);
    try std.testing.expectEqual(@as(usize, 0), bus.pendingCount());
}

test "capability_engine: talk_agent rejects user target to avoid delivery leak" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_agent", "{\"message\":\"handoff\",\"target_brain\":\"user\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "must be a non-user brain") != null);
    try std.testing.expectEqual(@as(usize, 0), bus.pendingCount());
}

test "capability_engine: talk_log emits log-targeted event" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_log", "{\"message\":\"log line\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
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

test "capability_engine: talk_brain requires target_brain" {
    const allocator = std.testing.allocator;
    var mem = try memory.RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();
    var bus = event_bus.EventBus.init(allocator);
    defer bus.deinit();

    var brain = try brain_context.BrainContext.init(allocator, "primary");
    defer brain.deinit();
    try brain.queueToolUse("talk_brain", "{\"message\":\"missing target\"}");

    var engine = CapabilityEngine.init(allocator, &mem, &bus);
    const results = try engine.executePending(&brain);
    defer deinitResults(allocator, results);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(!results[0].success);
    try std.testing.expect(std.mem.indexOf(u8, results[0].payload_json, "talk_brain requires 'target_brain'") != null);
}
