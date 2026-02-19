const std = @import("std");
const hook_registry = @import("hook_registry.zig");
const HookContext = hook_registry.HookContext;
const HookData = hook_registry.HookData;
const HookError = hook_registry.HookError;
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const brain_tools = @import("brain_tools.zig");
const agent_config = @import("agent_config.zig");

/// Brain specialization configuration from agent.json
pub const BrainSpecialization = struct {
    allocator: std.mem.Allocator,
    brain_name: []const u8,
    allowed_tools: ?std.ArrayListUnmanaged([]const u8),
    denied_tools: ?std.ArrayListUnmanaged([]const u8),
    role: ?[]const u8,
    can_spawn_subbrains: bool,
    provider_name: ?[]const u8,
    model_name: ?[]const u8,
    think_level: ?[]const u8,
    additional_rom: std.ArrayListUnmanaged(hook_registry.RomEntry),

    pub fn init(allocator: std.mem.Allocator, brain_name: []const u8) BrainSpecialization {
        return .{
            .allocator = allocator,
            .brain_name = brain_name,
            .allowed_tools = null,
            .denied_tools = null,
            .role = null,
            .can_spawn_subbrains = false,
            .provider_name = null,
            .model_name = null,
            .think_level = null,
            .additional_rom = .{},
        };
    }

    pub fn deinit(self: *BrainSpecialization) void {
        if (self.allowed_tools) |*tools| {
            for (tools.items) |tool| {
                self.allocator.free(tool);
            }
            tools.deinit(self.allocator);
        }
        if (self.denied_tools) |*tools| {
            for (tools.items) |tool| {
                self.allocator.free(tool);
            }
            tools.deinit(self.allocator);
        }
        if (self.role) |role| {
            self.allocator.free(role);
        }
        if (self.provider_name) |value| {
            self.allocator.free(value);
        }
        if (self.model_name) |value| {
            self.allocator.free(value);
        }
        if (self.think_level) |value| {
            self.allocator.free(value);
        }
        for (self.additional_rom.items) |*entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
        self.additional_rom.deinit(self.allocator);
    }

    /// Check if a tool is allowed for this brain
    pub fn isToolAllowed(self: *const BrainSpecialization, tool_name: []const u8) bool {
        // If denied list exists and contains tool, deny it
        if (self.denied_tools) |denied| {
            for (denied.items) |denied_tool| {
                if (std.mem.eql(u8, denied_tool, tool_name)) return false;
            }
        }

        // If allowed list exists, tool must be in it
        if (self.allowed_tools) |allowed| {
            for (allowed.items) |allowed_tool| {
                if (std.mem.eql(u8, allowed_tool, tool_name)) return true;
            }
            return false; // Not in allowed list
        }

        // No restrictions = allowed
        return true;
    }
};

/// Parse agent.json and create specialization config
pub fn loadBrainSpecialization(
    allocator: std.mem.Allocator,
    runtime: *AgentRuntime,
    brain_name: []const u8,
) !?BrainSpecialization {
    const content = try loadAgentJsonFile(allocator, runtime, brain_name);
    if (content == null) return null;
    defer allocator.free(content.?);

    var spec = BrainSpecialization.init(allocator, brain_name);
    errdefer spec.deinit();

    // Parse JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, content.?, .{});
    defer parsed.deinit();

    // Validate root is an object
    if (parsed.value != .object) {
        std.log.warn("agent.json for {s} is not a JSON object", .{brain_name});
        return null;
    }

    const root = parsed.value.object;

    // Parse allowed_tools
    if (root.get("allowed_tools")) |tools_json| {
        if (tools_json == .array) {
            spec.allowed_tools = .{};
            for (tools_json.array.items) |tool| {
                if (tool == .string) {
                    const owned = try allocator.dupe(u8, tool.string);
                    try spec.allowed_tools.?.append(allocator, owned);
                }
            }
        }
    }

    // Parse denied_tools
    if (root.get("denied_tools")) |tools_json| {
        if (tools_json == .array) {
            spec.denied_tools = .{};
            for (tools_json.array.items) |tool| {
                if (tool == .string) {
                    const owned = try allocator.dupe(u8, tool.string);
                    try spec.denied_tools.?.append(allocator, owned);
                }
            }
        }
    }

    // Parse role/specialization
    if (root.get("specialization")) |spec_json| {
        if (spec_json == .string) {
            spec.role = try allocator.dupe(u8, spec_json.string);
        }
    }

    // Parse can_spawn_subbrains
    if (root.get("can_spawn_subbrains")) |spawn_json| {
        if (spawn_json == .bool) {
            spec.can_spawn_subbrains = spawn_json.bool;
        }
    }

    // Parse provider/model/think settings (top-level or provider object)
    if (root.get("provider")) |provider_json| {
        switch (provider_json) {
            .string => {
                spec.provider_name = try allocator.dupe(u8, provider_json.string);
            },
            .object => {
                if (provider_json.object.get("name")) |name_json| {
                    if (name_json == .string) {
                        spec.provider_name = try allocator.dupe(u8, name_json.string);
                    }
                }
                if (provider_json.object.get("model")) |model_json| {
                    if (model_json == .string) {
                        spec.model_name = try allocator.dupe(u8, model_json.string);
                    }
                }
                if (provider_json.object.get("think_level")) |think_json| {
                    if (think_json == .string) {
                        spec.think_level = try allocator.dupe(u8, think_json.string);
                    }
                }
            },
            else => {},
        }
    }
    if (root.get("model")) |model_json| {
        if (model_json == .string) {
            if (spec.model_name) |existing| allocator.free(existing);
            spec.model_name = try allocator.dupe(u8, model_json.string);
        }
    }
    if (root.get("think_level")) |think_json| {
        if (think_json == .string) {
            if (spec.think_level) |existing| allocator.free(existing);
            spec.think_level = try allocator.dupe(u8, think_json.string);
        }
    } else if (root.get("thinking_level")) |think_json| {
        if (think_json == .string) {
            if (spec.think_level) |existing| allocator.free(existing);
            spec.think_level = try allocator.dupe(u8, think_json.string);
        }
    } else if (root.get("reasoning")) |think_json| {
        if (think_json == .string) {
            if (spec.think_level) |existing| allocator.free(existing);
            spec.think_level = try allocator.dupe(u8, think_json.string);
        }
    }

    // Parse additional ROM entries
    if (root.get("rom_entries")) |rom_json| {
        if (rom_json == .array) {
            for (rom_json.array.items) |entry| {
                if (entry == .object) {
                    const key = entry.object.get("key");
                    const value = entry.object.get("value");
                    if (key != null and value != null and key.? == .string and value.? == .string) {
                        const owned_key = try allocator.dupe(u8, key.?.string);
                        errdefer allocator.free(owned_key);
                        const owned_value = try allocator.dupe(u8, value.?.string);
                        try spec.additional_rom.append(allocator, .{
                            .key = owned_key,
                            .value = owned_value,
                            .mutable = true,
                        });
                    }
                }
            }
        }
    }

    return spec;
}

/// Load brain specialization from flat agent config with template merging
pub fn loadBrainSpecializationFlat(
    allocator: std.mem.Allocator,
    runtime: *AgentRuntime,
    brain_name: []const u8,
) !?BrainSpecialization {
    // Try to load flat config first
    var flat_config = try agent_config.loadAgentConfig(allocator, runtime.agent_id);
    if (flat_config == null) {
        // Fall back to old agent.json loading
        return loadBrainSpecialization(allocator, runtime, brain_name);
    }
    defer flat_config.?.deinit();
    
    // Get brain config from flat config
    const brain_cfg = flat_config.?.getBrainConfig(brain_name) orelse {
        // No config for this brain
        return null;
    };
    
    // If template is specified, load and merge
    var merged_config: ?agent_config.BrainConfig = null;
    defer if (merged_config) |*m| m.deinit();
    
    const effective_config = blk: {
        if (brain_cfg.template) |template_name| {
            var template = try agent_config.loadSubBrainTemplate(allocator, template_name);
            if (template) |*tmpl| {
                defer tmpl.deinit();
                
                // Need to reconstruct BrainConfig from view for merging
                var cfg = agent_config.BrainConfig.init(allocator);
                cfg.provider.name = if (brain_cfg.provider.name) |n| try allocator.dupe(u8, n) else null;
                cfg.provider.model = if (brain_cfg.provider.model) |m| try allocator.dupe(u8, m) else null;
                cfg.provider.think_level = if (brain_cfg.provider.think_level) |tl| try allocator.dupe(u8, tl) else null;
                cfg.can_spawn_subbrains = brain_cfg.can_spawn_subbrains;
                cfg.template = if (brain_cfg.template) |tn| try allocator.dupe(u8, tn) else null;
                
                // Copy arrays
                if (brain_cfg.allowed_tools) |tools| {
                    cfg.allowed_tools = .{};
                    for (tools.items) |tool| {
                        const owned = try allocator.dupe(u8, tool);
                        try cfg.allowed_tools.?.append(allocator, owned);
                    }
                }
                if (brain_cfg.denied_tools) |tools| {
                    cfg.denied_tools = .{};
                    for (tools.items) |tool| {
                        const owned = try allocator.dupe(u8, tool);
                        try cfg.denied_tools.?.append(allocator, owned);
                    }
                }
                if (brain_cfg.capabilities) |caps| {
                    cfg.capabilities = .{};
                    for (caps.items) |cap| {
                        const owned = try allocator.dupe(u8, cap);
                        try cfg.capabilities.?.append(allocator, owned);
                    }
                }
                if (brain_cfg.rom_overrides) |roms| {
                    cfg.rom_overrides = .{};
                    for (roms.items) |rom| {
                        const entry = agent_config.RomEntry{
                            .key = try allocator.dupe(u8, rom.key),
                            .value = try allocator.dupe(u8, rom.value),
                        };
                        try cfg.rom_overrides.?.append(allocator, entry);
                    }
                }
                
                merged_config = try agent_config.mergeWithTemplate(allocator, cfg, tmpl.*);
                break :blk merged_config.?.view();
            }
        }
        break :blk brain_cfg;
    };
    
    // Convert to BrainSpecialization
    var spec = BrainSpecialization.init(allocator, brain_name);
    errdefer spec.deinit();
    
    // Set provider info
    if (effective_config.provider.name) |name| {
        spec.provider_name = try allocator.dupe(u8, name);
    }
    if (effective_config.provider.model) |model| {
        spec.model_name = try allocator.dupe(u8, model);
    }
    if (effective_config.provider.think_level) |think| {
        spec.think_level = try allocator.dupe(u8, think);
    }
    
    // Set spawn capability
    spec.can_spawn_subbrains = effective_config.can_spawn_subbrains;
    
    // Copy tool lists
    if (effective_config.allowed_tools) |tools| {
        spec.allowed_tools = .{};
        for (tools.items) |tool| {
            const owned = try allocator.dupe(u8, tool);
            try spec.allowed_tools.?.append(allocator, owned);
        }
    }
    if (effective_config.denied_tools) |tools| {
        spec.denied_tools = .{};
        for (tools.items) |tool| {
            const owned = try allocator.dupe(u8, tool);
            try spec.denied_tools.?.append(allocator, owned);
        }
    }
    
    // Copy capabilities as role (just use first capability for now)
    if (effective_config.capabilities) |caps| {
        if (caps.items.len > 0) {
            spec.role = try allocator.dupe(u8, caps.items[0]);
        }
    }
    
    // Copy ROM entries
    if (effective_config.rom_overrides) |roms| {
        for (roms.items) |rom| {
            const owned_key = try allocator.dupe(u8, rom.key);
            errdefer allocator.free(owned_key);
            const owned_value = try allocator.dupe(u8, rom.value);
            try spec.additional_rom.append(allocator, .{
                .key = owned_key,
                .value = owned_value,
                .mutable = true,
            });
        }
    }
    
    return spec;
}

/// Hook that applies brain specialization to ROM
pub fn applyBrainSpecializationHook(ctx: *HookContext, data: HookData) HookError!void {
    const rom = data.pre_observe;
    const allocator = ctx.runtime.allocator;

    // Load specialization for this brain using new flat config
    var spec = loadBrainSpecializationFlat(allocator, ctx.runtime, ctx.brain_name) catch |err| {
        std.log.warn("Failed to load brain specialization for {s}: {s}", .{ ctx.brain_name, @errorName(err) });
        return; // Continue without specialization
    };
    if (spec == null) return; // No specialization file
    defer spec.?.deinit();

    // Add role to ROM
    if (spec.?.role) |role| {
        rom.set("system:role", role) catch return HookError.OutOfMemory;
    }

    // Add can_spawn_subbrains flag
    rom.set("system:can_spawn_subbrains", if (spec.?.can_spawn_subbrains) "true" else "false") catch return HookError.OutOfMemory;

    var effective_provider = spec.?.provider_name;
    var effective_model = spec.?.model_name;
    var effective_think_level = spec.?.think_level;
    if (ctx.runtime.getBrainProviderOverride(ctx.brain_name)) |runtime_override| {
        if (runtime_override.provider_name) |value| effective_provider = value;
        if (runtime_override.model_name) |value| effective_model = value;
        if (runtime_override.think_level) |value| effective_think_level = value;
    }
    if (effective_provider) |value| {
        rom.set("system:provider", value) catch return HookError.OutOfMemory;
    }
    if (effective_model) |value| {
        rom.set("system:model", value) catch return HookError.OutOfMemory;
    }
    if (effective_think_level) |value| {
        rom.set("system:think_level", value) catch return HookError.OutOfMemory;
    }

    // Filter available tools
    const capabilities_json = rom.get("system:capabilities") orelse return;

    // Parse capabilities, filter, and rebuild
    const filtered = filterToolsForBrain(allocator, capabilities_json, &spec.?) catch |err| {
        std.log.warn("Failed to filter tools for {s}: {s}", .{ ctx.brain_name, @errorName(err) });
        return;
    };
    defer allocator.free(filtered);

    rom.set("system:capabilities", filtered) catch return HookError.OutOfMemory;

    // Add additional ROM entries
    for (spec.?.additional_rom.items) |entry| {
        rom.set(entry.key, entry.value) catch return HookError.OutOfMemory;
    }

    // Store specialization in scratch for other hooks to reference
    ctx.setScratch(allocator, "brain:has_specialization", "true") catch {};
    if (spec.?.role) |role| {
        ctx.setScratch(allocator, "brain:role", role) catch {};
    }

    // Also store the specialization itself for the pre_mutate filter hook
    // We store the allowed/denied tool lists as JSON in scratch
    if (spec.?.allowed_tools) |tools| {
        var tools_json = std.ArrayListUnmanaged(u8){};
        defer tools_json.deinit(allocator);
        const writer = tools_json.writer(allocator);
        try writer.writeByte('[');
        for (tools.items, 0..) |tool, i| {
            if (i > 0) try writer.writeByte(',');
            try writeJsonString(writer, tool);
        }
        try writer.writeByte(']');
        const tools_str = try tools_json.toOwnedSlice(allocator);
        defer allocator.free(tools_str);
        ctx.setScratch(allocator, "brain:allowed_tools", tools_str) catch {};
    }
    if (spec.?.denied_tools) |tools| {
        var tools_json = std.ArrayListUnmanaged(u8){};
        defer tools_json.deinit(allocator);
        const writer = tools_json.writer(allocator);
        try writer.writeByte('[');
        for (tools.items, 0..) |tool, i| {
            if (i > 0) try writer.writeByte(',');
            try writeJsonString(writer, tool);
        }
        try writer.writeByte(']');
        const tools_str = try tools_json.toOwnedSlice(allocator);
        defer allocator.free(tools_str);
        ctx.setScratch(allocator, "brain:denied_tools", tools_str) catch {};
    }
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

/// Pre-mutate hook that filters tools based on allow/deny rules
pub fn filterToolsHook(ctx: *HookContext, data: HookData) HookError!void {
    const pending_tools = data.pre_mutate;
    const allocator = ctx.runtime.allocator;

    // Get allowed/denied tools from scratch (set by applyBrainSpecializationHook)
    const allowed_json = ctx.getScratch("brain:allowed_tools");
    const denied_json = ctx.getScratch("brain:denied_tools");

    // If no restrictions, allow all
    if (allowed_json == null and denied_json == null) return;

    // Parse allowed list
    var allowed_list: ?std.ArrayListUnmanaged([]const u8) = null;
    defer {
        if (allowed_list) |*list| {
            for (list.items) |tool| allocator.free(tool);
            list.deinit(allocator);
        }
    }
    if (allowed_json) |json| {
        allowed_list = .{};
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value == .array) {
            for (parsed.value.array.items) |item| {
                if (item == .string) {
                    const owned = allocator.dupe(u8, item.string) catch continue;
                    allowed_list.?.append(allocator, owned) catch allocator.free(owned);
                }
            }
        }
    }

    // Parse denied list
    var denied_list: ?std.ArrayListUnmanaged([]const u8) = null;
    defer {
        if (denied_list) |*list| {
            for (list.items) |tool| allocator.free(tool);
            list.deinit(allocator);
        }
    }
    if (denied_json) |json| {
        denied_list = .{};
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value == .array) {
            for (parsed.value.array.items) |item| {
                if (item == .string) {
                    const owned = allocator.dupe(u8, item.string) catch continue;
                    denied_list.?.append(allocator, owned) catch allocator.free(owned);
                }
            }
        }
    }

    // Filter pending tools - remove disallowed ones
    var i: usize = 0;
    while (i < pending_tools.tools.items.len) {
        const tool_name = pending_tools.tools.items[i].name;
        var allowed = true;

        // Check denied list first
        if (denied_list) |denied| {
            for (denied.items) |denied_tool| {
                if (std.mem.eql(u8, denied_tool, tool_name)) {
                    allowed = false;
                    break;
                }
            }
        }

        // Check allowed list
        if (allowed and allowed_list != null) {
            var in_allowed = false;
            for (allowed_list.?.items) |allowed_tool| {
                if (std.mem.eql(u8, allowed_tool, tool_name)) {
                    in_allowed = true;
                    break;
                }
            }
            allowed = in_allowed;
        }

        if (!allowed) {
            // Remove this tool from pending
            std.log.warn("Tool '{s}' blocked by brain specialization for {s}", .{ tool_name, ctx.brain_name });
            const removed = pending_tools.tools.orderedRemove(i);
            allocator.free(removed.name);
            allocator.free(removed.args_json);
        } else {
            i += 1;
        }
    }
}

/// Filter tool schemas based on brain specialization
fn filterToolsForBrain(
    allocator: std.mem.Allocator,
    capabilities_json: []const u8,
    spec: *const BrainSpecialization,
) ![]u8 {
    // Parse the capabilities JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, capabilities_json, .{});
    defer parsed.deinit();

    // If it's not an array, return as-is
    if (parsed.value != .array) {
        return allocator.dupe(u8, capabilities_json);
    }

    // Build filtered list of tool schema objects (not just names)
    var filtered_tools = std.ArrayListUnmanaged(std.json.Value){};
    defer filtered_tools.deinit(allocator);

    for (parsed.value.array.items) |tool| {
        const tool_name = getToolName(tool) orelse continue;

        if (spec.isToolAllowed(tool_name)) {
            // Clone the full tool schema object
            try filtered_tools.append(allocator, tool);
        }
    }

    // Build result JSON with full schema objects
    var result_json = std.ArrayListUnmanaged(u8){};
    defer result_json.deinit(allocator);

    const writer = result_json.writer(allocator);
    try writer.writeByte('[');
    for (filtered_tools.items, 0..) |tool, i| {
        if (i > 0) try writer.writeByte(',');
        // Serialize the full tool schema object
        try writeJsonValue(writer, tool);
    }
    try writer.writeByte(']');

    return result_json.toOwnedSlice(allocator);
}

/// Write a JSON value to the writer
fn writeJsonValue(writer: anytype, value: std.json.Value) !void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.print("{}", .{b}),
        .integer => |n| try writer.print("{d}", .{n}),
        .float => |n| try writer.print("{e}", .{n}),
        .string => |s| try writeJsonString(writer, s),
        .array => |arr| {
            try writer.writeByte('[');
            for (arr.items, 0..) |item, i| {
                if (i > 0) try writer.writeByte(',');
                try writeJsonValue(writer, item);
            }
            try writer.writeByte(']');
        },
        .object => |obj| {
            try writer.writeByte('{');
            var first = true;
            var it = obj.iterator();
            while (it.next()) |entry| {
                if (!first) try writer.writeByte(',');
                first = false;
                try writeJsonString(writer, entry.key_ptr.*);
                try writer.writeByte(':');
                try writeJsonValue(writer, entry.value_ptr.*);
            }
            try writer.writeByte('}');
        },
        .number_string => |s| try writer.writeAll(s),
    }
}

/// Extract tool name from tool schema JSON
fn getToolName(tool: std.json.Value) ?[]const u8 {
    if (tool != .object) return null;
    const name_field = tool.object.get("name") orelse return null;
    if (name_field != .string) return null;
    return name_field.string;
}

/// Load agent.json file for a brain
fn loadAgentJsonFile(
    allocator: std.mem.Allocator,
    runtime: *AgentRuntime,
    brain_name: []const u8,
) !?[]u8 {
    // Security: Validate agent_id doesn't contain path traversal
    if (!isValidAgentId(runtime.agent_id)) {
        std.log.err("Invalid agent_id contains path traversal: {s}", .{runtime.agent_id});
        return error.InvalidAgentId;
    }

    // Construct path: agents/{agent_id}/{brain_name}/agent.json
    // For primary brain, use agent root: agents/{agent_id}/agent.json
    const agents_dir = runtime.runtime_config.agents_dir;
    const base_dir = try std.fs.path.join(allocator, &.{ agents_dir, runtime.agent_id });
    defer allocator.free(base_dir);

    const brain_dir = if (std.mem.eql(u8, brain_name, "primary"))
        try allocator.dupe(u8, base_dir)
    else
        try std.fs.path.join(allocator, &.{ base_dir, brain_name });
    defer allocator.free(brain_dir);

    const path = try std.fs.path.join(allocator, &.{ brain_dir, "agent.json" });
    defer allocator.free(path);

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

/// Register brain specialization hook for a specific brain
pub fn registerBrainSpecialization(
    registry: *hook_registry.HookRegistry,
    brain_name: []const u8,
) !void {
    _ = brain_name; // Currently we use a generic hook that loads per-brain

    // Register the specialization hook at priority 0 (between system_first and system_last)
    try registry.register(.pre_observe, .{
        .name = "brain:specialization:observe",
        .priority = 0,
        .callback = applyBrainSpecializationHook,
    });

    // Register tool filtering hook for pre_mutate
    try registry.register(.pre_mutate, .{
        .name = "brain:specialization:mutate",
        .priority = 0,
        .callback = filterToolsHook,
    });
}
