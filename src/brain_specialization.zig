const std = @import("std");
const hook_registry = @import("hook_registry.zig");
const HookContext = hook_registry.HookContext;
const HookData = hook_registry.HookData;
const HookError = hook_registry.HookError;
const AgentRuntime = @import("agent_runtime.zig").AgentRuntime;
const brain_tools = @import("brain_tools.zig");

/// Brain specialization configuration from agent.json
pub const BrainSpecialization = struct {
    allocator: std.mem.Allocator,
    brain_name: []const u8,
    allowed_tools: ?std.ArrayListUnmanaged([]const u8),
    denied_tools: ?std.ArrayListUnmanaged([]const u8),
    role: ?[]const u8,
    can_spawn_subbrains: bool,
    additional_rom: std.ArrayListUnmanaged(hook_registry.RomEntry),
    
    pub fn init(allocator: std.mem.Allocator, brain_name: []const u8) BrainSpecialization {
        return .{
            .allocator = allocator,
            .brain_name = brain_name,
            .allowed_tools = null,
            .denied_tools = null,
            .role = null,
            .can_spawn_subbrains = false,
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

/// Hook that applies brain specialization to ROM
pub fn applyBrainSpecializationHook(ctx: *HookContext, data: HookData) HookError!void {
    const rom = data.pre_observe;
    const allocator = ctx.runtime.allocator;
    
    // Load specialization for this brain
    var spec = loadBrainSpecialization(allocator, ctx.runtime, ctx.brain_name) catch |err| {
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
    rom.set("system:can_spawn_subbrains", 
        if (spec.?.can_spawn_subbrains) "true" else "false"
    ) catch return HookError.OutOfMemory;
    
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
    
    // If it's an array of tools, filter it
    if (parsed.value != .array) {
        // Not an array, return as-is
        return allocator.dupe(u8, capabilities_json);
    }
    
    // Build filtered list of tool names
    var allowed_tools = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (allowed_tools.items) |tool| {
            allocator.free(tool);
        }
        allowed_tools.deinit(allocator);
    }
    
    for (parsed.value.array.items) |tool| {
        const tool_name = getToolName(tool) orelse continue;
        
        if (spec.isToolAllowed(tool_name)) {
            const owned = try allocator.dupe(u8, tool_name);
            try allowed_tools.append(allocator, owned);
        }
    }
    
    // Build simple JSON array of allowed tool names
    var result_json = std.ArrayListUnmanaged(u8){};
    defer result_json.deinit(allocator);
    
    const writer = result_json.writer(allocator);
    try writer.writeByte('[');
    for (allowed_tools.items, 0..) |tool_name, i| {
        if (i > 0) try writer.writeByte(',');
        // Manual JSON string encoding (simple version - assumes no special chars)
        try writer.writeByte('"');
        try writer.writeAll(tool_name);
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
    
    return result_json.toOwnedSlice(allocator);
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
    // Construct path: agents/{agent_id}/{brain_name}/agent.json
    // For primary brain, use agent root
    const agent_dir = try std.fs.path.join(allocator, &.{ runtime.agent_id, "agents" });
    defer allocator.free(agent_dir);
    
    const brain_dir = if (std.mem.eql(u8, brain_name, "primary"))
        try allocator.dupe(u8, agent_dir)
    else
        try std.fs.path.join(allocator, &.{ agent_dir, brain_name });
    defer allocator.free(brain_dir);
    
    const path = try std.fs.path.join(allocator, &.{ brain_dir, "agent.json" });
    defer allocator.free(path);
    
    return std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
}

/// Register brain specialization hook for a specific brain
pub fn registerBrainSpecialization(
    registry: *hook_registry.HookRegistry,
    brain_name: []const u8,
) !void {
    _ = brain_name; // Currently we use a generic hook that loads per-brain
    
    // Register the specialization hook at priority 0 (between system_first and system_last)
    try registry.register(.pre_observe, .{
        .name = "brain:specialization",
        .priority = 0, // Normal priority
        .callback = applyBrainSpecializationHook,
    });
}
