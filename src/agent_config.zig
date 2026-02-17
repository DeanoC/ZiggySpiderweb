const std = @import("std");
const BrainSpecialization = @import("brain_specialization.zig").BrainSpecialization;

/// Flat agent configuration structure
pub const AgentConfig = struct {
    allocator: std.mem.Allocator,
    agent_id: ?[]u8,
    name: ?[]u8,
    description: ?[]u8,
    
    primary: BrainConfig,
    sub_brains: std.StringHashMapUnmanaged(SubBrainConfig),
    
    pub fn init(allocator: std.mem.Allocator) AgentConfig {
        return .{
            .allocator = allocator,
            .agent_id = null,
            .name = null,
            .description = null,
            .primary = BrainConfig.init(allocator),
            .sub_brains = .{},
        };
    }
    
    pub fn deinit(self: *AgentConfig) void {
        if (self.agent_id) |value| self.allocator.free(value);
        if (self.name) |value| self.allocator.free(value);
        if (self.description) |value| self.allocator.free(value);
        
        self.primary.deinit();
        
        var it = self.sub_brains.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.sub_brains.deinit(self.allocator);
    }
    
    /// Get brain config for a specific brain name
    pub fn getBrainConfig(self: *const AgentConfig, brain_name: []const u8) ?BrainConfigView {
        if (std.mem.eql(u8, brain_name, "primary")) {
            return self.primary.view();
        }
        if (self.sub_brains.get(brain_name)) |sub| {
            return sub.view();
        }
        return null;
    }
};

/// Brain configuration (primary or sub-brain)
pub const BrainConfig = struct {
    allocator: std.mem.Allocator,
    provider: ProviderConfig,
    can_spawn_subbrains: bool,
    allowed_tools: ?std.ArrayListUnmanaged([]u8),
    denied_tools: ?std.ArrayListUnmanaged([]u8),
    capabilities: ?std.ArrayListUnmanaged([]u8),
    rom_overrides: ?std.ArrayListUnmanaged(RomEntry),
    template: ?[]u8,
    
    pub fn init(allocator: std.mem.Allocator) BrainConfig {
        return .{
            .allocator = allocator,
            .provider = ProviderConfig{},
            .can_spawn_subbrains = false,
            .allowed_tools = null,
            .denied_tools = null,
            .capabilities = null,
            .rom_overrides = null,
            .template = null,
        };
    }
    
    pub fn deinit(self: *BrainConfig) void {
        self.provider.deinit(self.allocator);
        
        if (self.allowed_tools) |*tools| {
            for (tools.items) |tool| self.allocator.free(tool);
            tools.deinit(self.allocator);
        }
        if (self.denied_tools) |*tools| {
            for (tools.items) |tool| self.allocator.free(tool);
            tools.deinit(self.allocator);
        }
        if (self.capabilities) |*caps| {
            for (caps.items) |cap| self.allocator.free(cap);
            caps.deinit(self.allocator);
        }
        if (self.rom_overrides) |*roms| {
            for (roms.items) |*rom| rom.deinit(self.allocator);
            roms.deinit(self.allocator);
        }
        if (self.template) |value| self.allocator.free(value);
    }
    
    pub fn view(self: *const BrainConfig) BrainConfigView {
        return .{
            .provider = self.provider.view(),
            .can_spawn_subbrains = self.can_spawn_subbrains,
            .allowed_tools = self.allowed_tools,
            .denied_tools = self.denied_tools,
            .capabilities = self.capabilities,
            .rom_overrides = self.rom_overrides,
            .template = self.template,
        };
    }
};

/// Read-only view of brain config
pub const BrainConfigView = struct {
    provider: ProviderConfigView,
    can_spawn_subbrains: bool,
    allowed_tools: ?std.ArrayListUnmanaged([]u8),
    denied_tools: ?std.ArrayListUnmanaged([]u8),
    capabilities: ?std.ArrayListUnmanaged([]u8),
    rom_overrides: ?std.ArrayListUnmanaged(RomEntry),
    template: ?[]u8,
};

/// Sub-brain configuration (extends base with template reference)
pub const SubBrainConfig = struct {
    base: BrainConfig,
    
    pub fn init(allocator: std.mem.Allocator) SubBrainConfig {
        return .{ .base = BrainConfig.init(allocator) };
    }
    
    pub fn deinit(self: *SubBrainConfig, allocator: std.mem.Allocator) void {
        self.base.deinit();
        _ = allocator;
    }
    
    pub fn view(self: *const SubBrainConfig) BrainConfigView {
        return self.base.view();
    }
};

/// Provider configuration
pub const ProviderConfig = struct {
    name: ?[]u8,
    model: ?[]u8,
    think_level: ?[]u8,
    
    pub const empty = ProviderConfig{ .name = null, .model = null, .think_level = null };
    
    pub fn deinit(self: *ProviderConfig, allocator: std.mem.Allocator) void {
        if (self.name) |value| allocator.free(value);
        if (self.model) |value| allocator.free(value);
        if (self.think_level) |value| allocator.free(value);
    }
    
    pub fn view(self: *const ProviderConfig) ProviderConfigView {
        return .{
            .name = self.name,
            .model = self.model,
            .think_level = self.think_level,
        };
    }
};

pub const ProviderConfigView = struct {
    name: ?[]const u8,
    model: ?[]const u8,
    think_level: ?[]const u8,
};

/// ROM entry for pre-loading guidance
pub const RomEntry = struct {
    key: []u8,
    value: []u8,
    
    pub fn deinit(self: *RomEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

/// Sub-brain template definition
pub const SubBrainTemplate = struct {
    allocator: std.mem.Allocator,
    name: ?[]u8,
    specialization: ?[]u8,
    description: ?[]u8,
    default_provider: ProviderConfig,
    capabilities: ?std.ArrayListUnmanaged([]u8),
    rom_entries: ?std.ArrayListUnmanaged(RomEntry),
    allowed_tools: ?std.ArrayListUnmanaged([]u8),
    denied_tools: ?std.ArrayListUnmanaged([]u8),
    can_spawn_subbrains: bool,
    
    pub fn init(allocator: std.mem.Allocator) SubBrainTemplate {
        return .{
            .allocator = allocator,
            .name = null,
            .specialization = null,
            .description = null,
            .default_provider = ProviderConfig{},
            .capabilities = null,
            .rom_entries = null,
            .allowed_tools = null,
            .denied_tools = null,
            .can_spawn_subbrains = false,
        };
    }
    
    pub fn deinit(self: *SubBrainTemplate) void {
        if (self.name) |value| self.allocator.free(value);
        if (self.specialization) |value| self.allocator.free(value);
        if (self.description) |value| self.allocator.free(value);
        
        self.default_provider.deinit(self.allocator);
        
        if (self.capabilities) |*caps| {
            for (caps.items) |cap| self.allocator.free(cap);
            caps.deinit(self.allocator);
        }
        if (self.rom_entries) |*roms| {
            for (roms.items) |*rom| rom.deinit(self.allocator);
            roms.deinit(self.allocator);
        }
        if (self.allowed_tools) |*tools| {
            for (tools.items) |tool| self.allocator.free(tool);
            tools.deinit(self.allocator);
        }
        if (self.denied_tools) |*tools| {
            for (tools.items) |tool| self.allocator.free(tool);
            tools.deinit(self.allocator);
        }
    }
};


// ============================================================================
// Loading Functions
// ============================================================================

/// Load flat agent config from {agent_id}_config.json
pub fn loadAgentConfig(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
) !?AgentConfig {
    const config_path = try std.fmt.allocPrint(allocator, "agents/{s}_config.json", .{agent_id});
    defer allocator.free(config_path);
    
    const content = std.fs.cwd().readFileAlloc(allocator, config_path, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer allocator.free(content);
    
    return parseAgentConfig(allocator, content);
}

/// Parse agent config JSON
fn parseAgentConfig(allocator: std.mem.Allocator, json_content: []const u8) !AgentConfig {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_content, .{});
    defer parsed.deinit();
    
    var config = AgentConfig.init(allocator);
    errdefer config.deinit();
    
    if (parsed.value != .object) return config;
    const root = parsed.value.object;
    
    // Parse agent metadata
    if (root.get("agent_id")) |v| {
        if (v == .string) config.agent_id = try allocator.dupe(u8, v.string);
    }
    if (root.get("name")) |v| {
        if (v == .string) config.name = try allocator.dupe(u8, v.string);
    }
    if (root.get("description")) |v| {
        if (v == .string) config.description = try allocator.dupe(u8, v.string);
    }
    
    // Parse primary brain config
    if (root.get("primary")) |primary_json| {
        config.primary = try parseBrainConfig(allocator, primary_json);
    }
    
    // Parse sub-brains
    if (root.get("sub_brains")) |subs_json| {
        if (subs_json == .object) {
            var it = subs_json.object.iterator();
            while (it.next()) |entry| {
                const brain_name = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(brain_name);
                
                const sub_config = try parseSubBrainConfig(allocator, entry.value_ptr.*);
                errdefer sub_config.deinit(allocator);
                
                try config.sub_brains.put(allocator, brain_name, sub_config);
            }
        }
    }
    
    return config;
}

/// Parse brain config from JSON
fn parseBrainConfig(allocator: std.mem.Allocator, json: std.json.Value) !BrainConfig {
    var config = BrainConfig.init(allocator);
    errdefer config.deinit();
    
    if (json != .object) return config;
    const obj = json.object;
    
    // Parse provider
    if (obj.get("provider")) |provider_json| {
        config.provider = try parseProviderConfig(allocator, provider_json);
    }
    
    // Parse can_spawn_subbrains
    if (obj.get("can_spawn_subbrains")) |v| {
        if (v == .bool) config.can_spawn_subbrains = v.bool;
    }
    
    // Parse allowed_tools
    if (obj.get("allowed_tools")) |tools_json| {
        if (tools_json == .array) {
            config.allowed_tools = .{};
            for (tools_json.array.items) |tool| {
                if (tool == .string) {
                    const owned = try allocator.dupe(u8, tool.string);
                    try config.allowed_tools.?.append(allocator, owned);
                }
            }
        }
    }
    
    // Parse denied_tools
    if (obj.get("denied_tools")) |tools_json| {
        if (tools_json == .array) {
            config.denied_tools = .{};
            for (tools_json.array.items) |tool| {
                if (tool == .string) {
                    const owned = try allocator.dupe(u8, tool.string);
                    try config.denied_tools.?.append(allocator, owned);
                }
            }
        }
    }
    
    // Parse capabilities
    if (obj.get("capabilities")) |caps_json| {
        if (caps_json == .array) {
            config.capabilities = .{};
            for (caps_json.array.items) |cap| {
                if (cap == .string) {
                    const owned = try allocator.dupe(u8, cap.string);
                    try config.capabilities.?.append(allocator, owned);
                }
            }
        }
    }
    
    // Parse rom_overrides
    if (obj.get("rom_overrides")) |roms_json| {
        if (roms_json == .array) {
            config.rom_overrides = .{};
            for (roms_json.array.items) |rom| {
                if (rom == .object) {
                    const key_json = rom.object.get("key") orelse continue;
                    const value_json = rom.object.get("value") orelse continue;
                    if (key_json != .string or value_json != .string) continue;
                    
                    const entry = RomEntry{
                        .key = try allocator.dupe(u8, key_json.string),
                        .value = try allocator.dupe(u8, value_json.string),
                    };
                    try config.rom_overrides.?.append(allocator, entry);
                }
            }
        }
    }
    
    // Parse template reference
    if (obj.get("template")) |v| {
        if (v == .string) config.template = try allocator.dupe(u8, v.string);
    }
    
    return config;
}

/// Parse sub-brain config (same as brain config)
fn parseSubBrainConfig(allocator: std.mem.Allocator, json: std.json.Value) !SubBrainConfig {
    const base = try parseBrainConfig(allocator, json);
    return SubBrainConfig{ .base = base };
}

/// Parse provider config from JSON
fn parseProviderConfig(allocator: std.mem.Allocator, json: std.json.Value) !ProviderConfig {
    var config = ProviderConfig.empty;
    
    switch (json) {
        .string => {
            // Shorthand: "provider-name"
            config.name = try allocator.dupe(u8, json.string);
        },
        .object => {
            const obj = json.object;
            if (obj.get("name")) |v| {
                if (v == .string) config.name = try allocator.dupe(u8, v.string);
            }
            if (obj.get("model")) |v| {
                if (v == .string) config.model = try allocator.dupe(u8, v.string);
            }
            if (obj.get("think_level")) |v| {
                if (v == .string) config.think_level = try allocator.dupe(u8, v.string);
            }
        },
        else => {},
    }
    
    return config;
}

/// Load sub-brain template from templates/sub-brains/{template_name}.json
pub fn loadSubBrainTemplate(
    allocator: std.mem.Allocator,
    template_name: []const u8,
) !?SubBrainTemplate {
    const path = try std.fmt.allocPrint(allocator, "templates/sub-brains/{s}.json", .{template_name});
    defer allocator.free(path);
    
    const content = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) {
            std.log.warn("Sub-brain template not found: {s}", .{template_name});
            return null;
        }
        return err;
    };
    defer allocator.free(content);
    
    return parseSubBrainTemplate(allocator, content);
}

/// Parse sub-brain template JSON
fn parseSubBrainTemplate(allocator: std.mem.Allocator, json_content: []const u8) !SubBrainTemplate {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_content, .{});
    defer parsed.deinit();
    
    var template = SubBrainTemplate.init(allocator);
    errdefer template.deinit();
    
    if (parsed.value != .object) return template;
    const root = parsed.value.object;
    
    // Parse metadata
    if (root.get("name")) |v| {
        if (v == .string) template.name = try allocator.dupe(u8, v.string);
    }
    if (root.get("specialization")) |v| {
        if (v == .string) template.specialization = try allocator.dupe(u8, v.string);
    }
    if (root.get("description")) |v| {
        if (v == .string) template.description = try allocator.dupe(u8, v.string);
    }
    
    // Parse default provider
    if (root.get("default_provider")) |provider_json| {
        template.default_provider = try parseProviderConfig(allocator, provider_json);
    }
    
    // Parse capabilities
    if (root.get("capabilities")) |caps_json| {
        if (caps_json == .array) {
            template.capabilities = .{};
            for (caps_json.array.items) |cap| {
                if (cap == .string) {
                    const owned = try allocator.dupe(u8, cap.string);
                    try template.capabilities.?.append(allocator, owned);
                }
            }
        }
    }
    
    // Parse rom_entries
    if (root.get("rom_entries")) |roms_json| {
        if (roms_json == .array) {
            template.rom_entries = .{};
            for (roms_json.array.items) |rom| {
                if (rom == .object) {
                    const key_json = rom.object.get("key") orelse continue;
                    const value_json = rom.object.get("value") orelse continue;
                    if (key_json != .string or value_json != .string) continue;
                    
                    const entry = RomEntry{
                        .key = try allocator.dupe(u8, key_json.string),
                        .value = try allocator.dupe(u8, value_json.string),
                    };
                    try template.rom_entries.?.append(allocator, entry);
                }
            }
        }
    }
    
    // Parse allowed_tools
    if (root.get("allowed_tools")) |tools_json| {
        if (tools_json == .array) {
            template.allowed_tools = .{};
            for (tools_json.array.items) |tool| {
                if (tool == .string) {
                    const owned = try allocator.dupe(u8, tool.string);
                    try template.allowed_tools.?.append(allocator, owned);
                }
            }
        }
    }
    
    // Parse denied_tools
    if (root.get("denied_tools")) |tools_json| {
        if (tools_json == .array) {
            template.denied_tools = .{};
            for (tools_json.array.items) |tool| {
                if (tool == .string) {
                    const owned = try allocator.dupe(u8, tool.string);
                    try template.denied_tools.?.append(allocator, owned);
                }
            }
        }
    }
    
    // Parse can_spawn_subbrains
    if (root.get("can_spawn_subbrains")) |v| {
        if (v == .bool) template.can_spawn_subbrains = v.bool;
    }
    
    return template;
}

// ============================================================================
// Merging Functions
// ============================================================================

/// Merge brain config with template
/// Template provides defaults, config provides overrides
pub fn mergeWithTemplate(
    allocator: std.mem.Allocator,
    config: BrainConfig,
    template: SubBrainTemplate,
) !BrainConfig {
    var merged = BrainConfig.init(allocator);
    errdefer merged.deinit();
    
    // Template name/specialization/description become ROM entries if not already present
    
    // Provider: Config overrides template
    if (config.provider.name) |_| {
        merged.provider = config.provider;
    } else {
        merged.provider = template.default_provider;
    }
    // But allow partial override (config can override just model, keep provider name)
    if (config.provider.model) |model| {
        if (merged.provider.model) |old| allocator.free(old);
        merged.provider.model = try allocator.dupe(u8, model);
    }
    if (config.provider.think_level) |think| {
        if (merged.provider.think_level) |old| allocator.free(old);
        merged.provider.think_level = try allocator.dupe(u8, think);
    }
    
    // can_spawn_subbrains: Config overrides template
    merged.can_spawn_subbrains = config.can_spawn_subbrains or template.can_spawn_subbrains;
    
    // Tools: Config replaces template (not merged)
    if (config.allowed_tools) |tools| {
        merged.allowed_tools = .{};
        for (tools.items) |tool| {
            const owned = try allocator.dupe(u8, tool);
            try merged.allowed_tools.?.append(allocator, owned);
        }
    } else if (template.allowed_tools) |tools| {
        merged.allowed_tools = .{};
        for (tools.items) |tool| {
            const owned = try allocator.dupe(u8, tool);
            try merged.allowed_tools.?.append(allocator, owned);
        }
    }
    
    if (config.denied_tools) |tools| {
        merged.denied_tools = .{};
        for (tools.items) |tool| {
            const owned = try allocator.dupe(u8, tool);
            try merged.denied_tools.?.append(allocator, owned);
        }
    } else if (template.denied_tools) |tools| {
        merged.denied_tools = .{};
        for (tools.items) |tool| {
            const owned = try allocator.dupe(u8, tool);
            try merged.denied_tools.?.append(allocator, owned);
        }
    }
    
    // Capabilities: Config replaces template
    if (config.capabilities) |caps| {
        merged.capabilities = .{};
        for (caps.items) |cap| {
            const owned = try allocator.dupe(u8, cap);
            try merged.capabilities.?.append(allocator, owned);
        }
    } else if (template.capabilities) |caps| {
        merged.capabilities = .{};
        for (caps.items) |cap| {
            const owned = try allocator.dupe(u8, cap);
            try merged.capabilities.?.append(allocator, owned);
        }
    }
    
    // ROM entries: Template first, then config overrides/adds
    merged.rom_overrides = .{};
    
    // Add template ROM entries
    if (template.rom_entries) |roms| {
        for (roms.items) |rom| {
            const entry = RomEntry{
                .key = try allocator.dupe(u8, rom.key),
                .value = try allocator.dupe(u8, rom.value),
            };
            try merged.rom_overrides.?.append(allocator, entry);
        }
    }
    
    // Add config ROM overrides (will replace if key exists)
    if (config.rom_overrides) |roms| {
        for (roms.items) |rom| {
            // Check if key already exists and replace
            var found = false;
            if (merged.rom_overrides) |*existing| {
                for (existing.items, 0..) |*existing_rom, idx| {
                    if (std.mem.eql(u8, existing_rom.key, rom.key)) {
                        allocator.free(existing_rom.value);
                        existing_rom.value = try allocator.dupe(u8, rom.value);
                        found = true;
                        break;
                    }
                }
            }
            
            if (!found) {
                const entry = RomEntry{
                    .key = try allocator.dupe(u8, rom.key),
                    .value = try allocator.dupe(u8, rom.value),
                };
                try merged.rom_overrides.?.append(allocator, entry);
            }
        }
    }
    
    return merged;
}
