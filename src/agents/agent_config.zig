const std = @import("std");
const BrainSpecialization = @import("brain_specialization.zig").BrainSpecialization;

/// Flat agent configuration structure
pub const AgentConfig = struct {
    allocator: std.mem.Allocator,
    agent_id: ?[]u8,
    name: ?[]u8,
    description: ?[]u8,
    creature: ?[]u8,
    vibe: ?[]u8,
    emoji: ?[]u8,

    primary: BrainConfig,
    sub_brains: std.StringHashMapUnmanaged(SubBrainConfig),

    pub fn init(allocator: std.mem.Allocator) AgentConfig {
        return .{
            .allocator = allocator,
            .agent_id = null,
            .name = null,
            .description = null,
            .creature = null,
            .vibe = null,
            .emoji = null,
            .primary = BrainConfig.init(allocator),
            .sub_brains = .{},
        };
    }

    pub fn deinit(self: *AgentConfig) void {
        if (self.agent_id) |value| self.allocator.free(value);
        if (self.name) |value| self.allocator.free(value);
        if (self.description) |value| self.allocator.free(value);
        if (self.creature) |value| self.allocator.free(value);
        if (self.vibe) |value| self.allocator.free(value);
        if (self.emoji) |value| self.allocator.free(value);

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
            .provider = ProviderConfig.empty,
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
    creature: ?[]u8,
    vibe: ?[]u8,
    emoji: ?[]u8,
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
            .creature = null,
            .vibe = null,
            .emoji = null,
            .default_provider = ProviderConfig.empty,
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
        if (self.creature) |value| self.allocator.free(value);
        if (self.vibe) |value| self.allocator.free(value);
        if (self.emoji) |value| self.allocator.free(value);

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
    return loadAgentConfigFromDir(allocator, "agents", agent_id);
}

pub fn loadAgentConfigFromDir(
    allocator: std.mem.Allocator,
    agents_dir: []const u8,
    agent_id: []const u8,
) !?AgentConfig {
    const file_name = try std.fmt.allocPrint(allocator, "{s}_config.json", .{agent_id});
    defer allocator.free(file_name);
    const config_path = try std.fs.path.join(allocator, &.{ agents_dir, file_name });
    defer allocator.free(config_path);

    const content = std.fs.cwd().readFileAlloc(allocator, config_path, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer allocator.free(content);

    return try parseAgentConfig(allocator, content);
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
    if (root.get("creature")) |v| {
        if (v == .string) config.creature = try allocator.dupe(u8, v.string);
    }
    if (root.get("vibe")) |v| {
        if (v == .string) config.vibe = try allocator.dupe(u8, v.string);
    }
    if (root.get("emoji")) |v| {
        if (v == .string) config.emoji = try allocator.dupe(u8, v.string);
    }
    if (root.get("personality")) |v| {
        if (v == .object) {
            if (v.object.get("name")) |field| {
                if (field == .string) {
                    if (config.name) |existing| allocator.free(existing);
                    config.name = try allocator.dupe(u8, field.string);
                }
            }
            if (v.object.get("description")) |field| {
                if (field == .string) {
                    if (config.description) |existing| allocator.free(existing);
                    config.description = try allocator.dupe(u8, field.string);
                }
            }
            if (v.object.get("creature")) |field| {
                if (field == .string) {
                    if (config.creature) |existing| allocator.free(existing);
                    config.creature = try allocator.dupe(u8, field.string);
                }
            }
            if (v.object.get("vibe")) |field| {
                if (field == .string) {
                    if (config.vibe) |existing| allocator.free(existing);
                    config.vibe = try allocator.dupe(u8, field.string);
                }
            }
            if (v.object.get("emoji")) |field| {
                if (field == .string) {
                    if (config.emoji) |existing| allocator.free(existing);
                    config.emoji = try allocator.dupe(u8, field.string);
                }
            }
        }
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

                var sub_config = try parseSubBrainConfig(allocator, entry.value_ptr.*);
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

    // Parse OpenClaw-style personality metadata into ROM overrides.
    if (obj.get("personality")) |v| {
        if (v == .object) {
            if (v.object.get("name")) |field| {
                if (field == .string) try setRomOverride(allocator, &config, "system:personality_name", field.string);
            }
            if (v.object.get("description")) |field| {
                if (field == .string) try setRomOverride(allocator, &config, "system:personality_description", field.string);
            }
            if (v.object.get("creature")) |field| {
                if (field == .string) try setRomOverride(allocator, &config, "system:personality_creature", field.string);
            }
            if (v.object.get("vibe")) |field| {
                if (field == .string) try setRomOverride(allocator, &config, "system:personality_vibe", field.string);
            }
            if (v.object.get("emoji")) |field| {
                if (field == .string) try setRomOverride(allocator, &config, "system:personality_emoji", field.string);
            }
        }
    }
    if (obj.get("creature")) |v| {
        if (v == .string) try setRomOverride(allocator, &config, "system:personality_creature", v.string);
    }
    if (obj.get("vibe")) |v| {
        if (v == .string) try setRomOverride(allocator, &config, "system:personality_vibe", v.string);
    }
    if (obj.get("emoji")) |v| {
        if (v == .string) try setRomOverride(allocator, &config, "system:personality_emoji", v.string);
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

fn setRomOverride(
    allocator: std.mem.Allocator,
    config: *BrainConfig,
    key: []const u8,
    value: []const u8,
) !void {
    if (config.rom_overrides == null) config.rom_overrides = .{};
    try setRomEntryInList(allocator, &(config.rom_overrides.?), key, value);
}

fn setRomEntryInList(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(RomEntry),
    key: []const u8,
    value: []const u8,
) !void {
    for (list.items) |*existing| {
        if (!std.mem.eql(u8, existing.key, key)) continue;
        allocator.free(existing.value);
        existing.value = try allocator.dupe(u8, value);
        return;
    }
    try list.append(allocator, .{
        .key = try allocator.dupe(u8, key),
        .value = try allocator.dupe(u8, value),
    });
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

    return try parseSubBrainTemplate(allocator, content);
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
    if (root.get("creature")) |v| {
        if (v == .string) template.creature = try allocator.dupe(u8, v.string);
    }
    if (root.get("vibe")) |v| {
        if (v == .string) template.vibe = try allocator.dupe(u8, v.string);
    }
    if (root.get("emoji")) |v| {
        if (v == .string) template.emoji = try allocator.dupe(u8, v.string);
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

    // Provider: deep-copy merged values so merged config does not alias template/config memory.
    if (config.provider.name) |value| {
        merged.provider.name = try allocator.dupe(u8, value);
    } else if (template.default_provider.name) |value| {
        merged.provider.name = try allocator.dupe(u8, value);
    }
    if (config.provider.model) |value| {
        merged.provider.model = try allocator.dupe(u8, value);
    } else if (template.default_provider.model) |value| {
        merged.provider.model = try allocator.dupe(u8, value);
    }
    if (config.provider.think_level) |value| {
        merged.provider.think_level = try allocator.dupe(u8, value);
    } else if (template.default_provider.think_level) |value| {
        merged.provider.think_level = try allocator.dupe(u8, value);
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

    // Add template metadata as default personality/specialization ROM.
    if (template.name) |value| {
        try setRomEntryInList(allocator, &(merged.rom_overrides.?), "system:template_name", value);
        try setRomEntryInList(allocator, &(merged.rom_overrides.?), "system:personality_name", value);
    }
    if (template.specialization) |value| {
        try setRomEntryInList(allocator, &(merged.rom_overrides.?), "system:specialization", value);
    }
    if (template.description) |value| {
        try setRomEntryInList(allocator, &(merged.rom_overrides.?), "system:template_description", value);
    }
    if (template.creature) |value| {
        try setRomEntryInList(allocator, &(merged.rom_overrides.?), "system:personality_creature", value);
    }
    if (template.vibe) |value| {
        try setRomEntryInList(allocator, &(merged.rom_overrides.?), "system:personality_vibe", value);
    }
    if (template.emoji) |value| {
        try setRomEntryInList(allocator, &(merged.rom_overrides.?), "system:personality_emoji", value);
    }

    // Add template ROM entries
    if (template.rom_entries) |roms| {
        for (roms.items) |rom| try setRomEntryInList(allocator, &(merged.rom_overrides.?), rom.key, rom.value);
    }

    // Add config ROM overrides (will replace if key exists)
    if (config.rom_overrides) |roms| {
        for (roms.items) |rom| try setRomEntryInList(allocator, &(merged.rom_overrides.?), rom.key, rom.value);
    }

    return merged;
}

pub fn saveAgentConfig(
    allocator: std.mem.Allocator,
    agents_dir: []const u8,
    agent_id: []const u8,
    config: *const AgentConfig,
) !void {
    const content = try stringifyAgentConfig(allocator, config);
    defer allocator.free(content);
    const file_name = try std.fmt.allocPrint(allocator, "{s}_config.json", .{agent_id});
    defer allocator.free(file_name);
    const path = try std.fs.path.join(allocator, &.{ agents_dir, file_name });
    defer allocator.free(path);
    try std.fs.cwd().writeFile(.{
        .sub_path = path,
        .data = content,
    });
}

pub fn stringifyAgentConfig(allocator: std.mem.Allocator, config: *const AgentConfig) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);
    try writer.writeByte('{');
    var first = true;

    try writeOptionalStringField(allocator, &out, &first, "agent_id", config.agent_id);
    try writeOptionalStringField(allocator, &out, &first, "name", config.name);
    try writeOptionalStringField(allocator, &out, &first, "description", config.description);
    try writeOptionalStringField(allocator, &out, &first, "creature", config.creature);
    try writeOptionalStringField(allocator, &out, &first, "vibe", config.vibe);
    try writeOptionalStringField(allocator, &out, &first, "emoji", config.emoji);

    if (!first) try writer.writeByte(',');
    first = false;
    try writer.writeAll("\"primary\":");
    try writeBrainConfigJson(allocator, &out, config.primary);

    if (!first) try writer.writeByte(',');
    first = false;
    try writer.writeAll("\"sub_brains\":{");
    var sub_names = std.ArrayListUnmanaged([]const u8){};
    defer sub_names.deinit(allocator);
    var it = config.sub_brains.iterator();
    while (it.next()) |entry| try sub_names.append(allocator, entry.key_ptr.*);
    std.mem.sort([]const u8, sub_names.items, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);
    for (sub_names.items, 0..) |name, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writeJsonString(writer, name);
        try writer.writeByte(':');
        const sub = config.sub_brains.get(name) orelse continue;
        try writeBrainConfigJson(allocator, &out, sub.base);
    }
    try writer.writeByte('}');

    try writer.writeByte('}');
    return out.toOwnedSlice(allocator);
}

fn writeBrainConfigJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    cfg: BrainConfig,
) !void {
    const writer = out.writer(allocator);
    try writer.writeByte('{');
    var first = true;

    if (providerHasValues(cfg.provider)) {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("\"provider\":");
        try writeProviderConfigJson(allocator, out, cfg.provider);
    }
    if (cfg.can_spawn_subbrains) {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("\"can_spawn_subbrains\":true");
    }
    try writeOptionalStringArrayField(allocator, out, &first, "allowed_tools", cfg.allowed_tools);
    try writeOptionalStringArrayField(allocator, out, &first, "denied_tools", cfg.denied_tools);
    try writeOptionalStringArrayField(allocator, out, &first, "capabilities", cfg.capabilities);
    if (cfg.rom_overrides) |roms| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("\"rom_overrides\":[");
        for (roms.items, 0..) |rom, idx| {
            if (idx > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try writer.writeAll("\"key\":");
            try writeJsonString(writer, rom.key);
            try writer.writeAll(",\"value\":");
            try writeJsonString(writer, rom.value);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
    }
    if (cfg.template) |value| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("\"template\":");
        try writeJsonString(writer, value);
    }

    try writer.writeByte('}');
}

fn writeProviderConfigJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    provider: ProviderConfig,
) !void {
    const writer = out.writer(allocator);
    try writer.writeByte('{');
    var first = true;
    if (provider.name) |value| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("\"name\":");
        try writeJsonString(writer, value);
    }
    if (provider.model) |value| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("\"model\":");
        try writeJsonString(writer, value);
    }
    if (provider.think_level) |value| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("\"think_level\":");
        try writeJsonString(writer, value);
    }
    try writer.writeByte('}');
}

fn providerHasValues(provider: ProviderConfig) bool {
    return provider.name != null or provider.model != null or provider.think_level != null;
}

fn writeOptionalStringField(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    first: *bool,
    key: []const u8,
    value: ?[]const u8,
) !void {
    const concrete = value orelse return;
    const writer = out.writer(allocator);
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writeJsonString(writer, key);
    try writer.writeByte(':');
    try writeJsonString(writer, concrete);
}

fn writeOptionalStringArrayField(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    first: *bool,
    key: []const u8,
    values: ?std.ArrayListUnmanaged([]u8),
) !void {
    const concrete = values orelse return;
    const writer = out.writer(allocator);
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try writeJsonString(writer, key);
    try writer.writeByte(':');
    try writer.writeByte('[');
    for (concrete.items, 0..) |item, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writeJsonString(writer, item);
    }
    try writer.writeByte(']');
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |char| {
        switch (char) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => if (char < 0x20) {
                try writer.print("\\u00{x:0>2}", .{char});
            } else {
                try writer.writeByte(char);
            },
        }
    }
    try writer.writeByte('"');
}
