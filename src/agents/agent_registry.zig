const std = @import("std");
const persona_pack = @import("persona_pack.zig");

pub const AgentCapability = enum {
    chat,
    code,
    plan,
    research,
};

pub const AgentInfo = struct {
    id: []u8,
    name: []u8,
    description: []u8,
    is_default: bool,
    capabilities: std.ArrayListUnmanaged(AgentCapability),
    identity_loaded: bool,
    persona_pack: ?[]u8,

    pub fn deinit(self: *AgentInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.description);
        if (self.persona_pack) |value| allocator.free(value);
        self.capabilities.deinit(allocator);
    }
};

pub const AgentRegistry = struct {
    allocator: std.mem.Allocator,
    agents: std.ArrayListUnmanaged(AgentInfo),
    base_dir: []const u8,
    agents_dir_rel: []const u8,
    assets_dir_rel: []const u8,
    default_agent_id: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, base_dir: []const u8, agents_dir: []const u8, assets_dir: []const u8) AgentRegistry {
        return .{
            .allocator = allocator,
            .agents = .{},
            .base_dir = base_dir,
            .agents_dir_rel = agents_dir,
            .assets_dir_rel = assets_dir,
            .default_agent_id = null,
        };
    }

    pub fn deinit(self: *AgentRegistry) void {
        for (self.agents.items) |*agent| {
            agent.deinit(self.allocator);
        }
        self.agents.deinit(self.allocator);
        if (self.default_agent_id) |id| {
            self.allocator.free(id);
        }
    }

    /// Scan agents/ directory and load all agent definitions
    pub fn scan(self: *AgentRegistry) !void {
        // Clear existing agents
        for (self.agents.items) |*agent| {
            agent.deinit(self.allocator);
        }
        self.agents.clearRetainingCapacity();

        // Try to open agents/ directory
        const agents_dir_path = try self.resolveAgentsDirPath();
        defer self.allocator.free(agents_dir_path);

        var agents_dir = std.fs.cwd().openDir(agents_dir_path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) {
                // No agents directory yet - first-boot state with no provisioned agents.
                return;
            }
            return err;
        };
        defer agents_dir.close();

        var has_default = false;
        var mother_index: ?usize = null;
        var it = agents_dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;

            const agent = try self.loadAgent(entry.name, agents_dir_path);
            if (std.mem.eql(u8, agent.id, "mother")) {
                mother_index = self.agents.items.len;
            }
            if (agent.is_default) {
                has_default = true;
            }
            try self.agents.append(self.allocator, agent);
        }

        // If no agent is marked as default, prefer Mother and otherwise the first agent.
        if (!has_default and self.agents.items.len > 0) {
            if (mother_index) |idx| {
                self.agents.items[idx].is_default = true;
            } else {
                self.agents.items[0].is_default = true;
            }
        }
    }

    /// Check if server is in first-boot state (no provisioned agents exist yet).
    /// Call `scan()` before this check.
    pub fn isFirstBoot(self: *const AgentRegistry) bool {
        return self.agents.items.len == 0;
    }

    /// Initialize first agent on first boot
    pub fn initializeFirstAgent(self: *AgentRegistry, agent_id: []const u8, persona_pack_path: ?[]const u8) !void {
        // Create the agents directory
        const agents_dir_path = try self.resolveAgentsDirPath();
        defer self.allocator.free(agents_dir_path);

        try std.fs.cwd().makePath(agents_dir_path);

        // Seed the first agent from the selected persona pack.
        try self.createAgent(agent_id, persona_pack_path);

        // Mark it as default
        for (self.agents.items) |*a| {
            if (std.mem.eql(u8, a.id, agent_id)) {
                // Clear default from all others
                for (self.agents.items) |*other| {
                    other.is_default = false;
                }
                a.is_default = true;
                break;
            }
        }
    }

    fn loadAgent(self: *AgentRegistry, agent_id: []const u8, agents_dir: []const u8) !AgentInfo {
        const agent_path = try std.fs.path.join(self.allocator, &.{ agents_dir, agent_id });
        defer self.allocator.free(agent_path);

        // Try to load agent.json first
        const agent_json = try self.loadAgentJson(agent_path);
        defer if (agent_json) |j| self.allocator.free(j);

        if (agent_json) |json| {
            return try self.parseAgentJson(agent_id, agent_path, json);
        }

        // Fallback: infer from identity files
        return try self.inferAgentFromIdentity(agent_id, agent_path);
    }

    fn loadAgentJson(self: *AgentRegistry, agent_path: []const u8) !?[]u8 {
        const json_path = try std.fs.path.join(self.allocator, &.{ agent_path, "agent.json" });
        defer self.allocator.free(json_path);

        const file = std.fs.cwd().openFile(json_path, .{ .mode = .read_only }) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        defer file.close();

        return try file.readToEndAlloc(self.allocator, 64 * 1024);
    }

    fn parseAgentJson(self: *AgentRegistry, agent_id: []const u8, agent_path: []const u8, json: []const u8) !AgentInfo {
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, json, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        const name = if (root.get("name")) |n|
            if (n == .string) try self.allocator.dupe(u8, n.string) else try self.allocator.dupe(u8, agent_id)
        else
            try self.allocator.dupe(u8, agent_id);

        const description = if (root.get("description")) |d|
            if (d == .string) try self.allocator.dupe(u8, d.string) else try self.allocator.dupe(u8, "")
        else
            try self.allocator.dupe(u8, "");

        const is_default = if (root.get("is_default")) |d|
            d == .bool and d.bool
        else
            false;

        var capabilities = std.ArrayListUnmanaged(AgentCapability){};
        if (root.get("capabilities")) |caps| {
            if (caps == .array) {
                for (caps.array.items) |cap| {
                    if (cap == .string) {
                        const capability = parseCapability(cap.string) catch continue;
                        try capabilities.append(self.allocator, capability);
                    }
                }
            }
        }

        const persona_pack_id = if (root.get("persona_pack")) |value|
            if (value == .string) try self.allocator.dupe(u8, value.string) else null
        else
            null;
        const identity_loaded = self.checkIdentityFiles(agent_path) or self.checkPersonaPackAssets(persona_pack_id);

        return .{
            .id = try self.allocator.dupe(u8, agent_id),
            .name = name,
            .description = description,
            .is_default = is_default,
            .capabilities = capabilities,
            .identity_loaded = identity_loaded,
            .persona_pack = persona_pack_id,
        };
    }

    fn inferAgentFromIdentity(self: *AgentRegistry, agent_id: []const u8, agent_path: []const u8) !AgentInfo {
        // Try to extract name from SOUL.md or IDENTITY.md
        const name = try self.extractNameFromIdentity(agent_path) orelse try self.allocator.dupe(u8, agent_id);

        // Check which identity files exist
        const identity_loaded = self.checkIdentityFiles(agent_path);

        // Infer capabilities from agent_id
        var capabilities = std.ArrayListUnmanaged(AgentCapability){};
        try capabilities.append(self.allocator, .chat);

        if (std.mem.containsAtLeast(u8, agent_id, 1, "code") or
            std.mem.containsAtLeast(u8, agent_id, 1, "dev") or
            std.mem.containsAtLeast(u8, agent_id, 1, "prog"))
        {
            try capabilities.append(self.allocator, .code);
        }

        if (std.mem.containsAtLeast(u8, agent_id, 1, "plan") or
            std.mem.containsAtLeast(u8, agent_id, 1, "pm") or
            std.mem.containsAtLeast(u8, agent_id, 1, "manage"))
        {
            try capabilities.append(self.allocator, .plan);
        }

        if (std.mem.containsAtLeast(u8, agent_id, 1, "research") or
            std.mem.containsAtLeast(u8, agent_id, 1, "search"))
        {
            try capabilities.append(self.allocator, .research);
        }

        return .{
            .id = try self.allocator.dupe(u8, agent_id),
            .name = name,
            .description = try self.allocator.dupe(u8, ""),
            .is_default = false,
            .capabilities = capabilities,
            .identity_loaded = identity_loaded,
            .persona_pack = null,
        };
    }

    fn checkIdentityFiles(self: *AgentRegistry, agent_path: []const u8) bool {
        // Check for any supported identity file: SOUL.md, AGENT.md, or IDENTITY.md
        const identity_files = [_][]const u8{ "SOUL.md", "AGENT.md", "IDENTITY.md" };

        for (identity_files) |filename| {
            const path = std.fs.path.join(self.allocator, &.{ agent_path, filename }) catch continue;
            defer self.allocator.free(path);

            std.fs.cwd().access(path, .{}) catch continue;
            return true; // Found at least one identity file
        }
        return false;
    }

    fn checkPersonaPackAssets(self: *AgentRegistry, maybe_pack_id: ?[]const u8) bool {
        const pack_id = maybe_pack_id orelse return false;
        if (!persona_pack.isValidPackId(pack_id)) return false;

        const assets_dir_path = self.resolveAssetsDirPath() catch return false;
        defer self.allocator.free(assets_dir_path);

        if (persona_pack.ensurePackExists(self.allocator, assets_dir_path, pack_id)) |_| {} else |_| return false;

        for (required_persona_files) |filename| {
            if (persona_pack.readOptionalPackFile(self.allocator, assets_dir_path, pack_id, filename, 128 * 1024)) |content| {
                if (content) |value| {
                    self.allocator.free(value);
                    continue;
                }
                return false;
            } else |_| return false;
        }
        return true;
    }

    /// Create a new agent by seeding identity files from a persona pack directory.
    pub fn createAgent(self: *AgentRegistry, persona_agent_id: []const u8, persona_pack_path: ?[]const u8) !void {
        const selected_pack_id = if (persona_pack_path) |tp| std.fs.path.basename(tp) else persona_pack.default_pack_id;
        if (!persona_pack.isValidPackId(selected_pack_id)) return error.InvalidTemplatePath;
        const resolved_persona_pack_path = if (persona_pack_path) |tp|
            try self.resolvePersonaPackPath(tp)
        else blk: {
            const assets_dir_path = try self.resolveAssetsDirPath();
            defer self.allocator.free(assets_dir_path);
            try persona_pack.ensurePackExists(self.allocator, assets_dir_path, persona_pack.default_pack_id);
            break :blk try persona_pack.resolvePackDir(self.allocator, assets_dir_path, persona_pack.default_pack_id);
        };
        defer self.allocator.free(resolved_persona_pack_path);

        // Create agent directory
        const agents_dir_path = try self.resolveAgentsDirPath();
        defer self.allocator.free(agents_dir_path);
        const agent_path = try std.fs.path.join(self.allocator, &.{ agents_dir_path, persona_agent_id });
        defer self.allocator.free(agent_path);

        try std.fs.cwd().makePath(agent_path);
        try self.seedAgentFromPersonaPack(agent_path, resolved_persona_pack_path);
        try self.ensurePersonaPackMetadata(agent_path, selected_pack_id);

        // Reload agents to include the new one
        try self.scan();
    }

    fn resolvePersonaPackPath(self: *AgentRegistry, template_path: []const u8) ![]u8 {
        if (persona_pack.isValidPackId(template_path)) {
            const assets_dir_path = try self.resolveAssetsDirPath();
            defer self.allocator.free(assets_dir_path);
            return persona_pack.resolvePackDir(self.allocator, assets_dir_path, template_path);
        }
        if (template_path.len == 0) return error.InvalidTemplatePath;
        if (containsParentTraversal(template_path)) return error.InvalidTemplatePath;

        const candidate_path = try resolveConfiguredPath(self.allocator, self.base_dir, template_path);
        defer self.allocator.free(candidate_path);

        const candidate_real = std.fs.cwd().realpathAlloc(self.allocator, candidate_path) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return err,
            else => return err,
        };
        defer self.allocator.free(candidate_real);

        const assets_dir_path = try self.resolveAssetsDirPath();
        defer self.allocator.free(assets_dir_path);
        if (try self.isTemplatePathUnderRoot(candidate_real, assets_dir_path)) {
            var dir = std.fs.cwd().openDir(candidate_real, .{}) catch return error.InvalidTemplatePath;
            dir.close();
            return self.allocator.dupe(u8, candidate_real);
        }

        const agents_dir_path = try self.resolveAgentsDirPath();
        defer self.allocator.free(agents_dir_path);
        if (try self.isTemplatePathUnderRoot(candidate_real, agents_dir_path)) {
            var dir = std.fs.cwd().openDir(candidate_real, .{}) catch return error.InvalidTemplatePath;
            dir.close();
            return self.allocator.dupe(u8, candidate_real);
        }

        return error.InvalidTemplatePath;
    }

    fn isTemplatePathUnderRoot(self: *AgentRegistry, candidate_real: []const u8, root_path: []const u8) !bool {
        const root_real = std.fs.cwd().realpathAlloc(self.allocator, root_path) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer self.allocator.free(root_real);
        return isPathWithinRoot(root_real, candidate_real);
    }

    fn resolveAgentsDirPath(self: *const AgentRegistry) ![]u8 {
        return resolveConfiguredPath(self.allocator, self.base_dir, self.agents_dir_rel);
    }

    fn resolveAssetsDirPath(self: *const AgentRegistry) ![]u8 {
        return resolveConfiguredPath(self.allocator, self.base_dir, self.assets_dir_rel);
    }

    fn seedAgentFromPersonaPack(self: *AgentRegistry, agent_path: []const u8, persona_pack_path: []const u8) !void {
        inline for (required_persona_files) |filename| {
            try self.copyPersonaFile(agent_path, persona_pack_path, filename, true);
        }
        inline for (optional_persona_files) |filename| {
            try self.copyPersonaFile(agent_path, persona_pack_path, filename, false);
        }
    }

    fn copyPersonaFile(
        self: *AgentRegistry,
        agent_path: []const u8,
        persona_pack_path: []const u8,
        filename: []const u8,
        required: bool,
    ) !void {
        const source_path = try std.fs.path.join(self.allocator, &.{ persona_pack_path, filename });
        defer self.allocator.free(source_path);

        const content = std.fs.cwd().readFileAlloc(self.allocator, source_path, 128 * 1024) catch |err| {
            if (!required and err == error.FileNotFound) return;
            if (err == error.FileNotFound) return error.InvalidTemplatePath;
            return err;
        };
        defer self.allocator.free(content);

        const target_path = try std.fs.path.join(self.allocator, &.{ agent_path, filename });
        defer self.allocator.free(target_path);
        try std.fs.cwd().writeFile(.{
            .sub_path = target_path,
            .data = content,
        });
    }

    fn ensurePersonaPackMetadata(
        self: *AgentRegistry,
        agent_path: []const u8,
        pack_id: []const u8,
    ) !void {
        if (!persona_pack.isValidPackId(pack_id)) return error.InvalidTemplatePath;

        const metadata_path = try std.fs.path.join(self.allocator, &.{ agent_path, "agent.json" });
        defer self.allocator.free(metadata_path);

        const existing_json = std.fs.cwd().readFileAlloc(self.allocator, metadata_path, 128 * 1024) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (existing_json) |value| self.allocator.free(value);

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);
        var writer = out.writer(self.allocator);
        try writer.writeByte('{');
        var wrote_field = false;

        if (existing_json) |value| {
            var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, value, .{});
            defer parsed.deinit();
            if (parsed.value == .object) {
                var it = parsed.value.object.iterator();
                while (it.next()) |entry| {
                    if (std.mem.eql(u8, entry.key_ptr.*, "persona_pack")) continue;
                    if (wrote_field) try writer.writeByte(',');
                    wrote_field = true;
                    try writer.print("{f}", .{std.json.fmt(entry.key_ptr.*, .{})});
                    try writer.writeByte(':');
                    try writer.print("{f}", .{std.json.fmt(entry.value_ptr.*, .{})});
                }
            }
        }

        if (wrote_field) try writer.writeByte(',');
        try writer.print("{f}", .{std.json.fmt("persona_pack", .{})});
        try writer.writeByte(':');
        try writer.print("{f}", .{std.json.fmt(pack_id, .{})});
        try writer.writeByte('}');

        const metadata_json = try out.toOwnedSlice(self.allocator);
        defer self.allocator.free(metadata_json);
        try std.fs.cwd().writeFile(.{
            .sub_path = metadata_path,
            .data = metadata_json,
        });
    }

    fn extractNameFromIdentity(self: *AgentRegistry, agent_path: []const u8) !?[]u8 {
        // Try IDENTITY.md first, then SOUL.md
        const filenames = [_][]const u8{ "IDENTITY.md", "SOUL.md" };

        for (filenames) |filename| {
            const path = try std.fs.path.join(self.allocator, &.{ agent_path, filename });
            defer self.allocator.free(path);

            const content = std.fs.cwd().readFileAlloc(self.allocator, path, 64 * 1024) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            defer self.allocator.free(content);

            // Look for "Name:" or "# Name" in first few lines
            var lines = std.mem.splitSequence(u8, content, "\n");
            var line_count: usize = 0;
            while (lines.next()) |line| : (line_count += 1) {
                if (line_count > 20) break;

                const trimmed = std.mem.trim(u8, line, " \t\r\n");

                // Look for "Name: X" pattern
                if (std.mem.startsWith(u8, trimmed, "Name:")) {
                    const name = std.mem.trim(u8, trimmed[5..], " \t\r\n-");
                    if (name.len > 0) {
                        return try self.allocator.dupe(u8, name);
                    }
                }

                // Look for "# X" (heading) pattern
                if (std.mem.startsWith(u8, trimmed, "# ")) {
                    const name = std.mem.trim(u8, trimmed[2..], " \t\r\n-");
                    if (name.len > 0 and !std.mem.eql(u8, name, "SOUL") and !std.mem.eql(u8, name, "IDENTITY")) {
                        return try self.allocator.dupe(u8, name);
                    }
                }
            }
        }

        return null;
    }

    /// Get all agents
    pub fn listAgents(self: *const AgentRegistry) []const AgentInfo {
        return self.agents.items;
    }

    /// Get agent by ID
    pub fn getAgent(self: *const AgentRegistry, agent_id: []const u8) ?*const AgentInfo {
        for (self.agents.items) |*agent| {
            if (std.mem.eql(u8, agent.id, agent_id)) {
                return agent;
            }
        }
        return null;
    }

    /// Get the default agent
    pub fn getDefaultAgent(self: *const AgentRegistry) ?*const AgentInfo {
        for (self.agents.items) |*agent| {
            if (agent.is_default) {
                return agent;
            }
        }
        if (self.agents.items.len > 0) {
            return &self.agents.items[0];
        }
        return null;
    }
};

fn resolveConfiguredPath(allocator: std.mem.Allocator, base_dir: []const u8, configured_path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(configured_path)) {
        return allocator.dupe(u8, configured_path);
    }
    return std.fs.path.join(allocator, &.{ base_dir, configured_path });
}

fn containsParentTraversal(path: []const u8) bool {
    var parts = std.mem.tokenizeAny(u8, path, "/\\");
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return true;
    }
    return false;
}

fn isPathWithinRoot(root: []const u8, candidate: []const u8) bool {
    if (std.mem.eql(u8, root, candidate)) return true;
    if (!std.mem.startsWith(u8, candidate, root)) return false;
    return candidate.len > root.len and std.fs.path.isSep(candidate[root.len]);
}

const required_persona_files = [_][]const u8{
    "SOUL.md",
    "AGENT.md",
    "IDENTITY.md",
};

const optional_persona_files = [_][]const u8{
    "USER.md",
    "agent.json",
};

fn parseCapability(str: []const u8) !AgentCapability {
    if (std.mem.eql(u8, str, "chat")) return .chat;
    if (std.mem.eql(u8, str, "code")) return .code;
    if (std.mem.eql(u8, str, "plan")) return .plan;
    if (std.mem.eql(u8, str, "research")) return .research;
    return error.UnknownCapability;
}

test "agent_registry: scan supports absolute agents_dir path" {
    const allocator = std.testing.allocator;
    const nonce = std.crypto.random.int(u64);
    const rel_root = try std.fmt.allocPrint(allocator, ".tmp-agent-registry-abs-{d}", .{nonce});
    defer allocator.free(rel_root);
    defer std.fs.cwd().deleteTree(rel_root) catch {};
    try std.fs.cwd().makePath(rel_root);

    const abs_root = try std.fs.cwd().realpathAlloc(allocator, rel_root);
    defer allocator.free(abs_root);
    const abs_agents_dir = try std.fs.path.join(allocator, &.{ abs_root, "agents" });
    defer allocator.free(abs_agents_dir);
    try std.fs.cwd().makePath(abs_agents_dir);

    const mother_dir = try std.fs.path.join(allocator, &.{ abs_agents_dir, "mother" });
    defer allocator.free(mother_dir);
    try std.fs.cwd().makePath(mother_dir);
    const mother_json_path = try std.fs.path.join(allocator, &.{ mother_dir, "agent.json" });
    defer allocator.free(mother_json_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = mother_json_path,
        .data =
        \\{
        \\  "name": "Mother",
        \\  "description": "Primary orchestrator",
        \\  "is_default": true,
        \\  "capabilities": ["chat","plan"]
        \\}
        ,
    });

    var registry = AgentRegistry.init(allocator, ".", abs_agents_dir, abs_root);
    defer registry.deinit();
    try registry.scan();
    try std.testing.expect(registry.listAgents().len == 1);
    const mother = registry.getAgent("mother");
    try std.testing.expect(mother != null);
    try std.testing.expect(mother.?.is_default);
    try std.testing.expectEqualStrings("Mother", mother.?.name);
}

test "agent_registry: createAgent seeds identity files from configured persona pack" {
    const allocator = std.testing.allocator;
    const nonce = std.crypto.random.int(u64);
    const rel_root = try std.fmt.allocPrint(allocator, ".tmp-agent-registry-template-ok-{d}", .{nonce});
    defer allocator.free(rel_root);
    defer std.fs.cwd().deleteTree(rel_root) catch {};
    try std.fs.cwd().makePath(rel_root);

    const assets_dir = try std.fs.path.join(allocator, &.{ rel_root, "templates" });
    defer allocator.free(assets_dir);
    const agents_dir = try std.fs.path.join(allocator, &.{ rel_root, "agents" });
    defer allocator.free(agents_dir);
    try std.fs.cwd().makePath(assets_dir);
    try std.fs.cwd().makePath(agents_dir);

    const persona_pack_dir = try std.fs.path.join(allocator, &.{ assets_dir, "persona-packs", "custom-pack" });
    defer allocator.free(persona_pack_dir);
    try std.fs.cwd().makePath(persona_pack_dir);
    inline for (required_persona_files) |filename| {
        const path = try std.fs.path.join(allocator, &.{ persona_pack_dir, filename });
        defer allocator.free(path);
        try std.fs.cwd().writeFile(.{
            .sub_path = path,
            .data = "# custom persona file\n",
        });
    }

    var registry = AgentRegistry.init(allocator, rel_root, "agents", "templates");
    defer registry.deinit();
    try registry.createAgent("alpha", "templates/persona-packs/custom-pack");

    const soul_path = try std.fs.path.join(allocator, &.{ agents_dir, "alpha", "SOUL.md" });
    defer allocator.free(soul_path);
    const soul = try std.fs.cwd().readFileAlloc(allocator, soul_path, 1024);
    defer allocator.free(soul);
    try std.testing.expectEqualStrings("# custom persona file\n", soul);
}

test "agent_registry: createAgent seeds identity files from absolute persona pack path" {
    const allocator = std.testing.allocator;
    const nonce = std.crypto.random.int(u64);
    const rel_root = try std.fmt.allocPrint(allocator, ".tmp-agent-registry-template-abs-{d}", .{nonce});
    defer allocator.free(rel_root);
    defer std.fs.cwd().deleteTree(rel_root) catch {};
    try std.fs.cwd().makePath(rel_root);

    const agents_dir = try std.fs.path.join(allocator, &.{ rel_root, "agents" });
    defer allocator.free(agents_dir);
    const assets_dir = try std.fs.path.join(allocator, &.{ rel_root, "templates" });
    defer allocator.free(assets_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(assets_dir);

    const abs_root = try std.fs.cwd().realpathAlloc(allocator, rel_root);
    defer allocator.free(abs_root);
    const abs_assets_dir = try std.fs.path.join(allocator, &.{ abs_root, "templates" });
    defer allocator.free(abs_assets_dir);
    const abs_agents_dir = try std.fs.path.join(allocator, &.{ abs_root, "agents" });
    defer allocator.free(abs_agents_dir);

    const persona_pack_dir = try std.fs.path.join(allocator, &.{ abs_assets_dir, "persona-packs", "custom-pack" });
    defer allocator.free(persona_pack_dir);
    try std.fs.cwd().makePath(persona_pack_dir);
    inline for (required_persona_files) |filename| {
        const path = try std.fs.path.join(allocator, &.{ persona_pack_dir, filename });
        defer allocator.free(path);
        try std.fs.cwd().writeFile(.{
            .sub_path = path,
            .data = "# absolute custom persona file\n",
        });
    }

    var registry = AgentRegistry.init(allocator, rel_root, abs_agents_dir, abs_assets_dir);
    defer registry.deinit();

    try registry.createAgent("alpha", persona_pack_dir);

    const soul_path = try std.fs.path.join(allocator, &.{ abs_agents_dir, "alpha", "SOUL.md" });
    defer allocator.free(soul_path);
    const soul = try std.fs.cwd().readFileAlloc(allocator, soul_path, 1024);
    defer allocator.free(soul);
    try std.testing.expectEqualStrings("# absolute custom persona file\n", soul);
}

test "agent_registry: createAgent rejects traversal persona pack path" {
    const allocator = std.testing.allocator;
    const nonce = std.crypto.random.int(u64);
    const rel_root = try std.fmt.allocPrint(allocator, ".tmp-agent-registry-template-traversal-{d}", .{nonce});
    defer allocator.free(rel_root);
    defer std.fs.cwd().deleteTree(rel_root) catch {};
    try std.fs.cwd().makePath(rel_root);

    const agents_dir = try std.fs.path.join(allocator, &.{ rel_root, "agents" });
    defer allocator.free(agents_dir);
    const assets_dir = try std.fs.path.join(allocator, &.{ rel_root, "templates" });
    defer allocator.free(assets_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(assets_dir);

    var registry = AgentRegistry.init(allocator, rel_root, "agents", "templates");
    defer registry.deinit();

    try std.testing.expectError(error.InvalidTemplatePath, registry.createAgent("beta", "templates/../../etc/passwd"));
}

test "agent_registry: createAgent rejects persona pack missing required identity files" {
    const allocator = std.testing.allocator;
    const nonce = std.crypto.random.int(u64);
    const rel_root = try std.fmt.allocPrint(allocator, ".tmp-agent-registry-persona-invalid-{d}", .{nonce});
    defer allocator.free(rel_root);
    defer std.fs.cwd().deleteTree(rel_root) catch {};
    try std.fs.cwd().makePath(rel_root);

    const agents_dir = try std.fs.path.join(allocator, &.{ rel_root, "agents" });
    defer allocator.free(agents_dir);
    const assets_dir = try std.fs.path.join(allocator, &.{ rel_root, "templates" });
    defer allocator.free(assets_dir);
    const persona_pack_dir = try std.fs.path.join(allocator, &.{ assets_dir, "persona-packs", "broken-pack" });
    defer allocator.free(persona_pack_dir);
    try std.fs.cwd().makePath(persona_pack_dir);

    var registry = AgentRegistry.init(allocator, rel_root, "agents", "templates");
    defer registry.deinit();

    try std.testing.expectError(error.InvalidTemplatePath, registry.createAgent("beta", "templates/persona-packs/broken-pack"));
}
