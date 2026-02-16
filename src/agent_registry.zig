const std = @import("std");
const identity = @import("identity.zig");

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
    needs_hatching: bool,

    pub fn deinit(self: *AgentInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.description);
        self.capabilities.deinit(allocator);
    }
};

pub const AgentRegistry = struct {
    allocator: std.mem.Allocator,
    agents: std.ArrayListUnmanaged(AgentInfo),
    base_dir: []const u8,
    default_agent_id: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, base_dir: []const u8) AgentRegistry {
        return .{
            .allocator = allocator,
            .agents = .{},
            .base_dir = base_dir,
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
        const agents_dir_path = try std.fs.path.join(self.allocator, &.{ self.base_dir, "agents" });
        defer self.allocator.free(agents_dir_path);

        var agents_dir = std.fs.cwd().openDir(agents_dir_path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) {
                // No agents directory - we're in first-boot state
                // Don't create anything yet - wait for client to trigger first boot
                try self.loadDefaultAgent();
                return;
            }
            return err;
        };
        defer agents_dir.close();

        var has_default = false;
        var it = agents_dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .directory) continue;

            const agent = try self.loadAgent(entry.name, agents_dir_path);
            if (agent.is_default) {
                has_default = true;
            }
            try self.agents.append(self.allocator, agent);
        }

        // If no agent marked as default, mark first one
        if (!has_default and self.agents.items.len > 0) {
            self.agents.items[0].is_default = true;
        }

        // If no agents found, create default
        if (self.agents.items.len == 0) {
            try self.loadDefaultAgent();
        }
    }

    /// Check if server is in first-boot state (no real agents exist yet)
    pub fn isFirstBoot(self: *const AgentRegistry) bool {
        // First boot if only the in-memory default agent exists
        // Distinguish synthetic placeholder from real agent by checking if agents/ has any subdirectories
        const len_ok = self.agents.items.len == 1;
        const id_ok = len_ok and std.mem.eql(u8, self.agents.items[0].id, "default");
        const identity_ok = len_ok and !self.agents.items[0].identity_loaded;
        const needs_hatching_ok = len_ok and !self.agents.items[0].needs_hatching;

        // The key check: synthetic placeholder has no agent subdirectories in agents/
        // Real agents have at least one subdirectory (even if hatched with no identity files yet)
        const agents_dir_path = std.fs.path.join(self.allocator, &.{ self.base_dir, "agents" }) catch return false;
        defer self.allocator.free(agents_dir_path);

        var has_agent_subdirs = false;
        if (std.fs.cwd().openDir(agents_dir_path, .{ .iterate = true })) |*agents_dir| {
            defer agents_dir.close(); // P1 fix: close the handle
            var it = agents_dir.iterate();
            while (it.next() catch null) |entry| {
                if (entry.kind == .directory) {
                    has_agent_subdirs = true;
                    break;
                }
            }
        } else |_| {
            // Directory doesn't exist = definitely first boot
            has_agent_subdirs = false;
        }

        // First boot = only synthetic placeholder in memory, no agent subdirectories
        return len_ok and id_ok and identity_ok and needs_hatching_ok and !has_agent_subdirs;
    }

    /// Initialize first agent on first boot
    pub fn initializeFirstAgent(self: *AgentRegistry, agent_id: []const u8, template_path: ?[]const u8) !void {
        // Create the agents directory
        const agents_dir_path = try std.fs.path.join(self.allocator, &.{ self.base_dir, "agents" });
        defer self.allocator.free(agents_dir_path);

        try std.fs.cwd().makePath(agents_dir_path);

        // Create the first agent with HATCH.md
        try self.createAgent(agent_id, template_path);

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

        // Check if identity files exist
        const identity_loaded = self.checkIdentityFiles(agent_path);
        
        // Check if HATCH.md exists (needs hatching)
        const needs_hatching = self.checkHatchFile(agent_path);

        return .{
            .id = try self.allocator.dupe(u8, agent_id),
            .name = name,
            .description = description,
            .is_default = is_default,
            .capabilities = capabilities,
            .identity_loaded = identity_loaded,
            .needs_hatching = needs_hatching,
        };
    }

    fn inferAgentFromIdentity(self: *AgentRegistry, agent_id: []const u8, agent_path: []const u8) !AgentInfo {
        // Try to extract name from SOUL.md or IDENTITY.md
        const name = try self.extractNameFromIdentity(agent_path) orelse try self.allocator.dupe(u8, agent_id);

        // Check which identity files exist
        const identity_loaded = self.checkIdentityFiles(agent_path);
        
        // Check if HATCH.md exists
        const needs_hatching = self.checkHatchFile(agent_path);

        // Infer capabilities from agent_id
        var capabilities = std.ArrayListUnmanaged(AgentCapability){};
        try capabilities.append(self.allocator, .chat);

        if (std.mem.containsAtLeast(u8, agent_id, 1, "code") or
            std.mem.containsAtLeast(u8, agent_id, 1, "dev") or
            std.mem.containsAtLeast(u8, agent_id, 1, "prog")) {
            try capabilities.append(self.allocator, .code);
        }

        if (std.mem.containsAtLeast(u8, agent_id, 1, "plan") or
            std.mem.containsAtLeast(u8, agent_id, 1, "pm") or
            std.mem.containsAtLeast(u8, agent_id, 1, "manage")) {
            try capabilities.append(self.allocator, .plan);
        }

        if (std.mem.containsAtLeast(u8, agent_id, 1, "research") or
            std.mem.containsAtLeast(u8, agent_id, 1, "search")) {
            try capabilities.append(self.allocator, .research);
        }

        return .{
            .id = try self.allocator.dupe(u8, agent_id),
            .name = name,
            .description = try self.allocator.dupe(u8, ""),
            .is_default = false,
            .capabilities = capabilities,
            .identity_loaded = identity_loaded,
            .needs_hatching = needs_hatching,
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

    fn checkHatchFile(self: *AgentRegistry, agent_path: []const u8) bool {
        const hatch_path = std.fs.path.join(self.allocator, &.{ agent_path, "HATCH.md" }) catch return false;
        defer self.allocator.free(hatch_path);

        std.fs.cwd().access(hatch_path, .{}) catch return false;
        return true;
    }

    /// Read HATCH.md content if it exists
    pub fn readHatchFile(self: *AgentRegistry, agent_id: []const u8) !?[]u8 {
        const agent_path = try std.fs.path.join(self.allocator, &.{ self.base_dir, "agents", agent_id });
        defer self.allocator.free(agent_path);

        const hatch_path = try std.fs.path.join(self.allocator, &.{ agent_path, "HATCH.md" });
        defer self.allocator.free(hatch_path);

        const content = std.fs.cwd().readFileAlloc(self.allocator, hatch_path, 64 * 1024) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        return content;
    }

    /// Create a new agent with HATCH.md
    pub fn createAgent(self: *AgentRegistry, agent_id: []const u8, template_path: ?[]const u8) !void {
        // Create agent directory
        const agent_path = try std.fs.path.join(self.allocator, &.{ self.base_dir, "agents", agent_id });
        defer self.allocator.free(agent_path);

        try std.fs.cwd().makePath(agent_path);

        // Determine template source
        const template_source = if (template_path) |tp|
            try std.fs.cwd().readFileAlloc(self.allocator, tp, 64 * 1024)
        else
            try self.loadDefaultHatchTemplate();
        defer self.allocator.free(template_source);

        // Write HATCH.md
        const hatch_path = try std.fs.path.join(self.allocator, &.{ agent_path, "HATCH.md" });
        defer self.allocator.free(hatch_path);

        try std.fs.cwd().writeFile(.{
            .sub_path = hatch_path,
            .data = template_source,
        });

        // Reload agents to include the new one
        try self.scan();
    }

    /// Complete hatching - delete HATCH.md and update agent
    pub fn completeHatching(self: *AgentRegistry, agent_id: []const u8) !void {
        const agent_path = try std.fs.path.join(self.allocator, &.{ self.base_dir, "agents", agent_id });
        defer self.allocator.free(agent_path);

        // Delete HATCH.md
        const hatch_path = try std.fs.path.join(self.allocator, &.{ agent_path, "HATCH.md" });
        defer self.allocator.free(hatch_path);

        std.fs.cwd().deleteFile(hatch_path) catch |err| {
            if (err != error.FileNotFound) return err;
        };

        // Reload to update agent state
        try self.scan();
    }

    fn loadDefaultHatchTemplate(self: *AgentRegistry) ![]u8 {
        // Try to load from file first
        const template_path = try std.fs.path.join(self.allocator, &.{ self.base_dir, "agents", "HATCH.template.md" });
        defer self.allocator.free(template_path);

        return std.fs.cwd().readFileAlloc(self.allocator, template_path, 64 * 1024) catch {
            // Fallback to embedded minimal template
            return self.allocator.dupe(u8,
                "# HATCH.md — New Agent Initialization\n" ++
                "\n" ++
                "Welcome, newborn agent. You are hatching in ZiggySpiderweb (ZSS).\n" ++
                "\n" ++
                "## Your Task\n" ++
                "Create your identity by writing SOUL.md, then respond with:\n" ++
                "{\"type\":\"agent.hatch\",\"agent_id\":\"YourName\"}\n" ++
                "\n" ++
                "The server will confirm with agent.hatched and delete this HATCH.md.\n" ++
                "You won't need it again.\n"
            );
        };
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

    fn loadDefaultAgent(self: *AgentRegistry) !void {
        var capabilities = std.ArrayListUnmanaged(AgentCapability){};
        try capabilities.append(self.allocator, .chat);

        const agent = AgentInfo{
            .id = try self.allocator.dupe(u8, "default"),
            .name = try self.allocator.dupe(u8, "Assistant"),
            .description = try self.allocator.dupe(u8, "General purpose AI assistant"),
            .is_default = true,
            .capabilities = capabilities,
            .identity_loaded = false,
            .needs_hatching = false,
        };

        try self.agents.append(self.allocator, agent);
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

fn parseCapability(str: []const u8) !AgentCapability {
    if (std.mem.eql(u8, str, "chat")) return .chat;
    if (std.mem.eql(u8, str, "code")) return .code;
    if (std.mem.eql(u8, str, "plan")) return .plan;
    if (std.mem.eql(u8, str, "research")) return .research;
    return error.UnknownCapability;
}
