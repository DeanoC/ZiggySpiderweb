const std = @import("std");

const max_policy_bytes: usize = 1024 * 1024;

pub const ResourcePolicy = struct {
    fs: bool = true,
    camera: bool = false,
    screen: bool = false,
    user: bool = false,
};

pub const NodePolicy = struct {
    id: []u8,
    resources: ResourcePolicy = .{},
    terminals: std.ArrayListUnmanaged([]u8) = .{},

    fn deinit(self: *NodePolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.terminals.items) |terminal| allocator.free(terminal);
        self.terminals.deinit(allocator);
        self.* = undefined;
    }
};

pub const ProjectLink = struct {
    name: []u8,
    node_id: []u8,
    resource: []u8,

    fn deinit(self: *ProjectLink, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.node_id);
        allocator.free(self.resource);
        self.* = undefined;
    }
};

pub const Policy = struct {
    show_debug: bool = false,
    project_id: []u8,
    nodes: std.ArrayListUnmanaged(NodePolicy) = .{},
    visible_agents: std.ArrayListUnmanaged([]u8) = .{},
    project_links: std.ArrayListUnmanaged(ProjectLink) = .{},

    pub fn deinit(self: *Policy, allocator: std.mem.Allocator) void {
        allocator.free(self.project_id);
        for (self.nodes.items) |*node| node.deinit(allocator);
        self.nodes.deinit(allocator);
        for (self.visible_agents.items) |agent| allocator.free(agent);
        self.visible_agents.deinit(allocator);
        for (self.project_links.items) |*link| link.deinit(allocator);
        self.project_links.deinit(allocator);
        self.* = undefined;
    }
};

pub const LoadOptions = struct {
    agent_id: []const u8,
    project_id: ?[]const u8 = null,
    agents_dir: []const u8 = "agents",
    projects_dir: []const u8 = "projects",
};

pub fn load(allocator: std.mem.Allocator, options: LoadOptions) !Policy {
    var policy = try initDefaults(allocator, options);
    errdefer policy.deinit(allocator);

    const agent_policy_path = try std.fs.path.join(allocator, &.{ options.agents_dir, options.agent_id, "agent_policy.json" });
    defer allocator.free(agent_policy_path);
    try applyPolicyFile(allocator, &policy, options.agent_id, agent_policy_path);

    const project_policy_path = try std.fs.path.join(allocator, &.{ options.projects_dir, policy.project_id, "project_policy.json" });
    defer allocator.free(project_policy_path);
    try applyPolicyFile(allocator, &policy, options.agent_id, project_policy_path);

    try ensureDefaults(allocator, &policy, options.agent_id);
    return policy;
}

fn initDefaults(allocator: std.mem.Allocator, options: LoadOptions) !Policy {
    const project_seed = options.project_id orelse "system";
    var policy = Policy{
        .show_debug = std.mem.eql(u8, options.agent_id, "mother"),
        .project_id = try allocator.dupe(u8, project_seed),
    };
    errdefer policy.deinit(allocator);

    try policy.visible_agents.append(allocator, try allocator.dupe(u8, options.agent_id));
    try appendDefaultLocalNode(allocator, &policy.nodes);
    try appendDefaultProjectLinks(allocator, &policy);
    return policy;
}

fn appendDefaultLocalNode(
    allocator: std.mem.Allocator,
    nodes: *std.ArrayListUnmanaged(NodePolicy),
) !void {
    var node = NodePolicy{
        .id = try allocator.dupe(u8, "local"),
        .resources = .{
            .fs = true,
            .camera = false,
            .screen = false,
            .user = false,
        },
    };
    errdefer node.deinit(allocator);
    try node.terminals.append(allocator, try allocator.dupe(u8, "1"));
    try nodes.append(allocator, node);
}

fn appendDefaultProjectLinks(allocator: std.mem.Allocator, policy: *Policy) !void {
    for (policy.nodes.items) |node| {
        if (!node.resources.fs) continue;
        const link_name = try std.fmt.allocPrint(allocator, "{s}::fs", .{node.id});
        errdefer allocator.free(link_name);
        var link = ProjectLink{
            .name = link_name,
            .node_id = try allocator.dupe(u8, node.id),
            .resource = try allocator.dupe(u8, "fs"),
        };
        errdefer link.deinit(allocator);
        try policy.project_links.append(allocator, link);
    }
}

fn ensureDefaults(
    allocator: std.mem.Allocator,
    policy: *Policy,
    agent_id: []const u8,
) !void {
    if (policy.nodes.items.len == 0) {
        try appendDefaultLocalNode(allocator, &policy.nodes);
    }

    if (!sliceListContains(policy.visible_agents.items, agent_id)) {
        try policy.visible_agents.append(allocator, try allocator.dupe(u8, agent_id));
    }

    if (policy.visible_agents.items.len == 0) {
        try policy.visible_agents.append(allocator, try allocator.dupe(u8, agent_id));
    }

    if (policy.project_links.items.len == 0) {
        try appendDefaultProjectLinks(allocator, policy);
    }

    if (policy.project_links.items.len == 0 and policy.nodes.items.len > 0) {
        const link_name = try std.fmt.allocPrint(allocator, "{s}::fs", .{policy.nodes.items[0].id});
        errdefer allocator.free(link_name);
        var link = ProjectLink{
            .name = link_name,
            .node_id = try allocator.dupe(u8, policy.nodes.items[0].id),
            .resource = try allocator.dupe(u8, "fs"),
        };
        errdefer link.deinit(allocator);
        try policy.project_links.append(allocator, link);
    }
}

fn applyPolicyFile(
    allocator: std.mem.Allocator,
    policy: *Policy,
    agent_id: []const u8,
    path: []const u8,
) !void {
    const raw = std.fs.cwd().readFileAlloc(allocator, path, max_policy_bytes) catch |err| switch (err) {
        error.FileNotFound => return,
        else => {
            std.log.warn("world policy load skipped for {s}: {s}", .{ path, @errorName(err) });
            return;
        },
    };
    defer allocator.free(raw);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch |err| {
        std.log.warn("world policy parse skipped for {s}: {s}", .{ path, @errorName(err) });
        return;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        std.log.warn("world policy parse skipped for {s}: root is not object", .{path});
        return;
    }
    const obj = parsed.value.object;

    if (obj.get("show_debug")) |raw_value| {
        if (raw_value == .bool) policy.show_debug = raw_value.bool;
    }

    if (obj.get("project_id")) |raw_value| {
        if (raw_value == .string and raw_value.string.len > 0) {
            allocator.free(policy.project_id);
            policy.project_id = try allocator.dupe(u8, raw_value.string);
        }
    }

    if (obj.get("nodes")) |raw_nodes| {
        try replaceNodesFromValue(allocator, &policy.nodes, raw_nodes);
    }

    if (obj.get("visible_agents")) |raw_agents| {
        try replaceVisibleAgentsFromValue(allocator, &policy.visible_agents, raw_agents);
    }

    if (obj.get("project_links")) |raw_links| {
        try replaceProjectLinksFromValue(allocator, &policy.project_links, raw_links);
    }

    if (!sliceListContains(policy.visible_agents.items, agent_id)) {
        try policy.visible_agents.append(allocator, try allocator.dupe(u8, agent_id));
    }
}

fn replaceNodesFromValue(
    allocator: std.mem.Allocator,
    nodes: *std.ArrayListUnmanaged(NodePolicy),
    value: std.json.Value,
) !void {
    if (value != .array) return;

    for (nodes.items) |*node| node.deinit(allocator);
    nodes.clearRetainingCapacity();

    for (value.array.items) |item| {
        if (item != .object) continue;
        const obj = item.object;
        const raw_id = obj.get("id") orelse continue;
        if (raw_id != .string or raw_id.string.len == 0) continue;

        var node = NodePolicy{
            .id = try allocator.dupe(u8, raw_id.string),
            .resources = .{},
        };
        errdefer node.deinit(allocator);

        if (obj.get("resources")) |raw_resources| {
            if (raw_resources == .object) {
                if (raw_resources.object.get("fs")) |raw_field| {
                    if (raw_field == .bool) node.resources.fs = raw_field.bool;
                }
                if (raw_resources.object.get("camera")) |raw_field| {
                    if (raw_field == .bool) node.resources.camera = raw_field.bool;
                }
                if (raw_resources.object.get("screen")) |raw_field| {
                    if (raw_field == .bool) node.resources.screen = raw_field.bool;
                }
                if (raw_resources.object.get("user")) |raw_field| {
                    if (raw_field == .bool) node.resources.user = raw_field.bool;
                }
            }
        }

        if (obj.get("terminals")) |raw_terminals| {
            if (raw_terminals == .array) {
                for (raw_terminals.array.items) |raw_terminal| {
                    if (raw_terminal != .string or raw_terminal.string.len == 0) continue;
                    try node.terminals.append(allocator, try allocator.dupe(u8, raw_terminal.string));
                }
            }
        }

        if (node.resources.fs and node.terminals.items.len == 0) {
            try node.terminals.append(allocator, try allocator.dupe(u8, "1"));
        }
        try nodes.append(allocator, node);
    }
}

fn replaceVisibleAgentsFromValue(
    allocator: std.mem.Allocator,
    visible_agents: *std.ArrayListUnmanaged([]u8),
    value: std.json.Value,
) !void {
    if (value != .array) return;

    for (visible_agents.items) |agent| allocator.free(agent);
    visible_agents.clearRetainingCapacity();

    for (value.array.items) |item| {
        if (item != .string or item.string.len == 0) continue;
        if (sliceListContains(visible_agents.items, item.string)) continue;
        try visible_agents.append(allocator, try allocator.dupe(u8, item.string));
    }
}

fn replaceProjectLinksFromValue(
    allocator: std.mem.Allocator,
    project_links: *std.ArrayListUnmanaged(ProjectLink),
    value: std.json.Value,
) !void {
    if (value != .array) return;

    for (project_links.items) |*link| link.deinit(allocator);
    project_links.clearRetainingCapacity();

    for (value.array.items) |item| {
        if (item != .object) continue;
        const obj = item.object;
        const raw_node_id = obj.get("node_id") orelse continue;
        if (raw_node_id != .string or raw_node_id.string.len == 0) continue;
        const resource = if (obj.get("resource")) |raw_resource|
            if (raw_resource == .string and raw_resource.string.len > 0) raw_resource.string else "fs"
        else
            "fs";
        const name = if (obj.get("name")) |raw_name|
            if (raw_name == .string and raw_name.string.len > 0) raw_name.string else null
        else
            null;

        const resolved_name = if (name) |provided|
            try allocator.dupe(u8, provided)
        else
            try std.fmt.allocPrint(allocator, "{s}::{s}", .{ raw_node_id.string, resource });
        errdefer allocator.free(resolved_name);

        var link = ProjectLink{
            .name = resolved_name,
            .node_id = try allocator.dupe(u8, raw_node_id.string),
            .resource = try allocator.dupe(u8, resource),
        };
        errdefer link.deinit(allocator);
        try project_links.append(allocator, link);
    }
}

fn sliceListContains(items: []const []u8, value: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, value)) return true;
    }
    return false;
}

test "world_policy: defaults provide a usable world view" {
    const allocator = std.testing.allocator;
    var policy = try load(
        allocator,
        .{
            .agent_id = "mother",
            .project_id = "system",
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
        },
    );
    defer policy.deinit(allocator);

    try std.testing.expect(policy.show_debug);
    try std.testing.expectEqualStrings("system", policy.project_id);
    try std.testing.expect(policy.nodes.items.len > 0);
    try std.testing.expect(policy.project_links.items.len > 0);
    try std.testing.expect(policy.visible_agents.items.len > 0);
}
