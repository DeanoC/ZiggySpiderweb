const std = @import("std");
const venom_package = @import("spiderweb_node").venom_package;

pub const BuiltinPackageSpec = struct {
    venom_id: []const u8,
    kind: []const u8,
    version: []const u8 = "1",
    default_provider_scope: []const u8,
    default_target_path: ?[]const u8 = null,
    categories_json: []const u8 = "[]",
    hosts_json: []const u8 = "[]",
    projection_modes_json: []const u8 = "[]",
    requirements_json: []const u8 = "{}",
    capabilities_json: []const u8 = "{}",
    ops_json: []const u8 = "{}",
    runtime_json: []const u8 = "{}",
    permissions_json: []const u8 = "{}",
    schema_json: []const u8 = "{}",
    help_md: ?[]const u8 = null,
};

const builtin_packages = [_]BuiltinPackageSpec{
    .{ .venom_id = "library", .kind = "library", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/library", .categories_json = "[\"docs\",\"discovery\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\"]", .help_md = "Workspace library and topic discovery." },
    .{ .venom_id = "venom_packages", .kind = "registry", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/venom_packages", .categories_json = "[\"venoms\",\"registry\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "Registry of available Venom packages and install/remove operations." },
    .{ .venom_id = "chat", .kind = "chat", .default_provider_scope = "session_dynamic", .default_target_path = "/nodes/local/venoms/chat", .categories_json = "[\"chat\",\"session\"]", .hosts_json = "[\"spiderweb\",\"node\"]", .projection_modes_json = "[\"session_dynamic\",\"host_local\",\"node_export\"]", .help_md = "Inbound and outbound chat surface for attached users and agents." },
    .{ .venom_id = "jobs", .kind = "jobs", .default_provider_scope = "session_dynamic", .default_target_path = "/nodes/local/venoms/jobs", .categories_json = "[\"jobs\",\"queue\"]", .hosts_json = "[\"spiderweb\",\"node\"]", .projection_modes_json = "[\"session_dynamic\",\"host_local\",\"node_export\"]", .help_md = "Durable job queue and result surface." },
    .{ .venom_id = "thoughts", .kind = "thoughts", .default_provider_scope = "session_dynamic", .default_target_path = "/nodes/local/venoms/thoughts", .categories_json = "[\"telemetry\",\"thoughts\"]", .hosts_json = "[\"spiderweb\",\"worker\"]", .projection_modes_json = "[\"session_dynamic\",\"worker_private\"]", .help_md = "Thought telemetry and observational loop traces." },
    .{ .venom_id = "events", .kind = "events", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/events", .categories_json = "[\"events\",\"coordination\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "Filesystem-native waits and event delivery." },
    .{ .venom_id = "home", .kind = "home", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/home", .categories_json = "[\"agent\",\"storage\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "Provision durable per-agent workspace homes." },
    .{ .venom_id = "workers", .kind = "workers", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/workers", .categories_json = "[\"worker\",\"registration\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "Register and maintain worker-private venom instances." },
    .{ .venom_id = "web_search", .kind = "web_search", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/web_search", .categories_json = "[\"search\",\"web\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "External web search service." },
    .{ .venom_id = "search_code", .kind = "search_code", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/search_code", .categories_json = "[\"search\",\"code\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "Workspace code search service." },
    .{ .venom_id = "fs", .kind = "fs", .default_provider_scope = "node_export", .categories_json = "[\"filesystem\",\"node\"]", .hosts_json = "[\"node\"]", .projection_modes_json = "[\"node_export\"]", .runtime_json = "{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}", .schema_json = "{\"model\":\"namespace-mount\"}", .help_md = "Filesystem export surfaced by a Spiderweb node." },
    .{ .venom_id = "terminal", .kind = "terminal", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/terminal", .categories_json = "[\"terminal\",\"exec\"]", .hosts_json = "[\"spiderweb\",\"node\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\",\"node_export\"]", .help_md = "Terminal session and command execution service." },
    .{ .venom_id = "mounts", .kind = "mounts", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/mounts", .categories_json = "[\"workspace\",\"mounts\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "Workspace mounts and binds management." },
    .{ .venom_id = "agents", .kind = "agents", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/agents", .categories_json = "[\"agent\",\"provisioning\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .help_md = "Agent registry and provisioning service." },
    .{ .venom_id = "workspaces", .kind = "workspaces", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/workspaces", .categories_json = "[\"workspace\",\"control\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\"]", .help_md = "Workspace control-plane management service." },
    .{ .venom_id = "git", .kind = "git", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/git", .categories_json = "[\"developer\",\"scm\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .requirements_json = "{\"host_capabilities\":[\"local_fs_export\"]}", .help_md = "Git checkout and diff operations." },
    .{ .venom_id = "github_pr", .kind = "github_pr", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/github_pr", .categories_json = "[\"developer\",\"provider\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .requirements_json = "{\"host_capabilities\":[\"local_fs_export\"]}", .help_md = "GitHub PR sync and review publication." },
    .{ .venom_id = "missions", .kind = "missions", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/missions", .categories_json = "[\"workflow\",\"missions\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .requirements_json = "{\"host_capabilities\":[\"mission_store\"]}", .help_md = "Persistent mission lifecycle substrate." },
    .{ .venom_id = "pr_review", .kind = "pr_review", .default_provider_scope = "host_local", .default_target_path = "/nodes/local/venoms/pr_review", .categories_json = "[\"workflow\",\"review\"]", .hosts_json = "[\"spiderweb\"]", .projection_modes_json = "[\"host_local\",\"workspace_service\"]", .requirements_json = "{\"venoms\":[\"missions\",\"git\",\"github_pr\",\"terminal\"],\"host_capabilities\":[\"mission_store\",\"local_fs_export\"]}", .help_md = "PR review workflow veneer over missions." },
    .{ .venom_id = "memory", .kind = "memory", .default_provider_scope = "worker_private", .categories_json = "[\"memory\",\"agent_private\"]", .hosts_json = "[\"worker\"]", .projection_modes_json = "[\"worker_private\"]", .capabilities_json = "{\"invoke\":true,\"operations\":[\"memory_create\",\"memory_load\",\"memory_versions\",\"memory_mutate\",\"memory_evict\",\"memory_search\"],\"discoverable\":true,\"worker_owned\":true}", .ops_json = "{\"model\":\"filesystem_loopback\",\"invoke\":\"control/invoke.json\",\"transport\":\"filesystem\",\"paths\":{\"create\":\"control/create.json\",\"load\":\"control/load.json\",\"versions\":\"control/versions.json\",\"mutate\":\"control/mutate.json\",\"evict\":\"control/evict.json\",\"search\":\"control/search.json\"},\"operations\":{\"create\":\"create\",\"load\":\"load\",\"versions\":\"versions\",\"mutate\":\"mutate\",\"evict\":\"evict\",\"search\":\"search\"}}", .runtime_json = "{\"type\":\"external_worker\",\"transport\":\"filesystem_loopback\",\"component\":\"spider_monkey\"}", .permissions_json = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"worker\"}", .schema_json = "{\"model\":\"worker-loopback-memory-v1\"}", .help_md = "Worker-private memory service." },
    .{ .venom_id = "sub_brains", .kind = "sub_brains", .default_provider_scope = "worker_private", .categories_json = "[\"agent_private\",\"sub_brains\"]", .hosts_json = "[\"worker\"]", .projection_modes_json = "[\"worker_private\"]", .capabilities_json = "{\"invoke\":true,\"operations\":[\"sub_brains_list\",\"sub_brains_upsert\",\"sub_brains_delete\"],\"discoverable\":true,\"worker_owned\":true}", .ops_json = "{\"model\":\"filesystem_loopback\",\"invoke\":\"control/invoke.json\",\"transport\":\"filesystem\",\"paths\":{\"list\":\"control/list.json\",\"upsert\":\"control/upsert.json\",\"delete\":\"control/delete.json\"},\"operations\":{\"list\":\"list\",\"upsert\":\"upsert\",\"delete\":\"delete\"}}", .runtime_json = "{\"type\":\"external_worker\",\"transport\":\"filesystem_loopback\",\"component\":\"spider_monkey\"}", .permissions_json = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"worker\"}", .schema_json = "{\"model\":\"worker-loopback-sub-brains-v1\"}", .help_md = "Worker-private sub-brain service." },
};

pub fn allBuiltinPackages() []const BuiltinPackageSpec {
    return builtin_packages[0..];
}

pub fn findBuiltinPackage(venom_id: []const u8) ?BuiltinPackageSpec {
    for (builtin_packages) |spec| {
        if (std.mem.eql(u8, spec.venom_id, venom_id)) return spec;
    }
    return null;
}

pub fn resolveBuiltinTargetPath(venom_id: []const u8, provider_scope: []const u8) ?[]const u8 {
    const spec = findBuiltinPackage(venom_id) orelse return null;
    if (!std.mem.eql(u8, spec.default_provider_scope, provider_scope)) return null;
    return spec.default_target_path;
}

pub fn buildPackagesJson(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.append(allocator, '[');
    for (builtin_packages, 0..) |spec, idx| {
        if (idx != 0) try out.append(allocator, ',');
        try appendPackageJson(allocator, &out, spec);
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

pub fn buildCombinedPackagesJson(
    allocator: std.mem.Allocator,
    installed_packages: []const venom_package.VenomPackage,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.append(allocator, '[');
    var first = true;
    for (builtin_packages) |spec| {
        if (!first) try out.append(allocator, ',');
        first = false;
        try appendPackageJson(allocator, &out, spec);
    }
    for (installed_packages) |package| {
        if (!first) try out.append(allocator, ',');
        first = false;
        try venom_package.appendPackageJson(allocator, &out, package);
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

pub fn renderPackageMetadataJson(allocator: std.mem.Allocator, spec: BuiltinPackageSpec) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    try appendPackageJson(allocator, &out, spec);
    return out.toOwnedSlice(allocator);
}

pub fn cloneBuiltinPackage(
    allocator: std.mem.Allocator,
    venom_id: []const u8,
) !?venom_package.VenomPackage {
    const spec = findBuiltinPackage(venom_id) orelse return null;
    return .{
        .venom_id = try allocator.dupe(u8, spec.venom_id),
        .kind = try allocator.dupe(u8, spec.kind),
        .version = try allocator.dupe(u8, spec.version),
        .categories_json = try allocator.dupe(u8, spec.categories_json),
        .hosts_json = try allocator.dupe(u8, spec.hosts_json),
        .projection_modes_json = try allocator.dupe(u8, spec.projection_modes_json),
        .requirements_json = try allocator.dupe(u8, spec.requirements_json),
        .capabilities_json = try allocator.dupe(u8, spec.capabilities_json),
        .ops_json = try allocator.dupe(u8, spec.ops_json),
        .runtime_json = try allocator.dupe(u8, spec.runtime_json),
        .permissions_json = try allocator.dupe(u8, spec.permissions_json),
        .schema_json = try allocator.dupe(u8, spec.schema_json),
        .help_md = if (spec.help_md) |help| try allocator.dupe(u8, help) else null,
    };
}

fn appendPackageJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    spec: BuiltinPackageSpec,
) !void {
    const escaped_venom_id = try jsonEscape(allocator, spec.venom_id);
    defer allocator.free(escaped_venom_id);
    const escaped_kind = try jsonEscape(allocator, spec.kind);
    defer allocator.free(escaped_kind);
    const escaped_version = try jsonEscape(allocator, spec.version);
    defer allocator.free(escaped_version);
    const escaped_provider_scope = try jsonEscape(allocator, spec.default_provider_scope);
    defer allocator.free(escaped_provider_scope);
    const target_path_json = if (spec.default_target_path) |value| blk: {
        const escaped = try jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(target_path_json);

    try out.writer(allocator).print(
        "{{\"venom_id\":\"{s}\",\"kind\":\"{s}\",\"version\":\"{s}\",\"categories\":{s},\"hosts\":{s},\"projection_modes\":{s},\"requirements\":{s},\"capabilities\":{s},\"ops\":{s},\"runtime\":{s},\"permissions\":{s},\"schema\":{s},\"default_provider_scope\":\"{s}\",\"default_target_path\":{s}",
        .{
            escaped_venom_id,
            escaped_kind,
            escaped_version,
            spec.categories_json,
            spec.hosts_json,
            spec.projection_modes_json,
            spec.requirements_json,
            spec.capabilities_json,
            spec.ops_json,
            spec.runtime_json,
            spec.permissions_json,
            spec.schema_json,
            escaped_provider_scope,
            target_path_json,
        },
    );
    if (spec.help_md) |help| {
        const escaped_help = try jsonEscape(allocator, help);
        defer allocator.free(escaped_help);
        try out.writer(allocator).print(",\"help_md\":\"{s}\"}}", .{escaped_help});
        return;
    }
    try out.appendSlice(allocator, "}");
}

fn jsonEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    for (value) |ch| switch (ch) {
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '"' => try out.appendSlice(allocator, "\\\""),
        '\n' => try out.appendSlice(allocator, "\\n"),
        '\r' => try out.appendSlice(allocator, "\\r"),
        '\t' => try out.appendSlice(allocator, "\\t"),
        else => if (ch < 0x20) {
            try out.writer(allocator).print("\\u00{x:0>2}", .{ch});
        } else {
            try out.append(allocator, ch);
        },
    };
    return out.toOwnedSlice(allocator);
}

test "venom_packages: builtins render through shared package parser" {
    const allocator = std.testing.allocator;
    const raw = try buildPackagesJson(allocator);
    defer allocator.free(raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();

    var packages = std.ArrayListUnmanaged(venom_package.VenomPackage){};
    defer venom_package.deinitPackages(allocator, &packages);
    try venom_package.replacePackagesFromJsonValue(allocator, &packages, parsed.value);

    try std.testing.expect(packages.items.len >= 5);
    try std.testing.expect(findBuiltinPackage("workers") != null);
    try std.testing.expect(std.mem.indexOf(u8, raw, "\"venom_id\":\"memory\"") != null);
}
