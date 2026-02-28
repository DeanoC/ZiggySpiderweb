const std = @import("std");
const fs_node_ops = @import("fs_node_ops.zig");

pub const NodeLabelArg = struct {
    key: []const u8,
    value: []const u8,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    enable_fs_service: bool = true,
    fs_export_count: usize = 0,
    fs_rw_export_count: usize = 0,
    terminal_ids: std.ArrayListUnmanaged([]u8) = .{},
    labels: std.ArrayListUnmanaged(NodeLabel) = .{},

    pub const InitOptions = struct {
        enable_fs_service: bool = true,
        export_specs: []const fs_node_ops.ExportSpec = &.{},
        terminal_ids: []const []const u8 = &.{},
        labels: []const NodeLabelArg = &.{},
    };

    pub fn init(allocator: std.mem.Allocator, options: InitOptions) !Registry {
        var registry = Registry{
            .allocator = allocator,
            .enable_fs_service = options.enable_fs_service,
            .fs_export_count = options.export_specs.len,
            .fs_rw_export_count = countRwExports(options.export_specs),
        };
        errdefer registry.deinit();

        var terminal_ids = std.StringHashMapUnmanaged(void){};
        defer terminal_ids.deinit(allocator);
        for (options.terminal_ids) |terminal_id| {
            try validateIdentifier(terminal_id, 128);
            if (terminal_ids.contains(terminal_id)) return error.InvalidProviderConfig;
            try terminal_ids.put(allocator, terminal_id, {});
            try registry.terminal_ids.append(allocator, try allocator.dupe(u8, terminal_id));
        }

        var label_keys = std.StringHashMapUnmanaged(void){};
        defer label_keys.deinit(allocator);
        for (options.labels) |item| {
            try validateIdentifier(item.key, 128);
            try validateLabelValue(item.value, 512);
            if (label_keys.contains(item.key)) return error.InvalidProviderConfig;
            try label_keys.put(allocator, item.key, {});
            try registry.labels.append(allocator, .{
                .key = try allocator.dupe(u8, item.key),
                .value = try allocator.dupe(u8, item.value),
            });
        }

        return registry;
    }

    pub fn clone(self: *const Registry, allocator: std.mem.Allocator) !Registry {
        var copy = Registry{
            .allocator = allocator,
            .enable_fs_service = self.enable_fs_service,
            .fs_export_count = self.fs_export_count,
            .fs_rw_export_count = self.fs_rw_export_count,
        };
        errdefer copy.deinit();

        for (self.terminal_ids.items) |terminal_id| {
            try copy.terminal_ids.append(allocator, try allocator.dupe(u8, terminal_id));
        }

        for (self.labels.items) |label| {
            try copy.labels.append(allocator, .{
                .key = try allocator.dupe(u8, label.key),
                .value = try allocator.dupe(u8, label.value),
            });
        }

        return copy;
    }

    pub fn deinit(self: *Registry) void {
        for (self.terminal_ids.items) |terminal_id| self.allocator.free(terminal_id);
        self.terminal_ids.deinit(self.allocator);
        for (self.labels.items) |*label| label.deinit(self.allocator);
        self.labels.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn buildServiceUpsertPayload(
        self: *const Registry,
        allocator: std.mem.Allocator,
        node_id: []const u8,
        node_secret: []const u8,
        platform_os: []const u8,
        platform_arch: []const u8,
        platform_runtime_kind: []const u8,
    ) ![]u8 {
        const escaped_node_id = try jsonEscape(allocator, node_id);
        defer allocator.free(escaped_node_id);
        const escaped_node_secret = try jsonEscape(allocator, node_secret);
        defer allocator.free(escaped_node_secret);
        const escaped_os = try jsonEscape(allocator, platform_os);
        defer allocator.free(escaped_os);
        const escaped_arch = try jsonEscape(allocator, platform_arch);
        defer allocator.free(escaped_arch);
        const escaped_runtime = try jsonEscape(allocator, platform_runtime_kind);
        defer allocator.free(escaped_runtime);

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(allocator);

        try out.writer(allocator).print(
            "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"platform\":{{\"os\":\"{s}\",\"arch\":\"{s}\",\"runtime_kind\":\"{s}\"}}",
            .{ escaped_node_id, escaped_node_secret, escaped_os, escaped_arch, escaped_runtime },
        );

        if (self.labels.items.len > 0) {
            try out.appendSlice(allocator, ",\"labels\":{");
            for (self.labels.items, 0..) |label, idx| {
                if (idx != 0) try out.append(allocator, ',');
                const escaped_key = try jsonEscape(allocator, label.key);
                defer allocator.free(escaped_key);
                const escaped_value = try jsonEscape(allocator, label.value);
                defer allocator.free(escaped_value);
                try out.writer(allocator).print("\"{s}\":\"{s}\"", .{ escaped_key, escaped_value });
            }
            try out.append(allocator, '}');
        }

        try out.appendSlice(allocator, ",\"services\":[");
        var service_count: usize = 0;

        if (self.enable_fs_service) {
            try appendFsService(self, allocator, &out, node_id);
            service_count += 1;
        }

        for (self.terminal_ids.items) |terminal_id| {
            if (service_count > 0) try out.append(allocator, ',');
            try appendTerminalService(allocator, &out, node_id, terminal_id);
            service_count += 1;
        }

        try out.appendSlice(allocator, "]}");
        return out.toOwnedSlice(allocator);
    }
};

const NodeLabel = struct {
    key: []u8,
    value: []u8,

    fn deinit(self: *NodeLabel, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
        self.* = undefined;
    }
};

fn countRwExports(specs: []const fs_node_ops.ExportSpec) usize {
    var rw_count: usize = 0;
    for (specs) |spec| {
        if (!spec.ro) rw_count += 1;
    }
    return rw_count;
}

fn appendFsService(
    registry: *const Registry,
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    node_id: []const u8,
) !void {
    const escaped_node_id = try jsonEscape(allocator, node_id);
    defer allocator.free(escaped_node_id);
    const endpoint = try std.fmt.allocPrint(allocator, "/nodes/{s}/fs", .{escaped_node_id});
    defer allocator.free(endpoint);

    try out.writer(allocator).print(
        "{{\"service_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"{s}\"],\"capabilities\":{{\"rw\":{s},\"export_count\":{d}}}}}",
        .{
            endpoint,
            if (registry.fs_rw_export_count > 0) "true" else "false",
            registry.fs_export_count,
        },
    );
}

fn appendTerminalService(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    node_id: []const u8,
    terminal_id: []const u8,
) !void {
    const escaped_node_id = try jsonEscape(allocator, node_id);
    defer allocator.free(escaped_node_id);
    const escaped_terminal_id = try jsonEscape(allocator, terminal_id);
    defer allocator.free(escaped_terminal_id);

    const service_id = try std.fmt.allocPrint(allocator, "terminal-{s}", .{escaped_terminal_id});
    defer allocator.free(service_id);
    const endpoint = try std.fmt.allocPrint(allocator, "/nodes/{s}/terminal/{s}", .{ escaped_node_id, escaped_terminal_id });
    defer allocator.free(endpoint);

    try out.writer(allocator).print(
        "{{\"service_id\":\"{s}\",\"kind\":\"terminal\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"{s}\"],\"capabilities\":{{\"pty\":true,\"terminal_id\":\"{s}\"}}}}",
        .{ service_id, endpoint, escaped_terminal_id },
    );
}

fn validateIdentifier(value: []const u8, max_len: usize) !void {
    if (value.len == 0 or value.len > max_len) return error.InvalidProviderConfig;
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '-' or char == '_' or char == '.') continue;
        return error.InvalidProviderConfig;
    }
}

fn validateLabelValue(value: []const u8, max_len: usize) !void {
    if (value.len == 0 or value.len > max_len) return error.InvalidProviderConfig;
    for (value) |char| {
        if (char < 0x20) return error.InvalidProviderConfig;
    }
}

fn jsonEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    for (value) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => if (char < 0x20) {
                try out.writer(allocator).print("\\u00{x:0>2}", .{char});
            } else {
                try out.append(allocator, char);
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

test "node_capability_providers: build service upsert payload includes fs and terminal" {
    const allocator = std.testing.allocator;
    var registry = try Registry.init(allocator, .{
        .enable_fs_service = true,
        .export_specs = &[_]fs_node_ops.ExportSpec{
            .{ .name = "work", .path = ".", .ro = false },
            .{ .name = "read-only", .path = "/tmp", .ro = true },
        },
        .terminal_ids = &.{ "1", "2" },
        .labels = &.{
            .{ .key = "site", .value = "home-lab" },
            .{ .key = "tier", .value = "edge" },
        },
    });
    defer registry.deinit();

    const payload = try registry.buildServiceUpsertPayload(
        allocator,
        "node-99",
        "secret-abc",
        "linux",
        "amd64",
        "native",
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_id\":\"terminal-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_id\":\"terminal-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"export_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"site\":\"home-lab\"") != null);
}

test "node_capability_providers: duplicate terminal id rejected" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidProviderConfig, Registry.init(allocator, .{
        .terminal_ids = &.{ "1", "1" },
    }));
}
