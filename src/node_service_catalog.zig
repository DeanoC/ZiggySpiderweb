const std = @import("std");

pub const Error = error{
    InvalidPayload,
};

pub const ServiceDescriptor = struct {
    service_id: []u8,
    kind: []u8,
    version: []u8,
    state: []u8,
    capabilities_json: []u8,
    endpoints: std.ArrayListUnmanaged([]u8) = .{},

    pub fn deinit(self: *ServiceDescriptor, allocator: std.mem.Allocator) void {
        allocator.free(self.service_id);
        allocator.free(self.kind);
        allocator.free(self.version);
        allocator.free(self.state);
        allocator.free(self.capabilities_json);
        for (self.endpoints.items) |endpoint| allocator.free(endpoint);
        self.endpoints.deinit(allocator);
        self.* = undefined;
    }
};

pub fn deinitServices(
    allocator: std.mem.Allocator,
    services: *std.ArrayListUnmanaged(ServiceDescriptor),
) void {
    for (services.items) |*service| service.deinit(allocator);
    services.deinit(allocator);
    services.* = .{};
}

pub fn replaceServicesFromJsonValue(
    allocator: std.mem.Allocator,
    services: *std.ArrayListUnmanaged(ServiceDescriptor),
    raw: std.json.Value,
) !void {
    if (raw != .array) return Error.InvalidPayload;

    var next = std.ArrayListUnmanaged(ServiceDescriptor){};
    errdefer {
        for (next.items) |*service| service.deinit(allocator);
        next.deinit(allocator);
    }

    var ids = std.StringHashMapUnmanaged(void){};
    defer ids.deinit(allocator);

    for (raw.array.items) |entry| {
        if (entry != .object) return Error.InvalidPayload;
        const obj = entry.object;

        const service_id = getRequiredString(obj, "service_id");
        try validateIdentifier(service_id, 128);
        if (ids.contains(service_id)) return Error.InvalidPayload;
        try ids.put(allocator, service_id, {});

        const kind = getRequiredString(obj, "kind");
        try validateIdentifier(kind, 128);

        const version = getOptionalString(obj, "version") orelse "1";
        try validateDisplayString(version, 64);

        const state = getRequiredString(obj, "state");
        try validateIdentifier(state, 64);

        const endpoints_raw = obj.get("endpoints") orelse return Error.InvalidPayload;
        if (endpoints_raw != .array) return Error.InvalidPayload;
        if (endpoints_raw.array.items.len == 0) return Error.InvalidPayload;

        var service = ServiceDescriptor{
            .service_id = try allocator.dupe(u8, service_id),
            .kind = try allocator.dupe(u8, kind),
            .version = try allocator.dupe(u8, version),
            .state = try allocator.dupe(u8, state),
            .capabilities_json = if (obj.get("capabilities")) |caps_value|
                try encodeCapabilitiesValue(allocator, caps_value)
            else
                try allocator.dupe(u8, "{}"),
        };
        errdefer service.deinit(allocator);

        for (endpoints_raw.array.items) |endpoint_value| {
            if (endpoint_value != .string) return Error.InvalidPayload;
            const endpoint = endpoint_value.string;
            if (endpoint.len == 0 or endpoint.len > 512) return Error.InvalidPayload;
            if (endpoint[0] != '/') return Error.InvalidPayload;
            try service.endpoints.append(allocator, try allocator.dupe(u8, endpoint));
        }

        try next.append(allocator, service);
    }

    deinitServices(allocator, services);
    services.* = next;
}

pub fn appendServiceJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    service: ServiceDescriptor,
) !void {
    const escaped_id = try jsonEscape(allocator, service.service_id);
    defer allocator.free(escaped_id);
    const escaped_kind = try jsonEscape(allocator, service.kind);
    defer allocator.free(escaped_kind);
    const escaped_version = try jsonEscape(allocator, service.version);
    defer allocator.free(escaped_version);
    const escaped_state = try jsonEscape(allocator, service.state);
    defer allocator.free(escaped_state);

    try out.writer(allocator).print(
        "{{\"service_id\":\"{s}\",\"kind\":\"{s}\",\"version\":\"{s}\",\"state\":\"{s}\",\"endpoints\":[",
        .{ escaped_id, escaped_kind, escaped_version, escaped_state },
    );
    for (service.endpoints.items, 0..) |endpoint, idx| {
        if (idx != 0) try out.append(allocator, ',');
        const escaped_endpoint = try jsonEscape(allocator, endpoint);
        defer allocator.free(escaped_endpoint);
        try out.writer(allocator).print("\"{s}\"", .{escaped_endpoint});
    }
    try out.writer(allocator).print("],\"capabilities\":{s}}}", .{service.capabilities_json});
}

fn getRequiredString(obj: std.json.ObjectMap, name: []const u8) []const u8 {
    const value = obj.get(name) orelse return "";
    if (value != .string or value.string.len == 0) return "";
    return value.string;
}

fn getOptionalString(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = obj.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn encodeCapabilitiesValue(allocator: std.mem.Allocator, raw: std.json.Value) ![]u8 {
    if (raw != .object) return Error.InvalidPayload;
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(raw, .{})});
}

fn validateIdentifier(value: []const u8, max_len: usize) !void {
    if (value.len == 0 or value.len > max_len) return Error.InvalidPayload;
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '-' or char == '_' or char == '.') continue;
        return Error.InvalidPayload;
    }
}

fn validateDisplayString(value: []const u8, max_len: usize) !void {
    if (value.len == 0 or value.len > max_len) return Error.InvalidPayload;
    for (value) |char| {
        if (char < 0x20) return Error.InvalidPayload;
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

test "node_service_catalog: parses and re-renders services array" {
    const allocator = std.testing.allocator;

    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        "[{\"service_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/node-1/fs\"],\"capabilities\":{\"rw\":true}}]",
        .{},
    );
    defer parsed.deinit();

    var services = std.ArrayListUnmanaged(ServiceDescriptor){};
    defer deinitServices(allocator, &services);
    try replaceServicesFromJsonValue(allocator, &services, parsed.value);
    try std.testing.expectEqual(@as(usize, 1), services.items.len);

    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    try appendServiceJson(allocator, &out, services.items[0]);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"service_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "\"capabilities\":{\"rw\":true}") != null);
}
