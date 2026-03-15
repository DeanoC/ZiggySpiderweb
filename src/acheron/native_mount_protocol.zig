const std = @import("std");

pub const schema_version: u32 = 1;

pub const EndpointSpec = struct {
    name: []const u8,
    url: []const u8,
    export_name: ?[]const u8 = null,
    mount_path: []const u8,
    auth_token: ?[]const u8 = null,
};

pub const NamespaceBinding = struct {
    namespace_url: []const u8,
    auth_token: ?[]const u8 = null,
    project_id: []const u8,
    agent_id: []const u8,
    session_key: []const u8,
    project_token: ?[]const u8 = null,
};

pub const LaunchConfig = struct {
    schema: u32 = schema_version,
    mountpoint: []const u8,
    workspace_sync_interval_ms: u64 = 5_000,
    namespace_keepalive_interval_ms: u64 = 60_000,
    endpoints: []const EndpointSpec,
    namespace: ?NamespaceBinding = null,
};

pub const OwnedLaunchConfig = struct {
    mountpoint: []u8,
    workspace_sync_interval_ms: u64,
    namespace_keepalive_interval_ms: u64,
    endpoints: []OwnedEndpointSpec,
    namespace: ?OwnedNamespaceBinding = null,

    pub fn deinit(self: *OwnedLaunchConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.mountpoint);
        for (self.endpoints) |*endpoint| endpoint.deinit(allocator);
        allocator.free(self.endpoints);
        if (self.namespace) |*namespace| namespace.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedEndpointSpec = struct {
    name: []u8,
    url: []u8,
    export_name: ?[]u8 = null,
    mount_path: []u8,
    auth_token: ?[]u8 = null,

    pub fn deinit(self: *OwnedEndpointSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.url);
        if (self.export_name) |value| allocator.free(value);
        allocator.free(self.mount_path);
        if (self.auth_token) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const OwnedNamespaceBinding = struct {
    namespace_url: []u8,
    auth_token: ?[]u8 = null,
    project_id: []u8,
    agent_id: []u8,
    session_key: []u8,
    project_token: ?[]u8 = null,

    pub fn deinit(self: *OwnedNamespaceBinding, allocator: std.mem.Allocator) void {
        allocator.free(self.namespace_url);
        if (self.auth_token) |value| allocator.free(value);
        allocator.free(self.project_id);
        allocator.free(self.agent_id);
        allocator.free(self.session_key);
        if (self.project_token) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const LockMode = enum {
    shared,
    exclusive,
    unlock,
};

pub const RequestOp = enum {
    ping,
    getattr,
    readdir,
    statfs,
    open,
    read,
    release,
    create,
    write,
    truncate,
    unlink,
    mkdir,
    rmdir,
    rename,
    symlink,
    setxattr,
    getxattr,
    listxattr,
    removexattr,
    lock,
};

pub const OwnedRequest = union(RequestOp) {
    ping: void,
    getattr: PathRequest,
    readdir: ReaddirRequest,
    statfs: PathRequest,
    open: OpenRequest,
    read: ReadRequest,
    release: HandleRequest,
    create: CreateRequest,
    write: WriteRequest,
    truncate: TruncateRequest,
    unlink: PathRequest,
    mkdir: PathRequest,
    rmdir: PathRequest,
    rename: RenameRequest,
    symlink: SymlinkRequest,
    setxattr: SetxattrRequest,
    getxattr: NamedPathRequest,
    listxattr: PathRequest,
    removexattr: NamedPathRequest,
    lock: LockRequest,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .ping => {},
            .getattr, .statfs, .unlink, .mkdir, .rmdir, .listxattr => |*request| request.deinit(allocator),
            .readdir => |*request| request.deinit(allocator),
            .open => |*request| request.deinit(allocator),
            .read => {},
            .release => {},
            .create => |*request| request.deinit(allocator),
            .write => |*request| request.deinit(allocator),
            .truncate => |*request| request.deinit(allocator),
            .rename => |*request| request.deinit(allocator),
            .symlink => |*request| request.deinit(allocator),
            .setxattr => |*request| request.deinit(allocator),
            .getxattr, .removexattr => |*request| request.deinit(allocator),
            .lock => {},
        }
        self.* = undefined;
    }
};

pub const PathRequest = struct {
    path: []u8,
    fn deinit(self: *PathRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const NamedPathRequest = struct {
    path: []u8,
    name: []u8,
    fn deinit(self: *NamedPathRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.name);
        self.* = undefined;
    }
};

pub const ReaddirRequest = struct {
    path: []u8,
    cookie: u64,
    max_entries: u32,
    fn deinit(self: *ReaddirRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const OpenRequest = struct {
    path: []u8,
    flags: u32,
    fn deinit(self: *OpenRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const HandleRequest = struct {
    handle_id: u64,
};

pub const ReadRequest = struct {
    handle_id: u64,
    off: u64,
    len: u32,
};

pub const CreateRequest = struct {
    path: []u8,
    mode: u32,
    flags: u32,
    fn deinit(self: *CreateRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const WriteRequest = struct {
    handle_id: u64,
    off: u64,
    data: []u8,
    fn deinit(self: *WriteRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        self.* = undefined;
    }
};

pub const TruncateRequest = struct {
    path: []u8,
    size: u64,
    fn deinit(self: *TruncateRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const RenameRequest = struct {
    old_path: []u8,
    new_path: []u8,
    fn deinit(self: *RenameRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.old_path);
        allocator.free(self.new_path);
        self.* = undefined;
    }
};

pub const SymlinkRequest = struct {
    target: []u8,
    link_path: []u8,
    fn deinit(self: *SymlinkRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        allocator.free(self.link_path);
        self.* = undefined;
    }
};

pub const SetxattrRequest = struct {
    path: []u8,
    name: []u8,
    value: []u8,
    flags: u32,
    fn deinit(self: *SetxattrRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.name);
        allocator.free(self.value);
        self.* = undefined;
    }
};

pub const LockRequest = struct {
    handle_id: u64,
    mode: LockMode,
    wait: bool,
};

pub const SuccessResponse = struct {
    ok: bool = true,
    op: []const u8,
    result_json: ?[]const u8 = null,
    data_b64: ?[]const u8 = null,
    handle_id: ?u64 = null,
    writable: ?bool = null,
    bytes_written: ?u32 = null,
};

pub const ErrorResponse = struct {
    ok: bool = false,
    op: []const u8,
    code: []const u8,
    message: []const u8,
};

pub fn encodeLaunchConfig(allocator: std.mem.Allocator, config: LaunchConfig) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, config, .{
        .emit_null_optional_fields = false,
        .whitespace = .indent_2,
    });
}

pub fn parseLaunchConfigOwned(allocator: std.mem.Allocator, json: []const u8) !OwnedLaunchConfig {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;

    const schema_value = parsed.value.object.get("schema") orelse return error.InvalidResponse;
    if (schema_value != .integer or schema_value.integer != schema_version) return error.InvalidResponse;

    const mountpoint = try duplicateRequiredString(allocator, parsed.value.object.get("mountpoint"));
    errdefer allocator.free(mountpoint);

    const workspace_sync_interval_ms = integerFieldToU64(parsed.value.object.get("workspace_sync_interval_ms")) orelse 5_000;
    const namespace_keepalive_interval_ms = integerFieldToU64(parsed.value.object.get("namespace_keepalive_interval_ms")) orelse 60_000;

    const endpoints_value = parsed.value.object.get("endpoints") orelse return error.InvalidResponse;
    if (endpoints_value != .array) return error.InvalidResponse;
    const endpoints = try allocator.alloc(OwnedEndpointSpec, endpoints_value.array.items.len);
    errdefer allocator.free(endpoints);
    var endpoints_len: usize = 0;
    errdefer {
        for (endpoints[0..endpoints_len]) |*endpoint| endpoint.deinit(allocator);
    }
    for (endpoints_value.array.items) |entry| {
        if (entry != .object) return error.InvalidResponse;
        endpoints[endpoints_len] = .{
            .name = try duplicateRequiredString(allocator, entry.object.get("name")),
            .url = try duplicateRequiredString(allocator, entry.object.get("url")),
            .export_name = try duplicateOptionalString(allocator, entry.object.get("export_name")),
            .mount_path = try duplicateRequiredString(allocator, entry.object.get("mount_path")),
            .auth_token = try duplicateOptionalString(allocator, entry.object.get("auth_token")),
        };
        endpoints_len += 1;
    }

    var namespace: ?OwnedNamespaceBinding = null;
    if (parsed.value.object.get("namespace")) |namespace_value| {
        if (namespace_value != .object) return error.InvalidResponse;
        namespace = .{
            .namespace_url = try duplicateRequiredString(allocator, namespace_value.object.get("namespace_url")),
            .auth_token = try duplicateOptionalString(allocator, namespace_value.object.get("auth_token")),
            .project_id = try duplicateRequiredString(allocator, namespace_value.object.get("project_id")),
            .agent_id = try duplicateRequiredString(allocator, namespace_value.object.get("agent_id")),
            .session_key = try duplicateRequiredString(allocator, namespace_value.object.get("session_key")),
            .project_token = try duplicateOptionalString(allocator, namespace_value.object.get("project_token")),
        };
    }

    return .{
        .mountpoint = mountpoint,
        .workspace_sync_interval_ms = workspace_sync_interval_ms,
        .namespace_keepalive_interval_ms = namespace_keepalive_interval_ms,
        .endpoints = endpoints,
        .namespace = namespace,
    };
}

pub fn parseRequestOwned(allocator: std.mem.Allocator, json: []const u8) !OwnedRequest {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;
    const op = parsed.value.object.get("op") orelse return error.InvalidResponse;
    if (op != .string) return error.InvalidResponse;

    if (std.mem.eql(u8, op.string, "ping")) return .{ .ping = {} };
    if (std.mem.eql(u8, op.string, "getattr")) return .{ .getattr = .{ .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")) } };
    if (std.mem.eql(u8, op.string, "readdir")) return .{ .readdir = .{
        .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")),
        .cookie = integerFieldToU64(parsed.value.object.get("cookie")) orelse 0,
        .max_entries = integerFieldToU32(parsed.value.object.get("max_entries")) orelse 256,
    } };
    if (std.mem.eql(u8, op.string, "statfs")) return .{ .statfs = .{ .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")) } };
    if (std.mem.eql(u8, op.string, "open")) return .{ .open = .{
        .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")),
        .flags = integerFieldToU32(parsed.value.object.get("flags")) orelse return error.InvalidResponse,
    } };
    if (std.mem.eql(u8, op.string, "read")) return .{ .read = .{
        .handle_id = integerFieldToU64(parsed.value.object.get("handle_id")) orelse return error.InvalidResponse,
        .off = integerFieldToU64(parsed.value.object.get("off")) orelse 0,
        .len = integerFieldToU32(parsed.value.object.get("len")) orelse return error.InvalidResponse,
    } };
    if (std.mem.eql(u8, op.string, "release")) return .{ .release = .{
        .handle_id = integerFieldToU64(parsed.value.object.get("handle_id")) orelse return error.InvalidResponse,
    } };
    if (std.mem.eql(u8, op.string, "create")) return .{ .create = .{
        .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")),
        .mode = integerFieldToU32(parsed.value.object.get("mode")) orelse return error.InvalidResponse,
        .flags = integerFieldToU32(parsed.value.object.get("flags")) orelse return error.InvalidResponse,
    } };
    if (std.mem.eql(u8, op.string, "write")) return .{ .write = .{
        .handle_id = integerFieldToU64(parsed.value.object.get("handle_id")) orelse return error.InvalidResponse,
        .off = integerFieldToU64(parsed.value.object.get("off")) orelse 0,
        .data = try decodeBase64Field(allocator, parsed.value.object.get("data_b64")),
    } };
    if (std.mem.eql(u8, op.string, "truncate")) return .{ .truncate = .{
        .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")),
        .size = integerFieldToU64(parsed.value.object.get("size")) orelse return error.InvalidResponse,
    } };
    if (std.mem.eql(u8, op.string, "unlink")) return .{ .unlink = .{ .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")) } };
    if (std.mem.eql(u8, op.string, "mkdir")) return .{ .mkdir = .{ .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")) } };
    if (std.mem.eql(u8, op.string, "rmdir")) return .{ .rmdir = .{ .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")) } };
    if (std.mem.eql(u8, op.string, "rename")) return .{ .rename = .{
        .old_path = try duplicateRequiredString(allocator, parsed.value.object.get("old_path")),
        .new_path = try duplicateRequiredString(allocator, parsed.value.object.get("new_path")),
    } };
    if (std.mem.eql(u8, op.string, "symlink")) return .{ .symlink = .{
        .target = try duplicateRequiredString(allocator, parsed.value.object.get("target")),
        .link_path = try duplicateRequiredString(allocator, parsed.value.object.get("link_path")),
    } };
    if (std.mem.eql(u8, op.string, "setxattr")) return .{ .setxattr = .{
        .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")),
        .name = try duplicateRequiredString(allocator, parsed.value.object.get("name")),
        .value = try decodeBase64Field(allocator, parsed.value.object.get("value_b64")),
        .flags = integerFieldToU32(parsed.value.object.get("flags")) orelse 0,
    } };
    if (std.mem.eql(u8, op.string, "getxattr")) return .{ .getxattr = .{
        .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")),
        .name = try duplicateRequiredString(allocator, parsed.value.object.get("name")),
    } };
    if (std.mem.eql(u8, op.string, "listxattr")) return .{ .listxattr = .{ .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")) } };
    if (std.mem.eql(u8, op.string, "removexattr")) return .{ .removexattr = .{
        .path = try duplicateRequiredString(allocator, parsed.value.object.get("path")),
        .name = try duplicateRequiredString(allocator, parsed.value.object.get("name")),
    } };
    if (std.mem.eql(u8, op.string, "lock")) {
        const mode_value = parsed.value.object.get("mode") orelse return error.InvalidResponse;
        if (mode_value != .string) return error.InvalidResponse;
        const mode: LockMode = if (std.mem.eql(u8, mode_value.string, "shared"))
            .shared
        else if (std.mem.eql(u8, mode_value.string, "exclusive"))
            .exclusive
        else if (std.mem.eql(u8, mode_value.string, "unlock"))
            .unlock
        else
            return error.InvalidResponse;
        return .{ .lock = .{
            .handle_id = integerFieldToU64(parsed.value.object.get("handle_id")) orelse return error.InvalidResponse,
            .mode = mode,
            .wait = boolField(parsed.value.object.get("wait")) orelse false,
        } };
    }
    return error.InvalidResponse;
}

pub fn encodeSuccessResponse(allocator: std.mem.Allocator, response: SuccessResponse) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, response, .{
        .emit_null_optional_fields = false,
    });
}

pub fn encodeErrorResponse(allocator: std.mem.Allocator, response: ErrorResponse) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, response, .{
        .emit_null_optional_fields = false,
    });
}

pub fn encodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const out_len = std.base64.standard.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, out_len);
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

fn decodeBase64Field(allocator: std.mem.Allocator, value: ?std.json.Value) ![]u8 {
    const resolved = value orelse return error.InvalidResponse;
    if (resolved != .string) return error.InvalidResponse;
    const out_len = try std.base64.standard.Decoder.calcSizeForSlice(resolved.string);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    try std.base64.standard.Decoder.decode(out, resolved.string);
    return out;
}

fn duplicateRequiredString(allocator: std.mem.Allocator, value: ?std.json.Value) ![]u8 {
    const resolved = value orelse return error.InvalidResponse;
    if (resolved != .string or resolved.string.len == 0) return error.InvalidResponse;
    return allocator.dupe(u8, resolved.string);
}

fn duplicateOptionalString(allocator: std.mem.Allocator, value: ?std.json.Value) !?[]u8 {
    const resolved = value orelse return null;
    if (resolved != .string) return error.InvalidResponse;
    const copied = try allocator.dupe(u8, resolved.string);
    return copied;
}

fn integerFieldToU64(value: ?std.json.Value) ?u64 {
    const resolved = value orelse return null;
    if (resolved != .integer or resolved.integer < 0) return null;
    return @intCast(resolved.integer);
}

fn integerFieldToU32(value: ?std.json.Value) ?u32 {
    const resolved = value orelse return null;
    if (resolved != .integer or resolved.integer < 0 or resolved.integer > std.math.maxInt(u32)) return null;
    return @intCast(resolved.integer);
}

fn boolField(value: ?std.json.Value) ?bool {
    const resolved = value orelse return null;
    if (resolved != .bool) return null;
    return resolved.bool;
}

test "native_mount_protocol: launch config roundtrips endpoint and namespace fields" {
    const allocator = std.testing.allocator;
    const encoded = try encodeLaunchConfig(allocator, .{
        .mountpoint = "/Volumes/spiderweb",
        .workspace_sync_interval_ms = 12_000,
        .namespace_keepalive_interval_ms = 90_000,
        .endpoints = &.{
            .{
                .name = "local",
                .url = "ws://127.0.0.1:18891/v2/fs",
                .mount_path = "/nodes/local/fs",
            },
        },
        .namespace = .{
            .namespace_url = "ws://127.0.0.1:18790/",
            .auth_token = "sw-admin-123",
            .project_id = "proj-1",
            .agent_id = "codex",
            .session_key = "session-1",
        },
    });
    defer allocator.free(encoded);

    var parsed = try parseLaunchConfigOwned(allocator, encoded);
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("/Volumes/spiderweb", parsed.mountpoint);
    try std.testing.expectEqual(@as(usize, 1), parsed.endpoints.len);
    try std.testing.expect(parsed.namespace != null);
    try std.testing.expectEqualStrings("/nodes/local/fs", parsed.endpoints[0].mount_path);
    try std.testing.expectEqualStrings("proj-1", parsed.namespace.?.project_id);
}

test "native_mount_protocol: parses write requests with base64 payload" {
    const allocator = std.testing.allocator;
    var request = try parseRequestOwned(
        allocator,
        "{\"op\":\"write\",\"handle_id\":9,\"off\":3,\"data_b64\":\"aGVsbG8=\"}",
    );
    defer request.deinit(allocator);

    switch (request) {
        .write => |write| {
            try std.testing.expectEqual(@as(u64, 9), write.handle_id);
            try std.testing.expectEqual(@as(u64, 3), write.off);
            try std.testing.expectEqualStrings("hello", write.data);
        },
        else => return error.TestUnexpectedResult,
    }
}
