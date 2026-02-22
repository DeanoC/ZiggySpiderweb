const std = @import("std");

pub const RequestError = error{
    InvalidEnvelope,
    MissingField,
    InvalidType,
    UnsupportedOperation,
};

pub const Op = enum {
    HELLO,
    EXPORTS,
    LOOKUP,
    GETATTR,
    READDIRP,
    SYMLINK,
    SETXATTR,
    GETXATTR,
    LISTXATTR,
    REMOVEXATTR,
    OPEN,
    READ,
    CLOSE,
    LOCK,
    CREATE,
    WRITE,
    TRUNCATE,
    UNLINK,
    MKDIR,
    RMDIR,
    RENAME,
    STATFS,
    INVAL,
    INVAL_DIR,
};

pub const Errno = struct {
    pub const SUCCESS: i32 = 0;
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EBADF: i32 = 9;
    pub const EAGAIN: i32 = 11;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const EXDEV: i32 = 18;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const ERANGE: i32 = 34;
    pub const ENOSYS: i32 = 38;
    pub const ENOTEMPTY: i32 = 39;
    pub const ENODATA: i32 = 61;
    pub const ETIMEDOUT: i32 = 110;
    pub const EROFS: i32 = 30;
};

pub const ParsedRequest = struct {
    parsed: std.json.Parsed(std.json.Value),
    id: u32,
    op: Op,
    node: ?u64,
    handle: ?u64,
    args: std.json.ObjectMap,

    pub fn deinit(self: *ParsedRequest) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub const InvalidationWhat = enum {
    attr,
    data,
    all,
};

pub const InvalidationEvent = union(enum) {
    INVAL: struct {
        node: u64,
        what: InvalidationWhat = .all,
        gen: ?u64 = null,
    },
    INVAL_DIR: struct {
        dir: u64,
        dir_gen: ?u64 = null,
    },
};

pub fn opFromString(raw: []const u8) ?Op {
    inline for (@typeInfo(Op).@"enum".fields) |field| {
        if (std.mem.eql(u8, raw, field.name)) {
            return @enumFromInt(field.value);
        }
    }
    return null;
}

pub fn opName(op: Op) []const u8 {
    return @tagName(op);
}

pub fn parseRequest(allocator: std.mem.Allocator, payload: []const u8) !ParsedRequest {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    errdefer parsed.deinit();

    if (parsed.value != .object) return RequestError.InvalidEnvelope;
    const root = parsed.value.object;

    const t = root.get("t") orelse return RequestError.MissingField;
    if (t != .string or !std.mem.eql(u8, t.string, "req")) return RequestError.InvalidEnvelope;

    const id = root.get("id") orelse return RequestError.MissingField;
    if (id != .integer or id.integer < 0 or id.integer > std.math.maxInt(u32)) return RequestError.InvalidType;

    const op_value = root.get("op") orelse return RequestError.MissingField;
    if (op_value != .string) return RequestError.InvalidType;
    const op = opFromString(op_value.string) orelse return RequestError.UnsupportedOperation;

    const node = try parseOptionalU64(root, "node");
    const handle = try parseOptionalU64(root, "h");
    const args = try parseOptionalObject(root, "a");

    return .{
        .parsed = parsed,
        .id = @intCast(id.integer),
        .op = op,
        .node = node,
        .handle = handle,
        .args = args,
    };
}

pub fn getRequiredString(args: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = args.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

pub fn getOptionalString(args: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = args.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

pub fn getOptionalBool(args: std.json.ObjectMap, name: []const u8, default: bool) !bool {
    const value = args.get(name) orelse return default;
    if (value != .bool) return RequestError.InvalidType;
    return value.bool;
}

pub fn getOptionalU32(args: std.json.ObjectMap, name: []const u8, default: u32) !u32 {
    const value = args.get(name) orelse return default;
    if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u32)) return RequestError.InvalidType;
    return @intCast(value.integer);
}

pub fn getOptionalU64(args: std.json.ObjectMap, name: []const u8, default: u64) !u64 {
    const value = args.get(name) orelse return default;
    if (value != .integer or value.integer < 0) return RequestError.InvalidType;
    return @intCast(value.integer);
}

pub fn buildSuccessResponse(allocator: std.mem.Allocator, id: u32, result_json: ?[]const u8) ![]u8 {
    const payload = result_json orelse "{}";
    return std.fmt.allocPrint(allocator, "{{\"t\":\"res\",\"id\":{d},\"ok\":true,\"r\":{s}}}", .{ id, payload });
}

pub fn buildErrorResponse(allocator: std.mem.Allocator, id: u32, err_no: i32, msg: []const u8) ![]u8 {
    const escaped_msg = try jsonEscape(allocator, msg);
    defer allocator.free(escaped_msg);

    return std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"res\",\"id\":{d},\"ok\":false,\"err\":{{\"no\":{d},\"msg\":\"{s}\"}}}}",
        .{ id, err_no, escaped_msg },
    );
}

pub fn buildEvent(allocator: std.mem.Allocator, op: Op, args_json: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"evt\",\"op\":\"{s}\",\"a\":{s}}}",
        .{ opName(op), args_json },
    );
}

pub fn buildInvalidationEvent(allocator: std.mem.Allocator, event: InvalidationEvent) ![]u8 {
    return switch (event) {
        .INVAL => |ev| blk: {
            const args = if (ev.gen) |gen|
                try std.fmt.allocPrint(
                    allocator,
                    "{{\"node\":{d},\"what\":\"{s}\",\"gen\":{d}}}",
                    .{ ev.node, @tagName(ev.what), gen },
                )
            else
                try std.fmt.allocPrint(
                    allocator,
                    "{{\"node\":{d},\"what\":\"{s}\"}}",
                    .{ ev.node, @tagName(ev.what) },
                );
            defer allocator.free(args);
            break :blk buildEvent(allocator, .INVAL, args);
        },
        .INVAL_DIR => |ev| blk: {
            const args = if (ev.dir_gen) |gen|
                try std.fmt.allocPrint(
                    allocator,
                    "{{\"dir\":{d},\"dir_gen\":{d}}}",
                    .{ ev.dir, gen },
                )
            else
                try std.fmt.allocPrint(
                    allocator,
                    "{{\"dir\":{d}}}",
                    .{ev.dir},
                );
            defer allocator.free(args);
            break :blk buildEvent(allocator, .INVAL_DIR, args);
        },
    };
}

pub fn parseMaybeInvalidationEvent(allocator: std.mem.Allocator, payload: []const u8) !?InvalidationEvent {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const root = parsed.value.object;

    const t = root.get("t") orelse return null;
    if (t != .string or !std.mem.eql(u8, t.string, "evt")) return null;

    const op_value = root.get("op") orelse return error.InvalidEnvelope;
    if (op_value != .string) return error.InvalidType;
    const op = opFromString(op_value.string) orelse return error.UnsupportedOperation;

    const a_value = root.get("a") orelse return error.MissingField;
    if (a_value != .object) return error.InvalidType;
    const args = a_value.object;

    return switch (op) {
        .INVAL => .{
            .INVAL = .{
                .node = node_blk: {
                    const node_value = args.get("node") orelse return error.MissingField;
                    if (node_value != .integer or node_value.integer < 0) return error.InvalidType;
                    break :node_blk @as(u64, @intCast(node_value.integer));
                },
                .what = what_blk: {
                    const raw = getOptionalString(args, "what") orelse "all";
                    if (std.mem.eql(u8, raw, "attr")) break :what_blk .attr;
                    if (std.mem.eql(u8, raw, "data")) break :what_blk .data;
                    if (std.mem.eql(u8, raw, "all")) break :what_blk .all;
                    return error.InvalidType;
                },
                .gen = if (args.get("gen")) |gen_value| blk: {
                    if (gen_value != .integer or gen_value.integer < 0) return error.InvalidType;
                    break :blk @as(u64, @intCast(gen_value.integer));
                } else null,
            },
        },
        .INVAL_DIR => .{
            .INVAL_DIR = .{
                .dir = dir_blk: {
                    const dir_value = args.get("dir") orelse return error.MissingField;
                    if (dir_value != .integer or dir_value.integer < 0) return error.InvalidType;
                    break :dir_blk @as(u64, @intCast(dir_value.integer));
                },
                .dir_gen = if (args.get("dir_gen")) |gen_value| blk: {
                    if (gen_value != .integer or gen_value.integer < 0) return error.InvalidType;
                    break :blk @as(u64, @intCast(gen_value.integer));
                } else null,
            },
        },
        else => null,
    };
}

pub fn jsonEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
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

fn parseOptionalObject(root: std.json.ObjectMap, name: []const u8) !std.json.ObjectMap {
    const value = root.get(name) orelse return root;
    if (value != .object) return RequestError.InvalidType;
    return value.object;
}

fn parseOptionalU64(root: std.json.ObjectMap, name: []const u8) !?u64 {
    const value = root.get(name) orelse return null;
    if (value != .integer or value.integer < 0) return RequestError.InvalidType;
    return @intCast(value.integer);
}

test "fs_protocol: parseRequest reads envelope and args" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"t":"req","id":7,"op":"LOOKUP","node":42,"a":{"name":"hello.txt"}}
    ;
    var parsed = try parseRequest(allocator, payload);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 7), parsed.id);
    try std.testing.expectEqual(Op.LOOKUP, parsed.op);
    try std.testing.expectEqual(@as(u64, 42), parsed.node.?);
    try std.testing.expectEqualStrings("hello.txt", getRequiredString(parsed.args, "name").?);
}

test "fs_protocol: parseRequest rejects unknown op" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"t":"req","id":1,"op":"UNKNOWN"}
    ;
    try std.testing.expectError(RequestError.UnsupportedOperation, parseRequest(allocator, payload));
}

test "fs_protocol: buildErrorResponse escapes message" {
    const allocator = std.testing.allocator;
    const msg = "bad \"quote\"\n";
    const response = try buildErrorResponse(allocator, 1, Errno.EINVAL, msg);
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\\\"quote\\\"") != null);
}

test "fs_protocol: invalidation event build + parse roundtrip" {
    const allocator = std.testing.allocator;
    const payload = try buildInvalidationEvent(allocator, .{
        .INVAL = .{
            .node = 123,
            .what = .all,
            .gen = 456,
        },
    });
    defer allocator.free(payload);

    const parsed = try parseMaybeInvalidationEvent(allocator, payload);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(@as(u64, 123), parsed.?.INVAL.node);
    try std.testing.expectEqual(InvalidationWhat.all, parsed.?.INVAL.what);
    try std.testing.expectEqual(@as(?u64, 456), parsed.?.INVAL.gen);
}
