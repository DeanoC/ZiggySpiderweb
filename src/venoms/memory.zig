const std = @import("std");
const unified = @import("spider-protocol").unified;
const memory_ownership = @import("../agents/memory_ownership.zig");

pub const Op = enum {
    create,
    load,
    versions,
    mutate,
    evict,
    search,
};

const Request = struct {
    op: Op,
    args_json: []u8,

    fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        allocator.free(self.args_json);
        self.* = undefined;
    }
};

pub fn seedNamespace(self: anytype, memory_dir: u32) !void {
    return seedNamespaceAt(self, memory_dir, "/global/memory");
}

pub fn seedNamespaceAt(self: anytype, memory_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"memory\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        memory_dir,
        "Memory",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"memory_create\",\"memory_load\",\"memory_versions\",\"memory_mutate\",\"memory_evict\",\"memory_search\"],\"discoverable\":true}",
        "First-class memory namespace. Write operation payloads to control/*.json, then read status.json/result.json.",
    );
    _ = try self.addFile(
        memory_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"create\":\"control/create.json\",\"load\":\"control/load.json\",\"versions\":\"control/versions.json\",\"mutate\":\"control/mutate.json\",\"evict\":\"control/evict.json\",\"search\":\"control/search.json\"},\"operations\":{\"create\":\"create\",\"load\":\"load\",\"versions\":\"versions\",\"mutate\":\"mutate\",\"evict\":\"evict\",\"search\":\"search\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        memory_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"agent_memory\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        memory_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        memory_dir,
        "STATUS.json",
        "{\"venom_id\":\"memory\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    _ = try self.addFile(
        memory_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    _ = try self.addFile(
        memory_dir,
        "result.json",
        "{\"ok\":false,\"result\":null,\"error\":null}",
        false,
        .none,
    );

    const control_dir = try self.addDir(memory_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Write JSON payloads to operation files. Generic invoke is available at invoke.json.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .memory_invoke);
    _ = try self.addFile(control_dir, "create.json", "", true, .memory_create);
    _ = try self.addFile(control_dir, "load.json", "", true, .memory_load);
    _ = try self.addFile(control_dir, "versions.json", "", true, .memory_versions);
    _ = try self.addFile(control_dir, "mutate.json", "", true, .memory_mutate);
    _ = try self.addFile(control_dir, "evict.json", "", true, .memory_evict);
    _ = try self.addFile(control_dir, "search.json", "", true, .memory_search);
}

pub fn handleNamespaceWrite(self: anytype, special: anytype, node_id: u32, raw_input: []const u8) !usize {
    const invoke_node = self.nodes.get(node_id) orelse return error.MissingNode;
    const control_dir_id = invoke_node.parent orelse return error.MissingNode;
    const venom_dir_id = (self.nodes.get(control_dir_id) orelse return error.MissingNode).parent orelse return error.MissingNode;
    if (!self.canInvokeVenomDirectory(venom_dir_id)) return error.AccessDenied;
    const status_runtime_id = self.lookupChild(venom_dir_id, "status.json") orelse return error.MissingNode;
    const result_id = self.lookupChild(venom_dir_id, "result.json") orelse return error.MissingNode;

    var parsed = try parseRequest(self, special, invoke_node.name, raw_input);
    defer parsed.deinit(self.allocator);

    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    try self.setFileContent(node_id, if (input.len == 0) "{}" else input);

    const tool_name = runtimeTool(parsed.op);
    const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
    defer self.allocator.free(running_status);
    try self.setFileContent(status_runtime_id, running_status);

    const runtime_args = try normalizeArgsForRuntime(self, parsed.op, parsed.args_json);
    defer self.allocator.free(runtime_args);
    const runtime_payload = try self.executeServiceToolCall(tool_name, runtime_args);
    defer self.allocator.free(runtime_payload);
    const transformed_payload = try transformResultPayload(self, runtime_payload);
    defer self.allocator.free(transformed_payload);

    if (try self.extractErrorMessageFromToolPayload(transformed_payload)) |message| {
        defer self.allocator.free(message);
        const status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
        defer self.allocator.free(status);
        try self.setFileContent(status_runtime_id, status);
    } else {
        const status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
        defer self.allocator.free(status);
        try self.setFileContent(status_runtime_id, status);
    }
    try self.setFileContent(result_id, transformed_payload);
    return raw_input.len;
}

pub fn buildMemoryPathFromMemId(allocator: std.mem.Allocator, mem_id: []const u8) ![]u8 {
    const encoded = try urlPathEncode(allocator, mem_id);
    defer allocator.free(encoded);
    return std.fmt.allocPrint(allocator, "/nodes/local/venoms/memory/items/{s}", .{encoded});
}

pub fn decodeMemIdFromPath(allocator: std.mem.Allocator, path_or_mem_id: []const u8) ![]u8 {
    inline for ([_][]const u8{
        "/nodes/local/venoms/memory/items/",
        "/services/memory/items/",
        "/global/memory/items/",
    }) |prefix| {
        if (std.mem.startsWith(u8, path_or_mem_id, prefix)) {
            const tail = path_or_mem_id[prefix.len..];
            if (tail.len == 0) return error.InvalidPayload;
            const slash = std.mem.indexOfScalar(u8, tail, '/') orelse tail.len;
            if (slash == 0) return error.InvalidPayload;
            return urlPathDecode(allocator, tail[0..slash]);
        }
    }
    return allocator.dupe(u8, path_or_mem_id);
}

fn parseRequest(self: anytype, special: anytype, invoke_file_name: []const u8, raw_input: []const u8) !Request {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    const payload = if (input.len == 0) "{}" else input;
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const op = switch (special) {
        .memory_create => Op.create,
        .memory_load => Op.load,
        .memory_versions => Op.versions,
        .memory_mutate => Op.mutate,
        .memory_evict => Op.evict,
        .memory_search => Op.search,
        .memory_invoke => blk: {
            const op_raw = blk2: {
                if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                break :blk2 null;
            } orelse return error.InvalidPayload;
            break :blk parseOp(op_raw) orelse return error.InvalidPayload;
        },
        else => return error.InvalidPayload,
    };

    const args_json = if (obj.get("arguments")) |value|
        try self.renderJsonValue(value)
    else if (obj.get("args")) |value|
        try self.renderJsonValue(value)
    else if (special == .memory_invoke)
        try self.renderJsonValue(parsed.value)
    else
        try self.renderJsonValue(parsed.value);

    _ = invoke_file_name;
    return .{ .op = op, .args_json = args_json };
}

fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "create") or std.mem.eql(u8, value, "memory_create")) return .create;
    if (std.mem.eql(u8, value, "load") or std.mem.eql(u8, value, "memory_load")) return .load;
    if (std.mem.eql(u8, value, "versions") or std.mem.eql(u8, value, "memory_versions")) return .versions;
    if (std.mem.eql(u8, value, "mutate") or std.mem.eql(u8, value, "memory_mutate")) return .mutate;
    if (std.mem.eql(u8, value, "evict") or std.mem.eql(u8, value, "memory_evict")) return .evict;
    if (std.mem.eql(u8, value, "search") or std.mem.eql(u8, value, "memory_search")) return .search;
    return null;
}

fn runtimeTool(op: Op) []const u8 {
    return switch (op) {
        .create => "memory_create",
        .load => "memory_load",
        .versions => "memory_versions",
        .mutate => "memory_mutate",
        .evict => "memory_evict",
        .search => "memory_search",
    };
}

fn opNeedsMemId(op: Op) bool {
    return switch (op) {
        .load, .versions, .mutate, .evict => true,
        else => false,
    };
}

fn normalizeArgsForRuntime(self: anytype, op: Op, args_json: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, args_json, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;
    if (!opNeedsMemId(op)) return self.allocator.dupe(u8, args_json);

    var mem_id: ?[]const u8 = null;
    var mem_id_owned = false;
    if (obj.get("mem_id")) |value| {
        if (value == .string and value.string.len > 0) mem_id = value.string;
    }
    if (mem_id == null) {
        if (obj.get("memory_path")) |value| {
            if (value != .string or value.string.len == 0) return error.InvalidPayload;
            mem_id = try decodeMemIdFromPath(self.allocator, value.string);
            mem_id_owned = true;
        }
    }
    const resolved_mem_id = mem_id orelse return error.InvalidPayload;
    defer if (mem_id_owned) self.allocator.free(resolved_mem_id);

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeByte('{');
    var first = true;
    var has_mem_id = false;
    var it = obj.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "memory_path")) continue;
        if (std.mem.eql(u8, entry.key_ptr.*, "mem_id")) {
            has_mem_id = true;
        }
        if (!first) try writer.writeByte(',');
        first = false;
        try writeJsonString(writer, entry.key_ptr.*);
        try writer.writeByte(':');
        if (std.mem.eql(u8, entry.key_ptr.*, "mem_id")) {
            try writeJsonString(writer, resolved_mem_id);
        } else {
            try self.renderJsonValueToWriter(writer, entry.value_ptr.*);
        }
    }
    if (!has_mem_id) {
        if (!first) try writer.writeByte(',');
        try writer.writeAll("\"mem_id\":");
        try writeJsonString(writer, resolved_mem_id);
    }
    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

fn transformResultPayload(self: anytype, runtime_payload: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, runtime_payload, .{}) catch {
        return self.allocator.dupe(u8, runtime_payload);
    };
    defer parsed.deinit();
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try renderJsonValueWithMemoryPaths(self, writer, parsed.value);
    return out.toOwnedSlice(self.allocator);
}

fn renderJsonValueWithMemoryPaths(self: anytype, writer: anytype, value: std.json.Value) !void {
    switch (value) {
        .null, .bool, .integer, .float, .number_string, .string => try self.renderJsonValueToWriter(writer, value),
        .array => |arr| {
            try writer.writeByte('[');
            for (arr.items, 0..) |item, idx| {
                if (idx != 0) try writer.writeByte(',');
                try renderJsonValueWithMemoryPaths(self, writer, item);
            }
            try writer.writeByte(']');
        },
        .object => |obj| {
            try writer.writeByte('{');
            var first = true;
            var it = obj.iterator();
            while (it.next()) |entry| {
                if (std.mem.eql(u8, entry.key_ptr.*, "mem_id")) {
                    if (entry.value_ptr.* == .string and entry.value_ptr.*.string.len > 0) {
                        const memory_path = try buildMemoryPathFromMemId(self.allocator, entry.value_ptr.*.string);
                        defer self.allocator.free(memory_path);
                        if (!first) try writer.writeByte(',');
                        first = false;
                        try writer.writeAll("\"memory_path\":");
                        try writeJsonString(writer, memory_path);

                        if (memory_ownership.ownershipLabelFromMemId(entry.value_ptr.*.string)) |ownership| {
                            try writer.writeByte(',');
                            try writer.writeAll("\"ownership\":");
                            try writeJsonString(writer, ownership);
                        }
                        continue;
                    }
                }
                if (!first) try writer.writeByte(',');
                first = false;
                try writeJsonString(writer, entry.key_ptr.*);
                try writer.writeByte(':');
                try renderJsonValueWithMemoryPaths(self, writer, entry.value_ptr.*);
            }
            try writer.writeByte('}');
        },
    }
}

fn parseHexNibble(char: u8) ?u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => 10 + (char - 'a'),
        'A'...'F' => 10 + (char - 'A'),
        else => null,
    };
}

fn urlPathEncode(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    for (value) |char| {
        if ((char >= 'A' and char <= 'Z') or
            (char >= 'a' and char <= 'z') or
            (char >= '0' and char <= '9') or
            char == '-' or char == '_' or char == '.' or char == '~')
        {
            try out.append(allocator, char);
        } else {
            try out.writer(allocator).print("%{X:0>2}", .{char});
        }
    }
    return out.toOwnedSlice(allocator);
}

fn urlPathDecode(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < value.len) {
        const char = value[i];
        if (char == '%') {
            if (i + 2 >= value.len) return error.InvalidPayload;
            const hi = parseHexNibble(value[i + 1]) orelse return error.InvalidPayload;
            const lo = parseHexNibble(value[i + 2]) orelse return error.InvalidPayload;
            try out.append(allocator, (hi << 4) | lo);
            i += 3;
            continue;
        }
        try out.append(allocator, char);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |char| {
        switch (char) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => if (char < 0x20)
                try writer.print("\\u{X:0>4}", .{@as(u16, char)})
            else
                try writer.writeByte(char),
        }
    }
    try writer.writeByte('"');
}
