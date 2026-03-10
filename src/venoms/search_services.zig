const std = @import("std");
const unified = @import("spider-protocol").unified;

pub const Namespace = enum {
    web_search,
    search_code,
};

const Request = struct {
    tool_name: []const u8,
    args_json: []u8,

    fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        allocator.free(self.args_json);
        self.* = undefined;
    }
};

pub fn seedWebSearchNamespace(self: anytype, web_search_dir: u32) !void {
    return seedWebSearchNamespaceAt(self, web_search_dir, "/global/web_search");
}

pub fn seedWebSearchNamespaceAt(self: anytype, web_search_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"web_search\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        web_search_dir,
        "Web Search",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"web_search\"],\"discoverable\":true,\"network\":true}",
        "First-class web search namespace. Write search payloads to control/search.json (or invoke.json), then read status.json/result.json.",
    );
    _ = try self.addFile(
        web_search_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"search\":\"control/search.json\"},\"operations\":{\"search\":\"search\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        web_search_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"web_search\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        web_search_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        web_search_dir,
        "STATUS.json",
        "{\"venom_id\":\"web_search\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    _ = try self.addFile(
        web_search_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    _ = try self.addFile(
        web_search_dir,
        "result.json",
        "{\"ok\":false,\"result\":null,\"error\":null}",
        false,
        .none,
    );

    const control_dir = try self.addDir(web_search_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Write search payloads to search.json (or explicit envelopes to invoke.json). Read result.json and status.json.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .web_search_invoke);
    _ = try self.addFile(control_dir, "search.json", "", true, .web_search_search);
}

pub fn seedSearchCodeNamespace(self: anytype, search_code_dir: u32) !void {
    return seedSearchCodeNamespaceAt(self, search_code_dir, "/global/search_code");
}

pub fn seedSearchCodeNamespaceAt(self: anytype, search_code_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"search_code\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        search_code_dir,
        "Search Code",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"search_code\"],\"discoverable\":true}",
        "First-class code search namespace. Write search payloads to control/search.json (or invoke.json), then read status.json/result.json.",
    );
    _ = try self.addFile(
        search_code_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"search\":\"control/search.json\"},\"operations\":{\"search\":\"search\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        search_code_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"search_code\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        search_code_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        search_code_dir,
        "STATUS.json",
        "{\"venom_id\":\"search_code\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    _ = try self.addFile(
        search_code_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    _ = try self.addFile(
        search_code_dir,
        "result.json",
        "{\"ok\":false,\"result\":null,\"error\":null}",
        false,
        .none,
    );

    const control_dir = try self.addDir(search_code_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Write search payloads to search.json (or explicit envelopes to invoke.json). Read result.json and status.json.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .search_code_invoke);
    _ = try self.addFile(control_dir, "search.json", "", true, .search_code_search);
}

pub fn handleNamespaceWrite(self: anytype, special: anytype, node_id: u32, raw_input: []const u8) !usize {
    const invoke_node = self.nodes.get(node_id) orelse return error.MissingNode;
    const control_dir_id = invoke_node.parent orelse return error.MissingNode;
    const venom_dir_id = (self.nodes.get(control_dir_id) orelse return error.MissingNode).parent orelse return error.MissingNode;
    if (!self.canInvokeVenomDirectory(venom_dir_id)) return error.AccessDenied;
    const status_runtime_id = self.lookupChild(venom_dir_id, "status.json") orelse return error.MissingNode;
    const result_id = self.lookupChild(venom_dir_id, "result.json") orelse return error.MissingNode;

    var request = try parseRequest(self, special, invoke_node.name, raw_input);
    defer request.deinit(self.allocator);

    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    try self.setFileContent(node_id, input);

    const running_status = try self.buildServiceInvokeStatusJson("running", request.tool_name, null);
    defer self.allocator.free(running_status);
    try self.setFileContent(status_runtime_id, running_status);

    const result_payload = try self.executeServiceToolCall(request.tool_name, request.args_json);
    defer self.allocator.free(result_payload);
    if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
        defer self.allocator.free(message);
        const status = try self.buildServiceInvokeStatusJson("failed", request.tool_name, message);
        defer self.allocator.free(status);
        try self.setFileContent(status_runtime_id, status);
    } else {
        const status = try self.buildServiceInvokeStatusJson("done", request.tool_name, null);
        defer self.allocator.free(status);
        try self.setFileContent(status_runtime_id, status);
    }
    try self.setFileContent(result_id, result_payload);
    return raw_input.len;
}

fn parseRequest(self: anytype, special: anytype, invoke_file_name: []const u8, raw_input: []const u8) !Request {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const namespace = namespaceFromSpecial(special) orelse return error.InvalidPayload;
    if (!namespaceMatchesInvokeFile(special, invoke_file_name)) return error.InvalidPayload;

    if (extractOptionalStringByNames(obj, &.{ "op", "operation", "tool", "tool_name" })) |raw_op| {
        if (!isValidOperation(namespace, raw_op)) return error.InvalidPayload;
    }

    const args_json = if (obj.get("arguments")) |value| blk: {
        if (value != .object) return error.InvalidPayload;
        break :blk try self.renderJsonValue(value);
    } else if (obj.get("args")) |value| blk: {
        if (value != .object) return error.InvalidPayload;
        break :blk try self.renderJsonValue(value);
    } else try self.renderJsonValue(parsed.value);

    return .{
        .tool_name = runtimeTool(namespace),
        .args_json = args_json,
    };
}

fn namespaceFromSpecial(special: anytype) ?Namespace {
    return switch (special) {
        .web_search_invoke, .web_search_search => .web_search,
        .search_code_invoke, .search_code_search => .search_code,
        else => null,
    };
}

fn namespaceMatchesInvokeFile(special: anytype, invoke_file_name: []const u8) bool {
    return switch (special) {
        .web_search_invoke, .search_code_invoke => std.mem.eql(u8, invoke_file_name, "invoke.json"),
        .web_search_search, .search_code_search => std.mem.eql(u8, invoke_file_name, "search.json"),
        else => false,
    };
}

fn runtimeTool(namespace: Namespace) []const u8 {
    return switch (namespace) {
        .web_search => "web_search",
        .search_code => "search_code",
    };
}

fn isValidOperation(namespace: Namespace, raw_operation: []const u8) bool {
    const op = std.mem.trim(u8, raw_operation, " \t\r\n");
    return switch (namespace) {
        .web_search => std.mem.eql(u8, op, "search") or std.mem.eql(u8, op, "web_search"),
        .search_code => std.mem.eql(u8, op, "search") or std.mem.eql(u8, op, "search_code"),
    };
}

fn extractOptionalStringByNames(obj: std.json.ObjectMap, names: []const []const u8) ?[]const u8 {
    for (names) |name| {
        if (obj.get(name)) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
    }
    return null;
}
