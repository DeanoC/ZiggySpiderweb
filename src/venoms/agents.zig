const std = @import("std");
const unified = @import("spider-protocol").unified;
const agent_registry = @import("../agents/agent_registry.zig");

const max_agent_id_len: usize = 64;

pub const Op = enum {
    list,
    create,
};

pub fn seedNamespace(self: anytype, agents_dir: u32) !void {
    return seedNamespaceAt(self, agents_dir, "/global/agents");
}

pub fn seedNamespaceAt(self: anytype, agents_dir: u32, base_path: []const u8) !void {
    const can_create_agents = self.canCreateAgents();
    const caps_json = if (can_create_agents)
        "{\"invoke\":true,\"operations\":[\"agents_list\",\"agents_create\"],\"discoverable\":true,\"create_allowed\":true}"
    else
        "{\"invoke\":true,\"operations\":[\"agents_list\"],\"discoverable\":true,\"create_allowed\":false}";
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"agents\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        agents_dir,
        "Agents Management",
        shape_json,
        caps_json,
        "List and create agent workspaces through Acheron control files.",
    );
    _ = try self.addFile(
        agents_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"create\":\"control/create.json\"},\"operations\":{\"list\":\"agents_list\",\"create\":\"agents_create\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        agents_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"agent_registry\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        agents_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\",\"project_token_required\":false}",
        false,
        .none,
    );
    _ = try self.addFile(
        agents_dir,
        "STATUS.json",
        "{\"venom_id\":\"agents\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    self.agents_status_id = try self.addFile(
        agents_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    const initial_result = try buildListResultJson(self);
    defer self.allocator.free(initial_result);
    self.agents_result_id = try self.addFile(
        agents_dir,
        "result.json",
        initial_result,
        false,
        .none,
    );

    const control_dir = try self.addDir(agents_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Use list/create operation files, or invoke.json with op=list|create plus arguments. Create requires agent provisioning capability.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .agents_invoke);
    _ = try self.addFile(control_dir, "list.json", "", true, .agents_list);
    _ = try self.addFile(control_dir, "create.json", "", can_create_agents, .agents_create);
}

pub fn handleInvokeWrite(self: anytype, invoke_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(invoke_node_id, input);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const op_raw = blk: {
        if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        break :blk null;
    } orelse return error.InvalidPayload;
    const op = parseOp(op_raw) orelse return error.InvalidPayload;

    const args_obj = blk: {
        if (obj.get("arguments")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value.object;
        }
        if (obj.get("args")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value.object;
        }
        break :blk obj;
    };
    return executeOp(self, op, args_obj, raw_input.len);
}

pub fn handleListWrite(self: anytype, list_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    const payload = if (input.len == 0) "{}" else input;
    try self.setFileContent(list_node_id, payload);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return executeOp(self, .list, parsed.value.object, raw_input.len);
}

pub fn handleCreateWrite(self: anytype, create_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(create_node_id, input);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return executeOp(self, .create, parsed.value.object, raw_input.len);
}

pub fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "agents_list")) return .list;
    if (std.mem.eql(u8, value, "create") or std.mem.eql(u8, value, "agents_create")) return .create;
    return null;
}

pub fn operationName(op: Op) []const u8 {
    return switch (op) {
        .list => "list",
        .create => "create",
    };
}

pub fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .list => "agents_list",
        .create => "agents_create",
    };
}

fn executeOp(self: anytype, op: Op, args_obj: std.json.ObjectMap, written: usize) !usize {
    const tool_name = statusToolName(op);
    const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
    defer self.allocator.free(running_status);
    if (self.agents_status_id != 0) try self.setFileContent(self.agents_status_id, running_status);

    const result_payload = executeOpPayload(self, op, args_obj) catch |err| {
        const error_message = @errorName(err);
        const error_code = switch (err) {
            error.AccessDenied => "forbidden",
            error.AlreadyExists => "already_exists",
            error.InvalidAgentId => "invalid_agent_id",
            else => "invalid_payload",
        };
        const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
        defer self.allocator.free(failed_status);
        if (self.agents_status_id != 0) try self.setFileContent(self.agents_status_id, failed_status);
        const failed_result = try buildFailureResultJson(self, op, error_code, error_message);
        defer self.allocator.free(failed_result);
        if (self.agents_result_id != 0) try self.setFileContent(self.agents_result_id, failed_result);
        return err;
    };
    defer self.allocator.free(result_payload);

    const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
    defer self.allocator.free(done_status);
    if (self.agents_status_id != 0) try self.setFileContent(self.agents_status_id, done_status);
    if (self.agents_result_id != 0) try self.setFileContent(self.agents_result_id, result_payload);
    return written;
}

fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    return switch (op) {
        .list => executeListOp(self),
        .create => executeCreateOp(self, args_obj),
    };
}

fn executeListOp(self: anytype) ![]u8 {
    const inventory = try buildInventoryJson(self);
    defer self.allocator.free(inventory);
    return buildSuccessResultJson(self, .list, inventory);
}

fn executeCreateOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    if (!self.canCreateAgents()) return error.AccessDenied;
    const new_agent_id = extractAgentId(args_obj) orelse return error.InvalidPayload;
    if (!isValidManagedAgentId(new_agent_id)) return error.InvalidAgentId;
    if (std.mem.eql(u8, new_agent_id, "self")) return error.InvalidAgentId;

    const metadata_obj = blk: {
        if (args_obj.get("agent")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value.object;
        }
        break :blk args_obj;
    };
    const template_path = extractOptionalStringByNames(metadata_obj, &.{ "persona_pack", "persona", "template" });
    const desired_project_id = extractOptionalStringByNames(args_obj, &.{"project_id"});
    const desired_project_token = extractOptionalStringByNames(args_obj, &.{"project_token"});

    var registry = agent_registry.AgentRegistry.init(
        self.allocator,
        ".",
        self.agents_dir,
        self.assets_dir,
    );
    defer registry.deinit();
    try registry.scan();
    if (registry.getAgent(new_agent_id) != null) return error.AlreadyExists;
    try registry.createAgent(new_agent_id, template_path);

    const metadata_written = try maybeWriteAgentMetadataFile(self, new_agent_id, args_obj);
    var activated = false;
    var activation_error: ?[]u8 = null;
    defer if (activation_error) |value| self.allocator.free(value);

    if (desired_project_id) |project_id| {
        if (self.control_plane) |plane| {
            const activation_payload = try buildProjectActivationPayload(self.allocator, project_id, desired_project_token);
            defer self.allocator.free(activation_payload);
            const activation_result = plane.activateProjectWithRole(new_agent_id, activation_payload, self.is_admin) catch |err| blk: {
                activation_error = try self.allocator.dupe(u8, @errorName(err));
                break :blk null;
            };
            if (activation_result) |payload| {
                defer plane.allocator.free(payload);
                activated = true;
            }
        } else {
            activation_error = try self.allocator.dupe(u8, "ControlPlaneUnavailable");
        }
    }

    const inventory = try buildInventoryJson(self);
    defer self.allocator.free(inventory);
    const escaped_agent = try unified.jsonEscape(self.allocator, new_agent_id);
    defer self.allocator.free(escaped_agent);
    const project_json = if (desired_project_id) |project_id| blk: {
        const escaped = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(project_json);
    const activation_error_json = if (activation_error) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(activation_error_json);
    const detail = try std.fmt.allocPrint(
        self.allocator,
        "{{\"agent_id\":\"{s}\",\"created\":true,\"metadata_updated\":{},\"project_id\":{s},\"activated\":{},\"activation_error\":{s},\"inventory\":{s}}}",
        .{ escaped_agent, metadata_written, project_json, activated, activation_error_json, inventory },
    );
    defer self.allocator.free(detail);
    return buildSuccessResultJson(self, .create, detail);
}

fn buildProjectActivationPayload(
    allocator: std.mem.Allocator,
    project_id: []const u8,
    project_token: ?[]const u8,
) ![]u8 {
    const escaped_project = try unified.jsonEscape(allocator, project_id);
    defer allocator.free(escaped_project);
    if (project_token) |token| {
        const escaped_token = try unified.jsonEscape(allocator, token);
        defer allocator.free(escaped_token);
        return std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
            .{ escaped_project, escaped_token },
        );
    }
    return std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\"}}",
        .{escaped_project},
    );
}

fn buildListResultJson(self: anytype) ![]u8 {
    const inventory = try buildInventoryJson(self);
    defer self.allocator.free(inventory);
    return buildSuccessResultJson(self, .list, inventory);
}

fn buildInventoryJson(self: anytype) ![]u8 {
    const create_allowed = self.canCreateAgents();
    var registry = agent_registry.AgentRegistry.init(
        self.allocator,
        ".",
        self.agents_dir,
        self.assets_dir,
    );
    defer registry.deinit();
    try registry.scan();

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);

    try writer.writeAll("{\"agents\":[");
    const agents = registry.listAgents();
    for (agents, 0..) |agent, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try writer.writeAll("\"agent_id\":");
        try writeJsonString(writer, agent.id);
        try writer.writeAll(",\"name\":");
        try writeJsonString(writer, agent.name);
        try writer.writeAll(",\"description\":");
        try writeJsonString(writer, agent.description);
        try writer.writeAll(",\"is_default\":");
        try writer.print("{}", .{agent.is_default});
        try writer.writeAll(",\"identity_loaded\":");
        try writer.print("{}", .{agent.identity_loaded});
        try writer.writeAll(",\"persona_pack\":");
        if (agent.persona_pack) |value| {
            try writeJsonString(writer, value);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"capabilities\":[");
        for (agent.capabilities.items, 0..) |capability, cap_idx| {
            if (cap_idx > 0) try writer.writeByte(',');
            try writeJsonString(writer, managedAgentCapabilityName(capability));
        }
        try writer.writeAll("]}");
    }
    try writer.print("],\"count\":{d},\"create_allowed\":{}}}", .{ agents.len, create_allowed });
    return out.toOwnedSlice(self.allocator);
}

fn buildSuccessResultJson(self: anytype, op: Op, result_json: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
        .{ escaped_operation, result_json },
    );
}

fn buildFailureResultJson(self: anytype, op: Op, code: []const u8, message: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    const escaped_code = try unified.jsonEscape(self.allocator, code);
    defer self.allocator.free(escaped_code);
    const escaped_message = try unified.jsonEscape(self.allocator, message);
    defer self.allocator.free(escaped_message);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":false,\"operation\":\"{s}\",\"result\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
        .{ escaped_operation, escaped_code, escaped_message },
    );
}

fn maybeWriteAgentMetadataFile(self: anytype, target_agent_id: []const u8, args_obj: std.json.ObjectMap) !bool {
    const metadata_obj = blk: {
        if (args_obj.get("agent")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value.object;
        }
        break :blk args_obj;
    };

    var name_value: ?[]const u8 = null;
    var description_value: ?[]const u8 = null;
    var capabilities_value: ?std.json.Value = null;
    var has_capabilities = false;
    var existing_persona_pack: ?[]u8 = null;
    defer if (existing_persona_pack) |value| self.allocator.free(value);

    const agent_dir = try std.fs.path.join(self.allocator, &.{ self.agents_dir, target_agent_id });
    defer self.allocator.free(agent_dir);
    const metadata_path = try std.fs.path.join(self.allocator, &.{ agent_dir, "agent.json" });
    defer self.allocator.free(metadata_path);

    const existing_content = std.fs.cwd().readFileAlloc(self.allocator, metadata_path, 128 * 1024) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (existing_content) |value| self.allocator.free(value);
    if (existing_content) |value| {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, value, .{});
        defer parsed.deinit();
        if (parsed.value == .object) {
            if (parsed.value.object.get("persona_pack")) |entry| {
                if (entry == .string) existing_persona_pack = try self.allocator.dupe(u8, entry.string);
            }
        }
    }

    if (metadata_obj.get("name")) |value| {
        if (value == .string) name_value = value.string else if (value != .null) return error.InvalidPayload;
    }
    if (metadata_obj.get("description")) |value| {
        if (value == .string) description_value = value.string else if (value != .null) return error.InvalidPayload;
    }
    if (metadata_obj.get("persona_pack")) |value| {
        if (value == .string) {
            if (existing_persona_pack) |owned| self.allocator.free(owned);
            existing_persona_pack = try self.allocator.dupe(u8, value.string);
        } else if (value != .null) return error.InvalidPayload;
    } else if (metadata_obj.get("persona")) |value| {
        if (value == .string) {
            if (existing_persona_pack) |owned| self.allocator.free(owned);
            existing_persona_pack = try self.allocator.dupe(u8, value.string);
        } else if (value != .null) return error.InvalidPayload;
    }
    if (metadata_obj.get("capabilities")) |value| {
        if (value == .array) {
            has_capabilities = true;
            for (value.array.items) |entry| {
                if (entry != .string) return error.InvalidPayload;
            }
            capabilities_value = value;
        } else if (value != .null) {
            return error.InvalidPayload;
        }
    }

    if (name_value == null and description_value == null and !has_capabilities) return false;

    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeByte('{');
    var first = true;

    if (name_value) |value| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writeJsonString(writer, "name");
        try writer.writeByte(':');
        try writeJsonString(writer, value);
    }
    if (description_value) |value| {
        if (!first) try writer.writeByte(',');
        first = false;
        try writeJsonString(writer, "description");
        try writer.writeByte(':');
        try writeJsonString(writer, value);
    }
    if (has_capabilities) {
        if (!first) try writer.writeByte(',');
        first = false;
        try writeJsonString(writer, "capabilities");
        try writer.writeByte(':');
        try writer.writeByte('[');
        if (capabilities_value) |caps_raw| {
            const caps = caps_raw.array;
            for (caps.items, 0..) |entry, idx| {
                if (idx > 0) try writer.writeByte(',');
                try writeJsonString(writer, entry.string);
            }
        }
        try writer.writeByte(']');
    }
    if (existing_persona_pack) |value| {
        if (!first) try writer.writeByte(',');
        try writeJsonString(writer, "persona_pack");
        try writer.writeByte(':');
        try writeJsonString(writer, value);
    }
    try writer.writeByte('}');

    const metadata_json = try out.toOwnedSlice(self.allocator);
    defer self.allocator.free(metadata_json);
    try std.fs.cwd().makePath(agent_dir);
    try std.fs.cwd().writeFile(.{
        .sub_path = metadata_path,
        .data = metadata_json,
    });
    return true;
}

fn extractAgentId(obj: std.json.ObjectMap) ?[]const u8 {
    const candidates = [_][]const u8{ "agent_id", "id" };
    inline for (candidates) |field| {
        if (obj.get(field)) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
    }
    return null;
}

fn extractOptionalStringByNames(obj: std.json.ObjectMap, candidate_names: []const []const u8) ?[]const u8 {
    for (candidate_names) |field| {
        if (obj.get(field)) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
    }
    return null;
}

fn isValidManagedAgentId(agent_id: []const u8) bool {
    if (agent_id.len == 0 or agent_id.len > max_agent_id_len) return false;
    if (std.mem.eql(u8, agent_id, ".")) return false;
    for (agent_id) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '_' or char == '-') continue;
        return false;
    }
    return true;
}

fn managedAgentCapabilityName(value: agent_registry.AgentCapability) []const u8 {
    return switch (value) {
        .chat => "chat",
        .code => "code",
        .plan => "plan",
        .research => "research",
    };
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.print("{f}", .{std.json.fmt(value, .{})});
}
