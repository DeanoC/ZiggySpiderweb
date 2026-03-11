const std = @import("std");
const unified = @import("spider-protocol").unified;
const control_plane_mod = @import("../acheron/control_plane.zig");

pub const Op = enum {
    list,
    get,
    up,
};

pub fn seedNamespace(self: anytype, workspaces_dir: u32) !void {
    return seedNamespaceAt(self, workspaces_dir, "/global/workspaces");
}

pub fn seedNamespaceAt(self: anytype, workspaces_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"workspaces\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        workspaces_dir,
        "Workspace Management",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"workspaces_list\",\"workspaces_get\",\"workspaces_up\"],\"discoverable\":true}",
        "List, inspect, and create/update workspaces through Acheron control files.",
    );
    _ = try self.addFile(
        workspaces_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"get\":\"control/get.json\",\"up\":\"control/up.json\"},\"operations\":{\"list\":\"workspaces_list\",\"get\":\"workspaces_get\",\"up\":\"workspaces_up\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        workspaces_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"control_plane_workspaces\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        workspaces_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"workspace_control_plane\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        workspaces_dir,
        "STATUS.json",
        "{\"venom_id\":\"workspaces\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    self.projects_status_id = try self.addFile(
        workspaces_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    const initial_result = try buildListResultJson(self);
    defer self.allocator.free(initial_result);
    self.projects_result_id = try self.addFile(
        workspaces_dir,
        "result.json",
        initial_result,
        false,
        .none,
    );

    const control_dir = try self.addDir(workspaces_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Use list/get/up operation files, or invoke.json with op=list|get|up plus arguments. For Mother bootstrap provisioning, use up with activate=false.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .projects_invoke);
    _ = try self.addFile(control_dir, "list.json", "", true, .projects_list);
    _ = try self.addFile(control_dir, "get.json", "", true, .projects_get);
    _ = try self.addFile(control_dir, "up.json", "", true, .projects_up);
}

pub fn handleNamespaceWrite(self: anytype, special: anytype, node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    const payload = if (input.len == 0) "{}" else input;
    try self.setFileContent(node_id, payload);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const op = switch (special) {
        .projects_list => Op.list,
        .projects_get => Op.get,
        .projects_up => Op.up,
        .projects_invoke => blk: {
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

fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "workspaces_list") or std.mem.eql(u8, value, "projects_list")) return .list;
    if (std.mem.eql(u8, value, "get") or std.mem.eql(u8, value, "workspaces_get") or std.mem.eql(u8, value, "projects_get")) return .get;
    if (std.mem.eql(u8, value, "up") or std.mem.eql(u8, value, "workspace_up") or std.mem.eql(u8, value, "workspaces_up") or std.mem.eql(u8, value, "project_up") or std.mem.eql(u8, value, "projects_up")) return .up;
    return null;
}

fn executeOp(self: anytype, op: Op, args_obj: std.json.ObjectMap, written: usize) !usize {
    const tool_name = statusToolName(op);
    const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
    defer self.allocator.free(running_status);
    if (self.projects_status_id != 0) try self.setFileContent(self.projects_status_id, running_status);

    const result_payload = executeOpPayload(self, op, args_obj) catch |err| {
        const error_message = @errorName(err);
        const error_code = switch (err) {
            error.AccessDenied => "forbidden",
            else => "invalid_payload",
        };
        const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
        defer self.allocator.free(failed_status);
        if (self.projects_status_id != 0) try self.setFileContent(self.projects_status_id, failed_status);
        const failed_result = try buildFailureResultJson(self, op, error_code, error_message);
        defer self.allocator.free(failed_result);
        if (self.projects_result_id != 0) try self.setFileContent(self.projects_result_id, failed_result);
        return err;
    };
    defer self.allocator.free(result_payload);

    const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
    defer self.allocator.free(done_status);
    if (self.projects_status_id != 0) try self.setFileContent(self.projects_status_id, done_status);
    if (self.projects_result_id != 0) try self.setFileContent(self.projects_result_id, result_payload);
    return written;
}

fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    const plane = self.control_plane orelse return error.InvalidPayload;
    return switch (op) {
        .list => buildListResultJson(self),
        .get => blk: {
            const workspace_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "workspace_id", "project_id", "id" }) orelse return error.InvalidPayload;
            const escaped_project = try unified.jsonEscape(self.allocator, workspace_id);
            defer self.allocator.free(escaped_project);
            const token_fragment = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"project_token"})) |token| blk2: {
                const escaped = try unified.jsonEscape(self.allocator, token);
                defer self.allocator.free(escaped);
                break :blk2 try std.fmt.allocPrint(self.allocator, ",\"project_token\":\"{s}\"", .{escaped});
            } else if (self.project_token) |token| blk2: {
                const escaped = try unified.jsonEscape(self.allocator, token);
                defer self.allocator.free(escaped);
                break :blk2 try std.fmt.allocPrint(self.allocator, ",\"project_token\":\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "");
            defer self.allocator.free(token_fragment);
            const payload = try std.fmt.allocPrint(
                self.allocator,
                "{{\"project_id\":\"{s}\"{s}}}",
                .{ escaped_project, token_fragment },
            );
            defer self.allocator.free(payload);
            const result = plane.getProjectWithRole(payload, self.is_admin) catch |err| switch (err) {
                control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                => return error.AccessDenied,
                control_plane_mod.ControlPlaneError.MissingField,
                control_plane_mod.ControlPlaneError.InvalidPayload,
                control_plane_mod.ControlPlaneError.ProjectNotFound,
                => return error.InvalidPayload,
                else => return err,
            };
            defer self.allocator.free(result);
            break :blk buildSuccessResultJson(self, .get, result);
        },
        .up => blk: {
            const payload = try renderWorkspaceUpPayload(self, args_obj);
            defer self.allocator.free(payload);
            const result = plane.projectUpWithRole(self.agent_id, payload, self.is_admin) catch |err| switch (err) {
                control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                control_plane_mod.ControlPlaneError.ProjectProtected,
                => return error.AccessDenied,
                control_plane_mod.ControlPlaneError.MissingField,
                control_plane_mod.ControlPlaneError.InvalidPayload,
                control_plane_mod.ControlPlaneError.ProjectNotFound,
                control_plane_mod.ControlPlaneError.NodeNotFound,
                control_plane_mod.ControlPlaneError.MountConflict,
                => return error.InvalidPayload,
                else => return err,
            };
            defer self.allocator.free(result);
            break :blk buildSuccessResultJson(self, .up, result);
        },
    };
}

fn renderWorkspaceUpPayload(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const has_explicit_project_id = args_obj.get("project_id") != null;

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeByte('{');
    var first = true;

    var it = args_obj.iterator();
    while (it.next()) |entry| {
        const original_key = entry.key_ptr.*;
        if (std.mem.eql(u8, original_key, "workspace_id") and has_explicit_project_id) continue;
        const key = if (std.mem.eql(u8, original_key, "workspace_id")) "project_id" else original_key;
        if (!first) try writer.writeByte(',');
        first = false;
        try writeJsonString(writer, key);
        try writer.writeByte(':');
        try writer.print("{f}", .{std.json.fmt(entry.value_ptr.*, .{})});
    }

    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

fn buildListResultJson(self: anytype) ![]u8 {
    const plane = self.control_plane orelse return buildSuccessResultJson(self, .list, "{\"workspaces\":[]}");
    const result = try plane.listProjects();
    defer self.allocator.free(result);
    const workspaces_array = try extractObjectArrayJson(self.allocator, result, "projects");
    defer self.allocator.free(workspaces_array);
    const payload = try std.fmt.allocPrint(
        self.allocator,
        "{{\"workspaces\":{s}}}",
        .{workspaces_array},
    );
    defer self.allocator.free(payload);
    return buildSuccessResultJson(self, .list, payload);
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

fn operationName(op: Op) []const u8 {
    return switch (op) {
        .list => "list",
        .get => "get",
        .up => "up",
    };
}

fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .list => "workspaces_list",
        .get => "workspaces_get",
        .up => "workspaces_up",
    };
}

fn extractObjectArrayJson(allocator: std.mem.Allocator, json_text: []const u8, field_name: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch {
        return allocator.dupe(u8, "[]");
    };
    defer parsed.deinit();
    if (parsed.value != .object) return allocator.dupe(u8, "[]");
    const field = parsed.value.object.get(field_name) orelse return allocator.dupe(u8, "[]");
    if (field != .array) return allocator.dupe(u8, "[]");
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(field, .{})});
}

fn extractOptionalStringByNames(
    obj: std.json.ObjectMap,
    candidate_names: []const []const u8,
) ?[]const u8 {
    for (candidate_names) |field| {
        if (obj.get(field)) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
    }
    return null;
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |char| {
        switch (char) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => if (char < 0x20) {
                try writer.print("\\u00{x:0>2}", .{char});
            } else {
                try writer.writeByte(char);
            },
        }
    }
    try writer.writeByte('"');
}
