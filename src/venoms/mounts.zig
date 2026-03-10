const std = @import("std");
const unified = @import("spider-protocol").unified;
const control_plane_mod = @import("../acheron/control_plane.zig");

pub const Op = enum {
    list,
    mount,
    mkdir,
    unmount,
    bind,
    unbind,
    resolve,
};

const MountProjectScope = struct {
    project_id: []const u8,
    project_token: ?[]const u8,
};

const local_fs_world_prefix = "/nodes/local/fs";

pub fn seedNamespace(self: anytype, mounts_dir: u32) !void {
    return seedNamespaceAt(self, mounts_dir, "/global/mounts");
}

pub fn seedNamespaceAt(self: anytype, mounts_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"mounts\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        mounts_dir,
        "Mounts and Binds",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"list\",\"mount\",\"mkdir\",\"unmount\",\"bind\",\"unbind\",\"resolve\"],\"discoverable\":true,\"project_scope\":true}",
        "Manage project mounts and path binds through Acheron control files.",
    );
    _ = try self.addFile(
        mounts_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"mount\":\"control/mount.json\",\"mkdir\":\"control/mkdir.json\",\"unmount\":\"control/unmount.json\",\"bind\":\"control/bind.json\",\"unbind\":\"control/unbind.json\",\"resolve\":\"control/resolve.json\"},\"operations\":{\"list\":\"list\",\"mount\":\"mount\",\"mkdir\":\"mkdir\",\"unmount\":\"unmount\",\"bind\":\"bind\",\"unbind\":\"unbind\",\"resolve\":\"resolve\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        mounts_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"project_mounts_binds\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        mounts_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"project\",\"project_token_required\":false}",
        false,
        .none,
    );
    _ = try self.addFile(
        mounts_dir,
        "STATUS.json",
        "{\"venom_id\":\"mounts\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    self.mounts_status_id = try self.addFile(
        mounts_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    const initial_result = try buildListResultJson(self, null, null);
    defer self.allocator.free(initial_result);
    self.mounts_result_id = try self.addFile(
        mounts_dir,
        "result.json",
        initial_result,
        false,
        .none,
    );

    const control_dir = try self.addDir(mounts_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Use list/mount/mkdir/unmount/bind/unbind/resolve operation files, or invoke.json with op plus arguments.\nMount, mkdir, and bind operations require project mount permission.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .mounts_invoke);
    _ = try self.addFile(control_dir, "list.json", "", true, .mounts_list);
    _ = try self.addFile(control_dir, "mount.json", "", true, .mounts_mount);
    _ = try self.addFile(control_dir, "mkdir.json", "", true, .mounts_mkdir);
    _ = try self.addFile(control_dir, "unmount.json", "", true, .mounts_unmount);
    _ = try self.addFile(control_dir, "bind.json", "", true, .mounts_bind);
    _ = try self.addFile(control_dir, "unbind.json", "", true, .mounts_unbind);
    _ = try self.addFile(control_dir, "resolve.json", "", true, .mounts_resolve);
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
        .mounts_list => Op.list,
        .mounts_mount => Op.mount,
        .mounts_mkdir => Op.mkdir,
        .mounts_unmount => Op.unmount,
        .mounts_bind => Op.bind,
        .mounts_unbind => Op.unbind,
        .mounts_resolve => Op.resolve,
        .mounts_invoke => blk: {
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

pub fn normalizeLocalFsRelativePath(self: anytype, raw_path: []const u8) ![]u8 {
    var path = std.mem.trim(u8, raw_path, " \t\r\n");
    if (path.len == 0) return error.InvalidPayload;

    if (std.mem.startsWith(u8, path, local_fs_world_prefix)) {
        path = path[local_fs_world_prefix.len..];
        if (path.len == 0) return error.InvalidPayload;
        if (path[0] != '/') return error.InvalidPayload;
        path = path[1..];
    } else if (path[0] == '/') {
        return error.InvalidPayload;
    }

    var normalized = std.ArrayListUnmanaged(u8){};
    errdefer normalized.deinit(self.allocator);

    var token_it = std.mem.tokenizeAny(u8, path, "/\\");
    var first = true;
    while (token_it.next()) |segment| {
        if (segment.len == 0) continue;
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return error.InvalidPayload;
        if (std.mem.indexOfScalar(u8, segment, ':') != null) return error.InvalidPayload;
        if (!first) try normalized.append(self.allocator, '/');
        first = false;
        try normalized.appendSlice(self.allocator, segment);
    }

    if (normalized.items.len == 0) return error.InvalidPayload;
    return normalized.toOwnedSlice(self.allocator);
}

pub fn ensurePathExists(path: []const u8) !void {
    if (path.len == 0) return error.InvalidPath;
    if (std.fs.path.isAbsolute(path)) {
        var root_dir = try std.fs.openDirAbsolute("/", .{});
        defer root_dir.close();
        const rel_path = std.mem.trimLeft(u8, path, "/");
        if (rel_path.len == 0) return;
        try root_dir.makePath(rel_path);
        return;
    }
    try std.fs.cwd().makePath(path);
}

fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "list")) return .list;
    if (std.mem.eql(u8, value, "mount")) return .mount;
    if (std.mem.eql(u8, value, "mkdir") or std.mem.eql(u8, value, "create_folder")) return .mkdir;
    if (std.mem.eql(u8, value, "unmount")) return .unmount;
    if (std.mem.eql(u8, value, "bind")) return .bind;
    if (std.mem.eql(u8, value, "unbind")) return .unbind;
    if (std.mem.eql(u8, value, "resolve")) return .resolve;
    return null;
}

fn resolveProjectScope(args_obj: std.json.ObjectMap) !MountProjectScope {
    const project_id_raw = extractOptionalStringByNames(args_obj, &[_][]const u8{"project_id"}) orelse
        return error.InvalidPayload;
    const project_id = std.mem.trim(u8, project_id_raw, " \t\r\n");
    if (project_id.len == 0) return error.InvalidPayload;
    return .{
        .project_id = project_id,
        .project_token = extractOptionalStringByNames(args_obj, &[_][]const u8{"project_token"}),
    };
}

fn buildLocalFsWorldPath(allocator: std.mem.Allocator, relative_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ local_fs_world_prefix, relative_path });
}

fn pathExistsAsDirectory(path: []const u8) !bool {
    if (std.fs.path.isAbsolute(path)) {
        var dir = std.fs.openDirAbsolute(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer dir.close();
        return true;
    }

    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer dir.close();
    return true;
}

fn executeOp(self: anytype, op: Op, args_obj: std.json.ObjectMap, written: usize) !usize {
    const status_tool = statusToolName(op);
    const running_status = try self.buildServiceInvokeStatusJson("running", status_tool, null);
    defer self.allocator.free(running_status);
    try self.setMirroredFileContent(self.mounts_status_id, self.mounts_status_alias_id, running_status);

    const result_payload = executeOpPayload(self, op, args_obj) catch |err| {
        const error_message = @errorName(err);
        const code = switch (err) {
            error.AccessDenied => "forbidden",
            else => "invalid_payload",
        };
        const failed_status = try self.buildServiceInvokeStatusJson("failed", status_tool, error_message);
        defer self.allocator.free(failed_status);
        try self.setMirroredFileContent(self.mounts_status_id, self.mounts_status_alias_id, failed_status);
        const failed_result = try buildFailureResultJson(self, op, code, error_message);
        defer self.allocator.free(failed_result);
        try self.setMirroredFileContent(self.mounts_result_id, self.mounts_result_alias_id, failed_result);
        return err;
    };
    defer self.allocator.free(result_payload);

    const done_status = try self.buildServiceInvokeStatusJson("done", status_tool, null);
    defer self.allocator.free(done_status);
    try self.setMirroredFileContent(self.mounts_status_id, self.mounts_status_alias_id, done_status);
    try self.setMirroredFileContent(self.mounts_result_id, self.mounts_result_alias_id, result_payload);
    return written;
}

fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    const scope = try resolveProjectScope(args_obj);
    switch (op) {
        .list => return buildListResultJson(self, scope.project_id, scope.project_token),
        .mount => {
            const node_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"node_id"}) orelse return error.InvalidPayload;
            const export_name = extractOptionalStringByNames(args_obj, &[_][]const u8{"export_name"}) orelse return error.InvalidPayload;
            const mount_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"mount_path"}) orelse return error.InvalidPayload;
            const payload = try buildProjectScopedMountPayload(self, scope.project_id, scope.project_token, node_id, export_name, mount_path);
            defer self.allocator.free(payload);
            const plane = self.control_plane orelse return error.InvalidPayload;
            const result = plane.setProjectMountWithRole(payload, self.is_admin) catch |err| switch (err) {
                control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                control_plane_mod.ControlPlaneError.ProjectProtected,
                control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                => return error.AccessDenied,
                control_plane_mod.ControlPlaneError.MissingField,
                control_plane_mod.ControlPlaneError.InvalidPayload,
                => return error.InvalidPayload,
                else => return err,
            };
            defer self.allocator.free(result);
            try self.refreshProjectBindsFromControlPlane();
            return buildSuccessResultJson(self, op, result);
        },
        .unmount => {
            const mount_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"mount_path"}) orelse return error.InvalidPayload;
            const node_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"node_id"});
            const export_name = extractOptionalStringByNames(args_obj, &[_][]const u8{"export_name"});
            const payload = try buildProjectScopedUnmountPayload(self, scope.project_id, scope.project_token, mount_path, node_id, export_name);
            defer self.allocator.free(payload);
            const plane = self.control_plane orelse return error.InvalidPayload;
            const result = plane.removeProjectMountWithRole(payload, self.is_admin) catch |err| switch (err) {
                control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                control_plane_mod.ControlPlaneError.ProjectProtected,
                control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                => return error.AccessDenied,
                control_plane_mod.ControlPlaneError.MissingField,
                control_plane_mod.ControlPlaneError.InvalidPayload,
                control_plane_mod.ControlPlaneError.MountNotFound,
                => return error.InvalidPayload,
                else => return err,
            };
            defer self.allocator.free(result);
            return buildSuccessResultJson(self, op, result);
        },
        .bind => {
            const bind_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"bind_path"}) orelse return error.InvalidPayload;
            const target_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"target_path"}) orelse return error.InvalidPayload;
            const payload = try buildProjectScopedBindPayload(self, scope.project_id, scope.project_token, bind_path, target_path);
            defer self.allocator.free(payload);
            const plane = self.control_plane orelse return error.InvalidPayload;
            const result = plane.setProjectBindWithRole(payload, self.is_admin) catch |err| switch (err) {
                control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                control_plane_mod.ControlPlaneError.ProjectProtected,
                control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                => return error.AccessDenied,
                control_plane_mod.ControlPlaneError.MissingField,
                control_plane_mod.ControlPlaneError.InvalidPayload,
                control_plane_mod.ControlPlaneError.BindConflict,
                => return error.InvalidPayload,
                else => return err,
            };
            defer self.allocator.free(result);
            try self.refreshProjectBindsFromControlPlane();
            return buildSuccessResultJson(self, op, result);
        },
        .unbind => {
            const bind_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"bind_path"}) orelse return error.InvalidPayload;
            const payload = try buildProjectScopedUnbindPayload(self, scope.project_id, scope.project_token, bind_path);
            defer self.allocator.free(payload);
            const plane = self.control_plane orelse return error.InvalidPayload;
            const result = plane.removeProjectBindWithRole(payload, self.is_admin) catch |err| switch (err) {
                control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                control_plane_mod.ControlPlaneError.ProjectProtected,
                control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                => return error.AccessDenied,
                control_plane_mod.ControlPlaneError.MissingField,
                control_plane_mod.ControlPlaneError.InvalidPayload,
                control_plane_mod.ControlPlaneError.BindNotFound,
                => return error.InvalidPayload,
                else => return err,
            };
            defer self.allocator.free(result);
            try self.refreshProjectBindsFromControlPlane();
            return buildSuccessResultJson(self, op, result);
        },
        .mkdir => {
            const plane = self.control_plane orelse return error.InvalidPayload;
            if (!plane.projectAllowsAction(scope.project_id, self.agent_id, .mount, scope.project_token, self.is_admin)) {
                return error.AccessDenied;
            }
            const path = extractOptionalStringByNames(args_obj, &[_][]const u8{ "path", "folder", "relative_path" }) orelse return error.InvalidPayload;
            const local_root = self.local_fs_export_root orelse return error.InvalidPayload;
            const relative_path = try normalizeLocalFsRelativePath(self, path);
            defer self.allocator.free(relative_path);
            const host_path = try std.fs.path.join(self.allocator, &.{ local_root, relative_path });
            defer self.allocator.free(host_path);

            const exists_before = pathExistsAsDirectory(host_path) catch |err| switch (err) {
                error.NotDir => return error.InvalidPayload,
                else => return err,
            };
            if (!exists_before) {
                ensurePathExists(host_path) catch |err| switch (err) {
                    error.PathAlreadyExists,
                    error.NotDir,
                    error.AccessDenied,
                    => return error.InvalidPayload,
                    else => return err,
                };
            }

            const world_path = try buildLocalFsWorldPath(self.allocator, relative_path);
            defer self.allocator.free(world_path);
            const escaped_world_path = try unified.jsonEscape(self.allocator, world_path);
            defer self.allocator.free(escaped_world_path);
            const detail = try std.fmt.allocPrint(
                self.allocator,
                "{{\"path\":\"{s}\",\"created\":{}}}",
                .{ escaped_world_path, !exists_before },
            );
            defer self.allocator.free(detail);
            return buildSuccessResultJson(self, op, detail);
        },
        .resolve => {
            const path = extractOptionalStringByNames(args_obj, &[_][]const u8{ "path", "mount_path", "bind_path" }) orelse return error.InvalidPayload;
            const payload = try buildProjectScopedResolvePayload(self, scope.project_id, scope.project_token, path);
            defer self.allocator.free(payload);
            const plane = self.control_plane orelse return error.InvalidPayload;
            const result = plane.resolveProjectPathWithRole(payload, self.is_admin) catch |err| switch (err) {
                control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                => return error.AccessDenied,
                control_plane_mod.ControlPlaneError.MissingField,
                control_plane_mod.ControlPlaneError.InvalidPayload,
                => return error.InvalidPayload,
                else => return err,
            };
            defer self.allocator.free(result);
            return buildSuccessResultJson(self, op, result);
        },
    }
}

fn buildProjectScopedMountPayload(
    self: anytype,
    project_id: []const u8,
    project_token: ?[]const u8,
    node_id: []const u8,
    export_name: []const u8,
    mount_path: []const u8,
) ![]u8 {
    const escaped_project = try unified.jsonEscape(self.allocator, project_id);
    defer self.allocator.free(escaped_project);
    const escaped_node = try unified.jsonEscape(self.allocator, node_id);
    defer self.allocator.free(escaped_node);
    const escaped_export = try unified.jsonEscape(self.allocator, export_name);
    defer self.allocator.free(escaped_export);
    const escaped_path = try unified.jsonEscape(self.allocator, mount_path);
    defer self.allocator.free(escaped_path);
    const token_fragment = if (project_token) |token| blk: {
        const escaped_token = try unified.jsonEscape(self.allocator, token);
        defer self.allocator.free(escaped_token);
        break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(token_fragment);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"project_id\":\"{s}\",{s}\"node_id\":\"{s}\",\"export_name\":\"{s}\",\"mount_path\":\"{s}\"}}",
        .{ escaped_project, token_fragment, escaped_node, escaped_export, escaped_path },
    );
}

fn buildProjectScopedBindPayload(self: anytype, project_id: []const u8, project_token: ?[]const u8, bind_path: []const u8, target_path: []const u8) ![]u8 {
    const escaped_project = try unified.jsonEscape(self.allocator, project_id);
    defer self.allocator.free(escaped_project);
    const escaped_bind = try unified.jsonEscape(self.allocator, bind_path);
    defer self.allocator.free(escaped_bind);
    const escaped_target = try unified.jsonEscape(self.allocator, target_path);
    defer self.allocator.free(escaped_target);
    const token_fragment = if (project_token) |token| blk: {
        const escaped_token = try unified.jsonEscape(self.allocator, token);
        defer self.allocator.free(escaped_token);
        break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(token_fragment);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"project_id\":\"{s}\",{s}\"bind_path\":\"{s}\",\"target_path\":\"{s}\"}}",
        .{ escaped_project, token_fragment, escaped_bind, escaped_target },
    );
}

fn buildProjectScopedUnbindPayload(self: anytype, project_id: []const u8, project_token: ?[]const u8, bind_path: []const u8) ![]u8 {
    const escaped_project = try unified.jsonEscape(self.allocator, project_id);
    defer self.allocator.free(escaped_project);
    const escaped_bind = try unified.jsonEscape(self.allocator, bind_path);
    defer self.allocator.free(escaped_bind);
    const token_fragment = if (project_token) |token| blk: {
        const escaped_token = try unified.jsonEscape(self.allocator, token);
        defer self.allocator.free(escaped_token);
        break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(token_fragment);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"project_id\":\"{s}\",{s}\"bind_path\":\"{s}\"}}",
        .{ escaped_project, token_fragment, escaped_bind },
    );
}

fn buildProjectScopedResolvePayload(self: anytype, project_id: []const u8, project_token: ?[]const u8, path: []const u8) ![]u8 {
    const escaped_project = try unified.jsonEscape(self.allocator, project_id);
    defer self.allocator.free(escaped_project);
    const escaped_path = try unified.jsonEscape(self.allocator, path);
    defer self.allocator.free(escaped_path);
    const token_fragment = if (project_token) |token| blk: {
        const escaped_token = try unified.jsonEscape(self.allocator, token);
        defer self.allocator.free(escaped_token);
        break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(token_fragment);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"project_id\":\"{s}\",{s}\"path\":\"{s}\"}}",
        .{ escaped_project, token_fragment, escaped_path },
    );
}

fn buildProjectScopedUnmountPayload(
    self: anytype,
    project_id: []const u8,
    project_token: ?[]const u8,
    mount_path: []const u8,
    node_id: ?[]const u8,
    export_name: ?[]const u8,
) ![]u8 {
    const escaped_project = try unified.jsonEscape(self.allocator, project_id);
    defer self.allocator.free(escaped_project);
    const escaped_mount = try unified.jsonEscape(self.allocator, mount_path);
    defer self.allocator.free(escaped_mount);
    const token_fragment = if (project_token) |token| blk: {
        const escaped_token = try unified.jsonEscape(self.allocator, token);
        defer self.allocator.free(escaped_token);
        break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(token_fragment);
    const node_fragment = if (node_id) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, ",\"node_id\":\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(node_fragment);
    const export_fragment = if (export_name) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, ",\"export_name\":\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(export_fragment);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"project_id\":\"{s}\",{s}\"mount_path\":\"{s}\"{s}{s}}}",
        .{ escaped_project, token_fragment, escaped_mount, node_fragment, export_fragment },
    );
}

fn buildSuccessResultJson(self: anytype, op: Op, detail_json: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
        .{ escaped_operation, detail_json },
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
        .mount => "mount",
        .mkdir => "mkdir",
        .unmount => "unmount",
        .bind => "bind",
        .unbind => "unbind",
        .resolve => "resolve",
    };
}

fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .list => "mounts_list",
        .mount => "mounts_mount",
        .mkdir => "mounts_mkdir",
        .unmount => "mounts_unmount",
        .bind => "mounts_bind",
        .unbind => "mounts_unbind",
        .resolve => "mounts_resolve",
    };
}

fn buildListResultJson(self: anytype, project_id_override: ?[]const u8, project_token_override: ?[]const u8) ![]u8 {
    const plane = self.control_plane orelse return buildSuccessResultJson(self, .list, "{\"project_id\":null,\"mounts\":[],\"binds\":[]}");
    const project_id = project_id_override orelse self.project_id orelse return buildSuccessResultJson(self, .list, "{\"project_id\":null,\"mounts\":[],\"binds\":[]}");
    const project_token = if (project_token_override) |value| value else self.project_token;
    const escaped_project = try unified.jsonEscape(self.allocator, project_id);
    defer self.allocator.free(escaped_project);
    const payload = if (project_token) |token| blk: {
        const escaped_token = try unified.jsonEscape(self.allocator, token);
        defer self.allocator.free(escaped_token);
        break :blk try std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
            .{ escaped_project, escaped_token },
        );
    } else try std.fmt.allocPrint(self.allocator, "{{\"project_id\":\"{s}\"}}", .{escaped_project});
    defer self.allocator.free(payload);

    const mounts_json = plane.listProjectMountsWithRole(payload, self.is_admin) catch |err| switch (err) {
        control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
        control_plane_mod.ControlPlaneError.ProjectAuthFailed,
        control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
        => return error.AccessDenied,
        else => return err,
    };
    defer self.allocator.free(mounts_json);
    const binds_json = plane.listProjectBindsWithRole(payload, self.is_admin) catch |err| switch (err) {
        control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
        control_plane_mod.ControlPlaneError.ProjectAuthFailed,
        control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
        => return error.AccessDenied,
        else => return err,
    };
    defer self.allocator.free(binds_json);

    const mounts_array = try extractObjectArrayJson(self.allocator, mounts_json, "mounts");
    defer self.allocator.free(mounts_array);
    const binds_array = try extractObjectArrayJson(self.allocator, binds_json, "binds");
    defer self.allocator.free(binds_array);
    const result_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"project_id\":\"{s}\",\"mounts\":{s},\"binds\":{s}}}",
        .{ escaped_project, mounts_array, binds_array },
    );
    defer self.allocator.free(result_json);
    return buildSuccessResultJson(self, .list, result_json);
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
