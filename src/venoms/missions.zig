const std = @import("std");
const unified = @import("spider-protocol").unified;
const mission_store_mod = @import("../mission_store.zig");
const mounts_venom = @import("./mounts.zig");

const ParsedNodeVenomServicePath = struct {
    node_id: []const u8,
    venom_id: []const u8,
};

pub const Op = enum {
    create,
    list,
    get,
    heartbeat,
    checkpoint,
    bootstrap_contract,
    invoke_service,
    recover,
    request_approval,
    approve,
    reject,
    @"resume",
    block,
    complete,
    fail,
    cancel,
};

pub fn seedNamespace(self: anytype, missions_dir: u32) !void {
    return seedNamespaceAt(self, missions_dir, "/global/missions");
}

pub fn seedNamespaceAt(self: anytype, missions_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"missions\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        missions_dir,
        "Missions",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"missions_create\",\"missions_list\",\"missions_get\",\"missions_heartbeat\",\"missions_checkpoint\",\"missions_bootstrap_contract\",\"missions_invoke_service\",\"missions_recover\",\"missions_request_approval\",\"missions_approve\",\"missions_reject\",\"missions_resume\",\"missions_block\",\"missions_complete\",\"missions_fail\",\"missions_cancel\"],\"discoverable\":true,\"persistent\":true}",
        "Long-running mission records. Create/list/get missions, invoke workspace services through mission steps, request approvals, and track recovery/state transitions.",
    );
    _ = try self.addFile(
        missions_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"create\":\"control/create.json\",\"list\":\"control/list.json\",\"get\":\"control/get.json\",\"heartbeat\":\"control/heartbeat.json\",\"checkpoint\":\"control/checkpoint.json\",\"bootstrap_contract\":\"control/bootstrap_contract.json\",\"invoke_service\":\"control/invoke_service.json\",\"recover\":\"control/recover.json\",\"request_approval\":\"control/request_approval.json\",\"approve\":\"control/approve.json\",\"reject\":\"control/reject.json\",\"resume\":\"control/resume.json\",\"block\":\"control/block.json\",\"complete\":\"control/complete.json\",\"fail\":\"control/fail.json\",\"cancel\":\"control/cancel.json\"},\"operations\":{\"create\":\"create\",\"list\":\"list\",\"get\":\"get\",\"heartbeat\":\"heartbeat\",\"checkpoint\":\"checkpoint\",\"bootstrap_contract\":\"bootstrap_contract\",\"invoke_service\":\"invoke_service\",\"recover\":\"recover\",\"request_approval\":\"request_approval\",\"approve\":\"approve\",\"reject\":\"reject\",\"resume\":\"resume\",\"block\":\"block\",\"complete\":\"complete\",\"fail\":\"fail\",\"cancel\":\"cancel\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        missions_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"mission_store\",\"subject\":\"missions\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        missions_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\",\"admin_actions\":[\"approve\",\"reject\"]}",
        false,
        .none,
    );
    _ = try self.addFile(
        missions_dir,
        "STATUS.json",
        "{\"venom_id\":\"missions\",\"state\":\"namespace\",\"has_invoke\":true,\"persistent\":true}",
        false,
        .none,
    );
    self.missions_status_id = try self.addFile(
        missions_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    self.missions_result_id = try self.addFile(
        missions_dir,
        "result.json",
        "{\"ok\":false,\"result\":null,\"error\":null}",
        false,
        .none,
    );

    const control_dir = try self.addDir(missions_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Write JSON payloads to mission control files. invoke.json accepts op=create|list|get|heartbeat|checkpoint|bootstrap_contract|invoke_service|recover|request_approval|approve|reject|resume|block|complete|fail|cancel envelopes.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .missions_invoke);
    _ = try self.addFile(control_dir, "bootstrap_contract.json", "", true, .missions_bootstrap_contract);
    _ = try self.addFile(control_dir, "invoke_service.json", "", true, .missions_invoke_service);
    _ = try self.addFile(control_dir, "create.json", "", true, .missions_create);
    _ = try self.addFile(control_dir, "list.json", "", true, .missions_list);
    _ = try self.addFile(control_dir, "get.json", "", true, .missions_get);
    _ = try self.addFile(control_dir, "heartbeat.json", "", true, .missions_heartbeat);
    _ = try self.addFile(control_dir, "checkpoint.json", "", true, .missions_checkpoint);
    _ = try self.addFile(control_dir, "recover.json", "", true, .missions_recover);
    _ = try self.addFile(control_dir, "request_approval.json", "", true, .missions_request_approval);
    _ = try self.addFile(control_dir, "approve.json", "", true, .missions_approve);
    _ = try self.addFile(control_dir, "reject.json", "", true, .missions_reject);
    _ = try self.addFile(control_dir, "resume.json", "", true, .missions_resume);
    _ = try self.addFile(control_dir, "block.json", "", true, .missions_block);
    _ = try self.addFile(control_dir, "complete.json", "", true, .missions_complete);
    _ = try self.addFile(control_dir, "fail.json", "", true, .missions_fail);
    _ = try self.addFile(control_dir, "cancel.json", "", true, .missions_cancel);
}

pub fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "create") or std.mem.eql(u8, value, "missions_create")) return .create;
    if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "missions_list")) return .list;
    if (std.mem.eql(u8, value, "get") or std.mem.eql(u8, value, "missions_get")) return .get;
    if (std.mem.eql(u8, value, "heartbeat") or std.mem.eql(u8, value, "missions_heartbeat")) return .heartbeat;
    if (std.mem.eql(u8, value, "checkpoint") or std.mem.eql(u8, value, "missions_checkpoint")) return .checkpoint;
    if (std.mem.eql(u8, value, "bootstrap_contract") or std.mem.eql(u8, value, "missions_bootstrap_contract")) return .bootstrap_contract;
    if (std.mem.eql(u8, value, "invoke_service") or std.mem.eql(u8, value, "missions_invoke_service")) return .invoke_service;
    if (std.mem.eql(u8, value, "recover") or std.mem.eql(u8, value, "missions_recover")) return .recover;
    if (std.mem.eql(u8, value, "request_approval") or std.mem.eql(u8, value, "missions_request_approval")) return .request_approval;
    if (std.mem.eql(u8, value, "approve") or std.mem.eql(u8, value, "missions_approve")) return .approve;
    if (std.mem.eql(u8, value, "reject") or std.mem.eql(u8, value, "missions_reject")) return .reject;
    if (std.mem.eql(u8, value, "resume") or std.mem.eql(u8, value, "missions_resume")) return .@"resume";
    if (std.mem.eql(u8, value, "block") or std.mem.eql(u8, value, "missions_block")) return .block;
    if (std.mem.eql(u8, value, "complete") or std.mem.eql(u8, value, "missions_complete")) return .complete;
    if (std.mem.eql(u8, value, "fail") or std.mem.eql(u8, value, "missions_fail")) return .fail;
    if (std.mem.eql(u8, value, "cancel") or std.mem.eql(u8, value, "missions_cancel")) return .cancel;
    return null;
}

pub fn operationName(op: Op) []const u8 {
    return switch (op) {
        .create => "create",
        .list => "list",
        .get => "get",
        .heartbeat => "heartbeat",
        .checkpoint => "checkpoint",
        .bootstrap_contract => "bootstrap_contract",
        .invoke_service => "invoke_service",
        .recover => "recover",
        .request_approval => "request_approval",
        .approve => "approve",
        .reject => "reject",
        .@"resume" => "resume",
        .block => "block",
        .complete => "complete",
        .fail => "fail",
        .cancel => "cancel",
    };
}

pub fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .create => "missions_create",
        .list => "missions_list",
        .get => "missions_get",
        .heartbeat => "missions_heartbeat",
        .checkpoint => "missions_checkpoint",
        .bootstrap_contract => "missions_bootstrap_contract",
        .invoke_service => "missions_invoke_service",
        .recover => "missions_recover",
        .request_approval => "missions_request_approval",
        .approve => "missions_approve",
        .reject => "missions_reject",
        .@"resume" => "missions_resume",
        .block => "missions_block",
        .complete => "missions_complete",
        .fail => "missions_fail",
        .cancel => "missions_cancel",
    };
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
        .missions_create => Op.create,
        .missions_list => Op.list,
        .missions_get => Op.get,
        .missions_heartbeat => Op.heartbeat,
        .missions_checkpoint => Op.checkpoint,
        .missions_bootstrap_contract => Op.bootstrap_contract,
        .missions_invoke_service => Op.invoke_service,
        .missions_recover => Op.recover,
        .missions_request_approval => Op.request_approval,
        .missions_approve => Op.approve,
        .missions_reject => Op.reject,
        .missions_resume => Op.@"resume",
        .missions_block => Op.block,
        .missions_complete => Op.complete,
        .missions_fail => Op.fail,
        .missions_cancel => Op.cancel,
        .missions_invoke => blk: {
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

pub fn executeOp(self: anytype, op: Op, args_obj: std.json.ObjectMap, written: usize) !usize {
    const tool_name = statusToolName(op);
    const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
    defer self.allocator.free(running_status);
    try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, running_status);

    const result_payload = executeOpPayload(self, op, args_obj) catch |err| {
        const error_message = @errorName(err);
        const error_code = switch (err) {
            error.AccessDenied => "forbidden",
            error.NotFound => "mission_not_found",
            else => "invalid_payload",
        };
        const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
        defer self.allocator.free(failed_status);
        try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, failed_status);
        const failed_result = try buildMissionFailureResultJson(self, op, error_code, error_message);
        defer self.allocator.free(failed_result);
        try self.setMirroredFileContent(self.missions_result_id, self.missions_result_alias_id, failed_result);
        return err;
    };
    defer self.allocator.free(result_payload);

    if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
        defer self.allocator.free(message);
        const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
        defer self.allocator.free(failed_status);
        try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, failed_status);
    } else {
        const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
        defer self.allocator.free(done_status);
        try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, done_status);
    }
    try self.setMirroredFileContent(self.missions_result_id, self.missions_result_alias_id, result_payload);
    return written;
}

pub fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    return switch (op) {
        .create => blk: {
            const use_case = extractOptionalStringByNames(args_obj, &[_][]const u8{ "use_case", "kind" }) orelse return error.InvalidPayload;
            const allow_override = self.is_admin or std.mem.eql(u8, self.agent_id, "mother");
            const agent_id = if (allow_override)
                extractOptionalStringByNames(args_obj, &[_][]const u8{"agent_id"})
            else
                self.agent_id;
            const project_id = if (allow_override)
                extractOptionalStringByNames(args_obj, &[_][]const u8{"project_id"})
            else
                self.project_id;
            var created = try store.create(self.allocator, .{
                .use_case = use_case,
                .title = extractOptionalStringByNames(args_obj, &[_][]const u8{ "title", "name" }),
                .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}),
                .agent_id = agent_id,
                .project_id = project_id,
                .run_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"run_id"}),
                .workspace_root = extractOptionalStringByNames(args_obj, &[_][]const u8{"workspace_root"}),
                .worktree_name = extractOptionalStringByNames(args_obj, &[_][]const u8{"worktree_name"}),
                .contract = try self.parseMissionContractInput(args_obj),
                .created_by = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
            });
            defer created.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(created);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(
                self.allocator,
                "{{\"mission\":{s}}}",
                .{mission_json},
            );
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(.create, detail);
        },
        .list => blk: {
            const state_filter = blk2: {
                const raw = extractOptionalStringByNames(args_obj, &[_][]const u8{"state"}) orelse break :blk2 null;
                break :blk2 mission_store_mod.parseMissionState(raw) orelse return error.InvalidPayload;
            };
            const missions = try store.listOwned(self.allocator, .{
                .state = state_filter,
                .use_case = extractOptionalStringByNames(args_obj, &[_][]const u8{"use_case"}),
                .agent_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"agent_id"}),
                .project_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"project_id"}),
            });
            defer mission_store_mod.deinitMissionList(self.allocator, missions);
            const inventory = try self.buildMissionListJson(missions);
            defer self.allocator.free(inventory);
            break :blk self.buildMissionSuccessResultJson(.list, inventory);
        },
        .get => blk: {
            const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
            var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
            defer mission.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(self.allocator, "{{\"mission\":{s}}}", .{mission_json});
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(.get, detail);
        },
        .heartbeat => blk: {
            const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
            var mission = store.recordHeartbeat(
                self.allocator,
                mission_id,
                extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}),
            ) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                else => return error.InvalidPayload,
            };
            defer mission.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(self.allocator, "{{\"mission\":{s}}}", .{mission_json});
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(.heartbeat, detail);
        },
        .checkpoint => blk: {
            const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
            const artifact_input = if (args_obj.get("artifact")) |value| blk2: {
                if (value != .object) return error.InvalidPayload;
                const kind = extractOptionalStringByNames(value.object, &[_][]const u8{"kind"}) orelse return error.InvalidPayload;
                break :blk2 mission_store_mod.MissionArtifactInput{
                    .kind = kind,
                    .path = extractOptionalStringByNames(value.object, &[_][]const u8{"path"}),
                    .summary = extractOptionalStringByNames(value.object, &[_][]const u8{"summary"}),
                };
            } else null;
            var mission = store.recordCheckpoint(self.allocator, mission_id, .{
                .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}),
                .summary = extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}),
                .artifact = artifact_input,
                .contract = try self.parseMissionContractUpdateInput(args_obj),
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                else => return error.InvalidPayload,
            };
            defer mission.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(self.allocator, "{{\"mission\":{s}}}", .{mission_json});
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(.checkpoint, detail);
        },
        .bootstrap_contract => executeBootstrapContractOp(self, args_obj),
        .invoke_service => executeInvokeServiceOp(self, args_obj),
        .recover => blk: {
            const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
            const reason = extractOptionalStringByNames(args_obj, &[_][]const u8{ "reason", "message" }) orelse return error.InvalidPayload;
            var mission = store.recordRecovery(self.allocator, mission_id, .{
                .reason = reason,
                .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}),
                .summary = extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}),
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                else => return error.InvalidPayload,
            };
            defer mission.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(self.allocator, "{{\"mission\":{s}}}", .{mission_json});
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(.recover, detail);
        },
        .request_approval => blk: {
            const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
            const action_kind = extractOptionalStringByNames(args_obj, &[_][]const u8{ "action_kind", "action" }) orelse return error.InvalidPayload;
            const message = extractOptionalStringByNames(args_obj, &[_][]const u8{ "message", "reason" }) orelse return error.InvalidPayload;
            const payload_json = if (args_obj.get("payload")) |value|
                try self.renderJsonValue(value)
            else
                null;
            defer if (payload_json) |value| self.allocator.free(value);
            var mission = store.requestApproval(self.allocator, mission_id, .{
                .action_kind = action_kind,
                .message = message,
                .payload_json = payload_json,
                .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}),
                .requested_by = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                mission_store_mod.MissionStoreError.ApprovalPending => return error.InvalidPayload,
                else => return error.InvalidPayload,
            };
            defer mission.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(self.allocator, "{{\"mission\":{s}}}", .{mission_json});
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(.request_approval, detail);
        },
        .approve, .reject => blk: {
            if (!self.is_admin) return error.AccessDenied;
            const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
            var mission = store.resolveApproval(self.allocator, mission_id, op == .approve, .{
                .note = extractOptionalStringByNames(args_obj, &[_][]const u8{ "note", "message" }),
                .resolved_by = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                mission_store_mod.MissionStoreError.ApprovalNotPending => return error.InvalidPayload,
                else => return error.InvalidPayload,
            };
            defer mission.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(self.allocator, "{{\"mission\":{s}}}", .{mission_json});
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(op, detail);
        },
        .@"resume", .block, .complete, .fail, .cancel => blk: {
            const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
            const next_state: mission_store_mod.MissionState = switch (op) {
                .@"resume" => .running,
                .block => .blocked,
                .complete => .completed,
                .fail => .failed,
                .cancel => .cancelled,
                else => unreachable,
            };
            var mission = store.transition(self.allocator, mission_id, .{
                .next_state = next_state,
                .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}),
                .reason = extractOptionalStringByNames(args_obj, &[_][]const u8{ "reason", "message" }),
                .summary = extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}),
                .contract = try self.parseMissionContractUpdateInput(args_obj),
                .actor = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                else => return error.InvalidPayload,
            };
            defer mission.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try std.fmt.allocPrint(self.allocator, "{{\"mission\":{s}}}", .{mission_json});
            defer self.allocator.free(detail);
            break :blk self.buildMissionSuccessResultJson(op, detail);
        },
    };
}

fn executeInvokeServiceOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
    var existing = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer existing.deinit(self.allocator);

    const service_path = try self.normalizeMissionAbsolutePath(
        extractOptionalStringByNames(args_obj, &[_][]const u8{ "service_path", "venom_path" }) orelse return error.InvalidPayload,
    );
    defer self.allocator.free(service_path);

    const invoke_path = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"invoke_path"})) |raw|
        try self.normalizeMissionAbsolutePath(raw)
    else
        self.deriveMissionServiceInvokePath(service_path) catch |err| switch (err) {
            error.NotFound => try self.pathWithInvokeSuffix(service_path),
            else => return err,
        };
    defer self.allocator.free(invoke_path);

    const request_payload = try self.buildMissionServiceInvokeRequestPayload(args_obj);
    defer self.allocator.free(request_payload);

    const status_path = try self.pathWithInvokeTarget(service_path, "status.json");
    defer self.allocator.free(status_path);
    const result_path = try self.pathWithInvokeTarget(service_path, "result.json");
    defer self.allocator.free(result_path);

    var write_error = try self.writeInternalPath(invoke_path, request_payload);
    defer if (write_error) |*value| value.deinit(self.allocator);

    const status_payload = if (write_error == null)
        try self.tryReadInternalPath(status_path)
    else
        null;
    defer if (status_payload) |value| self.allocator.free(value);
    const service_result_payload = if (write_error == null)
        try self.tryReadInternalPath(result_path)
    else
        null;
    defer if (service_result_payload) |value| self.allocator.free(value);

    const effective_result_payload = blk: {
        if (write_error) |value| break :blk try self.buildServiceInvokeFailureResultJson(value.code, value.message);
        if (service_result_payload) |value| break :blk try self.allocator.dupe(u8, value);
        break :blk try self.buildServiceInvokeFailureResultJson("missing_result", "service produced no result payload");
    };
    defer self.allocator.free(effective_result_payload);

    const artifact_path = if (args_obj.get("artifact")) |value| blk: {
        if (value != .object) return error.InvalidPayload;
        break :blk if (extractOptionalStringByNames(value.object, &[_][]const u8{"path"})) |raw_path|
            try self.normalizeMissionAbsolutePath(raw_path)
        else
            try self.allocator.dupe(u8, result_path);
    } else try self.allocator.dupe(u8, result_path);
    defer self.allocator.free(artifact_path);

    const artifact_summary = if (args_obj.get("artifact")) |value| blk: {
        if (value != .object) return error.InvalidPayload;
        break :blk extractOptionalStringByNames(value.object, &[_][]const u8{"summary"});
    } else extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"});

    const artifact_kind = if (args_obj.get("artifact")) |value| blk: {
        if (value != .object) return error.InvalidPayload;
        break :blk extractOptionalStringByNames(value.object, &[_][]const u8{"kind"}) orelse "service_result";
    } else "service_result";

    var mission = store.recordServiceInvocation(self.allocator, mission_id, .{
        .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}),
        .summary = extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}),
        .service_path = service_path,
        .invoke_path = invoke_path,
        .request_payload_json = request_payload,
        .result_payload_json = effective_result_payload,
        .status_payload_json = status_payload,
        .artifact = .{
            .kind = artifact_kind,
            .path = artifact_path,
            .summary = artifact_summary,
        },
        .contract = try self.parseMissionContractUpdateInput(args_obj),
        .actor = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
    }) catch |err| switch (err) {
        mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
        else => return error.InvalidPayload,
    };
    defer mission.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(mission);
    defer self.allocator.free(mission_json);
    const detail = try self.buildMissionServiceInvocationDetailJson(
        mission_json,
        service_path,
        invoke_path,
        request_payload,
        effective_result_payload,
        status_payload,
    );
    defer self.allocator.free(detail);

    if (try self.extractErrorInfoFromToolPayload(effective_result_payload)) |service_error| {
        var owned_service_error = service_error;
        defer owned_service_error.deinit(self.allocator);
        return self.buildMissionPartialFailureResultJson(
            .invoke_service,
            detail,
            owned_service_error.code,
            owned_service_error.message,
        );
    }
    return self.buildMissionSuccessResultJson(.invoke_service, detail);
}

fn executeBootstrapContractOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
    var existing = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer existing.deinit(self.allocator);

    const contract = try self.resolveMissionBootstrapContract(existing, args_obj);

    const context_payload = if (args_obj.get("context")) |value|
        try self.renderJsonValue(value)
    else
        return error.InvalidPayload;
    defer self.allocator.free(context_payload);

    const state_payload = if (args_obj.get("state")) |value|
        try self.renderJsonValue(value)
    else
        return error.InvalidPayload;
    defer self.allocator.free(state_payload);

    try ensureContractDirectory(self, contract.artifact_root);
    try writeContractFile(self, contract.context_path, context_payload);
    try writeContractFile(self, contract.state_path, state_payload);

    var mission = store.recordCheckpoint(self.allocator, mission_id, .{
        .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}) orelse "bootstrap_contract",
        .summary = extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}) orelse "Materialized mission contract files",
        .artifact = .{
            .kind = "contract_state",
            .path = contract.state_path,
            .summary = "Mission contract state file",
        },
        .contract = .{
            .contract_id = contract.contract_id,
            .context_path = contract.context_path,
            .state_path = contract.state_path,
            .artifact_root = contract.artifact_root,
        },
    }) catch |err| switch (err) {
        mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
        else => return error.InvalidPayload,
    };
    defer mission.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(mission);
    defer self.allocator.free(mission_json);
    const detail = try self.buildMissionBootstrapContractDetailJson(
        mission_json,
        contract.context_path,
        contract.state_path,
        contract.artifact_root,
    );
    defer self.allocator.free(detail);
    return self.buildMissionSuccessResultJson(.bootstrap_contract, detail);
}

pub const ResolvedBootstrapContract = struct {
    contract_id: []const u8,
    context_path: []const u8,
    state_path: []const u8,
    artifact_root: []const u8,
};

pub fn resolveContractHostPath(self: anytype, absolute_path: []const u8) ![]u8 {
    const local_root = self.local_fs_export_root orelse return error.InvalidPayload;
    const local_fs_world_prefix = "/nodes/local/fs";
    const trimmed = std.mem.trimRight(u8, absolute_path, "/");
    if (std.mem.eql(u8, trimmed, local_fs_world_prefix)) {
        return self.allocator.dupe(u8, local_root);
    }
    const relative_path = try self.normalizeLocalFsRelativePath(absolute_path);
    defer self.allocator.free(relative_path);
    return std.fs.path.join(self.allocator, &.{ local_root, relative_path });
}

pub fn ensureContractDirectory(self: anytype, absolute_path: []const u8) !void {
    const host_path = try resolveContractHostPath(self, absolute_path);
    defer self.allocator.free(host_path);
    mounts_venom.ensurePathExists(host_path) catch |err| switch (err) {
        error.PathAlreadyExists,
        error.NotDir,
        error.AccessDenied,
        => return error.InvalidPayload,
        else => return err,
    };
}

pub fn writeContractFile(self: anytype, absolute_path: []const u8, content: []const u8) !void {
    const host_path = try resolveContractHostPath(self, absolute_path);
    defer self.allocator.free(host_path);

    const parent = std.fs.path.dirname(host_path) orelse return error.InvalidPayload;
    mounts_venom.ensurePathExists(parent) catch |err| switch (err) {
        error.PathAlreadyExists,
        error.NotDir,
        error.AccessDenied,
        => return error.InvalidPayload,
        else => return err,
    };

    const file = if (std.fs.path.isAbsolute(host_path))
        try std.fs.createFileAbsolute(host_path, .{ .truncate = true })
    else
        try std.fs.cwd().createFile(host_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
}

pub fn parseMissionContractInput(self: anytype, args_obj: std.json.ObjectMap) !?mission_store_mod.MissionContractInput {
    _ = self;
    const value = args_obj.get("contract") orelse return null;
    if (value != .object) return error.InvalidPayload;
    const obj = value.object;
    const contract_id = (try jsonObjectOptionalString(obj, "contract_id")) orelse return error.InvalidPayload;
    return .{
        .contract_id = contract_id,
        .context_path = try extractOptionalMissionContractPath(obj, "context_path"),
        .state_path = try extractOptionalMissionContractPath(obj, "state_path"),
        .artifact_root = try extractOptionalMissionContractPath(obj, "artifact_root"),
    };
}

pub fn parseMissionContractUpdateInput(self: anytype, args_obj: std.json.ObjectMap) !?mission_store_mod.MissionContractUpdateInput {
    _ = self;
    const value = args_obj.get("contract") orelse return null;
    if (value != .object) return error.InvalidPayload;
    const obj = value.object;

    const contract_id = try jsonObjectOptionalString(obj, "contract_id");
    const context_path = try extractOptionalMissionContractPath(obj, "context_path");
    const state_path = try extractOptionalMissionContractPath(obj, "state_path");
    const artifact_root = try extractOptionalMissionContractPath(obj, "artifact_root");
    if (contract_id == null and context_path == null and state_path == null and artifact_root == null) return null;

    return .{
        .contract_id = contract_id,
        .context_path = context_path,
        .state_path = state_path,
        .artifact_root = artifact_root,
    };
}

pub fn resolveMissionBootstrapContract(
    self: anytype,
    mission: mission_store_mod.MissionRecord,
    args_obj: std.json.ObjectMap,
) !ResolvedBootstrapContract {
    if (mission.contract) |contract| {
        const update = try self.parseMissionContractUpdateInput(args_obj);
        return .{
            .contract_id = if (update) |value| value.contract_id orelse contract.contract_id else contract.contract_id,
            .context_path = if (update) |value| value.context_path orelse (contract.context_path orelse return error.InvalidPayload) else contract.context_path orelse return error.InvalidPayload,
            .state_path = if (update) |value| value.state_path orelse (contract.state_path orelse return error.InvalidPayload) else contract.state_path orelse return error.InvalidPayload,
            .artifact_root = if (update) |value| value.artifact_root orelse (contract.artifact_root orelse return error.InvalidPayload) else contract.artifact_root orelse return error.InvalidPayload,
        };
    }

    const contract = (try self.parseMissionContractInput(args_obj)) orelse return error.InvalidPayload;
    return .{
        .contract_id = contract.contract_id,
        .context_path = contract.context_path orelse return error.InvalidPayload,
        .state_path = contract.state_path orelse return error.InvalidPayload,
        .artifact_root = contract.artifact_root orelse return error.InvalidPayload,
    };
}

pub fn normalizeMissionAbsolutePath(self: anytype, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '/') return error.InvalidPayload;
    const normalized = if (trimmed.len > 1)
        std.mem.trimRight(u8, trimmed, "/")
    else
        trimmed;
    return self.allocator.dupe(u8, normalized);
}

pub fn deriveMissionServiceInvokePath(self: anytype, service_path: []const u8) ![]u8 {
    if (parseNodeVenomServicePath(service_path)) |parsed| {
        const venom_dir_id = self.resolveAbsolutePathNoBinds(service_path) orelse return error.NotFound;
        return (try self.deriveVenomInvokePath(parsed.node_id, parsed.venom_id, venom_dir_id)) orelse error.NotFound;
    }

    const service_dir_id = self.resolveAbsolutePathNoBinds(service_path) orelse return error.NotFound;
    const service_node = self.nodes.get(service_dir_id) orelse return error.NotFound;
    if (service_node.kind != .dir) return error.InvalidPayload;

    const invoke_target = try self.resolveNodeVenomInvokeTarget(service_dir_id);
    defer self.allocator.free(invoke_target);
    if (isWorldAbsolutePath(invoke_target)) return self.allocator.dupe(u8, invoke_target);
    return self.pathWithInvokeTarget(service_path, std.mem.trimLeft(u8, invoke_target, "/"));
}

pub fn buildMissionServiceInvokeRequestPayload(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    if (args_obj.get("payload")) |value| return self.renderJsonValue(value);
    if (args_obj.get("request")) |value| return self.renderJsonValue(value);

    const op_name = extractOptionalStringByNames(args_obj, &[_][]const u8{ "op", "operation", "tool", "tool_name" }) orelse return error.InvalidPayload;
    const escaped_op = try unified.jsonEscape(self.allocator, op_name);
    defer self.allocator.free(escaped_op);
    const arguments_json = if (args_obj.get("arguments")) |value|
        try self.renderJsonValue(value)
    else if (args_obj.get("args")) |value|
        try self.renderJsonValue(value)
    else
        try self.allocator.dupe(u8, "{}");
    defer self.allocator.free(arguments_json);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"op\":\"{s}\",\"arguments\":{s}}}",
        .{ escaped_op, arguments_json },
    );
}

pub fn buildMissionServiceInvocationDetailJson(
    self: anytype,
    mission_json: []const u8,
    service_path: []const u8,
    invoke_path: []const u8,
    request_payload_json: []const u8,
    result_payload_json: []const u8,
    status_payload_json: ?[]const u8,
) ![]u8 {
    const escaped_service_path = try unified.jsonEscape(self.allocator, service_path);
    defer self.allocator.free(escaped_service_path);
    const escaped_invoke_path = try unified.jsonEscape(self.allocator, invoke_path);
    defer self.allocator.free(escaped_invoke_path);
    const status_json = if (status_payload_json) |value|
        try self.allocator.dupe(u8, value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(status_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"mission\":{s},\"service\":{{\"service_path\":\"{s}\",\"invoke_path\":\"{s}\",\"request\":{s},\"result\":{s},\"status\":{s}}}}}",
        .{
            mission_json,
            escaped_service_path,
            escaped_invoke_path,
            request_payload_json,
            result_payload_json,
            status_json,
        },
    );
}

pub fn buildMissionBootstrapContractDetailJson(
    self: anytype,
    mission_json: []const u8,
    context_path: []const u8,
    state_path: []const u8,
    artifact_root: []const u8,
) ![]u8 {
    const escaped_context_path = try unified.jsonEscape(self.allocator, context_path);
    defer self.allocator.free(escaped_context_path);
    const escaped_state_path = try unified.jsonEscape(self.allocator, state_path);
    defer self.allocator.free(escaped_state_path);
    const escaped_artifact_root = try unified.jsonEscape(self.allocator, artifact_root);
    defer self.allocator.free(escaped_artifact_root);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"mission\":{s},\"materialized\":{{\"context_path\":\"{s}\",\"state_path\":\"{s}\",\"artifact_root\":\"{s}\"}}}}",
        .{ mission_json, escaped_context_path, escaped_state_path, escaped_artifact_root },
    );
}

pub fn buildMissionSuccessResultJson(self: anytype, op: Op, result_json: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
        .{ escaped_operation, result_json },
    );
}

pub fn buildMissionPartialFailureResultJson(
    self: anytype,
    op: Op,
    result_json: []const u8,
    code: []const u8,
    message: []const u8,
) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    const escaped_code = try unified.jsonEscape(self.allocator, code);
    defer self.allocator.free(escaped_code);
    const escaped_message = try unified.jsonEscape(self.allocator, message);
    defer self.allocator.free(escaped_message);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":false,\"operation\":\"{s}\",\"result\":{s},\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
        .{ escaped_operation, result_json, escaped_code, escaped_message },
    );
}

pub fn buildMissionFailureResultJson(self: anytype, op: Op, code: []const u8, message: []const u8) ![]u8 {
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

pub fn buildMissionListJson(self: anytype, missions: []const mission_store_mod.MissionRecord) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeAll("{\"missions\":[");
    for (missions, 0..) |mission, idx| {
        if (idx > 0) try writer.writeByte(',');
        const mission_json = try self.buildMissionRecordJson(mission);
        defer self.allocator.free(mission_json);
        try writer.writeAll(mission_json);
    }
    try writer.print("],\"count\":{d}}}", .{missions.len});
    return out.toOwnedSlice(self.allocator);
}

pub fn buildMissionRecordJson(self: anytype, mission: mission_store_mod.MissionRecord) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);

    try writer.writeByte('{');
    try writer.writeAll("\"mission_id\":");
    try writeJsonString(writer, mission.mission_id);
    try writer.writeAll(",\"use_case\":");
    try writeJsonString(writer, mission.use_case);
    try writer.writeAll(",\"title\":");
    if (mission.title) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"stage\":");
    try writeJsonString(writer, mission.stage);
    try writer.writeAll(",\"state\":");
    try writeJsonString(writer, mission_store_mod.missionStateName(mission.state));
    try writer.writeAll(",\"agent_id\":");
    if (mission.agent_id) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"project_id\":");
    if (mission.project_id) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"run_id\":");
    if (mission.run_id) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"workspace_root\":");
    if (mission.workspace_root) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"worktree_name\":");
    if (mission.worktree_name) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"created_by\":{");
    try writer.writeAll("\"actor_type\":");
    try writeJsonString(writer, mission.created_by.actor_type);
    try writer.writeAll(",\"actor_id\":");
    try writeJsonString(writer, mission.created_by.actor_id);
    try writer.writeByte('}');
    try writer.print(",\"created_at_ms\":{d}", .{mission.created_at_ms});
    try writer.print(",\"updated_at_ms\":{d}", .{mission.updated_at_ms});
    try writer.print(",\"last_heartbeat_ms\":{d}", .{mission.last_heartbeat_ms});
    try writer.print(",\"checkpoint_seq\":{d}", .{mission.checkpoint_seq});
    try writer.print(",\"recovery_count\":{d}", .{mission.recovery_count});
    try writer.writeAll(",\"recovery_reason\":");
    if (mission.recovery_reason) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"blocked_reason\":");
    if (mission.blocked_reason) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"summary\":");
    if (mission.summary) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"contract\":");
    if (mission.contract) |value| {
        const contract_json = try self.buildMissionContractJson(value);
        defer self.allocator.free(contract_json);
        try writer.writeAll(contract_json);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"pending_approval\":");
    if (mission.pending_approval) |value| {
        const approval_json = try self.buildMissionApprovalJson(value);
        defer self.allocator.free(approval_json);
        try writer.writeAll(approval_json);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"artifacts\":[");
    for (mission.artifacts.items, 0..) |artifact, idx| {
        if (idx > 0) try writer.writeByte(',');
        const artifact_json = try self.buildMissionArtifactJson(artifact);
        defer self.allocator.free(artifact_json);
        try writer.writeAll(artifact_json);
    }
    try writer.writeAll("],\"events\":[");
    for (mission.events.items, 0..) |event, idx| {
        if (idx > 0) try writer.writeByte(',');
        const event_json = try self.buildMissionEventJson(event);
        defer self.allocator.free(event_json);
        try writer.writeAll(event_json);
    }
    try writer.writeAll("]}");
    return out.toOwnedSlice(self.allocator);
}

pub fn buildMissionContractJson(self: anytype, contract: mission_store_mod.MissionContract) ![]u8 {
    const contract_id_json = try formatJsonStringOrNull(self.allocator, contract.contract_id);
    defer self.allocator.free(contract_id_json);
    const context_path_json = if (contract.context_path) |value| try formatJsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(context_path_json);
    const state_path_json = if (contract.state_path) |value| try formatJsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(state_path_json);
    const artifact_root_json = if (contract.artifact_root) |value| try formatJsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(artifact_root_json);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"contract_id\":{s},\"context_path\":{s},\"state_path\":{s},\"artifact_root\":{s}}}",
        .{
            contract_id_json,
            context_path_json,
            state_path_json,
            artifact_root_json,
        },
    );
}

pub fn buildMissionArtifactJson(self: anytype, artifact: mission_store_mod.MissionArtifact) ![]u8 {
    const kind_json = try formatJsonStringOrNull(self.allocator, artifact.kind);
    defer self.allocator.free(kind_json);
    const path_json = if (artifact.path) |value| try formatJsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(path_json);
    const summary_json = if (artifact.summary) |value| try formatJsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(summary_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":{s},\"path\":{s},\"summary\":{s},\"created_at_ms\":{d}}}",
        .{
            kind_json,
            path_json,
            summary_json,
            artifact.created_at_ms,
        },
    );
}

pub fn buildMissionEventJson(self: anytype, event: mission_store_mod.MissionEvent) ![]u8 {
    const event_type_json = try formatJsonStringOrNull(self.allocator, event.event_type);
    defer self.allocator.free(event_type_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"seq\":{d},\"event_type\":{s},\"payload\":{s},\"created_at_ms\":{d}}}",
        .{ event.seq, event_type_json, event.payload_json, event.created_at_ms },
    );
}

pub fn buildMissionApprovalJson(self: anytype, approval: mission_store_mod.MissionApproval) ![]u8 {
    const approval_id_json = try formatJsonStringOrNull(self.allocator, approval.approval_id);
    defer self.allocator.free(approval_id_json);
    const action_json = try formatJsonStringOrNull(self.allocator, approval.action_kind);
    defer self.allocator.free(action_json);
    const message_json = try formatJsonStringOrNull(self.allocator, approval.message);
    defer self.allocator.free(message_json);
    const payload_json = if (approval.payload_json) |value| try self.allocator.dupe(u8, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(payload_json);
    const resolution_note_json = if (approval.resolution_note) |value| try formatJsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(resolution_note_json);
    const resolution_json = if (approval.resolution) |value| try formatJsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(resolution_json);

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeByte('{');
    try writer.writeAll("\"approval_id\":");
    try writer.writeAll(approval_id_json);
    try writer.writeAll(",\"action_kind\":");
    try writer.writeAll(action_json);
    try writer.writeAll(",\"message\":");
    try writer.writeAll(message_json);
    try writer.writeAll(",\"payload\":");
    try writer.writeAll(payload_json);
    try writer.print(",\"requested_at_ms\":{d}", .{approval.requested_at_ms});
    try writer.writeAll(",\"requested_by\":{");
    try writer.writeAll("\"actor_type\":");
    try writeJsonString(writer, approval.requested_by.actor_type);
    try writer.writeAll(",\"actor_id\":");
    try writeJsonString(writer, approval.requested_by.actor_id);
    try writer.writeByte('}');
    try writer.print(",\"resolved_at_ms\":{d}", .{approval.resolved_at_ms});
    try writer.writeAll(",\"resolved_by\":");
    if (approval.resolved_by) |value| {
        try writer.writeByte('{');
        try writer.writeAll("\"actor_type\":");
        try writeJsonString(writer, value.actor_type);
        try writer.writeAll(",\"actor_id\":");
        try writeJsonString(writer, value.actor_id);
        try writer.writeByte('}');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"resolution_note\":");
    try writer.writeAll(resolution_note_json);
    try writer.writeAll(",\"resolution\":");
    try writer.writeAll(resolution_json);
    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

fn extractOptionalStringByNames(obj: std.json.ObjectMap, candidate_names: []const []const u8) ?[]const u8 {
    for (candidate_names) |field| {
        if (obj.get(field)) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
    }
    return null;
}

fn extractOptionalMissionContractPath(obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    const raw = try jsonObjectOptionalString(obj, key);
    const value = raw orelse return null;
    if (value.len == 0 or value[0] != '/') return error.InvalidPayload;
    return value;
}

fn jsonObjectOptionalString(obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value == .null) return null;
    if (value != .string) return error.InvalidPayload;
    return value.string;
}

fn formatJsonStringOrNull(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.print("{f}", .{std.json.fmt(value, .{})});
}

fn isWorldAbsolutePath(path: []const u8) bool {
    return std.mem.startsWith(u8, path, "/nodes/") or
        std.mem.startsWith(u8, path, "/agents/") or
        std.mem.startsWith(u8, path, "/global/") or
        std.mem.startsWith(u8, path, "/debug/");
}

fn parseNodeVenomServicePath(path: []const u8) ?ParsedNodeVenomServicePath {
    if (!std.mem.startsWith(u8, path, "/nodes/")) return null;
    const after_prefix = path["/nodes/".len..];
    const node_end = std.mem.indexOfScalar(u8, after_prefix, '/') orelse return null;
    const node_id = after_prefix[0..node_end];
    if (node_id.len == 0) return null;
    const after_node = after_prefix[node_end..];
    if (!std.mem.startsWith(u8, after_node, "/venoms/")) return null;
    const after_venoms = after_node["/venoms/".len..];
    if (after_venoms.len == 0) return null;
    const venom_end = std.mem.indexOfScalar(u8, after_venoms, '/') orelse after_venoms.len;
    const venom_id = after_venoms[0..venom_end];
    if (venom_id.len == 0) return null;
    return .{
        .node_id = node_id,
        .venom_id = venom_id,
    };
}
