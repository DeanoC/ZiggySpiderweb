const std = @import("std");
const unified = @import("spider-protocol").unified;
const mission_store_mod = @import("../mission_store.zig");

pub const Op = enum {
    configure_repo,
    get_repo,
    list_repos,
    intake,
    start,
    sync,
    run_validation,
    record_validation,
    draft_review,
    save_draft,
    record_review,
    advance,
};

pub fn seedNamespace(self: anytype, pr_review_dir: u32) !void {
    return seedNamespaceAt(self, pr_review_dir, "/global/pr_review");
}

pub fn seedNamespaceAt(self: anytype, pr_review_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"pr_review\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        pr_review_dir,
        "PR Review",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"pr_review_configure_repo\",\"pr_review_get_repo\",\"pr_review_list_repos\",\"pr_review_intake\",\"pr_review_start\",\"pr_review_sync\",\"pr_review_run_validation\",\"pr_review_record_validation\",\"pr_review_draft_review\",\"pr_review_save_draft\",\"pr_review_record_review\",\"pr_review_advance\"],\"discoverable\":true,\"persistent\":true}",
        "Start PR review missions as a thin use-case venom layered over the missions service.",
    );
    _ = try self.addFile(
        pr_review_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"configure_repo\":\"control/configure_repo.json\",\"get_repo\":\"control/get_repo.json\",\"list_repos\":\"control/list_repos.json\",\"intake\":\"control/intake.json\",\"start\":\"control/start.json\",\"sync\":\"control/sync.json\",\"run_validation\":\"control/run_validation.json\",\"record_validation\":\"control/record_validation.json\",\"draft_review\":\"control/draft_review.json\",\"save_draft\":\"control/save_draft.json\",\"record_review\":\"control/record_review.json\",\"advance\":\"control/advance.json\"},\"operations\":{\"configure_repo\":\"pr_review_configure_repo\",\"get_repo\":\"pr_review_get_repo\",\"list_repos\":\"pr_review_list_repos\",\"intake\":\"pr_review_intake\",\"start\":\"pr_review_start\",\"sync\":\"pr_review_sync\",\"run_validation\":\"pr_review_run_validation\",\"record_validation\":\"pr_review_record_validation\",\"draft_review\":\"pr_review_draft_review\",\"save_draft\":\"pr_review_save_draft\",\"record_review\":\"pr_review_record_review\",\"advance\":\"pr_review_advance\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        pr_review_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"pr_review_use_case\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        pr_review_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"mission_use_case\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        pr_review_dir,
        "STATUS.json",
        "{\"venom_id\":\"pr_review\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    self.pr_review_status_id = try self.addFile(
        pr_review_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    self.pr_review_result_id = try self.addFile(
        pr_review_dir,
        "result.json",
        "{\"ok\":true,\"operation\":null,\"result\":null,\"error\":null}",
        false,
        .none,
    );

    const control_dir = try self.addDir(pr_review_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Use configure_repo.json, get_repo.json, list_repos.json, intake.json, start.json, sync.json, run_validation.json, record_validation.json, draft_review.json, save_draft.json, record_review.json, advance.json, or invoke.json with the same op names to drive the PR review use-case venom over Acheron.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .pr_review_invoke);
    _ = try self.addFile(control_dir, "configure_repo.json", "", true, .pr_review_configure_repo);
    _ = try self.addFile(control_dir, "get_repo.json", "", true, .pr_review_get_repo);
    _ = try self.addFile(control_dir, "list_repos.json", "", true, .pr_review_list_repos);
    _ = try self.addFile(control_dir, "intake.json", "", true, .pr_review_intake);
    _ = try self.addFile(control_dir, "start.json", "", true, .pr_review_start);
    _ = try self.addFile(control_dir, "sync.json", "", true, .pr_review_sync);
    _ = try self.addFile(control_dir, "run_validation.json", "", true, .pr_review_run_validation);
    _ = try self.addFile(control_dir, "record_validation.json", "", true, .pr_review_record_validation);
    _ = try self.addFile(control_dir, "draft_review.json", "", true, .pr_review_draft_review);
    _ = try self.addFile(control_dir, "save_draft.json", "", true, .pr_review_save_draft);
    _ = try self.addFile(control_dir, "record_review.json", "", true, .pr_review_record_review);
    _ = try self.addFile(control_dir, "advance.json", "", true, .pr_review_advance);
}

pub fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "configure_repo") or std.mem.eql(u8, value, "pr_review_configure_repo")) return .configure_repo;
    if (std.mem.eql(u8, value, "get_repo") or std.mem.eql(u8, value, "pr_review_get_repo")) return .get_repo;
    if (std.mem.eql(u8, value, "list_repos") or std.mem.eql(u8, value, "pr_review_list_repos")) return .list_repos;
    if (std.mem.eql(u8, value, "intake") or std.mem.eql(u8, value, "pr_review_intake")) return .intake;
    if (std.mem.eql(u8, value, "start") or std.mem.eql(u8, value, "pr_review_start")) return .start;
    if (std.mem.eql(u8, value, "sync") or std.mem.eql(u8, value, "pr_review_sync")) return .sync;
    if (std.mem.eql(u8, value, "run_validation") or std.mem.eql(u8, value, "pr_review_run_validation")) return .run_validation;
    if (std.mem.eql(u8, value, "record_validation") or std.mem.eql(u8, value, "pr_review_record_validation")) return .record_validation;
    if (std.mem.eql(u8, value, "draft_review") or std.mem.eql(u8, value, "pr_review_draft_review")) return .draft_review;
    if (std.mem.eql(u8, value, "save_draft") or std.mem.eql(u8, value, "pr_review_save_draft")) return .save_draft;
    if (std.mem.eql(u8, value, "record_review") or std.mem.eql(u8, value, "pr_review_record_review")) return .record_review;
    if (std.mem.eql(u8, value, "advance") or std.mem.eql(u8, value, "pr_review_advance")) return .advance;
    return null;
}

pub fn operationName(op: Op) []const u8 {
    return switch (op) {
        .configure_repo => "configure_repo",
        .get_repo => "get_repo",
        .list_repos => "list_repos",
        .intake => "intake",
        .start => "start",
        .sync => "sync",
        .run_validation => "run_validation",
        .record_validation => "record_validation",
        .draft_review => "draft_review",
        .save_draft => "save_draft",
        .record_review => "record_review",
        .advance => "advance",
    };
}

pub fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .configure_repo => "pr_review_configure_repo",
        .get_repo => "pr_review_get_repo",
        .list_repos => "pr_review_list_repos",
        .intake => "pr_review_intake",
        .start => "pr_review_start",
        .sync => "pr_review_sync",
        .run_validation => "pr_review_run_validation",
        .record_validation => "pr_review_record_validation",
        .draft_review => "pr_review_draft_review",
        .save_draft => "pr_review_save_draft",
        .record_review => "pr_review_record_review",
        .advance => "pr_review_advance",
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
        .pr_review_configure_repo => Op.configure_repo,
        .pr_review_get_repo => Op.get_repo,
        .pr_review_list_repos => Op.list_repos,
        .pr_review_intake => Op.intake,
        .pr_review_start => Op.start,
        .pr_review_sync => Op.sync,
        .pr_review_run_validation => Op.run_validation,
        .pr_review_record_validation => Op.record_validation,
        .pr_review_draft_review => Op.draft_review,
        .pr_review_save_draft => Op.save_draft,
        .pr_review_record_review => Op.record_review,
        .pr_review_advance => Op.advance,
        .pr_review_invoke => blk: {
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
    try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, running_status);

    const result_payload = executeOpPayload(self, op, args_obj) catch |err| {
        const error_message = @errorName(err);
        const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
        defer self.allocator.free(failed_status);
        try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, failed_status);
        const failed_result = try buildPrReviewFailureResultJson(self, op, "invalid_payload", error_message);
        defer self.allocator.free(failed_result);
        try self.setMirroredFileContent(self.pr_review_result_id, self.pr_review_result_alias_id, failed_result);
        return err;
    };
    defer self.allocator.free(result_payload);

    if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
        defer self.allocator.free(message);
        const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
        defer self.allocator.free(failed_status);
        try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, failed_status);
    } else {
        const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
        defer self.allocator.free(done_status);
        try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, done_status);
    }
    try self.setMirroredFileContent(self.pr_review_result_id, self.pr_review_result_alias_id, result_payload);
    return written;
}

pub fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    return switch (op) {
        .configure_repo => executeConfigureRepoOp(self, args_obj),
        .get_repo => executeGetRepoOp(self, args_obj),
        .list_repos => executeListReposOp(self),
        .intake => executeIntakeOp(self, args_obj),
        .start => executeStartOp(self, args_obj),
        .sync => executeSyncOp(self, args_obj),
        .run_validation => executeRunValidationOp(self, args_obj),
        .record_validation => executeRecordValidationOp(self, args_obj),
        .draft_review => executeDraftReviewOp(self, args_obj),
        .save_draft => executeSaveDraftOp(self, args_obj),
        .record_review => executeRecordReviewOp(self, args_obj),
        .advance => executeAdvanceOp(self, args_obj),
    };
}

pub const ServiceCapture = struct {
    artifact_path: []u8,
    result_payload: []u8,
    status_payload: ?[]u8 = null,

    pub fn deinit(self: *ServiceCapture, allocator: std.mem.Allocator) void {
        allocator.free(self.artifact_path);
        allocator.free(self.result_payload);
        if (self.status_payload) |value| allocator.free(value);
        self.* = undefined;
    }
};

const PreferredServiceTarget = struct {
    service_path: []u8,
    invoke_path: []u8,

    fn deinit(self: *PreferredServiceTarget, allocator: std.mem.Allocator) void {
        allocator.free(self.service_path);
        allocator.free(self.invoke_path);
        self.* = undefined;
    }
};

pub const ResolvedContract = struct {
    contract_id: []u8,
    context_path: []u8,
    state_path: []u8,
    artifact_root: []u8,

    pub fn deinit(self: *ResolvedContract, allocator: std.mem.Allocator) void {
        allocator.free(self.contract_id);
        allocator.free(self.context_path);
        allocator.free(self.state_path);
        allocator.free(self.artifact_root);
        self.* = undefined;
    }
};

pub const ContextSnapshot = struct {
    provider: []u8,
    repo_key: []u8,
    pr_number: u64,
    pr_url: []u8,
    base_branch: []u8,
    base_sha: []u8,
    head_branch: []u8,
    head_sha: []u8,
    checkout_path: []u8,
    review_policy_paths_json: []u8,
    default_review_commands_json: []u8,
    approval_policy_json: []u8,

    pub fn deinit(self: *ContextSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.provider);
        allocator.free(self.repo_key);
        allocator.free(self.pr_url);
        allocator.free(self.base_branch);
        allocator.free(self.base_sha);
        allocator.free(self.head_branch);
        allocator.free(self.head_sha);
        allocator.free(self.checkout_path);
        allocator.free(self.review_policy_paths_json);
        allocator.free(self.default_review_commands_json);
        allocator.free(self.approval_policy_json);
        self.* = undefined;
    }
};

pub const StateSnapshot = struct {
    phase: []u8,
    last_synced_head_sha: []u8,
    current_focus: []u8,
    open_threads_json: []u8,
    latest_validation_status: []u8,
    latest_validation_summary: ?[]u8 = null,
    latest_draft_status: []u8,
    latest_draft_summary: ?[]u8 = null,
    latest_draft_revision: u64 = 0,
    latest_recommendation_status: []u8,
    latest_recommendation_summary: ?[]u8 = null,
    draft_review_artifact: []u8,
    draft_review_comment_artifact: []u8,
    draft_history_dir: []u8,
    findings_artifact: []u8,
    validation_artifact: []u8,
    recommendation_artifact: []u8,
    thread_actions_artifact: []u8,
    provider_sync_artifact: []u8,
    checkout_sync_artifact: []u8,
    repo_status_artifact: []u8,
    diff_range_artifact: []u8,
    publish_review_artifact: []u8,
    notes_json: []u8,

    pub fn deinit(self: *StateSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.phase);
        allocator.free(self.last_synced_head_sha);
        allocator.free(self.current_focus);
        allocator.free(self.open_threads_json);
        allocator.free(self.latest_validation_status);
        if (self.latest_validation_summary) |value| allocator.free(value);
        allocator.free(self.latest_draft_status);
        if (self.latest_draft_summary) |value| allocator.free(value);
        allocator.free(self.draft_review_artifact);
        allocator.free(self.draft_review_comment_artifact);
        allocator.free(self.draft_history_dir);
        allocator.free(self.latest_recommendation_status);
        if (self.latest_recommendation_summary) |value| allocator.free(value);
        allocator.free(self.findings_artifact);
        allocator.free(self.validation_artifact);
        allocator.free(self.recommendation_artifact);
        allocator.free(self.thread_actions_artifact);
        allocator.free(self.provider_sync_artifact);
        allocator.free(self.checkout_sync_artifact);
        allocator.free(self.repo_status_artifact);
        allocator.free(self.diff_range_artifact);
        allocator.free(self.publish_review_artifact);
        allocator.free(self.notes_json);
        self.* = undefined;
    }
};

const LoadedDraftSnapshot = struct {
    parsed: std.json.Parsed(std.json.Value),
    findings: std.json.Value,
    recommendation: std.json.Value,
    review_comment: ?[]const u8 = null,
    thread_actions: ?std.json.Value = null,
    summary: ?[]const u8 = null,
    status: ?[]const u8 = null,

    fn deinit(self: *LoadedDraftSnapshot) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

const OptionalServiceArgs = struct {
    enabled: bool = false,
    overrides: ?std.json.ObjectMap = null,
};

const default_approval_policy_json =
    "{\"push_fix_requires_approval\":false,\"merge_requires_approval\":true}";
const repo_catalog_path = "/nodes/local/fs/pr-review/state/repos.json";

pub const RepoConfigSnapshot = struct {
    repo_key: []u8,
    provider: []u8,
    default_branch: []u8,
    checkout_path: []u8,
    review_policy_paths_json: []u8,
    default_review_commands_json: []u8,
    approval_policy_json: []u8,
    auto_intake: ?bool = null,
    project_id: ?[]u8 = null,
    agent_id: ?[]u8 = null,
    workspace_root: ?[]u8 = null,
    worktree_name: ?[]u8 = null,

    pub fn deinit(self: *RepoConfigSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.repo_key);
        allocator.free(self.provider);
        allocator.free(self.default_branch);
        allocator.free(self.checkout_path);
        allocator.free(self.review_policy_paths_json);
        allocator.free(self.default_review_commands_json);
        allocator.free(self.approval_policy_json);
        if (self.project_id) |value| allocator.free(value);
        if (self.agent_id) |value| allocator.free(value);
        if (self.workspace_root) |value| allocator.free(value);
        if (self.worktree_name) |value| allocator.free(value);
        self.* = undefined;
    }

    pub fn cloneOwned(self: RepoConfigSnapshot, allocator: std.mem.Allocator) !RepoConfigSnapshot {
        return .{
            .repo_key = try allocator.dupe(u8, self.repo_key),
            .provider = try allocator.dupe(u8, self.provider),
            .default_branch = try allocator.dupe(u8, self.default_branch),
            .checkout_path = try allocator.dupe(u8, self.checkout_path),
            .review_policy_paths_json = try allocator.dupe(u8, self.review_policy_paths_json),
            .default_review_commands_json = try allocator.dupe(u8, self.default_review_commands_json),
            .approval_policy_json = try allocator.dupe(u8, self.approval_policy_json),
            .auto_intake = self.auto_intake,
            .project_id = if (self.project_id) |value| try allocator.dupe(u8, value) else null,
            .agent_id = if (self.agent_id) |value| try allocator.dupe(u8, value) else null,
            .workspace_root = if (self.workspace_root) |value| try allocator.dupe(u8, value) else null,
            .worktree_name = if (self.worktree_name) |value| try allocator.dupe(u8, value) else null,
        };
    }
};

const RepoCatalogSnapshot = struct {
    project_id: ?[]u8 = null,
    approval_policy_json: ?[]u8 = null,
    repositories: []RepoConfigSnapshot,

    fn deinit(self: *RepoCatalogSnapshot, allocator: std.mem.Allocator) void {
        if (self.project_id) |value| allocator.free(value);
        if (self.approval_policy_json) |value| allocator.free(value);
        for (self.repositories) |*repo| repo.deinit(allocator);
        if (self.repositories.len > 0) allocator.free(self.repositories);
        self.* = undefined;
    }
};

pub fn configuredRepoCatalogPath(_: anytype) []const u8 {
    return repo_catalog_path;
}

pub fn loadConfiguredRepo(self: anytype, repo_key: []const u8) !?RepoConfigSnapshot {
    const trimmed_repo_key = std.mem.trim(u8, repo_key, " \t\r\n");
    if (trimmed_repo_key.len == 0) return error.InvalidPayload;

    var catalog = try loadRepoCatalog(self);
    defer catalog.deinit(self.allocator);

    for (catalog.repositories) |repo| {
        if (std.mem.eql(u8, repo.repo_key, trimmed_repo_key)) {
            return try repo.cloneOwned(self.allocator);
        }
    }
    return null;
}

fn loadRepoCatalog(self: anytype) !RepoCatalogSnapshot {
    const raw = self.readMissionContractFile(repo_catalog_path, 512 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            return .{ .repositories = &[_]RepoConfigSnapshot{} };
        },
        else => return err,
    };
    defer self.allocator.free(raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
    defer parsed.deinit();

    if (parsed.value == .array) {
        return buildRepoCatalogFromArray(self, parsed.value.array.items, null, null);
    }
    if (parsed.value != .object) return error.InvalidPayload;

    const obj = parsed.value.object;
    const project_id = if (try jsonObjectOptionalString(obj, "project_id")) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else
        null;
    errdefer if (project_id) |value| self.allocator.free(value);
    const approval_policy_json = if (obj.get("approval_policy")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .object) return error.InvalidPayload;
        break :blk try self.renderJsonValue(value);
    } else null;
    errdefer if (approval_policy_json) |value| self.allocator.free(value);

    const repositories = if (obj.get("repositories")) |value| blk: {
        if (value == .null) break :blk &[_]std.json.Value{};
        if (value != .array) return error.InvalidPayload;
        break :blk value.array.items;
    } else if (obj.get("repos")) |value| blk: {
        if (value == .null) break :blk &[_]std.json.Value{};
        if (value != .array) return error.InvalidPayload;
        break :blk value.array.items;
    } else &[_]std.json.Value{};

    return buildRepoCatalogFromArray(self, repositories, project_id, approval_policy_json);
}

fn buildRepoCatalogFromArray(
    self: anytype,
    items: []const std.json.Value,
    project_id: ?[]u8,
    approval_policy_json: ?[]u8,
) !RepoCatalogSnapshot {
    var repos = std.ArrayListUnmanaged(RepoConfigSnapshot){};
    errdefer {
        for (repos.items) |*repo| repo.deinit(self.allocator);
        repos.deinit(self.allocator);
        if (project_id) |value| self.allocator.free(value);
        if (approval_policy_json) |value| self.allocator.free(value);
    }

    for (items) |item| {
        if (item != .object) return error.InvalidPayload;
        try repos.append(
            self.allocator,
            try parseRepoConfigSnapshot(self, item.object, project_id, approval_policy_json, null),
        );
    }

    return .{
        .project_id = project_id,
        .approval_policy_json = approval_policy_json,
        .repositories = try repos.toOwnedSlice(self.allocator),
    };
}

fn parseRepoConfigSnapshot(
    self: anytype,
    obj: std.json.ObjectMap,
    default_project_id: ?[]const u8,
    default_approval_policy: ?[]const u8,
    default_auto_intake: ?bool,
) !RepoConfigSnapshot {
    const review_obj = if (obj.get("review")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .object) return error.InvalidPayload;
        break :blk value.object;
    } else null;
    const setup_obj = if (obj.get("setup")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .object) return error.InvalidPayload;
        break :blk value.object;
    } else null;

    const repo_key_raw = extractOptionalStringByNames(obj, &[_][]const u8{"repo_key"}) orelse return error.InvalidPayload;
    const repo_key = std.mem.trim(u8, repo_key_raw, " \t\r\n");
    if (repo_key.len == 0) return error.InvalidPayload;

    const provider = std.mem.trim(u8, extractOptionalStringByNames(obj, &[_][]const u8{ "provider", "host" }) orelse "github", " \t\r\n");
    const default_branch = std.mem.trim(u8, extractOptionalStringByNames(obj, &[_][]const u8{ "default_branch", "base_branch" }) orelse "main", " \t\r\n");
    if (provider.len == 0 or default_branch.len == 0) return error.InvalidPayload;

    const checkout_path = if (extractOptionalStringByNames(obj, &[_][]const u8{ "checkout_path", "local_checkout_path" })) |value|
        try self.normalizeLocalWorkspaceAbsolutePath(value)
    else blk: {
        const repo_slug = try buildRepoKeySlug(self, repo_key);
        defer self.allocator.free(repo_slug);
        break :blk try std.fmt.allocPrint(self.allocator, "/nodes/local/fs/pr-review/repos/{s}", .{repo_slug});
    };
    errdefer self.allocator.free(checkout_path);

    const review_policy_paths_json = blk: {
        if (obj.get("review_policy_paths")) |value| {
            if (value != .array) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        }
        if (review_obj) |review| {
            if (review.get("policy_paths")) |value| {
                if (value != .array) return error.InvalidPayload;
                break :blk try self.renderJsonValue(value);
            }
        }
        break :blk try self.allocator.dupe(u8, "[]");
    };
    errdefer self.allocator.free(review_policy_paths_json);

    const default_review_commands_json = blk: {
        if (obj.get("default_review_commands")) |value| {
            if (value != .array) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        }
        if (review_obj) |review| {
            if (review.get("commands")) |value| {
                if (value != .array) return error.InvalidPayload;
                break :blk try self.renderJsonValue(value);
            }
        }
        if (setup_obj) |setup| {
            if (setup.get("baseline_checks")) |value| {
                if (value != .array) return error.InvalidPayload;
                break :blk try self.renderJsonValue(value);
            }
        }
        break :blk try self.allocator.dupe(u8, "[]");
    };
    errdefer self.allocator.free(default_review_commands_json);

    const approval_policy_json = blk: {
        if (obj.get("approval_policy")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        }
        if (default_approval_policy) |value| break :blk try self.allocator.dupe(u8, value);
        break :blk try self.allocator.dupe(u8, default_approval_policy_json);
    };
    errdefer self.allocator.free(approval_policy_json);

    const project_id = if (extractOptionalStringByNames(obj, &[_][]const u8{"project_id"})) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else if (default_project_id) |value|
        try self.allocator.dupe(u8, value)
    else
        null;
    errdefer if (project_id) |value| self.allocator.free(value);

    const agent_id = if (extractOptionalStringByNames(obj, &[_][]const u8{"agent_id"})) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else
        null;
    errdefer if (agent_id) |value| self.allocator.free(value);

    const workspace_root = if (extractOptionalStringByNames(obj, &[_][]const u8{"workspace_root"})) |value|
        try self.normalizeLocalWorkspaceAbsolutePath(value)
    else
        null;
    errdefer if (workspace_root) |value| self.allocator.free(value);

    const worktree_name = if (extractOptionalStringByNames(obj, &[_][]const u8{"worktree_name"})) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else
        null;
    errdefer if (worktree_name) |value| self.allocator.free(value);

    return .{
        .repo_key = try self.allocator.dupe(u8, repo_key),
        .provider = try self.allocator.dupe(u8, provider),
        .default_branch = try self.allocator.dupe(u8, default_branch),
        .checkout_path = checkout_path,
        .review_policy_paths_json = review_policy_paths_json,
        .default_review_commands_json = default_review_commands_json,
        .approval_policy_json = approval_policy_json,
        .auto_intake = (try jsonObjectOptionalBool(obj, "auto_intake")) orelse default_auto_intake,
        .project_id = project_id,
        .agent_id = agent_id,
        .workspace_root = workspace_root,
        .worktree_name = worktree_name,
    };
}

fn renderRepoCatalogJson(self: anytype, catalog: RepoCatalogSnapshot) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);

    try writer.writeByte('{');
    try writer.writeAll("\"use_case\":\"pr_review\"");
    if (catalog.project_id) |value| {
        try writer.writeAll(",\"project_id\":");
        try writeJsonString(writer, value);
    }
    if (catalog.approval_policy_json) |value| {
        try writer.writeAll(",\"approval_policy\":");
        try writer.writeAll(value);
    }
    try writer.writeAll(",\"repositories\":[");
    for (catalog.repositories, 0..) |repo, idx| {
        if (idx > 0) try writer.writeByte(',');
        const repo_json = try renderRepoConfigJson(self, repo);
        defer self.allocator.free(repo_json);
        try writer.writeAll(repo_json);
    }
    try writer.writeAll("]}");
    return out.toOwnedSlice(self.allocator);
}

fn renderRepoConfigJson(self: anytype, repo: RepoConfigSnapshot) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);

    try writer.writeByte('{');
    try writer.writeAll("\"repo_key\":");
    try writeJsonString(writer, repo.repo_key);
    try writer.writeAll(",\"provider\":");
    try writeJsonString(writer, repo.provider);
    try writer.writeAll(",\"default_branch\":");
    try writeJsonString(writer, repo.default_branch);
    try writer.writeAll(",\"checkout_path\":");
    try writeJsonString(writer, repo.checkout_path);
    try writer.writeAll(",\"review_policy_paths\":");
    try writer.writeAll(repo.review_policy_paths_json);
    try writer.writeAll(",\"default_review_commands\":");
    try writer.writeAll(repo.default_review_commands_json);
    try writer.writeAll(",\"approval_policy\":");
    try writer.writeAll(repo.approval_policy_json);
    if (repo.auto_intake) |value| {
        try writer.writeAll(",\"auto_intake\":");
        try writer.writeAll(if (value) "true" else "false");
    }
    if (repo.project_id) |value| {
        try writer.writeAll(",\"project_id\":");
        try writeJsonString(writer, value);
    }
    if (repo.agent_id) |value| {
        try writer.writeAll(",\"agent_id\":");
        try writeJsonString(writer, value);
    }
    if (repo.workspace_root) |value| {
        try writer.writeAll(",\"workspace_root\":");
        try writeJsonString(writer, value);
    }
    if (repo.worktree_name) |value| {
        try writer.writeAll(",\"worktree_name\":");
        try writeJsonString(writer, value);
    }
    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

fn buildRepoCatalogDetailJson(self: anytype, catalog_json: []const u8) ![]u8 {
    const escaped_config_path = try unified.jsonEscape(self.allocator, repo_catalog_path);
    defer self.allocator.free(escaped_config_path);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"config_path\":\"{s}\",\"catalog\":{s}}}",
        .{ escaped_config_path, catalog_json },
    );
}

fn buildRepoConfigDetailJson(self: anytype, repo_key: []const u8, repository_json: []const u8, repositories_count: usize) ![]u8 {
    const escaped_config_path = try unified.jsonEscape(self.allocator, repo_catalog_path);
    defer self.allocator.free(escaped_config_path);
    const escaped_repo_key = try unified.jsonEscape(self.allocator, repo_key);
    defer self.allocator.free(escaped_repo_key);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"config_path\":\"{s}\",\"repo_key\":\"{s}\",\"repositories_count\":{d},\"repository\":{s}}}",
        .{ escaped_config_path, escaped_repo_key, repositories_count, repository_json },
    );
}

pub fn bootstrapMission(self: anytype, args_obj: std.json.ObjectMap) !mission_store_mod.MissionRecord {
    const store = self.mission_store orelse return error.InvalidPayload;
    if (self.local_fs_export_root == null) return error.InvalidPayload;

    const repo_key_raw = extractOptionalStringByNames(args_obj, &[_][]const u8{"repo_key"}) orelse return error.InvalidPayload;
    const repo_key = std.mem.trim(u8, repo_key_raw, " \t\r\n");
    if (repo_key.len == 0) return error.InvalidPayload;
    const pr_number = (try jsonObjectOptionalU64(args_obj, "pr_number")) orelse return error.InvalidPayload;

    var configured_repo = try loadConfiguredRepo(self, repo_key);
    defer if (configured_repo) |*value| value.deinit(self.allocator);
    const repo_slug = try buildRepoKeySlug(self, repo_key);
    defer self.allocator.free(repo_slug);

    const provider = std.mem.trim(
        u8,
        extractOptionalStringByNames(args_obj, &[_][]const u8{"provider"}) orelse if (configured_repo) |value| value.provider else "github",
        " \t\r\n",
    );
    if (provider.len == 0) return error.InvalidPayload;
    const pr_url = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"pr_url"})) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else if (std.mem.eql(u8, provider, "github"))
        try std.fmt.allocPrint(self.allocator, "https://github.com/{s}/pull/{d}", .{ repo_key, pr_number })
    else
        return error.InvalidPayload;
    defer self.allocator.free(pr_url);

    const checkout_path = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"checkout_path"})) |value|
        try self.normalizeLocalWorkspaceAbsolutePath(value)
    else if (configured_repo) |value|
        try self.allocator.dupe(u8, value.checkout_path)
    else
        try std.fmt.allocPrint(self.allocator, "/nodes/local/fs/pr-review/repos/{s}", .{repo_slug});
    defer self.allocator.free(checkout_path);

    const context_path = try std.fmt.allocPrint(self.allocator, "/nodes/local/fs/pr-review/state/{s}/pr-{d}/context.json", .{ repo_slug, pr_number });
    defer self.allocator.free(context_path);
    const state_path = try std.fmt.allocPrint(self.allocator, "/nodes/local/fs/pr-review/state/{s}/pr-{d}/state.json", .{ repo_slug, pr_number });
    defer self.allocator.free(state_path);
    const artifact_root = try std.fmt.allocPrint(self.allocator, "/nodes/local/fs/pr-review/runs/{s}/pr-{d}", .{ repo_slug, pr_number });
    defer self.allocator.free(artifact_root);

    const review_policy_paths_json = blk: {
        if (args_obj.get("review_policy_paths")) |value| {
            if (value != .array) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        }
        if (configured_repo) |value| break :blk try self.allocator.dupe(u8, value.review_policy_paths_json);
        break :blk try self.allocator.dupe(u8, "[]");
    };
    defer self.allocator.free(review_policy_paths_json);

    const default_review_commands_json = blk: {
        if (args_obj.get("default_review_commands")) |value| {
            if (value != .array) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        }
        if (configured_repo) |value| break :blk try self.allocator.dupe(u8, value.default_review_commands_json);
        break :blk try self.allocator.dupe(u8, "[]");
    };
    defer self.allocator.free(default_review_commands_json);

    const approval_policy_json = blk: {
        if (args_obj.get("approval_policy")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        }
        if (configured_repo) |value| break :blk try self.allocator.dupe(u8, value.approval_policy_json);
        break :blk try self.allocator.dupe(u8, default_approval_policy_json);
    };
    defer self.allocator.free(approval_policy_json);

    const base_branch = std.mem.trim(
        u8,
        extractOptionalStringByNames(args_obj, &[_][]const u8{"base_branch"}) orelse if (configured_repo) |value| value.default_branch else "main",
        " \t\r\n",
    );
    const base_sha = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"base_sha"}) orelse "", " \t\r\n");
    const head_branch = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"head_branch"}) orelse "", " \t\r\n");
    const head_sha = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"head_sha"}) orelse "", " \t\r\n");
    const title = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"title"})) |value|
        std.mem.trim(u8, value, " \t\r\n")
    else
        null;
    const mission_title = if (title) |value|
        if (value.len > 0) value else null
    else
        null;
    const mission_title_fallback = try std.fmt.allocPrint(self.allocator, "Review PR #{d} ({s})", .{ pr_number, repo_key });
    defer self.allocator.free(mission_title_fallback);
    const derived_run_id = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"run_id"}) == null)
        try buildRunId(self, repo_key, pr_number)
    else
        null;
    defer if (derived_run_id) |value| self.allocator.free(value);

    var mission = try store.create(self.allocator, .{
        .use_case = "pr_review",
        .title = mission_title orelse mission_title_fallback,
        .stage = "planning",
        .agent_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"agent_id"}) orelse if (configured_repo) |value| value.agent_id orelse self.agent_id else self.agent_id,
        .project_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"project_id"}) orelse if (configured_repo) |value| value.project_id orelse self.project_id else self.project_id,
        .run_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"run_id"}) orelse derived_run_id,
        .workspace_root = extractOptionalStringByNames(args_obj, &[_][]const u8{"workspace_root"}) orelse if (configured_repo) |value| value.workspace_root orelse checkout_path else checkout_path,
        .worktree_name = extractOptionalStringByNames(args_obj, &[_][]const u8{"worktree_name"}) orelse if (configured_repo) |value| value.worktree_name else null,
        .contract = .{
            .contract_id = "spider_monkey/pr_review@v1",
            .context_path = context_path,
            .state_path = state_path,
            .artifact_root = artifact_root,
        },
        .created_by = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
    });
    defer mission.deinit(self.allocator);

    const context_payload = try self.buildPrReviewContextPayloadJson(
        provider,
        repo_key,
        pr_number,
        pr_url,
        base_branch,
        base_sha,
        head_branch,
        head_sha,
        checkout_path,
        review_policy_paths_json,
        default_review_commands_json,
        approval_policy_json,
    );
    defer self.allocator.free(context_payload);
    const state_payload = try self.buildDefaultPrReviewStatePayloadJson(head_sha);
    defer self.allocator.free(state_payload);

    try self.ensureMissionContractDirectory(artifact_root);
    try self.writeMissionContractFile(context_path, context_payload);
    try self.writeMissionContractFile(state_path, state_payload);

    const bootstrapped = try store.recordCheckpoint(self.allocator, mission.mission_id, .{
        .stage = "bootstrap_context",
        .summary = "Bootstrapped PR review contract",
        .artifact = .{
            .kind = "contract_state",
            .path = state_path,
            .summary = "PR review state file",
        },
        .contract = .{
            .contract_id = "spider_monkey/pr_review@v1",
            .context_path = context_path,
            .state_path = state_path,
            .artifact_root = artifact_root,
        },
    });

    return bootstrapped;
}

pub fn resolveMissionContract(self: anytype, mission: mission_store_mod.MissionRecord) !ResolvedContract {
    if (!std.mem.eql(u8, mission.use_case, "pr_review")) return error.InvalidPayload;
    const contract = mission.contract orelse return error.InvalidPayload;
    if (!std.mem.eql(u8, contract.contract_id, "spider_monkey/pr_review@v1")) return error.InvalidPayload;
    return .{
        .contract_id = try self.allocator.dupe(u8, contract.contract_id),
        .context_path = try self.allocator.dupe(u8, contract.context_path orelse return error.InvalidPayload),
        .state_path = try self.allocator.dupe(u8, contract.state_path orelse return error.InvalidPayload),
        .artifact_root = try self.allocator.dupe(u8, contract.artifact_root orelse return error.InvalidPayload),
    };
}

pub fn buildRunId(self: anytype, repo_key: []const u8, pr_number: u64) ![]u8 {
    const repo_slug = try buildRepoKeySlug(self, repo_key);
    defer self.allocator.free(repo_slug);
    return std.fmt.allocPrint(self.allocator, "pr_review:{s}:{d}", .{ repo_slug, pr_number });
}

pub fn findActiveMissionByRunId(
    self: anytype,
    store: *mission_store_mod.MissionStore,
    run_id: []const u8,
    project_id: ?[]const u8,
) !?mission_store_mod.MissionRecord {
    const missions = try store.listOwned(self.allocator, .{ .use_case = "pr_review" });
    defer {
        for (missions) |*item| item.deinit(self.allocator);
        self.allocator.free(missions);
    }

    for (missions) |mission| {
        const mission_run_id = mission.run_id orelse continue;
        if (!std.mem.eql(u8, mission_run_id, run_id)) continue;
        if (!sameOptionalString(project_id, mission.project_id)) continue;
        if (!isActiveMissionState(mission.state)) continue;
        return try mission.cloneOwned(self.allocator);
    }
    return null;
}

pub fn loadContextSnapshot(self: anytype, context_path: []const u8) !ContextSnapshot {
    const raw = try self.readMissionContractFile(context_path, 512 * 1024);
    defer self.allocator.free(raw);
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const provider = std.mem.trim(u8, (try jsonObjectOptionalString(obj, "provider")) orelse "github", " \t\r\n");
    const repo_key = std.mem.trim(u8, (try jsonObjectOptionalString(obj, "repo_key")) orelse return error.InvalidPayload, " \t\r\n");
    if (provider.len == 0 or repo_key.len == 0) return error.InvalidPayload;

    return .{
        .provider = try self.allocator.dupe(u8, provider),
        .repo_key = try self.allocator.dupe(u8, repo_key),
        .pr_number = (try jsonObjectOptionalU64(obj, "pr_number")) orelse return error.InvalidPayload,
        .pr_url = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "pr_url")) orelse ""),
        .base_branch = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "base_branch")) orelse "main"),
        .base_sha = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "base_sha")) orelse ""),
        .head_branch = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "head_branch")) orelse ""),
        .head_sha = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "head_sha")) orelse ""),
        .checkout_path = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "checkout_path")) orelse return error.InvalidPayload),
        .review_policy_paths_json = try renderJsonFieldOrDefault(self, obj, "review_policy_paths", "[]"),
        .default_review_commands_json = try renderJsonFieldOrDefault(self, obj, "default_review_commands", "[]"),
        .approval_policy_json = try renderJsonFieldOrDefault(
            self,
            obj,
            "approval_policy",
            "{\"push_fix_requires_approval\":false,\"merge_requires_approval\":true}",
        ),
    };
}

pub fn loadStateSnapshot(self: anytype, state_path: []const u8) !StateSnapshot {
    const raw = try self.readMissionContractFile(state_path, 512 * 1024);
    defer self.allocator.free(raw);
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const validation_obj = if (obj.get("latest_validation")) |value| blk: {
        if (value == .object) break :blk value.object;
        if (value == .null) break :blk null;
        return error.InvalidPayload;
    } else null;
    const draft_obj = if (obj.get("latest_draft")) |value| blk: {
        if (value == .object) break :blk value.object;
        if (value == .null) break :blk null;
        return error.InvalidPayload;
    } else null;
    const recommendation_obj = if (obj.get("latest_recommendation")) |value| blk: {
        if (value == .object) break :blk value.object;
        if (value == .null) break :blk null;
        return error.InvalidPayload;
    } else null;
    const artifacts_obj = if (obj.get("artifacts")) |value| blk: {
        if (value == .object) break :blk value.object;
        if (value == .null) break :blk null;
        return error.InvalidPayload;
    } else null;

    return .{
        .phase = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "phase")) orelse "discovered"),
        .last_synced_head_sha = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "last_synced_head_sha")) orelse ""),
        .current_focus = try self.allocator.dupe(u8, (try jsonObjectOptionalString(obj, "current_focus")) orelse ""),
        .open_threads_json = try renderJsonFieldOrDefault(self, obj, "open_threads", "[]"),
        .latest_validation_status = try self.allocator.dupe(u8, if (validation_obj) |value| (try jsonObjectOptionalString(value, "status")) orelse "unknown" else "unknown"),
        .latest_validation_summary = if (validation_obj) |value|
            if (try jsonObjectOptionalString(value, "summary")) |summary| try self.allocator.dupe(u8, summary) else null
        else
            null,
        .latest_draft_status = try self.allocator.dupe(u8, if (draft_obj) |value| (try jsonObjectOptionalString(value, "status")) orelse "pending" else "pending"),
        .latest_draft_summary = if (draft_obj) |value|
            if (try jsonObjectOptionalString(value, "summary")) |summary| try self.allocator.dupe(u8, summary) else null
        else
            null,
        .latest_draft_revision = if (draft_obj) |value| (try jsonObjectOptionalU64(value, "revision")) orelse 0 else 0,
        .latest_recommendation_status = try self.allocator.dupe(u8, if (recommendation_obj) |value| (try jsonObjectOptionalString(value, "status")) orelse "pending" else "pending"),
        .latest_recommendation_summary = if (recommendation_obj) |value|
            if (try jsonObjectOptionalString(value, "summary")) |summary| try self.allocator.dupe(u8, summary) else null
        else
            null,
        .draft_review_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "draft_review")) orelse "draft-review.json" else "draft-review.json"),
        .draft_review_comment_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "draft_review_comment")) orelse "review-comment-draft.md" else "review-comment-draft.md"),
        .draft_history_dir = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "draft_history_dir")) orelse "drafts" else "drafts"),
        .findings_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "findings")) orelse "findings.json" else "findings.json"),
        .validation_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "validation")) orelse "validation.json" else "validation.json"),
        .recommendation_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "recommendation")) orelse "recommendation.json" else "recommendation.json"),
        .thread_actions_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "thread_actions")) orelse "thread-actions.json" else "thread-actions.json"),
        .provider_sync_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "provider_sync")) orelse "services/provider-sync.json" else "services/provider-sync.json"),
        .checkout_sync_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "checkout")) orelse "services/checkout.json" else "services/checkout.json"),
        .repo_status_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "repo_status")) orelse "services/repo-status.json" else "services/repo-status.json"),
        .diff_range_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "diff_range")) orelse "services/diff-range.json" else "services/diff-range.json"),
        .publish_review_artifact = try self.allocator.dupe(u8, if (artifacts_obj) |value| (try jsonObjectOptionalString(value, "publish_review")) orelse "services/publish-review.json" else "services/publish-review.json"),
        .notes_json = try renderJsonFieldOrDefault(self, obj, "notes", "[]"),
    };
}

pub fn renderPrReviewStringArg(
    self: anytype,
    overrides: ?std.json.ObjectMap,
    names: []const []const u8,
    default: ?[]const u8,
) ![]u8 {
    if (overrides) |obj| {
        if (self.findJsonObjectFieldByNames(obj, names)) |value| {
            if (value == .null) return self.allocator.dupe(u8, "null");
            if (value != .string) return error.InvalidPayload;
            return self.formatJsonString(std.mem.trim(u8, value.string, " \t\r\n"));
        }
    }
    if (default) |value| return self.formatJsonString(value);
    return self.allocator.dupe(u8, "null");
}

pub fn renderPrReviewU64Arg(
    self: anytype,
    overrides: ?std.json.ObjectMap,
    names: []const []const u8,
    default: ?u64,
) ![]u8 {
    if (overrides) |obj| {
        if (self.findJsonObjectFieldByNames(obj, names)) |value| {
            if (value == .null) return self.allocator.dupe(u8, "null");
            return switch (value) {
                .integer => |signed| blk: {
                    if (signed < 0) return error.InvalidPayload;
                    break :blk std.fmt.allocPrint(self.allocator, "{d}", .{@as(u64, @intCast(signed))});
                },
                .float => |float_value| blk: {
                    if (float_value < 0 or std.math.floor(float_value) != float_value) return error.InvalidPayload;
                    if (float_value > @as(f64, @floatFromInt(std.math.maxInt(u64)))) return error.InvalidPayload;
                    break :blk std.fmt.allocPrint(self.allocator, "{d}", .{@as(u64, @intFromFloat(float_value))});
                },
                else => error.InvalidPayload,
            };
        }
    }
    if (default) |value| return std.fmt.allocPrint(self.allocator, "{d}", .{value});
    return self.allocator.dupe(u8, "null");
}

pub fn renderPrReviewBoolArg(
    self: anytype,
    overrides: ?std.json.ObjectMap,
    names: []const []const u8,
    default: ?bool,
) ![]u8 {
    if (overrides) |obj| {
        if (self.findJsonObjectFieldByNames(obj, names)) |value| {
            if (value == .null) return self.allocator.dupe(u8, "null");
            if (value != .bool) return error.InvalidPayload;
            return self.allocator.dupe(u8, if (value.bool) "true" else "false");
        }
    }
    if (default) |value| return self.allocator.dupe(u8, if (value) "true" else "false");
    return self.allocator.dupe(u8, "null");
}

pub fn buildPrReviewGitHubSyncRequestJson(
    self: anytype,
    context: ContextSnapshot,
    overrides: ?std.json.ObjectMap,
) ![]u8 {
    const repo_key_json = try renderPrReviewStringArg(self, overrides, &.{"repo_key"}, context.repo_key);
    defer self.allocator.free(repo_key_json);
    const pr_number_json = try renderPrReviewU64Arg(self, overrides, &.{"pr_number"}, context.pr_number);
    defer self.allocator.free(pr_number_json);
    const dry_run_json = try renderPrReviewBoolArg(self, overrides, &.{"dry_run"}, false);
    defer self.allocator.free(dry_run_json);
    const timeout_ms_json = try renderPrReviewU64Arg(self, overrides, &.{"timeout_ms"}, null);
    defer self.allocator.free(timeout_ms_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"repo_key\":{s},\"pr_number\":{s},\"dry_run\":{s},\"timeout_ms\":{s}}}",
        .{ repo_key_json, pr_number_json, dry_run_json, timeout_ms_json },
    );
}

pub fn buildPrReviewGitSyncCheckoutRequestJson(
    self: anytype,
    context: ContextSnapshot,
    overrides: ?std.json.ObjectMap,
) ![]u8 {
    const provider_json = try renderPrReviewStringArg(self, overrides, &.{"provider"}, context.provider);
    defer self.allocator.free(provider_json);
    const repo_key_json = try renderPrReviewStringArg(self, overrides, &.{"repo_key"}, context.repo_key);
    defer self.allocator.free(repo_key_json);
    const repo_url_json = try renderPrReviewStringArg(self, overrides, &.{"repo_url"}, null);
    defer self.allocator.free(repo_url_json);
    const checkout_path_json = try renderPrReviewStringArg(self, overrides, &.{"checkout_path"}, context.checkout_path);
    defer self.allocator.free(checkout_path_json);
    const base_branch_json = try renderPrReviewStringArg(self, overrides, &.{"base_branch"}, context.base_branch);
    defer self.allocator.free(base_branch_json);
    const head_branch_json = try renderPrReviewStringArg(self, overrides, &.{"head_branch"}, context.head_branch);
    defer self.allocator.free(head_branch_json);
    const head_sha_json = try renderPrReviewStringArg(self, overrides, &.{"head_sha"}, context.head_sha);
    defer self.allocator.free(head_sha_json);
    const pr_number_json = try renderPrReviewU64Arg(self, overrides, &.{"pr_number"}, context.pr_number);
    defer self.allocator.free(pr_number_json);
    const timeout_ms_json = try renderPrReviewU64Arg(self, overrides, &.{"timeout_ms"}, null);
    defer self.allocator.free(timeout_ms_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"provider\":{s},\"repo_key\":{s},\"repo_url\":{s},\"checkout_path\":{s},\"base_branch\":{s},\"head_branch\":{s},\"head_sha\":{s},\"pr_number\":{s},\"timeout_ms\":{s}}}",
        .{
            provider_json,
            repo_key_json,
            repo_url_json,
            checkout_path_json,
            base_branch_json,
            head_branch_json,
            head_sha_json,
            pr_number_json,
            timeout_ms_json,
        },
    );
}

pub fn buildPrReviewGitStatusRequestJson(
    self: anytype,
    context: ContextSnapshot,
    overrides: ?std.json.ObjectMap,
) ![]u8 {
    const checkout_path_json = try renderPrReviewStringArg(self, overrides, &.{"checkout_path"}, context.checkout_path);
    defer self.allocator.free(checkout_path_json);
    const base_ref_json = try renderPrReviewStringArg(self, overrides, &.{"base_ref"}, null);
    defer self.allocator.free(base_ref_json);
    const base_branch_json = try renderPrReviewStringArg(self, overrides, &.{"base_branch"}, context.base_branch);
    defer self.allocator.free(base_branch_json);
    const timeout_ms_json = try renderPrReviewU64Arg(self, overrides, &.{"timeout_ms"}, null);
    defer self.allocator.free(timeout_ms_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"checkout_path\":{s},\"base_ref\":{s},\"base_branch\":{s},\"timeout_ms\":{s}}}",
        .{ checkout_path_json, base_ref_json, base_branch_json, timeout_ms_json },
    );
}

pub fn buildPrReviewGitDiffRangeRequestJson(
    self: anytype,
    context: ContextSnapshot,
    overrides: ?std.json.ObjectMap,
) ![]u8 {
    const checkout_path_json = try renderPrReviewStringArg(self, overrides, &.{"checkout_path"}, context.checkout_path);
    defer self.allocator.free(checkout_path_json);
    const base_ref_json = try renderPrReviewStringArg(self, overrides, &.{"base_ref"}, null);
    defer self.allocator.free(base_ref_json);
    const base_branch_json = try renderPrReviewStringArg(self, overrides, &.{"base_branch"}, context.base_branch);
    defer self.allocator.free(base_branch_json);
    const head_ref_json = try renderPrReviewStringArg(self, overrides, &.{"head_ref"}, "HEAD");
    defer self.allocator.free(head_ref_json);
    const symmetric_json = try renderPrReviewBoolArg(self, overrides, &.{"symmetric"}, true);
    defer self.allocator.free(symmetric_json);
    const timeout_ms_json = try renderPrReviewU64Arg(self, overrides, &.{"timeout_ms"}, null);
    defer self.allocator.free(timeout_ms_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"checkout_path\":{s},\"base_ref\":{s},\"base_branch\":{s},\"head_ref\":{s},\"symmetric\":{s},\"timeout_ms\":{s}}}",
        .{ checkout_path_json, base_ref_json, base_branch_json, head_ref_json, symmetric_json, timeout_ms_json },
    );
}

pub fn buildPrReviewGitHubPublishRequestJson(
    self: anytype,
    context: ContextSnapshot,
    recommendation_value: std.json.Value,
    review_comment: ?[]const u8,
    thread_actions_value: ?std.json.Value,
    overrides: ?std.json.ObjectMap,
) ![]u8 {
    const repo_key_json = try renderPrReviewStringArg(self, overrides, &.{"repo_key"}, context.repo_key);
    defer self.allocator.free(repo_key_json);
    const pr_number_json = try renderPrReviewU64Arg(self, overrides, &.{"pr_number"}, context.pr_number);
    defer self.allocator.free(pr_number_json);
    const default_decision = try recommendationDecisionFromValue(recommendation_value);
    const decision_json = try renderPrReviewStringArg(self, overrides, &.{"decision"}, default_decision);
    defer self.allocator.free(decision_json);
    const body_json = try renderPrReviewStringArg(self, overrides, &.{ "body", "review_comment" }, review_comment);
    defer self.allocator.free(body_json);
    const dry_run_json = try renderPrReviewBoolArg(self, overrides, &.{"dry_run"}, false);
    defer self.allocator.free(dry_run_json);
    const timeout_ms_json = try renderPrReviewU64Arg(self, overrides, &.{"timeout_ms"}, null);
    defer self.allocator.free(timeout_ms_json);
    const thread_actions_json = if (overrides) |obj|
        if (self.findJsonObjectFieldByNames(obj, &.{"thread_actions"})) |value|
            if (value == .null)
                try self.allocator.dupe(u8, "null")
            else if (value == .array)
                try self.renderJsonValue(value)
            else
                return error.InvalidPayload
        else if (thread_actions_value) |value|
            try self.renderJsonValue(value)
        else
            try self.allocator.dupe(u8, "null")
    else if (thread_actions_value) |value|
        try self.renderJsonValue(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(thread_actions_json);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"repo_key\":{s},\"pr_number\":{s},\"decision\":{s},\"body\":{s},\"dry_run\":{s},\"timeout_ms\":{s},\"thread_actions\":{s}}}",
        .{ repo_key_json, pr_number_json, decision_json, body_json, dry_run_json, timeout_ms_json, thread_actions_json },
    );
}

pub fn buildPrReviewTerminalCreateRequestJson(self: anytype, checkout_path: []const u8) ![]u8 {
    const escaped_checkout_path = try unified.jsonEscape(self.allocator, checkout_path);
    defer self.allocator.free(escaped_checkout_path);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"cwd\":\"{s}\",\"label\":\"PR Review Validation\"}}",
        .{escaped_checkout_path},
    );
}

pub fn buildPrReviewValidationExecRequestJson(
    self: anytype,
    command_value: std.json.Value,
    checkout_path: []const u8,
) ![]u8 {
    return switch (command_value) {
        .string => blk: {
            const escaped_command = try unified.jsonEscape(self.allocator, std.mem.trim(u8, command_value.string, " \t\r\n"));
            defer self.allocator.free(escaped_command);
            const escaped_checkout_path = try unified.jsonEscape(self.allocator, checkout_path);
            defer self.allocator.free(escaped_checkout_path);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"command\":\"{s}\",\"cwd\":\"{s}\"}}",
                .{ escaped_command, escaped_checkout_path },
            );
        },
        .object => self.buildTerminalExecArgsJson(command_value.object, checkout_path),
        else => error.InvalidPayload,
    };
}

pub fn buildPrReviewServiceArtifactPayloadJson(
    self: anytype,
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
        "{{\"service_path\":\"{s}\",\"invoke_path\":\"{s}\",\"request\":{s},\"result\":{s},\"status\":{s}}}",
        .{ escaped_service_path, escaped_invoke_path, request_payload_json, result_payload_json, status_json },
    );
}

pub fn invokePrReviewServiceCapture(
    self: anytype,
    store: *mission_store_mod.MissionStore,
    mission_id: []const u8,
    stage: []const u8,
    summary: []const u8,
    service_path: []const u8,
    invoke_path: []const u8,
    request_payload: []const u8,
    artifact_root: []const u8,
    artifact_relative_path: []const u8,
    artifact_kind: []const u8,
) !ServiceCapture {
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
    errdefer if (status_payload) |value| self.allocator.free(value);
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
    errdefer self.allocator.free(effective_result_payload);

    const artifact_payload = try buildPrReviewServiceArtifactPayloadJson(
        self,
        service_path,
        invoke_path,
        request_payload,
        effective_result_payload,
        status_payload,
    );
    defer self.allocator.free(artifact_payload);

    const artifact_path = try self.writePrReviewArtifactPayload(artifact_root, artifact_relative_path, artifact_payload);
    errdefer self.allocator.free(artifact_path);

    var mission = store.recordServiceInvocation(self.allocator, mission_id, .{
        .stage = stage,
        .summary = summary,
        .service_path = service_path,
        .invoke_path = invoke_path,
        .request_payload_json = request_payload,
        .result_payload_json = effective_result_payload,
        .status_payload_json = status_payload,
        .artifact = .{
            .kind = artifact_kind,
            .path = artifact_path,
            .summary = summary,
        },
        .actor = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
    }) catch |err| switch (err) {
        mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
        else => return error.InvalidPayload,
    };
    mission.deinit(self.allocator);

    return .{
        .artifact_path = artifact_path,
        .result_payload = effective_result_payload,
        .status_payload = status_payload,
    };
}

pub fn applyPrReviewContextFromGitHubSyncPayload(
    self: anytype,
    context: *ContextSnapshot,
    state: *StateSnapshot,
    payload_json: []const u8,
) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const root = parsed.value.object;
    const result_value = root.get("result") orelse return;
    if (result_value != .object) return;
    const provider_value = result_value.object.get("provider") orelse return;
    if (provider_value != .object) return;
    const provider_obj = provider_value.object;

    if (try jsonObjectOptionalString(provider_obj, "url")) |value| if (value.len > 0) try self.replaceOwnedString(&context.pr_url, value);
    if (try jsonObjectOptionalString(provider_obj, "baseRefName")) |value| if (value.len > 0) try self.replaceOwnedString(&context.base_branch, value);
    if (try jsonObjectOptionalString(provider_obj, "baseRefOid")) |value| if (value.len > 0) try self.replaceOwnedString(&context.base_sha, value);
    if (try jsonObjectOptionalString(provider_obj, "headRefName")) |value| if (value.len > 0) try self.replaceOwnedString(&context.head_branch, value);
    if (try jsonObjectOptionalString(provider_obj, "headRefOid")) |value| {
        if (value.len > 0) {
            try self.replaceOwnedString(&context.head_sha, value);
            try self.replaceOwnedString(&state.last_synced_head_sha, value);
        }
    }
}

pub fn applyPrReviewContextFromGitSyncPayload(
    self: anytype,
    context: *ContextSnapshot,
    state: *StateSnapshot,
    payload_json: []const u8,
) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const root = parsed.value.object;
    const result_value = root.get("result") orelse return;
    if (result_value != .object) return;
    const result_obj = result_value.object;

    if (try jsonObjectOptionalString(result_obj, "checkout_path")) |value| if (value.len > 0) try self.replaceOwnedString(&context.checkout_path, value);
    if (try jsonObjectOptionalString(result_obj, "base_branch")) |value| if (value.len > 0) try self.replaceOwnedString(&context.base_branch, value);
    if (try jsonObjectOptionalString(result_obj, "head_branch")) |value| if (value.len > 0) try self.replaceOwnedString(&context.head_branch, value);
    if (try jsonObjectOptionalString(result_obj, "base_sha")) |value| if (value.len > 0) try self.replaceOwnedString(&context.base_sha, value);
    if (try jsonObjectOptionalString(result_obj, "head_sha")) |value| {
        if (value.len > 0) {
            try self.replaceOwnedString(&context.head_sha, value);
            try self.replaceOwnedString(&state.last_synced_head_sha, value);
        }
    }
}

pub fn applyPrReviewContextFromGitStatusPayload(
    self: anytype,
    context: *ContextSnapshot,
    state: *StateSnapshot,
    payload_json: []const u8,
) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const root = parsed.value.object;
    const result_value = root.get("result") orelse return;
    if (result_value != .object) return;
    const result_obj = result_value.object;

    if (try jsonObjectOptionalString(result_obj, "head_sha")) |value| {
        if (value.len > 0) {
            try self.replaceOwnedString(&context.head_sha, value);
            try self.replaceOwnedString(&state.last_synced_head_sha, value);
        }
    }
}

pub fn applyPrReviewCommonStateFields(self: anytype, args_obj: std.json.ObjectMap, state: *StateSnapshot) !void {
    if (args_obj.get("phase")) |value| {
        if (value != .string) return error.InvalidPayload;
        const phase = std.mem.trim(u8, value.string, " \t\r\n");
        if (phase.len == 0) return error.InvalidPayload;
        try self.replaceOwnedString(&state.phase, phase);
    }
    if (args_obj.get("head_sha")) |value| {
        if (value != .string) return error.InvalidPayload;
        try self.replaceOwnedString(&state.last_synced_head_sha, std.mem.trim(u8, value.string, " \t\r\n"));
    } else if (args_obj.get("last_synced_head_sha")) |value| {
        if (value != .string) return error.InvalidPayload;
        try self.replaceOwnedString(&state.last_synced_head_sha, std.mem.trim(u8, value.string, " \t\r\n"));
    }
    if (args_obj.get("current_focus")) |value| {
        if (value != .string) return error.InvalidPayload;
        try self.replaceOwnedString(&state.current_focus, value.string);
    }
    if (args_obj.get("open_threads")) |value| {
        if (value != .array and value != .null) return error.InvalidPayload;
        try self.replaceOwnedJsonValue(&state.open_threads_json, value, "[]");
    }
    if (args_obj.get("notes")) |value| {
        if (value != .array and value != .null) return error.InvalidPayload;
        try self.replaceOwnedJsonValue(&state.notes_json, value, "[]");
    }
}

pub fn resolvePrReviewArtifactPath(self: anytype, artifact_root: []const u8, artifact_relative_path: []const u8) ![]u8 {
    const normalized_relative = try self.normalizeLocalFsRelativePath(artifact_relative_path);
    defer self.allocator.free(normalized_relative);
    const base = try self.normalizeMissionAbsolutePath(artifact_root);
    defer self.allocator.free(base);
    return std.fmt.allocPrint(
        self.allocator,
        "{s}/{s}",
        .{ std.mem.trimRight(u8, base, "/"), normalized_relative },
    );
}

pub fn writePrReviewJsonArtifact(
    self: anytype,
    artifact_root: []const u8,
    artifact_relative_path: []const u8,
    value: std.json.Value,
) ![]u8 {
    const artifact_path = try resolvePrReviewArtifactPath(self, artifact_root, artifact_relative_path);
    errdefer self.allocator.free(artifact_path);
    const payload = try self.renderJsonValue(value);
    defer self.allocator.free(payload);
    try self.writeMissionContractFile(artifact_path, payload);
    return artifact_path;
}

pub fn writePrReviewArtifactPayload(
    self: anytype,
    artifact_root: []const u8,
    artifact_relative_path: []const u8,
    payload_json: []const u8,
) ![]u8 {
    const artifact_path = try resolvePrReviewArtifactPath(self, artifact_root, artifact_relative_path);
    errdefer self.allocator.free(artifact_path);
    try self.writeMissionContractFile(artifact_path, payload_json);
    return artifact_path;
}

pub fn writePrReviewTextArtifact(
    self: anytype,
    artifact_root: []const u8,
    artifact_relative_path: []const u8,
    content: []const u8,
) ![]u8 {
    const artifact_path = try resolvePrReviewArtifactPath(self, artifact_root, artifact_relative_path);
    errdefer self.allocator.free(artifact_path);
    try self.writeMissionContractFile(artifact_path, content);
    return artifact_path;
}

fn buildDraftHistoryRelativePath(
    self: anytype,
    history_dir: []const u8,
    stem: []const u8,
    suffix: []const u8,
    revision: u64,
) ![]u8 {
    const normalized_dir = try self.normalizeLocalFsRelativePath(history_dir);
    defer self.allocator.free(normalized_dir);
    return std.fmt.allocPrint(
        self.allocator,
        "{s}/{s}-{d:0>3}{s}",
        .{ normalized_dir, stem, revision, suffix },
    );
}

fn buildPrReviewDraftPayloadJson(
    self: anytype,
    revision: u64,
    phase: []const u8,
    status: []const u8,
    summary: ?[]const u8,
    current_focus: []const u8,
    findings_value: ?std.json.Value,
    recommendation_value: ?std.json.Value,
    review_comment: ?[]const u8,
    thread_actions_value: ?std.json.Value,
    open_threads_json: []const u8,
    notes_json: []const u8,
) ![]u8 {
    const escaped_phase = try unified.jsonEscape(self.allocator, phase);
    defer self.allocator.free(escaped_phase);
    const escaped_status = try unified.jsonEscape(self.allocator, status);
    defer self.allocator.free(escaped_status);
    const escaped_focus = try unified.jsonEscape(self.allocator, current_focus);
    defer self.allocator.free(escaped_focus);
    const summary_json = if (summary) |value|
        try self.formatJsonString(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(summary_json);
    const findings_json = if (findings_value) |value|
        try self.renderJsonValue(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(findings_json);
    const recommendation_json = if (recommendation_value) |value|
        try self.renderJsonValue(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(recommendation_json);
    const review_comment_json = if (review_comment) |value|
        try self.formatJsonString(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(review_comment_json);
    const thread_actions_json = if (thread_actions_value) |value|
        try self.renderJsonValue(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(thread_actions_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"revision\":{d},\"phase\":\"{s}\",\"status\":\"{s}\",\"summary\":{s},\"current_focus\":\"{s}\",\"findings\":{s},\"recommendation\":{s},\"review_comment\":{s},\"thread_actions\":{s},\"open_threads\":{s},\"notes\":{s}}}",
        .{
            revision,
            escaped_phase,
            escaped_status,
            summary_json,
            escaped_focus,
            findings_json,
            recommendation_json,
            review_comment_json,
            thread_actions_json,
            open_threads_json,
            notes_json,
        },
    );
}

pub fn buildPrReviewContextPayloadJson(
    self: anytype,
    provider: []const u8,
    repo_key: []const u8,
    pr_number: u64,
    pr_url: []const u8,
    base_branch: []const u8,
    base_sha: []const u8,
    head_branch: []const u8,
    head_sha: []const u8,
    checkout_path: []const u8,
    review_policy_paths_json: []const u8,
    default_review_commands_json: []const u8,
    approval_policy_json: []const u8,
) ![]u8 {
    const escaped_provider = try unified.jsonEscape(self.allocator, provider);
    defer self.allocator.free(escaped_provider);
    const escaped_repo_key = try unified.jsonEscape(self.allocator, repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_pr_url = try unified.jsonEscape(self.allocator, pr_url);
    defer self.allocator.free(escaped_pr_url);
    const escaped_base_branch = try unified.jsonEscape(self.allocator, base_branch);
    defer self.allocator.free(escaped_base_branch);
    const escaped_base_sha = try unified.jsonEscape(self.allocator, base_sha);
    defer self.allocator.free(escaped_base_sha);
    const escaped_head_branch = try unified.jsonEscape(self.allocator, head_branch);
    defer self.allocator.free(escaped_head_branch);
    const escaped_head_sha = try unified.jsonEscape(self.allocator, head_sha);
    defer self.allocator.free(escaped_head_sha);
    const escaped_checkout_path = try unified.jsonEscape(self.allocator, checkout_path);
    defer self.allocator.free(escaped_checkout_path);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"contract_id\":\"spider_monkey/pr_review@v1\",\"provider\":\"{s}\",\"repo_key\":\"{s}\",\"pr_number\":{d},\"pr_url\":\"{s}\",\"base_branch\":\"{s}\",\"base_sha\":\"{s}\",\"head_branch\":\"{s}\",\"head_sha\":\"{s}\",\"checkout_path\":\"{s}\",\"review_policy_paths\":{s},\"default_review_commands\":{s},\"approval_policy\":{s}}}",
        .{
            escaped_provider,
            escaped_repo_key,
            pr_number,
            escaped_pr_url,
            escaped_base_branch,
            escaped_base_sha,
            escaped_head_branch,
            escaped_head_sha,
            escaped_checkout_path,
            review_policy_paths_json,
            default_review_commands_json,
            approval_policy_json,
        },
    );
}

pub fn buildDefaultPrReviewStatePayloadJson(self: anytype, head_sha: []const u8) ![]u8 {
    const escaped_head_sha = try unified.jsonEscape(self.allocator, head_sha);
    defer self.allocator.free(escaped_head_sha);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"phase\":\"discovered\",\"last_synced_head_sha\":\"{s}\",\"current_focus\":\"\",\"open_threads\":[],\"latest_validation\":{{\"status\":\"unknown\",\"summary\":null}},\"latest_draft\":{{\"status\":\"pending\",\"summary\":null,\"revision\":0}},\"latest_recommendation\":{{\"status\":\"pending\",\"summary\":null}},\"artifacts\":{{\"draft_review\":\"draft-review.json\",\"draft_review_comment\":\"review-comment-draft.md\",\"draft_history_dir\":\"drafts\",\"findings\":\"findings.json\",\"validation\":\"validation.json\",\"recommendation\":\"recommendation.json\",\"thread_actions\":\"thread-actions.json\",\"provider_sync\":\"services/provider-sync.json\",\"checkout\":\"services/checkout.json\",\"repo_status\":\"services/repo-status.json\",\"diff_range\":\"services/diff-range.json\",\"publish_review\":\"services/publish-review.json\"}},\"notes\":[]}}",
        .{escaped_head_sha},
    );
}

pub fn buildPrReviewStatePayloadJson(self: anytype, state: StateSnapshot) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);

    try writer.writeByte('{');
    try writer.writeAll("\"phase\":");
    try writeJsonString(writer, state.phase);
    try writer.writeAll(",\"last_synced_head_sha\":");
    try writeJsonString(writer, state.last_synced_head_sha);
    try writer.writeAll(",\"current_focus\":");
    try writeJsonString(writer, state.current_focus);
    try writer.writeAll(",\"open_threads\":");
    try writer.writeAll(state.open_threads_json);
    try writer.writeAll(",\"latest_validation\":{");
    try writer.writeAll("\"status\":");
    try writeJsonString(writer, state.latest_validation_status);
    try writer.writeAll(",\"summary\":");
    if (state.latest_validation_summary) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeByte('}');
    try writer.writeAll(",\"latest_draft\":{");
    try writer.writeAll("\"status\":");
    try writeJsonString(writer, state.latest_draft_status);
    try writer.writeAll(",\"summary\":");
    if (state.latest_draft_summary) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeAll(",\"revision\":");
    try writer.print("{d}", .{state.latest_draft_revision});
    try writer.writeByte('}');
    try writer.writeAll(",\"latest_recommendation\":{");
    try writer.writeAll("\"status\":");
    try writeJsonString(writer, state.latest_recommendation_status);
    try writer.writeAll(",\"summary\":");
    if (state.latest_recommendation_summary) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
    try writer.writeByte('}');
    try writer.writeAll(",\"artifacts\":{");
    try writer.writeAll("\"draft_review\":");
    try writeJsonString(writer, state.draft_review_artifact);
    try writer.writeAll(",\"draft_review_comment\":");
    try writeJsonString(writer, state.draft_review_comment_artifact);
    try writer.writeAll(",\"draft_history_dir\":");
    try writeJsonString(writer, state.draft_history_dir);
    try writer.writeAll(",\"findings\":");
    try writeJsonString(writer, state.findings_artifact);
    try writer.writeAll(",\"validation\":");
    try writeJsonString(writer, state.validation_artifact);
    try writer.writeAll(",\"recommendation\":");
    try writeJsonString(writer, state.recommendation_artifact);
    try writer.writeAll(",\"thread_actions\":");
    try writeJsonString(writer, state.thread_actions_artifact);
    try writer.writeAll(",\"provider_sync\":");
    try writeJsonString(writer, state.provider_sync_artifact);
    try writer.writeAll(",\"checkout\":");
    try writeJsonString(writer, state.checkout_sync_artifact);
    try writer.writeAll(",\"repo_status\":");
    try writeJsonString(writer, state.repo_status_artifact);
    try writer.writeAll(",\"diff_range\":");
    try writeJsonString(writer, state.diff_range_artifact);
    try writer.writeAll(",\"publish_review\":");
    try writeJsonString(writer, state.publish_review_artifact);
    try writer.writeByte('}');
    try writer.writeAll(",\"notes\":");
    try writer.writeAll(state.notes_json);
    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

pub fn buildPrReviewStartDetailJson(
    self: anytype,
    mission_json: []const u8,
    provider: []const u8,
    repo_key: []const u8,
    pr_number: u64,
    pr_url: []const u8,
    checkout_path: []const u8,
    context_path: []const u8,
    state_path: []const u8,
    artifact_root: []const u8,
) ![]u8 {
    const escaped_provider = try unified.jsonEscape(self.allocator, provider);
    defer self.allocator.free(escaped_provider);
    const escaped_repo_key = try unified.jsonEscape(self.allocator, repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_pr_url = try unified.jsonEscape(self.allocator, pr_url);
    defer self.allocator.free(escaped_pr_url);
    const escaped_checkout_path = try unified.jsonEscape(self.allocator, checkout_path);
    defer self.allocator.free(escaped_checkout_path);
    const escaped_context_path = try unified.jsonEscape(self.allocator, context_path);
    defer self.allocator.free(escaped_context_path);
    const escaped_state_path = try unified.jsonEscape(self.allocator, state_path);
    defer self.allocator.free(escaped_state_path);
    const escaped_artifact_root = try unified.jsonEscape(self.allocator, artifact_root);
    defer self.allocator.free(escaped_artifact_root);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"mission\":{s},\"review\":{{\"provider\":\"{s}\",\"repo_key\":\"{s}\",\"pr_number\":{d},\"pr_url\":\"{s}\",\"checkout_path\":\"{s}\",\"context_path\":\"{s}\",\"state_path\":\"{s}\",\"artifact_root\":\"{s}\"}}}}",
        .{
            mission_json,
            escaped_provider,
            escaped_repo_key,
            pr_number,
            escaped_pr_url,
            escaped_checkout_path,
            escaped_context_path,
            escaped_state_path,
            escaped_artifact_root,
        },
    );
}

pub fn buildPrReviewIntakeDetailJson(
    self: anytype,
    mission_json: []const u8,
    provider: []const u8,
    repo_key: []const u8,
    pr_number: u64,
    pr_url: []const u8,
    checkout_path: []const u8,
    context_path: []const u8,
    state_path: []const u8,
    artifact_root: []const u8,
    provider_sync_path: ?[]const u8,
) ![]u8 {
    const provider_sync_json = if (provider_sync_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(provider_sync_json);
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeAll("{\"mission\":");
    try writer.writeAll(mission_json);
    try writer.writeAll(",\"review\":{\"provider\":");
    try writeJsonString(writer, provider);
    try writer.writeAll(",\"repo_key\":");
    try writeJsonString(writer, repo_key);
    try writer.print(",\"pr_number\":{d}", .{pr_number});
    try writer.writeAll(",\"pr_url\":");
    try writeJsonString(writer, pr_url);
    try writer.writeAll(",\"checkout_path\":");
    try writeJsonString(writer, checkout_path);
    try writer.writeAll(",\"context_path\":");
    try writeJsonString(writer, context_path);
    try writer.writeAll(",\"state_path\":");
    try writeJsonString(writer, state_path);
    try writer.writeAll(",\"artifact_root\":");
    try writeJsonString(writer, artifact_root);
    try writer.writeAll(",\"services\":{\"provider_sync_path\":");
    try writer.writeAll(provider_sync_json);
    try writer.writeAll("}}}");
    return out.toOwnedSlice(self.allocator);
}

pub fn buildPrReviewSyncDetailJson(
    self: anytype,
    mission_json: []const u8,
    phase: []const u8,
    state_path: []const u8,
    thread_actions_path: ?[]const u8,
    provider_sync_path: ?[]const u8,
    checkout_sync_path: ?[]const u8,
    repo_status_path: ?[]const u8,
    diff_range_path: ?[]const u8,
) ![]u8 {
    const thread_actions_json = if (thread_actions_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(thread_actions_json);
    const provider_sync_json = if (provider_sync_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(provider_sync_json);
    const checkout_sync_json = if (checkout_sync_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(checkout_sync_json);
    const repo_status_json = if (repo_status_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(repo_status_json);
    const diff_range_json = if (diff_range_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(diff_range_json);
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeAll("{\"mission\":");
    try writer.writeAll(mission_json);
    try writer.writeAll(",\"review\":{\"phase\":");
    try writeJsonString(writer, phase);
    try writer.writeAll(",\"state_path\":");
    try writeJsonString(writer, state_path);
    try writer.writeAll(",\"thread_actions_path\":");
    try writer.writeAll(thread_actions_json);
    try writer.writeAll(",\"services\":{\"provider_sync_path\":");
    try writer.writeAll(provider_sync_json);
    try writer.writeAll(",\"checkout_sync_path\":");
    try writer.writeAll(checkout_sync_json);
    try writer.writeAll(",\"repo_status_path\":");
    try writer.writeAll(repo_status_json);
    try writer.writeAll(",\"diff_range_path\":");
    try writer.writeAll(diff_range_json);
    try writer.writeAll("}}}");
    return out.toOwnedSlice(self.allocator);
}

pub fn buildPrReviewValidationDetailJson(
    self: anytype,
    mission_json: []const u8,
    phase: []const u8,
    state_path: []const u8,
    validation_path: []const u8,
    session_create_path: ?[]const u8,
    command_paths_json: []const u8,
    session_close_path: ?[]const u8,
) ![]u8 {
    const session_create_json = if (session_create_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(session_create_json);
    const session_close_json = if (session_close_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(session_close_json);
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeAll("{\"mission\":");
    try writer.writeAll(mission_json);
    try writer.writeAll(",\"review\":{\"phase\":");
    try writeJsonString(writer, phase);
    try writer.writeAll(",\"state_path\":");
    try writeJsonString(writer, state_path);
    try writer.writeAll(",\"validation_path\":");
    try writeJsonString(writer, validation_path);
    try writer.writeAll(",\"services\":{\"validation_session_path\":");
    try writer.writeAll(session_create_json);
    try writer.writeAll(",\"validation_command_paths\":");
    try writer.writeAll(command_paths_json);
    try writer.writeAll(",\"validation_close_path\":");
    try writer.writeAll(session_close_json);
    try writer.writeAll("}}}");
    return out.toOwnedSlice(self.allocator);
}

pub fn buildPrReviewDraftDetailJson(
    self: anytype,
    mission_json: []const u8,
    phase: []const u8,
    state_path: []const u8,
    draft_path: []const u8,
    draft_history_path: []const u8,
    review_comment_path: ?[]const u8,
    review_comment_history_path: ?[]const u8,
    revision: u64,
) ![]u8 {
    const escaped_phase = try unified.jsonEscape(self.allocator, phase);
    defer self.allocator.free(escaped_phase);
    const escaped_state_path = try unified.jsonEscape(self.allocator, state_path);
    defer self.allocator.free(escaped_state_path);
    const escaped_draft_path = try unified.jsonEscape(self.allocator, draft_path);
    defer self.allocator.free(escaped_draft_path);
    const escaped_draft_history_path = try unified.jsonEscape(self.allocator, draft_history_path);
    defer self.allocator.free(escaped_draft_history_path);
    const review_comment_json = if (review_comment_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(review_comment_json);
    const review_comment_history_json = if (review_comment_history_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(review_comment_history_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"mission\":{s},\"review\":{{\"phase\":\"{s}\",\"state_path\":\"{s}\",\"draft_path\":\"{s}\",\"draft_history_path\":\"{s}\",\"review_comment_path\":{s},\"review_comment_history_path\":{s},\"draft_revision\":{d}}}}}",
        .{
            mission_json,
            escaped_phase,
            escaped_state_path,
            escaped_draft_path,
            escaped_draft_history_path,
            review_comment_json,
            review_comment_history_json,
            revision,
        },
    );
}

pub fn buildPrReviewAgenticDraftDetailJson(
    self: anytype,
    mission_json: []const u8,
    phase: []const u8,
    state_path: []const u8,
    draft_status: []const u8,
    draft_summary: ?[]const u8,
    draft_path: ?[]const u8,
    revision: u64,
    action: []const u8,
    run_id: ?[]const u8,
    run_state: ?[]const u8,
    assistant_output: ?[]const u8,
) ![]u8 {
    const draft_summary_json = if (draft_summary) |value|
        try self.formatJsonString(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(draft_summary_json);
    const draft_path_json = if (draft_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(draft_path_json);
    const run_id_json = if (run_id) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(run_id_json);
    const run_state_json = if (run_state) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(run_state_json);
    const assistant_output_json = if (assistant_output) |value|
        try self.formatJsonString(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(assistant_output_json);

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeAll("{\"mission\":");
    try writer.writeAll(mission_json);
    try writer.writeAll(",\"review\":{\"phase\":");
    try writeJsonString(writer, phase);
    try writer.writeAll(",\"state_path\":");
    try writeJsonString(writer, state_path);
    try writer.writeAll(",\"draft_status\":");
    try writeJsonString(writer, draft_status);
    try writer.writeAll(",\"draft_summary\":");
    try writer.writeAll(draft_summary_json);
    try writer.writeAll(",\"draft_path\":");
    try writer.writeAll(draft_path_json);
    try writer.print(",\"draft_revision\":{d}", .{revision});
    try writer.writeAll(",\"agentic_action\":");
    try writeJsonString(writer, action);
    try writer.writeAll("},\"runtime\":{\"run_id\":");
    try writer.writeAll(run_id_json);
    try writer.writeAll(",\"state\":");
    try writer.writeAll(run_state_json);
    try writer.writeAll(",\"assistant_output\":");
    try writer.writeAll(assistant_output_json);
    try writer.writeAll("}}");
    return out.toOwnedSlice(self.allocator);
}

pub fn buildPrReviewReviewDetailJson(
    self: anytype,
    mission_json: []const u8,
    phase: []const u8,
    state_path: []const u8,
    findings_path: []const u8,
    recommendation_path: []const u8,
    review_comment_path: ?[]const u8,
    thread_actions_path: ?[]const u8,
    publish_review_path: ?[]const u8,
) ![]u8 {
    const review_comment_json = if (review_comment_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(review_comment_json);
    const thread_actions_json = if (thread_actions_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(thread_actions_json);
    const publish_review_json = if (publish_review_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(publish_review_json);
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeAll("{\"mission\":");
    try writer.writeAll(mission_json);
    try writer.writeAll(",\"review\":{\"phase\":");
    try writeJsonString(writer, phase);
    try writer.writeAll(",\"state_path\":");
    try writeJsonString(writer, state_path);
    try writer.writeAll(",\"findings_path\":");
    try writeJsonString(writer, findings_path);
    try writer.writeAll(",\"recommendation_path\":");
    try writeJsonString(writer, recommendation_path);
    try writer.writeAll(",\"review_comment_path\":");
    try writer.writeAll(review_comment_json);
    try writer.writeAll(",\"thread_actions_path\":");
    try writer.writeAll(thread_actions_json);
    try writer.writeAll(",\"services\":{\"publish_review_path\":");
    try writer.writeAll(publish_review_json);
    try writer.writeAll("}}}");
    return out.toOwnedSlice(self.allocator);
}

pub fn buildPrReviewSuccessResultJson(self: anytype, op: Op, result_json: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
        .{ escaped_operation, result_json },
    );
}

pub fn buildPrReviewPartialFailureResultJson(
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

pub fn buildPrReviewFailureResultJson(self: anytype, op: Op, code: []const u8, message: []const u8) ![]u8 {
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

pub fn buildPrReviewValidationReportJson(
    self: anytype,
    status: []const u8,
    summary: []const u8,
    session_create_path: ?[]const u8,
    commands_json: []const u8,
    session_close_path: ?[]const u8,
) ![]u8 {
    const escaped_status = try unified.jsonEscape(self.allocator, status);
    defer self.allocator.free(escaped_status);
    const escaped_summary = try unified.jsonEscape(self.allocator, summary);
    defer self.allocator.free(escaped_summary);
    const session_create_json = if (session_create_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(session_create_json);
    const session_close_json = if (session_close_path) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(session_close_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"status\":\"{s}\",\"summary\":\"{s}\",\"services\":{{\"validation_session_path\":{s},\"validation_close_path\":{s}}},\"commands\":{s}}}",
        .{ escaped_status, escaped_summary, session_create_json, session_close_json, commands_json },
    );
}

pub fn buildPrReviewValidationCommandEntryJson(
    self: anytype,
    index: usize,
    request_payload_json: []const u8,
    capture_path: []const u8,
    result_payload_json: []const u8,
    exit_code: ?i32,
    error_code: ?[]const u8,
    error_message: ?[]const u8,
) ![]u8 {
    const escaped_capture_path = try unified.jsonEscape(self.allocator, capture_path);
    defer self.allocator.free(escaped_capture_path);
    const exit_code_json = if (exit_code) |value|
        try std.fmt.allocPrint(self.allocator, "{d}", .{value})
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(exit_code_json);
    const error_json = if (error_code != null or error_message != null) blk: {
        const escaped_code = try unified.jsonEscape(self.allocator, error_code orelse "execution_failed");
        defer self.allocator.free(escaped_code);
        const escaped_message = try unified.jsonEscape(self.allocator, error_message orelse "validation command failed");
        defer self.allocator.free(escaped_message);
        break :blk try std.fmt.allocPrint(
            self.allocator,
            "{{\"code\":\"{s}\",\"message\":\"{s}\"}}",
            .{ escaped_code, escaped_message },
        );
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(error_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"index\":{d},\"ok\":{s},\"service_capture_path\":\"{s}\",\"request\":{s},\"result\":{s},\"exit_code\":{s},\"error\":{s}}}",
        .{ index, if (error_code == null and error_message == null) "true" else "false", escaped_capture_path, request_payload_json, result_payload_json, exit_code_json, error_json },
    );
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.print("{f}", .{std.json.fmt(value, .{})});
}

fn executeConfigureRepoOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    if (self.local_fs_export_root == null) return error.InvalidPayload;

    var catalog = try loadRepoCatalog(self);
    defer catalog.deinit(self.allocator);
    var repo = try parseRepoConfigSnapshot(
        self,
        args_obj,
        if (catalog.project_id) |value| value else null,
        if (catalog.approval_policy_json) |value| value else null,
        true,
    );
    defer repo.deinit(self.allocator);

    var replaced = false;
    for (catalog.repositories) |*existing| {
        if (!std.mem.eql(u8, existing.repo_key, repo.repo_key)) continue;
        existing.deinit(self.allocator);
        existing.* = try repo.cloneOwned(self.allocator);
        replaced = true;
        break;
    }
    if (!replaced) {
        const old_len = catalog.repositories.len;
        const new_items = try self.allocator.alloc(RepoConfigSnapshot, old_len + 1);
        for (catalog.repositories, 0..) |existing, idx| new_items[idx] = existing;
        if (catalog.repositories.len > 0) self.allocator.free(catalog.repositories);
        new_items[old_len] = try repo.cloneOwned(self.allocator);
        catalog.repositories = new_items;
    }

    const catalog_json = try renderRepoCatalogJson(self, catalog);
    defer self.allocator.free(catalog_json);
    try self.writeMissionContractFile(repo_catalog_path, catalog_json);

    for (catalog.repositories) |configured| {
        if (!std.mem.eql(u8, configured.repo_key, repo.repo_key)) continue;
        const repo_json = try renderRepoConfigJson(self, configured);
        defer self.allocator.free(repo_json);
        const detail = try buildRepoConfigDetailJson(self, configured.repo_key, repo_json, catalog.repositories.len);
        defer self.allocator.free(detail);
        return self.buildPrReviewSuccessResultJson(.configure_repo, detail);
    }

    return error.InvalidPayload;
}

fn executeGetRepoOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const repo_key_raw = extractOptionalStringByNames(args_obj, &[_][]const u8{"repo_key"}) orelse return error.InvalidPayload;
    const repo_key = std.mem.trim(u8, repo_key_raw, " \t\r\n");
    if (repo_key.len == 0) return error.InvalidPayload;

    var catalog = try loadRepoCatalog(self);
    defer catalog.deinit(self.allocator);

    for (catalog.repositories) |repo| {
        if (!std.mem.eql(u8, repo.repo_key, repo_key)) continue;
        const repo_json = try renderRepoConfigJson(self, repo);
        defer self.allocator.free(repo_json);
        const detail = try buildRepoConfigDetailJson(self, repo.repo_key, repo_json, catalog.repositories.len);
        defer self.allocator.free(detail);
        return self.buildPrReviewSuccessResultJson(.get_repo, detail);
    }

    const detail = try buildRepoConfigDetailJson(self, repo_key, "null", catalog.repositories.len);
    defer self.allocator.free(detail);
    return self.buildPrReviewPartialFailureResultJson(
        .get_repo,
        detail,
        "repo_not_found",
        "PR review repository is not configured",
    );
}

fn executeListReposOp(self: anytype) ![]u8 {
    var catalog = try loadRepoCatalog(self);
    defer catalog.deinit(self.allocator);

    const catalog_json = try renderRepoCatalogJson(self, catalog);
    defer self.allocator.free(catalog_json);
    const detail = try buildRepoCatalogDetailJson(self, catalog_json);
    defer self.allocator.free(detail);
    return self.buildPrReviewSuccessResultJson(.list_repos, detail);
}

fn executeStartOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    var mission = try self.bootstrapPrReviewMission(args_obj);
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);
    var context = try self.loadPrReviewContextSnapshot(contract.context_path);
    defer context.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(mission);
    defer self.allocator.free(mission_json);
    const detail = try self.buildPrReviewStartDetailJson(
        mission_json,
        context.provider,
        context.repo_key,
        context.pr_number,
        context.pr_url,
        context.checkout_path,
        contract.context_path,
        contract.state_path,
        contract.artifact_root,
    );
    defer self.allocator.free(detail);
    return self.buildPrReviewSuccessResultJson(.start, detail);
}

fn executeIntakeOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;

    var mission = try self.bootstrapPrReviewMission(args_obj);
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);

    var context = try self.loadPrReviewContextSnapshot(contract.context_path);
    defer context.deinit(self.allocator);
    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);
    try self.applyPrReviewCommonStateFields(args_obj, &state);

    var provider_sync_input = try parseOptionalServiceArgs(args_obj, "provider_sync");
    if (args_obj.get("provider_sync") == null) provider_sync_input.enabled = true;
    const checkpoint_stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}) orelse "intake";

    var provider_sync_capture: ?ServiceCapture = null;
    defer if (provider_sync_capture) |*value| value.deinit(self.allocator);
    var service_error_code: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_code);
    var service_error_message: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_message);

    if (provider_sync_input.enabled) {
        const request_payload = try self.buildPrReviewGitHubSyncRequestJson(context, provider_sync_input.overrides);
        defer self.allocator.free(request_payload);
        var github_pr_target = try resolvePreferredServiceTarget(self, "github_pr", "/control/sync.json");
        defer github_pr_target.deinit(self.allocator);
        provider_sync_capture = try self.invokePrReviewServiceCapture(
            store,
            mission.mission_id,
            checkpoint_stage,
            "Loaded provider metadata for PR review intake",
            github_pr_target.service_path,
            github_pr_target.invoke_path,
            request_payload,
            contract.artifact_root,
            state.provider_sync_artifact,
            "provider_sync",
        );
        if (try captureServiceErrorFromPayload(
            self,
            provider_sync_capture.?.result_payload,
            &service_error_code,
            &service_error_message,
        )) {
            // handled above
        } else {
            try self.applyPrReviewContextFromGitHubSyncPayload(&context, &state, provider_sync_capture.?.result_payload);
        }
    }

    const context_payload = try self.buildPrReviewContextPayloadJson(
        context.provider,
        context.repo_key,
        context.pr_number,
        context.pr_url,
        context.base_branch,
        context.base_sha,
        context.head_branch,
        context.head_sha,
        context.checkout_path,
        context.review_policy_paths_json,
        context.default_review_commands_json,
        context.approval_policy_json,
    );
    defer self.allocator.free(context_payload);
    try self.writeMissionContractFile(contract.context_path, context_payload);

    const state_payload = try self.buildPrReviewStatePayloadJson(state);
    defer self.allocator.free(state_payload);
    try self.writeMissionContractFile(contract.state_path, state_payload);

    const checkpoint_summary = if (service_error_message) |value|
        value
    else
        extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}) orelse "Intook PR review mission";
    var checkpointed = try store.recordCheckpoint(self.allocator, mission.mission_id, .{
        .stage = checkpoint_stage,
        .summary = checkpoint_summary,
        .artifact = .{
            .kind = if (provider_sync_capture != null) "provider_sync" else "contract_state",
            .path = if (provider_sync_capture) |value| value.artifact_path else contract.state_path,
            .summary = checkpoint_summary,
        },
    });
    defer checkpointed.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(checkpointed);
    defer self.allocator.free(mission_json);
    const detail = try self.buildPrReviewIntakeDetailJson(
        mission_json,
        context.provider,
        context.repo_key,
        context.pr_number,
        context.pr_url,
        context.checkout_path,
        contract.context_path,
        contract.state_path,
        contract.artifact_root,
        if (provider_sync_capture) |value| value.artifact_path else null,
    );
    defer self.allocator.free(detail);
    if (service_error_code) |code| {
        return self.buildPrReviewPartialFailureResultJson(.intake, detail, code, service_error_message.?);
    }
    return self.buildPrReviewSuccessResultJson(.intake, detail);
}

fn executeSyncOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
    var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);

    var context = try self.loadPrReviewContextSnapshot(contract.context_path);
    defer context.deinit(self.allocator);
    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);
    try self.applyPrReviewCommonStateFields(args_obj, &state);

    var thread_actions_path: ?[]u8 = null;
    defer if (thread_actions_path) |value| self.allocator.free(value);
    if (args_obj.get("thread_actions")) |value| {
        thread_actions_path = try self.writePrReviewJsonArtifact(contract.artifact_root, state.thread_actions_artifact, value);
    }

    const provider_sync_input = try parseOptionalServiceArgs(args_obj, "provider_sync");
    const sync_checkout_input = try parseOptionalServiceArgs(args_obj, "sync_checkout");
    const repo_status_input = try parseOptionalServiceArgs(args_obj, "repo_status");
    const diff_range_input = try parseOptionalServiceArgs(args_obj, "diff_range");
    const checkpoint_stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}) orelse state.phase;

    var provider_sync_capture: ?ServiceCapture = null;
    defer if (provider_sync_capture) |*value| value.deinit(self.allocator);
    var checkout_sync_capture: ?ServiceCapture = null;
    defer if (checkout_sync_capture) |*value| value.deinit(self.allocator);
    var repo_status_capture: ?ServiceCapture = null;
    defer if (repo_status_capture) |*value| value.deinit(self.allocator);
    var diff_range_capture: ?ServiceCapture = null;
    defer if (diff_range_capture) |*value| value.deinit(self.allocator);

    var service_error_code: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_code);
    var service_error_message: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_message);

    if (provider_sync_input.enabled) {
        const request_payload = try self.buildPrReviewGitHubSyncRequestJson(context, provider_sync_input.overrides);
        defer self.allocator.free(request_payload);
        var github_pr_target = try resolvePreferredServiceTarget(self, "github_pr", "/control/sync.json");
        defer github_pr_target.deinit(self.allocator);
        provider_sync_capture = try self.invokePrReviewServiceCapture(
            store,
            mission_id,
            checkpoint_stage,
            "Synced provider PR metadata",
            github_pr_target.service_path,
            github_pr_target.invoke_path,
            request_payload,
            contract.artifact_root,
            state.provider_sync_artifact,
            "provider_sync",
        );
        if (try captureServiceErrorFromPayload(
            self,
            provider_sync_capture.?.result_payload,
            &service_error_code,
            &service_error_message,
        )) {
            // handled above
        } else {
            try self.applyPrReviewContextFromGitHubSyncPayload(&context, &state, provider_sync_capture.?.result_payload);
        }
    }

    if (service_error_code == null and sync_checkout_input.enabled) {
        const request_payload = try self.buildPrReviewGitSyncCheckoutRequestJson(context, sync_checkout_input.overrides);
        defer self.allocator.free(request_payload);
        var git_sync_target = try resolvePreferredServiceTarget(self, "git", "/control/sync_checkout.json");
        defer git_sync_target.deinit(self.allocator);
        checkout_sync_capture = try self.invokePrReviewServiceCapture(
            store,
            mission_id,
            checkpoint_stage,
            "Synced PR checkout",
            git_sync_target.service_path,
            git_sync_target.invoke_path,
            request_payload,
            contract.artifact_root,
            state.checkout_sync_artifact,
            "checkout_sync",
        );
        if (try captureServiceErrorFromPayload(
            self,
            checkout_sync_capture.?.result_payload,
            &service_error_code,
            &service_error_message,
        )) {
            // handled above
        } else {
            try self.applyPrReviewContextFromGitSyncPayload(&context, &state, checkout_sync_capture.?.result_payload);
        }
    }

    if (service_error_code == null and repo_status_input.enabled) {
        const request_payload = try self.buildPrReviewGitStatusRequestJson(context, repo_status_input.overrides);
        defer self.allocator.free(request_payload);
        var git_status_target = try resolvePreferredServiceTarget(self, "git", "/control/status.json");
        defer git_status_target.deinit(self.allocator);
        repo_status_capture = try self.invokePrReviewServiceCapture(
            store,
            mission_id,
            checkpoint_stage,
            "Captured repository status for PR review",
            git_status_target.service_path,
            git_status_target.invoke_path,
            request_payload,
            contract.artifact_root,
            state.repo_status_artifact,
            "repo_status",
        );
        if (try captureServiceErrorFromPayload(
            self,
            repo_status_capture.?.result_payload,
            &service_error_code,
            &service_error_message,
        )) {
            // handled above
        } else {
            try self.applyPrReviewContextFromGitStatusPayload(&context, &state, repo_status_capture.?.result_payload);
        }
    }

    if (service_error_code == null and diff_range_input.enabled) {
        const request_payload = try self.buildPrReviewGitDiffRangeRequestJson(context, diff_range_input.overrides);
        defer self.allocator.free(request_payload);
        var git_diff_target = try resolvePreferredServiceTarget(self, "git", "/control/diff_range.json");
        defer git_diff_target.deinit(self.allocator);
        diff_range_capture = try self.invokePrReviewServiceCapture(
            store,
            mission_id,
            checkpoint_stage,
            "Captured changed files for PR review",
            git_diff_target.service_path,
            git_diff_target.invoke_path,
            request_payload,
            contract.artifact_root,
            state.diff_range_artifact,
            "diff_range",
        );
        _ = try captureServiceErrorFromPayload(
            self,
            diff_range_capture.?.result_payload,
            &service_error_code,
            &service_error_message,
        );
    }

    const context_payload = try self.buildPrReviewContextPayloadJson(
        context.provider,
        context.repo_key,
        context.pr_number,
        context.pr_url,
        context.base_branch,
        context.base_sha,
        context.head_branch,
        context.head_sha,
        context.checkout_path,
        context.review_policy_paths_json,
        context.default_review_commands_json,
        context.approval_policy_json,
    );
    defer self.allocator.free(context_payload);
    try self.writeMissionContractFile(contract.context_path, context_payload);

    const state_payload = try self.buildPrReviewStatePayloadJson(state);
    defer self.allocator.free(state_payload);
    try self.writeMissionContractFile(contract.state_path, state_payload);

    const checkpoint_summary = if (service_error_message) |value|
        value
    else
        extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}) orelse "Synced PR review state";
    const checkpoint_artifact: struct { kind: []const u8, path: []const u8, summary: []const u8 } = blk: {
        if (service_error_code != null) {
            if (diff_range_capture) |value| break :blk .{ .kind = "diff_range", .path = value.artifact_path, .summary = "PR review diff-range capture" };
            if (repo_status_capture) |value| break :blk .{ .kind = "repo_status", .path = value.artifact_path, .summary = "PR review repo-status capture" };
            if (checkout_sync_capture) |value| break :blk .{ .kind = "checkout_sync", .path = value.artifact_path, .summary = "PR checkout capture" };
            if (provider_sync_capture) |value| break :blk .{ .kind = "provider_sync", .path = value.artifact_path, .summary = "PR provider sync capture" };
            if (thread_actions_path) |value| break :blk .{ .kind = "thread_actions", .path = value, .summary = "PR review thread action snapshot" };
            break :blk .{ .kind = "state_sync", .path = contract.state_path, .summary = "PR review state file" };
        }
        if (diff_range_capture) |value| break :blk .{ .kind = "diff_range", .path = value.artifact_path, .summary = "PR review diff-range capture" };
        if (repo_status_capture) |value| break :blk .{ .kind = "repo_status", .path = value.artifact_path, .summary = "PR review repo-status capture" };
        if (checkout_sync_capture) |value| break :blk .{ .kind = "checkout_sync", .path = value.artifact_path, .summary = "PR checkout capture" };
        if (provider_sync_capture) |value| break :blk .{ .kind = "provider_sync", .path = value.artifact_path, .summary = "PR provider sync capture" };
        if (thread_actions_path) |value| break :blk .{ .kind = "thread_actions", .path = value, .summary = "PR review thread action snapshot" };
        break :blk .{ .kind = "state_sync", .path = contract.state_path, .summary = "PR review state file" };
    };
    var checkpointed = try store.recordCheckpoint(self.allocator, mission_id, .{
        .stage = checkpoint_stage,
        .summary = checkpoint_summary,
        .artifact = .{
            .kind = checkpoint_artifact.kind,
            .path = checkpoint_artifact.path,
            .summary = checkpoint_artifact.summary,
        },
    });
    defer checkpointed.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(checkpointed);
    defer self.allocator.free(mission_json);
    const detail = try self.buildPrReviewSyncDetailJson(
        mission_json,
        state.phase,
        contract.state_path,
        thread_actions_path,
        if (provider_sync_capture) |value| value.artifact_path else null,
        if (checkout_sync_capture) |value| value.artifact_path else null,
        if (repo_status_capture) |value| value.artifact_path else null,
        if (diff_range_capture) |value| value.artifact_path else null,
    );
    defer self.allocator.free(detail);
    if (service_error_code) |code| {
        return self.buildPrReviewPartialFailureResultJson(.sync, detail, code, service_error_message.?);
    }
    return self.buildPrReviewSuccessResultJson(.sync, detail);
}

fn executeRunValidationOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
    var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);

    var context = try self.loadPrReviewContextSnapshot(contract.context_path);
    defer context.deinit(self.allocator);
    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);
    try self.applyPrReviewCommonStateFields(args_obj, &state);
    if (args_obj.get("phase") == null) try self.replaceOwnedString(&state.phase, "validating");

    var parsed_default_commands: ?std.json.Parsed(std.json.Value) = null;
    defer if (parsed_default_commands) |*value| value.deinit();
    const command_items = if (args_obj.get("commands")) |value| blk: {
        if (value != .array) return error.InvalidPayload;
        break :blk value.array.items;
    } else blk: {
        parsed_default_commands = try std.json.parseFromSlice(std.json.Value, self.allocator, context.default_review_commands_json, .{});
        if (parsed_default_commands.?.value != .array) return error.InvalidPayload;
        break :blk parsed_default_commands.?.value.array.items;
    };
    if (command_items.len == 0) return error.InvalidPayload;

    const checkpoint_stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}) orelse state.phase;

    var create_capture: ?ServiceCapture = null;
    defer if (create_capture) |*value| value.deinit(self.allocator);
    var close_capture: ?ServiceCapture = null;
    defer if (close_capture) |*value| value.deinit(self.allocator);
    var service_error_code: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_code);
    var service_error_message: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_message);
    var validation_terminal_needs_close = false;

    var command_results_json = std.ArrayListUnmanaged(u8){};
    defer command_results_json.deinit(self.allocator);
    var command_paths_json = std.ArrayListUnmanaged(u8){};
    defer command_paths_json.deinit(self.allocator);
    try command_results_json.append(self.allocator, '[');
    try command_paths_json.append(self.allocator, '[');
    var first_command_entry = true;
    var first_command_path = true;
    const terminal_service_path = try self.resolvePreferredServicePath("terminal", "");
    defer self.allocator.free(terminal_service_path);
    const terminal_create_path = try self.resolvePreferredServicePath("terminal", "/control/create.json");
    defer self.allocator.free(terminal_create_path);
    const terminal_exec_path = try self.resolvePreferredServicePath("terminal", "/control/exec.json");
    defer self.allocator.free(terminal_exec_path);
    const terminal_close_path = try self.resolvePreferredServicePath("terminal", "/control/close.json");
    defer self.allocator.free(terminal_close_path);

    const create_payload = try self.buildPrReviewTerminalCreateRequestJson(context.checkout_path);
    defer self.allocator.free(create_payload);
    create_capture = try self.invokePrReviewServiceCapture(
        store,
        mission_id,
        checkpoint_stage,
        "Opened validation terminal session",
        terminal_service_path,
        terminal_create_path,
        create_payload,
        contract.artifact_root,
        "services/validation-create.json",
        "validation_create",
    );
    _ = try captureServiceErrorFromPayload(
        self,
        create_capture.?.result_payload,
        &service_error_code,
        &service_error_message,
    );
    validation_terminal_needs_close = service_error_code == null;
    errdefer if (validation_terminal_needs_close) {
        if (self.allocator.dupe(u8, "{}")) |cleanup_payload| {
            defer self.allocator.free(cleanup_payload);
            var cleanup_capture = self.invokePrReviewServiceCapture(
                store,
                mission_id,
                checkpoint_stage,
                "Closed validation terminal session after early validation failure",
                terminal_service_path,
                terminal_close_path,
                cleanup_payload,
                contract.artifact_root,
                "services/validation-close.json",
                "validation_close",
            ) catch null;
            if (cleanup_capture) |*value| value.deinit(self.allocator);
        } else |_| {}
    };

    if (service_error_code == null) {
        for (command_items, 0..) |command_value, idx| {
            const request_payload = try self.buildPrReviewValidationExecRequestJson(command_value, context.checkout_path);
            defer self.allocator.free(request_payload);
            const relative_path = try std.fmt.allocPrint(self.allocator, "services/validation-command-{d:0>3}.json", .{idx + 1});
            defer self.allocator.free(relative_path);

            var command_capture = try self.invokePrReviewServiceCapture(
                store,
                mission_id,
                checkpoint_stage,
                "Ran PR review validation command",
                terminal_service_path,
                terminal_exec_path,
                request_payload,
                contract.artifact_root,
                relative_path,
                "validation_command",
            );
            defer command_capture.deinit(self.allocator);

            var command_error_code: ?[]u8 = null;
            defer freeOptionalOwnedString(self, &command_error_code);
            var command_error_message: ?[]u8 = null;
            defer freeOptionalOwnedString(self, &command_error_message);
            var exit_code: ?i32 = null;

            if (try captureServiceErrorFromPayload(
                self,
                command_capture.result_payload,
                &command_error_code,
                &command_error_message,
            )) {
                // handled above
            } else {
                exit_code = try self.extractTerminalExitCodeFromToolPayload(command_capture.result_payload);
                if (exit_code == null) return error.InvalidPayload;
                if (exit_code.? != 0) {
                    const message = try std.fmt.allocPrint(
                        self.allocator,
                        "Validation command {d} exited with code {d}",
                        .{ idx + 1, exit_code.? },
                    );
                    defer self.allocator.free(message);
                    try setServiceError(self, &command_error_code, &command_error_message, "execution_failed", message);
                }
            }

            const command_entry = try self.buildPrReviewValidationCommandEntryJson(
                idx + 1,
                request_payload,
                command_capture.artifact_path,
                command_capture.result_payload,
                exit_code,
                command_error_code,
                command_error_message,
            );
            defer self.allocator.free(command_entry);

            if (!first_command_entry) try command_results_json.append(self.allocator, ',');
            first_command_entry = false;
            try command_results_json.appendSlice(self.allocator, command_entry);

            const command_path_json = try self.formatJsonString(command_capture.artifact_path);
            defer self.allocator.free(command_path_json);
            if (!first_command_path) try command_paths_json.append(self.allocator, ',');
            first_command_path = false;
            try command_paths_json.appendSlice(self.allocator, command_path_json);

            if (command_error_code) |code| {
                try setServiceError(self, &service_error_code, &service_error_message, code, command_error_message.?);
                break;
            }
        }
    }

    try command_results_json.append(self.allocator, ']');
    try command_paths_json.append(self.allocator, ']');
    const command_results_slice = try command_results_json.toOwnedSlice(self.allocator);
    defer self.allocator.free(command_results_slice);
    const command_paths_slice = try command_paths_json.toOwnedSlice(self.allocator);
    defer self.allocator.free(command_paths_slice);

    if (create_capture != null) {
        const close_payload = try self.allocator.dupe(u8, "{}");
        defer self.allocator.free(close_payload);
        close_capture = self.invokePrReviewServiceCapture(
            store,
            mission_id,
            checkpoint_stage,
            "Closed validation terminal session",
            terminal_service_path,
            terminal_close_path,
            close_payload,
            contract.artifact_root,
            "services/validation-close.json",
            "validation_close",
        ) catch null;
        if (close_capture != null) validation_terminal_needs_close = false;
    }

    const validation_status = if (service_error_code == null) "passed" else "failed";
    try self.replaceOwnedString(&state.latest_validation_status, validation_status);
    const generated_summary = if (service_error_message) |value|
        value
    else
        try std.fmt.allocPrint(self.allocator, "{d} review command{s} passed", .{
            command_items.len,
            if (command_items.len == 1) "" else "s",
        });
    defer if (service_error_message == null) self.allocator.free(generated_summary);
    const validation_summary = extractOptionalStringByNames(args_obj, &[_][]const u8{"summary"}) orelse generated_summary;
    try self.replaceOptionalOwnedString(&state.latest_validation_summary, validation_summary);

    const validation_payload = try self.buildPrReviewValidationReportJson(
        validation_status,
        validation_summary,
        if (create_capture) |value| value.artifact_path else null,
        command_results_slice,
        if (close_capture) |value| value.artifact_path else null,
    );
    defer self.allocator.free(validation_payload);
    const validation_path = try self.writePrReviewArtifactPayload(contract.artifact_root, state.validation_artifact, validation_payload);
    defer self.allocator.free(validation_path);

    const state_payload = try self.buildPrReviewStatePayloadJson(state);
    defer self.allocator.free(state_payload);
    try self.writeMissionContractFile(contract.state_path, state_payload);

    var checkpointed = try store.recordCheckpoint(self.allocator, mission_id, .{
        .stage = checkpoint_stage,
        .summary = validation_summary,
        .artifact = .{
            .kind = "validation",
            .path = validation_path,
            .summary = validation_summary,
        },
    });
    defer checkpointed.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(checkpointed);
    defer self.allocator.free(mission_json);
    const detail = try self.buildPrReviewValidationDetailJson(
        mission_json,
        state.phase,
        contract.state_path,
        validation_path,
        if (create_capture) |value| value.artifact_path else null,
        command_paths_slice,
        if (close_capture) |value| value.artifact_path else null,
    );
    defer self.allocator.free(detail);
    if (service_error_code) |code| {
        return self.buildPrReviewPartialFailureResultJson(.run_validation, detail, code, service_error_message.?);
    }
    return self.buildPrReviewSuccessResultJson(.run_validation, detail);
}

fn executeRecordValidationOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
    const validation_value = args_obj.get("validation") orelse return error.InvalidPayload;

    var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);

    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);
    try self.applyPrReviewCommonStateFields(args_obj, &state);
    if (args_obj.get("phase") == null) try self.replaceOwnedString(&state.phase, "validating");

    const validation_status = if (try jsonObjectOptionalString(args_obj, "status")) |value|
        value
    else if (validation_value == .object)
        (try jsonObjectOptionalString(validation_value.object, "status")) orelse state.latest_validation_status
    else
        state.latest_validation_status;
    try self.replaceOwnedString(&state.latest_validation_status, validation_status);

    const validation_summary = if (try jsonObjectOptionalString(args_obj, "summary")) |value|
        value
    else if (validation_value == .object)
        try jsonObjectOptionalString(validation_value.object, "summary")
    else
        null;
    try self.replaceOptionalOwnedString(&state.latest_validation_summary, validation_summary);

    const validation_path = try self.writePrReviewJsonArtifact(contract.artifact_root, state.validation_artifact, validation_value);
    defer self.allocator.free(validation_path);

    const state_payload = try self.buildPrReviewStatePayloadJson(state);
    defer self.allocator.free(state_payload);
    try self.writeMissionContractFile(contract.state_path, state_payload);

    const checkpoint_summary = validation_summary orelse "Recorded PR review validation";
    var checkpointed = try store.recordCheckpoint(self.allocator, mission_id, .{
        .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}) orelse state.phase,
        .summary = checkpoint_summary,
        .artifact = .{
            .kind = "validation",
            .path = validation_path,
            .summary = checkpoint_summary,
        },
    });
    defer checkpointed.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(checkpointed);
    defer self.allocator.free(mission_json);
    const detail = try self.buildPrReviewValidationDetailJson(
        mission_json,
        state.phase,
        contract.state_path,
        validation_path,
        null,
        "[]",
        null,
    );
    defer self.allocator.free(detail);
    return self.buildPrReviewSuccessResultJson(.record_validation, detail);
}

fn executeDraftReviewOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const max_auto_resume_steps: usize = 6;
    const max_rescue_auto_resume_steps: usize = 2;
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;

    var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);
    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);
    const prior_revision = state.latest_draft_revision;
    const action = if (prior_revision > 0) "revise_review" else "draft_review";

    const explicit_goal = extractOptionalStringByNames(args_obj, &[_][]const u8{ "goal", "content", "instructions" });
    const goal = if (explicit_goal) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else
        try buildPrReviewAgenticGoal(
            self,
            mission_id,
            contract.context_path,
            contract.state_path,
            contract.artifact_root,
            state,
            action,
        );
    defer self.allocator.free(goal);
    if (goal.len == 0) return error.InvalidPayload;

    var resume_run_id = extractOptionalStringByNames(args_obj, &[_][]const u8{
        "resume_run_id",
        "agent_run_id",
    });
    var run = try self.executeAgentRun(goal, resume_run_id);
    defer run.deinit(self.allocator);
    var auto_resume_steps: usize = 0;

    const initial_mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    mission.deinit(self.allocator);
    mission = initial_mission;

    const initial_state = try self.loadPrReviewStateSnapshot(contract.state_path);
    state.deinit(self.allocator);
    state = initial_state;

    while (shouldAutoResumeDraftRun(run, prior_revision, state)) {
        if (auto_resume_steps >= max_auto_resume_steps) break;
        const current_run_id = switch (run) {
            .success => |success| success.run_id,
            .failure => break,
        };
        resume_run_id = current_run_id;

        auto_resume_steps += 1;
        const next_run = try self.executeAgentRun(goal, resume_run_id);
        run.deinit(self.allocator);
        run = next_run;

        const latest_mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
        mission.deinit(self.allocator);
        mission = latest_mission;

        const latest_state = try self.loadPrReviewStateSnapshot(contract.state_path);
        state.deinit(self.allocator);
        state = latest_state;
    }

    if (state.latest_draft_revision <= prior_revision) {
        const rescue_goal = try buildPrReviewAgenticRescueGoal(
            self,
            mission_id,
            contract.context_path,
            contract.state_path,
            contract.artifact_root,
            state,
            action,
        );
        defer self.allocator.free(rescue_goal);

        run.deinit(self.allocator);
        run = try self.executeAgentRun(rescue_goal, null);

        const rescued_mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
        mission.deinit(self.allocator);
        mission = rescued_mission;

        const rescued_state = try self.loadPrReviewStateSnapshot(contract.state_path);
        state.deinit(self.allocator);
        state = rescued_state;

        var rescue_auto_resume_steps: usize = 0;
        while (shouldAutoResumeDraftRun(run, prior_revision, state)) {
            if (rescue_auto_resume_steps >= max_rescue_auto_resume_steps) break;
            const current_run_id = switch (run) {
                .success => |success| success.run_id,
                .failure => break,
            };

            rescue_auto_resume_steps += 1;
            const next_run = try self.executeAgentRun(rescue_goal, current_run_id);
            run.deinit(self.allocator);
            run = next_run;

            const latest_mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
            mission.deinit(self.allocator);
            mission = latest_mission;

            const latest_state = try self.loadPrReviewStateSnapshot(contract.state_path);
            state.deinit(self.allocator);
            state = latest_state;
        }
    }

    const refreshed_mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    mission.deinit(self.allocator);
    mission = refreshed_mission;

    const refreshed_state = try self.loadPrReviewStateSnapshot(contract.state_path);
    state.deinit(self.allocator);
    state = refreshed_state;

    const mission_json = try self.buildMissionRecordJson(mission);
    defer self.allocator.free(mission_json);
    const draft_path = if (state.latest_draft_revision > 0)
        try resolvePrReviewArtifactPath(self, contract.artifact_root, state.draft_review_artifact)
    else
        null;
    defer if (draft_path) |value| self.allocator.free(value);

    const detail = switch (run) {
        .success => |success| try buildPrReviewAgenticDraftDetailJson(
            self,
            mission_json,
            state.phase,
            contract.state_path,
            state.latest_draft_status,
            state.latest_draft_summary,
            draft_path,
            state.latest_draft_revision,
            action,
            success.run_id,
            success.state,
            success.assistant_output,
        ),
        .failure => |failure| try buildPrReviewAgenticDraftDetailJson(
            self,
            mission_json,
            state.phase,
            contract.state_path,
            state.latest_draft_status,
            state.latest_draft_summary,
            draft_path,
            state.latest_draft_revision,
            action,
            null,
            null,
            failure.message,
        ),
    };
    defer self.allocator.free(detail);

    if (state.latest_draft_revision > prior_revision) {
        return self.buildPrReviewSuccessResultJson(.draft_review, detail);
    }

    switch (run) {
        .failure => |failure| {
            return self.buildPrReviewPartialFailureResultJson(.draft_review, detail, failure.code, failure.message);
        },
        .success => {},
    }

    if (state.latest_draft_revision <= prior_revision) {
        return self.buildPrReviewPartialFailureResultJson(
            .draft_review,
            detail,
            "draft_not_saved",
            "Spider Monkey did not persist a PR review draft via save_draft.json",
        );
    }
    return self.buildPrReviewSuccessResultJson(.draft_review, detail);
}

fn shouldAutoResumeDraftRun(
    run: anytype,
    prior_revision: u64,
    state: StateSnapshot,
) bool {
    if (state.latest_draft_revision > prior_revision) return false;
    return switch (run) {
        .failure => false,
        .success => |success| blk: {
            if (!std.mem.eql(u8, success.state, "waiting_for_user")) break :blk false;
            const assistant_output = success.assistant_output orelse break :blk false;
            break :blk std.mem.indexOf(u8, assistant_output, "\"tool_calls\"") != null;
        },
    };
}

fn executeSaveDraftOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;

    var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);

    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);
    try self.applyPrReviewCommonStateFields(args_obj, &state);
    if (args_obj.get("phase") == null and !std.mem.eql(u8, state.phase, "awaiting_author") and !std.mem.eql(u8, state.phase, "awaiting_ci")) {
        try self.replaceOwnedString(&state.phase, "reviewing");
    }

    const explicit_review_comment = try jsonObjectOptionalString(args_obj, "review_comment");
    var prior_draft: ?LoadedDraftSnapshot = null;
    defer if (prior_draft) |*value| value.deinit();
    if (state.latest_draft_revision > 0 and
        (args_obj.get("findings") == null or
            args_obj.get("recommendation") == null or
            args_obj.get("thread_actions") == null or
            explicit_review_comment == null))
    {
        prior_draft = try loadLatestPrReviewDraftSnapshot(self, contract, state);
    }

    const findings_value = blk: {
        if (args_obj.get("findings")) |value| {
            if (value != .array and value != .null) return error.InvalidPayload;
            break :blk value;
        }
        if (prior_draft) |value| break :blk value.findings;
        break :blk null;
    };
    const recommendation_value = blk: {
        if (args_obj.get("recommendation")) |value| {
            if (value != .object and value != .null) return error.InvalidPayload;
            break :blk value;
        }
        if (prior_draft) |value| break :blk value.recommendation;
        break :blk null;
    };
    const thread_actions_value = blk: {
        if (args_obj.get("thread_actions")) |value| {
            if (value != .array and value != .null) return error.InvalidPayload;
            break :blk value;
        }
        if (prior_draft) |value| if (value.thread_actions) |draft_value| break :blk draft_value;
        break :blk null;
    };
    const review_comment = explicit_review_comment orelse if (prior_draft) |value| value.review_comment else null;

    const has_payload = findings_value != null or
        recommendation_value != null or
        thread_actions_value != null or
        review_comment != null or
        args_obj.get("current_focus") != null or
        args_obj.get("notes") != null or
        args_obj.get("open_threads") != null or
        args_obj.get("summary") != null;
    if (!has_payload) return error.InvalidPayload;

    const draft_revision = state.latest_draft_revision + 1;
    const draft_status = if (try jsonObjectOptionalString(args_obj, "status")) |value|
        value
    else if (draft_revision > 1)
        "revised"
    else
        "drafted";
    try self.replaceOwnedString(&state.latest_draft_status, draft_status);

    const draft_summary = if (try jsonObjectOptionalString(args_obj, "summary")) |value|
        value
    else if (recommendation_value) |value|
        if (value == .object) try jsonObjectOptionalString(value.object, "summary") else null
    else
        null;
    try self.replaceOptionalOwnedString(&state.latest_draft_summary, draft_summary);
    state.latest_draft_revision = draft_revision;

    const draft_payload = try buildPrReviewDraftPayloadJson(
        self,
        draft_revision,
        state.phase,
        draft_status,
        draft_summary,
        state.current_focus,
        findings_value,
        recommendation_value,
        review_comment,
        thread_actions_value,
        state.open_threads_json,
        state.notes_json,
    );
    defer self.allocator.free(draft_payload);
    const draft_path = try self.writePrReviewArtifactPayload(contract.artifact_root, state.draft_review_artifact, draft_payload);
    defer self.allocator.free(draft_path);

    const draft_history_relative = try buildDraftHistoryRelativePath(self, state.draft_history_dir, "review-draft", ".json", draft_revision);
    defer self.allocator.free(draft_history_relative);
    const draft_history_path = try self.writePrReviewArtifactPayload(contract.artifact_root, draft_history_relative, draft_payload);
    defer self.allocator.free(draft_history_path);

    var review_comment_path: ?[]u8 = null;
    defer if (review_comment_path) |value| self.allocator.free(value);
    var review_comment_history_path: ?[]u8 = null;
    defer if (review_comment_history_path) |value| self.allocator.free(value);
    if (review_comment) |value| {
        review_comment_path = try self.writePrReviewTextArtifact(contract.artifact_root, state.draft_review_comment_artifact, value);
        const review_comment_history_relative = try buildDraftHistoryRelativePath(self, state.draft_history_dir, "review-comment", ".md", draft_revision);
        defer self.allocator.free(review_comment_history_relative);
        review_comment_history_path = try self.writePrReviewTextArtifact(contract.artifact_root, review_comment_history_relative, value);
    }

    const state_payload = try self.buildPrReviewStatePayloadJson(state);
    defer self.allocator.free(state_payload);
    try self.writeMissionContractFile(contract.state_path, state_payload);

    const checkpoint_summary = draft_summary orelse "Saved PR review draft";
    var checkpointed = try store.recordCheckpoint(self.allocator, mission_id, .{
        .stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}) orelse "draft_review",
        .summary = checkpoint_summary,
        .artifact = .{
            .kind = "review_draft",
            .path = draft_path,
            .summary = checkpoint_summary,
        },
    });
    defer checkpointed.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(checkpointed);
    defer self.allocator.free(mission_json);
    const detail = try buildPrReviewDraftDetailJson(
        self,
        mission_json,
        state.phase,
        contract.state_path,
        draft_path,
        draft_history_path,
        review_comment_path,
        review_comment_history_path,
        draft_revision,
    );
    defer self.allocator.free(detail);
    return self.buildPrReviewSuccessResultJson(.save_draft, detail);
}

fn executeRecordReviewOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;

    var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer mission.deinit(self.allocator);
    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);

    var context = try self.loadPrReviewContextSnapshot(contract.context_path);
    defer context.deinit(self.allocator);
    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);
    try self.applyPrReviewCommonStateFields(args_obj, &state);

    const explicit_review_comment = try jsonObjectOptionalString(args_obj, "review_comment");
    const explicit_summary = try jsonObjectOptionalString(args_obj, "summary");
    const explicit_status = try jsonObjectOptionalString(args_obj, "status");
    var loaded_draft: ?LoadedDraftSnapshot = null;
    defer if (loaded_draft) |*value| value.deinit();
    if (args_obj.get("findings") == null or
        args_obj.get("recommendation") == null or
        explicit_review_comment == null or
        args_obj.get("thread_actions") == null or
        explicit_summary == null or
        explicit_status == null)
    {
        loaded_draft = try loadLatestPrReviewDraftSnapshot(self, contract, state);
    }

    const findings_value = blk: {
        if (args_obj.get("findings")) |value| {
            if (value != .array) return error.InvalidPayload;
            break :blk value;
        }
        if (loaded_draft) |value| break :blk value.findings;
        return error.InvalidPayload;
    };
    const recommendation_value = blk: {
        if (args_obj.get("recommendation")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value;
        }
        if (loaded_draft) |value| break :blk value.recommendation;
        return error.InvalidPayload;
    };
    const review_comment = explicit_review_comment orelse if (loaded_draft) |value| value.review_comment else null;
    const thread_actions_value = blk: {
        if (args_obj.get("thread_actions")) |value| {
            if (value != .array and value != .null) return error.InvalidPayload;
            break :blk value;
        }
        if (loaded_draft) |value| if (value.thread_actions) |draft_value| break :blk draft_value;
        break :blk null;
    };
    const effective_summary = explicit_summary orelse if (loaded_draft) |value| value.summary else null;
    const effective_status = explicit_status orelse if (loaded_draft) |value| value.status else null;

    const recommendation_decision = try recommendationDecisionFromValue(recommendation_value);
    if (args_obj.get("phase") == null) {
        try self.replaceOwnedString(&state.phase, phaseForDecision(recommendation_decision));
    }

    const recommendation_status = if (effective_status) |value|
        value
    else
        (try jsonObjectOptionalString(recommendation_value.object, "status")) orelse recommendation_decision;
    try self.replaceOwnedString(&state.latest_recommendation_status, recommendation_status);

    const recommendation_summary = if (effective_summary) |value|
        value
    else
        try jsonObjectOptionalString(recommendation_value.object, "summary");
    try self.replaceOptionalOwnedString(&state.latest_recommendation_summary, recommendation_summary);
    if (state.latest_draft_revision > 0) {
        try self.replaceOwnedString(&state.latest_draft_status, "finalized");
        if (recommendation_summary) |value| {
            try self.replaceOptionalOwnedString(&state.latest_draft_summary, value);
        }
    }

    const findings_path = try self.writePrReviewJsonArtifact(contract.artifact_root, state.findings_artifact, findings_value);
    defer self.allocator.free(findings_path);
    const recommendation_path = try self.writePrReviewJsonArtifact(contract.artifact_root, state.recommendation_artifact, recommendation_value);
    defer self.allocator.free(recommendation_path);

    var review_comment_path: ?[]u8 = null;
    defer if (review_comment_path) |value| self.allocator.free(value);
    if (review_comment) |value| {
        review_comment_path = try self.writePrReviewTextArtifact(contract.artifact_root, "review-comment.md", value);
    }

    var thread_actions_path: ?[]u8 = null;
    defer if (thread_actions_path) |value| self.allocator.free(value);
    if (thread_actions_value) |value| {
        thread_actions_path = try self.writePrReviewJsonArtifact(contract.artifact_root, state.thread_actions_artifact, value);
    }

    const publish_review_input = try parseOptionalServiceArgs(args_obj, "publish_review");
    const checkpoint_stage = extractOptionalStringByNames(args_obj, &[_][]const u8{"stage"}) orelse state.phase;

    var publish_review_capture: ?ServiceCapture = null;
    defer if (publish_review_capture) |*value| value.deinit(self.allocator);
    var service_error_code: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_code);
    var service_error_message: ?[]u8 = null;
    defer freeOptionalOwnedString(self, &service_error_message);

    if (publish_review_input.enabled) {
        const request_payload = try self.buildPrReviewGitHubPublishRequestJson(
            context,
            recommendation_value,
            review_comment,
            thread_actions_value,
            publish_review_input.overrides,
        );
        defer self.allocator.free(request_payload);
        var github_pr_target = try resolvePreferredServiceTarget(self, "github_pr", "/control/publish_review.json");
        defer github_pr_target.deinit(self.allocator);
        publish_review_capture = try self.invokePrReviewServiceCapture(
            store,
            mission_id,
            checkpoint_stage,
            "Published PR review through provider",
            github_pr_target.service_path,
            github_pr_target.invoke_path,
            request_payload,
            contract.artifact_root,
            state.publish_review_artifact,
            "publish_review",
        );
        _ = try captureServiceErrorFromPayload(
            self,
            publish_review_capture.?.result_payload,
            &service_error_code,
            &service_error_message,
        );
    }

    const state_payload = try self.buildPrReviewStatePayloadJson(state);
    defer self.allocator.free(state_payload);
    try self.writeMissionContractFile(contract.state_path, state_payload);

    const checkpoint_summary = if (service_error_message) |value|
        value
    else
        recommendation_summary orelse "Recorded PR review recommendation";
    var checkpointed = try store.recordCheckpoint(self.allocator, mission_id, .{
        .stage = checkpoint_stage,
        .summary = checkpoint_summary,
        .artifact = .{
            .kind = "recommendation",
            .path = recommendation_path,
            .summary = checkpoint_summary,
        },
    });
    defer checkpointed.deinit(self.allocator);

    const mission_json = try self.buildMissionRecordJson(checkpointed);
    defer self.allocator.free(mission_json);
    const detail = try self.buildPrReviewReviewDetailJson(
        mission_json,
        state.phase,
        contract.state_path,
        findings_path,
        recommendation_path,
        review_comment_path,
        thread_actions_path,
        if (publish_review_capture) |value| value.artifact_path else null,
    );
    defer self.allocator.free(detail);
    if (service_error_code) |code| {
        return self.buildPrReviewPartialFailureResultJson(.record_review, detail, code, service_error_message.?);
    }
    return self.buildPrReviewSuccessResultJson(.record_review, detail);
}

fn executeAdvanceOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const store = self.mission_store orelse return error.InvalidPayload;
    const mission_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "mission_id", "id" }) orelse return error.InvalidPayload;
    const wait_timeout_ms = blk: {
        if (args_obj.get("wait_timeout_ms")) |value| {
            if (value == .null) break :blk @as(i64, 0);
            if (value != .integer or value.integer < 0) return error.InvalidPayload;
            break :blk value.integer;
        }
        break :blk @as(i64, 0);
    };
    const resume_blocked = (try jsonObjectOptionalBool(args_obj, "resume_blocked")) orelse true;
    const run_validation = (try jsonObjectOptionalBool(args_obj, "run_validation")) orelse true;

    var mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    defer mission.deinit(self.allocator);

    switch (mission.state) {
        .completed, .failed, .cancelled => {
            var contract = try self.resolvePrReviewMissionContract(mission);
            defer contract.deinit(self.allocator);
            var state = try self.loadPrReviewStateSnapshot(contract.state_path);
            defer state.deinit(self.allocator);
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try buildPrReviewAdvanceDetailJson(
                self,
                mission_json,
                state.phase,
                contract.context_path,
                contract.state_path,
                contract.artifact_root,
                "terminal",
                "none",
                null,
                null,
                null,
                null,
            );
            defer self.allocator.free(detail);
            return self.buildPrReviewSuccessResultJson(.advance, detail);
        },
        else => {},
    }

    if (mission.pending_approval != null or mission.state == .waiting_for_approval) {
        var contract = try self.resolvePrReviewMissionContract(mission);
        defer contract.deinit(self.allocator);
        var state = try self.loadPrReviewStateSnapshot(contract.state_path);
        defer state.deinit(self.allocator);
        const mission_json = try self.buildMissionRecordJson(mission);
        defer self.allocator.free(mission_json);
        const detail = try buildPrReviewAdvanceDetailJson(
            self,
            mission_json,
            state.phase,
            contract.context_path,
            contract.state_path,
            contract.artifact_root,
            "waiting_for_approval",
            "resolve_approval",
            null,
            null,
            null,
            "Mission has a pending approval before PR review can continue.",
        );
        defer self.allocator.free(detail);
        return self.buildPrReviewSuccessResultJson(.advance, detail);
    }

    if (mission.state == .blocked and !resume_blocked) {
        var contract = try self.resolvePrReviewMissionContract(mission);
        defer contract.deinit(self.allocator);
        var state = try self.loadPrReviewStateSnapshot(contract.state_path);
        defer state.deinit(self.allocator);
        const mission_json = try self.buildMissionRecordJson(mission);
        defer self.allocator.free(mission_json);
        const note = mission.blocked_reason orelse "Mission is blocked; pass resume_blocked=true after clearing the blocker.";
        const detail = try buildPrReviewAdvanceDetailJson(
            self,
            mission_json,
            state.phase,
            contract.context_path,
            contract.state_path,
            contract.artifact_root,
            "blocked",
            "resume_blocked",
            null,
            null,
            null,
            note,
        );
        defer self.allocator.free(detail);
        return self.buildPrReviewSuccessResultJson(.advance, detail);
    }

    if (mission.state == .planning or mission.state == .recovering or (mission.state == .blocked and resume_blocked)) {
        const resumed = store.transition(self.allocator, mission_id, .{
            .next_state = .running,
            .stage = "runner.advance",
            .summary = "Resumed PR review runner",
            .reason = if (resume_blocked) "Resumed by pr_review.advance" else null,
            .actor = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
        }) catch |err| switch (err) {
            mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
            else => return error.InvalidPayload,
        };
        mission.deinit(self.allocator);
        mission = resumed;
    }

    var contract = try self.resolvePrReviewMissionContract(mission);
    defer contract.deinit(self.allocator);
    var context = try self.loadPrReviewContextSnapshot(contract.context_path);
    defer context.deinit(self.allocator);
    var state = try self.loadPrReviewStateSnapshot(contract.state_path);
    defer state.deinit(self.allocator);

    const should_wait = phaseWaitsForGitHubEvents(state.phase);
    const previous_phase = try self.allocator.dupe(u8, state.phase);
    defer self.allocator.free(previous_phase);
    const previous_head_sha = try self.allocator.dupe(u8, state.last_synced_head_sha);
    defer self.allocator.free(previous_head_sha);

    var wait_result_json: ?[]u8 = null;
    defer if (wait_result_json) |value| self.allocator.free(value);
    if (should_wait) {
        wait_result_json = try executeAdvanceWait(self, args_obj, state.phase, wait_timeout_ms);
        if (try self.extractErrorInfoFromToolPayload(wait_result_json.?)) |info| {
            defer info.deinit(self.allocator);
            const blocked = store.transition(self.allocator, mission_id, .{
                .next_state = .blocked,
                .stage = "runner.blocked",
                .reason = info.message,
                .summary = info.message,
                .actor = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                else => return error.InvalidPayload,
            };
            mission.deinit(self.allocator);
            mission = blocked;
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try buildPrReviewAdvanceDetailJson(
                self,
                mission_json,
                state.phase,
                contract.context_path,
                contract.state_path,
                contract.artifact_root,
                "blocked",
                "fix_environment",
                null,
                null,
                wait_result_json.?,
                info.message,
            );
            defer self.allocator.free(detail);
            return self.buildPrReviewSuccessResultJson(.advance, detail);
        }
        if (!try didAdvanceWaitFire(self, wait_result_json.?, mission.run_id)) {
            const heartbeat = store.recordHeartbeat(
                self.allocator,
                mission_id,
                state.phase,
            ) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                else => return error.InvalidPayload,
            };
            mission.deinit(self.allocator);
            mission = heartbeat;
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try buildPrReviewAdvanceDetailJson(
                self,
                mission_json,
                state.phase,
                contract.context_path,
                contract.state_path,
                contract.artifact_root,
                "waiting_for_event",
                "wait_for_github_event",
                null,
                null,
                wait_result_json.?,
                "Waiting for a matching GitHub PR event before resuming review work.",
            );
            defer self.allocator.free(detail);
            return self.buildPrReviewSuccessResultJson(.advance, detail);
        }
    }

    const wants_validation = try advanceHasValidationCommands(self, args_obj, context);
    var sync_result_json: ?[]u8 = null;
    defer if (sync_result_json) |value| self.allocator.free(value);
    var validation_result_json: ?[]u8 = null;
    defer if (validation_result_json) |value| self.allocator.free(value);

    const should_sync = advanceNeedsSync(previous_phase, wait_result_json != null);
    if (should_sync) {
        const sync_phase = if (run_validation and wants_validation and advanceNeedsValidation(previous_phase, wait_result_json != null, false))
            "ready_for_checkout"
        else
            "reviewing";
        sync_result_json = try executeAdvanceSync(self, mission_id, sync_phase, args_obj);
        if (try self.extractErrorInfoFromToolPayload(sync_result_json.?)) |info| {
            defer info.deinit(self.allocator);
            const blocked = store.transition(self.allocator, mission_id, .{
                .next_state = .blocked,
                .stage = "runner.blocked",
                .reason = info.message,
                .summary = info.message,
                .actor = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                else => return error.InvalidPayload,
            };
            mission.deinit(self.allocator);
            mission = blocked;
            const mission_json = try self.buildMissionRecordJson(mission);
            defer self.allocator.free(mission_json);
            const detail = try buildPrReviewAdvanceDetailJson(
                self,
                mission_json,
                state.phase,
                contract.context_path,
                contract.state_path,
                contract.artifact_root,
                "blocked",
                "fix_environment",
                sync_result_json.?,
                null,
                wait_result_json,
                info.message,
            );
            defer self.allocator.free(detail);
            return self.buildPrReviewSuccessResultJson(.advance, detail);
        }
        const next_context = try self.loadPrReviewContextSnapshot(contract.context_path);
        context.deinit(self.allocator);
        context = next_context;
        const next_state = try self.loadPrReviewStateSnapshot(contract.state_path);
        state.deinit(self.allocator);
        state = next_state;
    }

    const head_changed = !std.mem.eql(u8, previous_head_sha, state.last_synced_head_sha);
    if (run_validation and wants_validation and advanceNeedsValidation(previous_phase, wait_result_json != null, head_changed)) {
        validation_result_json = try executeAdvanceValidation(self, mission_id, args_obj);
        const next_state = try self.loadPrReviewStateSnapshot(contract.state_path);
        state.deinit(self.allocator);
        state = next_state;
        if (try self.extractErrorInfoFromToolPayload(validation_result_json.?)) |info| {
            defer info.deinit(self.allocator);
            if (!std.mem.eql(u8, state.latest_validation_status, "passed") and !std.mem.eql(u8, state.latest_validation_status, "failed")) {
                const blocked = store.transition(self.allocator, mission_id, .{
                    .next_state = .blocked,
                    .stage = "runner.blocked",
                    .reason = info.message,
                    .summary = info.message,
                    .actor = .{ .actor_type = self.actor_type, .actor_id = self.actor_id },
                }) catch |err| switch (err) {
                    mission_store_mod.MissionStoreError.MissionNotFound => return error.NotFound,
                    else => return error.InvalidPayload,
                };
                mission.deinit(self.allocator);
                mission = blocked;
                const mission_json = try self.buildMissionRecordJson(mission);
                defer self.allocator.free(mission_json);
                const detail = try buildPrReviewAdvanceDetailJson(
                    self,
                    mission_json,
                    state.phase,
                    contract.context_path,
                    contract.state_path,
                    contract.artifact_root,
                    "blocked",
                    "fix_environment",
                    sync_result_json,
                    validation_result_json.?,
                    wait_result_json,
                    info.message,
                );
                defer self.allocator.free(detail);
                return self.buildPrReviewSuccessResultJson(.advance, detail);
            }
        }
    }

    const latest_mission = (try store.getOwned(self.allocator, mission_id)) orelse return error.NotFound;
    mission.deinit(self.allocator);
    mission = latest_mission;
    const mission_json = try self.buildMissionRecordJson(mission);
    defer self.allocator.free(mission_json);

    const runner_status: []const u8 = "ready_for_review";
    const next_action: []const u8 = if (state.latest_draft_revision > 0 and std.mem.eql(u8, state.latest_recommendation_status, "pending"))
        "record_review"
    else if (state.latest_draft_revision > 0)
        "revise_review"
    else
        "draft_review";
    const runner_note: []const u8 = if (std.mem.eql(u8, next_action, "record_review"))
        "Deterministic PR review runner steps are complete; Spider Monkey should promote the saved draft into a final review and optionally publish it."
    else
        "Deterministic PR review runner steps are complete; Spider Monkey should inspect the workspace artifacts and continue the review draft.";
    const detail = try buildPrReviewAdvanceDetailJson(
        self,
        mission_json,
        state.phase,
        contract.context_path,
        contract.state_path,
        contract.artifact_root,
        runner_status,
        next_action,
        sync_result_json,
        validation_result_json,
        wait_result_json,
        runner_note,
    );
    defer self.allocator.free(detail);
    return self.buildPrReviewSuccessResultJson(.advance, detail);
}

fn buildPrReviewAgenticGoal(
    self: anytype,
    mission_id: []const u8,
    context_path: []const u8,
    state_path: []const u8,
    artifact_root: []const u8,
    state: StateSnapshot,
    action: []const u8,
) ![]u8 {
    const draft_path = try resolvePrReviewArtifactPath(self, artifact_root, state.draft_review_artifact);
    defer self.allocator.free(draft_path);
    const validation_path = try resolvePrReviewArtifactPath(self, artifact_root, state.validation_artifact);
    defer self.allocator.free(validation_path);
    const repo_status_path = try resolvePrReviewArtifactPath(self, artifact_root, state.repo_status_artifact);
    defer self.allocator.free(repo_status_path);
    const diff_range_path = try resolvePrReviewArtifactPath(self, artifact_root, state.diff_range_artifact);
    defer self.allocator.free(diff_range_path);
    const review_comment_path = try resolvePrReviewArtifactPath(self, artifact_root, state.draft_review_comment_artifact);
    defer self.allocator.free(review_comment_path);
    const playbook_path = try self.resolvePreferredServicePath("library", "/use-cases/pr-review/README.md");
    defer self.allocator.free(playbook_path);
    const save_draft_path = try self.resolvePreferredServicePath("pr_review", "/control/save_draft.json");
    defer self.allocator.free(save_draft_path);
    const validation_summary = state.latest_validation_summary orelse "none";
    const validation_preview = try loadPrReviewValidationPreview(self, validation_path);
    defer if (validation_preview) |value| self.allocator.free(value);
    const draft_artifact_instruction = if (state.latest_draft_revision > 0)
        try std.fmt.allocPrint(
            self.allocator,
            "If you genuinely need the prior draft, you may read {s} and {s}, but still finish by saving the revised draft.",
            .{ draft_path, review_comment_path },
        )
    else
        try std.fmt.allocPrint(
            self.allocator,
            "Do not read or list {s} or {s}; save_draft will create those first-draft artifacts.",
            .{ draft_path, review_comment_path },
        );
    defer self.allocator.free(draft_artifact_instruction);
    const save_payload_instruction = try std.fmt.allocPrint(
        self.allocator,
        "Your save_draft payload only needs mission_id=\"{s}\", summary, findings (array), recommendation (object), and review_comment.",
        .{mission_id},
    );
    defer self.allocator.free(save_payload_instruction);

    if (validation_preview) |preview| {
        return std.fmt.allocPrint(
            self.allocator,
            "Continue PR review mission {s}.\n" ++
                "Start with {s} and {s}.\n" ++
                "Latest validation status: {s}. Latest validation summary: {s}.\n" ++
                "Validation preview:\n{s}\n" ++
                "You already have enough evidence to draft a review from that validation failure unless another file is strictly necessary.\n" ++
                "Inspect the latest review artifacts under {s}. Read {s} only if you need the full capture; only read {s} or {s} if you still need supporting evidence.\n" ++
                "{s}\n" ++
                "Read {s} only if you genuinely need a workflow reminder.\n" ++
                "Current phase: {s}. Current focus: {s}.\n" ++
                "You must finish this handoff by calling {s} to {s} the review draft and create or update the draft artifacts.\n" ++
                "{s}\n" ++
                "Once save_draft succeeds, stop issuing further tool calls.\n" ++
                "Use the minimum number of reads needed to produce a concrete draft; do not stop after inspection alone.\n" ++
                "Persist concrete findings, a recommendation object, and a review_comment draft.\n" ++
                "Do not publish or finalize the review yet. If evidence is missing, capture the blocker in the saved draft summary.",
            .{
                mission_id,
                context_path,
                state_path,
                state.latest_validation_status,
                validation_summary,
                preview,
                artifact_root,
                validation_path,
                repo_status_path,
                diff_range_path,
                draft_artifact_instruction,
                playbook_path,
                state.phase,
                state.current_focus,
                save_draft_path,
                action,
                save_payload_instruction,
            },
        );
    }

    return std.fmt.allocPrint(
        self.allocator,
        "Continue PR review mission {s}.\n" ++
            "Start with {s} and {s}.\n" ++
            "Latest validation status: {s}. Latest validation summary: {s}.\n" ++
            "Inspect the latest review artifacts under {s}. Start with {s}; only read {s} or {s} if you still need supporting evidence.\n" ++
            "{s}\n" ++
            "Read {s} only if you genuinely need a workflow reminder.\n" ++
            "Current phase: {s}. Current focus: {s}.\n" ++
            "You must finish this handoff by calling {s} to {s} the review draft and create or update the draft artifacts.\n" ++
            "{s}\n" ++
            "Once save_draft succeeds, stop issuing further tool calls.\n" ++
            "Use the minimum number of reads needed to produce a concrete draft; do not stop after inspection alone.\n" ++
            "Persist concrete findings, a recommendation object, and a review_comment draft.\n" ++
            "Do not publish or finalize the review yet. If evidence is missing, capture the blocker in the saved draft summary.",
        .{
            mission_id,
            context_path,
            state_path,
            state.latest_validation_status,
            validation_summary,
            artifact_root,
            validation_path,
            repo_status_path,
            diff_range_path,
            draft_artifact_instruction,
            playbook_path,
            state.phase,
            state.current_focus,
            save_draft_path,
            action,
            save_payload_instruction,
        },
    );
}

fn buildPrReviewAgenticRescueGoal(
    self: anytype,
    mission_id: []const u8,
    context_path: []const u8,
    state_path: []const u8,
    artifact_root: []const u8,
    state: StateSnapshot,
    action: []const u8,
) ![]u8 {
    const save_draft_path = try self.resolvePreferredServicePath("pr_review", "/control/save_draft.json");
    defer self.allocator.free(save_draft_path);
    const validation_path = try resolvePrReviewArtifactPath(self, artifact_root, state.validation_artifact);
    defer self.allocator.free(validation_path);
    const draft_path = try resolvePrReviewArtifactPath(self, artifact_root, state.draft_review_artifact);
    defer self.allocator.free(draft_path);
    const review_comment_path = try resolvePrReviewArtifactPath(self, artifact_root, state.draft_review_comment_artifact);
    defer self.allocator.free(review_comment_path);

    const validation_summary = state.latest_validation_summary orelse "Review evidence is already available in the validation artifact.";
    const validation_preview = try loadPrReviewValidationPreview(self, validation_path);
    defer if (validation_preview) |value| self.allocator.free(value);

    if (validation_preview) |preview| {
        return std.fmt.allocPrint(
            self.allocator,
            "Rescue PR review mission {s}.\n" ++
                "The previous attempt did not persist a draft.\n" ++
                "Treat {s} and {s} as outputs to create on the first save, not files to inspect.\n" ++
                "Use exactly one file_write tool call to {s} now.\n" ++
                "Do not call file_read again unless {s} or {s} is genuinely missing from active memory.\n" ++
                "Write a valid save_draft payload with mission_id=\"{s}\", status=\"drafted\", summary, findings (array), recommendation (object), and review_comment.\n" ++
                "This is a {s} step, so create a draft rather than publishing a final review.\n" ++
                "Use this validation summary: {s}\n" ++
                "Use this validation preview as evidence:\n{s}\n" ++
                "A recommendation decision of \"comment\" is acceptable for this draft if you are blocked on validation.\n" ++
                "This rescue round must end by saving the draft, then stopping with no additional inspection or extra tool calls.",
            .{
                mission_id,
                draft_path,
                review_comment_path,
                save_draft_path,
                context_path,
                state_path,
                mission_id,
                action,
                validation_summary,
                preview,
            },
        );
    }

    return std.fmt.allocPrint(
        self.allocator,
        "Rescue PR review mission {s}.\n" ++
            "The previous attempt did not persist a draft.\n" ++
            "Treat {s} and {s} as outputs to create on the first save, not files to inspect.\n" ++
            "Use exactly one file_write tool call to {s} now.\n" ++
            "Do not call file_read again unless {s} or {s} is genuinely missing from active memory.\n" ++
            "Write a valid save_draft payload with mission_id=\"{s}\", status=\"drafted\", summary, findings (array), recommendation (object), and review_comment.\n" ++
            "This is a {s} step, so create a draft rather than publishing a final review.\n" ++
            "Use this factual summary in the draft if helpful: {s}\n" ++
            "A recommendation decision of \"comment\" is acceptable for this draft if you are blocked on validation.\n" ++
            "This rescue round must end by saving the draft, then stopping with no additional inspection or extra tool calls.",
        .{
            mission_id,
            draft_path,
            review_comment_path,
            save_draft_path,
            context_path,
            state_path,
            mission_id,
            action,
            validation_summary,
        },
    );
}

fn loadPrReviewValidationPreview(self: anytype, validation_path: []const u8) !?[]u8 {
    const validation_json = (self.tryReadInternalPath(validation_path) catch return null) orelse return null;
    defer self.allocator.free(validation_json);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, validation_json, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const root = parsed.value.object;

    if (root.get("commands")) |commands_value| {
        if (commands_value == .array) {
            for (commands_value.array.items) |command_value| {
                if (command_value != .object) continue;
                const result_value = command_value.object.get("result") orelse continue;
                if (result_value != .object) continue;
                const nested_result = result_value.object.get("result") orelse continue;
                if (nested_result != .object) continue;
                const data_b64 = nested_result.object.get("data_b64") orelse continue;
                if (data_b64 != .string or data_b64.string.len == 0) continue;

                const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(data_b64.string) catch continue;
                const decoded = try self.allocator.alloc(u8, decoded_len);
                defer self.allocator.free(decoded);
                _ = std.base64.standard.Decoder.decode(decoded, data_b64.string) catch continue;

                const trimmed = std.mem.trim(u8, decoded, " \t\r\n");
                if (trimmed.len == 0) continue;
                const preview_len = @min(trimmed.len, 480);
                return @as(?[]u8, try self.allocator.dupe(u8, trimmed[0..preview_len]));
            }
        }
    }

    if (root.get("summary")) |summary_value| {
        if (summary_value == .string and summary_value.string.len > 0) {
            return @as(?[]u8, try self.allocator.dupe(u8, summary_value.string));
        }
    }
    return null;
}

fn resolvePreferredServiceTarget(self: anytype, service_id: []const u8, control_suffix: []const u8) !PreferredServiceTarget {
    const service_path = try self.resolvePreferredServicePath(service_id, "");
    errdefer self.allocator.free(service_path);
    const invoke_path = try self.resolvePreferredServicePath(service_id, control_suffix);
    errdefer self.allocator.free(invoke_path);
    return .{
        .service_path = service_path,
        .invoke_path = invoke_path,
    };
}

fn executeAdvanceSync(self: anytype, mission_id: []const u8, phase: []const u8, args_obj: std.json.ObjectMap) ![]u8 {
    const payload = try buildAdvanceSyncArgsJson(self, mission_id, phase, args_obj);
    defer self.allocator.free(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return executeSyncOp(self, parsed.value.object);
}

fn executeAdvanceValidation(self: anytype, mission_id: []const u8, args_obj: std.json.ObjectMap) ![]u8 {
    const payload = try buildAdvanceValidationArgsJson(self, mission_id, args_obj);
    defer self.allocator.free(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return executeRunValidationOp(self, parsed.value.object);
}

fn buildAdvanceSyncArgsJson(
    self: anytype,
    mission_id: []const u8,
    phase: []const u8,
    args_obj: std.json.ObjectMap,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeByte('{');
    try writer.writeAll("\"mission_id\":");
    try writer.print("{f}", .{std.json.fmt(mission_id, .{})});
    try writer.writeAll(",\"phase\":");
    try writer.print("{f}", .{std.json.fmt(phase, .{})});
    try writer.writeAll(",\"stage\":\"ready_for_checkout\"");
    if (args_obj.get("current_focus")) |value| {
        const raw = try self.renderJsonValue(value);
        defer self.allocator.free(raw);
        try writer.writeAll(",\"current_focus\":");
        try writer.writeAll(raw);
    }
    // Advance refreshes the PR state by default unless the caller explicitly opts a step out.
    inline for ([_][]const u8{ "provider_sync", "sync_checkout", "repo_status", "diff_range" }) |field| {
        if (args_obj.get(field)) |value| {
            const raw = try self.renderJsonValue(value);
            defer self.allocator.free(raw);
            try writer.print(",\"{s}\":", .{field});
            try writer.writeAll(raw);
        } else {
            try writer.print(",\"{s}\":true", .{field});
        }
    }
    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

fn buildAdvanceValidationArgsJson(
    self: anytype,
    mission_id: []const u8,
    args_obj: std.json.ObjectMap,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeByte('{');
    try writer.writeAll("\"mission_id\":");
    try writer.print("{f}", .{std.json.fmt(mission_id, .{})});
    try writer.writeAll(",\"phase\":\"reviewing\"");
    try writer.writeAll(",\"stage\":\"validating\"");
    if (args_obj.get("current_focus")) |value| {
        const raw = try self.renderJsonValue(value);
        defer self.allocator.free(raw);
        try writer.writeAll(",\"current_focus\":");
        try writer.writeAll(raw);
    }
    if (args_obj.get("commands")) |value| {
        const raw = try self.renderJsonValue(value);
        defer self.allocator.free(raw);
        try writer.writeAll(",\"commands\":");
        try writer.writeAll(raw);
    }
    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

fn executeAdvanceWait(
    self: anytype,
    args_obj: std.json.ObjectMap,
    phase: []const u8,
    timeout_ms: i64,
) ![]u8 {
    const wait_request = try buildAdvanceWaitRequestJson(self, args_obj, phase, timeout_ms);
    defer self.allocator.free(wait_request);
    const events_wait_path = try self.resolvePreferredServicePath("events", "/control/wait.json");
    defer self.allocator.free(events_wait_path);
    const events_next_path = try self.resolvePreferredServicePath("events", "/next.json");
    defer self.allocator.free(events_next_path);

    var write_error = try self.writeInternalPath(events_wait_path, wait_request);
    defer if (write_error) |*value| value.deinit(self.allocator);
    if (write_error) |value| {
        return self.buildPrReviewFailureResultJson(.advance, value.code, value.message);
    }
    const payload = (try self.tryReadInternalPath(events_next_path)) orelse
        try self.buildPrReviewFailureResultJson(.advance, "missing_wait_result", "events next.json produced no payload");
    return payload;
}

fn buildAdvanceWaitRequestJson(
    self: anytype,
    args_obj: std.json.ObjectMap,
    phase: []const u8,
    timeout_ms: i64,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeAll("{\"paths\":");
    if (args_obj.get("wait_paths")) |value| {
        if (value != .array) return error.InvalidPayload;
        const raw = try self.renderJsonValue(value);
        defer self.allocator.free(raw);
        try writer.writeAll(raw);
    } else {
        const github_event_path = try self.resolvePreferredServicePath("events", "/sources/agent/github_pr.json");
        defer self.allocator.free(github_event_path);
        const ci_timeout_path = try self.resolvePreferredServicePath("events", "/sources/time/after/300000.json");
        defer self.allocator.free(ci_timeout_path);
        try writer.writeByte('[');
        try writer.print("{f}", .{std.json.fmt(github_event_path, .{})});
        if (std.mem.eql(u8, phase, "awaiting_ci")) {
            try writer.writeByte(',');
            try writer.print("{f}", .{std.json.fmt(ci_timeout_path, .{})});
        }
        try writer.writeByte(']');
    }
    try writer.print(",\"timeout_ms\":{d}}}", .{timeout_ms});
    return out.toOwnedSlice(self.allocator);
}

fn didAdvanceWaitFire(self: anytype, payload_json: []const u8, expected_run_id: ?[]const u8) !bool {
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const waiting = (try jsonObjectOptionalBool(parsed.value.object, "waiting")) orelse false;
    const configured = (try jsonObjectOptionalBool(parsed.value.object, "configured")) orelse false;
    if (!configured or waiting) return false;
    const run_id = expected_run_id orelse return true;
    const signal_value = parsed.value.object.get("signal") orelse return true;
    if (signal_value != .object) return false;
    const parameter = (try jsonObjectOptionalString(signal_value.object, "parameter")) orelse return true;
    if (!std.mem.eql(u8, parameter, "github_pr")) return true;
    const payload_value = signal_value.object.get("payload") orelse return false;
    if (payload_value != .object) return false;
    const payload_run_id = (try jsonObjectOptionalString(payload_value.object, "run_id")) orelse return false;
    return std.mem.eql(u8, payload_run_id, run_id);
}

fn advanceHasValidationCommands(
    self: anytype,
    args_obj: std.json.ObjectMap,
    context: ContextSnapshot,
) !bool {
    if (args_obj.get("commands")) |value| {
        if (value != .array) return error.InvalidPayload;
        return value.array.items.len > 0;
    }
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, context.default_review_commands_json, .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.InvalidPayload;
    return parsed.value.array.items.len > 0;
}

fn buildPrReviewAdvanceDetailJson(
    self: anytype,
    mission_json: []const u8,
    phase: []const u8,
    context_path: []const u8,
    state_path: []const u8,
    artifact_root: []const u8,
    runner_status: []const u8,
    next_action: []const u8,
    sync_result_json: ?[]const u8,
    validation_result_json: ?[]const u8,
    wait_result_json: ?[]const u8,
    note: ?[]const u8,
) ![]u8 {
    const escaped_phase = try unified.jsonEscape(self.allocator, phase);
    defer self.allocator.free(escaped_phase);
    const escaped_context = try unified.jsonEscape(self.allocator, context_path);
    defer self.allocator.free(escaped_context);
    const escaped_state = try unified.jsonEscape(self.allocator, state_path);
    defer self.allocator.free(escaped_state);
    const escaped_artifact_root = try unified.jsonEscape(self.allocator, artifact_root);
    defer self.allocator.free(escaped_artifact_root);
    const escaped_runner_status = try unified.jsonEscape(self.allocator, runner_status);
    defer self.allocator.free(escaped_runner_status);
    const escaped_next_action = try unified.jsonEscape(self.allocator, next_action);
    defer self.allocator.free(escaped_next_action);
    const note_json = if (note) |value|
        try self.formatJsonString(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(note_json);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"mission\":{s},\"review\":{{\"phase\":\"{s}\",\"context_path\":\"{s}\",\"state_path\":\"{s}\",\"artifact_root\":\"{s}\"}},\"runner\":{{\"status\":\"{s}\",\"next_action\":\"{s}\",\"sync\":{s},\"validation\":{s},\"wait\":{s},\"note\":{s}}}}}",
        .{
            mission_json,
            escaped_phase,
            escaped_context,
            escaped_state,
            escaped_artifact_root,
            escaped_runner_status,
            escaped_next_action,
            sync_result_json orelse "null",
            validation_result_json orelse "null",
            wait_result_json orelse "null",
            note_json,
        },
    );
}

fn parseOptionalServiceArgs(args_obj: std.json.ObjectMap, key: []const u8) !OptionalServiceArgs {
    if (args_obj.get(key)) |value| {
        return switch (value) {
            .null => .{},
            .bool => .{ .enabled = value.bool },
            .object => .{ .enabled = true, .overrides = value.object },
            else => error.InvalidPayload,
        };
    }
    return .{};
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

fn jsonObjectOptionalString(obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    if (obj.get(key)) |value| {
        return switch (value) {
            .null => null,
            .string => value.string,
            else => error.InvalidPayload,
        };
    }
    return null;
}

fn jsonObjectOptionalU64(obj: std.json.ObjectMap, key: []const u8) !?u64 {
    if (obj.get(key)) |value| {
        return switch (value) {
            .null => null,
            .integer => |signed| blk: {
                if (signed < 0) return error.InvalidPayload;
                break :blk @as(u64, @intCast(signed));
            },
            .float => |float_value| blk: {
                if (float_value < 0) return error.InvalidPayload;
                if (std.math.floor(float_value) != float_value) return error.InvalidPayload;
                if (float_value > @as(f64, @floatFromInt(std.math.maxInt(u64)))) return error.InvalidPayload;
                break :blk @as(u64, @intFromFloat(float_value));
            },
            else => error.InvalidPayload,
        };
    }
    return null;
}

fn jsonObjectOptionalBool(obj: std.json.ObjectMap, key: []const u8) !?bool {
    if (obj.get(key)) |value| {
        return switch (value) {
            .null => null,
            .bool => value.bool,
            else => error.InvalidPayload,
        };
    }
    return null;
}

fn buildRepoKeySlug(self: anytype, repo_key: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    var token_it = std.mem.tokenizeScalar(u8, repo_key, '/');
    var count: usize = 0;
    while (token_it.next()) |segment| {
        const trimmed = std.mem.trim(u8, segment, " \t\r\n");
        if (trimmed.len == 0 or std.mem.eql(u8, trimmed, ".") or std.mem.eql(u8, trimmed, "..")) return error.InvalidPayload;
        if (std.mem.indexOfAny(u8, trimmed, "\\:") != null) return error.InvalidPayload;
        if (count > 0) try out.appendSlice(self.allocator, "__");
        try out.appendSlice(self.allocator, trimmed);
        count += 1;
    }
    if (count == 0) return error.InvalidPayload;
    return out.toOwnedSlice(self.allocator);
}

fn renderJsonFieldOrDefault(self: anytype, obj: std.json.ObjectMap, key: []const u8, default_json: []const u8) ![]u8 {
    if (obj.get(key)) |value| {
        if (value == .null) return self.allocator.dupe(u8, default_json);
        return self.renderJsonValue(value);
    }
    return self.allocator.dupe(u8, default_json);
}

fn phaseForDecision(decision: []const u8) []const u8 {
    if (std.mem.eql(u8, decision, "approve")) return "awaiting_ci";
    if (std.mem.eql(u8, decision, "request_changes")) return "awaiting_author";
    return "reviewing";
}

fn normalizeRecommendationDecision(raw: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return "comment";
    if (std.ascii.eqlIgnoreCase(trimmed, "approve") or
        std.ascii.eqlIgnoreCase(trimmed, "approved") or
        std.ascii.eqlIgnoreCase(trimmed, "approval"))
    {
        return "approve";
    }
    if (std.ascii.eqlIgnoreCase(trimmed, "request_changes") or
        std.ascii.eqlIgnoreCase(trimmed, "request-changes") or
        std.ascii.eqlIgnoreCase(trimmed, "request changes") or
        std.ascii.eqlIgnoreCase(trimmed, "changes_requested") or
        std.ascii.eqlIgnoreCase(trimmed, "changes-requested") or
        std.ascii.eqlIgnoreCase(trimmed, "block") or
        std.ascii.eqlIgnoreCase(trimmed, "blocked") or
        std.ascii.eqlIgnoreCase(trimmed, "reject"))
    {
        return "request_changes";
    }
    return "comment";
}

fn recommendationDecisionFromValue(value: std.json.Value) ![]const u8 {
    if (value != .object) return "comment";
    return recommendationDecisionFromObject(value.object);
}

fn recommendationDecisionFromObject(obj: std.json.ObjectMap) ![]const u8 {
    inline for ([_][]const u8{ "decision", "verdict", "action", "status" }) |field| {
        if (try jsonObjectOptionalString(obj, field)) |value| {
            return normalizeRecommendationDecision(value);
        }
    }
    if ((try jsonObjectOptionalBool(obj, "blocking")) orelse false) {
        return "request_changes";
    }
    return "comment";
}

fn loadLatestPrReviewDraftSnapshot(
    self: anytype,
    contract: ResolvedContract,
    state: StateSnapshot,
) !LoadedDraftSnapshot {
    if (state.latest_draft_revision == 0) return error.NotFound;
    const draft_path = try resolvePrReviewArtifactPath(self, contract.artifact_root, state.draft_review_artifact);
    defer self.allocator.free(draft_path);
    const draft_json = try self.readMissionContractFile(draft_path, 256 * 1024);
    defer self.allocator.free(draft_json);

    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, draft_json, .{});
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const findings = obj.get("findings") orelse return error.InvalidPayload;
    if (findings != .array) return error.InvalidPayload;
    const recommendation = obj.get("recommendation") orelse return error.InvalidPayload;
    if (recommendation != .object) return error.InvalidPayload;

    const review_comment = if (obj.get("review_comment")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .string) return error.InvalidPayload;
        break :blk value.string;
    } else null;
    const thread_actions = if (obj.get("thread_actions")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .array) return error.InvalidPayload;
        break :blk value;
    } else null;
    const summary = if (obj.get("summary")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .string) return error.InvalidPayload;
        break :blk value.string;
    } else null;
    const status = if (obj.get("status")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .string) return error.InvalidPayload;
        break :blk value.string;
    } else null;

    return .{
        .parsed = parsed,
        .findings = findings,
        .recommendation = recommendation,
        .review_comment = review_comment,
        .thread_actions = thread_actions,
        .summary = summary,
        .status = status,
    };
}

fn phaseWaitsForGitHubEvents(phase: []const u8) bool {
    return std.mem.eql(u8, phase, "awaiting_author") or
        std.mem.eql(u8, phase, "awaiting_ci");
}

fn advanceNeedsSync(phase: []const u8, resumed_from_event: bool) bool {
    if (resumed_from_event) return true;
    return std.mem.eql(u8, phase, "discovered") or
        std.mem.eql(u8, phase, "ready_for_checkout") or
        std.mem.eql(u8, phase, "fixing");
}

fn advanceNeedsValidation(
    phase: []const u8,
    resumed_from_event: bool,
    head_changed: bool,
) bool {
    if (std.mem.eql(u8, phase, "discovered") or
        std.mem.eql(u8, phase, "ready_for_checkout") or
        std.mem.eql(u8, phase, "fixing") or
        std.mem.eql(u8, phase, "validating"))
    {
        return true;
    }
    if (!resumed_from_event) return false;
    if (std.mem.eql(u8, phase, "awaiting_author")) return true;
    if (std.mem.eql(u8, phase, "awaiting_ci")) return head_changed;
    return false;
}

fn sameOptionalString(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null and right == null) return true;
    if (left == null or right == null) return false;
    return std.mem.eql(u8, left.?, right.?);
}

fn isActiveMissionState(state: mission_store_mod.MissionState) bool {
    return switch (state) {
        .planning,
        .running,
        .waiting_for_approval,
        .blocked,
        .recovering,
        => true,
        .completed,
        .failed,
        .cancelled,
        => false,
    };
}

fn freeOptionalOwnedString(self: anytype, value: *?[]u8) void {
    if (value.*) |owned| self.allocator.free(owned);
    value.* = null;
}

fn setServiceError(self: anytype, code: *?[]u8, message: *?[]u8, new_code: []const u8, new_message: []const u8) !void {
    freeOptionalOwnedString(self, code);
    freeOptionalOwnedString(self, message);
    code.* = try self.allocator.dupe(u8, new_code);
    message.* = try self.allocator.dupe(u8, new_message);
}

test "pr_review: jsonObjectOptionalU64 rejects negative integers" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"pr_number\":-1}", .{});
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidPayload, jsonObjectOptionalU64(parsed.value.object, "pr_number"));
}

test "pr_review: renderPrReviewU64Arg rejects overflowing floats" {
    const allocator = std.testing.allocator;
    const TestCtx = struct {
        allocator: std.mem.Allocator,

        fn findJsonObjectFieldByNames(_: @This(), obj: std.json.ObjectMap, names: []const []const u8) ?std.json.Value {
            for (names) |name| {
                if (obj.get(name)) |value| return value;
            }
            return null;
        }
    };
    var ctx = TestCtx{ .allocator = allocator };

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"timeout_ms\":1e40}", .{});
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidPayload, renderPrReviewU64Arg(&ctx, parsed.value.object, &.{"timeout_ms"}, null));
}

test "pr_review: didAdvanceWaitFire requires matching github run_id" {
    const allocator = std.testing.allocator;
    const TestCtx = struct { allocator: std.mem.Allocator };
    var ctx = TestCtx{ .allocator = allocator };

    try std.testing.expect(!try didAdvanceWaitFire(
        &ctx,
        "{\"configured\":true,\"waiting\":false,\"signal\":{\"parameter\":\"github_pr\",\"payload\":{\"run_id\":\"pr_review:DeanoC__Spiderweb:999\"}}}",
        "pr_review:DeanoC__Spiderweb:131",
    ));
    try std.testing.expect(try didAdvanceWaitFire(
        &ctx,
        "{\"configured\":true,\"waiting\":false,\"signal\":{\"parameter\":\"github_pr\",\"payload\":{\"run_id\":\"pr_review:DeanoC__Spiderweb:131\"}}}",
        "pr_review:DeanoC__Spiderweb:131",
    ));
}

fn captureServiceErrorFromPayload(
    self: anytype,
    payload_json: []const u8,
    code: *?[]u8,
    message: *?[]u8,
) !bool {
    if (try self.extractErrorInfoFromToolPayload(payload_json)) |info| {
        defer info.deinit(self.allocator);
        try setServiceError(self, code, message, info.code, info.message);
        return true;
    }
    return false;
}
