const std = @import("std");
const unified = @import("spider-protocol").unified;
const mission_store_mod = @import("../mission_store.zig");
const credential_store = @import("../credential_store.zig");
const pr_review_venom = @import("pr_review.zig");

pub const Op = enum {
    sync,
    ingest_event,
    publish_review,
};

const MissionAction = enum {
    none,
    existing,
    created,
};

const EventSnapshot = struct {
    provider: []u8,
    repo_key: []u8,
    pr_number: u64,
    action: []u8,
    event_name: []u8,
    title: []u8,
    pr_url: []u8,
    base_branch: []u8,
    base_sha: []u8,
    head_branch: []u8,
    head_sha: []u8,
    auto_intake: bool,

    fn deinit(self: *EventSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.provider);
        allocator.free(self.repo_key);
        allocator.free(self.action);
        allocator.free(self.event_name);
        allocator.free(self.title);
        allocator.free(self.pr_url);
        allocator.free(self.base_branch);
        allocator.free(self.base_sha);
        allocator.free(self.head_branch);
        allocator.free(self.head_sha);
        self.* = undefined;
    }
};

pub fn seedNamespace(self: anytype, github_pr_dir: u32) !void {
    try self.addDirectoryDescriptors(
        github_pr_dir,
        "GitHub PR",
        "{\"kind\":\"venom\",\"venom_id\":\"github_pr\",\"shape\":\"/global/github_pr/{README.md,SCHEMA.json,TEMPLATE.json,CAPS.json,OPS.json,RUNTIME.json,HOST.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
        "{\"invoke\":true,\"operations\":[\"github_pr_sync\",\"github_pr_ingest_event\",\"github_pr_publish_review\"],\"discoverable\":true,\"network\":true}",
        "GitHub pull-request helpers backed by the GitHub REST API. Use sync to load provider PR metadata, ingest_event to normalize GitHub PR events into Acheron and auto-start review missions, and publish_review for top-level review submission.",
    );
    _ = try self.addFile(
        github_pr_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"sync\":\"control/sync.json\",\"ingest_event\":\"control/ingest_event.json\",\"publish_review\":\"control/publish_review.json\"},\"operations\":{\"sync\":\"github_pr_sync\",\"ingest_event\":\"github_pr_ingest_event\",\"publish_review\":\"github_pr_publish_review\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        github_pr_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"github_pr_service\",\"tool_backend\":\"std_http\",\"api\":\"github_rest\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        github_pr_dir,
        "HOST.json",
        "{\"runtime_kind\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"github_pr_service\",\"tool_backend\":\"std_http\",\"api\":\"github_rest\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        github_pr_dir,
        "TEMPLATE.json",
        "{\"op\":\"ingest_event\",\"arguments\":{\"repo_key\":\"owner/repo\",\"pr_number\":123,\"action\":\"opened\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        github_pr_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        github_pr_dir,
        "STATUS.json",
        "{\"venom_id\":\"github_pr\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    self.github_pr_status_id = try self.addFile(
        github_pr_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    self.github_pr_result_id = try self.addFile(
        github_pr_dir,
        "result.json",
        "{\"ok\":false,\"operation\":null,\"result\":null,\"error\":null}",
        false,
        .none,
    );

    const control_dir = try self.addDir(github_pr_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Use sync.json to load provider metadata for a PR, ingest_event.json to normalize a GitHub PR event into Acheron and auto-start PR Review missions, and publish_review.json to submit a top-level review through the GitHub REST API. invoke.json accepts op=sync|ingest_event|publish_review plus arguments.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .github_pr_invoke);
    _ = try self.addFile(control_dir, "sync.json", "", true, .github_pr_sync);
    _ = try self.addFile(control_dir, "ingest_event.json", "", true, .github_pr_ingest_event);
    _ = try self.addFile(control_dir, "publish_review.json", "", true, .github_pr_publish_review);
}

pub fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "sync") or std.mem.eql(u8, value, "github_pr_sync")) return .sync;
    if (std.mem.eql(u8, value, "ingest_event") or std.mem.eql(u8, value, "github_pr_ingest_event")) return .ingest_event;
    if (std.mem.eql(u8, value, "publish_review") or std.mem.eql(u8, value, "github_pr_publish_review")) return .publish_review;
    return null;
}

pub fn operationName(op: Op) []const u8 {
    return switch (op) {
        .sync => "sync",
        .ingest_event => "ingest_event",
        .publish_review => "publish_review",
    };
}

pub fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .sync => "github_pr_sync",
        .ingest_event => "github_pr_ingest_event",
        .publish_review => "github_pr_publish_review",
    };
}

pub fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    return switch (op) {
        .sync => executeSyncOp(self, args_obj),
        .ingest_event => executeIngestEventOp(self, args_obj),
        .publish_review => executePublishReviewOp(self, args_obj),
    };
}

pub fn buildGitHubPrSuccessResultJson(self: anytype, op: Op, result_json: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
        .{ escaped_operation, result_json },
    );
}

pub fn buildGitHubPrFailureResultJson(self: anytype, op: Op, code: []const u8, message: []const u8) ![]u8 {
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

fn executeSyncOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const provider = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"provider"}) orelse "github", " \t\r\n");
    if (!std.mem.eql(u8, provider, "github")) return error.InvalidPayload;
    const repo_key = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"repo_key"}) orelse return error.InvalidPayload, " \t\r\n");
    if (repo_key.len == 0) return error.InvalidPayload;
    const pr_number = (try jsonObjectOptionalU64(args_obj, "pr_number")) orelse return error.InvalidPayload;
    const dry_run = (try jsonObjectOptionalBool(args_obj, "dry_run")) orelse false;
    const pr_url = try buildPullRequestApiUrl(self.allocator, repo_key, pr_number);
    defer self.allocator.free(pr_url);
    const files_url = try buildPullRequestFilesApiUrl(self.allocator, repo_key, pr_number);
    defer self.allocator.free(files_url);

    if (dry_run) {
        const detail = try buildSyncDryRunDetailJson(self, repo_key, pr_number, pr_url, files_url);
        defer self.allocator.free(detail);
        return self.buildGitHubPrSuccessResultJson(.sync, detail);
    }

    const access_token = resolveGitHubApiToken(self.allocator, args_obj) catch |err| switch (err) {
        error.InvalidPayload => return error.InvalidPayload,
        else => return self.buildGitHubPrFailureResultJson(.sync, "missing_token", "GitHub token not configured"),
    };
    defer self.allocator.free(access_token);

    var pr_response = githubApiRequest(self.allocator, access_token, .GET, pr_url, null) catch |err|
        return self.buildGitHubPrFailureResultJson(.sync, "request_failed", @errorName(err));
    defer pr_response.deinit(self.allocator);
    if (!isGitHubApiSuccessStatus(pr_response.status)) {
        const message = try extractGitHubApiErrorMessage(self.allocator, pr_response.body, "GitHub pull request request failed");
        defer self.allocator.free(message);
        return self.buildGitHubPrFailureResultJson(.sync, gitHubStatusCode(pr_response.status), message);
    }

    var files_response = githubApiRequest(self.allocator, access_token, .GET, files_url, null) catch |err|
        return self.buildGitHubPrFailureResultJson(.sync, "request_failed", @errorName(err));
    defer files_response.deinit(self.allocator);
    if (!isGitHubApiSuccessStatus(files_response.status)) {
        const message = try extractGitHubApiErrorMessage(self.allocator, files_response.body, "GitHub pull request files request failed");
        defer self.allocator.free(message);
        return self.buildGitHubPrFailureResultJson(.sync, gitHubStatusCode(files_response.status), message);
    }

    const provider_json = buildGitHubProviderJson(self, pr_response.body, files_response.body) catch |err|
        return self.buildGitHubPrFailureResultJson(.sync, "invalid_provider_payload", @errorName(err));
    defer self.allocator.free(provider_json);
    const detail = try buildSyncDetailJson(self, repo_key, pr_number, pr_url, files_url, provider_json);
    defer self.allocator.free(detail);
    return self.buildGitHubPrSuccessResultJson(.sync, detail);
}

fn executeIngestEventOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    var snapshot = try parseEventSnapshot(self, args_obj);
    defer snapshot.deinit(self.allocator);
    var configured_repo = try self.loadConfiguredPrReviewRepo(snapshot.repo_key);
    defer if (configured_repo) |*value| value.deinit(self.allocator);

    const run_id = try self.buildPrReviewRunId(snapshot.repo_key, snapshot.pr_number);
    defer self.allocator.free(run_id);

    const effective_project_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"project_id"}) orelse self.project_id;
    const auto_intake = if (try jsonObjectOptionalBool(args_obj, "auto_intake")) |value|
        value
    else if (configured_repo) |value|
        if (value.auto_intake) |enabled| enabled else snapshot.auto_intake
    else
        snapshot.auto_intake;

    var mission_action: MissionAction = .none;
    var mission_json: ?[]u8 = null;
    defer if (mission_json) |value| self.allocator.free(value);
    var mission_id: ?[]u8 = null;
    defer if (mission_id) |value| self.allocator.free(value);

    if (auto_intake) {
        const store = self.mission_store orelse return error.InvalidPayload;
        if (self.local_fs_export_root == null) return error.InvalidPayload;

        if (try self.findActivePrReviewMissionByRunId(store, run_id, effective_project_id)) |mission| {
            var active = mission;
            defer active.deinit(self.allocator);
            mission_action = .existing;

            const checkpoint_summary = try std.fmt.allocPrint(
                self.allocator,
                "Received GitHub PR event {s}",
                .{snapshot.event_name},
            );
            defer self.allocator.free(checkpoint_summary);

            var checkpointed = store.recordCheckpoint(self.allocator, active.mission_id, .{
                .stage = "event_intake",
                .summary = checkpoint_summary,
            }) catch |err| switch (err) {
                mission_store_mod.MissionStoreError.MissionNotFound,
                mission_store_mod.MissionStoreError.InvalidStateTransition,
                => try active.cloneOwned(self.allocator),
                else => return error.InvalidPayload,
            };
            defer checkpointed.deinit(self.allocator);

            mission_json = try self.buildMissionRecordJson(checkpointed);
            mission_id = try self.allocator.dupe(u8, checkpointed.mission_id);
        } else {
            const intake_payload = try buildIntakeRequestJson(self, snapshot, run_id, args_obj, configured_repo);
            defer self.allocator.free(intake_payload);

            const intake_invoke_path = try self.resolvePreferredServicePath("pr_review", "/control/intake.json");
            defer self.allocator.free(intake_invoke_path);
            const intake_result_path = try self.resolvePreferredServicePath("pr_review", "/result.json");
            defer self.allocator.free(intake_result_path);

            var write_error = try self.writeInternalPath(intake_invoke_path, intake_payload);
            defer if (write_error) |*value| value.deinit(self.allocator);
            if (write_error) |value| {
                return self.buildGitHubPrFailureResultJson(.ingest_event, value.code, value.message);
            }

            const intake_result = (try self.tryReadInternalPath(intake_result_path)) orelse
                return self.buildGitHubPrFailureResultJson(.ingest_event, "missing_result", "pr_review intake produced no result payload");
            defer self.allocator.free(intake_result);

            if (try self.extractErrorInfoFromToolPayload(intake_result)) |info| {
                defer info.deinit(self.allocator);
                return self.buildGitHubPrFailureResultJson(.ingest_event, info.code, info.message);
            }

            var created = (try self.findActivePrReviewMissionByRunId(store, run_id, effective_project_id)) orelse
                return self.buildGitHubPrFailureResultJson(.ingest_event, "mission_not_found", "pr_review intake did not create an active mission");
            defer created.deinit(self.allocator);

            mission_action = .created;
            mission_json = try self.buildMissionRecordJson(created);
            mission_id = try self.allocator.dupe(u8, created.mission_id);
        }
    }

    const signal_payload = try buildSignalPayloadJson(
        self,
        snapshot,
        run_id,
        missionActionName(mission_action),
        mission_id,
    );
    defer self.allocator.free(signal_payload);
    const signal_request = try buildSignalRequestJson(self, "agent", "github_pr", signal_payload);
    defer self.allocator.free(signal_request);

    var signal_error = try self.writeInternalPath("/global/events/control/signal.json", signal_request);
    defer if (signal_error) |*value| value.deinit(self.allocator);
    if (signal_error) |value| {
        return self.buildGitHubPrFailureResultJson(.ingest_event, value.code, value.message);
    }

    const detail = try buildIngestDetailJson(
        self,
        snapshot,
        run_id,
        missionActionName(mission_action),
        "/global/events/sources/agent/github_pr.json",
        mission_json,
    );
    defer self.allocator.free(detail);
    return self.buildGitHubPrSuccessResultJson(.ingest_event, detail);
}

fn executePublishReviewOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const provider = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"provider"}) orelse "github", " \t\r\n");
    if (!std.mem.eql(u8, provider, "github")) return error.InvalidPayload;
    const repo_key = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"repo_key"}) orelse return error.InvalidPayload, " \t\r\n");
    if (repo_key.len == 0) return error.InvalidPayload;
    const pr_number = (try jsonObjectOptionalU64(args_obj, "pr_number")) orelse return error.InvalidPayload;
    const decision = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"decision"}) orelse "comment", " \t\r\n");
    if (!std.mem.eql(u8, decision, "comment") and !std.mem.eql(u8, decision, "approve") and !std.mem.eql(u8, decision, "request_changes")) {
        return error.InvalidPayload;
    }
    const body = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{ "body", "review_comment" }) orelse "", " \t\r\n");
    const dry_run = (try jsonObjectOptionalBool(args_obj, "dry_run")) orelse false;
    const thread_actions_count = blk: {
        if (args_obj.get("thread_actions")) |value| {
            if (value != .array) return error.InvalidPayload;
            break :blk value.array.items.len;
        }
        break :blk @as(usize, 0);
    };

    const review_url = try buildPullRequestReviewsApiUrl(self.allocator, repo_key, pr_number);
    defer self.allocator.free(review_url);
    const payload_json = try buildPublishReviewPayloadJson(self.allocator, decision, body);
    defer self.allocator.free(payload_json);

    if (dry_run) {
        const detail = try buildPublishDryRunDetailJson(self, repo_key, pr_number, decision, review_url, payload_json, thread_actions_count);
        defer self.allocator.free(detail);
        return self.buildGitHubPrSuccessResultJson(.publish_review, detail);
    }

    const access_token = resolveGitHubApiToken(self.allocator, args_obj) catch |err| switch (err) {
        error.InvalidPayload => return error.InvalidPayload,
        else => return self.buildGitHubPrFailureResultJson(.publish_review, "missing_token", "GitHub token not configured"),
    };
    defer self.allocator.free(access_token);

    var review_response = githubApiRequest(self.allocator, access_token, .POST, review_url, payload_json) catch |err|
        return self.buildGitHubPrFailureResultJson(.publish_review, "request_failed", @errorName(err));
    defer review_response.deinit(self.allocator);
    if (!isGitHubApiSuccessStatus(review_response.status)) {
        const message = try extractGitHubApiErrorMessage(self.allocator, review_response.body, "GitHub publish review failed");
        defer self.allocator.free(message);
        return self.buildGitHubPrFailureResultJson(.publish_review, gitHubStatusCode(review_response.status), message);
    }

    const detail = try buildPublishDetailJson(self, repo_key, pr_number, decision, review_url, payload_json, thread_actions_count);
    defer self.allocator.free(detail);
    return self.buildGitHubPrSuccessResultJson(.publish_review, detail);
}

fn missionActionName(action: MissionAction) []const u8 {
    return switch (action) {
        .none => "none",
        .existing => "existing",
        .created => "created",
    };
}

fn gitHubPrEventNameForAction(action: []const u8) []const u8 {
    if (std.mem.eql(u8, action, "opened")) return "pr.opened";
    if (std.mem.eql(u8, action, "reopened")) return "pr.reopened";
    if (std.mem.eql(u8, action, "synchronize") or std.mem.eql(u8, action, "synchronized")) return "pr.synchronized";
    return "pr.updated";
}

fn shouldAutoIntakeGitHubPrAction(action: []const u8) bool {
    return std.mem.eql(u8, action, "opened") or
        std.mem.eql(u8, action, "reopened") or
        std.mem.eql(u8, action, "synchronize") or
        std.mem.eql(u8, action, "synchronized");
}

fn parseEventSnapshot(self: anytype, args_obj: std.json.ObjectMap) !EventSnapshot {
    const repository_obj = if (args_obj.get("repository")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .object) return error.InvalidPayload;
        break :blk value.object;
    } else null;
    const pull_request_obj = if (args_obj.get("pull_request")) |value| blk: {
        if (value == .null) break :blk null;
        if (value != .object) return error.InvalidPayload;
        break :blk value.object;
    } else null;
    const base_obj = if (pull_request_obj) |value|
        if (value.get("base")) |base_value| blk: {
            if (base_value == .null) break :blk null;
            if (base_value != .object) return error.InvalidPayload;
            break :blk base_value.object;
        } else null
    else
        null;
    const head_obj = if (pull_request_obj) |value|
        if (value.get("head")) |head_value| blk: {
            if (head_value == .null) break :blk null;
            if (head_value != .object) return error.InvalidPayload;
            break :blk head_value.object;
        } else null
    else
        null;

    const provider = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"provider"}) orelse "github", " \t\r\n");
    const repo_key = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"repo_key"}) orelse if (repository_obj) |value| (try jsonObjectOptionalString(value, "full_name")) orelse "" else "", " \t\r\n");
    const action = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"action"}) orelse "", " \t\r\n");
    const event_name = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{ "event_name", "event" }) orelse gitHubPrEventNameForAction(action), " \t\r\n");
    const title = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"title"}) orelse if (pull_request_obj) |value| (try jsonObjectOptionalString(value, "title")) orelse "" else "", " \t\r\n");
    const pr_url = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{ "pr_url", "url" }) orelse if (pull_request_obj) |value| (try jsonObjectOptionalString(value, "html_url")) orelse "" else "", " \t\r\n");
    const base_branch = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"base_branch"}) orelse if (base_obj) |value| (try jsonObjectOptionalString(value, "ref")) orelse "" else "", " \t\r\n");
    const base_sha = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"base_sha"}) orelse if (base_obj) |value| (try jsonObjectOptionalString(value, "sha")) orelse "" else "", " \t\r\n");
    const head_branch = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"head_branch"}) orelse if (head_obj) |value| (try jsonObjectOptionalString(value, "ref")) orelse "" else "", " \t\r\n");
    const head_sha = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"head_sha"}) orelse if (head_obj) |value| (try jsonObjectOptionalString(value, "sha")) orelse "" else "", " \t\r\n");
    const pr_number = (try jsonObjectOptionalU64(args_obj, "pr_number")) orelse if (pull_request_obj) |value| (try jsonObjectOptionalU64(value, "number")) orelse 0 else 0;

    if (provider.len == 0 or repo_key.len == 0 or action.len == 0 or event_name.len == 0 or pr_number == 0) {
        return error.InvalidPayload;
    }

    return .{
        .provider = try self.allocator.dupe(u8, provider),
        .repo_key = try self.allocator.dupe(u8, repo_key),
        .pr_number = pr_number,
        .action = try self.allocator.dupe(u8, action),
        .event_name = try self.allocator.dupe(u8, event_name),
        .title = try self.allocator.dupe(u8, title),
        .pr_url = try self.allocator.dupe(u8, pr_url),
        .base_branch = try self.allocator.dupe(u8, base_branch),
        .base_sha = try self.allocator.dupe(u8, base_sha),
        .head_branch = try self.allocator.dupe(u8, head_branch),
        .head_sha = try self.allocator.dupe(u8, head_sha),
        .auto_intake = if (try jsonObjectOptionalBool(args_obj, "auto_intake")) |value|
            value
        else
            shouldAutoIntakeGitHubPrAction(action),
    };
}

fn buildSyncDryRunDetailJson(self: anytype, repo_key: []const u8, pr_number: u64, pr_url: []const u8, files_url: []const u8) ![]u8 {
    const escaped_repo_key = try unified.jsonEscape(self.allocator, repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_pr_url = try unified.jsonEscape(self.allocator, pr_url);
    defer self.allocator.free(escaped_pr_url);
    const escaped_files_url = try unified.jsonEscape(self.allocator, files_url);
    defer self.allocator.free(escaped_files_url);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"repo_key\":\"{s}\",\"pr_number\":{d},\"dry_run\":true,\"requests\":[{{\"method\":\"GET\",\"url\":\"{s}\"}},{{\"method\":\"GET\",\"url\":\"{s}\"}}]}}",
        .{ escaped_repo_key, pr_number, escaped_pr_url, escaped_files_url },
    );
}

fn buildSyncDetailJson(self: anytype, repo_key: []const u8, pr_number: u64, pr_url: []const u8, files_url: []const u8, provider_json: []const u8) ![]u8 {
    const escaped_repo_key = try unified.jsonEscape(self.allocator, repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_pr_url = try unified.jsonEscape(self.allocator, pr_url);
    defer self.allocator.free(escaped_pr_url);
    const escaped_files_url = try unified.jsonEscape(self.allocator, files_url);
    defer self.allocator.free(escaped_files_url);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"repo_key\":\"{s}\",\"pr_number\":{d},\"dry_run\":false,\"requests\":[{{\"method\":\"GET\",\"url\":\"{s}\"}},{{\"method\":\"GET\",\"url\":\"{s}\"}}],\"provider\":{s}}}",
        .{ escaped_repo_key, pr_number, escaped_pr_url, escaped_files_url, provider_json },
    );
}

fn buildPublishDryRunDetailJson(
    self: anytype,
    repo_key: []const u8,
    pr_number: u64,
    decision: []const u8,
    review_url: []const u8,
    payload_json: []const u8,
    thread_actions_count: usize,
) ![]u8 {
    const escaped_repo_key = try unified.jsonEscape(self.allocator, repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_decision = try unified.jsonEscape(self.allocator, decision);
    defer self.allocator.free(escaped_decision);
    const escaped_review_url = try unified.jsonEscape(self.allocator, review_url);
    defer self.allocator.free(escaped_review_url);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"repo_key\":\"{s}\",\"pr_number\":{d},\"decision\":\"{s}\",\"dry_run\":true,\"request\":{{\"method\":\"POST\",\"url\":\"{s}\",\"payload\":{s}}},\"thread_actions_count\":{d},\"thread_actions_supported\":false}}",
        .{ escaped_repo_key, pr_number, escaped_decision, escaped_review_url, payload_json, thread_actions_count },
    );
}

fn buildPublishDetailJson(
    self: anytype,
    repo_key: []const u8,
    pr_number: u64,
    decision: []const u8,
    review_url: []const u8,
    payload_json: []const u8,
    thread_actions_count: usize,
) ![]u8 {
    const escaped_repo_key = try unified.jsonEscape(self.allocator, repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_decision = try unified.jsonEscape(self.allocator, decision);
    defer self.allocator.free(escaped_decision);
    const escaped_review_url = try unified.jsonEscape(self.allocator, review_url);
    defer self.allocator.free(escaped_review_url);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"repo_key\":\"{s}\",\"pr_number\":{d},\"decision\":\"{s}\",\"published\":true,\"request\":{{\"method\":\"POST\",\"url\":\"{s}\",\"payload\":{s}}},\"thread_actions_count\":{d},\"thread_actions_supported\":false}}",
        .{ escaped_repo_key, pr_number, escaped_decision, escaped_review_url, payload_json, thread_actions_count },
    );
}

fn buildIntakeRequestJson(
    self: anytype,
    snapshot: EventSnapshot,
    run_id: []const u8,
    args_obj: std.json.ObjectMap,
    configured_repo: ?pr_review_venom.RepoConfigSnapshot,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);

    try writer.writeByte('{');
    try writer.writeAll("\"provider\":");
    try writeJsonString(writer, snapshot.provider);
    try writer.writeAll(",\"repo_key\":");
    try writeJsonString(writer, snapshot.repo_key);
    try writer.writeAll(",\"pr_number\":");
    try writer.print("{d}", .{snapshot.pr_number});
    try writer.writeAll(",\"action\":");
    try writeJsonString(writer, snapshot.action);
    try writer.writeAll(",\"event_name\":");
    try writeJsonString(writer, snapshot.event_name);
    try writer.writeAll(",\"run_id\":");
    try writeJsonString(writer, run_id);
    try writer.writeAll(",\"provider_sync\":false");
    if (snapshot.title.len > 0) {
        try writer.writeAll(",\"title\":");
        try writeJsonString(writer, snapshot.title);
    }
    if (snapshot.pr_url.len > 0) {
        try writer.writeAll(",\"pr_url\":");
        try writeJsonString(writer, snapshot.pr_url);
    }
    if (snapshot.base_branch.len > 0) {
        try writer.writeAll(",\"base_branch\":");
        try writeJsonString(writer, snapshot.base_branch);
    }
    if (snapshot.base_sha.len > 0) {
        try writer.writeAll(",\"base_sha\":");
        try writeJsonString(writer, snapshot.base_sha);
    }
    if (snapshot.head_branch.len > 0) {
        try writer.writeAll(",\"head_branch\":");
        try writeJsonString(writer, snapshot.head_branch);
    }
    if (snapshot.head_sha.len > 0) {
        try writer.writeAll(",\"head_sha\":");
        try writeJsonString(writer, snapshot.head_sha);
    }

    const passthrough_fields = [_][]const u8{
        "default_review_commands",
        "review_policy_paths",
        "approval_policy",
        "checkout_path",
        "project_id",
        "agent_id",
        "workspace_root",
        "worktree_name",
    };
    for (passthrough_fields) |field| {
        if (args_obj.get(field)) |value| {
            const rendered = try self.renderJsonValue(value);
            defer self.allocator.free(rendered);
            try writer.print(",\"{s}\":{s}", .{ field, rendered });
        }
    }

    if (configured_repo) |value| {
        if (args_obj.get("base_branch") == null and snapshot.base_branch.len == 0) {
            try writer.writeAll(",\"base_branch\":");
            try writeJsonString(writer, value.default_branch);
        }
        if (args_obj.get("review_policy_paths") == null) {
            try writer.writeAll(",\"review_policy_paths\":");
            try writer.writeAll(value.review_policy_paths_json);
        }
        if (args_obj.get("default_review_commands") == null) {
            try writer.writeAll(",\"default_review_commands\":");
            try writer.writeAll(value.default_review_commands_json);
        }
        if (args_obj.get("approval_policy") == null) {
            try writer.writeAll(",\"approval_policy\":");
            try writer.writeAll(value.approval_policy_json);
        }
        if (args_obj.get("checkout_path") == null) {
            try writer.writeAll(",\"checkout_path\":");
            try writeJsonString(writer, value.checkout_path);
        }
        if (args_obj.get("project_id") == null) {
            if (value.project_id) |project_id| {
                try writer.writeAll(",\"project_id\":");
                try writeJsonString(writer, project_id);
            }
        }
        if (args_obj.get("agent_id") == null) {
            if (value.agent_id) |agent_id| {
                try writer.writeAll(",\"agent_id\":");
                try writeJsonString(writer, agent_id);
            }
        }
        if (args_obj.get("workspace_root") == null) {
            if (value.workspace_root) |workspace_root| {
                try writer.writeAll(",\"workspace_root\":");
                try writeJsonString(writer, workspace_root);
            }
        }
        if (args_obj.get("worktree_name") == null) {
            if (value.worktree_name) |worktree_name| {
                try writer.writeAll(",\"worktree_name\":");
                try writeJsonString(writer, worktree_name);
            }
        }
    }

    try writer.writeByte('}');
    return out.toOwnedSlice(self.allocator);
}

fn buildSignalPayloadJson(
    self: anytype,
    snapshot: EventSnapshot,
    run_id: []const u8,
    mission_action: []const u8,
    mission_id: ?[]const u8,
) ![]u8 {
    const escaped_provider = try unified.jsonEscape(self.allocator, snapshot.provider);
    defer self.allocator.free(escaped_provider);
    const escaped_repo_key = try unified.jsonEscape(self.allocator, snapshot.repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_action = try unified.jsonEscape(self.allocator, snapshot.action);
    defer self.allocator.free(escaped_action);
    const escaped_event_name = try unified.jsonEscape(self.allocator, snapshot.event_name);
    defer self.allocator.free(escaped_event_name);
    const escaped_title = try unified.jsonEscape(self.allocator, snapshot.title);
    defer self.allocator.free(escaped_title);
    const escaped_pr_url = try unified.jsonEscape(self.allocator, snapshot.pr_url);
    defer self.allocator.free(escaped_pr_url);
    const escaped_base_branch = try unified.jsonEscape(self.allocator, snapshot.base_branch);
    defer self.allocator.free(escaped_base_branch);
    const escaped_base_sha = try unified.jsonEscape(self.allocator, snapshot.base_sha);
    defer self.allocator.free(escaped_base_sha);
    const escaped_head_branch = try unified.jsonEscape(self.allocator, snapshot.head_branch);
    defer self.allocator.free(escaped_head_branch);
    const escaped_head_sha = try unified.jsonEscape(self.allocator, snapshot.head_sha);
    defer self.allocator.free(escaped_head_sha);
    const escaped_run_id = try unified.jsonEscape(self.allocator, run_id);
    defer self.allocator.free(escaped_run_id);
    const escaped_mission_action = try unified.jsonEscape(self.allocator, mission_action);
    defer self.allocator.free(escaped_mission_action);
    const mission_id_json = if (mission_id) |value|
        try self.formatJsonString(value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(mission_id_json);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"provider\":\"{s}\",\"repo_key\":\"{s}\",\"pr_number\":{d},\"action\":\"{s}\",\"event_name\":\"{s}\",\"title\":\"{s}\",\"pr_url\":\"{s}\",\"base_branch\":\"{s}\",\"base_sha\":\"{s}\",\"head_branch\":\"{s}\",\"head_sha\":\"{s}\",\"run_id\":\"{s}\",\"mission_action\":\"{s}\",\"mission_id\":{s}}}",
        .{
            escaped_provider,
            escaped_repo_key,
            snapshot.pr_number,
            escaped_action,
            escaped_event_name,
            escaped_title,
            escaped_pr_url,
            escaped_base_branch,
            escaped_base_sha,
            escaped_head_branch,
            escaped_head_sha,
            escaped_run_id,
            escaped_mission_action,
            mission_id_json,
        },
    );
}

fn buildSignalRequestJson(self: anytype, event_type: []const u8, parameter: []const u8, payload_json: []const u8) ![]u8 {
    const escaped_event_type = try unified.jsonEscape(self.allocator, event_type);
    defer self.allocator.free(escaped_event_type);
    const escaped_parameter = try unified.jsonEscape(self.allocator, parameter);
    defer self.allocator.free(escaped_parameter);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"event_type\":\"{s}\",\"parameter\":\"{s}\",\"payload\":{s}}}",
        .{ escaped_event_type, escaped_parameter, payload_json },
    );
}

fn buildIngestDetailJson(
    self: anytype,
    snapshot: EventSnapshot,
    run_id: []const u8,
    mission_action: []const u8,
    signal_path: []const u8,
    mission_json: ?[]const u8,
) ![]u8 {
    const escaped_provider = try unified.jsonEscape(self.allocator, snapshot.provider);
    defer self.allocator.free(escaped_provider);
    const escaped_repo_key = try unified.jsonEscape(self.allocator, snapshot.repo_key);
    defer self.allocator.free(escaped_repo_key);
    const escaped_action = try unified.jsonEscape(self.allocator, snapshot.action);
    defer self.allocator.free(escaped_action);
    const escaped_event_name = try unified.jsonEscape(self.allocator, snapshot.event_name);
    defer self.allocator.free(escaped_event_name);
    const escaped_title = try unified.jsonEscape(self.allocator, snapshot.title);
    defer self.allocator.free(escaped_title);
    const escaped_pr_url = try unified.jsonEscape(self.allocator, snapshot.pr_url);
    defer self.allocator.free(escaped_pr_url);
    const escaped_base_branch = try unified.jsonEscape(self.allocator, snapshot.base_branch);
    defer self.allocator.free(escaped_base_branch);
    const escaped_base_sha = try unified.jsonEscape(self.allocator, snapshot.base_sha);
    defer self.allocator.free(escaped_base_sha);
    const escaped_head_branch = try unified.jsonEscape(self.allocator, snapshot.head_branch);
    defer self.allocator.free(escaped_head_branch);
    const escaped_head_sha = try unified.jsonEscape(self.allocator, snapshot.head_sha);
    defer self.allocator.free(escaped_head_sha);
    const escaped_run_id = try unified.jsonEscape(self.allocator, run_id);
    defer self.allocator.free(escaped_run_id);
    const escaped_mission_action = try unified.jsonEscape(self.allocator, mission_action);
    defer self.allocator.free(escaped_mission_action);
    const escaped_signal_path = try unified.jsonEscape(self.allocator, signal_path);
    defer self.allocator.free(escaped_signal_path);
    const mission_json_value = if (mission_json) |value|
        try self.allocator.dupe(u8, value)
    else
        try self.allocator.dupe(u8, "null");
    defer self.allocator.free(mission_json_value);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"provider\":\"{s}\",\"repo_key\":\"{s}\",\"pr_number\":{d},\"action\":\"{s}\",\"event_name\":\"{s}\",\"title\":\"{s}\",\"pr_url\":\"{s}\",\"base_branch\":\"{s}\",\"base_sha\":\"{s}\",\"head_branch\":\"{s}\",\"head_sha\":\"{s}\",\"run_id\":\"{s}\",\"mission_action\":\"{s}\",\"signal_path\":\"{s}\",\"mission\":{s}}}",
        .{
            escaped_provider,
            escaped_repo_key,
            snapshot.pr_number,
            escaped_action,
            escaped_event_name,
            escaped_title,
            escaped_pr_url,
            escaped_base_branch,
            escaped_base_sha,
            escaped_head_branch,
            escaped_head_sha,
            escaped_run_id,
            escaped_mission_action,
            escaped_signal_path,
            mission_json_value,
        },
    );
}

const GitHubApiResponse = struct {
    status: std.http.Status,
    body: []u8,

    fn deinit(self: *GitHubApiResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        self.* = undefined;
    }
};

fn resolveGitHubApiToken(allocator: std.mem.Allocator, args_obj: std.json.ObjectMap) ![]u8 {
    if (extractOptionalStringByNames(args_obj, &[_][]const u8{ "github_token", "access_token", "token" })) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len == 0) return error.InvalidPayload;
        return allocator.dupe(u8, trimmed);
    }

    if (std.process.getEnvVarOwned(allocator, "GITHUB_TOKEN")) |value| {
        if (std.mem.trim(u8, value, " \t\r\n").len > 0) return value;
        allocator.free(value);
    } else |_| {}

    if (std.process.getEnvVarOwned(allocator, "GH_TOKEN")) |value| {
        if (std.mem.trim(u8, value, " \t\r\n").len > 0) return value;
        allocator.free(value);
    } else |_| {}

    const store = credential_store.CredentialStore.init(allocator);
    if (store.getProviderApiKey("github")) |value| return value;
    return error.MissingGitHubToken;
}

fn buildPullRequestApiUrl(allocator: std.mem.Allocator, repo_key: []const u8, pr_number: u64) ![]u8 {
    return std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/pulls/{d}", .{ repo_key, pr_number });
}

fn buildPullRequestFilesApiUrl(allocator: std.mem.Allocator, repo_key: []const u8, pr_number: u64) ![]u8 {
    return std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/pulls/{d}/files?per_page=100", .{ repo_key, pr_number });
}

fn buildPullRequestReviewsApiUrl(allocator: std.mem.Allocator, repo_key: []const u8, pr_number: u64) ![]u8 {
    return std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/pulls/{d}/reviews", .{ repo_key, pr_number });
}

fn buildPublishReviewPayloadJson(allocator: std.mem.Allocator, decision: []const u8, body: []const u8) ![]u8 {
    const event = if (std.mem.eql(u8, decision, "approve"))
        "APPROVE"
    else if (std.mem.eql(u8, decision, "request_changes"))
        "REQUEST_CHANGES"
    else
        "COMMENT";

    const escaped_event = try unified.jsonEscape(allocator, event);
    defer allocator.free(escaped_event);
    const body_json = if (body.len > 0) blk: {
        const escaped = try unified.jsonEscape(allocator, body);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(body_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"event\":\"{s}\",\"body\":{s}}}",
        .{ escaped_event, body_json },
    );
}

fn githubApiRequest(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
) !GitHubApiResponse {
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token});
    defer allocator.free(auth_header);

    var all_headers = std.ArrayListUnmanaged(std.http.Header){};
    defer all_headers.deinit(allocator);
    try all_headers.append(allocator, .{ .name = "authorization", .value = auth_header });
    try all_headers.append(allocator, .{ .name = "accept", .value = "application/vnd.github+json" });
    try all_headers.append(allocator, .{ .name = "accept-encoding", .value = "identity" });
    try all_headers.append(allocator, .{ .name = "x-github-api-version", .value = "2022-11-28" });
    try all_headers.append(allocator, .{ .name = "user-agent", .value = "spiderweb" });
    if (payload != null) {
        try all_headers.append(allocator, .{ .name = "content-type", .value = "application/json" });
    }

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse(url) catch return error.InvalidPayload;
    var req = client.request(method, uri, .{
        .redirect_behavior = .unhandled,
        .extra_headers = all_headers.items,
    }) catch return error.ExecutionFailed;
    defer req.deinit();

    if (payload) |payload_bytes| {
        req.transfer_encoding = .{ .content_length = payload_bytes.len };
        var request_body = req.sendBodyUnflushed(&.{}) catch return error.ExecutionFailed;
        request_body.writer.writeAll(payload_bytes) catch return error.ExecutionFailed;
        request_body.end() catch return error.ExecutionFailed;
        req.connection.?.flush() catch return error.ExecutionFailed;
    } else {
        req.sendBodiless() catch return error.ExecutionFailed;
    }

    var response = req.receiveHead(&.{}) catch return error.ExecutionFailed;
    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();

    const decompress_buffer: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .zstd => try allocator.alloc(u8, std.compress.zstd.default_window_len),
        .deflate, .gzip => try allocator.alloc(u8, std.compress.flate.max_window_len),
        .compress => return error.UnsupportedCompressionMethod,
    };
    defer if (decompress_buffer.len > 0) allocator.free(decompress_buffer);

    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);
    _ = reader.streamRemaining(&body_writer.writer) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr() orelse error.ExecutionFailed,
        else => return error.ExecutionFailed,
    };

    return .{
        .status = response.head.status,
        .body = try body_writer.toOwnedSlice(),
    };
}

fn isGitHubApiSuccessStatus(status: std.http.Status) bool {
    return switch (status) {
        .ok, .created, .accepted, .no_content => true,
        else => false,
    };
}

fn gitHubStatusCode(status: std.http.Status) []const u8 {
    return switch (status) {
        .unauthorized => "auth_failed",
        .forbidden => "forbidden",
        .not_found => "not_found",
        .too_many_requests => "rate_limited",
        .unprocessable_entity => "invalid_request",
        else => "api_error",
    };
}

fn extractGitHubApiErrorMessage(allocator: std.mem.Allocator, body: []const u8, fallback: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (trimmed.len == 0) return allocator.dupe(u8, fallback);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return allocator.dupe(u8, trimmed);
    };
    defer parsed.deinit();
    if (parsed.value != .object) return allocator.dupe(u8, trimmed);
    const obj = parsed.value.object;
    if (try jsonObjectOptionalString(obj, "message")) |message| {
        if (message.len > 0) return allocator.dupe(u8, message);
    }
    return allocator.dupe(u8, trimmed);
}

fn buildGitHubProviderJson(self: anytype, pull_request_body: []const u8, files_body: []const u8) ![]u8 {
    var pr_parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, pull_request_body, .{});
    defer pr_parsed.deinit();
    if (pr_parsed.value != .object) return error.InvalidPayload;
    const pr_obj = pr_parsed.value.object;

    const base_obj = if (pr_obj.get("base")) |value| blk: {
        if (value != .object) return error.InvalidPayload;
        break :blk value.object;
    } else return error.InvalidPayload;
    const head_obj = if (pr_obj.get("head")) |value| blk: {
        if (value != .object) return error.InvalidPayload;
        break :blk value.object;
    } else return error.InvalidPayload;

    const number = (try jsonObjectOptionalU64(pr_obj, "number")) orelse return error.InvalidPayload;
    const title = (try jsonObjectOptionalString(pr_obj, "title")) orelse "";
    const body = (try jsonObjectOptionalString(pr_obj, "body")) orelse "";
    const url = (try jsonObjectOptionalString(pr_obj, "html_url")) orelse "";
    const is_draft = (try jsonObjectOptionalBool(pr_obj, "draft")) orelse false;
    const state = (try jsonObjectOptionalString(pr_obj, "state")) orelse "";
    const merge_state = (try jsonObjectOptionalString(pr_obj, "mergeable_state")) orelse "";
    const base_ref_name = (try jsonObjectOptionalString(base_obj, "ref")) orelse "";
    const base_ref_oid = (try jsonObjectOptionalString(base_obj, "sha")) orelse "";
    const head_ref_name = (try jsonObjectOptionalString(head_obj, "ref")) orelse "";
    const head_ref_oid = (try jsonObjectOptionalString(head_obj, "sha")) orelse "";
    const files_json = try buildGitHubFilesJson(self, files_body);
    defer self.allocator.free(files_json);

    const escaped_title = try unified.jsonEscape(self.allocator, title);
    defer self.allocator.free(escaped_title);
    const escaped_body = try unified.jsonEscape(self.allocator, body);
    defer self.allocator.free(escaped_body);
    const escaped_url = try unified.jsonEscape(self.allocator, url);
    defer self.allocator.free(escaped_url);
    const escaped_state = try unified.jsonEscape(self.allocator, state);
    defer self.allocator.free(escaped_state);
    const escaped_merge_state = try unified.jsonEscape(self.allocator, merge_state);
    defer self.allocator.free(escaped_merge_state);
    const escaped_base_ref_name = try unified.jsonEscape(self.allocator, base_ref_name);
    defer self.allocator.free(escaped_base_ref_name);
    const escaped_base_ref_oid = try unified.jsonEscape(self.allocator, base_ref_oid);
    defer self.allocator.free(escaped_base_ref_oid);
    const escaped_head_ref_name = try unified.jsonEscape(self.allocator, head_ref_name);
    defer self.allocator.free(escaped_head_ref_name);
    const escaped_head_ref_oid = try unified.jsonEscape(self.allocator, head_ref_oid);
    defer self.allocator.free(escaped_head_ref_oid);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"number\":{d},\"title\":\"{s}\",\"body\":\"{s}\",\"url\":\"{s}\",\"isDraft\":{s},\"state\":\"{s}\",\"mergeStateStatus\":\"{s}\",\"reviewDecision\":null,\"baseRefName\":\"{s}\",\"baseRefOid\":\"{s}\",\"headRefName\":\"{s}\",\"headRefOid\":\"{s}\",\"files\":{s}}}",
        .{
            number,
            escaped_title,
            escaped_body,
            escaped_url,
            if (is_draft) "true" else "false",
            escaped_state,
            escaped_merge_state,
            escaped_base_ref_name,
            escaped_base_ref_oid,
            escaped_head_ref_name,
            escaped_head_ref_oid,
            files_json,
        },
    );
}

fn buildGitHubFilesJson(self: anytype, files_body: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, files_body, .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.InvalidPayload;

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);
    try writer.writeByte('[');
    var first = true;
    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const file_obj = item.object;
        const filename = (try jsonObjectOptionalString(file_obj, "filename")) orelse continue;
        const status = (try jsonObjectOptionalString(file_obj, "status")) orelse "";
        const additions = (try jsonObjectOptionalU64(file_obj, "additions")) orelse 0;
        const deletions = (try jsonObjectOptionalU64(file_obj, "deletions")) orelse 0;
        const changes = (try jsonObjectOptionalU64(file_obj, "changes")) orelse 0;
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeByte('{');
        try writer.writeAll("\"path\":");
        try writeJsonString(writer, filename);
        try writer.writeAll(",\"status\":");
        try writeJsonString(writer, status);
        try writer.print(",\"additions\":{d},\"deletions\":{d},\"changes\":{d}", .{ additions, deletions, changes });
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
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

fn jsonObjectOptionalString(obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    if (obj.get(key)) |value| {
        if (value == .null) return null;
        if (value != .string) return error.InvalidPayload;
        return value.string;
    }
    return null;
}

fn jsonObjectOptionalBool(obj: std.json.ObjectMap, key: []const u8) !?bool {
    if (obj.get(key)) |value| {
        if (value == .null) return null;
        if (value != .bool) return error.InvalidPayload;
        return value.bool;
    }
    return null;
}

fn jsonObjectOptionalU64(obj: std.json.ObjectMap, key: []const u8) !?u64 {
    if (obj.get(key)) |value| {
        if (value == .null) return null;
        return switch (value) {
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
            else => return error.InvalidPayload,
        };
    }
    return null;
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.print("{f}", .{std.json.fmt(value, .{})});
}
