const std = @import("std");
const protocol = @import("spider-protocol").protocol;
const Config = @import("config.zig");
const mission_store_mod = @import("mission_store.zig");
const chat_job_index = @import("agents/chat_job_index.zig");
const runtime_server_mod = @import("agents/runtime_server.zig");
const runtime_handle_mod = @import("agents/runtime_handle.zig");
const control_plane_mod = @import("acheron/control_plane.zig");
const tool_registry = @import("ziggy-tool-runtime").tool_registry;
const session_mod = @import("acheron/session.zig");

const Session = session_mod.Session;

const AcheronBridge = struct {
    allocator: std.mem.Allocator,
    cwd: []const u8,
    session: ?*Session = null,
    mutex: std.Thread.Mutex = .{},

    pub fn dispatch(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        tool_name: []const u8,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        const self: *AcheronBridge = @ptrCast(@alignCast(ctx));
        return self.dispatchInternal(allocator, tool_name, args_json);
    }

    fn dispatchInternal(
        self: *AcheronBridge,
        allocator: std.mem.Allocator,
        tool_name: []const u8,
        args_json: []const u8,
    ) tool_registry.ToolExecutionResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        const session = self.session orelse return fail(allocator, .execution_failed, "Acheron session is not ready");

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, args_json, .{}) catch {
            return fail(allocator, .invalid_params, "tool args must be valid JSON");
        };
        defer parsed.deinit();
        if (parsed.value != .object) return fail(allocator, .invalid_params, "tool args must be a JSON object");
        const obj = parsed.value.object;

        const raw_path = requiredString(obj, "path") orelse return fail(allocator, .invalid_params, "missing required parameter: path");
        const absolute_path = normalizePath(allocator, self.cwd, raw_path) catch return fail(allocator, .execution_failed, "out of memory");
        defer allocator.free(absolute_path);

        if (std.mem.eql(u8, tool_name, "file_write")) {
            if (!isAcheronPath(absolute_path)) {
                std.log.warn("dogfood bridge denied file_write outside Acheron: {s}", .{absolute_path});
                return fail(allocator, .permission_denied, "dogfood harness only allows file_write to Acheron paths");
            }
            const content = requiredString(obj, "content") orelse return fail(allocator, .invalid_params, "missing required parameter: content");
            const maybe_err = session.writeInternalPath(absolute_path, content) catch |err| {
                return failOwned(allocator, .execution_failed, allocator.dupe(u8, @errorName(err)) catch @panic("out of memory"));
            };
            if (maybe_err) |err_info| {
                defer {
                    var owned = err_info;
                    owned.deinit(allocator);
                }
                return failOwned(allocator, .execution_failed, allocator.dupe(u8, err_info.message) catch @panic("out of memory"));
            }

            const result_path = controlResultPath(allocator, absolute_path) catch return fail(allocator, .execution_failed, "out of memory");
            defer if (result_path) |value| allocator.free(value);
            const operation_result = if (result_path) |value| session.tryReadInternalPath(value) catch null else null;
            defer if (operation_result) |value| allocator.free(value);

            const payload = buildFileWritePayload(
                allocator,
                trimLeadingSlash(absolute_path),
                content.len,
                operation_result,
            ) catch return fail(allocator, .execution_failed, "out of memory");
            return .{ .success = .{ .payload_json = payload } };
        }

        if (std.mem.eql(u8, tool_name, "file_read")) {
            if (isAcheronPath(absolute_path)) {
                const content = session.tryReadInternalPath(absolute_path) catch null orelse
                    {
                        std.log.warn("dogfood bridge missing Acheron file: {s}", .{absolute_path});
                        return fail(allocator, .execution_failed, "file not found");
                    };
                defer allocator.free(content);
                const payload = buildFileReadPayload(
                    allocator,
                    trimLeadingSlash(absolute_path),
                    content,
                ) catch return fail(allocator, .execution_failed, "out of memory");
                return .{ .success = .{ .payload_json = payload } };
            }

            const content = readHostFile(allocator, absolute_path) catch |err| {
                std.log.warn("dogfood bridge host read failed: {s} err={s}", .{ absolute_path, @errorName(err) });
                return failOwned(allocator, .execution_failed, allocator.dupe(u8, @errorName(err)) catch @panic("out of memory"));
            };
            defer allocator.free(content);
            const payload = buildFileReadPayload(
                allocator,
                absolute_path,
                content,
            ) catch return fail(allocator, .execution_failed, "out of memory");
            return .{ .success = .{ .payload_json = payload } };
        }

        if (std.mem.eql(u8, tool_name, "file_list")) {
            const recursive = optionalBool(obj, "recursive") orelse false;
            const max_entries = optionalUsize(obj, "max_entries") orelse 100;
            if (isAcheronPath(absolute_path)) {
                const content = session.tryReadInternalPath(absolute_path) catch null orelse
                    {
                        std.log.warn("dogfood bridge missing Acheron directory: {s}", .{absolute_path});
                        return fail(allocator, .execution_failed, "directory not found");
                    };
                defer allocator.free(content);
                const payload = buildAcheronFileListPayload(
                    allocator,
                    trimLeadingSlash(absolute_path),
                    content,
                    max_entries,
                ) catch return fail(allocator, .execution_failed, "out of memory");
                return .{ .success = .{ .payload_json = payload } };
            }

            const payload = buildHostFileListPayload(
                allocator,
                absolute_path,
                recursive,
                max_entries,
            ) catch |err| {
                std.log.warn("dogfood bridge host list failed: {s} err={s}", .{ absolute_path, @errorName(err) });
                return failOwned(allocator, .execution_failed, allocator.dupe(u8, @errorName(err)) catch @panic("out of memory"));
            };
            return .{ .success = .{ .payload_json = payload } };
        }

        return fail(allocator, .invalid_params, "dogfood harness supports only file_read, file_write, and file_list");
    }
};

const Args = struct {
    repo_key: []const u8 = "DeanoC/Spiderweb",
    pr_number: u64 = 115,
    review_command: []const u8 = "zig build test",
    checkout_path: ?[]u8 = null,
    repo_key_owned: bool = false,
    review_command_owned: bool = false,

    fn deinit(self: *Args, allocator: std.mem.Allocator) void {
        if (self.repo_key_owned) allocator.free(self.repo_key);
        if (self.review_command_owned) allocator.free(self.review_command);
        if (self.checkout_path) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try parseArgs(allocator);
    defer args.deinit(allocator);

    var config = try Config.init(allocator, null);
    defer config.deinit();

    const repo_root = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(repo_root);

    const dogfood_root = try std.fmt.allocPrint(allocator, "{s}/zig-out/dogfood/pr-{d}", .{ repo_root, args.pr_number });
    defer allocator.free(dogfood_root);
    try std.fs.cwd().makePath(dogfood_root);

    const exports_dir = try std.fs.path.join(allocator, &.{ dogfood_root, "exports" });
    defer allocator.free(exports_dir);
    try std.fs.cwd().makePath(exports_dir);

    const checkout_path = if (args.checkout_path) |value|
        value
    else
        try std.fmt.allocPrint(allocator, "/nodes/local/fs/pr-review/checkouts/pr-{d}", .{args.pr_number});
    defer if (args.checkout_path == null) allocator.free(checkout_path);
    const checkout_host_path = try hostPathForLocalFsAcheronPath(allocator, exports_dir, checkout_path);
    defer allocator.free(checkout_host_path);
    const checkout_host_parent = std.fs.path.dirname(checkout_host_path) orelse return error.InvalidArgs;
    try std.fs.cwd().makePath(checkout_host_parent);

    var runtime_cfg = try config.runtime.clone(allocator);
    defer runtime_cfg.deinit(allocator);
    runtime_cfg.sandbox_enabled = false;
    allocator.free(runtime_cfg.ltm_directory);
    runtime_cfg.ltm_directory = try std.fs.path.join(allocator, &.{ dogfood_root, "ltm" });
    try std.fs.cwd().makePath(runtime_cfg.ltm_directory);

    var bridge = AcheronBridge{
        .allocator = allocator,
        .cwd = checkout_host_path,
        .session = null,
    };

    const agent_id = config.runtime.default_agent_id;
    const runtime_server = try runtime_server_mod.RuntimeServer.createWithProviderAndToolDispatch(
        allocator,
        agent_id,
        runtime_cfg,
        config.provider,
        &bridge,
        AcheronBridge.dispatch,
    );
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const project_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"name\":\"PR Review Dogfood {s}\",\"vision\":\"Dogfood the Spider Monkey PR review workflow for {s}\",\"template_id\":\"github\"}}",
        .{ args.repo_key, args.repo_key },
    );
    defer allocator.free(project_payload);
    const project_json = try control_plane.createProject(project_payload);
    defer allocator.free(project_json);

    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project_parsed.deinit();
    const project_id_value = project_parsed.value.object.get("project_id") orelse return error.InvalidPayload;
    if (project_id_value != .string) return error.InvalidPayload;
    const project_id = project_id_value.string;
    const project_token = blk: {
        const maybe_token = project_parsed.value.object.get("project_token") orelse break :blk null;
        if (maybe_token != .string) return error.InvalidPayload;
        break :blk maybe_token.string;
    };

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        agent_id,
        .{
            .mission_store = &mission_store,
            .control_plane = &control_plane,
            .local_fs_export_root = exports_dir,
            .actor_type = "agent",
            .actor_id = agent_id,
            .project_id = project_id,
            .project_token = project_token,
            .agents_dir = runtime_cfg.agents_dir,
            .assets_dir = runtime_cfg.assets_dir,
            .projects_dir = "projects",
        },
    );
    defer session.deinit();
    bridge.session = &session;

    try stdoutPrint("Loaded Spiderweb config provider {s}/{s}\n", .{
        config.provider.name,
        config.provider.model orelse "default",
    });
    try stdoutPrint("Using workspace: {s}\n", .{project_id});
    try stdoutPrint("Using checkout path: {s}\n", .{checkout_path});
    try stdoutPrint("Checkout host path: {s}\n", .{checkout_host_path});
    try stdoutPrint("Using export root: {s}\n\n", .{exports_dir});

    const configure_payload = try buildConfigureRepoPayload(allocator, args.repo_key, checkout_path, args.review_command);
    defer allocator.free(configure_payload);
    const configure_result = try invokeControl(&session, "/services/pr_review/control/configure_repo.json", configure_payload);
    defer allocator.free(configure_result);
    try stdoutPrint("Configured repo:\n{s}\n\n", .{configure_result});

    const ingest_payload = try buildIngestEventPayload(allocator, args.repo_key, args.pr_number);
    defer allocator.free(ingest_payload);
    const ingest_result = try invokeControl(&session, "/services/github_pr/control/ingest_event.json", ingest_payload);
    defer allocator.free(ingest_result);
    try stdoutPrint("Ingested PR event:\n{s}\n\n", .{ingest_result});

    const mission_id = try extractMissionId(allocator, ingest_result);
    defer allocator.free(mission_id);
    try stdoutPrint("Mission: {s}\n\n", .{mission_id});

    const advance_payload = try buildAdvancePayload(allocator, mission_id);
    defer allocator.free(advance_payload);
    const advance_result = try invokeControl(&session, "/services/pr_review/control/advance.json", advance_payload);
    defer allocator.free(advance_result);
    try stdoutPrint("Advance result:\n{s}\n\n", .{advance_result});

    const runner_status = try extractRunnerStatus(allocator, advance_result);
    defer allocator.free(runner_status);
    if (!std.mem.eql(u8, runner_status, "ready_for_review")) {
        try stdoutPrint("Runner stopped at status `{s}`; not attempting draft handoff.\n", .{runner_status});
        std.process.exit(1);
    }

    const draft_payload = try std.fmt.allocPrint(allocator, "{{\"mission_id\":\"{s}\"}}", .{mission_id});
    defer allocator.free(draft_payload);
    const draft_result = try invokeControl(&session, "/services/pr_review/control/draft_review.json", draft_payload);
    defer allocator.free(draft_result);
    try stdoutPrint("Draft result:\n{s}\n\n", .{draft_result});

    const record_review_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"publish_review\":{{\"dry_run\":true}}}}",
        .{mission_id},
    );
    defer allocator.free(record_review_payload);
    const record_review_result = try invokeControl(&session, "/services/pr_review/control/record_review.json", record_review_payload);
    defer allocator.free(record_review_result);
    try stdoutPrint("Record review result:\n{s}\n\n", .{record_review_result});

    const slug = try buildRepoSlug(allocator, args.repo_key);
    defer allocator.free(slug);
    const pr_dir_name = try std.fmt.allocPrint(allocator, "pr-{d}", .{args.pr_number});
    defer allocator.free(pr_dir_name);

    const draft_host_path = try std.fs.path.join(allocator, &.{
        exports_dir,
        "pr-review",
        "runs",
        slug,
        pr_dir_name,
        "draft-review.json",
    });
    defer allocator.free(draft_host_path);

    const review_comment_host_path = try std.fs.path.join(allocator, &.{
        exports_dir,
        "pr-review",
        "runs",
        slug,
        pr_dir_name,
        "review-comment-draft.md",
    });
    defer allocator.free(review_comment_host_path);
    const recommendation_host_path = try std.fs.path.join(allocator, &.{
        exports_dir,
        "pr-review",
        "runs",
        slug,
        pr_dir_name,
        "recommendation.json",
    });
    defer allocator.free(recommendation_host_path);
    const final_review_comment_host_path = try std.fs.path.join(allocator, &.{
        exports_dir,
        "pr-review",
        "runs",
        slug,
        pr_dir_name,
        "review-comment.md",
    });
    defer allocator.free(final_review_comment_host_path);
    const publish_review_host_path = try std.fs.path.join(allocator, &.{
        exports_dir,
        "pr-review",
        "runs",
        slug,
        pr_dir_name,
        "services",
        "publish-review.json",
    });
    defer allocator.free(publish_review_host_path);

    if (std.fs.cwd().access(draft_host_path, .{})) |_| {
        const draft_content = try std.fs.cwd().readFileAlloc(allocator, draft_host_path, 256 * 1024);
        defer allocator.free(draft_content);
        try stdoutPrint("Draft artifact ({s}):\n{s}\n\n", .{ draft_host_path, draft_content });
    } else |_| {
        try stdoutPrint("Draft artifact not found at {s}\n\n", .{draft_host_path});
    }

    if (std.fs.cwd().access(review_comment_host_path, .{})) |_| {
        const review_comment = try std.fs.cwd().readFileAlloc(allocator, review_comment_host_path, 64 * 1024);
        defer allocator.free(review_comment);
        try stdoutPrint("Review comment draft ({s}):\n{s}\n", .{ review_comment_host_path, review_comment });
    } else |_| {
        try stdoutPrint("Review comment draft not found at {s}\n", .{review_comment_host_path});
    }

    if (std.fs.cwd().access(recommendation_host_path, .{})) |_| {
        const recommendation = try std.fs.cwd().readFileAlloc(allocator, recommendation_host_path, 64 * 1024);
        defer allocator.free(recommendation);
        try stdoutPrint("\nRecommendation artifact ({s}):\n{s}\n", .{ recommendation_host_path, recommendation });
    } else |_| {
        try stdoutPrint("\nRecommendation artifact not found at {s}\n", .{recommendation_host_path});
    }

    if (std.fs.cwd().access(final_review_comment_host_path, .{})) |_| {
        const final_review_comment = try std.fs.cwd().readFileAlloc(allocator, final_review_comment_host_path, 64 * 1024);
        defer allocator.free(final_review_comment);
        try stdoutPrint("\nFinal review comment ({s}):\n{s}\n", .{ final_review_comment_host_path, final_review_comment });
    } else |_| {
        try stdoutPrint("\nFinal review comment not found at {s}\n", .{final_review_comment_host_path});
    }

    if (std.fs.cwd().access(publish_review_host_path, .{})) |_| {
        const publish_review = try std.fs.cwd().readFileAlloc(allocator, publish_review_host_path, 64 * 1024);
        defer allocator.free(publish_review);
        try stdoutPrint("\nPublish review artifact ({s}):\n{s}\n", .{ publish_review_host_path, publish_review });
    } else |_| {
        try stdoutPrint("\nPublish review artifact not found at {s}\n", .{publish_review_host_path});
    }
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    var result = Args{};
    errdefer result.deinit(allocator);
    var iter = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();
    _ = iter.next();
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--repo")) {
            const value = iter.next() orelse return error.InvalidArgs;
            if (result.repo_key_owned) allocator.free(result.repo_key);
            result.repo_key = try allocator.dupe(u8, value);
            result.repo_key_owned = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--pr")) {
            const value = iter.next() orelse return error.InvalidArgs;
            result.pr_number = try std.fmt.parseInt(u64, value, 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--command")) {
            const value = iter.next() orelse return error.InvalidArgs;
            if (result.review_command_owned) allocator.free(result.review_command);
            result.review_command = try allocator.dupe(u8, value);
            result.review_command_owned = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--checkout")) {
            const value = iter.next() orelse return error.InvalidArgs;
            if (result.checkout_path) |existing| allocator.free(existing);
            result.checkout_path = try allocator.dupe(u8, value);
            continue;
        }
        return error.InvalidArgs;
    }
    return result;
}

fn invokeControl(session: *Session, control_path: []const u8, payload: []const u8) ![]u8 {
    const maybe_err = try session.writeInternalPath(control_path, payload);
    if (maybe_err) |err_info| {
        defer {
            var owned = err_info;
            owned.deinit(session.allocator);
        }
        try stdoutPrint(
            "Control write failed for {s}: {s} ({s})\n",
            .{ control_path, err_info.message, err_info.code },
        );
        return error.ExecutionFailed;
    }
    const result_path = (try controlResultPath(session.allocator, control_path)) orelse return error.InvalidPayload;
    defer session.allocator.free(result_path);
    return (try session.tryReadInternalPath(result_path)) orelse error.NotFound;
}

fn buildConfigureRepoPayload(
    allocator: std.mem.Allocator,
    repo_key: []const u8,
    checkout_path: []const u8,
    review_command: []const u8,
) ![]u8 {
    const escaped_repo_key = try protocol.jsonEscape(allocator, repo_key);
    defer allocator.free(escaped_repo_key);
    const escaped_checkout = try protocol.jsonEscape(allocator, checkout_path);
    defer allocator.free(escaped_checkout);
    const escaped_command = try protocol.jsonEscape(allocator, review_command);
    defer allocator.free(escaped_command);
    return std.fmt.allocPrint(
        allocator,
        "{{\"repo_key\":\"{s}\",\"default_branch\":\"main\",\"checkout_path\":\"{s}\",\"default_review_commands\":[\"{s}\"],\"auto_intake\":true}}",
        .{ escaped_repo_key, escaped_checkout, escaped_command },
    );
}

fn buildIngestEventPayload(allocator: std.mem.Allocator, repo_key: []const u8, pr_number: u64) ![]u8 {
    const escaped_repo_key = try protocol.jsonEscape(allocator, repo_key);
    defer allocator.free(escaped_repo_key);
    return std.fmt.allocPrint(
        allocator,
        "{{\"repo_key\":\"{s}\",\"pr_number\":{d},\"action\":\"synchronize\"}}",
        .{ escaped_repo_key, pr_number },
    );
}

fn buildAdvancePayload(allocator: std.mem.Allocator, mission_id: []const u8) ![]u8 {
    const escaped_mission = try protocol.jsonEscape(allocator, mission_id);
    defer allocator.free(escaped_mission);
    return std.fmt.allocPrint(allocator, "{{\"mission_id\":\"{s}\",\"wait_timeout_ms\":0}}", .{escaped_mission});
}

fn hostPathForLocalFsAcheronPath(
    allocator: std.mem.Allocator,
    exports_dir: []const u8,
    acheron_path: []const u8,
) ![]u8 {
    const prefix = "/nodes/local/fs";
    if (!std.mem.startsWith(u8, acheron_path, prefix)) return error.InvalidArgs;
    const suffix = std.mem.trimLeft(u8, acheron_path[prefix.len..], "/");
    if (suffix.len == 0) return allocator.dupe(u8, exports_dir);
    return std.fs.path.join(allocator, &.{ exports_dir, suffix });
}

fn extractMissionId(allocator: std.mem.Allocator, result_json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_json, .{});
    defer parsed.deinit();
    const root = parsed.value.object.get("result") orelse return error.InvalidPayload;
    if (root != .object) return error.InvalidPayload;
    const result_obj = if (root.object.get("result")) |value|
        value
    else
        root;
    if (result_obj != .object) return error.InvalidPayload;
    const mission = result_obj.object.get("mission") orelse return error.InvalidPayload;
    if (mission != .object) return error.InvalidPayload;
    const mission_id = mission.object.get("mission_id") orelse return error.InvalidPayload;
    if (mission_id != .string) return error.InvalidPayload;
    return allocator.dupe(u8, mission_id.string);
}

fn extractRunnerStatus(allocator: std.mem.Allocator, result_json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_json, .{});
    defer parsed.deinit();
    const root = parsed.value.object.get("result") orelse return error.InvalidPayload;
    if (root != .object) return error.InvalidPayload;
    const result_obj = if (root.object.get("result")) |value|
        value
    else
        root;
    if (result_obj != .object) return error.InvalidPayload;
    const runner = result_obj.object.get("runner") orelse return error.InvalidPayload;
    if (runner != .object) return error.InvalidPayload;
    const status = runner.object.get("status") orelse return error.InvalidPayload;
    if (status != .string) return error.InvalidPayload;
    return allocator.dupe(u8, status.string);
}

fn buildRepoSlug(allocator: std.mem.Allocator, repo_key: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    for (repo_key) |char| {
        if (char == '/') {
            try out.appendSlice(allocator, "__");
        } else {
            try out.append(allocator, char);
        }
    }
    return out.toOwnedSlice(allocator);
}

fn requiredString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    return if (value == .string) value.string else null;
}

fn optionalBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const value = obj.get(key) orelse return null;
    return if (value == .bool) value.bool else null;
}

fn optionalUsize(obj: std.json.ObjectMap, key: []const u8) ?usize {
    const value = obj.get(key) orelse return null;
    return if (value == .integer and value.integer >= 0) @intCast(value.integer) else null;
}

fn isAcheronPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/services") or std.mem.startsWith(u8, path, "/services/") or
        std.mem.eql(u8, path, "/nodes") or std.mem.startsWith(u8, path, "/nodes/") or
        std.mem.eql(u8, path, "/global") or std.mem.startsWith(u8, path, "/global/") or
        std.mem.eql(u8, path, "/agents") or std.mem.startsWith(u8, path, "/agents/") or
        std.mem.eql(u8, path, "/meta") or std.mem.startsWith(u8, path, "/meta/") or
        std.mem.eql(u8, path, "/projects") or std.mem.startsWith(u8, path, "/projects/");
}

fn normalizePath(allocator: std.mem.Allocator, cwd: []const u8, raw_path: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw_path, " \t\r\n");
    if (trimmed.len == 0) return allocator.dupe(u8, "/");
    if (std.fs.path.isAbsolute(trimmed)) return allocator.dupe(u8, trimmed);
    if (std.mem.startsWith(u8, trimmed, "./")) return std.fs.path.join(allocator, &.{ cwd, trimmed[2..] });
    if (isAcheronPathWithOptionalSlash(trimmed)) return std.fmt.allocPrint(allocator, "/{s}", .{std.mem.trimLeft(u8, trimmed, "/")});
    return std.fs.path.join(allocator, &.{ cwd, trimmed });
}

fn isAcheronPathWithOptionalSlash(path: []const u8) bool {
    const normalized = std.mem.trimLeft(u8, path, "/");
    return std.mem.eql(u8, normalized, "services") or std.mem.startsWith(u8, normalized, "services/") or
        std.mem.eql(u8, normalized, "nodes") or std.mem.startsWith(u8, normalized, "nodes/") or
        std.mem.eql(u8, normalized, "global") or std.mem.startsWith(u8, normalized, "global/") or
        std.mem.eql(u8, normalized, "agents") or std.mem.startsWith(u8, normalized, "agents/") or
        std.mem.eql(u8, normalized, "meta") or std.mem.startsWith(u8, normalized, "meta/") or
        std.mem.eql(u8, normalized, "projects") or std.mem.startsWith(u8, normalized, "projects/");
}

fn trimLeadingSlash(path: []const u8) []const u8 {
    return std.mem.trimLeft(u8, path, "/");
}

fn controlResultPath(allocator: std.mem.Allocator, control_path: []const u8) !?[]u8 {
    const control_index = std.mem.indexOf(u8, control_path, "/control/") orelse return null;
    const value = try std.fmt.allocPrint(allocator, "{s}/result.json", .{control_path[0..control_index]});
    return value;
}

fn buildFileWritePayload(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes_written: usize,
    operation_result_json: ?[]const u8,
) ![]u8 {
    const escaped_path = try protocol.jsonEscape(allocator, path);
    defer allocator.free(escaped_path);
    if (operation_result_json) |value| {
        return std.fmt.allocPrint(
            allocator,
            "{{\"path\":\"{s}\",\"bytes_written\":{d},\"append\":false,\"ready\":true,\"wait_until_ready\":true,\"operation_result\":{s}}}",
            .{ escaped_path, bytes_written, value },
        );
    }
    return std.fmt.allocPrint(
        allocator,
        "{{\"path\":\"{s}\",\"bytes_written\":{d},\"append\":false,\"ready\":true,\"wait_until_ready\":true}}",
        .{ escaped_path, bytes_written },
    );
}

fn buildFileReadPayload(allocator: std.mem.Allocator, path: []const u8, content: []const u8) ![]u8 {
    const escaped_path = try protocol.jsonEscape(allocator, path);
    defer allocator.free(escaped_path);
    const escaped_content = try protocol.jsonEscape(allocator, content);
    defer allocator.free(escaped_content);
    return std.fmt.allocPrint(
        allocator,
        "{{\"path\":\"{s}\",\"bytes\":{d},\"truncated\":false,\"content\":\"{s}\",\"ready\":true,\"wait_until_ready\":true}}",
        .{ escaped_path, content.len, escaped_content },
    );
}

fn buildAcheronFileListPayload(
    allocator: std.mem.Allocator,
    path: []const u8,
    listing_content: []const u8,
    max_entries: usize,
) ![]u8 {
    const escaped_path = try protocol.jsonEscape(allocator, path);
    defer allocator.free(escaped_path);
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    try out.writer(allocator).print("{{\"path\":\"{s}\",\"entries\":[", .{escaped_path});
    var first = true;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, listing_content, '\n');
    var truncated = false;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        const escaped_name = try protocol.jsonEscape(allocator, trimmed);
        defer allocator.free(escaped_name);
        if (!first) try out.append(allocator, ',');
        first = false;
        count += 1;
        try out.writer(allocator).print("{{\"name\":\"{s}\",\"type\":\"unknown\"}}", .{escaped_name});
    }
    try out.writer(allocator).print("],\"truncated\":{s}}}", .{if (truncated) "true" else "false"});
    return out.toOwnedSlice(allocator);
}

fn buildHostFileListPayload(
    allocator: std.mem.Allocator,
    absolute_path: []const u8,
    recursive: bool,
    max_entries: usize,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    const escaped_path = try protocol.jsonEscape(allocator, absolute_path);
    defer allocator.free(escaped_path);
    try out.writer(allocator).print("{{\"path\":\"{s}\",\"entries\":[", .{escaped_path});
    var first = true;
    var count: usize = 0;
    var truncated = false;

    if (recursive) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        var dir = try std.fs.openDirAbsolute(absolute_path, .{ .iterate = true });
        defer dir.close();
        var walker = try dir.walk(arena.allocator());
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (count >= max_entries) {
                truncated = true;
                break;
            }
            const escaped_name = try protocol.jsonEscape(allocator, entry.path);
            defer allocator.free(escaped_name);
            if (!first) try out.append(allocator, ',');
            first = false;
            count += 1;
            try out.writer(allocator).print(
                "{{\"name\":\"{s}\",\"type\":\"{s}\"}}",
                .{ escaped_name, entryTypeName(entry.kind) },
            );
        }
    } else {
        var dir = try std.fs.openDirAbsolute(absolute_path, .{ .iterate = true });
        defer dir.close();
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (count >= max_entries) {
                truncated = true;
                break;
            }
            const escaped_name = try protocol.jsonEscape(allocator, entry.name);
            defer allocator.free(escaped_name);
            if (!first) try out.append(allocator, ',');
            first = false;
            count += 1;
            try out.writer(allocator).print(
                "{{\"name\":\"{s}\",\"type\":\"{s}\"}}",
                .{ escaped_name, entryTypeName(entry.kind) },
            );
        }
    }

    try out.writer(allocator).print("],\"truncated\":{s}}}", .{if (truncated) "true" else "false"});
    return out.toOwnedSlice(allocator);
}

fn entryTypeName(kind: std.fs.Dir.Entry.Kind) []const u8 {
    return switch (kind) {
        .directory => "dir",
        .file => "file",
        .sym_link => "symlink",
        else => "other",
    };
}

fn readHostFile(allocator: std.mem.Allocator, absolute_path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, absolute_path, 8 * 1024 * 1024);
}

fn fail(
    allocator: std.mem.Allocator,
    code: tool_registry.ToolErrorCode,
    message: []const u8,
) tool_registry.ToolExecutionResult {
    return .{ .failure = .{
        .code = code,
        .message = allocator.dupe(u8, message) catch @panic("out of memory"),
    } };
}

fn failOwned(
    allocator: std.mem.Allocator,
    code: tool_registry.ToolErrorCode,
    message: []u8,
) tool_registry.ToolExecutionResult {
    _ = allocator;
    return .{ .failure = .{ .code = code, .message = message } };
}

fn stdoutPrint(comptime fmt: []const u8, args: anytype) !void {
    var buf: [512 * 1024]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try std.fs.File.stdout().writeAll(msg);
}
