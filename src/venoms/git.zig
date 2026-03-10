const std = @import("std");
const unified = @import("spider-protocol").unified;

pub const Op = enum {
    sync_checkout,
    status,
    diff_range,
};

pub const ParsedShellExecResult = struct {
    exit_code: i32,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *ParsedShellExecResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

pub fn seedNamespace(self: anytype, git_dir: u32) !void {
    try self.addDirectoryDescriptors(
        git_dir,
        "Git",
        "{\"kind\":\"venom\",\"venom_id\":\"git\",\"shape\":\"/global/git/{README.md,SCHEMA.json,TEMPLATE.json,CAPS.json,OPS.json,RUNTIME.json,HOST.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
        "{\"invoke\":true,\"operations\":[\"git_sync_checkout\",\"git_status\",\"git_diff_range\"],\"discoverable\":true,\"workspace_fs\":true}",
        "Repository checkout and diff helpers backed by the runtime shell_exec tool. Prefer these high-level operations over ad-hoc git shell commands.",
    );
    _ = try self.addFile(
        git_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"sync_checkout\":\"control/sync_checkout.json\",\"status\":\"control/status.json\",\"diff_range\":\"control/diff_range.json\"},\"operations\":{\"sync_checkout\":\"git_sync_checkout\",\"status\":\"git_status\",\"diff_range\":\"git_diff_range\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        git_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"git_repo_service\",\"tool_backend\":\"shell_exec\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        git_dir,
        "HOST.json",
        "{\"runtime_kind\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"git_repo_service\",\"tool_backend\":\"shell_exec\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        git_dir,
        "TEMPLATE.json",
        "{\"op\":\"sync_checkout\",\"arguments\":{\"repo_key\":\"owner/repo\",\"pr_number\":123,\"checkout_path\":\"/nodes/local/fs/pr-review/repos/owner__repo\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        git_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        git_dir,
        "STATUS.json",
        "{\"venom_id\":\"git\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    self.git_status_id = try self.addFile(
        git_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    self.git_result_id = try self.addFile(
        git_dir,
        "result.json",
        "{\"ok\":false,\"operation\":null,\"result\":null,\"error\":null}",
        false,
        .none,
    );

    const control_dir = try self.addDir(git_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Use sync_checkout.json to clone/fetch and align a repo checkout, status.json to inspect repository state, diff_range.json to list changed files, or invoke.json with op plus arguments.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .git_invoke);
    _ = try self.addFile(control_dir, "sync_checkout.json", "", true, .git_sync_checkout);
    _ = try self.addFile(control_dir, "status.json", "", true, .git_status);
    _ = try self.addFile(control_dir, "diff_range.json", "", true, .git_diff_range);
}

pub fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "sync_checkout") or std.mem.eql(u8, value, "git_sync_checkout")) return .sync_checkout;
    if (std.mem.eql(u8, value, "status") or std.mem.eql(u8, value, "git_status")) return .status;
    if (std.mem.eql(u8, value, "diff_range") or std.mem.eql(u8, value, "git_diff_range")) return .diff_range;
    return null;
}

pub fn operationName(op: Op) []const u8 {
    return switch (op) {
        .sync_checkout => "sync_checkout",
        .status => "status",
        .diff_range => "diff_range",
    };
}

pub fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .sync_checkout => "git_sync_checkout",
        .status => "git_status",
        .diff_range => "git_diff_range",
    };
}

pub fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    return switch (op) {
        .sync_checkout => executeSyncCheckoutOp(self, args_obj),
        .status => executeStatusOp(self, args_obj),
        .diff_range => executeDiffRangeOp(self, args_obj),
    };
}

pub fn buildCliCommand(self: anytype, program: []const u8, argv: []const []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    try self.appendShellSingleQuoted(&out, program);
    for (argv) |arg| {
        try out.append(self.allocator, ' ');
        try self.appendShellSingleQuoted(&out, arg);
    }
    return out.toOwnedSlice(self.allocator);
}

pub fn buildShellExecArgsJson(self: anytype, command: []const u8, cwd: ?[]const u8, timeout_ms: u64) ![]u8 {
    const escaped_command = try unified.jsonEscape(self.allocator, command);
    defer self.allocator.free(escaped_command);
    const cwd_json = if (cwd) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(cwd_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"command\":\"{s}\",\"cwd\":{s},\"timeout_ms\":{d}}}",
        .{ escaped_command, cwd_json, timeout_ms },
    );
}

pub fn parseShellExecPayload(self: anytype, payload_json: []const u8) !ParsedShellExecResult {
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;
    const exit_code_value = obj.get("exit_code") orelse return error.InvalidPayload;
    if (exit_code_value != .integer) return error.InvalidPayload;
    const stdout_value = obj.get("stdout") orelse return error.InvalidPayload;
    if (stdout_value != .string) return error.InvalidPayload;
    const stderr_value = obj.get("stderr") orelse return error.InvalidPayload;
    if (stderr_value != .string) return error.InvalidPayload;
    return .{
        .exit_code = @intCast(exit_code_value.integer),
        .stdout = try self.allocator.dupe(u8, stdout_value.string),
        .stderr = try self.allocator.dupe(u8, stderr_value.string),
    };
}

pub fn normalizeJsonText(self: anytype, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPayload;
    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, trimmed, .{});
    defer parsed.deinit();
    return std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(parsed.value, .{})});
}

pub fn buildGitSuccessResultJson(self: anytype, op: Op, result_json: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
        .{ escaped_operation, result_json },
    );
}

pub fn buildGitFailureResultJson(self: anytype, op: Op, code: []const u8, message: []const u8) ![]u8 {
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

fn executeSyncCheckoutOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const checkout_path = try self.normalizeLocalWorkspaceAbsolutePath(
        extractOptionalStringByNames(args_obj, &[_][]const u8{"checkout_path"}) orelse return error.InvalidPayload,
    );
    defer self.allocator.free(checkout_path);

    const provider = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"provider"}) orelse "github", " \t\r\n");
    if (provider.len == 0) return error.InvalidPayload;
    const repo_url = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"repo_url"})) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else if (extractOptionalStringByNames(args_obj, &[_][]const u8{"repo_key"})) |repo_key_raw|
        try buildRepoRemoteUrl(self, provider, repo_key_raw)
    else
        return error.InvalidPayload;
    defer self.allocator.free(repo_url);

    const base_branch = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"base_branch"}) orelse "main", " \t\r\n");
    const head_branch = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"head_branch"}) orelse "", " \t\r\n");
    const head_sha = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"head_sha"}) orelse "", " \t\r\n");
    const timeout_ms = (try jsonObjectOptionalU64(args_obj, "timeout_ms")) orelse 120_000;
    const pr_number = try jsonObjectOptionalU64(args_obj, "pr_number");

    const checkout_host_path = try self.resolveMissionContractHostPath(checkout_path);
    defer self.allocator.free(checkout_host_path);
    const parent = std.fs.path.dirname(checkout_host_path) orelse return error.InvalidPayload;
    try ensurePathExists(parent);

    const git_dir_host = try std.fs.path.join(self.allocator, &.{ checkout_host_path, ".git" });
    defer self.allocator.free(git_dir_host);
    const had_checkout = try pathExistsAsDirectory(git_dir_host);

    if (had_checkout) {
        const dirty_command = try self.buildCliCommand("git", &.{ "-C", checkout_host_path, "status", "--porcelain" });
        defer self.allocator.free(dirty_command);
        var dirty_outcome = try self.runShellExecCommand(dirty_command, null, timeout_ms);
        defer dirty_outcome.deinit(self.allocator);
        switch (dirty_outcome) {
            .failure => |info| return self.buildGitFailureResultJson(.sync_checkout, info.code, info.message),
            .success => |result| {
                if (result.exit_code != 0) {
                    const message = if (std.mem.trim(u8, result.stderr, " \t\r\n").len > 0) result.stderr else "git status failed";
                    return self.buildGitFailureResultJson(.sync_checkout, "execution_failed", message);
                }
                if (std.mem.trim(u8, result.stdout, " \t\r\n").len > 0) {
                    return self.buildGitFailureResultJson(.sync_checkout, "dirty_checkout", "existing checkout has local changes");
                }
            },
        }
    }

    if (!had_checkout) {
        const clone_command = try self.buildCliCommand("git", &.{ "clone", "--no-checkout", repo_url, checkout_host_path });
        defer self.allocator.free(clone_command);
        var clone_outcome = try self.runShellExecCommand(clone_command, null, timeout_ms);
        defer clone_outcome.deinit(self.allocator);
        switch (clone_outcome) {
            .failure => |info| return self.buildGitFailureResultJson(.sync_checkout, info.code, info.message),
            .success => |result| if (result.exit_code != 0) {
                const message = if (std.mem.trim(u8, result.stderr, " \t\r\n").len > 0) result.stderr else "git clone failed";
                return self.buildGitFailureResultJson(.sync_checkout, "execution_failed", message);
            },
        }
    } else {
        const set_url_command = try self.buildCliCommand("git", &.{ "-C", checkout_host_path, "remote", "set-url", "origin", repo_url });
        defer self.allocator.free(set_url_command);
        var set_url_outcome = try self.runShellExecCommand(set_url_command, null, timeout_ms);
        defer set_url_outcome.deinit(self.allocator);
        switch (set_url_outcome) {
            .failure => |info| return self.buildGitFailureResultJson(.sync_checkout, info.code, info.message),
            .success => |result| if (result.exit_code != 0) {
                const message = if (std.mem.trim(u8, result.stderr, " \t\r\n").len > 0) result.stderr else "git remote set-url failed";
                return self.buildGitFailureResultJson(.sync_checkout, "execution_failed", message);
            },
        }
    }

    const fetch_command = if (pr_number) |value|
        try buildGitHubPrFetchCommand(self, checkout_host_path, value)
    else if (head_branch.len > 0) blk: {
        const fetch_head_ref = try std.fmt.allocPrint(self.allocator, "{s}:refs/remotes/origin/{s}", .{ head_branch, head_branch });
        defer self.allocator.free(fetch_head_ref);
        break :blk try self.buildCliCommand("git", &.{ "-C", checkout_host_path, "fetch", "--prune", "origin", fetch_head_ref });
    } else try self.buildCliCommand("git", &.{ "-C", checkout_host_path, "fetch", "--prune", "origin" });
    defer self.allocator.free(fetch_command);
    var fetch_outcome = try self.runShellExecCommand(fetch_command, null, timeout_ms);
    defer fetch_outcome.deinit(self.allocator);
    switch (fetch_outcome) {
        .failure => |info| return self.buildGitFailureResultJson(.sync_checkout, info.code, info.message),
        .success => |result| if (result.exit_code != 0) {
            const message = if (std.mem.trim(u8, result.stderr, " \t\r\n").len > 0) result.stderr else "git fetch failed";
            return self.buildGitFailureResultJson(.sync_checkout, "execution_failed", message);
        },
    }

    if (base_branch.len > 0) {
        const fetch_base_ref = try std.fmt.allocPrint(self.allocator, "{s}:refs/remotes/origin/{s}", .{ base_branch, base_branch });
        defer self.allocator.free(fetch_base_ref);
        const fetch_base_command = try self.buildCliCommand("git", &.{ "-C", checkout_host_path, "fetch", "origin", fetch_base_ref });
        defer self.allocator.free(fetch_base_command);
        var fetch_base_outcome = try self.runShellExecCommand(fetch_base_command, null, timeout_ms);
        defer fetch_base_outcome.deinit(self.allocator);
        switch (fetch_base_outcome) {
            .failure => |info| return self.buildGitFailureResultJson(.sync_checkout, info.code, info.message),
            .success => |result| if (result.exit_code != 0) {
                const message = if (std.mem.trim(u8, result.stderr, " \t\r\n").len > 0) result.stderr else "git fetch base failed";
                return self.buildGitFailureResultJson(.sync_checkout, "execution_failed", message);
            },
        }
    }

    const checkout_target = if (pr_number) |value|
        try std.fmt.allocPrint(self.allocator, "refs/remotes/origin/pr/{d}/head", .{value})
    else if (head_sha.len > 0)
        try self.allocator.dupe(u8, head_sha)
    else if (head_branch.len > 0)
        try std.fmt.allocPrint(self.allocator, "refs/remotes/origin/{s}", .{head_branch})
    else if (base_branch.len > 0)
        try std.fmt.allocPrint(self.allocator, "refs/remotes/origin/{s}", .{base_branch})
    else
        return error.InvalidPayload;
    defer self.allocator.free(checkout_target);

    const checkout_command = try self.buildCliCommand("git", &.{ "-C", checkout_host_path, "checkout", "--force", "--detach", checkout_target });
    defer self.allocator.free(checkout_command);
    var checkout_outcome = try self.runShellExecCommand(checkout_command, null, timeout_ms);
    defer checkout_outcome.deinit(self.allocator);
    switch (checkout_outcome) {
        .failure => |info| return self.buildGitFailureResultJson(.sync_checkout, info.code, info.message),
        .success => |result| if (result.exit_code != 0) {
            const message = if (std.mem.trim(u8, result.stderr, " \t\r\n").len > 0) result.stderr else "git checkout failed";
            return self.buildGitFailureResultJson(.sync_checkout, "execution_failed", message);
        },
    }

    const head_rev = try runGitCaptureStdout(self, checkout_host_path, &.{ "rev-parse", "HEAD" }, timeout_ms);
    defer self.allocator.free(head_rev);
    const head_rev_trimmed = std.mem.trim(u8, head_rev, " \t\r\n");
    const base_rev = if (base_branch.len > 0) blk: {
        const base_ref = try std.fmt.allocPrint(self.allocator, "refs/remotes/origin/{s}", .{base_branch});
        defer self.allocator.free(base_ref);
        break :blk runGitCaptureStdout(self, checkout_host_path, &.{ "rev-parse", base_ref }, timeout_ms) catch try self.allocator.dupe(u8, "");
    } else try self.allocator.dupe(u8, "");
    defer self.allocator.free(base_rev);

    const detail = try buildSyncCheckoutDetailJson(
        self,
        provider,
        repo_url,
        checkout_path,
        had_checkout,
        checkout_target,
        std.mem.trim(u8, head_rev_trimmed, " \t\r\n"),
        std.mem.trim(u8, base_rev, " \t\r\n"),
        base_branch,
        head_branch,
    );
    defer self.allocator.free(detail);
    return self.buildGitSuccessResultJson(.sync_checkout, detail);
}

fn executeStatusOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const checkout_path = try self.normalizeLocalWorkspaceAbsolutePath(
        extractOptionalStringByNames(args_obj, &[_][]const u8{"checkout_path"}) orelse return error.InvalidPayload,
    );
    defer self.allocator.free(checkout_path);
    const timeout_ms = (try jsonObjectOptionalU64(args_obj, "timeout_ms")) orelse 30_000;
    const checkout_host_path = try self.resolveMissionContractHostPath(checkout_path);
    defer self.allocator.free(checkout_host_path);

    const head_sha = try runGitCaptureStdout(self, checkout_host_path, &.{ "rev-parse", "HEAD" }, timeout_ms) catch |err| switch (err) {
        error.InvalidPayload => return error.InvalidPayload,
        else => return self.buildGitFailureResultJson(.status, "execution_failed", @errorName(err)),
    };
    defer self.allocator.free(head_sha);
    const branch_name = try runGitCaptureStdout(self, checkout_host_path, &.{ "rev-parse", "--abbrev-ref", "HEAD" }, timeout_ms) catch |err| switch (err) {
        error.InvalidPayload => return error.InvalidPayload,
        else => return self.buildGitFailureResultJson(.status, "execution_failed", @errorName(err)),
    };
    defer self.allocator.free(branch_name);
    const status_short = try runGitCaptureStdout(self, checkout_host_path, &.{ "status", "--short" }, timeout_ms) catch |err| switch (err) {
        error.InvalidPayload => return error.InvalidPayload,
        else => return self.buildGitFailureResultJson(.status, "execution_failed", @errorName(err)),
    };
    defer self.allocator.free(status_short);

    const base_ref = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"base_ref"})) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else if (extractOptionalStringByNames(args_obj, &[_][]const u8{"base_branch"})) |value|
        try std.fmt.allocPrint(self.allocator, "refs/remotes/origin/{s}", .{std.mem.trim(u8, value, " \t\r\n")})
    else
        null;
    defer if (base_ref) |value| self.allocator.free(value);

    const changed_files_json = if (base_ref) |value|
        try runGitDiffNamesJson(self, checkout_host_path, value, "HEAD", true, timeout_ms)
    else
        try self.allocator.dupe(u8, "[]");
    defer self.allocator.free(changed_files_json);

    const detail = try buildStatusDetailJson(
        self,
        checkout_path,
        std.mem.trim(u8, head_sha, " \t\r\n"),
        std.mem.trim(u8, branch_name, " \t\r\n"),
        std.mem.trim(u8, status_short, " \t\r\n"),
        changed_files_json,
        base_ref,
    );
    defer self.allocator.free(detail);
    return self.buildGitSuccessResultJson(.status, detail);
}

fn executeDiffRangeOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    const checkout_path = try self.normalizeLocalWorkspaceAbsolutePath(
        extractOptionalStringByNames(args_obj, &[_][]const u8{"checkout_path"}) orelse return error.InvalidPayload,
    );
    defer self.allocator.free(checkout_path);
    const checkout_host_path = try self.resolveMissionContractHostPath(checkout_path);
    defer self.allocator.free(checkout_host_path);
    const timeout_ms = (try jsonObjectOptionalU64(args_obj, "timeout_ms")) orelse 30_000;

    const base_ref = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"base_ref"})) |value|
        try self.allocator.dupe(u8, std.mem.trim(u8, value, " \t\r\n"))
    else if (extractOptionalStringByNames(args_obj, &[_][]const u8{"base_branch"})) |value|
        try std.fmt.allocPrint(self.allocator, "refs/remotes/origin/{s}", .{std.mem.trim(u8, value, " \t\r\n")})
    else
        return error.InvalidPayload;
    defer self.allocator.free(base_ref);

    const head_ref = std.mem.trim(u8, extractOptionalStringByNames(args_obj, &[_][]const u8{"head_ref"}) orelse "HEAD", " \t\r\n");
    const symmetric = (try jsonObjectOptionalBool(args_obj, "symmetric")) orelse true;
    const changed_files_json = try runGitDiffNamesJson(self, checkout_host_path, base_ref, head_ref, symmetric, timeout_ms);
    defer self.allocator.free(changed_files_json);
    const diff_stat = try runGitDiffStat(self, checkout_host_path, base_ref, head_ref, symmetric, timeout_ms);
    defer self.allocator.free(diff_stat);

    const detail = try buildDiffRangeDetailJson(
        self,
        checkout_path,
        base_ref,
        head_ref,
        symmetric,
        changed_files_json,
        std.mem.trim(u8, diff_stat, " \t\r\n"),
    );
    defer self.allocator.free(detail);
    return self.buildGitSuccessResultJson(.diff_range, detail);
}

fn buildRepoRemoteUrl(self: anytype, provider: []const u8, repo_key_raw: []const u8) ![]u8 {
    const repo_key = std.mem.trim(u8, repo_key_raw, " \t\r\n");
    if (repo_key.len == 0) return error.InvalidPayload;
    if (std.mem.eql(u8, provider, "github")) {
        return std.fmt.allocPrint(self.allocator, "https://github.com/{s}.git", .{repo_key});
    }
    return error.InvalidPayload;
}

fn buildGitHubPrFetchCommand(self: anytype, checkout_host_path: []const u8, pr_number: u64) ![]u8 {
    const refspec = try std.fmt.allocPrint(
        self.allocator,
        "+refs/pull/{d}/head:refs/remotes/origin/pr/{d}/head",
        .{ pr_number, pr_number },
    );
    defer self.allocator.free(refspec);
    return self.buildCliCommand("git", &.{ "-C", checkout_host_path, "fetch", "--prune", "origin", refspec });
}

fn runGitCaptureStdout(self: anytype, checkout_host_path: []const u8, git_args: []const []const u8, timeout_ms: u64) ![]u8 {
    var argv = std.ArrayListUnmanaged([]const u8){};
    defer argv.deinit(self.allocator);
    try argv.append(self.allocator, "-C");
    try argv.append(self.allocator, checkout_host_path);
    for (git_args) |arg| try argv.append(self.allocator, arg);
    const command = try self.buildCliCommand("git", argv.items);
    defer self.allocator.free(command);
    var outcome = try self.runShellExecCommand(command, null, timeout_ms);
    defer outcome.deinit(self.allocator);
    switch (outcome) {
        .failure => |info| {
            _ = info;
            return error.ExecutionFailed;
        },
        .success => |result| {
            if (result.exit_code != 0) return error.ExecutionFailed;
            return self.allocator.dupe(u8, result.stdout);
        },
    }
}

fn runGitDiffNamesJson(
    self: anytype,
    checkout_host_path: []const u8,
    base_ref: []const u8,
    head_ref: []const u8,
    symmetric: bool,
    timeout_ms: u64,
) ![]u8 {
    const range = if (symmetric)
        try std.fmt.allocPrint(self.allocator, "{s}...{s}", .{ base_ref, head_ref })
    else
        try std.fmt.allocPrint(self.allocator, "{s}..{s}", .{ base_ref, head_ref });
    defer self.allocator.free(range);
    const output = try runGitCaptureStdout(self, checkout_host_path, &.{ "diff", "--name-only", range }, timeout_ms);
    defer self.allocator.free(output);
    return renderJsonStringArrayFromLines(self.allocator, output);
}

fn runGitDiffStat(
    self: anytype,
    checkout_host_path: []const u8,
    base_ref: []const u8,
    head_ref: []const u8,
    symmetric: bool,
    timeout_ms: u64,
) ![]u8 {
    const range = if (symmetric)
        try std.fmt.allocPrint(self.allocator, "{s}...{s}", .{ base_ref, head_ref })
    else
        try std.fmt.allocPrint(self.allocator, "{s}..{s}", .{ base_ref, head_ref });
    defer self.allocator.free(range);
    return runGitCaptureStdout(self, checkout_host_path, &.{ "diff", "--stat", range }, timeout_ms);
}

fn buildSyncCheckoutDetailJson(
    self: anytype,
    provider: []const u8,
    repo_url: []const u8,
    checkout_path: []const u8,
    reused_checkout: bool,
    target_ref: []const u8,
    head_sha: []const u8,
    base_sha: []const u8,
    base_branch: []const u8,
    head_branch: []const u8,
) ![]u8 {
    const escaped_provider = try unified.jsonEscape(self.allocator, provider);
    defer self.allocator.free(escaped_provider);
    const escaped_repo_url = try unified.jsonEscape(self.allocator, repo_url);
    defer self.allocator.free(escaped_repo_url);
    const escaped_checkout_path = try unified.jsonEscape(self.allocator, checkout_path);
    defer self.allocator.free(escaped_checkout_path);
    const escaped_target_ref = try unified.jsonEscape(self.allocator, target_ref);
    defer self.allocator.free(escaped_target_ref);
    const escaped_head_sha = try unified.jsonEscape(self.allocator, head_sha);
    defer self.allocator.free(escaped_head_sha);
    const escaped_base_sha = try unified.jsonEscape(self.allocator, base_sha);
    defer self.allocator.free(escaped_base_sha);
    const escaped_base_branch = try unified.jsonEscape(self.allocator, base_branch);
    defer self.allocator.free(escaped_base_branch);
    const escaped_head_branch = try unified.jsonEscape(self.allocator, head_branch);
    defer self.allocator.free(escaped_head_branch);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"provider\":\"{s}\",\"repo_url\":\"{s}\",\"checkout_path\":\"{s}\",\"reused_checkout\":{s},\"target_ref\":\"{s}\",\"head_sha\":\"{s}\",\"base_sha\":\"{s}\",\"base_branch\":\"{s}\",\"head_branch\":\"{s}\"}}",
        .{
            escaped_provider,
            escaped_repo_url,
            escaped_checkout_path,
            if (reused_checkout) "true" else "false",
            escaped_target_ref,
            escaped_head_sha,
            escaped_base_sha,
            escaped_base_branch,
            escaped_head_branch,
        },
    );
}

fn buildStatusDetailJson(
    self: anytype,
    checkout_path: []const u8,
    head_sha: []const u8,
    branch_name: []const u8,
    status_short: []const u8,
    changed_files_json: []const u8,
    base_ref: ?[]const u8,
) ![]u8 {
    const escaped_checkout_path = try unified.jsonEscape(self.allocator, checkout_path);
    defer self.allocator.free(escaped_checkout_path);
    const escaped_head_sha = try unified.jsonEscape(self.allocator, head_sha);
    defer self.allocator.free(escaped_head_sha);
    const escaped_branch_name = try unified.jsonEscape(self.allocator, branch_name);
    defer self.allocator.free(escaped_branch_name);
    const escaped_status_short = try unified.jsonEscape(self.allocator, status_short);
    defer self.allocator.free(escaped_status_short);
    const base_ref_json = if (base_ref) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(base_ref_json);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"checkout_path\":\"{s}\",\"head_sha\":\"{s}\",\"branch\":\"{s}\",\"dirty\":{s},\"status_short\":\"{s}\",\"base_ref\":{s},\"changed_files\":{s}}}",
        .{
            escaped_checkout_path,
            escaped_head_sha,
            escaped_branch_name,
            if (status_short.len > 0) "true" else "false",
            escaped_status_short,
            base_ref_json,
            changed_files_json,
        },
    );
}

fn buildDiffRangeDetailJson(
    self: anytype,
    checkout_path: []const u8,
    base_ref: []const u8,
    head_ref: []const u8,
    symmetric: bool,
    changed_files_json: []const u8,
    diff_stat: []const u8,
) ![]u8 {
    const escaped_checkout_path = try unified.jsonEscape(self.allocator, checkout_path);
    defer self.allocator.free(escaped_checkout_path);
    const escaped_base_ref = try unified.jsonEscape(self.allocator, base_ref);
    defer self.allocator.free(escaped_base_ref);
    const escaped_head_ref = try unified.jsonEscape(self.allocator, head_ref);
    defer self.allocator.free(escaped_head_ref);
    const escaped_diff_stat = try unified.jsonEscape(self.allocator, diff_stat);
    defer self.allocator.free(escaped_diff_stat);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"checkout_path\":\"{s}\",\"base_ref\":\"{s}\",\"head_ref\":\"{s}\",\"symmetric\":{s},\"changed_files\":{s},\"diff_stat\":\"{s}\"}}",
        .{
            escaped_checkout_path,
            escaped_base_ref,
            escaped_head_ref,
            if (symmetric) "true" else "false",
            changed_files_json,
            escaped_diff_stat,
        },
    );
}

fn extractOptionalStringByNames(obj: std.json.ObjectMap, candidate_names: []const []const u8) ?[]const u8 {
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

fn renderJsonStringArrayFromLines(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);
    try writer.writeByte('[');
    var first = true;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try writeJsonString(writer, trimmed);
    }
    try writer.writeByte(']');
    return out.toOwnedSlice(allocator);
}

fn jsonObjectOptionalBool(obj: std.json.ObjectMap, key: []const u8) !?bool {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .bool => value.bool,
        .null => null,
        else => error.InvalidPayload,
    };
}

fn jsonObjectOptionalU64(obj: std.json.ObjectMap, key: []const u8) !?u64 {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .integer => if (value.integer < 0) error.InvalidPayload else @intCast(value.integer),
        .null => null,
        else => error.InvalidPayload,
    };
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

fn ensurePathExists(path: []const u8) !void {
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
