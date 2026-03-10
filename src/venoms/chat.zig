const std = @import("std");
const unified = @import("spider-protocol").unified;
const shared_node = @import("spiderweb_node");
const chat_runtime_job = @import("../agents/chat_runtime_job.zig");

pub const WriteResult = struct {
    written: usize,
    job_name: ?[]u8 = null,
    correlation_id: ?[]u8 = null,
    chat_reply_content: ?[]u8 = null,
};

pub fn seedNamespaceAt(self: anytype, chat_dir: u32, base_path: []const u8, jobs_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"chat\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,STATUS.json,meta.json,control/*,examples/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        chat_dir,
        "Chat",
        shape_json,
        "{\"invoke\":true,\"discoverable\":true,\"job_queue\":true}",
        "Chat submit/reply namespace. Write prompts to control/input and read queued job outputs from the jobs venom.",
    );

    const control = try self.addDir(chat_dir, "control", false);
    const examples = try self.addDir(chat_dir, "examples", false);
    self.chat_input_id = try self.addFile(control, "input", "", true, .chat_input);
    _ = try self.addFile(control, "reply", "", true, .chat_reply);
    _ = try self.addFile(examples, "send.txt", shared_node.venom_contracts.chat.example_send_txt, false, .none);

    const chat_schema_json = try shared_node.venom_contracts.chat.renderSchemaJson(self.allocator, jobs_path, "control/reply");
    defer self.allocator.free(chat_schema_json);
    const chat_ops_json = try shared_node.venom_contracts.chat.renderOpsJson(self.allocator, "control/input", jobs_path, "control/reply");
    defer self.allocator.free(chat_ops_json);
    const chat_status_json = try shared_node.venom_contracts.chat.renderStatusJson(self.allocator, base_path, jobs_path);
    defer self.allocator.free(chat_status_json);
    _ = try self.addFile(chat_dir, "README.md", shared_node.venom_contracts.chat.readme_md, false, .none);
    _ = try self.addFile(chat_dir, "SCHEMA.json", chat_schema_json, false, .none);
    _ = try self.addFile(chat_dir, "CAPS.json", shared_node.venom_contracts.chat.caps_json, false, .none);
    _ = try self.addFile(chat_dir, "OPS.json", chat_ops_json, false, .none);
    _ = try self.addFile(chat_dir, "STATUS.json", chat_status_json, false, .none);

    const chat_meta_json = try shared_node.venom_contracts.chat.renderMetaJson(self.allocator, .{
        .agent_id = self.agent_id,
        .actor_type = self.actor_type,
        .actor_id = self.actor_id,
        .project_id = self.active_namespace_project_id orelse self.project_id orelse "",
    });
    defer self.allocator.free(chat_meta_json);
    _ = try self.addFile(chat_dir, "meta.json", chat_meta_json, false, .none);
}

pub fn handleInputWrite(self: anytype, msg: *const unified.ParsedMessage, raw_input: []const u8) !WriteResult {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) {
        return .{ .written = 0, .job_name = null, .correlation_id = null };
    }

    const correlation_id = msg.correlation_id orelse msg.id;
    const job_name = try self.job_index.createJob(self.agent_id, correlation_id);
    defer self.allocator.free(job_name);

    const job_dir = try self.addDir(self.jobs_root_id, job_name, false);
    const queued_status = try self.buildJobStatusJson(.queued, correlation_id, null);
    defer self.allocator.free(queued_status);
    const status_id = try self.addFile(job_dir, "status.json", queued_status, true, .job_status);
    const result_id = try self.addFile(job_dir, "result.txt", "", true, .job_result);
    const log_id = try self.addFile(job_dir, "log.txt", "", true, .job_log);
    try self.ensureAliasedSubtree(job_dir);

    try self.job_index.markRunning(job_name);
    const running_status = try self.buildJobStatusJson(.running, correlation_id, null);
    defer self.allocator.free(running_status);
    try self.setFileContent(status_id, running_status);

    self.spawnAsyncChatRuntimeJob(job_name, input, correlation_id) catch |spawn_err| {
        const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("runtime_error", @errorName(spawn_err));
        const failed_status = try self.buildJobStatusJson(.failed, correlation_id, normalized.message);
        defer self.allocator.free(failed_status);

        self.setFileContent(status_id, failed_status) catch |err| {
            std.log.warn("failed to update chat status after spawn failure: {s}", .{@errorName(err)});
        };
        self.setFileContent(result_id, normalized.message) catch |err| {
            std.log.warn("failed to update chat result after spawn failure: {s}", .{@errorName(err)});
        };

        const spawn_log_owned = std.fmt.allocPrint(
            self.allocator,
            "[runtime worker spawn failure] {s}\n",
            .{@errorName(spawn_err)},
        ) catch null;
        defer if (spawn_log_owned) |value| self.allocator.free(value);
        const spawn_log = if (spawn_log_owned) |value|
            value
        else
            "[runtime worker spawn failure]\n";

        self.setFileContent(log_id, spawn_log) catch |err| {
            std.log.warn("failed to update chat log after spawn failure: {s}", .{@errorName(err)});
        };
        self.job_index.markCompleted(
            job_name,
            false,
            normalized.message,
            normalized.message,
            spawn_log,
        ) catch |err| {
            std.log.warn("chat job index completion update failed after spawn failure: {s}", .{@errorName(err)});
        };
    };

    return .{
        .written = raw_input.len,
        .job_name = try self.allocator.dupe(u8, job_name),
        .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
    };
}

pub fn handleReplyWrite(self: anytype, node_id: u32, raw_input: []const u8) !WriteResult {
    const reply = std.mem.trim(u8, raw_input, " \t\r\n");
    try self.setFileContent(node_id, reply);
    return .{
        .written = raw_input.len,
        .chat_reply_content = try self.allocator.dupe(u8, reply),
    };
}
