const std = @import("std");
const unified = @import("spider-protocol").unified;
const shared_node = @import("spiderweb_node");

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
    try self.job_index.setRequestText(job_name, input);
    const request_json = try buildChatJobRequestJson(self, job_name, input, correlation_id);
    defer self.allocator.free(request_json);
    _ = try self.addFile(job_dir, "request.json", request_json, false, .none);
    const queued_status = try self.buildJobStatusJson(.queued, correlation_id, null);
    defer self.allocator.free(queued_status);
    const status_id = try self.addFile(job_dir, "status.json", queued_status, true, .job_status);
    const result_id = try self.addFile(job_dir, "result.txt", "", true, .job_result);
    _ = try self.addFile(job_dir, "log.txt", "queued for external worker\n", true, .job_log);
    try self.ensureAliasedSubtree(job_dir);
    _ = status_id;
    _ = result_id;
    try self.job_index.updateArtifacts(job_name, "", null, "queued for external worker\n");

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

fn buildChatJobRequestJson(self: anytype, job_name: []const u8, input: []const u8, correlation_id: ?[]const u8) ![]u8 {
    const escaped_job = try unified.jsonEscape(self.allocator, job_name);
    defer self.allocator.free(escaped_job);
    const escaped_agent = try unified.jsonEscape(self.allocator, self.agent_id);
    defer self.allocator.free(escaped_agent);
    const escaped_actor_type = try unified.jsonEscape(self.allocator, self.actor_type);
    defer self.allocator.free(escaped_actor_type);
    const escaped_actor_id = try unified.jsonEscape(self.allocator, self.actor_id);
    defer self.allocator.free(escaped_actor_id);
    const escaped_input = try unified.jsonEscape(self.allocator, input);
    defer self.allocator.free(escaped_input);

    const correlation_json = if (correlation_id) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(correlation_json);

    const project_json = if (self.active_namespace_project_id orelse self.project_id) |value| blk: {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    } else try self.allocator.dupe(u8, "null");
    defer self.allocator.free(project_json);

    return std.fmt.allocPrint(
        self.allocator,
        "{{\"job_id\":\"{s}\",\"agent_id\":\"{s}\",\"actor_type\":\"{s}\",\"actor_id\":\"{s}\",\"project_id\":{s},\"correlation_id\":{s},\"input\":\"{s}\",\"created_at_ms\":{d}}}",
        .{
            escaped_job,
            escaped_agent,
            escaped_actor_type,
            escaped_actor_id,
            project_json,
            correlation_json,
            escaped_input,
            std.time.milliTimestamp(),
        },
    );
}
