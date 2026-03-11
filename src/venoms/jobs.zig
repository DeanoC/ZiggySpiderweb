const std = @import("std");
const chat_job_index = @import("../agents/chat_job_index.zig");
const shared_node = @import("spiderweb_node");
const unified = @import("spider-protocol").unified;

pub fn seedNamespaceAt(self: anytype, jobs_dir: u32, base_path: []const u8) !void {
    self.jobs_root_id = jobs_dir;
    try self.addDirectoryDescriptors(
        jobs_dir,
        "Jobs",
        "{\"kind\":\"collection\",\"entries\":\"job_id\",\"files\":[\"request.json\",\"status.json\",\"result.txt\",\"log.txt\"]}",
        "{\"read\":true,\"write\":false}",
        "Chat job requests, status, and outputs.",
    );
    const jobs_schema_json = try shared_node.venom_contracts.jobs.renderSchemaJson(self.allocator, base_path);
    defer self.allocator.free(jobs_schema_json);
    const jobs_status_json = try shared_node.venom_contracts.jobs.renderStatusJson(self.allocator, base_path);
    defer self.allocator.free(jobs_status_json);
    _ = try self.addFile(jobs_dir, "README.md", shared_node.venom_contracts.jobs.readme_md, false, .none);
    _ = try self.addFile(jobs_dir, "SCHEMA.json", jobs_schema_json, false, .none);
    _ = try self.addFile(jobs_dir, "CAPS.json", shared_node.venom_contracts.jobs.caps_json, false, .none);
    _ = try self.addFile(jobs_dir, "OPS.json", shared_node.venom_contracts.jobs.ops_json, false, .none);
    _ = try self.addFile(jobs_dir, "STATUS.json", jobs_status_json, false, .none);
}

pub fn seedFromIndex(self: anytype) !void {
    const jobs = try self.job_index.listJobsForAgent(self.allocator, self.agent_id);
    defer chat_job_index.deinitJobViews(self.allocator, jobs);

    for (jobs) |job| {
        if (self.lookupChild(self.jobs_root_id, job.job_id) != null) continue;
        const job_dir = try self.addDir(self.jobs_root_id, job.job_id, false);
        const request_json = try buildRequestJsonForJobView(self.allocator, job);
        defer self.allocator.free(request_json);
        _ = try self.addFile(job_dir, "request.json", request_json, false, .none);
        const status_json = try self.buildJobStatusJson(job.state, job.correlation_id, job.error_text);
        defer self.allocator.free(status_json);
        _ = try self.addFile(job_dir, "status.json", status_json, true, .job_status);
        _ = try self.addFile(job_dir, "result.txt", job.result_text orelse "", true, .job_result);
        _ = try self.addFile(job_dir, "log.txt", job.log_text orelse "", true, .job_log);
        try self.ensureAliasedSubtree(job_dir);
    }
}

fn buildRequestJsonForJobView(allocator: std.mem.Allocator, job: chat_job_index.JobView) ![]u8 {
    if (job.request_json) |value| return allocator.dupe(u8, value);

    const escaped_job = try unified.jsonEscape(allocator, job.job_id);
    defer allocator.free(escaped_job);
    const escaped_agent = try unified.jsonEscape(allocator, job.agent_id);
    defer allocator.free(escaped_agent);
    const escaped_input = try unified.jsonEscape(allocator, job.request_text orelse "");
    defer allocator.free(escaped_input);

    const correlation_json = if (job.correlation_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(correlation_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"job_id\":\"{s}\",\"agent_id\":\"{s}\",\"actor_type\":null,\"actor_id\":null,\"project_id\":null,\"correlation_id\":{s},\"input\":\"{s}\",\"created_at_ms\":{d}}}",
        .{
            escaped_job,
            escaped_agent,
            correlation_json,
            escaped_input,
            job.created_at_ms,
        },
    );
}

pub fn refreshNodeFromIndex(self: anytype, node_id: u32, special: anytype) !void {
    const node = self.nodes.get(node_id) orelse return error.MissingNode;
    const job_dir_id = node.parent orelse return;
    const job_dir = self.nodes.get(job_dir_id) orelse return error.MissingNode;
    const job_id = job_dir.name;
    const owned_view = try self.job_index.getJob(self.allocator, job_id);
    if (owned_view == null) return;

    var view = owned_view.?;
    defer view.deinit(self.allocator);
    if (!std.mem.eql(u8, view.agent_id, self.agent_id)) return;
    try self.syncThoughtFramesFromJobTelemetry(job_id);

    switch (special) {
        .job_status => {
            const status_json = try self.buildJobStatusJson(view.state, view.correlation_id, view.error_text);
            defer self.allocator.free(status_json);
            try self.setFileContent(node_id, status_json);
        },
        .job_result => {
            try self.setFileContent(node_id, view.result_text orelse "");
        },
        .job_log => {
            try self.setFileContent(node_id, view.log_text orelse "");
        },
        else => {},
    }
}
