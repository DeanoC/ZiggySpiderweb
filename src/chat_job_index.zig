const std = @import("std");
const unified = @import("ziggy-spider-protocol").unified;

const snapshot_filename = "chat-job-index.json";
const snapshot_schema: u32 = 1;
const default_ttl_ms: i64 = 24 * 60 * 60 * 1000;
const max_snapshot_bytes: usize = 32 * 1024 * 1024;

pub const JobState = enum {
    queued,
    running,
    done,
    failed,
};

pub const JobIndexError = error{
    JobNotFound,
};

const JobRecord = struct {
    job_id: []u8,
    agent_id: []u8,
    created_at_ms: i64,
    updated_at_ms: i64,
    expires_at_ms: i64,
    state: JobState,
    correlation_id: ?[]u8 = null,
    result_text: ?[]u8 = null,
    error_text: ?[]u8 = null,
    log_text: ?[]u8 = null,

    fn deinit(self: *JobRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.job_id);
        allocator.free(self.agent_id);
        if (self.correlation_id) |value| allocator.free(value);
        if (self.result_text) |value| allocator.free(value);
        if (self.error_text) |value| allocator.free(value);
        if (self.log_text) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const JobView = struct {
    job_id: []u8,
    agent_id: []u8,
    created_at_ms: i64,
    updated_at_ms: i64,
    expires_at_ms: i64,
    state: JobState,
    correlation_id: ?[]u8 = null,
    result_text: ?[]u8 = null,
    error_text: ?[]u8 = null,
    log_text: ?[]u8 = null,

    pub fn deinit(self: *JobView, allocator: std.mem.Allocator) void {
        allocator.free(self.job_id);
        allocator.free(self.agent_id);
        if (self.correlation_id) |value| allocator.free(value);
        if (self.result_text) |value| allocator.free(value);
        if (self.error_text) |value| allocator.free(value);
        if (self.log_text) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub fn deinitJobViews(allocator: std.mem.Allocator, views: []JobView) void {
    for (views) |*view| view.deinit(allocator);
    if (views.len > 0) allocator.free(views);
}

pub const ChatJobIndex = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    snapshot_path: ?[]u8 = null,
    next_job_seq: u64 = 1,
    ttl_ms: i64 = default_ttl_ms,
    jobs: std.StringHashMapUnmanaged(JobRecord) = .{},

    pub fn init(allocator: std.mem.Allocator, ltm_directory: []const u8) ChatJobIndex {
        var index = ChatJobIndex{
            .allocator = allocator,
        };
        if (ltm_directory.len == 0) return index;

        std.fs.cwd().makePath(ltm_directory) catch |err| {
            std.log.warn("chat job index disabled (cannot create ltm dir): {s}", .{@errorName(err)});
            return index;
        };

        index.snapshot_path = std.fs.path.join(allocator, &.{ ltm_directory, snapshot_filename }) catch |err| {
            std.log.warn("chat job index disabled (path allocation failed): {s}", .{@errorName(err)});
            return index;
        };

        index.loadFromDiskLocked() catch |err| {
            std.log.warn("chat job index load failed: {s}", .{@errorName(err)});
        };
        return index;
    }

    pub fn deinit(self: *ChatJobIndex) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.jobs.valueIterator();
        while (it.next()) |record| record.deinit(self.allocator);
        self.jobs.deinit(self.allocator);
        self.jobs = .{};

        if (self.snapshot_path) |value| {
            self.allocator.free(value);
            self.snapshot_path = null;
        }
    }

    pub fn createJob(
        self: *ChatJobIndex,
        agent_id: []const u8,
        correlation_id: ?[]const u8,
    ) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now_ms = std.time.milliTimestamp();
        try self.pruneExpiredLocked(now_ms);

        const job_id = try std.fmt.allocPrint(self.allocator, "job-{d}", .{self.next_job_seq});
        self.next_job_seq +%= 1;
        if (self.next_job_seq == 0) self.next_job_seq = 1;
        errdefer self.allocator.free(job_id);

        const record = JobRecord{
            .job_id = try self.allocator.dupe(u8, job_id),
            .agent_id = try self.allocator.dupe(u8, agent_id),
            .created_at_ms = now_ms,
            .updated_at_ms = now_ms,
            .expires_at_ms = now_ms + self.ttl_ms,
            .state = .queued,
            .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
        };
        errdefer {
            var tmp = record;
            tmp.deinit(self.allocator);
        }

        try self.jobs.put(self.allocator, record.job_id, record);
        self.persistSnapshotBestEffortLocked();
        return job_id;
    }

    pub fn markRunning(self: *ChatJobIndex, job_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const record = self.jobs.getPtr(job_id) orelse return JobIndexError.JobNotFound;
        const now_ms = std.time.milliTimestamp();
        record.state = .running;
        record.updated_at_ms = now_ms;
        record.expires_at_ms = now_ms + self.ttl_ms;
        self.persistSnapshotBestEffortLocked();
    }

    pub fn markCompleted(
        self: *ChatJobIndex,
        job_id: []const u8,
        succeeded: bool,
        result_text: []const u8,
        error_text: ?[]const u8,
        log_text: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const record = self.jobs.getPtr(job_id) orelse return JobIndexError.JobNotFound;
        const now_ms = std.time.milliTimestamp();
        record.state = if (succeeded) .done else .failed;
        record.updated_at_ms = now_ms;
        record.expires_at_ms = now_ms + self.ttl_ms;

        if (record.result_text) |value| {
            self.allocator.free(value);
            record.result_text = null;
        }
        if (record.error_text) |value| {
            self.allocator.free(value);
            record.error_text = null;
        }
        if (record.log_text) |value| {
            self.allocator.free(value);
            record.log_text = null;
        }

        record.result_text = try self.allocator.dupe(u8, result_text);
        if (error_text) |value| {
            record.error_text = try self.allocator.dupe(u8, value);
        }
        record.log_text = try self.allocator.dupe(u8, log_text);

        self.persistSnapshotBestEffortLocked();
    }

    pub fn listJobsForAgent(self: *ChatJobIndex, allocator: std.mem.Allocator, agent_id: []const u8) ![]JobView {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.pruneExpiredLocked(std.time.milliTimestamp());

        var out = std.ArrayListUnmanaged(JobView){};
        errdefer {
            for (out.items) |*view| view.deinit(allocator);
            out.deinit(allocator);
        }

        var it = self.jobs.valueIterator();
        while (it.next()) |record| {
            if (!std.mem.eql(u8, record.agent_id, agent_id)) continue;
            try out.append(allocator, try duplicateRecordView(allocator, record.*));
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn hasInFlightForAgent(self: *ChatJobIndex, agent_id: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.pruneExpiredLocked(std.time.milliTimestamp());

        var it = self.jobs.valueIterator();
        while (it.next()) |record| {
            if (!std.mem.eql(u8, record.agent_id, agent_id)) continue;
            if (record.state == .queued or record.state == .running) return true;
        }
        return false;
    }

    pub fn getJob(self: *ChatJobIndex, allocator: std.mem.Allocator, job_id: []const u8) !?JobView {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.pruneExpiredLocked(std.time.milliTimestamp());
        const record = self.jobs.get(job_id) orelse return null;
        return try duplicateRecordView(allocator, record);
    }

    fn duplicateRecordView(allocator: std.mem.Allocator, record: JobRecord) !JobView {
        return .{
            .job_id = try allocator.dupe(u8, record.job_id),
            .agent_id = try allocator.dupe(u8, record.agent_id),
            .created_at_ms = record.created_at_ms,
            .updated_at_ms = record.updated_at_ms,
            .expires_at_ms = record.expires_at_ms,
            .state = record.state,
            .correlation_id = if (record.correlation_id) |value| try allocator.dupe(u8, value) else null,
            .result_text = if (record.result_text) |value| try allocator.dupe(u8, value) else null,
            .error_text = if (record.error_text) |value| try allocator.dupe(u8, value) else null,
            .log_text = if (record.log_text) |value| try allocator.dupe(u8, value) else null,
        };
    }

    fn pruneExpiredLocked(self: *ChatJobIndex, now_ms: i64) !void {
        var expired_keys = std.ArrayListUnmanaged([]u8){};
        defer {
            for (expired_keys.items) |key| self.allocator.free(key);
            expired_keys.deinit(self.allocator);
        }

        var it = self.jobs.iterator();
        while (it.next()) |entry| {
            const record = entry.value_ptr.*;
            const terminal = record.state == .done or record.state == .failed;
            if (!terminal) continue;
            if (record.expires_at_ms > now_ms) continue;
            try expired_keys.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
        }

        if (expired_keys.items.len == 0) return;
        for (expired_keys.items) |key| {
            const removed = self.jobs.fetchRemove(key) orelse continue;
            var record = removed.value;
            record.deinit(self.allocator);
        }
        self.persistSnapshotBestEffortLocked();
    }

    fn persistSnapshotBestEffortLocked(self: *ChatJobIndex) void {
        self.persistSnapshotLocked() catch |err| {
            std.log.warn("chat job index persist failed: {s}", .{@errorName(err)});
        };
    }

    fn persistSnapshotLocked(self: *ChatJobIndex) !void {
        const path = self.snapshot_path orelse return;
        const snapshot = try self.buildSnapshotJsonLocked();
        defer self.allocator.free(snapshot);

        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{path});
        defer self.allocator.free(tmp_path);

        {
            var file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
            defer file.close();
            try file.writeAll(snapshot);
        }
        std.fs.cwd().rename(tmp_path, path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                std.fs.cwd().deleteFile(path) catch {};
                try std.fs.cwd().rename(tmp_path, path);
            },
            else => return err,
        };
    }

    fn buildSnapshotJsonLocked(self: *ChatJobIndex) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);

        try out.writer(self.allocator).print(
            "{{\"schema\":{d},\"next_job_seq\":{d},\"ttl_ms\":{d},\"jobs\":[",
            .{ snapshot_schema, self.next_job_seq, self.ttl_ms },
        );

        var first = true;
        var it = self.jobs.valueIterator();
        while (it.next()) |record| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try appendRecordJson(self.allocator, &out, record.*);
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    fn loadFromDiskLocked(self: *ChatJobIndex) !void {
        const path = self.snapshot_path orelse return;
        const raw = std.fs.cwd().readFileAlloc(self.allocator, path, max_snapshot_bytes) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.allocator.free(raw);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidSnapshot;
        const root = parsed.value.object;

        const schema_val = root.get("schema") orelse return error.InvalidSnapshot;
        if (schema_val != .integer or schema_val.integer != snapshot_schema) return error.InvalidSnapshot;

        if (root.get("next_job_seq")) |value| {
            if (value != .integer or value.integer <= 0) return error.InvalidSnapshot;
            self.next_job_seq = @intCast(value.integer);
        }
        if (root.get("ttl_ms")) |value| {
            if (value != .integer or value.integer <= 0) return error.InvalidSnapshot;
            self.ttl_ms = value.integer;
        }

        const jobs_val = root.get("jobs") orelse return error.InvalidSnapshot;
        if (jobs_val != .array) return error.InvalidSnapshot;
        for (jobs_val.array.items) |item| {
            if (item != .object) return error.InvalidSnapshot;
            const record = try parseRecord(self.allocator, item.object);
            errdefer {
                var tmp = record;
                tmp.deinit(self.allocator);
            }
            try self.jobs.put(self.allocator, record.job_id, record);
        }

        try self.pruneExpiredLocked(std.time.milliTimestamp());
    }
};

fn appendRecordJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    record: JobRecord,
) !void {
    const escaped_id = try unified.jsonEscape(allocator, record.job_id);
    defer allocator.free(escaped_id);
    const escaped_agent = try unified.jsonEscape(allocator, record.agent_id);
    defer allocator.free(escaped_agent);
    const correlation_json = if (record.correlation_id) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(correlation_json);
    const result_json = if (record.result_text) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(result_json);
    const error_json = if (record.error_text) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(error_json);
    const log_json = if (record.log_text) |value| blk: {
        const escaped = try unified.jsonEscape(allocator, value);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(log_json);

    try out.writer(allocator).print(
        "{{\"job_id\":\"{s}\",\"agent_id\":\"{s}\",\"created_at_ms\":{d},\"updated_at_ms\":{d},\"expires_at_ms\":{d},\"state\":\"{s}\",\"correlation_id\":{s},\"result_text\":{s},\"error_text\":{s},\"log_text\":{s}}}",
        .{
            escaped_id,
            escaped_agent,
            record.created_at_ms,
            record.updated_at_ms,
            record.expires_at_ms,
            jobStateName(record.state),
            correlation_json,
            result_json,
            error_json,
            log_json,
        },
    );
}

fn parseRecord(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !JobRecord {
    const job_id = try dupRequiredString(allocator, obj, "job_id");
    errdefer allocator.free(job_id);
    const agent_id = try dupRequiredString(allocator, obj, "agent_id");
    errdefer allocator.free(agent_id);
    const state = try jobStateFromString(try getRequiredString(obj, "state"));
    return .{
        .job_id = job_id,
        .agent_id = agent_id,
        .created_at_ms = try getRequiredI64(obj, "created_at_ms"),
        .updated_at_ms = try getRequiredI64(obj, "updated_at_ms"),
        .expires_at_ms = try getRequiredI64(obj, "expires_at_ms"),
        .state = state,
        .correlation_id = try dupOptionalNullableString(allocator, obj, "correlation_id"),
        .result_text = try dupOptionalNullableString(allocator, obj, "result_text"),
        .error_text = try dupOptionalNullableString(allocator, obj, "error_text"),
        .log_text = try dupOptionalNullableString(allocator, obj, "log_text"),
    };
}

fn getRequiredString(obj: std.json.ObjectMap, field: []const u8) ![]const u8 {
    const value = obj.get(field) orelse return error.InvalidSnapshot;
    if (value != .string or value.string.len == 0) return error.InvalidSnapshot;
    return value.string;
}

fn dupRequiredString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, field: []const u8) ![]u8 {
    return allocator.dupe(u8, try getRequiredString(obj, field));
}

fn dupOptionalNullableString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, field: []const u8) !?[]u8 {
    const value = obj.get(field) orelse return null;
    if (value == .null) return null;
    if (value != .string) return error.InvalidSnapshot;
    const copied = try allocator.dupe(u8, value.string);
    return @as(?[]u8, copied);
}

fn getRequiredI64(obj: std.json.ObjectMap, field: []const u8) !i64 {
    const value = obj.get(field) orelse return error.InvalidSnapshot;
    if (value != .integer) return error.InvalidSnapshot;
    return value.integer;
}

fn jobStateName(state: JobState) []const u8 {
    return switch (state) {
        .queued => "queued",
        .running => "running",
        .done => "done",
        .failed => "failed",
    };
}

fn jobStateFromString(value: []const u8) !JobState {
    if (std.mem.eql(u8, value, "queued")) return .queued;
    if (std.mem.eql(u8, value, "running")) return .running;
    if (std.mem.eql(u8, value, "done")) return .done;
    if (std.mem.eql(u8, value, "failed")) return .failed;
    return error.InvalidSnapshot;
}

test "chat_job_index: create and complete in memory" {
    const allocator = std.testing.allocator;
    var index = ChatJobIndex.init(allocator, "");
    defer index.deinit();

    const job_id = try index.createJob("agent-a", "corr-1");
    defer allocator.free(job_id);
    try index.markRunning(job_id);
    try index.markCompleted(job_id, true, "result", null, "log");

    const job = try index.getJob(allocator, job_id);
    try std.testing.expect(job != null);
    var view = job.?;
    defer view.deinit(allocator);
    try std.testing.expectEqual(JobState.done, view.state);
    try std.testing.expect(view.result_text != null);
    try std.testing.expectEqualStrings("result", view.result_text.?);
}

test "chat_job_index: hasInFlightForAgent tracks queued/running jobs" {
    const allocator = std.testing.allocator;
    var index = ChatJobIndex.init(allocator, "");
    defer index.deinit();

    const a_job = try index.createJob("agent-a", null);
    defer allocator.free(a_job);
    const b_job = try index.createJob("agent-b", null);
    defer allocator.free(b_job);

    try std.testing.expect(try index.hasInFlightForAgent("agent-a"));
    try std.testing.expect(try index.hasInFlightForAgent("agent-b"));
    try std.testing.expect(!(try index.hasInFlightForAgent("agent-c")));

    try index.markRunning(a_job);
    try std.testing.expect(try index.hasInFlightForAgent("agent-a"));

    try index.markCompleted(a_job, true, "done", null, "");
    try std.testing.expect(!(try index.hasInFlightForAgent("agent-a")));
    try std.testing.expect(try index.hasInFlightForAgent("agent-b"));
}
