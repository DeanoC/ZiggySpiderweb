const std = @import("std");

pub const WorkerType = enum {
    research,
    execution,
    status,
};

pub const WorkerResult = struct {
    task_id: usize,
    worker: WorkerType,
    title: []const u8,
    status: [16]u8,
    status_len: usize,
    detail: [128]u8,
    detail_len: usize,

    pub fn statusSlice(self: *const WorkerResult) []const u8 {
        return self.status[0..self.status_len];
    }

    pub fn detailSlice(self: *const WorkerResult) []const u8 {
        return self.detail[0..self.detail_len];
    }
};

pub fn workerTypeLabel(worker: WorkerType) []const u8 {
    return switch (worker) {
        .research => "research",
        .execution => "execution",
        .status => "status",
    };
}

pub fn executePlanWorkers(
    allocator: std.mem.Allocator,
    tasks: []const []const u8,
    max_parallelism: usize,
    results: *std.ArrayListUnmanaged(WorkerResult),
) !void {
    results.clearRetainingCapacity();

    if (tasks.len == 0) return;

    const worker_limit = if (max_parallelism == 0) 1 else max_parallelism;

    var outputs = try allocator.alloc(WorkerResult, tasks.len);
    defer allocator.free(outputs);

    var jobs = try allocator.alloc(WorkerJob, tasks.len);
    defer allocator.free(jobs);

    var threads = try allocator.alloc(std.Thread, worker_limit);
    defer allocator.free(threads);

    var started: usize = 0;
    while (started < tasks.len) {
        const batch_end = @min(started + worker_limit, tasks.len);
        var active_count: usize = 0;

        var idx = started;
        while (idx < batch_end) {
            jobs[idx] = .{
                .task_id = idx + 1,
                .kind = taskToWorkerKind(idx),
                .title = tasks[idx],
                .result = &outputs[idx],
            };
            initResult(&outputs[idx], jobs[idx]);
            threads[active_count] = try std.Thread.spawn(.{}, runWorkerJob, .{&jobs[idx]});
            active_count += 1;
            idx += 1;
        }

        var thread_idx: usize = 0;
        while (thread_idx < active_count) : (thread_idx += 1) {
            threads[thread_idx].join();
        }

        idx = started;
        while (idx < batch_end) {
            try results.append(allocator, outputs[idx]);
            idx += 1;
        }

        started = batch_end;
    }
}

const WorkerJob = struct {
    task_id: usize,
    kind: WorkerType,
    title: []const u8,
    result: *WorkerResult,
};

fn runWorkerJob(job: *WorkerJob) void {
    switch (job.kind) {
        .research => {
            runResearch(job.title, job.result);
        },
        .execution => {
            runExecution(job.title, job.result);
        },
        .status => {
            runStatusCheck(job.title, job.result);
        },
    }
}

fn setResult(result: *WorkerResult, kind: []const u8) void {
    result.status_len = 0;
    appendText(result.status[0..], kind, &result.status_len);
}

fn initResult(result: *WorkerResult, job: WorkerJob) void {
    result.task_id = job.task_id;
    result.worker = job.kind;
    result.title = job.title;
    result.status_len = 0;
    result.detail_len = 0;
    setResult(result, "queued");
}

fn taskToWorkerKind(index: usize) WorkerType {
    return switch (index % 3) {
        0 => .research,
        1 => .execution,
        else => .status,
    };
}

fn runResearch(task: []const u8, result: *WorkerResult) void {
    runTextScan(.research, task, result, "research terms");
}

fn runExecution(task: []const u8, result: *WorkerResult) void {
    runTextScan(.execution, task, result, "execution steps");
}

fn runStatusCheck(task: []const u8, result: *WorkerResult) void {
    runTextScan(.status, task, result, "status checks");
}

fn runTextScan(kind: WorkerType, task: []const u8, result: *WorkerResult, suffix: []const u8) void {
    setResult(result, "complete");
    const tokens = countWords(task);
    const label = workerTypeLabel(kind);
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "{s}: found {d} {s}", .{ label, tokens, suffix }) catch {
        return;
    };
    appendText(result.detail[0..], detail, &result.detail_len);
}

fn appendText(dst: []u8, src: []const u8, len: *usize) void {
    const available = dst.len - len.*;
    const needed = @min(src.len, available);
    @memcpy(dst[len.* .. len.* + needed], src[0..needed]);
    len.* += needed;
}

fn countWords(text: []const u8) usize {
    var count: usize = 0;
    var in_token: bool = false;
    for (text) |c| {
        const sep = c == ' ' or c == '\n' or c == '\t' or c == '\r';
        if (!sep and !in_token) {
            in_token = true;
            count += 1;
        } else if (sep) {
            in_token = false;
        }
    }
    return count;
}

test "workers: executePlanWorkers assigns bounded deterministic batches" {
    const allocator = std.testing.allocator;
    const tasks = [_][]const u8{
        "index project milestones",
        "execute rollout plan",
        "status check for blockers",
        "second pass planning",
    };

    var out = std.ArrayListUnmanaged(WorkerResult){};
    defer out.deinit(allocator);

    try executePlanWorkers(allocator, &tasks, 2, &out);
    try std.testing.expectEqual(@as(usize, 4), out.items.len);
    try std.testing.expectEqual(@as(usize, 1), out.items[0].task_id);
    try std.testing.expect(std.mem.eql(u8, out.items[1].statusSlice(), "complete"));
}
