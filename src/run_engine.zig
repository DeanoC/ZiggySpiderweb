const std = @import("std");
const ltm_store = @import("ltm_store.zig");
const run_store = @import("run_store.zig");

pub const RunState = enum {
    created,
    running,
    waiting_for_user,
    paused,
    cancelled,
    completed,
    failed,
};

pub const RunPhase = enum {
    observe,
    decide,
    act,
    integrate,
    checkpoint,
};

pub const RunEngineError = error{
    RunNotFound,
    InvalidState,
    NoPendingInput,
    MaxRunStepsExceeded,
};

pub const RunEngineConfig = struct {
    max_run_steps: usize = 1024,
    checkpoint_interval_steps: usize = 1,
    run_auto_resume_on_boot: bool = false,
};

pub const RunSnapshot = struct {
    run_id: []u8,
    state: RunState,
    step_count: u64,
    checkpoint_seq: u64,
    created_at_ms: i64,
    updated_at_ms: i64,
    last_input: ?[]u8 = null,
    last_output: ?[]u8 = null,

    pub fn deinit(self: *RunSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.run_id);
        if (self.last_input) |value| allocator.free(value);
        if (self.last_output) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const StepWork = struct {
    run_id: []u8,
    step_count: u64,
    input: []u8,

    pub fn deinit(self: *StepWork, allocator: std.mem.Allocator) void {
        allocator.free(self.run_id);
        allocator.free(self.input);
        self.* = undefined;
    }
};

pub const RunEventView = struct {
    seq: u64,
    event_type: []u8,
    payload_json: []u8,
    created_at_ms: i64,

    pub fn deinit(self: *RunEventView, allocator: std.mem.Allocator) void {
        allocator.free(self.event_type);
        allocator.free(self.payload_json);
        self.* = undefined;
    }
};

const RunRecord = struct {
    run_id: []u8,
    state: RunState,
    step_count: u64,
    checkpoint_seq: u64,
    created_at_ms: i64,
    updated_at_ms: i64,
    last_input: ?[]u8 = null,
    last_output: ?[]u8 = null,
    pending_inputs: std.ArrayListUnmanaged([]u8) = .{},
    events: std.ArrayListUnmanaged(run_store.RunEvent) = .{},

    fn deinit(self: *RunRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.run_id);
        if (self.last_input) |value| allocator.free(value);
        if (self.last_output) |value| allocator.free(value);
        for (self.pending_inputs.items) |value| allocator.free(value);
        self.pending_inputs.deinit(allocator);
        for (self.events.items) |*event| event.deinit(allocator);
        self.events.deinit(allocator);
        self.* = undefined;
    }

    fn cloneSnapshot(self: *const RunRecord, allocator: std.mem.Allocator) !RunSnapshot {
        return .{
            .run_id = try allocator.dupe(u8, self.run_id),
            .state = self.state,
            .step_count = self.step_count,
            .checkpoint_seq = self.checkpoint_seq,
            .created_at_ms = self.created_at_ms,
            .updated_at_ms = self.updated_at_ms,
            .last_input = if (self.last_input) |value| try allocator.dupe(u8, value) else null,
            .last_output = if (self.last_output) |value| try allocator.dupe(u8, value) else null,
        };
    }
};

pub const RunEngine = struct {
    allocator: std.mem.Allocator,
    config: RunEngineConfig,
    store: run_store.RunStore,
    mutex: std.Thread.Mutex = .{},
    runs: std.StringHashMapUnmanaged(RunRecord) = .{},
    next_run_counter: u64 = 1,

    pub fn init(
        allocator: std.mem.Allocator,
        persisted_store: ?*ltm_store.VersionedMemStore,
        config: RunEngineConfig,
    ) !RunEngine {
        var engine = RunEngine{
            .allocator = allocator,
            .config = .{
                .max_run_steps = if (config.max_run_steps == 0) 1024 else config.max_run_steps,
                .checkpoint_interval_steps = if (config.checkpoint_interval_steps == 0) 1 else config.checkpoint_interval_steps,
                .run_auto_resume_on_boot = config.run_auto_resume_on_boot,
            },
            .store = run_store.RunStore.init(allocator, persisted_store),
        };
        errdefer engine.deinit();

        try engine.recoverLocked();
        return engine;
    }

    pub fn deinit(self: *RunEngine) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.runs.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.runs.deinit(self.allocator);
        self.store.deinit();
    }

    pub fn start(self: *RunEngine, initial_input: ?[]const u8) !RunSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        const run_id = try std.fmt.allocPrint(
            self.allocator,
            "run-{d}-{d}",
            .{ now, self.next_run_counter },
        );
        self.next_run_counter += 1;

        var run = RunRecord{
            .run_id = try self.allocator.dupe(u8, run_id),
            .state = .created,
            .step_count = 0,
            .checkpoint_seq = 0,
            .created_at_ms = now,
            .updated_at_ms = now,
        };
        errdefer run.deinit(self.allocator);

        if (initial_input) |value| {
            try run.pending_inputs.append(self.allocator, try self.allocator.dupe(u8, value));
        }

        const owned_key = try self.allocator.dupe(u8, run_id);
        errdefer self.allocator.free(owned_key);
        try self.runs.put(self.allocator, owned_key, run);

        try self.persistMetaForRunLocked(self.runs.getPtr(run_id).?);
        _ = try self.appendEventLocked(run_id, "run.started", "{}", now);

        const snapshot = try self.runs.getPtr(run_id).?.cloneSnapshot(self.allocator);
        self.allocator.free(run_id);
        return snapshot;
    }

    pub fn enqueueInput(self: *RunEngine, run_id: []const u8, input: []const u8) !RunSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;
        if (run.state == .cancelled or run.state == .completed or run.state == .failed) {
            return RunEngineError.InvalidState;
        }

        try run.pending_inputs.append(self.allocator, try self.allocator.dupe(u8, input));
        run.updated_at_ms = std.time.milliTimestamp();

        const payload = try std.fmt.allocPrint(self.allocator, "{{\"queued\":{d}}}", .{run.pending_inputs.items.len});
        defer self.allocator.free(payload);
        _ = try self.appendEventLocked(run_id, "run.input_queued", payload, run.updated_at_ms);
        try self.persistMetaForRunLocked(run);

        return run.cloneSnapshot(self.allocator);
    }

    pub fn beginStep(self: *RunEngine, run_id: []const u8, inline_input: ?[]const u8) !StepWork {
        return self.beginStepInternal(run_id, inline_input, false);
    }

    pub fn beginResumedStep(self: *RunEngine, run_id: []const u8, inline_input: ?[]const u8) !StepWork {
        return self.beginStepInternal(run_id, inline_input, true);
    }

    fn beginStepInternal(
        self: *RunEngine,
        run_id: []const u8,
        inline_input: ?[]const u8,
        allow_paused: bool,
    ) !StepWork {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;

        if ((run.state == .paused and !allow_paused) or
            run.state == .cancelled or
            run.state == .completed or
            run.state == .failed)
        {
            return RunEngineError.InvalidState;
        }

        if (run.step_count >= self.config.max_run_steps) return RunEngineError.MaxRunStepsExceeded;

        if (inline_input) |value| {
            try run.pending_inputs.append(self.allocator, try self.allocator.dupe(u8, value));
        }

        if (run.pending_inputs.items.len == 0) return RunEngineError.NoPendingInput;

        const input = run.pending_inputs.items[0];
        const work_run_id = try self.allocator.dupe(u8, run_id);
        errdefer self.allocator.free(work_run_id);
        const work_input = try self.allocator.dupe(u8, input);
        errdefer self.allocator.free(work_input);
        const next_last_input = try self.allocator.dupe(u8, input);
        const was_paused = run.state == .paused;
        const previous_state = run.state;
        const previous_step_count = run.step_count;
        const previous_updated_at_ms = run.updated_at_ms;
        const previous_last_input = run.last_input;
        const previous_event_count = run.events.items.len;
        run.last_input = next_last_input;
        run.step_count += 1;
        run.state = .running;
        run.updated_at_ms = std.time.milliTimestamp();
        var committed = false;
        errdefer if (!committed) {
            run.state = previous_state;
            run.step_count = previous_step_count;
            run.updated_at_ms = previous_updated_at_ms;
            if (run.last_input) |value| self.allocator.free(value);
            run.last_input = previous_last_input;

            while (run.events.items.len > previous_event_count) {
                var event = run.events.pop().?;
                event.deinit(self.allocator);
            }
        };

        if (was_paused) {
            _ = try self.appendEventLocked(run_id, "run.resumed", "{}", run.updated_at_ms);
        }

        const payload = try std.fmt.allocPrint(self.allocator, "{{\"step\":{d}}}", .{run.step_count});
        defer self.allocator.free(payload);
        _ = try self.appendEventLocked(run_id, "run.step_started", payload, run.updated_at_ms);
        try self.persistMetaForRunLocked(run);
        const consumed_input = run.pending_inputs.orderedRemove(0);
        self.allocator.free(consumed_input);
        committed = true;

        if (previous_last_input) |value| self.allocator.free(value);

        return .{
            .run_id = work_run_id,
            .step_count = run.step_count,
            .input = work_input,
        };
    }

    pub fn recordPhase(
        self: *RunEngine,
        run_id: []const u8,
        phase: RunPhase,
        payload_json: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;
        run.updated_at_ms = std.time.milliTimestamp();

        const event_type = switch (phase) {
            .observe => "phase.observe",
            .decide => "phase.decide",
            .act => "phase.act",
            .integrate => "phase.integrate",
            .checkpoint => "phase.checkpoint",
        };

        _ = try self.appendEventLocked(run_id, event_type, payload_json, run.updated_at_ms);
    }

    pub fn completeStep(self: *RunEngine, run_id: []const u8, output: []const u8, wait_for_user: bool) !RunSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;
        if (run.state != .running) return RunEngineError.InvalidState;

        if (run.last_output) |value| self.allocator.free(value);
        run.last_output = try self.allocator.dupe(u8, output);
        run.updated_at_ms = std.time.milliTimestamp();

        const should_checkpoint = @mod(run.step_count, self.config.checkpoint_interval_steps) == 0;
        if (should_checkpoint) run.checkpoint_seq += 1;

        if (!wait_for_user and containsCaseInsensitive(output, "task_complete")) {
            run.state = .completed;
        } else if (wait_for_user) {
            run.state = .waiting_for_user;
        } else {
            run.state = .running;
        }

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"step\":{d},\"checkpoint_seq\":{d},\"state\":\"{s}\"}}",
            .{ run.step_count, run.checkpoint_seq, @tagName(run.state) },
        );
        defer self.allocator.free(payload);
        _ = try self.appendEventLocked(run_id, "run.step_completed", payload, run.updated_at_ms);
        try self.persistMetaForRunLocked(run);

        return run.cloneSnapshot(self.allocator);
    }

    pub fn failStep(self: *RunEngine, run_id: []const u8, reason: []const u8) !RunSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;
        run.state = .failed;
        run.updated_at_ms = std.time.milliTimestamp();

        const escaped_reason = try escapeJson(self.allocator, reason);
        defer self.allocator.free(escaped_reason);
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"reason\":\"{s}\"}}",
            .{escaped_reason},
        );
        defer self.allocator.free(payload);
        _ = try self.appendEventLocked(run_id, "run.failed", payload, run.updated_at_ms);
        try self.persistMetaForRunLocked(run);

        return run.cloneSnapshot(self.allocator);
    }

    pub fn pause(self: *RunEngine, run_id: []const u8) !RunSnapshot {
        return self.setState(run_id, .paused, "run.paused");
    }

    pub fn resumeRun(self: *RunEngine, run_id: []const u8) !RunSnapshot {
        return self.setState(run_id, .running, "run.resumed");
    }

    pub fn cancel(self: *RunEngine, run_id: []const u8) !RunSnapshot {
        return self.setState(run_id, .cancelled, "run.cancelled");
    }

    pub fn get(self: *RunEngine, run_id: []const u8) !RunSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;
        return run.cloneSnapshot(self.allocator);
    }

    pub fn list(self: *RunEngine, allocator: std.mem.Allocator) ![]RunSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        var out = std.ArrayListUnmanaged(RunSnapshot){};
        errdefer {
            for (out.items) |*snapshot| snapshot.deinit(allocator);
            out.deinit(allocator);
        }

        var it = self.runs.iterator();
        while (it.next()) |entry| {
            try out.append(allocator, try entry.value_ptr.cloneSnapshot(allocator));
        }

        return out.toOwnedSlice(allocator);
    }

    pub fn listEvents(self: *RunEngine, allocator: std.mem.Allocator, run_id: []const u8, limit: usize) ![]RunEventView {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;

        const available = run.events.items.len;
        const take = @min(available, limit);
        var out = try allocator.alloc(RunEventView, take);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |*event| event.deinit(allocator);
            allocator.free(out);
        }

        const start_idx = available - take;
        for (run.events.items[start_idx..], 0..) |event, idx| {
            const owned_event_type = try allocator.dupe(u8, event.event_type);
            errdefer allocator.free(owned_event_type);
            const owned_payload = try allocator.dupe(u8, event.payload_json);
            out[idx] = .{
                .seq = event.seq,
                .event_type = owned_event_type,
                .payload_json = owned_payload,
                .created_at_ms = event.created_at_ms,
            };
            initialized += 1;
        }

        return out;
    }

    fn setState(self: *RunEngine, run_id: []const u8, next: RunState, event_type: []const u8) !RunSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;
        if (run.state == .completed or run.state == .cancelled or run.state == .failed) {
            return RunEngineError.InvalidState;
        }

        run.state = next;
        run.updated_at_ms = std.time.milliTimestamp();
        _ = try self.appendEventLocked(run_id, event_type, "{}", run.updated_at_ms);
        try self.persistMetaForRunLocked(run);
        return run.cloneSnapshot(self.allocator);
    }

    fn persistMetaForRunLocked(self: *RunEngine, run: *const RunRecord) !void {
        try self.store.persistMeta(.{
            .run_id = run.run_id,
            .state = @tagName(run.state),
            .step_count = run.step_count,
            .checkpoint_seq = run.checkpoint_seq,
            .created_at_ms = run.created_at_ms,
            .updated_at_ms = run.updated_at_ms,
            .last_input = run.last_input,
            .last_output = run.last_output,
        });
    }

    fn appendEventLocked(
        self: *RunEngine,
        run_id: []const u8,
        event_type: []const u8,
        payload_json: []const u8,
        created_at_ms: i64,
    ) !u64 {
        const seq = try self.store.appendEvent(.{
            .run_id = run_id,
            .event_type = event_type,
            .payload_json = payload_json,
            .created_at_ms = created_at_ms,
        });

        const run = self.runs.getPtr(run_id) orelse return RunEngineError.RunNotFound;
        try run.events.append(self.allocator, .{
            .seq = seq,
            .event_type = try self.allocator.dupe(u8, event_type),
            .payload_json = try self.allocator.dupe(u8, payload_json),
            .created_at_ms = created_at_ms,
        });
        return seq;
    }

    fn recoverLocked(self: *RunEngine) !void {
        const recover_run_limit: usize = @intCast(std.math.maxInt(i64));
        const ids = try self.store.listRunIds(self.allocator, recover_run_limit);
        defer {
            for (ids) |id| self.allocator.free(id);
            self.allocator.free(ids);
        }

        for (ids) |run_id| {
            var meta = (try self.store.loadMeta(self.allocator, run_id)) orelse continue;
            defer meta.deinit(self.allocator);

            var run = RunRecord{
                .run_id = try self.allocator.dupe(u8, meta.run_id),
                .state = parseState(meta.state),
                .step_count = meta.step_count,
                .checkpoint_seq = meta.checkpoint_seq,
                .created_at_ms = meta.created_at_ms,
                .updated_at_ms = meta.updated_at_ms,
                .last_input = if (meta.last_input) |value| try self.allocator.dupe(u8, value) else null,
                .last_output = if (meta.last_output) |value| try self.allocator.dupe(u8, value) else null,
            };
            errdefer run.deinit(self.allocator);

            if (run.state == .running and !self.config.run_auto_resume_on_boot) {
                run.state = .paused;
            }

            const recover_event_limit: usize = @intCast(std.math.maxInt(i64));
            const persisted_events = try self.store.listEvents(self.allocator, run_id, recover_event_limit);
            defer run_store.deinitEvents(self.allocator, persisted_events);
            for (persisted_events) |event| {
                try run.events.append(self.allocator, .{
                    .seq = event.seq,
                    .event_type = try self.allocator.dupe(u8, event.event_type),
                    .payload_json = try self.allocator.dupe(u8, event.payload_json),
                    .created_at_ms = event.created_at_ms,
                });
            }

            const owned_key = try self.allocator.dupe(u8, run.run_id);
            errdefer self.allocator.free(owned_key);
            try self.runs.put(self.allocator, owned_key, run);

            if (run.step_count >= self.next_run_counter) {
                self.next_run_counter = run.step_count + 1;
            }
        }
    }
};

pub fn deinitSnapshots(allocator: std.mem.Allocator, snapshots: []RunSnapshot) void {
    for (snapshots) |*snapshot| snapshot.deinit(allocator);
    allocator.free(snapshots);
}

pub fn deinitEvents(allocator: std.mem.Allocator, events: []RunEventView) void {
    for (events) |*event| event.deinit(allocator);
    allocator.free(events);
}

fn parseState(raw: []const u8) RunState {
    if (std.mem.eql(u8, raw, "created")) return .created;
    if (std.mem.eql(u8, raw, "running")) return .running;
    if (std.mem.eql(u8, raw, "waiting_for_user")) return .waiting_for_user;
    if (std.mem.eql(u8, raw, "paused")) return .paused;
    if (std.mem.eql(u8, raw, "cancelled")) return .cancelled;
    if (std.mem.eql(u8, raw, "completed")) return .completed;
    if (std.mem.eql(u8, raw, "failed")) return .failed;
    return .failed;
}

fn containsCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var start: usize = 0;
    while (start + needle.len <= haystack.len) : (start += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) return true;
    }
    return false;
}

fn escapeJson(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    for (value) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, char),
        }
    }
    return out.toOwnedSlice(allocator);
}

test "run_engine: start, step and lifecycle transitions" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-engine-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    var engine = try RunEngine.init(allocator, &mem_store, .{
        .max_run_steps = 16,
        .checkpoint_interval_steps = 1,
    });
    defer engine.deinit();

    var started = try engine.start("build loop");
    defer started.deinit(allocator);
    try std.testing.expectEqual(RunState.created, started.state);

    var step = try engine.beginStep(started.run_id, null);
    defer step.deinit(allocator);
    try std.testing.expectEqualStrings("build loop", step.input);

    try engine.recordPhase(started.run_id, .observe, "{}");
    try engine.recordPhase(started.run_id, .act, "{}");

    var done = try engine.completeStep(started.run_id, "waiting", true);
    defer done.deinit(allocator);
    try std.testing.expectEqual(RunState.waiting_for_user, done.state);

    var paused = try engine.pause(started.run_id);
    defer paused.deinit(allocator);
    try std.testing.expectEqual(RunState.paused, paused.state);

    var resumed = try engine.resumeRun(started.run_id);
    defer resumed.deinit(allocator);
    try std.testing.expectEqual(RunState.running, resumed.state);

    var cancelled = try engine.cancel(started.run_id);
    defer cancelled.deinit(allocator);
    try std.testing.expectEqual(RunState.cancelled, cancelled.state);

    const events = try engine.listEvents(allocator, started.run_id, 32);
    defer deinitEvents(allocator, events);
    try std.testing.expect(events.len >= 5);
}

test "run_engine: recovery restores persisted run events" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-engine-recover-events-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var captured_run_id: []u8 = undefined;
    {
        var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
        defer mem_store.close();

        var first = try RunEngine.init(allocator, &mem_store, .{
            .max_run_steps = 16,
            .checkpoint_interval_steps = 1,
        });
        defer first.deinit();

        var started = try first.start("recover events");
        defer started.deinit(allocator);
        captured_run_id = try allocator.dupe(u8, started.run_id);

        var step = try first.beginStep(started.run_id, null);
        defer step.deinit(allocator);
        try first.recordPhase(started.run_id, .observe, "{}");
        var completed = try first.completeStep(started.run_id, "waiting", true);
        defer completed.deinit(allocator);
    }
    defer allocator.free(captured_run_id);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();
    var restored = try RunEngine.init(allocator, &mem_store, .{
        .max_run_steps = 16,
        .checkpoint_interval_steps = 1,
    });
    defer restored.deinit();

    const events = try restored.listEvents(allocator, captured_run_id, 64);
    defer deinitEvents(allocator, events);
    try std.testing.expect(events.len >= 4);

    var saw_started = false;
    for (events) |event| {
        if (std.mem.eql(u8, event.event_type, "run.started")) {
            saw_started = true;
            break;
        }
    }
    try std.testing.expect(saw_started);
}

test "run_engine: recovery loads more than 1024 persisted runs" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-engine-recover-many-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    {
        var store = run_store.RunStore.init(allocator, &mem_store);
        defer store.deinit();

        var i: usize = 0;
        while (i < 1100) : (i += 1) {
            const run_id = try std.fmt.allocPrint(allocator, "run-{d}", .{i});
            defer allocator.free(run_id);

            try store.persistMeta(.{
                .run_id = run_id,
                .state = "created",
                .step_count = i,
                .checkpoint_seq = 0,
                .created_at_ms = @as(i64, @intCast(i + 1)),
                .updated_at_ms = @as(i64, @intCast(i + 1)),
            });
        }
    }

    var restored = try RunEngine.init(allocator, &mem_store, .{
        .max_run_steps = 16,
        .checkpoint_interval_steps = 1,
    });
    defer restored.deinit();

    const snapshots = try restored.list(allocator);
    defer deinitSnapshots(allocator, snapshots);
    try std.testing.expectEqual(@as(usize, 1100), snapshots.len);
}

test "run_engine: recovery pauses running runs when auto resume is disabled" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-engine-recover-paused-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var captured_run_id: []u8 = undefined;
    {
        var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
        defer mem_store.close();

        var first = try RunEngine.init(allocator, &mem_store, .{
            .max_run_steps = 16,
            .checkpoint_interval_steps = 1,
            .run_auto_resume_on_boot = false,
        });
        defer first.deinit();

        var started = try first.start("inflight input");
        defer started.deinit(allocator);
        captured_run_id = try allocator.dupe(u8, started.run_id);

        var step = try first.beginStep(started.run_id, null);
        defer step.deinit(allocator);
    }
    defer allocator.free(captured_run_id);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();
    var restored = try RunEngine.init(allocator, &mem_store, .{
        .max_run_steps = 16,
        .checkpoint_interval_steps = 1,
        .run_auto_resume_on_boot = false,
    });
    defer restored.deinit();

    var snapshot = try restored.get(captured_run_id);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(RunState.paused, snapshot.state);
}

test "run_engine: recovery keeps running runs when auto resume is enabled" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-engine-recover-running-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var captured_run_id: []u8 = undefined;
    {
        var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
        defer mem_store.close();

        var first = try RunEngine.init(allocator, &mem_store, .{
            .max_run_steps = 16,
            .checkpoint_interval_steps = 1,
            .run_auto_resume_on_boot = false,
        });
        defer first.deinit();

        var started = try first.start("inflight input");
        defer started.deinit(allocator);
        captured_run_id = try allocator.dupe(u8, started.run_id);

        var step = try first.beginStep(started.run_id, null);
        defer step.deinit(allocator);
    }
    defer allocator.free(captured_run_id);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();
    var restored = try RunEngine.init(allocator, &mem_store, .{
        .max_run_steps = 16,
        .checkpoint_interval_steps = 1,
        .run_auto_resume_on_boot = true,
    });
    defer restored.deinit();

    var snapshot = try restored.get(captured_run_id);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(RunState.running, snapshot.state);
}

test "run_engine: listEvents returns out-of-memory without invalid deinit on partial copy" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-engine-events-oom-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    var engine = try RunEngine.init(allocator, &mem_store, .{
        .max_run_steps = 16,
        .checkpoint_interval_steps = 1,
    });
    defer engine.deinit();

    var started = try engine.start("events test");
    defer started.deinit(allocator);

    var step = try engine.beginStep(started.run_id, null);
    defer step.deinit(allocator);
    var completed = try engine.completeStep(started.run_id, "done", true);
    defer completed.deinit(allocator);

    var failing_state = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 2 });
    const failing_allocator = failing_state.allocator();

    try std.testing.expectError(error.OutOfMemory, engine.listEvents(failing_allocator, started.run_id, 2));
}

test "run_engine: beginStep keeps queued input when step start fails" {
    const allocator = std.testing.allocator;

    const baseline_alloc_index = blk: {
        var baseline_state = std.testing.FailingAllocator.init(allocator, .{});
        const baseline_allocator = baseline_state.allocator();

        var baseline_engine = try RunEngine.init(baseline_allocator, null, .{
            .max_run_steps = 16,
            .checkpoint_interval_steps = 1,
        });
        defer baseline_engine.deinit();

        var baseline_started = try baseline_engine.start("queued input");
        defer baseline_started.deinit(baseline_allocator);
        break :blk baseline_state.alloc_index;
    };

    var saw_begin_step_oom = false;
    var offset: usize = 0;
    while (offset < 64) : (offset += 1) {
        var failing_state = std.testing.FailingAllocator.init(allocator, .{ .fail_index = baseline_alloc_index + offset });
        const failing_allocator = failing_state.allocator();

        var engine = try RunEngine.init(failing_allocator, null, .{
            .max_run_steps = 16,
            .checkpoint_interval_steps = 1,
        });
        defer engine.deinit();

        var started = try engine.start("queued input");
        defer started.deinit(failing_allocator);

        const begin = engine.beginStep(started.run_id, null);
        if (begin) |work| {
            var owned_work = work;
            owned_work.deinit(failing_allocator);
            continue;
        } else |err| switch (err) {
            error.OutOfMemory => {
                saw_begin_step_oom = true;

                engine.mutex.lock();
                defer engine.mutex.unlock();
                const run = engine.runs.getPtr(started.run_id).?;
                try std.testing.expectEqual(@as(usize, 1), run.pending_inputs.items.len);
                try std.testing.expectEqual(@as(u64, 0), run.step_count);
                try std.testing.expectEqual(RunState.created, run.state);
                try std.testing.expect(run.last_input == null);
                break;
            },
            else => return err,
        }
    }

    try std.testing.expect(saw_begin_step_oom);
}
