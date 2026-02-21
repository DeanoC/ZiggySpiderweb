const std = @import("std");
const ltm_store = @import("ltm_store.zig");

pub const RunStoreError = error{
    InvalidRunRecord,
    InvalidRunEvent,
};

pub const RunMeta = struct {
    run_id: []u8,
    state: []u8,
    step_count: u64,
    checkpoint_seq: u64,
    created_at_ms: i64,
    updated_at_ms: i64,
    last_input: ?[]u8 = null,
    last_output: ?[]u8 = null,
    pending_inputs: [][]u8,

    pub fn deinit(self: *RunMeta, allocator: std.mem.Allocator) void {
        allocator.free(self.run_id);
        allocator.free(self.state);
        if (self.last_input) |value| allocator.free(value);
        if (self.last_output) |value| allocator.free(value);
        for (self.pending_inputs) |value| allocator.free(value);
        allocator.free(self.pending_inputs);
        self.* = undefined;
    }
};

pub const RunMetaInput = struct {
    run_id: []const u8,
    state: []const u8,
    step_count: u64,
    checkpoint_seq: u64,
    created_at_ms: i64,
    updated_at_ms: i64,
    last_input: ?[]const u8 = null,
    last_output: ?[]const u8 = null,
    pending_inputs: []const []const u8 = &.{},
};

pub const RunEvent = struct {
    seq: u64,
    event_type: []u8,
    payload_json: []u8,
    created_at_ms: i64,

    pub fn deinit(self: *RunEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.event_type);
        allocator.free(self.payload_json);
        self.* = undefined;
    }
};

pub const RunEventInput = struct {
    run_id: []const u8,
    event_type: []const u8,
    payload_json: []const u8,
    created_at_ms: i64,
};

pub const RunStore = struct {
    allocator: std.mem.Allocator,
    mem_store: ?*ltm_store.VersionedMemStore,
    mutex: std.Thread.Mutex = .{},
    ephemeral_event_seq: std.StringHashMapUnmanaged(u64) = .{},

    pub fn init(allocator: std.mem.Allocator, mem_store: ?*ltm_store.VersionedMemStore) RunStore {
        return .{
            .allocator = allocator,
            .mem_store = mem_store,
        };
    }

    pub fn deinit(self: *RunStore) void {
        var it = self.ephemeral_event_seq.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.ephemeral_event_seq.deinit(self.allocator);
    }

    pub fn attachStore(self: *RunStore, mem_store: ?*ltm_store.VersionedMemStore) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.mem_store = mem_store;
    }

    pub fn persistMeta(self: *RunStore, meta: RunMetaInput) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const store = self.mem_store orelse return;
        const base_id = try std.fmt.allocPrint(self.allocator, "run:{s}:meta", .{meta.run_id});
        defer self.allocator.free(base_id);

        const payload = try buildMetaPayload(self.allocator, meta);
        defer self.allocator.free(payload);

        _ = try store.appendAt(base_id, "run.meta", payload, meta.updated_at_ms);
    }

    pub fn appendEvent(self: *RunStore, event: RunEventInput) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const base_id = try std.fmt.allocPrint(self.allocator, "run:{s}:events", .{event.run_id});
        defer self.allocator.free(base_id);

        if (self.mem_store) |store| {
            const payload = try buildEventPayload(self.allocator, event);
            defer self.allocator.free(payload);
            return store.appendAt(base_id, "run.event", payload, event.created_at_ms);
        }

        if (self.ephemeral_event_seq.getPtr(base_id)) |value| {
            value.* += 1;
            return value.*;
        }

        const owned_key = try self.allocator.dupe(u8, base_id);
        errdefer self.allocator.free(owned_key);
        try self.ephemeral_event_seq.put(self.allocator, owned_key, 1);
        return 1;
    }

    pub fn purgeRun(self: *RunStore, run_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var meta_base_buf: [512]u8 = undefined;
        const meta_base_id = try std.fmt.bufPrint(&meta_base_buf, "run:{s}:meta", .{run_id});
        var events_base_buf: [512]u8 = undefined;
        const events_base_id = try std.fmt.bufPrint(&events_base_buf, "run:{s}:events", .{run_id});

        if (self.mem_store) |store| {
            try store.deleteBaseId(meta_base_id);
            try store.deleteBaseId(events_base_id);
        } else {
            if (self.ephemeral_event_seq.fetchRemove(events_base_id)) |entry| {
                self.allocator.free(entry.key);
            }
        }
    }

    pub fn loadMeta(self: *RunStore, allocator: std.mem.Allocator, run_id: []const u8) !?RunMeta {
        self.mutex.lock();
        defer self.mutex.unlock();

        const store = self.mem_store orelse return null;
        const base_id = try std.fmt.allocPrint(self.allocator, "run:{s}:meta", .{run_id});
        defer self.allocator.free(base_id);

        var record = (try store.load(allocator, base_id, null)) orelse return null;
        defer record.deinit(allocator);

        const parsed = try parseMetaPayload(allocator, record.content_json);
        return parsed;
    }

    pub fn listRunIds(self: *RunStore, allocator: std.mem.Allocator, limit: usize) ![][]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const store = self.mem_store orelse return try allocator.alloc([]u8, 0);
        const base_ids = try store.listDistinctBaseIds(allocator, "run.meta", "run:%:meta", limit, 0);
        defer {
            for (base_ids) |base_id| allocator.free(base_id);
            allocator.free(base_ids);
        }

        var out = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (out.items) |id| allocator.free(id);
            out.deinit(allocator);
        }

        for (base_ids) |base_id| {
            const run_id = parseRunIdFromBase(base_id) orelse continue;
            try out.append(allocator, try allocator.dupe(u8, run_id));
        }

        return out.toOwnedSlice(allocator);
    }

    pub fn listEvents(self: *RunStore, allocator: std.mem.Allocator, run_id: []const u8, limit: usize) ![]RunEvent {
        self.mutex.lock();
        defer self.mutex.unlock();

        const store = self.mem_store orelse return try allocator.alloc(RunEvent, 0);
        const base_id = try std.fmt.allocPrint(self.allocator, "run:{s}:events", .{run_id});
        defer self.allocator.free(base_id);

        const records = try store.listVersions(allocator, base_id, limit);
        defer ltm_store.deinitRecords(allocator, records);

        var out = try allocator.alloc(RunEvent, records.len);
        var initialized: usize = 0;
        errdefer {
            var idx: usize = 0;
            while (idx < initialized) : (idx += 1) {
                out[idx].deinit(allocator);
            }
            allocator.free(out);
        }

        var write_index: usize = 0;
        var idx = records.len;
        while (idx > 0) {
            idx -= 1;
            const record = records[idx];
            var parsed = try parseEventPayload(allocator, record.content_json);
            parsed.seq = record.version;
            out[write_index] = parsed;
            write_index += 1;
            initialized += 1;
        }

        return out;
    }
};

pub fn deinitEvents(allocator: std.mem.Allocator, events: []RunEvent) void {
    for (events) |*event| event.deinit(allocator);
    allocator.free(events);
}

fn buildMetaPayload(allocator: std.mem.Allocator, meta: RunMetaInput) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"run_id\":\"");
    try appendEscaped(allocator, &out, meta.run_id);
    try out.appendSlice(allocator, "\",\"state\":\"");
    try appendEscaped(allocator, &out, meta.state);
    try out.appendSlice(allocator, "\",\"step_count\":");
    try out.writer(allocator).print("{d}", .{meta.step_count});
    try out.appendSlice(allocator, ",\"checkpoint_seq\":");
    try out.writer(allocator).print("{d}", .{meta.checkpoint_seq});
    try out.appendSlice(allocator, ",\"created_at_ms\":");
    try out.writer(allocator).print("{d}", .{meta.created_at_ms});
    try out.appendSlice(allocator, ",\"updated_at_ms\":");
    try out.writer(allocator).print("{d}", .{meta.updated_at_ms});

    try out.appendSlice(allocator, ",\"last_input\":");
    if (meta.last_input) |value| {
        try out.append(allocator, '"');
        try appendEscaped(allocator, &out, value);
        try out.append(allocator, '"');
    } else {
        try out.appendSlice(allocator, "null");
    }

    try out.appendSlice(allocator, ",\"last_output\":");
    if (meta.last_output) |value| {
        try out.append(allocator, '"');
        try appendEscaped(allocator, &out, value);
        try out.append(allocator, '"');
    } else {
        try out.appendSlice(allocator, "null");
    }

    try out.appendSlice(allocator, ",\"pending_inputs\":[");
    for (meta.pending_inputs, 0..) |value, idx| {
        if (idx > 0) try out.append(allocator, ',');
        try out.append(allocator, '"');
        try appendEscaped(allocator, &out, value);
        try out.append(allocator, '"');
    }
    try out.append(allocator, ']');

    try out.append(allocator, '}');
    return out.toOwnedSlice(allocator);
}

fn buildEventPayload(allocator: std.mem.Allocator, event: RunEventInput) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"event_type\":\"");
    try appendEscaped(allocator, &out, event.event_type);
    try out.appendSlice(allocator, "\",\"created_at_ms\":");
    try out.writer(allocator).print("{d}", .{event.created_at_ms});
    try out.appendSlice(allocator, ",\"payload\":");
    try out.appendSlice(allocator, event.payload_json);
    try out.append(allocator, '}');

    return out.toOwnedSlice(allocator);
}

fn parseMetaPayload(allocator: std.mem.Allocator, payload_json: []const u8) !RunMeta {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return RunStoreError.InvalidRunRecord;
    const obj = parsed.value.object;

    const run_id = stringField(obj, "run_id") orelse return RunStoreError.InvalidRunRecord;
    const state = stringField(obj, "state") orelse return RunStoreError.InvalidRunRecord;
    const step_count = intField(obj, "step_count") orelse return RunStoreError.InvalidRunRecord;
    const checkpoint_seq = intField(obj, "checkpoint_seq") orelse return RunStoreError.InvalidRunRecord;
    const created_at_ms = intField(obj, "created_at_ms") orelse return RunStoreError.InvalidRunRecord;
    const updated_at_ms = intField(obj, "updated_at_ms") orelse return RunStoreError.InvalidRunRecord;
    const pending_inputs = if (obj.get("pending_inputs")) |value|
        try parsePendingInputs(allocator, value)
    else
        try allocator.alloc([]u8, 0);
    errdefer {
        for (pending_inputs) |value| allocator.free(value);
        allocator.free(pending_inputs);
    }

    const owned_run_id = try allocator.dupe(u8, run_id);
    errdefer allocator.free(owned_run_id);
    const owned_state = try allocator.dupe(u8, state);
    errdefer allocator.free(owned_state);
    const owned_last_input = if (stringField(obj, "last_input")) |value| try allocator.dupe(u8, value) else null;
    errdefer if (owned_last_input) |value| allocator.free(value);
    const owned_last_output = if (stringField(obj, "last_output")) |value| try allocator.dupe(u8, value) else null;
    errdefer if (owned_last_output) |value| allocator.free(value);

    return .{
        .run_id = owned_run_id,
        .state = owned_state,
        .step_count = @intCast(step_count),
        .checkpoint_seq = @intCast(checkpoint_seq),
        .created_at_ms = created_at_ms,
        .updated_at_ms = updated_at_ms,
        .last_input = owned_last_input,
        .last_output = owned_last_output,
        .pending_inputs = pending_inputs,
    };
}

fn parsePendingInputs(allocator: std.mem.Allocator, value: std.json.Value) ![][]u8 {
    if (value != .array) return RunStoreError.InvalidRunRecord;

    var out = std.ArrayListUnmanaged([]u8){};
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }

    for (value.array.items) |item| {
        if (item != .string) return RunStoreError.InvalidRunRecord;
        try out.append(allocator, try allocator.dupe(u8, item.string));
    }

    return out.toOwnedSlice(allocator);
}

fn parseEventPayload(allocator: std.mem.Allocator, payload_json: []const u8) !RunEvent {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return RunStoreError.InvalidRunEvent;
    const obj = parsed.value.object;

    const event_type = stringField(obj, "event_type") orelse return RunStoreError.InvalidRunEvent;
    const created_at_ms = intField(obj, "created_at_ms") orelse return RunStoreError.InvalidRunEvent;

    const payload_value = obj.get("payload") orelse return RunStoreError.InvalidRunEvent;
    const payload = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(payload_value, .{})});

    return .{
        .seq = 0,
        .event_type = try allocator.dupe(u8, event_type),
        .payload_json = payload,
        .created_at_ms = created_at_ms,
    };
}

fn parseRunIdFromBase(base_id: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, base_id, "run:")) return null;
    const suffix = base_id[4..];
    const marker = ":meta";
    if (!std.mem.endsWith(u8, suffix, marker)) return null;
    return suffix[0 .. suffix.len - marker.len];
}

fn appendEscaped(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
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
}

fn stringField(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = obj.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn intField(obj: std.json.ObjectMap, name: []const u8) ?i64 {
    const value = obj.get(name) orelse return null;
    if (value != .integer) return null;
    return value.integer;
}

test "run_store: persists and loads run metadata and events" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-store-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    var store = RunStore.init(allocator, &mem_store);
    defer store.deinit();

    try store.persistMeta(.{
        .run_id = "run-1",
        .state = "running",
        .step_count = 1,
        .checkpoint_seq = 1,
        .created_at_ms = 1,
        .updated_at_ms = 2,
        .last_input = "hello",
        .last_output = "world",
        .pending_inputs = &.{ "queued-1", "queued-2" },
    });

    const seq = try store.appendEvent(.{
        .run_id = "run-1",
        .event_type = "run.started",
        .payload_json = "{\"ok\":true}",
        .created_at_ms = 3,
    });
    try std.testing.expectEqual(@as(u64, 1), seq);

    var loaded = (try store.loadMeta(allocator, "run-1")).?;
    defer loaded.deinit(allocator);
    try std.testing.expectEqualStrings("run-1", loaded.run_id);
    try std.testing.expectEqualStrings("running", loaded.state);
    try std.testing.expectEqual(@as(usize, 2), loaded.pending_inputs.len);
    try std.testing.expectEqualStrings("queued-1", loaded.pending_inputs[0]);

    const ids = try store.listRunIds(allocator, 10);
    defer {
        for (ids) |id| allocator.free(id);
        allocator.free(ids);
    }
    try std.testing.expectEqual(@as(usize, 1), ids.len);

    const events = try store.listEvents(allocator, "run-1", 10);
    defer deinitEvents(allocator, events);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("run.started", events[0].event_type);
}

test "run_store: listEvents handles partially parsed records without invalid deinit" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-store-partial-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    _ = try mem_store.appendAt("run:run-1:events", "run.event", "{\"event_type\":\"run.started\",\"created_at_ms\":1,\"payload\":{\"ok\":true}}", 1);
    _ = try mem_store.appendAt("run:run-1:events", "run.event", "{\"event_type\":\"run.broken\",\"payload\":{\"ok\":false}}", 2);

    var store = RunStore.init(allocator, &mem_store);
    defer store.deinit();

    try std.testing.expectError(RunStoreError.InvalidRunEvent, store.listEvents(allocator, "run-1", 10));
}

test "run_store: loadMeta accepts records without pending_inputs" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-store-legacy-meta-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    _ = try mem_store.appendAt(
        "run:run-legacy:meta",
        "run.meta",
        "{\"run_id\":\"run-legacy\",\"state\":\"paused\",\"step_count\":2,\"checkpoint_seq\":1,\"created_at_ms\":1,\"updated_at_ms\":2,\"last_input\":null,\"last_output\":null}",
        2,
    );

    var store = RunStore.init(allocator, &mem_store);
    defer store.deinit();

    var loaded = (try store.loadMeta(allocator, "run-legacy")).?;
    defer loaded.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), loaded.pending_inputs.len);
}

test "run_store: purgeRun removes persisted metadata and events" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-store-purge-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    var store = RunStore.init(allocator, &mem_store);
    defer store.deinit();

    try store.persistMeta(.{
        .run_id = "run-purge",
        .state = "created",
        .step_count = 0,
        .checkpoint_seq = 0,
        .created_at_ms = 1,
        .updated_at_ms = 1,
    });
    _ = try store.appendEvent(.{
        .run_id = "run-purge",
        .event_type = "run.started",
        .payload_json = "{}",
        .created_at_ms = 1,
    });

    try store.purgeRun("run-purge");

    const meta = try store.loadMeta(allocator, "run-purge");
    try std.testing.expect(meta == null);

    const events = try store.listEvents(allocator, "run-purge", 10);
    defer deinitEvents(allocator, events);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "run_store: listRunIds returns distinct runs even with heavy metadata churn" {
    const allocator = std.testing.allocator;

    const dir = try std.fmt.allocPrint(allocator, ".tmp-run-store-run-ids-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);

    var mem_store = try ltm_store.VersionedMemStore.open(allocator, dir, "run.db");
    defer mem_store.close();

    var store = RunStore.init(allocator, &mem_store);
    defer store.deinit();

    try store.persistMeta(.{
        .run_id = "run-older",
        .state = "created",
        .step_count = 0,
        .checkpoint_seq = 0,
        .created_at_ms = 1,
        .updated_at_ms = 1,
    });

    var i: u64 = 0;
    while (i < 128) : (i += 1) {
        try store.persistMeta(.{
            .run_id = "run-busy",
            .state = "running",
            .step_count = i,
            .checkpoint_seq = i,
            .created_at_ms = 2,
            .updated_at_ms = @as(i64, @intCast(100 + i)),
        });
    }

    const ids = try store.listRunIds(allocator, 2);
    defer {
        for (ids) |id| allocator.free(id);
        allocator.free(ids);
    }

    try std.testing.expectEqual(@as(usize, 2), ids.len);
    try std.testing.expectEqualStrings("run-busy", ids[0]);
    try std.testing.expectEqualStrings("run-older", ids[1]);
}
