const std = @import("std");
const ziggy_piai = @import("ziggy-piai");
const memory = @import("memory.zig");

const sqlite3 = opaque {};
const sqlite3_stmt = opaque {};

extern fn sqlite3_open_v2(
    filename: [*:0]const u8,
    db: **sqlite3,
    flags: i32,
    vfs: ?[*:0]const u8,
) i32;
extern fn sqlite3_close(db: *sqlite3) i32;
extern fn sqlite3_errmsg(db: *sqlite3) [*:0]const u8;
extern fn sqlite3_prepare_v2(
    db: *sqlite3,
    sql: [*]const u8,
    n_byte: i32,
    statement: **sqlite3_stmt,
    tail: ?**u8,
) i32;
extern fn sqlite3_step(statement: *sqlite3_stmt) i32;
extern fn sqlite3_finalize(statement: *sqlite3_stmt) i32;
extern fn sqlite3_column_int64(statement: *sqlite3_stmt, column: i32) i64;
extern fn sqlite3_column_text(statement: *sqlite3_stmt, column: i32) ?[*:0]const u8;
extern fn sqlite3_column_type(statement: *sqlite3_stmt, column: i32) i32;
extern fn sqlite3_last_insert_rowid(db: *sqlite3) i64;

const SQLITE_OK: i32 = 0;
const SQLITE_ROW: i32 = 100;
const SQLITE_DONE: i32 = 101;
const SQLITE_NULL: i32 = 5;
const SQLITE_OPEN_READWRITE: i32 = 0x00000002;
const SQLITE_OPEN_CREATE: i32 = 0x00000004;
const SQLITE_OPEN_FULLMUTEX: i32 = 0x00010000;

pub const LtmError = error{
    OpenError,
    PrepareError,
    ExecError,
    InvalidData,
};

pub const Snapshot = struct {
    id: i64,
    timestamp_ms: i64,
    reason: []const u8,
    next_id: u64,
    entry_count: usize,
    summary_count: usize,
};

pub const SummaryRecord = struct {
    id: u64,
    source_id: u64,
    text: []const u8,
    created_at_ms: i64,
};

pub const EntryRecord = struct {
    id: u64,
    role: []const u8,
    state: []const u8,
    related_to: ?u64,
    content: []const u8,
};

pub const SnapshotData = struct {
    snapshot: Snapshot,
    summaries: std.ArrayListUnmanaged(SummaryRecord),
    entries: std.ArrayListUnmanaged(EntryRecord),

    pub fn deinit(self: *SnapshotData, allocator: std.mem.Allocator) void {
        allocator.free(self.snapshot.reason);
        for (self.summaries.items) |*summary| {
            allocator.free(summary.text);
        }
        self.summaries.deinit(allocator);

        for (self.entries.items) |*entry| {
            allocator.free(entry.role);
            allocator.free(entry.state);
            allocator.free(entry.content);
        }
        self.entries.deinit(allocator);
    }
};

pub const SessionMetadata = struct {
    session_id: []const u8,
    agent_id: []const u8,
    created_at_ms: i64,
    last_active_ms: i64,
    message_count: i64,
    is_active: bool,
    summary: ?[]const u8,

    pub fn deinit(self: *SessionMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.session_id);
        allocator.free(self.agent_id);
        if (self.summary) |s| allocator.free(s);
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    db: *sqlite3,

    pub fn open(
        allocator: std.mem.Allocator,
        directory: []const u8,
        filename: []const u8,
    ) !Store {
        _ = try std.fs.cwd().makeOpenPath(directory, .{});

        const db_path = try std.fs.path.join(allocator, &.{ directory, filename });
        defer allocator.free(db_path);
        const db_path_z = try allocator.dupeZ(u8, db_path);
        defer allocator.free(db_path_z);

        var db: *sqlite3 = undefined;
        const open_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
        const rc = sqlite3_open_v2(db_path_z, &db, open_flags, null);
        if (rc != SQLITE_OK) {
            return LtmError.OpenError;
        }

        var store = Store{
            .allocator = allocator,
            .db = db,
        };
        errdefer store.deinit();

        try store.initSchema();
        return store;
    }

    pub fn deinit(self: *Store) void {
        _ = sqlite3_close(self.db);
    }

    pub fn close(self: *Store) void {
        self.deinit();
    }

    pub fn archiveRamSnapshot(
        self: *Store,
        session_id: []const u8,
        reason: []const u8,
        ram: *const memory.RamContext,
    ) !bool {
        const now_ms = std.time.milliTimestamp();
        return self.archiveRamSnapshotAtTimestamp(session_id, reason, ram, now_ms);
    }

    pub fn archiveRamSnapshotAtTimestamp(
        self: *Store,
        session_id: []const u8,
        reason: []const u8,
        ram: *const memory.RamContext,
        timestamp_ms: i64,
    ) !bool {
        if (ram.entries.items.len == 0 and ram.summaries.items.len == 0) {
            return false;
        }

        const session_id_escaped = try self.escapeSqlLiteral(session_id);
        defer self.allocator.free(session_id_escaped);
        const reason_escaped = try self.escapeSqlLiteral(reason);
        defer self.allocator.free(reason_escaped);

        try self.run("BEGIN IMMEDIATE;");
        errdefer self.run("ROLLBACK;") catch {};

        const upsert_session = try std.fmt.allocPrint(
            self.allocator,
            "INSERT INTO sessions(session_id, created_at_ms, updated_at_ms, next_id) VALUES ({s}, {d}, {d}, {d}) " ++
                "ON CONFLICT(session_id) DO UPDATE SET updated_at_ms = {d}, next_id = {d};",
            .{ session_id_escaped, timestamp_ms, timestamp_ms, ram.next_id, timestamp_ms, ram.next_id },
        );
        defer self.allocator.free(upsert_session);

        try self.run(upsert_session);

        const insert_snapshot = try std.fmt.allocPrint(
            self.allocator,
            "INSERT INTO ram_snapshots(session_id, timestamp_ms, reason, next_id, entry_count, summary_count) " ++
                "VALUES ({s}, {d}, {s}, {d}, {d}, {d});",
            .{
                session_id_escaped,
                timestamp_ms,
                reason_escaped,
                ram.next_id,
                ram.entries.items.len,
                ram.summaries.items.len,
            },
        );
        defer self.allocator.free(insert_snapshot);
        try self.run(insert_snapshot);
        const snapshot_id = sqlite3_last_insert_rowid(self.db);

        for (ram.summaries.items) |summary| {
            const summary_text = try self.escapeSqlLiteral(summary.text);
            defer self.allocator.free(summary_text);

            const insert_summary = try std.fmt.allocPrint(
                self.allocator,
                "INSERT INTO summaries(snapshot_id, memory_id, source_id, text, created_at_ms) VALUES ({d}, {d}, {d}, {s}, {d});",
                .{ snapshot_id, summary.id, summary.source_id, summary_text, summary.created_at_ms },
            );
            defer self.allocator.free(insert_summary);
            try self.run(insert_summary);
        }

        for (ram.entries.items) |entry| {
            const role_name = roleToString(entry.message.role);
            const state_name = if (entry.state == .active) "active" else "tombstone";
            const role_escaped = try self.escapeSqlLiteral(role_name);
            defer self.allocator.free(role_escaped);
            const state_escaped = try self.escapeSqlLiteral(state_name);
            defer self.allocator.free(state_escaped);
            const content_escaped = try self.escapeSqlLiteral(entry.message.content);
            defer self.allocator.free(content_escaped);

            const insert_entry = if (entry.related_to) |related_to|
                try std.fmt.allocPrint(
                    self.allocator,
                    "INSERT INTO entries(snapshot_id, memory_id, role, state, related_to, content, created_at_ms) VALUES ({d}, {d}, {s}, {s}, {d}, {s}, {d});",
                    .{
                        snapshot_id,
                        entry.id,
                        role_escaped,
                        state_escaped,
                        related_to,
                        content_escaped,
                        timestamp_ms,
                    },
                )
            else
                try std.fmt.allocPrint(
                    self.allocator,
                    "INSERT INTO entries(snapshot_id, memory_id, role, state, related_to, content, created_at_ms) VALUES ({d}, {d}, {s}, {s}, NULL, {s}, {d});",
                    .{ snapshot_id, entry.id, role_escaped, state_escaped, content_escaped, timestamp_ms },
                );
            defer self.allocator.free(insert_entry);
            try self.run(insert_entry);
        }

        const event_payload = try self.escapeSqlLiteral(reason);
        defer self.allocator.free(event_payload);
        const insert_event = try std.fmt.allocPrint(
            self.allocator,
            "INSERT INTO ltm_events(session_id, event_type, created_at_ms, details) VALUES ({s}, 'snapshot', {d}, {s});",
            .{ session_id_escaped, timestamp_ms, event_payload },
        );
        defer self.allocator.free(insert_event);
        try self.run(insert_event);

        try self.run("COMMIT;");
        return true;
    }

    pub fn pruneSnapshots(
        self: *Store,
        older_than_ms: ?i64,
        max_snapshots_per_session: ?usize,
    ) !usize {
        if (older_than_ms == null and max_snapshots_per_session == null) return 0;

        var delete_ids = std.ArrayListUnmanaged(i64){};
        defer delete_ids.deinit(self.allocator);

        try self.run("BEGIN IMMEDIATE;");
        errdefer self.run("ROLLBACK;") catch {};

        if (older_than_ms) |cutoff| {
            try self.collectSnapshotIdsOlderThan(cutoff, &delete_ids);
        }

        if (max_snapshots_per_session) |max_keep| {
            try self.collectSnapshotsBySessionLimit(max_keep, &delete_ids);
        }

        for (delete_ids.items) |snapshot_id| {
            const snapshot_id_u = @as(i64, snapshot_id);
            try self.deleteSnapshotById(snapshot_id_u);
        }

        try self.run("DELETE FROM sessions WHERE session_id NOT IN (SELECT DISTINCT session_id FROM ram_snapshots);");
        try self.run("COMMIT;");
        return delete_ids.items.len;
    }

    pub fn countSnapshotsForSession(self: *Store, session_id: []const u8) !usize {
        const session_id_escaped = try self.escapeSqlLiteral(session_id);
        defer self.allocator.free(session_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT COUNT(*) FROM ram_snapshots WHERE session_id = {s};",
            .{session_id_escaped},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) return 0;
        if (rc != SQLITE_ROW) return LtmError.ExecError;

        const count = try self.columnToU64(stmt, 0);
        return @as(usize, @intCast(count));
    }

    pub fn migrateLegacyArchives(self: *Store, index_path: []const u8) !u32 {
        const index_file = std.fs.cwd().openFile(index_path, .{ .mode = .read_only }) catch |err| {
            if (err == error.FileNotFound) return 0;
            return err;
        };
        defer index_file.close();

        const data = try index_file.readToEndAlloc(self.allocator, 4 * 1024 * 1024);
        defer self.allocator.free(data);

        var imported_count: u32 = 0;
        var lines = std.mem.splitSequence(u8, data, "\n");

        while (lines.next()) |line| {
            if (line.len == 0) continue;

            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;

            const value_session = parsed.value.object.get("session_id") orelse continue;
            if (value_session != .string) continue;
            const session_id = value_session.string;

            const timestamp_ms = parseIntegerField(parsed.value.object.get("timestamp_ms") orelse continue) orelse continue;
            const reason_value = parsed.value.object.get("reason") orelse continue;
            if (reason_value != .string) continue;
            if (try self.hasSnapshotAtTimestamp(session_id, timestamp_ms)) continue;

            const archive_value = parsed.value.object.get("archive_path") orelse continue;
            if (archive_value != .string) continue;

            var imported = try self.loadLegacyArchive(archive_value.string);
            defer imported.deinit();

            if (imported.entries.items.len == 0 and imported.summaries.items.len == 0) continue;

            _ = try self.archiveRamSnapshotAtTimestamp(session_id, reason_value.string, &imported, timestamp_ms);
            imported_count += 1;
        }

        return imported_count;
    }

    pub fn loadLatestSnapshot(self: *Store, session_id: []const u8) !?SnapshotData {
        const snapshot = try self.fetchLatestSnapshot(session_id) orelse return null;
        return self.loadSnapshotById(snapshot.id);
    }

    pub fn loadSnapshotsForSession(
        self: *Store,
        session_id: []const u8,
        max_snapshots: ?usize,
    ) !std.ArrayListUnmanaged(SnapshotData) {
        var snapshots = std.ArrayListUnmanaged(SnapshotData){};
        errdefer {
            for (snapshots.items) |*snapshot| snapshot.deinit(self.allocator);
            snapshots.deinit(self.allocator);
        }

        var snapshot_ids = std.ArrayListUnmanaged(i64){};
        defer snapshot_ids.deinit(self.allocator);

        try self.collectSnapshotIdsForSession(session_id, max_snapshots, &snapshot_ids);
        for (snapshot_ids.items) |snapshot_id| {
            if (try self.loadSnapshotById(snapshot_id)) |snapshot_data| {
                try snapshots.append(self.allocator, snapshot_data);
            }
        }

        return snapshots;
    }

    pub fn loadSnapshotById(self: *Store, snapshot_id: i64) !?SnapshotData {
        const snapshot = try self.fetchSnapshotById(snapshot_id) orelse return null;
        var loaded = SnapshotData{
            .snapshot = snapshot,
            .summaries = .{},
            .entries = .{},
        };
        var loaded_ok = false;
        errdefer if (!loaded_ok) loaded.deinit(self.allocator);

        loaded.summaries = try self.loadSummariesForSnapshot(snapshot.id);
        loaded.entries = try self.loadEntriesForSnapshot(snapshot.id);
        loaded_ok = true;

        return loaded;
    }

    fn fetchLatestSnapshot(self: *Store, session_id: []const u8) !?Snapshot {
        const session_id_escaped = try self.escapeSqlLiteral(session_id);
        defer self.allocator.free(session_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT id, timestamp_ms, reason, next_id, entry_count, summary_count " ++
                "FROM ram_snapshots WHERE session_id = {s} ORDER BY timestamp_ms DESC, id DESC LIMIT 1;",
            .{session_id_escaped},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) return null;
        if (rc != SQLITE_ROW) return LtmError.ExecError;

        const id = sqlite3_column_int64(stmt, 0);
        const created_at_ms = sqlite3_column_int64(stmt, 1);
        const reason = try self.copyColumnText(stmt, 2);
        const next_id = try self.columnToU64(stmt, 3);
        const entry_count = try self.columnToU64(stmt, 4);
        const summary_count = try self.columnToU64(stmt, 5);

        return Snapshot{
            .id = id,
            .timestamp_ms = created_at_ms,
            .reason = reason,
            .next_id = next_id,
            .entry_count = @as(usize, @intCast(entry_count)),
            .summary_count = @as(usize, @intCast(summary_count)),
        };
    }

    fn fetchSnapshotById(self: *Store, snapshot_id: i64) !?Snapshot {
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT id, timestamp_ms, reason, next_id, entry_count, summary_count " ++
                "FROM ram_snapshots WHERE id = {d};",
            .{snapshot_id},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) return null;
        if (rc != SQLITE_ROW) return LtmError.ExecError;

        const id = sqlite3_column_int64(stmt, 0);
        const created_at_ms = sqlite3_column_int64(stmt, 1);
        const reason = try self.copyColumnText(stmt, 2);
        const next_id = try self.columnToU64(stmt, 3);
        const entry_count = try self.columnToU64(stmt, 4);
        const summary_count = try self.columnToU64(stmt, 5);

        return Snapshot{
            .id = id,
            .timestamp_ms = created_at_ms,
            .reason = reason,
            .next_id = next_id,
            .entry_count = @as(usize, @intCast(entry_count)),
            .summary_count = @as(usize, @intCast(summary_count)),
        };
    }

    fn collectSnapshotIdsForSession(
        self: *Store,
        session_id: []const u8,
        max_snapshots: ?usize,
        ids: *std.ArrayListUnmanaged(i64),
    ) !void {
        if (max_snapshots) |max| {
            if (max == 0) return;
        }

        const session_id_escaped = try self.escapeSqlLiteral(session_id);
        defer self.allocator.free(session_id_escaped);

        const sql = if (max_snapshots) |max_snapshots_value|
            try std.fmt.allocPrint(
                self.allocator,
                "SELECT id FROM ram_snapshots WHERE session_id = {s} ORDER BY timestamp_ms DESC, id DESC LIMIT {d};",
                .{ session_id_escaped, max_snapshots_value },
            )
        else
            try std.fmt.allocPrint(
                self.allocator,
                "SELECT id FROM ram_snapshots WHERE session_id = {s} ORDER BY timestamp_ms DESC, id DESC;",
                .{session_id_escaped},
            );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            const snapshot_id = sqlite3_column_int64(stmt, 0);
            try ids.append(self.allocator, snapshot_id);
        }
    }

    fn collectSnapshotIdsOlderThan(self: *Store, cutoff_ms: i64, ids: *std.ArrayListUnmanaged(i64)) !void {
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT id FROM ram_snapshots WHERE timestamp_ms < {d} ORDER BY timestamp_ms ASC, id ASC;",
            .{cutoff_ms},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            const snapshot_id = sqlite3_column_int64(stmt, 0);
            try appendUniqueI64(self.allocator, ids, snapshot_id);
        }
    }

    fn collectSnapshotsBySessionLimit(self: *Store, max_keep: usize, ids: *std.ArrayListUnmanaged(i64)) !void {
        const sql = "SELECT session_id, id FROM ram_snapshots ORDER BY session_id ASC, timestamp_ms DESC, id DESC;";
        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        var current_session: ?[]const u8 = null;
        defer if (current_session) |session| self.allocator.free(session);

        var seen_in_session: usize = 0;

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            const session_id = try self.copyColumnText(stmt, 0);
            defer self.allocator.free(session_id);
            const snapshot_id = sqlite3_column_int64(stmt, 1);

            if (current_session) |active_session| {
                if (!std.mem.eql(u8, session_id, active_session)) {
                    seen_in_session = 1;
                    const replacement = try self.allocator.dupe(u8, session_id);
                    if (current_session) |old| self.allocator.free(old);
                    current_session = replacement;
                } else {
                    seen_in_session += 1;
                }
            } else {
                current_session = try self.allocator.dupe(u8, session_id);
                seen_in_session = 1;
            }

            if (seen_in_session > max_keep) {
                try appendUniqueI64(self.allocator, ids, snapshot_id);
            }
        }

    }

    fn deleteSnapshotById(self: *Store, snapshot_id: i64) !void {
        const delete_entries = try std.fmt.allocPrint(
            self.allocator,
            "DELETE FROM entries WHERE snapshot_id = {d};",
            .{snapshot_id},
        );
        defer self.allocator.free(delete_entries);
        try self.run(delete_entries);

        const delete_summaries = try std.fmt.allocPrint(
            self.allocator,
            "DELETE FROM summaries WHERE snapshot_id = {d};",
            .{snapshot_id},
        );
        defer self.allocator.free(delete_summaries);
        try self.run(delete_summaries);

        const delete_snapshot = try std.fmt.allocPrint(
            self.allocator,
            "DELETE FROM ram_snapshots WHERE id = {d};",
            .{snapshot_id},
        );
        defer self.allocator.free(delete_snapshot);
        try self.run(delete_snapshot);
    }

    fn hasSnapshotAtTimestamp(self: *Store, session_id: []const u8, timestamp_ms: i64) !bool {
        const session_id_escaped = try self.escapeSqlLiteral(session_id);
        defer self.allocator.free(session_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT id FROM ram_snapshots WHERE session_id = {s} AND timestamp_ms = {d} LIMIT 1;",
            .{ session_id_escaped, timestamp_ms },
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) return false;
        if (rc != SQLITE_ROW) return LtmError.ExecError;
        return true;
    }

    fn loadLegacyArchive(self: *Store, archive_path: []const u8) !memory.RamContext {
        const file = std.fs.cwd().openFile(archive_path, .{ .mode = .read_only }) catch return LtmError.InvalidData;
        defer file.close();

        const data = try file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
        defer self.allocator.free(data);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, data, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return LtmError.InvalidData;

        var ram = memory.RamContext.init(self.allocator, 1024 * 1024, 8 * 1024 * 1024);
        errdefer ram.deinit();

        const next_id = if (parsed.value.object.get("next_id")) |next_id_value|
            parsePositiveInteger(next_id_value) orelse 1
        else
            1;
        ram.setNextId(next_id);

        if (parsed.value.object.get("summaries")) |summaries| {
            if (summaries == .array) {
                for (summaries.array.items) |summary_value| {
                    if (summary_value != .object) continue;
                    const summary_obj = summary_value.object;

                    const summary_id = parsePositiveInteger(summary_obj.get("id") orelse continue) orelse continue;
                    const source_id = parsePositiveInteger(summary_obj.get("source_id") orelse continue) orelse continue;
                    const text_value = summary_obj.get("text") orelse continue;
                    if (text_value != .string) continue;
                    const created_at_ms = if (summary_obj.get("created_at_ms")) |created|
                        parseIntegerField(created) orelse 0
                    else
                        0;

                    try ram.restoreSummary(summary_id, source_id, text_value.string, created_at_ms);
                }
            }
        }

        if (parsed.value.object.get("entries")) |entries| {
            if (entries == .array) {
                for (entries.array.items) |entry_value| {
                    if (entry_value != .object) continue;
                    const entry_obj = entry_value.object;

                    const id = parsePositiveInteger(entry_obj.get("id") orelse continue) orelse continue;
                    const role_value = entry_obj.get("role") orelse continue;
                    if (role_value != .string) continue;
                    const role = parseRole(role_value.string) orelse continue;
                    const state_value = entry_obj.get("state") orelse continue;
                    if (state_value != .string) continue;
                    const state = parseRamEntryState(state_value.string) orelse continue;
                    const content_value = entry_obj.get("content") orelse continue;
                    if (content_value != .string) continue;

                    const related_to = if (entry_obj.get("related_to")) |related| blk: {
                        if (related == .null) break :blk null;
                        break :blk parsePositiveInteger(related);
                    } else null;

                    try ram.restoreEntry(id, role, state, related_to, content_value.string);
                }
            }
        }

        return ram;
    }

    fn loadSummariesForSnapshot(self: *Store, snapshot_id: i64) !std.ArrayListUnmanaged(SummaryRecord) {
        var summaries = std.ArrayListUnmanaged(SummaryRecord){};
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT memory_id, source_id, text, created_at_ms FROM summaries WHERE snapshot_id = {d} ORDER BY id DESC;",
            .{snapshot_id},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            const id = try self.columnToU64(stmt, 0);
            const source_id = try self.columnToU64(stmt, 1);
            const text = try self.copyColumnText(stmt, 2);
            const created_at_ms = sqlite3_column_int64(stmt, 3);

            try summaries.append(self.allocator, .{
                .id = id,
                .source_id = source_id,
                .text = text,
                .created_at_ms = created_at_ms,
            });
        }

        return summaries;
    }

    fn loadEntriesForSnapshot(self: *Store, snapshot_id: i64) !std.ArrayListUnmanaged(EntryRecord) {
        var entries = std.ArrayListUnmanaged(EntryRecord){};
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT memory_id, role, state, related_to, content FROM entries WHERE snapshot_id = {d} ORDER BY id DESC;",
            .{snapshot_id},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            const id = try self.columnToU64(stmt, 0);
            const role = try self.copyColumnText(stmt, 1);
            const state = try self.copyColumnText(stmt, 2);
            const related_to = if (sqlite3_column_type(stmt, 3) == SQLITE_NULL)
                null
            else
                try self.columnToU64(stmt, 3);
            const content = try self.copyColumnText(stmt, 4);

            try entries.append(self.allocator, .{
                .id = id,
                .role = role,
                .state = state,
                .related_to = related_to,
                .content = content,
            });
        }

        return entries;
    }

    fn initSchema(self: *Store) !void {
        const statements = [_][]const u8{
            "PRAGMA foreign_keys = ON;",
            "CREATE TABLE IF NOT EXISTS sessions("
            ++ "session_id TEXT PRIMARY KEY,"
            ++ "created_at_ms INTEGER NOT NULL,"
            ++ "updated_at_ms INTEGER NOT NULL,"
            ++ "next_id INTEGER NOT NULL"
            ++ ");",
            "CREATE TABLE IF NOT EXISTS ram_snapshots("
            ++ "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            ++ "session_id TEXT NOT NULL,"
            ++ "timestamp_ms INTEGER NOT NULL,"
            ++ "reason TEXT NOT NULL,"
            ++ "next_id INTEGER NOT NULL,"
            ++ "entry_count INTEGER NOT NULL,"
            ++ "summary_count INTEGER NOT NULL,"
            ++ "FOREIGN KEY(session_id) REFERENCES sessions(session_id)"
            ++ ");",
            "CREATE TABLE IF NOT EXISTS summaries("
            ++ "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            ++ "snapshot_id INTEGER NOT NULL,"
            ++ "memory_id INTEGER NOT NULL,"
            ++ "source_id INTEGER NOT NULL,"
            ++ "text TEXT NOT NULL,"
            ++ "created_at_ms INTEGER NOT NULL,"
            ++ "FOREIGN KEY(snapshot_id) REFERENCES ram_snapshots(id)"
            ++ ");",
            "CREATE TABLE IF NOT EXISTS entries("
            ++ "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            ++ "snapshot_id INTEGER NOT NULL,"
            ++ "memory_id INTEGER NOT NULL,"
            ++ "role TEXT NOT NULL,"
            ++ "state TEXT NOT NULL,"
            ++ "related_to INTEGER,"
            ++ "content TEXT NOT NULL,"
            ++ "created_at_ms INTEGER NOT NULL,"
            ++ "FOREIGN KEY(snapshot_id) REFERENCES ram_snapshots(id)"
            ++ ");",
            "CREATE TABLE IF NOT EXISTS ltm_events("
            ++ "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            ++ "session_id TEXT NOT NULL,"
            ++ "event_type TEXT NOT NULL,"
            ++ "memory_id INTEGER,"
            ++ "created_at_ms INTEGER NOT NULL,"
            ++ "details TEXT"
            ++ ");",
            "CREATE INDEX IF NOT EXISTS idx_ram_snapshots_session ON ram_snapshots(session_id, timestamp_ms);",
            "CREATE INDEX IF NOT EXISTS idx_summaries_snapshot ON summaries(snapshot_id);",
            "CREATE INDEX IF NOT EXISTS idx_entries_snapshot ON entries(snapshot_id);",
            "CREATE TABLE IF NOT EXISTS session_metadata("
            ++ "session_id TEXT PRIMARY KEY,"
            ++ "agent_id TEXT NOT NULL,"
            ++ "created_at_ms INTEGER NOT NULL,"
            ++ "last_active_ms INTEGER NOT NULL,"
            ++ "message_count INTEGER NOT NULL,"
            ++ "is_active INTEGER NOT NULL DEFAULT 1,"
            ++ "summary TEXT"
            ++ ");",
            "CREATE INDEX IF NOT EXISTS idx_session_metadata_agent ON session_metadata(agent_id, last_active_ms);",
            "CREATE INDEX IF NOT EXISTS idx_session_metadata_active ON session_metadata(agent_id, is_active, last_active_ms);",
        };

        for (statements) |statement| {
            try self.run(statement);
        }
    }

    fn run(self: *Store, sql: []const u8) !void {
        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            return self.raiseError("sqlite3 step", rc);
        }
    }

    fn prepare(self: *Store, sql: []const u8) !*sqlite3_stmt {
        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var statement: *sqlite3_stmt = undefined;
        const rc = sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &statement, null);
        if (rc != SQLITE_OK) {
            self.raiseError("sqlite3 prepare", rc) catch |err| return err;
        }
        return statement;
    }

    fn columnToU64(self: *Store, statement: *sqlite3_stmt, column: i32) !u64 {
        _ = self;
        const raw = sqlite3_column_int64(statement, column);
        if (raw < 0) return LtmError.InvalidData;
        return @intCast(raw);
    }

    fn copyColumnText(self: *Store, statement: *sqlite3_stmt, column: i32) ![]u8 {
        const raw = sqlite3_column_text(statement, column) orelse return LtmError.InvalidData;
        return self.allocator.dupe(u8, std.mem.span(raw));
    }

fn appendUniqueI64(allocator: std.mem.Allocator, ids: *std.ArrayListUnmanaged(i64), value: i64) !void {
        for (ids.items) |existing| {
            if (existing == value) return;
        }
            try ids.append(allocator, value);
        }

    fn escapeSqlLiteral(self: *Store, value: []const u8) ![]u8 {
        var escaped = std.ArrayListUnmanaged(u8){};

        try escaped.append(self.allocator, '\'');
        for (value) |value_byte| {
            if (value_byte == '\'') {
                try escaped.appendSlice(self.allocator, "''");
            } else {
                try escaped.append(self.allocator, value_byte);
            }
        }
        try escaped.append(self.allocator, '\'');
        return try escaped.toOwnedSlice(self.allocator);
    }


    // Session metadata functions for agent discovery and restore
    pub fn updateSessionMetadata(
        self: *Store,
        session_id: []const u8,
        agent_id: []const u8,
        message_count: i64,
    ) !void {
        const now_ms = std.time.milliTimestamp();
        const session_id_escaped = try self.escapeSqlLiteral(session_id);
        defer self.allocator.free(session_id_escaped);
        const agent_id_escaped = try self.escapeSqlLiteral(agent_id);
        defer self.allocator.free(agent_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "INSERT INTO session_metadata(session_id, agent_id, created_at_ms, last_active_ms, message_count, is_active) " ++
                "VALUES ({s}, {s}, {d}, {d}, {d}, 1) " ++
                "ON CONFLICT(session_id) DO UPDATE SET last_active_ms = {d}, message_count = {d};",
            .{ session_id_escaped, agent_id_escaped, now_ms, now_ms, message_count, now_ms, message_count },
        );
        defer self.allocator.free(sql);

        try self.run(sql);
    }

    pub fn getLastActiveSession(
        self: *Store,
        agent_id: []const u8,
    ) !?SessionMetadata {
        const agent_id_escaped = try self.escapeSqlLiteral(agent_id);
        defer self.allocator.free(agent_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT session_id, agent_id, created_at_ms, last_active_ms, message_count, is_active, summary " ++
                "FROM session_metadata WHERE agent_id = {s} AND is_active = 1 " ++
                "ORDER BY last_active_ms DESC LIMIT 1;",
            .{agent_id_escaped},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) return null;
        if (rc != SQLITE_ROW) return LtmError.ExecError;

        return SessionMetadata{
            .session_id = try self.copyColumnText(stmt, 0),
            .agent_id = try self.copyColumnText(stmt, 1),
            .created_at_ms = sqlite3_column_int64(stmt, 2),
            .last_active_ms = sqlite3_column_int64(stmt, 3),
            .message_count = sqlite3_column_int64(stmt, 4),
            .is_active = sqlite3_column_int64(stmt, 5) != 0,
            .summary = if (sqlite3_column_type(stmt, 6) != SQLITE_NULL)
                try self.copyColumnText(stmt, 6)
            else
                null,
        };
    }

    pub fn listRecentSessions(
        self: *Store,
        agent_id: []const u8,
        limit: usize,
    ) !std.ArrayListUnmanaged(SessionMetadata) {
        const agent_id_escaped = try self.escapeSqlLiteral(agent_id);
        defer self.allocator.free(agent_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT session_id, agent_id, created_at_ms, last_active_ms, message_count, is_active, summary " ++
                "FROM session_metadata WHERE agent_id = {s} AND is_active = 1 " ++
                "ORDER BY last_active_ms DESC LIMIT {d};",
            .{ agent_id_escaped, limit },
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        var results = std.ArrayListUnmanaged(SessionMetadata){};

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            try results.append(self.allocator, .{
                .session_id = try self.copyColumnText(stmt, 0),
                .agent_id = try self.copyColumnText(stmt, 1),
                .created_at_ms = sqlite3_column_int64(stmt, 2),
                .last_active_ms = sqlite3_column_int64(stmt, 3),
                .message_count = sqlite3_column_int64(stmt, 4),
                .is_active = sqlite3_column_int64(stmt, 5) != 0,
                .summary = if (sqlite3_column_type(stmt, 6) != SQLITE_NULL)
                    try self.copyColumnText(stmt, 6)
                else
                    null,
            });
        }

        return results;
    }

    pub fn setSessionInactive(self: *Store, session_id: []const u8) !void {
        const session_id_escaped = try self.escapeSqlLiteral(session_id);
        defer self.allocator.free(session_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "UPDATE session_metadata SET is_active = 0 WHERE session_id = {s};",
            .{session_id_escaped},
        );
        defer self.allocator.free(sql);

        try self.run(sql);
    }

    fn raiseError(self: *Store, context: []const u8, rc: i32) !void {
        const message = std.mem.span(sqlite3_errmsg(self.db));
        std.log.err("{s} failed (code={d}): {s}", .{ context, rc, message });
        return LtmError.ExecError;
    }
};

fn parseIntegerField(value: std.json.Value) ?i64 {
    if (value == .integer) return value.integer;
    return null;
}

fn parsePositiveInteger(value: std.json.Value) ?u64 {
    if (value == .integer) {
        if (value.integer < 0) return null;
        return @intCast(value.integer);
    }
    return null;
}

fn parseRole(text: []const u8) ?ziggy_piai.types.MessageRole {
    if (std.mem.eql(u8, text, "user")) return .user;
    if (std.mem.eql(u8, text, "assistant")) return .assistant;
    if (std.mem.eql(u8, text, "system")) return .system;
    if (std.mem.eql(u8, text, "tool")) return .tool;
    if (std.mem.eql(u8, text, "tool_result")) return .tool_result;
    return null;
}

fn parseRamEntryState(text: []const u8) ?memory.RamEntryState {
    if (std.mem.eql(u8, text, "active")) return .active;
    if (std.mem.eql(u8, text, "tombstone")) return .tombstone;
    return null;
}

fn roleToString(role: ziggy_piai.types.MessageRole) []const u8 {
    return switch (role) {
        .user => "user",
        .assistant => "assistant",
        .system => "system",
        .tool => "tool",
        .tool_result => "tool_result",
    };
}

test "ltm_store: archive and load latest snapshot" {
    const allocator = std.testing.allocator;
    const dir_name = try std.fmt.allocPrint(allocator, ".tmp-ltm-store-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir_name);
    defer std.fs.cwd().deleteTree(dir_name) catch {};

    try std.fs.cwd().makePath(dir_name);
    var store = try Store.open(allocator, dir_name, "memory.db");
    defer store.close();

    var ram = memory.RamContext.init(allocator, 64, 8192);
    defer ram.deinit();

    _ = try ram.update(.user, "hello");
    _ = try ram.update(.assistant, "reply");
    try ram.summarize();

    try std.testing.expect(try store.archiveRamSnapshot("session-archive", "initial", &ram));

    const snapshot = try store.loadLatestSnapshot("session-archive") orelse return error.TestExpectedActual;
    defer snapshot.deinit(allocator);

    try std.testing.expectEqualStrings("initial", snapshot.snapshot.reason);
    try std.testing.expect(snapshot.entries.items.len > 0);
    try std.testing.expect(snapshot.summaries.items.len > 0);
    try std.testing.expect(snapshot.snapshot.entry_count == snapshot.entries.items.len);
    try std.testing.expect(snapshot.snapshot.summary_count == snapshot.summaries.items.len);

    const total = try store.countSnapshotsForSession("session-archive");
    try std.testing.expectEqual(@as(usize, 1), total);
}

test "ltm_store: prune snapshots by per-session limit" {
    const allocator = std.testing.allocator;
    const dir_name = try std.fmt.allocPrint(allocator, ".tmp-ltm-store-prune-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir_name);
    defer std.fs.cwd().deleteTree(dir_name) catch {};

    try std.fs.cwd().makePath(dir_name);
    var store = try Store.open(allocator, dir_name, "memory.db");
    defer store.close();

    var ram = memory.RamContext.init(allocator, 64, 8192);
    defer ram.deinit();

    _ = try ram.update(.user, "one");
    try std.testing.expect(try store.archiveRamSnapshot("session-prune", "first", &ram));
    _ = try ram.update(.assistant, "two");
    try std.testing.expect(try store.archiveRamSnapshot("session-prune", "second", &ram));
    _ = try ram.update(.assistant, "three");
    try std.testing.expect(try store.archiveRamSnapshot("session-prune", "third", &ram));

    const removed = try store.pruneSnapshots(null, 1);
    try std.testing.expectEqual(@as(usize, 2), removed);
    try std.testing.expectEqual(@as(usize, 1), try store.countSnapshotsForSession("session-prune"));
}

test "ltm_store: prune snapshots by age cutoff" {
    const allocator = std.testing.allocator;
    const dir_name = try std.fmt.allocPrint(allocator, ".tmp-ltm-store-prune-age-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir_name);
    defer std.fs.cwd().deleteTree(dir_name) catch {};

    try std.fs.cwd().makePath(dir_name);
    var store = try Store.open(allocator, dir_name, "memory.db");
    defer store.close();

    var ram = memory.RamContext.init(allocator, 64, 8192);
    defer ram.deinit();

    const now_ms = std.time.milliTimestamp();
    const old_snapshot_ms = now_ms - (15 * 24 * 60 * 60 * 1000);

    _ = try ram.update(.user, "old message");
    try std.testing.expect(try store.archiveRamSnapshotAtTimestamp("session-age", "old", &ram, old_snapshot_ms));

    _ = try ram.update(.assistant, "new message");
    try std.testing.expect(try store.archiveRamSnapshot("session-age", "new", &ram));

    const cutoff = now_ms - (7 * 24 * 60 * 60 * 1000);
    const removed = try store.pruneSnapshots(cutoff, null);
    try std.testing.expectEqual(@as(usize, 1), removed);
    try std.testing.expectEqual(@as(usize, 1), try store.countSnapshotsForSession("session-age"));
}

test "ltm_store: migrate legacy archive into sqlite snapshot table" {
    const allocator = std.testing.allocator;
    const dir_name = try std.fmt.allocPrint(allocator, ".tmp-ltm-store-migrate-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir_name);
    defer std.fs.cwd().deleteTree(dir_name) catch {};

    try std.fs.cwd().makePath(dir_name);
    var store = try Store.open(allocator, dir_name, "memory.db");
    defer store.close();

    const archive_timestamp = std.time.milliTimestamp();
    const archive_path = try std.fmt.allocPrint(allocator, "{s}/session-legacy.json", .{dir_name});
    defer allocator.free(archive_path);
    const legacy_archive = try std.fmt.allocPrint(
        allocator,
        "{{\"version\":1,\"timestamp_ms\":{d},\"session_id\":\"session-legacy\",\"reason\":\"legacy-save\",\"next_id\":3,\"entries\":[{{\"id\":1,\"role\":\"user\",\"state\":\"active\",\"content\":\"hello\",\"related_to\":null}}],\"summaries\":[]}}",
        .{archive_timestamp},
    );
    defer allocator.free(legacy_archive);

    var archive_file = try std.fs.cwd().createFile(archive_path, .{ .truncate = true });
    defer archive_file.close();
    try archive_file.writeAll(legacy_archive);

    const index_path = try std.fmt.allocPrint(allocator, "{s}/archive-index.ndjson", .{dir_name});
    defer allocator.free(index_path);
    const index_line = try std.fmt.allocPrint(
        allocator,
        "{{\"version\":1,\"timestamp_ms\":{d},\"session_id\":\"session-legacy\",\"reason\":\"legacy\",\"archive_path\":\"{s}\",\"next_id\":3,\"entry_count\":1,\"summary_count\":0}}\n",
        .{ archive_timestamp, archive_path },
    );
    defer allocator.free(index_line);

    var index_file = try std.fs.cwd().createFile(index_path, .{ .truncate = true });
    defer index_file.close();
    try index_file.writeAll(index_line);

    const imported_first = try store.migrateLegacyArchives(index_path);
    try std.testing.expectEqual(@as(u32, 1), imported_first);

    const snapshot = try store.loadLatestSnapshot("session-legacy") orelse return error.TestExpectedActual;
    defer snapshot.deinit(allocator);
    try std.testing.expectEqualStrings("legacy", snapshot.snapshot.reason);
    try std.testing.expectEqual(archive_timestamp, snapshot.snapshot.timestamp_ms);
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries.items.len);
    try std.testing.expectEqual(@as(u32, 0), try store.migrateLegacyArchives(index_path));

    const total = try store.countSnapshotsForSession("session-legacy");
    try std.testing.expectEqual(@as(usize, 1), total);
}
