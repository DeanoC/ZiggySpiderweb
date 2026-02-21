const std = @import("std");

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

pub const VersionedRecord = struct {
    base_id: []u8,
    version: u64,
    kind: []u8,
    content_json: []u8,
    created_at_ms: i64,

    pub fn deinit(self: *VersionedRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.base_id);
        allocator.free(self.kind);
        allocator.free(self.content_json);
        self.* = undefined;
    }
};

pub const VersionedMemStore = struct {
    allocator: std.mem.Allocator,
    db: *sqlite3,

    pub fn open(allocator: std.mem.Allocator, directory: []const u8, filename: []const u8) !VersionedMemStore {
        var dir_handle = try std.fs.cwd().makeOpenPath(directory, .{});
        dir_handle.close();

        const db_path = try std.fs.path.join(allocator, &.{ directory, filename });
        defer allocator.free(db_path);
        const db_path_z = try allocator.dupeZ(u8, db_path);
        defer allocator.free(db_path_z);

        var db: *sqlite3 = undefined;
        const rc = sqlite3_open_v2(db_path_z, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, null);
        if (rc != SQLITE_OK) return LtmError.OpenError;

        var store = VersionedMemStore{ .allocator = allocator, .db = db };
        errdefer store.deinit();
        try store.initSchema();
        return store;
    }

    pub fn close(self: *VersionedMemStore) void {
        self.deinit();
    }

    pub fn deinit(self: *VersionedMemStore) void {
        _ = sqlite3_close(self.db);
    }

    pub fn append(self: *VersionedMemStore, base_id: []const u8, kind: []const u8, content_json: []const u8) !u64 {
        return self.appendAt(base_id, kind, content_json, std.time.milliTimestamp());
    }

    pub fn appendAt(
        self: *VersionedMemStore,
        base_id: []const u8,
        kind: []const u8,
        content_json: []const u8,
        created_at_ms: i64,
    ) !u64 {
        const version = try self.nextVersion(base_id);
        try self.persistVersionAt(base_id, version, kind, content_json, created_at_ms);
        return version;
    }

    pub fn persistVersion(
        self: *VersionedMemStore,
        base_id: []const u8,
        version: u64,
        kind: []const u8,
        content_json: []const u8,
    ) !void {
        return self.persistVersionAt(base_id, version, kind, content_json, std.time.milliTimestamp());
    }

    pub fn persistVersionAt(
        self: *VersionedMemStore,
        base_id: []const u8,
        version: u64,
        kind: []const u8,
        content_json: []const u8,
        created_at_ms: i64,
    ) !void {
        const base_id_escaped = try self.escapeSqlLiteral(base_id);
        defer self.allocator.free(base_id_escaped);
        const kind_escaped = try self.escapeSqlLiteral(kind);
        defer self.allocator.free(kind_escaped);
        const content_escaped = try self.escapeSqlLiteral(content_json);
        defer self.allocator.free(content_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "INSERT OR IGNORE INTO mem_versions(base_id, version, kind, content_json, created_at_ms) VALUES ({s}, {d}, {s}, {s}, {d});",
            .{ base_id_escaped, version, kind_escaped, content_escaped, created_at_ms },
        );
        defer self.allocator.free(sql);

        try self.run(sql);
    }

    pub fn load(self: *VersionedMemStore, allocator: std.mem.Allocator, base_id: []const u8, version: ?u64) !?VersionedRecord {
        const base_id_escaped = try self.escapeSqlLiteral(base_id);
        defer self.allocator.free(base_id_escaped);

        const sql = if (version) |v|
            try std.fmt.allocPrint(
                self.allocator,
                "SELECT base_id, version, kind, content_json, created_at_ms FROM mem_versions WHERE base_id = {s} AND version = {d} LIMIT 1;",
                .{ base_id_escaped, v },
            )
        else
            try std.fmt.allocPrint(
                self.allocator,
                "SELECT base_id, version, kind, content_json, created_at_ms FROM mem_versions WHERE base_id = {s} ORDER BY version DESC LIMIT 1;",
                .{base_id_escaped},
            );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) return null;
        if (rc != SQLITE_ROW) return LtmError.ExecError;

        return VersionedRecord{
            .base_id = try self.copyColumnText(allocator, stmt, 0),
            .version = try self.columnToU64(stmt, 1),
            .kind = try self.copyColumnText(allocator, stmt, 2),
            .content_json = try self.copyColumnText(allocator, stmt, 3),
            .created_at_ms = sqlite3_column_int64(stmt, 4),
        };
    }

    pub fn highestAutoMemIndex(self: *VersionedMemStore, agent: []const u8, brain: []const u8) !u64 {
        const auto_prefix = try std.fmt.allocPrint(self.allocator, "{s}:{s}:mem_", .{ agent, brain });
        defer self.allocator.free(auto_prefix);
        const like_pattern = try std.fmt.allocPrint(self.allocator, "{s}%", .{auto_prefix});
        defer self.allocator.free(like_pattern);
        const pattern_escaped = try self.escapeSqlLiteral(like_pattern);
        defer self.allocator.free(pattern_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT DISTINCT base_id FROM mem_versions WHERE base_id LIKE {s};",
            .{pattern_escaped},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        var highest: u64 = 0;
        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            const base_id_text = sqlite3_column_text(stmt, 0) orelse return LtmError.InvalidData;
            const base_id = std.mem.span(base_id_text);
            const auto_index = parseAutoMemIndex(base_id, auto_prefix) orelse continue;
            if (auto_index > highest) highest = auto_index;
        }

        return highest;
    }

    pub fn search(
        self: *VersionedMemStore,
        allocator: std.mem.Allocator,
        keyword: []const u8,
        limit: usize,
    ) ![]VersionedRecord {
        const keyword_pattern = try std.fmt.allocPrint(self.allocator, "%{s}%", .{keyword});
        defer self.allocator.free(keyword_pattern);
        const keyword_escaped = try self.escapeSqlLiteral(keyword_pattern);
        defer self.allocator.free(keyword_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT base_id, version, kind, content_json, created_at_ms FROM mem_versions " ++
                "WHERE content_json LIKE {s} OR kind LIKE {s} OR base_id LIKE {s} " ++
                "ORDER BY created_at_ms DESC LIMIT {d};",
            .{ keyword_escaped, keyword_escaped, keyword_escaped, limit },
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        var out = std.ArrayListUnmanaged(VersionedRecord){};
        errdefer {
            for (out.items) |*record| record.deinit(allocator);
            out.deinit(allocator);
        }

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            try out.append(allocator, .{
                .base_id = try self.copyColumnText(allocator, stmt, 0),
                .version = try self.columnToU64(stmt, 1),
                .kind = try self.copyColumnText(allocator, stmt, 2),
                .content_json = try self.copyColumnText(allocator, stmt, 3),
                .created_at_ms = sqlite3_column_int64(stmt, 4),
            });
        }

        return out.toOwnedSlice(allocator);
    }

    pub fn listDistinctBaseIds(
        self: *VersionedMemStore,
        allocator: std.mem.Allocator,
        kind: []const u8,
        like_pattern: ?[]const u8,
        limit: usize,
        offset: usize,
    ) ![][]u8 {
        const kind_escaped = try self.escapeSqlLiteral(kind);
        defer self.allocator.free(kind_escaped);

        const sql = if (like_pattern) |pattern| blk: {
            const pattern_escaped = try self.escapeSqlLiteral(pattern);
            defer self.allocator.free(pattern_escaped);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "SELECT base_id FROM mem_versions WHERE kind = {s} AND base_id LIKE {s} " ++
                    "GROUP BY base_id ORDER BY MAX(created_at_ms) DESC LIMIT {d} OFFSET {d};",
                .{ kind_escaped, pattern_escaped, limit, offset },
            );
        } else try std.fmt.allocPrint(
            self.allocator,
            "SELECT base_id FROM mem_versions WHERE kind = {s} " ++
                "GROUP BY base_id ORDER BY MAX(created_at_ms) DESC LIMIT {d} OFFSET {d};",
            .{ kind_escaped, limit, offset },
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        var out = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (out.items) |base_id| allocator.free(base_id);
            out.deinit(allocator);
        }

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            try out.append(allocator, try self.copyColumnText(allocator, stmt, 0));
        }

        return out.toOwnedSlice(allocator);
    }

    pub fn listVersions(
        self: *VersionedMemStore,
        allocator: std.mem.Allocator,
        base_id: []const u8,
        limit: usize,
    ) ![]VersionedRecord {
        const base_id_escaped = try self.escapeSqlLiteral(base_id);
        defer self.allocator.free(base_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT base_id, version, kind, content_json, created_at_ms FROM mem_versions " ++
                "WHERE base_id = {s} ORDER BY version DESC LIMIT {d};",
            .{ base_id_escaped, limit },
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        var out = std.ArrayListUnmanaged(VersionedRecord){};
        errdefer {
            for (out.items) |*record| record.deinit(allocator);
            out.deinit(allocator);
        }

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) return LtmError.ExecError;

            try out.append(allocator, .{
                .base_id = try self.copyColumnText(allocator, stmt, 0),
                .version = try self.columnToU64(stmt, 1),
                .kind = try self.copyColumnText(allocator, stmt, 2),
                .content_json = try self.copyColumnText(allocator, stmt, 3),
                .created_at_ms = sqlite3_column_int64(stmt, 4),
            });
        }

        return out.toOwnedSlice(allocator);
    }

    fn initSchema(self: *VersionedMemStore) !void {
        const schema_sql =
            "CREATE TABLE IF NOT EXISTS mem_versions (" ++
            "  base_id TEXT NOT NULL," ++
            "  version INTEGER NOT NULL," ++
            "  kind TEXT NOT NULL," ++
            "  content_json TEXT NOT NULL," ++
            "  created_at_ms INTEGER NOT NULL," ++
            "  PRIMARY KEY(base_id, version)" ++
            ");" ++
            "CREATE INDEX IF NOT EXISTS idx_mem_versions_created_at ON mem_versions(created_at_ms DESC);";

        try self.run(schema_sql);
    }

    fn nextVersion(self: *VersionedMemStore, base_id: []const u8) !u64 {
        const base_id_escaped = try self.escapeSqlLiteral(base_id);
        defer self.allocator.free(base_id_escaped);

        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT COALESCE(MAX(version), 0) + 1 FROM mem_versions WHERE base_id = {s};",
            .{base_id_escaped},
        );
        defer self.allocator.free(sql);

        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        const rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) return 1;
        if (rc != SQLITE_ROW) return LtmError.ExecError;

        return try self.columnToU64(stmt, 0);
    }

    fn run(self: *VersionedMemStore, sql: []const u8) !void {
        const stmt = try self.prepare(sql);
        defer _ = sqlite3_finalize(stmt);

        while (true) {
            const rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc == SQLITE_ROW) continue;
            try self.raiseError("sqlite step", rc);
        }
    }

    fn prepare(self: *VersionedMemStore, sql: []const u8) !*sqlite3_stmt {
        var stmt: *sqlite3_stmt = undefined;
        const rc = sqlite3_prepare_v2(
            self.db,
            sql.ptr,
            @intCast(sql.len),
            &stmt,
            null,
        );
        if (rc != SQLITE_OK) {
            try self.raiseError("sqlite prepare", rc);
        }
        return stmt;
    }

    fn escapeSqlLiteral(self: *VersionedMemStore, input: []const u8) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);

        try out.append(self.allocator, '\'');
        for (input) |char| {
            if (char == '\'') {
                try out.appendSlice(self.allocator, "''");
            } else {
                try out.append(self.allocator, char);
            }
        }
        try out.append(self.allocator, '\'');

        return out.toOwnedSlice(self.allocator);
    }

    fn copyColumnText(self: *VersionedMemStore, allocator: std.mem.Allocator, stmt: *sqlite3_stmt, column: i32) ![]u8 {
        _ = self;
        const ptr = sqlite3_column_text(stmt, column) orelse return LtmError.InvalidData;
        return allocator.dupe(u8, std.mem.span(ptr));
    }

    fn parseAutoMemIndex(base_id: []const u8, auto_prefix: []const u8) ?u64 {
        if (!std.mem.startsWith(u8, base_id, auto_prefix)) return null;
        const suffix = base_id[auto_prefix.len..];
        if (suffix.len == 0) return null;
        return std.fmt.parseUnsigned(u64, suffix, 10) catch null;
    }

    fn columnToU64(self: *VersionedMemStore, stmt: *sqlite3_stmt, column: i32) !u64 {
        _ = self;
        if (sqlite3_column_type(stmt, column) == SQLITE_NULL) return LtmError.InvalidData;
        const value = sqlite3_column_int64(stmt, column);
        if (value < 0) return LtmError.InvalidData;
        return @intCast(value);
    }

    fn raiseError(self: *VersionedMemStore, context: []const u8, rc: i32) !void {
        const message = std.mem.span(sqlite3_errmsg(self.db));
        std.log.err("{s} failed (code={d}): {s}", .{ context, rc, message });
        return LtmError.ExecError;
    }
};

pub fn deinitRecords(allocator: std.mem.Allocator, records: []VersionedRecord) void {
    for (records) |*record| record.deinit(allocator);
    allocator.free(records);
}

test "ltm_store: append and load versions" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".tmp-vltm-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var store = try VersionedMemStore.open(allocator, dir, "runtime-memory.db");
    defer store.close();

    const base = "agentA:primary:notes";
    const v1 = try store.appendAt(base, "note", "{\"text\":\"hello\"}", 10);
    const v2 = try store.appendAt(base, "note", "{\"text\":\"world\"}", 20);
    try std.testing.expectEqual(@as(u64, 1), v1);
    try std.testing.expectEqual(@as(u64, 2), v2);

    var latest = (try store.load(allocator, base, null)).?;
    defer latest.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), latest.version);

    var old = (try store.load(allocator, base, 1)).?;
    defer old.deinit(allocator);
    try std.testing.expectEqualStrings("{\"text\":\"hello\"}", old.content_json);
}

test "ltm_store: search keyword returns matching records" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".tmp-vltm-search-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var store = try VersionedMemStore.open(allocator, dir, "runtime-memory.db");
    defer store.close();

    _ = try store.appendAt("agent:primary:task", "message", "{\"text\":\"compile fix\"}", 11);
    _ = try store.appendAt("agent:primary:task", "message", "{\"text\":\"docs\"}", 12);

    const records = try store.search(allocator, "compile", 10);
    defer deinitRecords(allocator, records);

    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqualStrings("agent:primary:task", records[0].base_id);
}

test "ltm_store: persistVersion is idempotent for same base/version" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".tmp-vltm-idempotent-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var store = try VersionedMemStore.open(allocator, dir, "runtime-memory.db");
    defer store.close();

    try store.persistVersionAt("agent:primary:artifact", 3, "tool_result", "{\"ok\":true}", 100);
    try store.persistVersionAt("agent:primary:artifact", 3, "tool_result", "{\"ok\":true}", 100);

    var v3 = (try store.load(allocator, "agent:primary:artifact", 3)).?;
    defer v3.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), v3.version);

    var latest = (try store.load(allocator, "agent:primary:artifact", null)).?;
    defer latest.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), latest.version);
}

test "ltm_store: listVersions returns latest-first rows for a base id" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".tmp-vltm-list-versions-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var store = try VersionedMemStore.open(allocator, dir, "runtime-memory.db");
    defer store.close();

    try store.persistVersionAt("agent:primary:notes", 1, "note", "{\"text\":\"v1\"}", 11);
    try store.persistVersionAt("agent:primary:notes", 2, "note", "{\"text\":\"v2\"}", 12);
    try store.persistVersionAt("agent:primary:notes", 3, "note", "{\"text\":\"v3\"}", 13);
    try store.persistVersionAt("agent:primary:other", 1, "note", "{\"text\":\"skip\"}", 14);

    const rows = try store.listVersions(allocator, "agent:primary:notes", 2);
    defer deinitRecords(allocator, rows);

    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(@as(u64, 3), rows[0].version);
    try std.testing.expectEqualStrings("{\"text\":\"v3\"}", rows[0].content_json);
    try std.testing.expectEqual(@as(u64, 2), rows[1].version);
    try std.testing.expectEqualStrings("{\"text\":\"v2\"}", rows[1].content_json);
}

test "ltm_store: listDistinctBaseIds groups by base id and sorts by newest update" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".tmp-vltm-list-distinct-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var store = try VersionedMemStore.open(allocator, dir, "runtime-memory.db");
    defer store.close();

    try store.persistVersionAt("run:run-1:meta", 1, "run.meta", "{\"state\":\"created\"}", 10);
    try store.persistVersionAt("run:run-1:meta", 2, "run.meta", "{\"state\":\"running\"}", 30);
    try store.persistVersionAt("run:run-2:meta", 1, "run.meta", "{\"state\":\"created\"}", 20);
    try store.persistVersionAt("agent:primary:notes", 1, "note", "{\"text\":\"skip\"}", 40);

    const ids = try store.listDistinctBaseIds(allocator, "run.meta", "run:%:meta", 10, 0);
    defer {
        for (ids) |base_id| allocator.free(base_id);
        allocator.free(ids);
    }

    try std.testing.expectEqual(@as(usize, 2), ids.len);
    try std.testing.expectEqualStrings("run:run-1:meta", ids[0]);
    try std.testing.expectEqualStrings("run:run-2:meta", ids[1]);
}

test "ltm_store: highestAutoMemIndex only counts canonical auto names for agent and brain" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".tmp-vltm-auto-index-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var store = try VersionedMemStore.open(allocator, dir, "runtime-memory.db");
    defer store.close();

    try store.persistVersionAt("agentA:primary:mem_1", 1, "note", "{\"text\":\"v1\"}", 1);
    try store.persistVersionAt("agentA:primary:mem_10", 2, "note", "{\"text\":\"v2\"}", 2);
    try store.persistVersionAt("agentA:primary:mem_10", 3, "note", "{\"text\":\"v3\"}", 3);
    try store.persistVersionAt("agentA:primary:mem_2_extra", 1, "note", "{\"text\":\"ignore\"}", 4);
    try store.persistVersionAt("agentA:secondary:mem_99", 1, "note", "{\"text\":\"ignore\"}", 5);
    try store.persistVersionAt("agentB:primary:mem_77", 1, "note", "{\"text\":\"ignore\"}", 6);

    const highest = try store.highestAutoMemIndex("agentA", "primary");
    try std.testing.expectEqual(@as(u64, 10), highest);

    const none = try store.highestAutoMemIndex("agentA", "tertiary");
    try std.testing.expectEqual(@as(u64, 0), none);
}
