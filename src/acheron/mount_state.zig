const builtin = @import("builtin");
const std = @import("std");

pub const ClientStateStore = struct {
    allocator: std.mem.Allocator,
    dir_path: []u8,
    file_path: []u8,

    pub fn init(allocator: std.mem.Allocator) !ClientStateStore {
        const root = try resolveConfigRoot(allocator);
        defer allocator.free(root);

        const dir_path = try std.fs.path.join(allocator, &.{ root, "spiderweb" });
        errdefer allocator.free(dir_path);
        const file_path = try std.fs.path.join(allocator, &.{ dir_path, "fs-mount-client.json" });
        errdefer allocator.free(file_path);

        return .{
            .allocator = allocator,
            .dir_path = dir_path,
            .file_path = file_path,
        };
    }

    pub fn initForTesting(allocator: std.mem.Allocator, base_dir: []const u8) !ClientStateStore {
        const dir_path = try allocator.dupe(u8, base_dir);
        errdefer allocator.free(dir_path);
        const file_path = try std.fs.path.join(allocator, &.{ dir_path, "fs-mount-client.json" });
        errdefer allocator.free(file_path);
        return .{
            .allocator = allocator,
            .dir_path = dir_path,
            .file_path = file_path,
        };
    }

    pub fn deinit(self: *ClientStateStore) void {
        self.allocator.free(self.dir_path);
        self.allocator.free(self.file_path);
        self.* = undefined;
    }

    pub fn loadOrCreateAgentId(
        self: *ClientStateStore,
        namespace_url: []const u8,
        project_id: []const u8,
    ) ![]u8 {
        var entries = try self.loadEntries();
        defer deinitStoredEntryList(self.allocator, &entries);

        for (entries.items) |entry| {
            if (std.mem.eql(u8, entry.namespace_url, namespace_url) and std.mem.eql(u8, entry.project_id, project_id)) {
                return self.allocator.dupe(u8, entry.agent_id);
            }
        }

        const generated = try generateStableExternalAgentId(self.allocator);
        errdefer self.allocator.free(generated);

        try entries.append(self.allocator, .{
            .namespace_url = try self.allocator.dupe(u8, namespace_url),
            .project_id = try self.allocator.dupe(u8, project_id),
            .agent_id = try self.allocator.dupe(u8, generated),
        });
        try self.writeEntries(entries.items);
        return generated;
    }

    pub fn generateEphemeralSessionKey(allocator: std.mem.Allocator) ![]u8 {
        var random_bytes: [10]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const encoded = try hexLower(allocator, &random_bytes);
        defer allocator.free(encoded);
        return std.fmt.allocPrint(
            allocator,
            "mount-{d}-{s}",
            .{ std.time.milliTimestamp(), encoded },
        );
    }

    const StoredEntry = struct {
        namespace_url: []u8,
        project_id: []u8,
        agent_id: []u8,

        fn deinit(self: *StoredEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.namespace_url);
            allocator.free(self.project_id);
            allocator.free(self.agent_id);
            self.* = undefined;
        }
    };

    const StoredEntryList = std.ArrayListUnmanaged(StoredEntry);

    fn deinitStoredEntryList(allocator: std.mem.Allocator, entries: *StoredEntryList) void {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    fn loadEntries(self: *ClientStateStore) !StoredEntryList {
        var entries: StoredEntryList = .{};
        errdefer {
            deinitStoredEntryList(self.allocator, &entries);
        }

        const content = readFileIfExistsAbsolute(self.allocator, self.file_path) catch |err| switch (err) {
            error.FileNotFound => return entries,
            else => return err,
        };
        defer self.allocator.free(content);
        if (content.len == 0) return entries;

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, content, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidClientState;

        const entries_value = parsed.value.object.get("entries") orelse return entries;
        if (entries_value != .array) return error.InvalidClientState;

        for (entries_value.array.items) |item| {
            if (item != .object) return error.InvalidClientState;
            const namespace_url = getRequiredString(item.object, "namespace_url") orelse return error.InvalidClientState;
            const project_id = getRequiredString(item.object, "project_id") orelse return error.InvalidClientState;
            const agent_id = getRequiredString(item.object, "agent_id") orelse return error.InvalidClientState;
            try entries.append(self.allocator, .{
                .namespace_url = try self.allocator.dupe(u8, namespace_url),
                .project_id = try self.allocator.dupe(u8, project_id),
                .agent_id = try self.allocator.dupe(u8, agent_id),
            });
        }

        return entries;
    }

    fn writeEntries(self: *ClientStateStore, entries: []const StoredEntry) !void {
        try makeAbsolutePath(self.dir_path);

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);

        try out.appendSlice(self.allocator, "{\"entries\":[");
        for (entries, 0..) |entry, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const escaped_namespace = try jsonEscape(self.allocator, entry.namespace_url);
            defer self.allocator.free(escaped_namespace);
            const escaped_project = try jsonEscape(self.allocator, entry.project_id);
            defer self.allocator.free(escaped_project);
            const escaped_agent = try jsonEscape(self.allocator, entry.agent_id);
            defer self.allocator.free(escaped_agent);
            try out.writer(self.allocator).print(
                "{{\"namespace_url\":\"{s}\",\"project_id\":\"{s}\",\"agent_id\":\"{s}\"}}",
                .{ escaped_namespace, escaped_project, escaped_agent },
            );
        }
        try out.appendSlice(self.allocator, "]}");

        try writeFileAbsolute(self.file_path, out.items);
    }
};

fn resolveConfigRoot(allocator: std.mem.Allocator) ![]u8 {
    return switch (builtin.os.tag) {
        .windows => blk: {
            if (std.process.getEnvVarOwned(allocator, "APPDATA")) |path| break :blk path else |_| {}
            if (std.process.getEnvVarOwned(allocator, "LOCALAPPDATA")) |path| break :blk path else |_| {}
            return error.MissingConfigDirectory;
        },
        .macos => blk: {
            const home = try std.process.getEnvVarOwned(allocator, "HOME");
            defer allocator.free(home);
            break :blk try std.fs.path.join(allocator, &.{ home, "Library", "Application Support" });
        },
        else => blk: {
            if (std.process.getEnvVarOwned(allocator, "XDG_CONFIG_HOME")) |path| break :blk path else |_| {}
            const home = try std.process.getEnvVarOwned(allocator, "HOME");
            defer allocator.free(home);
            break :blk try std.fs.path.join(allocator, &.{ home, ".config" });
        },
    };
}

fn getRequiredString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

fn generateStableExternalAgentId(allocator: std.mem.Allocator) ![]u8 {
    var random_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const encoded = try hexLower(allocator, &random_bytes);
    defer allocator.free(encoded);
    return std.fmt.allocPrint(allocator, "external-{s}", .{encoded});
}

fn jsonEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    for (value) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => if (char < 0x20) {
                try out.writer(allocator).print("\\u00{x:0>2}", .{char});
            } else {
                try out.append(allocator, char);
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

fn hexLower(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, idx| {
        out[idx * 2] = alphabet[(byte >> 4) & 0x0F];
        out[idx * 2 + 1] = alphabet[byte & 0x0F];
    }
    return out;
}

fn makeAbsolutePath(path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path)) {
        try std.fs.cwd().makePath(path);
        return;
    }

    switch (builtin.os.tag) {
        .windows => {
            if (path.len < 3 or path[1] != ':' or (path[2] != '\\' and path[2] != '/')) return error.InvalidPath;
            const root = path[0..3];
            const rel = std.mem.trimLeft(u8, path[3..], "\\/");
            var dir = try std.fs.openDirAbsolute(root, .{});
            defer dir.close();
            if (rel.len > 0) try dir.makePath(rel);
        },
        else => {
            var dir = try std.fs.openDirAbsolute("/", .{});
            defer dir.close();
            const rel = std.mem.trimLeft(u8, path, "/");
            if (rel.len > 0) try dir.makePath(rel);
        },
    }
}

fn readFileIfExistsAbsolute(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(path)) {
        return std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    }
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, 1024 * 1024);
}

fn writeFileAbsolute(path: []const u8, data: []const u8) !void {
    if (!std.fs.path.isAbsolute(path)) {
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = data });
        return;
    }
    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(data);
}

test "mount_state: loadOrCreateAgentId persists generated ids" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var store = try ClientStateStore.initForTesting(allocator, root);
    defer store.deinit();

    const first = try store.loadOrCreateAgentId("ws://127.0.0.1:18790/", "proj-a");
    defer allocator.free(first);
    const second = try store.loadOrCreateAgentId("ws://127.0.0.1:18790/", "proj-a");
    defer allocator.free(second);
    const third = try store.loadOrCreateAgentId("ws://127.0.0.1:18790/", "proj-b");
    defer allocator.free(third);

    try std.testing.expect(std.mem.startsWith(u8, first, "external-"));
    try std.testing.expectEqualStrings(first, second);
    try std.testing.expect(!std.mem.eql(u8, first, third));
}

test "mount_state: generateEphemeralSessionKey uses mount prefix" {
    const allocator = std.testing.allocator;
    const session_key = try ClientStateStore.generateEphemeralSessionKey(allocator);
    defer allocator.free(session_key);
    try std.testing.expect(std.mem.startsWith(u8, session_key, "mount-"));
}
