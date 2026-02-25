const std = @import("std");

pub const DefaultTtlMs: i64 = 2000;

pub const NodeKey = struct {
    endpoint_index: u16,
    node_id: u64,
};

pub const DirNameKey = struct {
    endpoint_index: u16,
    dir_id: u64,
    name: []const u8,

    fn clone(self: DirNameKey, allocator: std.mem.Allocator) !DirNameKey {
        return .{
            .endpoint_index = self.endpoint_index,
            .dir_id = self.dir_id,
            .name = try allocator.dupe(u8, self.name),
        };
    }

    fn deinit(self: *DirNameKey, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.* = undefined;
    }
};

pub const HandleBlockKey = struct {
    endpoint_index: u16,
    handle_id: u64,
    block_index: u64,
};

pub const AttrValue = struct {
    attr_json: []u8,
    gen: u64,
    expires_at_ms: i64,
};

pub const DirValue = struct {
    attr_json: []u8,
    expires_at_ms: i64,
};

pub const DirListingValue = struct {
    payload_json: []u8,
    expires_at_ms: i64,
};

pub const NegativeValue = struct {
    expires_at_ms: i64,
};

pub const ReadValue = struct {
    bytes: []u8,
};

pub const AttrCache = struct {
    allocator: std.mem.Allocator,
    ttl_ms: i64,
    map: std.AutoHashMapUnmanaged(NodeKey, AttrValue) = .{},

    pub fn init(allocator: std.mem.Allocator, ttl_ms: i64) AttrCache {
        return .{
            .allocator = allocator,
            .ttl_ms = if (ttl_ms <= 0) DefaultTtlMs else ttl_ms,
        };
    }

    pub fn deinit(self: *AttrCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |entry| self.allocator.free(entry.attr_json);
        self.map.deinit(self.allocator);
    }

    pub fn getFresh(self: *AttrCache, key: NodeKey, now_ms: i64) ?[]const u8 {
        const entry = self.map.get(key) orelse return null;
        if (entry.expires_at_ms < now_ms) return null;
        return entry.attr_json;
    }

    pub fn put(self: *AttrCache, key: NodeKey, attr_json: []const u8, gen: u64, now_ms: i64) !void {
        const owned = try self.allocator.dupe(u8, attr_json);
        errdefer self.allocator.free(owned);

        if (try self.map.fetchPut(self.allocator, key, .{
            .attr_json = owned,
            .gen = gen,
            .expires_at_ms = now_ms + self.ttl_ms,
        })) |existing| {
            self.allocator.free(existing.value.attr_json);
        }
    }

    pub fn invalidateNode(self: *AttrCache, key: NodeKey) void {
        if (self.map.fetchRemove(key)) |entry| self.allocator.free(entry.value.attr_json);
    }
};

pub const DirEntryCache = struct {
    allocator: std.mem.Allocator,
    ttl_ms: i64,
    map: std.ArrayListUnmanaged(struct { key: DirNameKey, value: DirValue }) = .{},

    pub fn init(allocator: std.mem.Allocator, ttl_ms: i64) DirEntryCache {
        return .{
            .allocator = allocator,
            .ttl_ms = if (ttl_ms <= 0) DefaultTtlMs else ttl_ms,
        };
    }

    pub fn deinit(self: *DirEntryCache) void {
        for (self.map.items) |*item| {
            item.key.deinit(self.allocator);
            self.allocator.free(item.value.attr_json);
        }
        self.map.deinit(self.allocator);
    }

    pub fn getFresh(self: *DirEntryCache, endpoint_index: u16, dir_id: u64, name: []const u8, now_ms: i64) ?[]const u8 {
        for (self.map.items) |item| {
            if (item.key.endpoint_index != endpoint_index) continue;
            if (item.key.dir_id != dir_id) continue;
            if (!std.mem.eql(u8, item.key.name, name)) continue;
            if (item.value.expires_at_ms < now_ms) return null;
            return item.value.attr_json;
        }
        return null;
    }

    pub fn put(self: *DirEntryCache, endpoint_index: u16, dir_id: u64, name: []const u8, attr_json: []const u8, now_ms: i64) !void {
        for (self.map.items) |*item| {
            if (item.key.endpoint_index != endpoint_index) continue;
            if (item.key.dir_id != dir_id) continue;
            if (!std.mem.eql(u8, item.key.name, name)) continue;
            self.allocator.free(item.value.attr_json);
            item.value.attr_json = try self.allocator.dupe(u8, attr_json);
            item.value.expires_at_ms = now_ms + self.ttl_ms;
            return;
        }

        try self.map.append(self.allocator, .{
            .key = try (DirNameKey{ .endpoint_index = endpoint_index, .dir_id = dir_id, .name = name }).clone(self.allocator),
            .value = .{
                .attr_json = try self.allocator.dupe(u8, attr_json),
                .expires_at_ms = now_ms + self.ttl_ms,
            },
        });
    }

    pub fn invalidateDir(self: *DirEntryCache, endpoint_index: u16, dir_id: u64) void {
        var i: usize = 0;
        while (i < self.map.items.len) {
            const item = self.map.items[i];
            if (item.key.endpoint_index != endpoint_index or item.key.dir_id != dir_id) {
                i += 1;
                continue;
            }

            self.map.items[i].key.deinit(self.allocator);
            self.allocator.free(self.map.items[i].value.attr_json);
            _ = self.map.swapRemove(i);
        }
    }
};

pub const DirListingCache = struct {
    allocator: std.mem.Allocator,
    ttl_ms: i64,
    map: std.AutoHashMapUnmanaged(NodeKey, DirListingValue) = .{},

    pub fn init(allocator: std.mem.Allocator, ttl_ms: i64) DirListingCache {
        return .{
            .allocator = allocator,
            .ttl_ms = if (ttl_ms <= 0) DefaultTtlMs else ttl_ms,
        };
    }

    pub fn deinit(self: *DirListingCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |entry| self.allocator.free(entry.payload_json);
        self.map.deinit(self.allocator);
    }

    pub fn getFresh(self: *DirListingCache, key: NodeKey, now_ms: i64) ?[]const u8 {
        const entry = self.map.get(key) orelse return null;
        if (entry.expires_at_ms < now_ms) return null;
        return entry.payload_json;
    }

    pub fn put(self: *DirListingCache, key: NodeKey, payload_json: []const u8, now_ms: i64) !void {
        const owned = try self.allocator.dupe(u8, payload_json);
        errdefer self.allocator.free(owned);

        if (try self.map.fetchPut(self.allocator, key, .{
            .payload_json = owned,
            .expires_at_ms = now_ms + self.ttl_ms,
        })) |existing| {
            self.allocator.free(existing.value.payload_json);
        }
    }

    pub fn invalidateDir(self: *DirListingCache, endpoint_index: u16, dir_id: u64) void {
        if (self.map.fetchRemove(.{ .endpoint_index = endpoint_index, .node_id = dir_id })) |entry| {
            self.allocator.free(entry.value.payload_json);
        }
    }
};

pub const NegativeCache = struct {
    allocator: std.mem.Allocator,
    ttl_ms: i64,
    map: std.ArrayListUnmanaged(struct { key: DirNameKey, value: NegativeValue }) = .{},

    pub fn init(allocator: std.mem.Allocator, ttl_ms: i64) NegativeCache {
        return .{
            .allocator = allocator,
            .ttl_ms = if (ttl_ms <= 0) 1000 else ttl_ms,
        };
    }

    pub fn deinit(self: *NegativeCache) void {
        for (self.map.items) |*item| item.key.deinit(self.allocator);
        self.map.deinit(self.allocator);
    }

    pub fn put(self: *NegativeCache, endpoint_index: u16, dir_id: u64, name: []const u8, now_ms: i64) !void {
        for (self.map.items) |*item| {
            if (item.key.endpoint_index == endpoint_index and item.key.dir_id == dir_id and std.mem.eql(u8, item.key.name, name)) {
                item.value.expires_at_ms = now_ms + self.ttl_ms;
                return;
            }
        }

        try self.map.append(self.allocator, .{
            .key = try (DirNameKey{ .endpoint_index = endpoint_index, .dir_id = dir_id, .name = name }).clone(self.allocator),
            .value = .{
                .expires_at_ms = now_ms + self.ttl_ms,
            },
        });
    }

    pub fn containsFresh(self: *NegativeCache, endpoint_index: u16, dir_id: u64, name: []const u8, now_ms: i64) bool {
        for (self.map.items) |item| {
            if (item.key.endpoint_index != endpoint_index) continue;
            if (item.key.dir_id != dir_id) continue;
            if (!std.mem.eql(u8, item.key.name, name)) continue;
            return item.value.expires_at_ms >= now_ms;
        }
        return false;
    }

    pub fn invalidateDir(self: *NegativeCache, endpoint_index: u16, dir_id: u64) void {
        var i: usize = 0;
        while (i < self.map.items.len) {
            const item = self.map.items[i];
            if (item.key.endpoint_index != endpoint_index or item.key.dir_id != dir_id) {
                i += 1;
                continue;
            }
            self.map.items[i].key.deinit(self.allocator);
            _ = self.map.swapRemove(i);
        }
    }
};

pub const ReadBlockCache = struct {
    allocator: std.mem.Allocator,
    capacity_blocks: usize,
    order: std.ArrayListUnmanaged(HandleBlockKey) = .{},
    map: std.AutoHashMapUnmanaged(HandleBlockKey, ReadValue) = .{},

    pub fn init(allocator: std.mem.Allocator, capacity_blocks: usize) ReadBlockCache {
        return .{
            .allocator = allocator,
            .capacity_blocks = if (capacity_blocks == 0) 128 else capacity_blocks,
        };
    }

    pub fn deinit(self: *ReadBlockCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |entry| self.allocator.free(entry.bytes);
        self.map.deinit(self.allocator);
        self.order.deinit(self.allocator);
    }

    pub fn get(self: *ReadBlockCache, key: HandleBlockKey) ?[]const u8 {
        const value = self.map.get(key) orelse return null;
        self.touch(key);
        return value.bytes;
    }

    pub fn put(self: *ReadBlockCache, key: HandleBlockKey, bytes: []const u8) !void {
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);

        if (try self.map.fetchPut(self.allocator, key, .{ .bytes = owned })) |existing| {
            self.allocator.free(existing.value.bytes);
            self.touch(key);
            return;
        }

        try self.order.append(self.allocator, key);
        try self.evictIfNeeded();
    }

    pub fn invalidateHandle(self: *ReadBlockCache, endpoint_index: u16, handle_id: u64) void {
        var i: usize = 0;
        while (i < self.order.items.len) {
            const key = self.order.items[i];
            if (key.endpoint_index != endpoint_index or key.handle_id != handle_id) {
                i += 1;
                continue;
            }

            if (self.map.fetchRemove(key)) |entry| self.allocator.free(entry.value.bytes);
            _ = self.order.swapRemove(i);
        }
    }

    pub fn invalidateEndpoint(self: *ReadBlockCache, endpoint_index: u16) void {
        var i: usize = 0;
        while (i < self.order.items.len) {
            const key = self.order.items[i];
            if (key.endpoint_index != endpoint_index) {
                i += 1;
                continue;
            }

            if (self.map.fetchRemove(key)) |entry| self.allocator.free(entry.value.bytes);
            _ = self.order.swapRemove(i);
        }
    }

    fn touch(self: *ReadBlockCache, key: HandleBlockKey) void {
        var idx: ?usize = null;
        for (self.order.items, 0..) |entry, i| {
            if (std.meta.eql(entry, key)) {
                idx = i;
                break;
            }
        }
        if (idx) |i| {
            const value = self.order.items[i];
            _ = self.order.swapRemove(i);
            self.order.append(self.allocator, value) catch {};
        }
    }

    fn evictIfNeeded(self: *ReadBlockCache) !void {
        while (self.order.items.len > self.capacity_blocks) {
            const evicted = self.order.orderedRemove(0);
            if (self.map.fetchRemove(evicted)) |entry| {
                self.allocator.free(entry.value.bytes);
            }
        }
    }
};

test "fs_cache: attr cache respects ttl" {
    const allocator = std.testing.allocator;
    var cache = AttrCache.init(allocator, 100);
    defer cache.deinit();

    try cache.put(.{ .endpoint_index = 1, .node_id = 77 }, "{\"id\":77}", 1, 10);
    try std.testing.expect(cache.getFresh(.{ .endpoint_index = 1, .node_id = 77 }, 50) != null);
    try std.testing.expect(cache.getFresh(.{ .endpoint_index = 1, .node_id = 77 }, 200) == null);
}

test "fs_cache: negative cache expires" {
    const allocator = std.testing.allocator;
    var cache = NegativeCache.init(allocator, 50);
    defer cache.deinit();

    try cache.put(1, 9, "missing.txt", 1000);
    try std.testing.expect(cache.containsFresh(1, 9, "missing.txt", 1025));
    try std.testing.expect(!cache.containsFresh(1, 9, "missing.txt", 2000));
}

test "fs_cache: directory listing cache respects ttl" {
    const allocator = std.testing.allocator;
    var cache = DirListingCache.init(allocator, 100);
    defer cache.deinit();

    const key = NodeKey{ .endpoint_index = 2, .node_id = 99 };
    try cache.put(key, "{\"ents\":[],\"next_cookie\":0}", 1000);
    try std.testing.expect(cache.getFresh(key, 1050) != null);
    try std.testing.expect(cache.getFresh(key, 1205) == null);
}
