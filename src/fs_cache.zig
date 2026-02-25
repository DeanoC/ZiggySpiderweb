const std = @import("std");

pub const DefaultTtlMs: i64 = 2000;

pub const NodeKey = struct {
    endpoint_index: u16,
    node_id: u64,
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
    node_id: u64,
    attr_json: []u8,
    expires_at_ms: i64,
};

pub const DirListingValue = struct {
    payload_json: []u8,
    expires_at_ms: i64,
};

pub const DirCompleteValue = struct {
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

pub const DirLookup = struct {
    node_id: u64,
    attr_json: []const u8,
};

const DirBucket = struct {
    entries: std.StringHashMapUnmanaged(DirValue) = .{},

    fn deinit(self: *DirBucket, allocator: std.mem.Allocator) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.attr_json);
        }
        self.entries.deinit(allocator);
        self.* = undefined;
    }
};

pub const DirEntryCache = struct {
    allocator: std.mem.Allocator,
    ttl_ms: i64,
    map: std.AutoHashMapUnmanaged(NodeKey, DirBucket) = .{},

    pub fn init(allocator: std.mem.Allocator, ttl_ms: i64) DirEntryCache {
        return .{
            .allocator = allocator,
            .ttl_ms = if (ttl_ms <= 0) DefaultTtlMs else ttl_ms,
        };
    }

    pub fn deinit(self: *DirEntryCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |bucket| bucket.deinit(self.allocator);
        self.map.deinit(self.allocator);
    }

    pub fn getFresh(self: *DirEntryCache, endpoint_index: u16, dir_id: u64, name: []const u8, now_ms: i64) ?DirLookup {
        const bucket = self.map.getPtr(.{ .endpoint_index = endpoint_index, .node_id = dir_id }) orelse return null;
        const value = bucket.entries.get(name) orelse return null;
        if (value.expires_at_ms < now_ms) return null;
        return .{
            .node_id = value.node_id,
            .attr_json = value.attr_json,
        };
    }

    pub fn put(self: *DirEntryCache, endpoint_index: u16, dir_id: u64, name: []const u8, node_id: u64, attr_json: []const u8, now_ms: i64) !void {
        const key = NodeKey{ .endpoint_index = endpoint_index, .node_id = dir_id };
        const bucket_gop = try self.map.getOrPut(self.allocator, key);
        if (!bucket_gop.found_existing) bucket_gop.value_ptr.* = .{};
        const bucket = bucket_gop.value_ptr;

        if (bucket.entries.getPtr(name)) |existing| {
            self.allocator.free(existing.attr_json);
            existing.* = .{
                .node_id = node_id,
                .attr_json = try self.allocator.dupe(u8, attr_json),
                .expires_at_ms = now_ms + self.ttl_ms,
            };
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try bucket.entries.put(self.allocator, owned_name, .{
            .node_id = node_id,
            .attr_json = try self.allocator.dupe(u8, attr_json),
            .expires_at_ms = now_ms + self.ttl_ms,
        });
    }

    pub fn invalidateDir(self: *DirEntryCache, endpoint_index: u16, dir_id: u64) void {
        if (self.map.fetchRemove(.{ .endpoint_index = endpoint_index, .node_id = dir_id })) |removed| {
            var bucket = removed.value;
            bucket.deinit(self.allocator);
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

pub const DirCompleteCache = struct {
    allocator: std.mem.Allocator,
    ttl_ms: i64,
    map: std.AutoHashMapUnmanaged(NodeKey, DirCompleteValue) = .{},

    pub fn init(allocator: std.mem.Allocator, ttl_ms: i64) DirCompleteCache {
        return .{
            .allocator = allocator,
            .ttl_ms = if (ttl_ms <= 0) DefaultTtlMs else ttl_ms,
        };
    }

    pub fn deinit(self: *DirCompleteCache) void {
        self.map.deinit(self.allocator);
    }

    pub fn isFresh(self: *DirCompleteCache, key: NodeKey, now_ms: i64) bool {
        const entry = self.map.get(key) orelse return false;
        return entry.expires_at_ms >= now_ms;
    }

    pub fn markComplete(self: *DirCompleteCache, key: NodeKey, now_ms: i64) !void {
        _ = try self.map.fetchPut(self.allocator, key, .{
            .expires_at_ms = now_ms + self.ttl_ms,
        });
    }

    pub fn invalidateDir(self: *DirCompleteCache, endpoint_index: u16, dir_id: u64) void {
        _ = self.map.remove(.{ .endpoint_index = endpoint_index, .node_id = dir_id });
    }
};

pub const NegativeCache = struct {
    allocator: std.mem.Allocator,
    ttl_ms: i64,
    map: std.AutoHashMapUnmanaged(NodeKey, std.StringHashMapUnmanaged(NegativeValue)) = .{},

    pub fn init(allocator: std.mem.Allocator, ttl_ms: i64) NegativeCache {
        return .{
            .allocator = allocator,
            .ttl_ms = if (ttl_ms <= 0) 1000 else ttl_ms,
        };
    }

    pub fn deinit(self: *NegativeCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |names| {
            var names_it = names.iterator();
            while (names_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
            names.deinit(self.allocator);
        }
        self.map.deinit(self.allocator);
    }

    pub fn put(self: *NegativeCache, endpoint_index: u16, dir_id: u64, name: []const u8, now_ms: i64) !void {
        const key = NodeKey{ .endpoint_index = endpoint_index, .node_id = dir_id };
        const bucket_gop = try self.map.getOrPut(self.allocator, key);
        if (!bucket_gop.found_existing) bucket_gop.value_ptr.* = .{};
        const bucket = bucket_gop.value_ptr;

        if (bucket.getPtr(name)) |existing| {
            existing.expires_at_ms = now_ms + self.ttl_ms;
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try bucket.put(self.allocator, owned_name, .{
            .expires_at_ms = now_ms + self.ttl_ms,
        });
    }

    pub fn containsFresh(self: *NegativeCache, endpoint_index: u16, dir_id: u64, name: []const u8, now_ms: i64) bool {
        const bucket = self.map.getPtr(.{ .endpoint_index = endpoint_index, .node_id = dir_id }) orelse return false;
        const value = bucket.get(name) orelse return false;
        return value.expires_at_ms >= now_ms;
    }

    pub fn invalidateDir(self: *NegativeCache, endpoint_index: u16, dir_id: u64) void {
        if (self.map.fetchRemove(.{ .endpoint_index = endpoint_index, .node_id = dir_id })) |removed| {
            var names = removed.value;
            var it = names.iterator();
            while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
            names.deinit(self.allocator);
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

test "fs_cache: directory complete cache respects ttl" {
    const allocator = std.testing.allocator;
    var cache = DirCompleteCache.init(allocator, 100);
    defer cache.deinit();

    const key = NodeKey{ .endpoint_index = 3, .node_id = 77 };
    try cache.markComplete(key, 2000);
    try std.testing.expect(cache.isFresh(key, 2050));
    try std.testing.expect(!cache.isFresh(key, 2201));
}
