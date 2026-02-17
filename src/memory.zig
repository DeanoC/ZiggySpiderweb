const std = @import("std");
const ltm_store = @import("ltm_store.zig");
const memid = @import("memid.zig");

pub const MemoryTier = enum {
    ram,
    rom,
};

pub const MemoryError = error{
    InvalidMemId,
    NotFound,
    ImmutableTier,
    InvalidVersion,
    PersistenceFailed,
};

pub const ActiveMemoryItem = struct {
    mem_id: []u8,
    tier: MemoryTier,
    version: ?u64,
    kind: []u8,
    mutable: bool,
    created_at_ms: i64,
    content_json: []u8,

    pub fn clone(self: *const ActiveMemoryItem, allocator: std.mem.Allocator) !ActiveMemoryItem {
        return .{
            .mem_id = try allocator.dupe(u8, self.mem_id),
            .tier = self.tier,
            .version = self.version,
            .kind = try allocator.dupe(u8, self.kind),
            .mutable = self.mutable,
            .created_at_ms = self.created_at_ms,
            .content_json = try allocator.dupe(u8, self.content_json),
        };
    }

    pub fn deinit(self: *ActiveMemoryItem, allocator: std.mem.Allocator) void {
        allocator.free(self.mem_id);
        allocator.free(self.kind);
        allocator.free(self.content_json);
        self.* = undefined;
    }
};

const MemoryHistory = struct {
    versions: std.ArrayListUnmanaged(ActiveMemoryItem) = .{},

    fn deinit(self: *MemoryHistory, allocator: std.mem.Allocator) void {
        for (self.versions.items) |*item| item.deinit(allocator);
        self.versions.deinit(allocator);
    }

    fn appendClone(self: *MemoryHistory, allocator: std.mem.Allocator, item: *const ActiveMemoryItem) !void {
        if (item.version) |version| {
            if (self.findVersion(version) != null) return;
        }
        try self.versions.append(allocator, try item.clone(allocator));
    }

    fn findVersion(self: *const MemoryHistory, version: u64) ?*const ActiveMemoryItem {
        for (self.versions.items) |*item| {
            if (item.version != null and item.version.? == version) return item;
        }
        return null;
    }

    fn latest(self: *const MemoryHistory) ?*const ActiveMemoryItem {
        var latest_item: ?*const ActiveMemoryItem = null;
        var latest_version: u64 = 0;

        for (self.versions.items) |*item| {
            const version = item.version orelse 0;
            if (latest_item == null or version >= latest_version) {
                latest_item = item;
                latest_version = version;
            }
        }
        return latest_item;
    }
};

const PersistHistoryHookFn = *const fn (self: *RuntimeMemory, item: *const ActiveMemoryItem) MemoryError!void;
var persist_history_hook: ?PersistHistoryHookFn = null;

const BrainStore = struct {
    ram_items: std.StringHashMapUnmanaged(ActiveMemoryItem) = .{},
    rom_items: std.StringHashMapUnmanaged(ActiveMemoryItem) = .{},
    ordered_ids: std.ArrayListUnmanaged([]const u8) = .{},

    fn deinit(self: *BrainStore, allocator: std.mem.Allocator) void {
        var ram_it = self.ram_items.iterator();
        while (ram_it.next()) |entry| {
            var item = entry.value_ptr.*;
            item.deinit(allocator);
        }
        self.ram_items.deinit(allocator);

        var rom_it = self.rom_items.iterator();
        while (rom_it.next()) |entry| {
            var item = entry.value_ptr.*;
            item.deinit(allocator);
        }
        self.rom_items.deinit(allocator);
        self.ordered_ids.deinit(allocator);
    }

    fn mapForTier(self: *BrainStore, tier: MemoryTier) *std.StringHashMapUnmanaged(ActiveMemoryItem) {
        return switch (tier) {
            .ram => &self.ram_items,
            .rom => &self.rom_items,
        };
    }

    fn appendOrder(self: *BrainStore, allocator: std.mem.Allocator, mem_id: []const u8) !void {
        try self.ordered_ids.append(allocator, mem_id);
    }

    fn removeOrder(self: *BrainStore, mem_id: []const u8) void {
        for (self.ordered_ids.items, 0..) |item_id, index| {
            if (std.mem.eql(u8, item_id, mem_id)) {
                _ = self.ordered_ids.orderedRemove(index);
                return;
            }
        }
    }

    fn replaceOrder(self: *BrainStore, old_mem_id: []const u8, new_mem_id: []const u8) void {
        for (self.ordered_ids.items) |*item_id| {
            if (std.mem.eql(u8, item_id.*, old_mem_id)) {
                item_id.* = new_mem_id;
                return;
            }
        }
    }
};

pub const RuntimeMemory = struct {
    allocator: std.mem.Allocator,
    agent_id: []u8,
    persisted_store: ?*ltm_store.VersionedMemStore = null,
    mutex: std.Thread.Mutex = .{},
    brains: std.StringHashMapUnmanaged(BrainStore) = .{},
    history_by_base: std.StringHashMapUnmanaged(MemoryHistory) = .{},
    next_auto_name: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, agent_id: []const u8) !RuntimeMemory {
        return initWithStore(allocator, agent_id, null);
    }

    pub fn initWithStore(
        allocator: std.mem.Allocator,
        agent_id: []const u8,
        store: ?*ltm_store.VersionedMemStore,
    ) !RuntimeMemory {
        return .{
            .allocator = allocator,
            .agent_id = try allocator.dupe(u8, agent_id),
            .persisted_store = store,
        };
    }

    pub fn attachStore(self: *RuntimeMemory, store: ?*ltm_store.VersionedMemStore) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.persisted_store = store;
    }

    pub fn deinit(self: *RuntimeMemory) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var brain_it = self.brains.iterator();
        while (brain_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.brains.deinit(self.allocator);

        var history_it = self.history_by_base.iterator();
        while (history_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.history_by_base.deinit(self.allocator);

        self.allocator.free(self.agent_id);
    }

    pub fn create(
        self: *RuntimeMemory,
        brain: []const u8,
        tier: MemoryTier,
        name: ?[]const u8,
        kind: []const u8,
        content_json: []const u8,
    ) !ActiveMemoryItem {
        self.mutex.lock();
        defer self.mutex.unlock();

        const store = try self.ensureBrainLocked(brain);
        const base_name = try self.uniqueNameLocked(store, brain, name);
        defer self.allocator.free(base_name);

        const parsed = memid.MemId{
            .agent = self.agent_id,
            .brain = brain,
            .name = base_name,
            .version = 1,
        };
        const mem_id = try parsed.format(self.allocator);

        var item = ActiveMemoryItem{
            .mem_id = mem_id,
            .tier = tier,
            .version = 1,
            .kind = try self.allocator.dupe(u8, kind),
            .mutable = tier == .ram,
            .created_at_ms = std.time.milliTimestamp(),
            .content_json = try self.allocator.dupe(u8, content_json),
        };

        const target = store.mapForTier(tier);
        try target.put(self.allocator, item.mem_id, item);
        try store.appendOrder(self.allocator, item.mem_id);

        try self.persistHistoryLocked(&item);
        return item.clone(self.allocator);
    }

    pub fn mutate(self: *RuntimeMemory, raw_mem_id: []const u8, content_json: []const u8) !ActiveMemoryItem {
        self.mutex.lock();
        defer self.mutex.unlock();

        const current_ref = try self.resolveMutableRefLocked(raw_mem_id);
        const current_item = current_ref.item.*;
        if (!current_item.mutable or current_item.tier != .ram) return MemoryError.ImmutableTier;

        const parsed = memid.MemId.parse(current_item.mem_id) catch return MemoryError.InvalidMemId;
        const next_version = (current_item.version orelse 0) + 1;
        const next_id = try parsed.withVersion(next_version).format(self.allocator);

        var next_item = ActiveMemoryItem{
            .mem_id = next_id,
            .tier = .ram,
            .version = next_version,
            .kind = try self.allocator.dupe(u8, current_item.kind),
            .mutable = true,
            .created_at_ms = std.time.milliTimestamp(),
            .content_json = try self.allocator.dupe(u8, content_json),
        };
        var inserted_into_map = false;
        errdefer if (!inserted_into_map) next_item.deinit(self.allocator);

        try self.persistHistoryLocked(&next_item);

        try current_ref.store.ram_items.put(self.allocator, next_item.mem_id, next_item);
        inserted_into_map = true;
        errdefer if (current_ref.store.ram_items.fetchRemove(next_item.mem_id)) |removed_entry| {
            var removed = removed_entry.value;
            removed.deinit(self.allocator);
        };
        try current_ref.store.appendOrder(self.allocator, next_item.mem_id);
        errdefer current_ref.store.removeOrder(next_item.mem_id);

        current_ref.store.removeOrder(current_item.mem_id);
        _ = current_ref.store.ram_items.remove(current_item.mem_id);

        var old = current_item;
        old.deinit(self.allocator);

        return next_item.clone(self.allocator);
    }

    pub fn evict(self: *RuntimeMemory, raw_mem_id: []const u8) !ActiveMemoryItem {
        self.mutex.lock();
        defer self.mutex.unlock();

        const current_ref = try self.resolveMutableRefLocked(raw_mem_id);
        const current_item = current_ref.item.*;
        if (!current_item.mutable or current_item.tier != .ram) return MemoryError.ImmutableTier;

        current_ref.store.removeOrder(current_item.mem_id);
        _ = current_ref.store.ram_items.remove(current_item.mem_id);

        try self.persistHistoryLocked(&current_item);
        const evicted = try current_item.clone(self.allocator);

        var owned = current_item;
        owned.deinit(self.allocator);
        return evicted;
    }

    pub fn load(self: *RuntimeMemory, raw_mem_id: []const u8, version: ?u64) !ActiveMemoryItem {
        self.mutex.lock();
        defer self.mutex.unlock();

        const parsed = memid.MemId.parse(raw_mem_id) catch return MemoryError.InvalidMemId;
        const resolved_version = version orelse parsed.version;

        if (resolved_version) |specific_version| {
            const concrete = try parsed.withVersion(specific_version).format(self.allocator);
            defer self.allocator.free(concrete);

            if (try self.findActiveByConcreteIdLocked(parsed.brain, concrete)) |item| {
                return item.clone(self.allocator);
            }

            const base_id = try parsed.formatBase(self.allocator);
            defer self.allocator.free(base_id);
            if (self.history_by_base.getPtr(base_id)) |history| {
                if (history.findVersion(specific_version)) |item| {
                    return item.clone(self.allocator);
                }
            }

            if (self.persisted_store) |store| {
                if (store.load(self.allocator, base_id, specific_version) catch return MemoryError.PersistenceFailed) |loaded_record| {
                    var record = loaded_record;
                    defer record.deinit(self.allocator);
                    return self.itemFromPersistedRecord(parsed.brain, &record);
                }
            }
            return MemoryError.NotFound;
        }

        if (try self.findLatestActiveByBaseLocked(&parsed)) |item| {
            return item.clone(self.allocator);
        }

        const base_id = try parsed.formatBase(self.allocator);
        defer self.allocator.free(base_id);
        if (self.history_by_base.getPtr(base_id)) |history| {
            if (history.latest()) |item| {
                return item.clone(self.allocator);
            }
        }

        if (self.persisted_store) |store| {
            if (store.load(self.allocator, base_id, null) catch return MemoryError.PersistenceFailed) |loaded_record| {
                var record = loaded_record;
                defer record.deinit(self.allocator);
                return self.itemFromPersistedRecord(parsed.brain, &record);
            }
        }
        return MemoryError.NotFound;
    }

    pub fn search(
        self: *RuntimeMemory,
        allocator: std.mem.Allocator,
        brain: []const u8,
        keyword: []const u8,
        limit: usize,
    ) ![]ActiveMemoryItem {
        self.mutex.lock();
        defer self.mutex.unlock();

        var out = std.ArrayListUnmanaged(ActiveMemoryItem){};
        errdefer {
            for (out.items) |*item| item.deinit(allocator);
            out.deinit(allocator);
        }

        const store = self.brains.getPtr(brain) orelse return out.toOwnedSlice(allocator);

        var added: usize = 0;
        const search_term = std.ascii.allocLowerString(allocator, keyword) catch keyword;
        const owns_search_term = search_term.ptr != keyword.ptr;
        defer if (owns_search_term) allocator.free(search_term);

        for (store.ordered_ids.items) |mem_id_ref| {
            if (added >= limit) break;

            const item = store.ram_items.getPtr(mem_id_ref) orelse store.rom_items.getPtr(mem_id_ref) orelse continue;
            if (!matchesKeyword(item, search_term)) continue;

            try out.append(allocator, try item.clone(allocator));
            added += 1;
        }

        return out.toOwnedSlice(allocator);
    }

    pub fn snapshotActive(self: *RuntimeMemory, allocator: std.mem.Allocator, brain: []const u8) ![]ActiveMemoryItem {
        self.mutex.lock();
        defer self.mutex.unlock();

        const store = self.brains.getPtr(brain) orelse return allocator.alloc(ActiveMemoryItem, 0);

        var out = std.ArrayListUnmanaged(ActiveMemoryItem){};
        errdefer {
            for (out.items) |*item| item.deinit(allocator);
            out.deinit(allocator);
        }

        for (store.ordered_ids.items) |mem_id_ref| {
            const item = store.ram_items.getPtr(mem_id_ref) orelse store.rom_items.getPtr(mem_id_ref) orelse continue;
            try out.append(allocator, try item.clone(allocator));
        }

        return out.toOwnedSlice(allocator);
    }

    fn ensureBrainLocked(self: *RuntimeMemory, brain: []const u8) !*BrainStore {
        if (self.brains.getPtr(brain)) |store| return store;

        const owned_name = try self.allocator.dupe(u8, brain);
        try self.brains.put(self.allocator, owned_name, .{});
        return self.brains.getPtr(owned_name).?;
    }

    fn uniqueNameLocked(self: *RuntimeMemory, store: *BrainStore, brain: []const u8, preferred: ?[]const u8) ![]u8 {
        const base_name = if (preferred) |name|
            if (std.mem.trim(u8, name, " \t\r\n").len > 0) try self.allocator.dupe(u8, std.mem.trim(u8, name, " \t\r\n")) else try self.autoNameLocked()
        else
            try self.autoNameLocked();

        var candidate = base_name;
        var suffix: u64 = 2;
        while (self.baseNameExistsLocked(store, brain, candidate)) {
            if (candidate.ptr != base_name.ptr) {
                self.allocator.free(candidate);
            }
            candidate = try std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ base_name, suffix });
            suffix += 1;
        }

        if (candidate.ptr != base_name.ptr) {
            self.allocator.free(base_name);
        }
        return candidate;
    }

    fn autoNameLocked(self: *RuntimeMemory) ![]u8 {
        defer self.next_auto_name += 1;
        return std.fmt.allocPrint(self.allocator, "mem_{d}", .{self.next_auto_name});
    }

    fn baseNameExistsLocked(self: *RuntimeMemory, store: *BrainStore, brain: []const u8, name: []const u8) bool {
        _ = self;
        const ram_it = store.ram_items.iterator();
        if (hasNameInIterator(ram_it, brain, name)) return true;
        const rom_it = store.rom_items.iterator();
        return hasNameInIterator(rom_it, brain, name);
    }

    fn persistHistoryLocked(self: *RuntimeMemory, item: *const ActiveMemoryItem) !void {
        if (persist_history_hook) |hook| {
            return hook(self, item);
        }

        const parsed = memid.MemId.parse(item.mem_id) catch return MemoryError.InvalidMemId;
        const base_id = try parsed.formatBase(self.allocator);
        defer self.allocator.free(base_id);

        const history = history_blk: {
            if (self.history_by_base.getPtr(base_id)) |existing| {
                break :history_blk existing;
            }

            const owned_base = try self.allocator.dupe(u8, base_id);
            try self.history_by_base.put(self.allocator, owned_base, .{});
            break :history_blk self.history_by_base.getPtr(owned_base).?;
        };

        try history.appendClone(self.allocator, item);

        if (self.persisted_store) |store| {
            if (item.version) |version| {
                store.persistVersionAt(
                    base_id,
                    version,
                    item.kind,
                    item.content_json,
                    item.created_at_ms,
                ) catch return MemoryError.PersistenceFailed;
            }
        }
    }

    fn itemFromPersistedRecord(
        self: *RuntimeMemory,
        brain: []const u8,
        record: *const ltm_store.VersionedRecord,
    ) !ActiveMemoryItem {
        var parts = std.mem.splitScalar(u8, record.base_id, ':');
        const agent = parts.next() orelse return MemoryError.InvalidMemId;
        const base_brain = parts.next() orelse return MemoryError.InvalidMemId;
        const name = parts.next() orelse return MemoryError.InvalidMemId;
        if (parts.next() != null) return MemoryError.InvalidMemId;

        const resolved_brain = if (brain.len == 0) base_brain else brain;
        const mem = memid.MemId{
            .agent = if (agent.len == 0) self.agent_id else agent,
            .brain = resolved_brain,
            .name = name,
            .version = record.version,
        };
        const mem_id = try mem.format(self.allocator);

        return .{
            .mem_id = mem_id,
            .tier = .ram,
            .version = record.version,
            .kind = try self.allocator.dupe(u8, record.kind),
            .mutable = true,
            .created_at_ms = record.created_at_ms,
            .content_json = try self.allocator.dupe(u8, record.content_json),
        };
    }

    fn findActiveByConcreteIdLocked(
        self: *RuntimeMemory,
        brain: []const u8,
        concrete_mem_id: []const u8,
    ) !?*const ActiveMemoryItem {
        const store = self.brains.getPtr(brain) orelse return null;
        if (store.ram_items.getPtr(concrete_mem_id)) |item| return item;
        if (store.rom_items.getPtr(concrete_mem_id)) |item| return item;
        return null;
    }

    fn findLatestActiveByBaseLocked(self: *RuntimeMemory, parsed: *const memid.MemId) !?*const ActiveMemoryItem {
        const store = self.brains.getPtr(parsed.brain) orelse return null;

        var latest: ?*const ActiveMemoryItem = null;
        var latest_version: u64 = 0;

        var ram_it = store.ram_items.iterator();
        while (ram_it.next()) |entry| {
            const current = entry.value_ptr;
            const current_parsed = memid.MemId.parse(current.mem_id) catch continue;
            if (!sameBase(parsed, &current_parsed)) continue;
            const version = current.version orelse 0;
            if (latest == null or version >= latest_version) {
                latest = current;
                latest_version = version;
            }
        }

        var rom_it = store.rom_items.iterator();
        while (rom_it.next()) |entry| {
            const current = entry.value_ptr;
            const current_parsed = memid.MemId.parse(current.mem_id) catch continue;
            if (!sameBase(parsed, &current_parsed)) continue;
            const version = current.version orelse 0;
            if (latest == null or version >= latest_version) {
                latest = current;
                latest_version = version;
            }
        }

        return latest;
    }

    const MutableRef = struct {
        store: *BrainStore,
        item: *const ActiveMemoryItem,
    };

    fn resolveMutableRefLocked(self: *RuntimeMemory, raw_mem_id: []const u8) !MutableRef {
        const parsed = memid.MemId.parse(raw_mem_id) catch return MemoryError.InvalidMemId;
        const store = self.brains.getPtr(parsed.brain) orelse return MemoryError.NotFound;

        if (parsed.version) |version| {
            const concrete = try parsed.withVersion(version).format(self.allocator);
            defer self.allocator.free(concrete);

            if (store.ram_items.getPtr(concrete)) |item| {
                return .{ .store = store, .item = item };
            }
            if (store.rom_items.getPtr(concrete)) |item| {
                return .{ .store = store, .item = item };
            }
            return MemoryError.NotFound;
        }

        var latest: ?*const ActiveMemoryItem = null;
        var latest_version: u64 = 0;

        var ram_it = store.ram_items.iterator();
        while (ram_it.next()) |entry| {
            const current = entry.value_ptr;
            const current_parsed = memid.MemId.parse(current.mem_id) catch continue;
            if (!sameBase(&parsed, &current_parsed)) continue;

            const version = current.version orelse 0;
            if (latest == null or version >= latest_version) {
                latest = current;
                latest_version = version;
            }
        }

        if (latest) |item| {
            return .{ .store = store, .item = item };
        }

        return MemoryError.NotFound;
    }
};

fn hasNameInIterator(it: std.StringHashMapUnmanaged(ActiveMemoryItem).Iterator, brain: []const u8, name: []const u8) bool {
    var iter = it;
    while (iter.next()) |entry| {
        const parsed = memid.MemId.parse(entry.value_ptr.mem_id) catch continue;
        if (std.mem.eql(u8, parsed.brain, brain) and std.mem.eql(u8, parsed.name, name)) {
            return true;
        }
    }
    return false;
}

fn sameBase(a: *const memid.MemId, b: *const memid.MemId) bool {
    return std.mem.eql(u8, a.agent, b.agent) and std.mem.eql(u8, a.brain, b.brain) and std.mem.eql(u8, a.name, b.name);
}

fn matchesKeyword(item: *const ActiveMemoryItem, keyword_lower: []const u8) bool {
    if (keyword_lower.len == 0) return true;

    const item_id_lower = std.heap.page_allocator.alloc(u8, item.mem_id.len) catch return false;
    defer std.heap.page_allocator.free(item_id_lower);
    _ = std.ascii.lowerString(item_id_lower, item.mem_id);
    if (std.mem.indexOf(u8, item_id_lower, keyword_lower) != null) return true;

    const kind_lower = std.heap.page_allocator.alloc(u8, item.kind.len) catch return false;
    defer std.heap.page_allocator.free(kind_lower);
    _ = std.ascii.lowerString(kind_lower, item.kind);
    if (std.mem.indexOf(u8, kind_lower, keyword_lower) != null) return true;

    const content_lower = std.heap.page_allocator.alloc(u8, item.content_json.len) catch return false;
    defer std.heap.page_allocator.free(content_lower);
    _ = std.ascii.lowerString(content_lower, item.content_json);
    return std.mem.indexOf(u8, content_lower, keyword_lower) != null;
}

pub fn deinitItems(allocator: std.mem.Allocator, items: []ActiveMemoryItem) void {
    for (items) |*item| item.deinit(allocator);
    allocator.free(items);
}

pub fn toActiveMemoryJson(allocator: std.mem.Allocator, brain: []const u8, items: []const ActiveMemoryItem) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"active_memory\":{\"brain\":\"");
    try appendJsonEscaped(allocator, &out, brain);
    try out.appendSlice(allocator, "\",\"items\":[");

    for (items, 0..) |item, index| {
        if (index > 0) try out.appendSlice(allocator, ",");

        try out.appendSlice(allocator, "{\"mem_id\":\"");
        try appendJsonEscaped(allocator, &out, item.mem_id);
        try out.appendSlice(allocator, "\",\"tier\":\"");
        try out.appendSlice(allocator, switch (item.tier) {
            .ram => "ram",
            .rom => "rom",
        });
        try out.appendSlice(allocator, "\",\"version\":");
        if (item.version) |version| {
            var version_buf: [32]u8 = undefined;
            const version_text = try std.fmt.bufPrint(&version_buf, "{d}", .{version});
            try out.appendSlice(allocator, version_text);
        } else {
            try out.appendSlice(allocator, "null");
        }

        try out.appendSlice(allocator, ",\"kind\":\"");
        try appendJsonEscaped(allocator, &out, item.kind);
        try out.appendSlice(allocator, "\",\"mutable\":");
        try out.appendSlice(allocator, if (item.mutable) "true" else "false");

        var time_buf: [32]u8 = undefined;
        const time_text = try std.fmt.bufPrint(&time_buf, "{d}", .{item.created_at_ms});
        try out.appendSlice(allocator, ",\"created_at_ms\":");
        try out.appendSlice(allocator, time_text);

        try out.appendSlice(allocator, ",\"content\":");
        if (isValidJson(item.content_json)) {
            try out.appendSlice(allocator, item.content_json);
        } else {
            try out.append(allocator, '"');
            try appendJsonEscaped(allocator, &out, item.content_json);
            try out.append(allocator, '"');
        }

        try out.appendSlice(allocator, "}");
    }

    try out.appendSlice(allocator, "]}}\n");
    return out.toOwnedSlice(allocator);
}

fn isValidJson(raw: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, raw, .{}) catch return false;
    defer parsed.deinit();
    return true;
}

fn appendJsonEscaped(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    raw: []const u8,
) !void {
    for (raw) |char| {
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

test "memory: create emits canonical mem ids with unique names" {
    const allocator = std.testing.allocator;
    var mem = try RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();

    var first = try mem.create("primary", .ram, "task_plan", "message", "{\"text\":\"first\"}");
    defer first.deinit(allocator);
    var second = try mem.create("primary", .ram, "task_plan", "message", "{\"text\":\"second\"}");
    defer second.deinit(allocator);

    _ = try memid.MemId.parse(first.mem_id);
    _ = try memid.MemId.parse(second.mem_id);
    try std.testing.expect(!std.mem.eql(u8, first.mem_id, second.mem_id));
}

test "memory: mutate creates new version and load supports historical version" {
    const allocator = std.testing.allocator;
    var mem = try RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();

    var created = try mem.create("primary", .ram, "notes", "note", "{\"text\":\"v1\"}");
    defer created.deinit(allocator);

    var mutated = try mem.mutate(created.mem_id, "{\"text\":\"v2\"}");
    defer mutated.deinit(allocator);

    const parsed = try memid.MemId.parse(created.mem_id);
    const latest_id = try parsed.withVersion(null).format(allocator);
    defer allocator.free(latest_id);

    var latest = try mem.load(latest_id, null);
    defer latest.deinit(allocator);
    try std.testing.expectEqual(@as(?u64, 2), latest.version);

    var v1 = try mem.load(latest_id, 1);
    defer v1.deinit(allocator);
    try std.testing.expectEqualStrings("{\"text\":\"v1\"}", v1.content_json);
}

fn failPersistHistoryForTest(_: *RuntimeMemory, _: *const ActiveMemoryItem) MemoryError!void {
    return MemoryError.PersistenceFailed;
}

test "memory: mutate does not change active state when persistence fails" {
    const allocator = std.testing.allocator;
    var mem = try RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();

    var created = try mem.create("primary", .ram, "persist_notes", "note", "{\"text\":\"v1\"}");
    defer created.deinit(allocator);
    const created_id_copy = try allocator.dupe(u8, created.mem_id);
    defer allocator.free(created_id_copy);

    const original_hook = persist_history_hook;
    defer persist_history_hook = original_hook;
    persist_history_hook = failPersistHistoryForTest;

    try std.testing.expectError(MemoryError.PersistenceFailed, mem.mutate(created_id_copy, "{\"text\":\"v2\"}"));

    const latest_alias = try (try memid.MemId.parse(created_id_copy)).withVersion(null).format(allocator);
    defer allocator.free(latest_alias);
    var latest = try mem.load(latest_alias, null);
    defer latest.deinit(allocator);

    try std.testing.expectEqual(@as(?u64, 1), latest.version);
    try std.testing.expectEqualStrings("{\"text\":\"v1\"}", latest.content_json);
}

test "memory: active memory JSON always includes mem_id" {
    const allocator = std.testing.allocator;
    var mem = try RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();

    var ram_item = try mem.create("primary", .ram, "task", "message", "{\"role\":\"assistant\",\"text\":\"hi\"}");
    defer ram_item.deinit(allocator);
    var rom_item = try mem.create("primary", .rom, "system_clock", "state", "{\"now\":\"2026-02-16T12:00:00Z\"}");
    defer rom_item.deinit(allocator);

    const snapshot = try mem.snapshotActive(allocator, "primary");
    defer deinitItems(allocator, snapshot);

    const json = try toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"mem_id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"tier\":\"rom\"") != null);
}

test "memory: ROM mutation and eviction are rejected deterministically" {
    const allocator = std.testing.allocator;
    var mem = try RuntimeMemory.init(allocator, "agentA");
    defer mem.deinit();

    var rom_item = try mem.create("primary", .rom, "policy", "state", "{\"text\":\"immutable\"}");
    defer rom_item.deinit(allocator);

    try std.testing.expectError(MemoryError.ImmutableTier, mem.mutate(rom_item.mem_id, "{\"text\":\"nope\"}"));
    try std.testing.expectError(MemoryError.ImmutableTier, mem.evict(rom_item.mem_id));
}

test "memory: persisted store supports reload across runtime restarts" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".tmp-memory-persist-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);
    var store = try ltm_store.VersionedMemStore.open(allocator, dir, "runtime-memory.db");
    defer store.close();

    const latest_alias = alias_blk: {
        var first_runtime = try RuntimeMemory.initWithStore(allocator, "agentA", &store);
        defer first_runtime.deinit();

        var created = try first_runtime.create("primary", .ram, "notes", "note", "{\"text\":\"v1\"}");
        defer created.deinit(allocator);
        var mutated = try first_runtime.mutate(created.mem_id, "{\"text\":\"v2\"}");
        defer mutated.deinit(allocator);

        break :alias_blk try (try memid.MemId.parse(created.mem_id)).withVersion(null).format(allocator);
    };
    defer allocator.free(latest_alias);

    var second_runtime = try RuntimeMemory.initWithStore(allocator, "agentA", &store);
    defer second_runtime.deinit();

    var latest = try second_runtime.load(latest_alias, null);
    defer latest.deinit(allocator);
    try std.testing.expectEqual(@as(?u64, 2), latest.version);
    try std.testing.expectEqualStrings("{\"text\":\"v2\"}", latest.content_json);

    var v1 = try second_runtime.load(latest_alias, 1);
    defer v1.deinit(allocator);
    try std.testing.expectEqualStrings("{\"text\":\"v1\"}", v1.content_json);
}
