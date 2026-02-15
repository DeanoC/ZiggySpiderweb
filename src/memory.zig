const std = @import("std");
const ziggy_piai = @import("ziggy-piai");

pub const MemoryID = u64;

pub const RamMutation = enum {
    load,
    update,
    evict,
    summarize,
};

pub const RamEntryState = enum {
    active,
    tombstone,
};

pub const RamEntry = struct {
    id: MemoryID,
    message: ziggy_piai.types.Message,
    state: RamEntryState,
    related_to: ?MemoryID = null,
};

pub const SummaryEntry = struct {
    id: MemoryID,
    source_id: MemoryID,
    text: []const u8,
    created_at_ms: i64,
};

pub const LtmRecord = struct {
    id: MemoryID,
    payload: []const u8,
    created_at_ms: i64,
};

pub const RamContext = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    entries: std.ArrayListUnmanaged(RamEntry),
    summaries: std.ArrayListUnmanaged(SummaryEntry),
    next_id: MemoryID = 1,
    max_messages: usize,
    max_bytes: usize,
    total_message_bytes: usize,

    pub fn init(allocator: std.mem.Allocator, max_messages: usize, max_bytes: usize) RamContext {
        return .{
            .allocator = allocator,
            .entries = .{},
            .summaries = .{},
            .max_messages = max_messages,
            .max_bytes = max_bytes,
            .total_message_bytes = 0,
        };
    }

    pub fn deinit(self: *RamContext) void {
        self.clearMessages();
        self.entries.deinit(self.allocator);

        for (self.summaries.items) |summary| {
            self.allocator.free(summary.text);
        }
        self.summaries.deinit(self.allocator);
    }

    pub fn clearMessages(self: *RamContext) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.message.content);
        }
        self.entries.clearRetainingCapacity();
        self.total_message_bytes = 0;
        self.next_id = 1;
    }

    pub fn load(self: *RamContext, allocator: std.mem.Allocator) ![]const ziggy_piai.types.Message {
        self.mutex.lock();
        defer self.mutex.unlock();

        var active_count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.state == .active) active_count += 1;
        }

        var context = try allocator.alloc(ziggy_piai.types.Message, active_count);
        var idx: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.state != .active) continue;
            context[idx] = .{
                .role = entry.message.role,
                .content = try allocator.dupe(u8, entry.message.content),
            };
            idx += 1;
        }

        return context;
    }

    pub fn loadSnapshot(self: *RamContext, allocator: std.mem.Allocator) ![]const ziggy_piai.types.Message {
        return self.load(allocator);
    }

    pub fn update(self: *RamContext, role: ziggy_piai.types.MessageRole, content: []const u8) !MemoryID {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = self.nextMemoryId();
        try self.entries.append(self.allocator, .{
            .id = id,
            .message = .{ .role = role, .content = try self.allocator.dupe(u8, content) },
            .state = .active,
        });
        self.total_message_bytes += content.len;

        try self.applyHardLimitLocked();
        return id;
    }

    pub fn evict(self: *RamContext) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.evictLocked();
    }

    pub fn summarize(self: *RamContext) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.summarizeLocked();
    }

    fn evictLocked(self: *RamContext) !void {
        const removed = self.removeOldestActive() orelse return;
        self.total_message_bytes -= removed.message.content.len;

        const tombstone = try self.buildTombstone(removed.id, "evicted", "[evicted context entry]");
        try self.entries.append(self.allocator, tombstone);

        self.allocator.free(removed.message.content);
    }

    fn summarizeLocked(self: *RamContext) !void {
        const removed = self.removeOldestActive() orelse return;
        self.total_message_bytes -= removed.message.content.len;

        const summary_text = try self.buildSummaryText(removed.id, removed.message.content);
        defer self.allocator.free(summary_text);

        const summary_id = self.nextMemoryId();
        try self.summaries.append(self.allocator, .{
            .id = summary_id,
            .source_id = removed.id,
            .text = try self.allocator.dupe(u8, summary_text),
            .created_at_ms = std.time.milliTimestamp(),
        });

        const tombstone = try self.buildTombstone(removed.id, "summarized", summary_text);
        try self.entries.append(self.allocator, tombstone);
        self.allocator.free(removed.message.content);

        try self.applyHardLimitLocked();
    }

    fn applyHardLimitLocked(self: *RamContext) !void {
        while (self.entries.items.len > self.max_messages or self.total_message_bytes > self.max_bytes) {
            const removed = self.removeOldestActive() orelse return;
            self.total_message_bytes -= removed.message.content.len;

            const tombstone = try self.buildTombstone(removed.id, "evicted", "[evicted context entry]");
            try self.entries.append(self.allocator, tombstone);
            self.allocator.free(removed.message.content);
        }
    }

    fn removeOldestActive(self: *RamContext) ?RamEntry {
        const idx = self.firstActiveIndex() orelse return null;
        return self.entries.orderedRemove(idx);
    }

    fn buildSummaryText(self: *RamContext, source_id: MemoryID, content: []const u8) ![]const u8 {
        const max_len = @min(content.len, 72);
        return std.fmt.allocPrint(self.allocator, "[summary:{d}] {s}", .{ source_id, content[0..max_len] });
    }

    fn buildTombstone(self: *RamContext, source_id: MemoryID, reason: []const u8, payload: []const u8) !RamEntry {
        const tombstone_text = try std.fmt.allocPrint(self.allocator, "[{s}:{d}] {s}", .{ reason, source_id, payload });
        return RamEntry{
            .id = self.nextMemoryId(),
            .message = .{ .role = .system, .content = tombstone_text },
            .state = .tombstone,
            .related_to = source_id,
        };
    }

    fn firstActiveIndex(self: *RamContext) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (entry.state == .active) return idx;
        }
        return null;
    }

    fn nextMemoryId(self: *RamContext) MemoryID {
        defer self.next_id +%= 1;
        return self.next_id;
    }
};
