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

const PendingMutation = struct {
    kind: RamMutation,
    id: MemoryID = 0,
    role: ziggy_piai.types.MessageRole = .system,
    content: ?[]const u8 = null,
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
    pending_mutations: std.ArrayListUnmanaged(PendingMutation),
    next_id: MemoryID = 1,
    max_messages: usize,
    max_bytes: usize,
    total_message_bytes: usize,

    pub fn init(allocator: std.mem.Allocator, max_messages: usize, max_bytes: usize) RamContext {
        return .{
            .allocator = allocator,
            .entries = .{},
            .summaries = .{},
            .pending_mutations = .{},
            .max_messages = max_messages,
            .max_bytes = max_bytes,
            .total_message_bytes = 0,
        };
    }

    pub fn deinit(self: *RamContext) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.clearMessages();
        self.entries.deinit(self.allocator);
        self.clearPendingLocked();
        self.pending_mutations.deinit(self.allocator);

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

    fn clearPendingLocked(self: *RamContext) void {
        for (self.pending_mutations.items) |mutation| {
            if (mutation.content) |content| {
                self.allocator.free(content);
            }
        }
        self.pending_mutations.clearRetainingCapacity();
    }

    pub fn load(self: *RamContext, allocator: std.mem.Allocator) ![]const ziggy_piai.types.Message {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.flushPendingLocked();

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
        const owned_content = try self.allocator.dupe(u8, content);
        try self.queueMutationLocked(.{
            .kind = .update,
            .id = id,
            .role = role,
            .content = owned_content,
        });
        try self.flushPendingLocked();
        return id;
    }

    pub fn evict(self: *RamContext) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.queueMutationLocked(.{ .kind = .evict });
        try self.flushPendingLocked();
    }

    pub fn summarize(self: *RamContext) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.queueMutationLocked(.{ .kind = .summarize });
        try self.flushPendingLocked();
    }

    fn queueMutationLocked(self: *RamContext, mutation: PendingMutation) !void {
        try self.pending_mutations.append(self.allocator, mutation);
    }

    fn flushPendingLocked(self: *RamContext) !void {
        while (self.pending_mutations.items.len > 0) {
            const mutation = self.pending_mutations.orderedRemove(0);
            errdefer self.clearMutationContent(&mutation);

            switch (mutation.kind) {
                .load => {},
                .update => {
                    const content = mutation.content orelse return;
                    try self.applyUpdateLocked(mutation.id, mutation.role, content);
                },
                .evict => try self.evictLocked(),
                .summarize => try self.summarizeLocked(),
            }

            self.clearMutationContent(&mutation);
        }
    }

    fn clearMutationContent(self: *RamContext, mutation: *const PendingMutation) void {
        if (mutation.content) |content| {
            self.allocator.free(content);
        }
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

    fn applyUpdateLocked(self: *RamContext, id: MemoryID, role: ziggy_piai.types.MessageRole, content: []const u8) !void {
        try self.entries.append(self.allocator, .{
            .id = id,
            .message = .{ .role = role, .content = try self.allocator.dupe(u8, content) },
            .state = .active,
        });
        self.total_message_bytes += content.len;

        try self.applyHardLimitLocked();
    }

    pub fn restoreEntry(
        self: *RamContext,
        id: MemoryID,
        role: ziggy_piai.types.MessageRole,
        state: RamEntryState,
        related_to: ?MemoryID,
        content: []const u8,
    ) !void {
        try self.entries.append(self.allocator, .{
            .id = id,
            .message = .{ .role = role, .content = try self.allocator.dupe(u8, content) },
            .state = state,
            .related_to = related_to,
        });
        if (state == .active) {
            self.total_message_bytes += content.len;
        }
    }

    pub fn restoreSummary(
        self: *RamContext,
        id: MemoryID,
        source_id: MemoryID,
        text: []const u8,
        created_at_ms: i64,
    ) !void {
        try self.summaries.append(self.allocator, .{
            .id = id,
            .source_id = source_id,
            .text = try self.allocator.dupe(u8, text),
            .created_at_ms = created_at_ms,
        });
    }

    pub fn setNextId(self: *RamContext, next_id: MemoryID) void {
        self.next_id = next_id;
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

test "memory: RAM context assigns stable incremental ids" {
    const allocator = std.testing.allocator;
    var ctx = RamContext.init(allocator, 32, 16 * 1024);
    defer ctx.deinit();

    const user_id = try ctx.update(.user, "hello");
    const assistant_id = try ctx.update(.assistant, "reply");
    const final_id = try ctx.update(.user, "again");

    try std.testing.expectEqual(@as(MemoryID, 1), user_id);
    try std.testing.expectEqual(@as(MemoryID, 2), assistant_id);
    try std.testing.expectEqual(@as(MemoryID, 3), final_id);

    const snapshot = try ctx.load(allocator);
    defer {
        for (snapshot) |msg| allocator.free(msg.content);
        allocator.free(snapshot);
    }
    try std.testing.expectEqual(@as(usize, 3), snapshot.len);
    try std.testing.expectEqual(ziggy_piai.types.MessageRole.user, snapshot[0].role);
    try std.testing.expectEqualStrings("hello", snapshot[0].content);
}

test "memory: summarize mutation creates summary + tombstone links" {
    const allocator = std.testing.allocator;
    var ctx = RamContext.init(allocator, 32, 16 * 1024);
    defer ctx.deinit();

    _ = try ctx.update(.user, "first message");
    _ = try ctx.update(.assistant, "second message");
    try ctx.summarize();

    const context = try ctx.load(allocator);
    defer {
        for (context) |msg| allocator.free(msg.content);
        allocator.free(context);
    }

    try std.testing.expectEqual(@as(usize, 1), context.len);
    try std.testing.expectEqualStrings("second message", context[0].content);

    try std.testing.expectEqual(@as(usize, 1), ctx.summaries.items.len);
    try std.testing.expectEqual(@as(MemoryID, 1), ctx.summaries.items[0].source_id);
    try std.testing.expectEqualStrings("[summary:1] first message", ctx.summaries.items[0].text);

    var found_tombstone = false;
    for (ctx.entries.items) |entry| {
        if (entry.state == .tombstone and entry.related_to == 1) {
            found_tombstone = true;
            break;
        }
    }
    try std.testing.expect(found_tombstone);
}

test "memory: queued mutations apply in FIFO order" {
    const allocator = std.testing.allocator;
    var ctx = RamContext.init(allocator, 16, 16 * 1024);
    defer ctx.deinit();

    const oldest_id = try ctx.update(.user, "oldest");
    try std.testing.expectEqual(@as(MemoryID, 1), oldest_id);

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try ctx.queueMutationLocked(.{
        .kind = .update,
        .id = 11,
        .role = .assistant,
        .content = try allocator.dupe(u8, "queued assistant"),
    });
    try ctx.queueMutationLocked(.{
        .kind = .update,
        .id = 12,
        .role = .assistant,
        .content = try allocator.dupe(u8, "queued assistant two"),
    });
    try ctx.queueMutationLocked(.{ .kind = .evict });
    try ctx.flushPendingLocked();

    var oldest_evicted = false;
    for (ctx.entries.items) |entry| {
        if (entry.state == .tombstone and entry.related_to == oldest_id) {
            oldest_evicted = true;
            break;
        }
    }
    try std.testing.expect(oldest_evicted);

    var active_count: usize = 0;
    for (ctx.entries.items) |entry| {
        if (entry.state == .active) active_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), active_count);
}
