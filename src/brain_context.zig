const std = @import("std");
const event_bus = @import("event_bus.zig");

pub const ToolUse = struct {
    name: []u8,
    args_json: []u8,

    pub fn deinit(self: *ToolUse, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.args_json);
        self.* = undefined;
    }
};

pub const BrainContext = struct {
    allocator: std.mem.Allocator,
    brain_name: []u8,
    ram_mem_ids: std.ArrayListUnmanaged([]u8) = .{},
    rom_mem_ids: std.ArrayListUnmanaged([]u8) = .{},
    inbox: std.ArrayListUnmanaged(event_bus.Event) = .{},
    outbox: std.ArrayListUnmanaged(event_bus.Event) = .{},
    pending_tool_uses: std.ArrayListUnmanaged(ToolUse) = .{},
    pending_wait_json: ?[]u8 = null,
    next_talk_id: event_bus.TalkId = 1,

    pub fn init(allocator: std.mem.Allocator, brain_name: []const u8) !BrainContext {
        return .{
            .allocator = allocator,
            .brain_name = try allocator.dupe(u8, brain_name),
        };
    }

    pub fn deinit(self: *BrainContext) void {
        self.allocator.free(self.brain_name);

        for (self.ram_mem_ids.items) |mem_id| self.allocator.free(mem_id);
        self.ram_mem_ids.deinit(self.allocator);

        for (self.rom_mem_ids.items) |mem_id| self.allocator.free(mem_id);
        self.rom_mem_ids.deinit(self.allocator);

        for (self.inbox.items) |*event| event.deinit(self.allocator);
        self.inbox.deinit(self.allocator);

        for (self.outbox.items) |*event| event.deinit(self.allocator);
        self.outbox.deinit(self.allocator);

        for (self.pending_tool_uses.items) |*tool_use| tool_use.deinit(self.allocator);
        self.pending_tool_uses.deinit(self.allocator);
        if (self.pending_wait_json) |pending| self.allocator.free(pending);
    }

    pub fn queueToolUse(self: *BrainContext, name: []const u8, args_json: []const u8) !void {
        try self.pending_tool_uses.append(self.allocator, .{
            .name = try self.allocator.dupe(u8, name),
            .args_json = try self.allocator.dupe(u8, args_json),
        });
    }

    pub fn pushInbox(self: *BrainContext, event: event_bus.Event) !void {
        try self.inbox.append(self.allocator, event);
    }

    pub fn pushOutbox(self: *BrainContext, event: event_bus.Event) !void {
        try self.outbox.append(self.allocator, event);
    }

    pub fn clearInbox(self: *BrainContext) void {
        for (self.inbox.items) |*event| event.deinit(self.allocator);
        self.inbox.clearRetainingCapacity();
    }

    pub fn clearOutbox(self: *BrainContext) void {
        for (self.outbox.items) |*event| event.deinit(self.allocator);
        self.outbox.clearRetainingCapacity();
    }

    pub fn clearPendingTools(self: *BrainContext) void {
        for (self.pending_tool_uses.items) |*tool_use| tool_use.deinit(self.allocator);
        self.pending_tool_uses.clearRetainingCapacity();
    }

    pub fn consumeInboxIndices(self: *BrainContext, matched_indices: []const usize) void {
        var i: usize = matched_indices.len;
        while (i > 0) {
            i -= 1;
            const index = matched_indices[i];
            var event = self.inbox.orderedRemove(index);
            event.deinit(self.allocator);
        }
    }

    pub fn setPendingWait(self: *BrainContext, wait_json: []const u8) !void {
        self.clearPendingWait();
        self.pending_wait_json = try self.allocator.dupe(u8, wait_json);
    }

    pub fn clearPendingWait(self: *BrainContext) void {
        if (self.pending_wait_json) |pending| {
            self.allocator.free(pending);
            self.pending_wait_json = null;
        }
    }

    pub fn hasPendingWait(self: *const BrainContext) bool {
        return self.pending_wait_json != null;
    }

    pub fn nextTalkId(self: *BrainContext) event_bus.TalkId {
        const talk_id = self.next_talk_id;
        self.next_talk_id +%= 1;
        if (self.next_talk_id == 0) {
            self.next_talk_id = 1;
        }
        return if (talk_id == 0) 1 else talk_id;
    }
};

test "brain_context: talk id is monotonic and skips zero" {
    const allocator = std.testing.allocator;
    var context = try BrainContext.init(allocator, "primary");
    defer context.deinit();

    context.next_talk_id = std.math.maxInt(event_bus.TalkId);
    const first = context.nextTalkId();
    const second = context.nextTalkId();

    try std.testing.expectEqual(std.math.maxInt(event_bus.TalkId), first);
    try std.testing.expectEqual(@as(event_bus.TalkId, 1), second);
}
