const std = @import("std");

pub const TalkId = u32;

pub const EventType = enum {
    user,
    agent,
    time,
    hook,
    talk,
    tool,
};

pub const Event = struct {
    event_type: EventType,
    source_brain: []u8,
    target_brain: []u8,
    talk_id: ?TalkId,
    payload: []u8,
    created_at_ms: i64,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        allocator.free(self.source_brain);
        allocator.free(self.target_brain);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const EventInput = struct {
    event_type: EventType,
    source_brain: []const u8,
    target_brain: []const u8,
    talk_id: ?TalkId = null,
    payload: []const u8,
    created_at_ms: ?i64 = null,
};

pub const EventBus = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    events: std.ArrayListUnmanaged(Event) = .{},
    talk_index: std.AutoHashMapUnmanaged(TalkId, usize) = .{},

    pub fn init(allocator: std.mem.Allocator) EventBus {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *EventBus) void {
        self.clear();
        self.events.deinit(self.allocator);
        self.talk_index.deinit(self.allocator);
    }

    pub fn enqueue(self: *EventBus, input: EventInput) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const event = Event{
            .event_type = input.event_type,
            .source_brain = try self.allocator.dupe(u8, input.source_brain),
            .target_brain = try self.allocator.dupe(u8, input.target_brain),
            .talk_id = input.talk_id,
            .payload = try self.allocator.dupe(u8, input.payload),
            .created_at_ms = input.created_at_ms orelse std.time.milliTimestamp(),
        };
        try self.events.append(self.allocator, event);

        if (event.talk_id) |talk_id| {
            const count = self.talk_index.get(talk_id) orelse 0;
            try self.talk_index.put(self.allocator, talk_id, count + 1);
        }
    }

    pub fn dequeueForBrain(self: *EventBus, allocator: std.mem.Allocator, brain: []const u8) ![]Event {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.events.items) |event| {
            const is_broadcast = event.target_brain.len == 0;
            const is_target = std.mem.eql(u8, event.target_brain, brain);
            if (is_broadcast or is_target) count += 1;
        }

        var out = try allocator.alloc(Event, count);
        var out_idx: usize = 0;

        var idx: usize = 0;
        while (idx < self.events.items.len) {
            const event = self.events.items[idx];
            const is_broadcast = event.target_brain.len == 0;
            const is_target = std.mem.eql(u8, event.target_brain, brain);

            if (is_broadcast or is_target) {
                out[out_idx] = event;
                out_idx += 1;
                _ = self.events.orderedRemove(idx);
            } else {
                idx += 1;
            }
        }

        try self.rebuildTalkIndexLocked();
        return out;
    }

    pub fn hasTalkId(self: *EventBus, talk_id: TalkId) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.talk_index.contains(talk_id);
    }

    pub fn pendingCount(self: *EventBus) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.events.items.len;
    }

    pub fn clear(self: *EventBus) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.events.items) |*event| {
            event.deinit(self.allocator);
        }
        self.events.clearRetainingCapacity();
        self.talk_index.clearRetainingCapacity();
    }

    fn rebuildTalkIndexLocked(self: *EventBus) !void {
        self.talk_index.clearRetainingCapacity();
        for (self.events.items) |event| {
            if (event.talk_id) |talk_id| {
                const count = self.talk_index.get(talk_id) orelse 0;
                try self.talk_index.put(self.allocator, talk_id, count + 1);
            }
        }
    }
};

test "event_bus: enqueue and dequeue with brain targeting" {
    const allocator = std.testing.allocator;
    var bus = EventBus.init(allocator);
    defer bus.deinit();

    try bus.enqueue(.{
        .event_type = .user,
        .source_brain = "user",
        .target_brain = "primary",
        .payload = "hello",
    });
    try bus.enqueue(.{
        .event_type = .agent,
        .source_brain = "primary",
        .target_brain = "sub",
        .payload = "sync",
    });

    const primary_events = try bus.dequeueForBrain(allocator, "primary");
    defer {
        for (primary_events) |*event| event.deinit(allocator);
        allocator.free(primary_events);
    }

    try std.testing.expectEqual(@as(usize, 1), primary_events.len);
    try std.testing.expectEqual(EventType.user, primary_events[0].event_type);
    try std.testing.expectEqualStrings("hello", primary_events[0].payload);

    const sub_events = try bus.dequeueForBrain(allocator, "sub");
    defer {
        for (sub_events) |*event| event.deinit(allocator);
        allocator.free(sub_events);
    }
    try std.testing.expectEqual(@as(usize, 1), sub_events.len);
    try std.testing.expectEqualStrings("sync", sub_events[0].payload);
}

test "event_bus: talk id index clears on consume" {
    const allocator = std.testing.allocator;
    var bus = EventBus.init(allocator);
    defer bus.deinit();

    try bus.enqueue(.{
        .event_type = .talk,
        .source_brain = "primary",
        .target_brain = "",
        .talk_id = 42,
        .payload = "spoken",
    });

    try std.testing.expect(bus.hasTalkId(42));

    const events = try bus.dequeueForBrain(allocator, "primary");
    defer {
        for (events) |*event| event.deinit(allocator);
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expect(!bus.hasTalkId(42));
}
