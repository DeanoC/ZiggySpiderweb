const std = @import("std");

pub const ConnectionHandler = *const fn (
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    ctx: ?*anyopaque,
) anyerror!void;

pub const ConnectionDispatcher = struct {
    allocator: std.mem.Allocator,
    handler: ConnectionHandler,
    handler_ctx: ?*anyopaque,
    max_queue: usize,

    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: std.ArrayListUnmanaged(std.net.Stream) = .{},
    stopping: bool = false,
    threads: []std.Thread,

    pub fn create(
        allocator: std.mem.Allocator,
        worker_threads: usize,
        max_queue: usize,
        handler: ConnectionHandler,
        handler_ctx: ?*anyopaque,
    ) !*ConnectionDispatcher {
        const worker_count = if (worker_threads == 0) 1 else worker_threads;

        const self = try allocator.create(ConnectionDispatcher);
        self.* = .{
            .allocator = allocator,
            .handler = handler,
            .handler_ctx = handler_ctx,
            .max_queue = max_queue,
            .threads = try allocator.alloc(std.Thread, worker_count),
        };

        var launched: usize = 0;
        errdefer {
            self.stopping = true;
            self.cond.broadcast();
            var i: usize = 0;
            while (i < launched) : (i += 1) {
                self.threads[i].join();
            }
            allocator.free(self.threads);
            allocator.destroy(self);
        }

        while (launched < self.threads.len) : (launched += 1) {
            self.threads[launched] = try std.Thread.spawn(.{}, workerMain, .{self});
        }

        return self;
    }

    pub fn destroy(self: *ConnectionDispatcher) void {
        self.mutex.lock();
        self.stopping = true;
        self.cond.broadcast();
        self.mutex.unlock();

        for (self.threads) |thread| {
            thread.join();
        }

        self.mutex.lock();
        for (self.queue.items) |stream| {
            stream.close();
        }
        self.queue.deinit(self.allocator);
        self.mutex.unlock();

        self.allocator.free(self.threads);
        self.allocator.destroy(self);
    }

    pub fn enqueue(self: *ConnectionDispatcher, stream: std.net.Stream) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.stopping) return false;
        if (self.queue.items.len >= self.max_queue) return false;

        try self.queue.append(self.allocator, stream);
        self.cond.signal();
        return true;
    }

    fn workerMain(self: *ConnectionDispatcher) void {
        while (true) {
            var stream = self.dequeue() orelse return;

            self.handler(self.allocator, &stream, self.handler_ctx) catch |err| {
                std.log.warn("connection worker handler failed: {s}", .{@errorName(err)});
            };
            stream.close();
        }
    }

    fn dequeue(self: *ConnectionDispatcher) ?std.net.Stream {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (!self.stopping and self.queue.items.len == 0) {
            self.cond.wait(&self.mutex);
        }

        if (self.queue.items.len == 0) return null;
        return self.queue.orderedRemove(0);
    }
};
