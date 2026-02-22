const std = @import("std");
const builtin = @import("builtin");
const fs_protocol = @import("fs_protocol.zig");
const fs_node_service = @import("fs_node_service.zig");

const c = if (builtin.os.tag == .linux) @cImport({
    @cInclude("sys/inotify.h");
}) else struct {};

pub const Backend = enum {
    scanner,
    inotify,
};

pub const Config = struct {
    poll_interval_ms: u64 = 350,
    max_events: usize = 2048,
    inotify_poll_timeout_ms: i32 = 500,
};

pub const EmitEventsFn = *const fn (ctx: ?*anyopaque, events: []const fs_protocol.InvalidationEvent) void;

pub fn spawnDetached(
    allocator: std.mem.Allocator,
    service: *fs_node_service.NodeService,
    emit_fn: EmitEventsFn,
    emit_ctx: ?*anyopaque,
    config: Config,
) !Backend {
    if (builtin.os.tag == .linux) {
        const roots = try service.copyExportRootPaths(allocator);
        defer freePaths(allocator, roots);

        if (InotifyWatcher.init(allocator, roots)) |watcher| {
            const ctx = try allocator.create(Context);
            ctx.* = .{
                .allocator = allocator,
                .service = service,
                .emit_fn = emit_fn,
                .emit_ctx = emit_ctx,
                .config = config,
                .mode = .{ .inotify = watcher },
            };
            const thread = try std.Thread.spawn(.{}, threadMain, .{ctx});
            thread.detach();
            return .inotify;
        } else |_| {}
    }

    const ctx = try allocator.create(Context);
    ctx.* = .{
        .allocator = allocator,
        .service = service,
        .emit_fn = emit_fn,
        .emit_ctx = emit_ctx,
        .config = config,
        .mode = .scanner,
    };
    const thread = try std.Thread.spawn(.{}, threadMain, .{ctx});
    thread.detach();
    return .scanner;
}

const Context = struct {
    allocator: std.mem.Allocator,
    service: *fs_node_service.NodeService,
    emit_fn: EmitEventsFn,
    emit_ctx: ?*anyopaque,
    config: Config,
    mode: union(enum) {
        scanner,
        inotify: InotifyWatcher,
    },
};

fn threadMain(ctx: *Context) void {
    defer {
        switch (ctx.mode) {
            .scanner => {},
            .inotify => |*watcher| watcher.deinit(),
        }
        ctx.allocator.destroy(ctx);
    }

    // Prime baseline snapshot so first observed external mutation produces events.
    _ = ctx.service.pollFilesystemInvalidations(ctx.config.max_events) catch {};

    switch (ctx.mode) {
        .scanner => scannerLoop(ctx),
        .inotify => inotifyLoop(ctx),
    }
}

fn scannerLoop(ctx: *Context) void {
    while (true) {
        emitScannerDiff(ctx);
        std.Thread.sleep(ctx.config.poll_interval_ms * std.time.ns_per_ms);
    }
}

fn inotifyLoop(ctx: *Context) void {
    while (true) {
        const changed = ctx.mode.inotify.waitForChange(ctx.config.inotify_poll_timeout_ms) catch {
            emitScannerDiff(ctx);
            std.Thread.sleep(ctx.config.poll_interval_ms * std.time.ns_per_ms);
            continue;
        };
        if (!changed) {
            // Keep eventual consistency even if a native event edge is missed.
            emitScannerDiff(ctx);
            continue;
        }
        emitScannerDiff(ctx);
    }
}

fn emitScannerDiff(ctx: *Context) void {
    const events = ctx.service.pollFilesystemInvalidations(ctx.config.max_events) catch return;
    defer ctx.allocator.free(events);
    if (events.len == 0) return;
    ctx.emit_fn(ctx.emit_ctx, events);
}

fn freePaths(allocator: std.mem.Allocator, paths: [][]u8) void {
    for (paths) |path| allocator.free(path);
    allocator.free(paths);
}

const InotifyWatcher = struct {
    allocator: std.mem.Allocator,
    fd: i32,
    wd_paths: std.AutoHashMapUnmanaged(i32, []u8) = .{},

    fn init(allocator: std.mem.Allocator, roots: []const []const u8) !InotifyWatcher {
        const fd = try std.posix.inotify_init1(@intCast(c.IN_NONBLOCK | c.IN_CLOEXEC));
        errdefer std.posix.close(fd);

        var watcher = InotifyWatcher{
            .allocator = allocator,
            .fd = fd,
        };
        errdefer watcher.deinit();

        for (roots) |root_path| {
            watcher.addWatchRecursive(root_path) catch {};
        }
        return watcher;
    }

    fn deinit(self: *InotifyWatcher) void {
        var it = self.wd_paths.valueIterator();
        while (it.next()) |path| self.allocator.free(path.*);
        self.wd_paths.deinit(self.allocator);
        std.posix.close(self.fd);
    }

    fn waitForChange(self: *InotifyWatcher, timeout_ms: i32) !bool {
        var fds = [_]std.posix.pollfd{
            .{
                .fd = self.fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            },
        };
        const ready = try std.posix.poll(&fds, timeout_ms);
        if (ready == 0) return false;
        if ((fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) {
            return error.WatcherFdClosed;
        }
        if ((fds[0].revents & std.posix.POLL.IN) == 0) return false;

        var file = std.fs.File{ .handle = self.fd };
        var buf: [32 * 1024]u8 = undefined;
        const n = file.read(&buf) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => return err,
        };
        if (n == 0) return false;

        var saw_change = false;
        const header_size = @sizeOf(std.os.linux.inotify_event);
        var offset: usize = 0;
        while (offset + header_size <= n) {
            var ev: std.os.linux.inotify_event = undefined;
            @memcpy(std.mem.asBytes(&ev), buf[offset .. offset + header_size]);
            offset += header_size;

            const name_len: usize = @intCast(ev.len);
            if (offset + name_len > n) break;
            const name_bytes = buf[offset .. offset + name_len];
            offset += name_len;
            const nul = std.mem.indexOfScalar(u8, name_bytes, 0) orelse name_bytes.len;
            const name = name_bytes[0..nul];

            const mask = ev.mask;
            if ((mask & @as(u32, c.IN_IGNORED)) != 0 or
                (mask & (@as(u32, c.IN_DELETE_SELF) | @as(u32, c.IN_MOVE_SELF))) != 0)
            {
                self.removeWatch(ev.wd);
            }

            if ((mask & (@as(u32, c.IN_CREATE) | @as(u32, c.IN_MOVED_TO) | @as(u32, c.IN_ATTRIB) | @as(u32, c.IN_MODIFY) | @as(u32, c.IN_CLOSE_WRITE) | @as(u32, c.IN_DELETE) | @as(u32, c.IN_MOVED_FROM) | @as(u32, c.IN_DELETE_SELF) | @as(u32, c.IN_MOVE_SELF) | @as(u32, c.IN_Q_OVERFLOW))) != 0) {
                saw_change = true;
            }

            if ((mask & @as(u32, c.IN_ISDIR)) != 0 and
                (mask & (@as(u32, c.IN_CREATE) | @as(u32, c.IN_MOVED_TO))) != 0 and
                name.len > 0)
            {
                const parent = self.wd_paths.get(ev.wd) orelse continue;
                const child_path = std.fs.path.join(self.allocator, &.{ parent, name }) catch continue;
                defer self.allocator.free(child_path);
                self.addWatchRecursive(child_path) catch {};
            }
        }
        return saw_change;
    }

    fn addWatchRecursive(self: *InotifyWatcher, root_path: []const u8) !void {
        var stack = std.ArrayListUnmanaged([]u8){};
        defer {
            while (stack.pop()) |path| self.allocator.free(path);
            stack.deinit(self.allocator);
        }

        try stack.append(self.allocator, try self.allocator.dupe(u8, root_path));
        while (stack.pop()) |dir_path| {
            defer self.allocator.free(dir_path);
            self.addWatchDir(dir_path) catch |err| switch (err) {
                error.AccessDenied, error.FileNotFound, error.NotDir => continue,
                else => return err,
            };

            var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch |err| switch (err) {
                error.AccessDenied, error.FileNotFound, error.NotDir => continue,
                else => return err,
            };
            defer dir.close();

            var it = dir.iterate();
            while (true) {
                const maybe_entry = it.next() catch |err| switch (err) {
                    error.AccessDenied, error.PermissionDenied, error.InvalidUtf8 => break,
                    else => return err,
                };
                const entry = maybe_entry orelse break;
                if (entry.kind != .directory) continue;

                const child = std.fs.path.join(self.allocator, &.{ dir_path, entry.name }) catch continue;
                try stack.append(self.allocator, child);
            }
        }
    }

    fn addWatchDir(self: *InotifyWatcher, path: []const u8) !void {
        const mask: u32 = @as(u32, c.IN_ATTRIB) |
            @as(u32, c.IN_CLOSE_WRITE) |
            @as(u32, c.IN_CREATE) |
            @as(u32, c.IN_DELETE) |
            @as(u32, c.IN_DELETE_SELF) |
            @as(u32, c.IN_MODIFY) |
            @as(u32, c.IN_MOVE_SELF) |
            @as(u32, c.IN_MOVED_FROM) |
            @as(u32, c.IN_MOVED_TO);
        const wd = try std.posix.inotify_add_watch(self.fd, path, mask);
        const owned = try self.allocator.dupe(u8, path);
        if (try self.wd_paths.fetchPut(self.allocator, wd, owned)) |existing| {
            self.allocator.free(existing.value);
        }
    }

    fn removeWatch(self: *InotifyWatcher, wd: i32) void {
        if (self.wd_paths.fetchRemove(wd)) |removed| {
            self.allocator.free(removed.value);
        }
    }
};
