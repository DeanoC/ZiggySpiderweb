const std = @import("std");
const fs_router = @import("acheron_fs_router");
const mount_provider = @import("spiderweb_mount_provider");

pub const MountSession = struct {
    allocator: std.mem.Allocator,
    provider: mount_provider.Provider,
    handles: std.AutoHashMapUnmanaged(u64, mount_provider.OpenFile) = .{},
    next_local_handle: u64 = 1,
    provider_mutex: std.Thread.Mutex = .{},
    handles_mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, provider: mount_provider.Provider) MountSession {
        return .{
            .allocator = allocator,
            .provider = provider,
        };
    }

    pub fn deinit(self: *MountSession) void {
        self.handles_mutex.lock();
        var handles = self.handles;
        self.handles = .{};
        self.handles_mutex.unlock();
        defer handles.deinit(self.allocator);

        var it = handles.valueIterator();
        while (it.next()) |open_file| {
            self.provider_mutex.lock();
            self.provider.release(open_file.*) catch {};
            self.provider_mutex.unlock();
        }
        self.provider.deinit();
    }

    pub fn getattr(self: *MountSession, path: []const u8) ![]u8 {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.getattr(path);
    }

    pub fn readdir(self: *MountSession, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.readdir(path, cookie, max_entries);
    }

    pub fn statfs(self: *MountSession, path: []const u8) ![]u8 {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.statfs(path);
    }

    pub fn open(self: *MountSession, path: []const u8, flags: u32) !mount_provider.OpenFile {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.open(path, flags);
    }

    pub fn openAndStoreHandle(self: *MountSession, path: []const u8, flags: u32) !u64 {
        self.provider_mutex.lock();
        errdefer self.provider_mutex.unlock();
        const open_file = try self.provider.open(path, flags);
        self.provider_mutex.unlock();
        errdefer {
            self.provider_mutex.lock();
            self.provider.release(open_file) catch {};
            self.provider_mutex.unlock();
        }

        self.handles_mutex.lock();
        defer self.handles_mutex.unlock();
        const local_id = self.reserveLocalHandleLocked();
        try self.handles.put(self.allocator, local_id, open_file);
        return local_id;
    }

    pub fn read(self: *MountSession, file: mount_provider.OpenFile, off: u64, len: u32) ![]u8 {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.read(file, off, len);
    }

    pub fn release(self: *MountSession, file: mount_provider.OpenFile) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.release(file);
    }

    pub fn create(self: *MountSession, path: []const u8, mode: u32, flags: u32) !mount_provider.OpenFile {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.create(path, mode, flags);
    }

    pub fn createAndStoreHandle(self: *MountSession, path: []const u8, mode: u32, flags: u32) !u64 {
        self.provider_mutex.lock();
        errdefer self.provider_mutex.unlock();
        const open_file = try self.provider.create(path, mode, flags);
        self.provider_mutex.unlock();
        errdefer {
            self.provider_mutex.lock();
            self.provider.release(open_file) catch {};
            self.provider_mutex.unlock();
        }

        self.handles_mutex.lock();
        defer self.handles_mutex.unlock();
        const local_id = self.reserveLocalHandleLocked();
        try self.handles.put(self.allocator, local_id, open_file);
        return local_id;
    }

    pub fn write(self: *MountSession, file: mount_provider.OpenFile, off: u64, data: []const u8) !u32 {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.write(file, off, data);
    }

    pub fn truncate(self: *MountSession, path: []const u8, size: u64) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.truncate(path, size);
    }

    pub fn unlink(self: *MountSession, path: []const u8) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.unlink(path);
    }

    pub fn mkdir(self: *MountSession, path: []const u8) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.mkdir(path);
    }

    pub fn rmdir(self: *MountSession, path: []const u8) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.rmdir(path);
    }

    pub fn rename(self: *MountSession, old_path: []const u8, new_path: []const u8) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.rename(old_path, new_path);
    }

    pub fn symlink(self: *MountSession, target: []const u8, link_path: []const u8) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.symlink(target, link_path);
    }

    pub fn setxattr(self: *MountSession, path: []const u8, name: []const u8, value: []const u8, flags: u32) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.setxattr(path, name, value, flags);
    }

    pub fn getxattr(self: *MountSession, path: []const u8, name: []const u8) ![]u8 {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.getxattr(path, name);
    }

    pub fn listxattr(self: *MountSession, path: []const u8) ![]u8 {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        return self.provider.listxattr(path);
    }

    pub fn removexattr(self: *MountSession, path: []const u8, name: []const u8) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.removexattr(path, name);
    }

    pub fn lock(self: *MountSession, file: mount_provider.OpenFile, mode: mount_provider.LockMode, wait: bool) !void {
        self.provider_mutex.lock();
        defer self.provider_mutex.unlock();
        try self.provider.lock(file, mode, wait);
    }

    pub fn tryReconcileEndpointsIfIdle(self: *MountSession, endpoint_configs: []const fs_router.EndpointConfig) !bool {
        if (!self.provider_mutex.tryLock()) return false;
        defer self.provider_mutex.unlock();
        self.handles_mutex.lock();
        const has_handles = self.handles.count() != 0;
        self.handles_mutex.unlock();
        if (has_handles) return false;
        return self.provider.tryReconcileEndpointsIfIdle(endpoint_configs);
    }

    pub fn tryKeepAliveIfIdle(self: *MountSession) !bool {
        if (!self.provider_mutex.tryLock()) return false;
        defer self.provider_mutex.unlock();
        self.handles_mutex.lock();
        const has_handles = self.handles.count() != 0;
        self.handles_mutex.unlock();
        if (has_handles) return false;
        return self.provider.tryKeepAliveIfIdle();
    }

    pub fn lookupOpenHandle(self: *MountSession, local_id: u64) ?mount_provider.OpenFile {
        self.handles_mutex.lock();
        defer self.handles_mutex.unlock();
        return self.handles.get(local_id);
    }

    pub fn releaseStoredHandle(self: *MountSession, local_id: u64) void {
        self.handles_mutex.lock();
        const removed = self.handles.fetchRemove(local_id);
        self.handles_mutex.unlock();
        if (removed) |entry| {
            self.provider_mutex.lock();
            self.provider.release(entry.value) catch {};
            self.provider_mutex.unlock();
        }
    }

    fn reserveLocalHandleLocked(self: *MountSession) u64 {
        var local_id = self.next_local_handle;
        self.next_local_handle +%= 1;
        if (local_id == 0) {
            local_id = self.next_local_handle;
            self.next_local_handle +%= 1;
        }
        return local_id;
    }
};
