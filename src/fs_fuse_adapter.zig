const std = @import("std");
const fs_protocol = @import("fs_protocol.zig");
const fs_router = @import("fs_router.zig");

const c = @cImport({
    @cInclude("fuse_compat.h");
});

var active_adapter: ?*FuseAdapter = null;

const FuseMainRealVersionedFn = *const fn (
    c_int,
    [*c][*c]u8,
    [*c]const c.struct_fuse_operations,
    usize,
    ?*c.struct_libfuse_version,
    ?*anyopaque,
) callconv(.c) c_int;

const FuseMainRealFn = *const fn (
    c_int,
    [*c][*c]u8,
    [*c]const c.struct_fuse_operations,
    usize,
    ?*anyopaque,
) callconv(.c) c_int;

pub const FuseAdapter = struct {
    allocator: std.mem.Allocator,
    router: *fs_router.Router,
    handles: std.AutoHashMapUnmanaged(u64, fs_router.OpenFile) = .{},
    next_local_handle: u64 = 1,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, router: *fs_router.Router) FuseAdapter {
        return .{
            .allocator = allocator,
            .router = router,
        };
    }

    pub fn deinit(self: *FuseAdapter) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.handles.valueIterator();
        while (it.next()) |open_file| {
            self.router.close(open_file.*) catch {};
        }
        self.handles.deinit(self.allocator);
    }

    pub fn getattr(self: *FuseAdapter, path: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.getattr(path);
    }

    pub fn readdir(self: *FuseAdapter, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.readdir(path, cookie, max_entries);
    }

    pub fn statfs(self: *FuseAdapter, path: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.statfs(path);
    }

    pub fn open(self: *FuseAdapter, path: []const u8, flags: u32) !fs_router.OpenFile {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.open(path, flags);
    }

    pub fn read(self: *FuseAdapter, file: fs_router.OpenFile, off: u64, len: u32) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.read(file, off, len);
    }

    pub fn release(self: *FuseAdapter, file: fs_router.OpenFile) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.close(file);
    }

    pub fn create(self: *FuseAdapter, path: []const u8, mode: u32, flags: u32) !fs_router.OpenFile {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.create(path, mode, flags);
    }

    pub fn write(self: *FuseAdapter, file: fs_router.OpenFile, off: u64, data: []const u8) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.write(file, off, data);
    }

    pub fn truncate(self: *FuseAdapter, path: []const u8, size: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.truncate(path, size);
    }

    pub fn unlink(self: *FuseAdapter, path: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.unlink(path);
    }

    pub fn mkdir(self: *FuseAdapter, path: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.mkdir(path);
    }

    pub fn rmdir(self: *FuseAdapter, path: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.rmdir(path);
    }

    pub fn rename(self: *FuseAdapter, old_path: []const u8, new_path: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.rename(old_path, new_path);
    }

    pub fn symlink(self: *FuseAdapter, target: []const u8, link_path: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.symlink(target, link_path);
    }

    pub fn setxattr(self: *FuseAdapter, path: []const u8, name: []const u8, value: []const u8, flags: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.setxattr(path, name, value, flags);
    }

    pub fn getxattr(self: *FuseAdapter, path: []const u8, name: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.getxattr(path, name);
    }

    pub fn listxattr(self: *FuseAdapter, path: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.router.listxattr(path);
    }

    pub fn removexattr(self: *FuseAdapter, path: []const u8, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.removexattr(path, name);
    }

    pub fn lock(self: *FuseAdapter, file: fs_router.OpenFile, mode: fs_router.LockMode, wait: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.router.lock(file, mode, wait);
    }

    pub fn tryReconcileEndpointsIfIdle(
        self: *FuseAdapter,
        endpoint_configs: []const fs_router.EndpointConfig,
    ) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.handles.count() != 0) return false;
        try self.router.reconcileEndpoints(endpoint_configs);
        return true;
    }

    pub fn mount(self: *FuseAdapter, mountpoint: []const u8) !void {
        if (mountpoint.len == 0) return error.InvalidMountpoint;
        if (active_adapter != null) return error.AlreadyMounted;

        var ops = std.mem.zeroes(c.struct_fuse_operations);
        ops.getattr = cGetattr;
        ops.readdir = cReaddir;
        ops.statfs = cStatfs;
        ops.open = cOpen;
        ops.read = cRead;
        ops.write = cWrite;
        ops.release = cRelease;
        ops.create = cCreate;
        ops.truncate = cTruncate;
        ops.unlink = cUnlink;
        ops.mkdir = cMkdir;
        ops.rmdir = cRmdir;
        ops.rename = cRename;
        ops.symlink = cSymlink;
        ops.setxattr = cSetxattr;
        ops.getxattr = cGetxattr;
        ops.listxattr = cListxattr;
        ops.removexattr = cRemovexattr;
        ops.flock = cFlock;

        var argv = std.ArrayListUnmanaged([*:0]u8){};
        defer {
            for (argv.items) |arg| freeArgZ(self.allocator, arg);
            argv.deinit(self.allocator);
        }

        try appendArgZ(self.allocator, &argv, "spiderweb-fs-mount");
        try appendArgZ(self.allocator, &argv, "-f");
        try appendArgZ(self.allocator, &argv, "-s");
        try appendArgZ(self.allocator, &argv, "-o");
        try appendArgZ(self.allocator, &argv, "default_permissions");
        try appendArgZ(self.allocator, &argv, mountpoint);

        active_adapter = self;
        defer active_adapter = null;

        var lib = try openFuseLibrary();
        defer lib.close();

        const argc: c_int = @intCast(argv.items.len);
        const argv_ptr: [*c][*c]u8 = @ptrCast(argv.items.ptr);
        const rc = if (lib.lookup(FuseMainRealVersionedFn, "fuse_main_real_versioned")) |fuse_main_real_versioned|
            fuse_main_real_versioned(
                argc,
                argv_ptr,
                &ops,
                @sizeOf(c.struct_fuse_operations),
                null,
                null,
            )
        else if (lib.lookup(FuseMainRealFn, "fuse_main_real")) |fuse_main_real|
            fuse_main_real(
                argc,
                argv_ptr,
                &ops,
                @sizeOf(c.struct_fuse_operations),
                null,
            )
        else
            return error.MissingFuseSymbol;
        if (rc != 0) return error.FuseMainFailed;
    }

    fn storeOpenHandle(self: *FuseAdapter, open_file: fs_router.OpenFile) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var local_id = self.next_local_handle;
        self.next_local_handle +%= 1;
        if (local_id == 0) {
            local_id = self.next_local_handle;
            self.next_local_handle +%= 1;
        }

        try self.handles.put(self.allocator, local_id, open_file);
        return local_id;
    }

    fn lookupOpenHandle(self: *FuseAdapter, local_id: u64) ?fs_router.OpenFile {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.handles.get(local_id);
    }

    fn releaseStoredHandle(self: *FuseAdapter, local_id: u64) void {
        self.mutex.lock();
        const removed = self.handles.fetchRemove(local_id);
        self.mutex.unlock();
        if (removed) |entry| {
            self.router.close(entry.value) catch {};
        }
    }
};

fn openFuseLibrary() !std.DynLib {
    const candidates = [_][]const u8{
        "libfuse3.so.3",
        "/lib/x86_64-linux-gnu/libfuse3.so.3",
        "/usr/lib/x86_64-linux-gnu/libfuse3.so.3",
        "libfuse3.so",
    };
    for (candidates) |candidate| {
        if (std.DynLib.open(candidate)) |lib| return lib else |_| {}
    }
    return error.FuseLibraryNotFound;
}

fn appendArgZ(allocator: std.mem.Allocator, argv: *std.ArrayListUnmanaged([*:0]u8), arg: []const u8) !void {
    const owned = try allocator.dupeZ(u8, arg);
    try argv.append(allocator, @ptrCast(owned.ptr));
}

fn freeArgZ(allocator: std.mem.Allocator, arg: [*:0]u8) void {
    const len = std.mem.len(arg);
    allocator.free(arg[0 .. len + 1]);
}

fn cGetattr(path_c: [*c]const u8, st_c: [*c]c.struct_stat, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    _ = fi;
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or st_c == null) return -fs_protocol.Errno.EINVAL;

    const path = std.mem.span(path_c);
    const attr_json = adapter.getattr(path) catch |err| return toFuseError(err);
    defer adapter.allocator.free(attr_json);

    parseAndFillStat(adapter.allocator, st_c, attr_json) catch |err| return toFuseError(err);
    return 0;
}

fn cReaddir(
    path_c: [*c]const u8,
    buf: ?*anyopaque,
    filler: c.fuse_fill_dir_t,
    off: c.off_t,
    fi: ?*c.struct_fuse_file_info,
    flags: c.enum_fuse_readdir_flags,
) callconv(.c) c_int {
    _ = fi;
    _ = flags;

    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);

    if (std.mem.eql(u8, path, "/")) {
        if (filler == null) return -fs_protocol.Errno.EINVAL;
        if (off <= 0) {
            if (filler.?(buf, ".", null, 0, c.FUSE_FILL_DIR_DEFAULTS) != 0) return 0;
            if (filler.?(buf, "..", null, 0, c.FUSE_FILL_DIR_DEFAULTS) != 0) return 0;
        }
    }

    const cookie: u64 = if (off <= 0) 0 else @intCast(off);
    const listing = adapter.readdir(path, cookie, 4096) catch |err| return toFuseError(err);
    defer adapter.allocator.free(listing);

    var parsed = std.json.parseFromSlice(std.json.Value, adapter.allocator, listing, .{}) catch return -fs_protocol.Errno.EIO;
    defer parsed.deinit();
    if (parsed.value != .object) return -fs_protocol.Errno.EIO;
    const ents = parsed.value.object.get("ents") orelse return -fs_protocol.Errno.EIO;
    if (ents != .array) return -fs_protocol.Errno.EIO;

    if (filler == null) return -fs_protocol.Errno.EINVAL;
    for (ents.array.items) |entry| {
        if (entry != .object) continue;
        const name_val = entry.object.get("name") orelse continue;
        if (name_val != .string) continue;
        const name_z = adapter.allocator.dupeZ(u8, name_val.string) catch return -fs_protocol.Errno.EIO;
        defer adapter.allocator.free(name_z);
        if (filler.?(buf, @ptrCast(name_z.ptr), null, 0, c.FUSE_FILL_DIR_DEFAULTS) != 0) break;
    }
    return 0;
}

fn cStatfs(path_c: [*c]const u8, stbuf: [*c]c.struct_statvfs) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or stbuf == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    const statfs_json = adapter.statfs(path) catch |err| return toFuseError(err);
    defer adapter.allocator.free(statfs_json);
    parseAndFillStatvfs(adapter.allocator, stbuf, statfs_json) catch |err| return toFuseError(err);
    return 0;
}

fn cOpen(path_c: [*c]const u8, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    const flags = if (fi) |info| @as(u32, @intCast(c.spiderweb_fi_get_flags(info))) else @as(u32, 0);
    const opened = adapter.open(path, flags) catch |err| return toFuseError(err);
    if (fi) |info| {
        const local_id = adapter.storeOpenHandle(opened) catch {
            adapter.release(opened) catch {};
            return -fs_protocol.Errno.EIO;
        };
        c.spiderweb_fi_set_fh(info, local_id);
    } else {
        adapter.release(opened) catch {};
    }
    return 0;
}

fn cRead(path_c: [*c]const u8, buf: [*c]u8, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    if (off < 0) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);

    var open_file: fs_router.OpenFile = undefined;
    var owns_close = false;
    if (fi) |info| {
        const local_id = c.spiderweb_fi_get_fh(info);
        if (local_id != 0) {
            if (adapter.lookupOpenHandle(local_id)) |existing| {
                open_file = existing;
            } else {
                const flags = @as(u32, @intCast(c.spiderweb_fi_get_flags(info)));
                open_file = adapter.open(path, flags) catch |err| return toFuseError(err);
                owns_close = true;
            }
        } else {
            const flags = @as(u32, @intCast(c.spiderweb_fi_get_flags(info)));
            open_file = adapter.open(path, flags) catch |err| return toFuseError(err);
            owns_close = true;
        }
    } else {
        open_file = adapter.open(path, 0) catch |err| return toFuseError(err);
        owns_close = true;
    }
    defer if (owns_close) adapter.release(open_file) catch {};

    const data = adapter.read(open_file, @intCast(off), @intCast(@min(size, std.math.maxInt(u32)))) catch |err| return toFuseError(err);
    defer adapter.allocator.free(data);
    if (data.len == 0) return 0;
    if (buf == null) return -fs_protocol.Errno.EIO;

    @memcpy(buf[0..data.len], data);
    return @intCast(data.len);
}

fn cWrite(path_c: [*c]const u8, buf: [*c]const u8, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    if (off < 0) return -fs_protocol.Errno.EINVAL;
    if (size > 0 and buf == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);

    var open_file: fs_router.OpenFile = undefined;
    var owns_close = false;
    if (fi) |info| {
        const local_id = c.spiderweb_fi_get_fh(info);
        if (local_id != 0) {
            if (adapter.lookupOpenHandle(local_id)) |existing| {
                open_file = existing;
            } else {
                const flags = @as(u32, @intCast(c.spiderweb_fi_get_flags(info)));
                open_file = adapter.open(path, flags) catch |err| return toFuseError(err);
                owns_close = true;
            }
        } else {
            const flags = @as(u32, @intCast(c.spiderweb_fi_get_flags(info)));
            open_file = adapter.open(path, flags) catch |err| return toFuseError(err);
            owns_close = true;
        }
    } else {
        open_file = adapter.open(path, 2) catch |err| return toFuseError(err);
        owns_close = true;
    }
    defer if (owns_close) adapter.release(open_file) catch {};

    const input = if (size == 0) "" else buf[0..size];
    const written = adapter.write(open_file, @intCast(off), input) catch |err| return toFuseError(err);
    return @intCast(written);
}

fn cRelease(path_c: [*c]const u8, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    _ = path_c;
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (fi) |info| {
        const local_id = c.spiderweb_fi_get_fh(info);
        if (local_id != 0) {
            c.spiderweb_fi_set_fh(info, 0);
            adapter.releaseStoredHandle(local_id);
        }
    }
    return 0;
}

fn cCreate(path_c: [*c]const u8, mode: c.mode_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    const flags = if (fi) |info| @as(u32, @intCast(c.spiderweb_fi_get_flags(info))) else @as(u32, 2);
    const opened = adapter.create(path, @intCast(mode), flags) catch |err| return toFuseError(err);
    if (fi) |info| {
        const local_id = adapter.storeOpenHandle(opened) catch {
            adapter.release(opened) catch {};
            return -fs_protocol.Errno.EIO;
        };
        c.spiderweb_fi_set_fh(info, local_id);
    } else {
        adapter.release(opened) catch {};
    }
    return 0;
}

fn cTruncate(path_c: [*c]const u8, size: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    _ = fi;
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    if (size < 0) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    adapter.truncate(path, @intCast(size)) catch |err| return toFuseError(err);
    return 0;
}

fn cUnlink(path_c: [*c]const u8) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    adapter.unlink(std.mem.span(path_c)) catch |err| return toFuseError(err);
    return 0;
}

fn cMkdir(path_c: [*c]const u8, mode: c.mode_t) callconv(.c) c_int {
    _ = mode;
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    adapter.mkdir(std.mem.span(path_c)) catch |err| return toFuseError(err);
    return 0;
}

fn cRmdir(path_c: [*c]const u8) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    adapter.rmdir(std.mem.span(path_c)) catch |err| return toFuseError(err);
    return 0;
}

fn cRename(from_c: [*c]const u8, to_c: [*c]const u8, flags: c_uint) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (from_c == null or to_c == null) return -fs_protocol.Errno.EINVAL;
    if (flags != 0) return -fs_protocol.Errno.EINVAL;
    adapter.rename(std.mem.span(from_c), std.mem.span(to_c)) catch |err| return toFuseError(err);
    return 0;
}

fn cSymlink(target_c: [*c]const u8, linkpath_c: [*c]const u8) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (target_c == null or linkpath_c == null) return -fs_protocol.Errno.EINVAL;
    adapter.symlink(std.mem.span(target_c), std.mem.span(linkpath_c)) catch |err| return toFuseError(err);
    return 0;
}

fn cSetxattr(path_c: [*c]const u8, name_c: [*c]const u8, value_c: [*c]const u8, size: usize, flags: c_int) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or name_c == null) return -fs_protocol.Errno.EINVAL;
    if (size > 0 and value_c == null) return -fs_protocol.Errno.EINVAL;
    if (flags < 0) return -fs_protocol.Errno.EINVAL;

    const input = if (size == 0) "" else value_c[0..size];
    adapter.setxattr(
        std.mem.span(path_c),
        std.mem.span(name_c),
        input,
        @intCast(flags),
    ) catch |err| return toFuseError(err);
    return 0;
}

fn cGetxattr(path_c: [*c]const u8, name_c: [*c]const u8, value_c: [*c]u8, size: usize) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or name_c == null) return -fs_protocol.Errno.EINVAL;

    const value = adapter.getxattr(std.mem.span(path_c), std.mem.span(name_c)) catch |err| return toFuseError(err);
    defer adapter.allocator.free(value);

    if (size == 0) {
        if (value.len > std.math.maxInt(c_int)) return -fs_protocol.Errno.EIO;
        return @intCast(value.len);
    }
    if (size < value.len) return -fs_protocol.Errno.ERANGE;
    if (value.len > 0 and value_c == null) return -fs_protocol.Errno.EINVAL;
    if (value.len > 0) @memcpy(value_c[0..value.len], value);
    if (value.len > std.math.maxInt(c_int)) return -fs_protocol.Errno.EIO;
    return @intCast(value.len);
}

fn cListxattr(path_c: [*c]const u8, list_c: [*c]u8, size: usize) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;

    const value = adapter.listxattr(std.mem.span(path_c)) catch |err| return toFuseError(err);
    defer adapter.allocator.free(value);

    if (size == 0) {
        if (value.len > std.math.maxInt(c_int)) return -fs_protocol.Errno.EIO;
        return @intCast(value.len);
    }
    if (size < value.len) return -fs_protocol.Errno.ERANGE;
    if (value.len > 0 and list_c == null) return -fs_protocol.Errno.EINVAL;
    if (value.len > 0) @memcpy(list_c[0..value.len], value);
    if (value.len > std.math.maxInt(c_int)) return -fs_protocol.Errno.EIO;
    return @intCast(value.len);
}

fn cRemovexattr(path_c: [*c]const u8, name_c: [*c]const u8) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or name_c == null) return -fs_protocol.Errno.EINVAL;
    adapter.removexattr(std.mem.span(path_c), std.mem.span(name_c)) catch |err| return toFuseError(err);
    return 0;
}

fn cFlock(path_c: [*c]const u8, fi: ?*c.struct_fuse_file_info, op: c_int) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (fi == null) return -fs_protocol.Errno.EINVAL;
    const info = fi.?;
    var open_file: fs_router.OpenFile = undefined;
    var owns_close = false;

    const local_id = c.spiderweb_fi_get_fh(info);
    if (local_id != 0) {
        if (adapter.lookupOpenHandle(local_id)) |existing| {
            open_file = existing;
        } else {
            if (path_c == null) return -fs_protocol.Errno.EBADF;
            const flags = @as(u32, @intCast(c.spiderweb_fi_get_flags(info)));
            open_file = adapter.open(std.mem.span(path_c), flags) catch |err| return toFuseError(err);
            owns_close = true;
        }
    } else {
        if (path_c == null) return -fs_protocol.Errno.EBADF;
        const flags = @as(u32, @intCast(c.spiderweb_fi_get_flags(info)));
        open_file = adapter.open(std.mem.span(path_c), flags) catch |err| return toFuseError(err);
        owns_close = true;
    }
    defer if (owns_close) adapter.release(open_file) catch {};

    const mode: fs_router.LockMode = if ((op & c.LOCK_UN) != 0)
        .unlock
    else if ((op & c.LOCK_EX) != 0)
        .exclusive
    else if ((op & c.LOCK_SH) != 0)
        .shared
    else
        return -fs_protocol.Errno.EINVAL;
    const wait = (op & c.LOCK_NB) == 0;

    adapter.lock(open_file, mode, wait) catch |err| return toFuseError(err);
    return 0;
}

const ParsedAttr = struct {
    id: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime_ns: i64,
    mtime_ns: i64,
    ctime_ns: i64,
};

const ParsedStatfs = struct {
    bsize: u64,
    frsize: u64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    favail: u64,
    namemax: u64,
};

fn parseAndFillStat(allocator: std.mem.Allocator, st: [*c]c.struct_stat, attr_json: []const u8) !void {
    const attr = try parseAttr(allocator, attr_json);
    st.* = std.mem.zeroes(c.struct_stat);

    if (@hasField(c.struct_stat, "st_ino")) st.*.st_ino = @intCast(attr.id);
    if (@hasField(c.struct_stat, "st_mode")) st.*.st_mode = @intCast(attr.mode);
    if (@hasField(c.struct_stat, "st_nlink")) st.*.st_nlink = @intCast(attr.nlink);
    if (@hasField(c.struct_stat, "st_uid")) st.*.st_uid = @intCast(attr.uid);
    if (@hasField(c.struct_stat, "st_gid")) st.*.st_gid = @intCast(attr.gid);
    if (@hasField(c.struct_stat, "st_size")) st.*.st_size = @intCast(attr.size);

    if (@hasField(c.struct_stat, "st_atim")) {
        st.*.st_atim = makeTimespec(@TypeOf(st.*.st_atim), attr.atime_ns);
    } else if (@hasField(c.struct_stat, "st_atimespec")) {
        st.*.st_atimespec = makeTimespec(@TypeOf(st.*.st_atimespec), attr.atime_ns);
    }
    if (@hasField(c.struct_stat, "st_mtim")) {
        st.*.st_mtim = makeTimespec(@TypeOf(st.*.st_mtim), attr.mtime_ns);
    } else if (@hasField(c.struct_stat, "st_mtimespec")) {
        st.*.st_mtimespec = makeTimespec(@TypeOf(st.*.st_mtimespec), attr.mtime_ns);
    }
    if (@hasField(c.struct_stat, "st_ctim")) {
        st.*.st_ctim = makeTimespec(@TypeOf(st.*.st_ctim), attr.ctime_ns);
    } else if (@hasField(c.struct_stat, "st_ctimespec")) {
        st.*.st_ctimespec = makeTimespec(@TypeOf(st.*.st_ctimespec), attr.ctime_ns);
    }
}

fn parseAndFillStatvfs(allocator: std.mem.Allocator, st: [*c]c.struct_statvfs, statfs_json: []const u8) !void {
    const statfs = try parseStatfs(allocator, statfs_json);
    st.* = std.mem.zeroes(c.struct_statvfs);

    if (@hasField(c.struct_statvfs, "f_bsize")) st.*.f_bsize = @intCast(statfs.bsize);
    if (@hasField(c.struct_statvfs, "f_frsize")) st.*.f_frsize = @intCast(statfs.frsize);
    if (@hasField(c.struct_statvfs, "f_blocks")) st.*.f_blocks = @intCast(statfs.blocks);
    if (@hasField(c.struct_statvfs, "f_bfree")) st.*.f_bfree = @intCast(statfs.bfree);
    if (@hasField(c.struct_statvfs, "f_bavail")) st.*.f_bavail = @intCast(statfs.bavail);
    if (@hasField(c.struct_statvfs, "f_files")) st.*.f_files = @intCast(statfs.files);
    if (@hasField(c.struct_statvfs, "f_ffree")) st.*.f_ffree = @intCast(statfs.ffree);
    if (@hasField(c.struct_statvfs, "f_favail")) st.*.f_favail = @intCast(statfs.favail);
    if (@hasField(c.struct_statvfs, "f_namemax")) st.*.f_namemax = @intCast(statfs.namemax);
}

fn makeTimespec(comptime T: type, ns_total: i64) T {
    var result: T = std.mem.zeroes(T);
    const sec = @divFloor(ns_total, 1_000_000_000);
    var nsec = @mod(ns_total, 1_000_000_000);
    if (nsec < 0) nsec += 1_000_000_000;

    result.tv_sec = @intCast(sec);
    result.tv_nsec = @intCast(nsec);
    return result;
}

fn parseAttr(allocator: std.mem.Allocator, json: []const u8) !ParsedAttr {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidAttrJson;

    return .{
        .id = try readRequiredU64(parsed.value.object, "id"),
        .mode = @intCast(try readRequiredU64(parsed.value.object, "m")),
        .nlink = @intCast(try readRequiredU64(parsed.value.object, "n")),
        .uid = @intCast(try readRequiredU64(parsed.value.object, "u")),
        .gid = @intCast(try readRequiredU64(parsed.value.object, "g")),
        .size = try readRequiredU64(parsed.value.object, "sz"),
        .atime_ns = try readRequiredI64(parsed.value.object, "at"),
        .mtime_ns = try readRequiredI64(parsed.value.object, "mt"),
        .ctime_ns = try readRequiredI64(parsed.value.object, "ct"),
    };
}

fn parseStatfs(allocator: std.mem.Allocator, json: []const u8) !ParsedStatfs {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidStatfsJson;

    return .{
        .bsize = try readRequiredU64(parsed.value.object, "bsize"),
        .frsize = try readRequiredU64(parsed.value.object, "frsize"),
        .blocks = try readRequiredU64(parsed.value.object, "blocks"),
        .bfree = try readRequiredU64(parsed.value.object, "bfree"),
        .bavail = try readRequiredU64(parsed.value.object, "bavail"),
        .files = try readRequiredU64(parsed.value.object, "files"),
        .ffree = try readRequiredU64(parsed.value.object, "ffree"),
        .favail = try readRequiredU64(parsed.value.object, "favail"),
        .namemax = try readRequiredU64(parsed.value.object, "namemax"),
    };
}

fn readRequiredU64(obj: std.json.ObjectMap, name: []const u8) !u64 {
    const value = obj.get(name) orelse return error.MissingField;
    if (value != .integer or value.integer < 0) return error.InvalidType;
    return @intCast(value.integer);
}

fn readRequiredI64(obj: std.json.ObjectMap, name: []const u8) !i64 {
    const value = obj.get(name) orelse return error.MissingField;
    if (value != .integer) return error.InvalidType;
    if (value.integer > std.math.maxInt(i64) or value.integer < std.math.minInt(i64)) return error.InvalidType;
    return @intCast(value.integer);
}

fn toFuseError(err: anyerror) c_int {
    return switch (err) {
        error.FileNotFound, error.InvalidPath, error.UnknownEndpoint => -fs_protocol.Errno.ENOENT,
        error.PermissionDenied => -fs_protocol.Errno.EACCES,
        error.NotDirectory => -fs_protocol.Errno.ENOTDIR,
        error.IsDirectory => -fs_protocol.Errno.EISDIR,
        error.AlreadyExists => -fs_protocol.Errno.EEXIST,
        error.NoData => -fs_protocol.Errno.ENODATA,
        error.NoSpace => -fs_protocol.Errno.ENOSPC,
        error.Range => -fs_protocol.Errno.ERANGE,
        error.WouldBlock => -fs_protocol.Errno.EAGAIN,
        error.CrossEndpointRename => -fs_protocol.Errno.EXDEV,
        error.ReadOnlyFilesystem => -fs_protocol.Errno.EROFS,
        error.OperationNotSupported => -fs_protocol.Errno.ENOSYS,
        error.InvalidResponse, error.ProtocolError => -fs_protocol.Errno.EINVAL,
        else => -fs_protocol.Errno.EIO,
    };
}

test "fs_fuse_adapter: parseAttr reads required fields" {
    const allocator = std.testing.allocator;
    const attr = try parseAttr(
        allocator,
        "{\"id\":12,\"m\":33188,\"n\":1,\"u\":1000,\"g\":1000,\"sz\":5,\"at\":100,\"mt\":200,\"ct\":300}",
    );
    try std.testing.expectEqual(@as(u64, 12), attr.id);
    try std.testing.expectEqual(@as(u32, 33188), attr.mode);
    try std.testing.expectEqual(@as(u64, 5), attr.size);
}

test "fs_fuse_adapter: parseStatfs reads required fields" {
    const allocator = std.testing.allocator;
    const statfs = try parseStatfs(
        allocator,
        "{\"bsize\":4096,\"frsize\":4096,\"blocks\":10,\"bfree\":7,\"bavail\":6,\"files\":100,\"ffree\":50,\"favail\":50,\"namemax\":255}",
    );
    try std.testing.expectEqual(@as(u64, 4096), statfs.bsize);
    try std.testing.expectEqual(@as(u64, 10), statfs.blocks);
    try std.testing.expectEqual(@as(u64, 255), statfs.namemax);
}

test "fs_fuse_adapter: toFuseError maps xattr and lock related errors" {
    try std.testing.expectEqual(-fs_protocol.Errno.ENODATA, toFuseError(error.NoData));
    try std.testing.expectEqual(-fs_protocol.Errno.EAGAIN, toFuseError(error.WouldBlock));
    try std.testing.expectEqual(-fs_protocol.Errno.ERANGE, toFuseError(error.Range));
    try std.testing.expectEqual(-fs_protocol.Errno.ENOSYS, toFuseError(error.OperationNotSupported));
}
