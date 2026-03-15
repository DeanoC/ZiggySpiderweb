const builtin = @import("builtin");
const std = @import("std");
const mount_provider = @import("spiderweb_mount_provider");
const mount_session = @import("spiderweb_mount_session");
const fs_protocol = @import("acheron_fs_router").acheron_protocol;

const c = @cImport({
    @cInclude("fuse_compat.h");
});

var active_adapter: ?*FuseAdapter = null;

const FuseStat = if (builtin.os.tag == .windows)
    c.struct_fuse_stat
else if (builtin.os.tag == .macos)
    c.struct_fuse_darwin_attr
else
    c.struct_stat;
const FuseStatvfs = if (builtin.os.tag == .windows)
    c.struct_fuse_statvfs
else if (builtin.os.tag == .macos)
    c.struct_statfs
else
    c.struct_statvfs;

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
    session: mount_session.MountSession,

    pub const MountBackend = enum {
        auto,
        native,
        fuse,
        winfsp,
    };

    pub fn init(allocator: std.mem.Allocator, provider: mount_provider.Provider) FuseAdapter {
        return .{
            .allocator = allocator,
            .session = mount_session.MountSession.init(allocator, provider),
        };
    }

    pub fn deinit(self: *FuseAdapter) void {
        self.session.deinit();
    }

    pub fn getattr(self: *FuseAdapter, path: []const u8) ![]u8 {
        return self.session.getattr(path);
    }

    pub fn readdir(self: *FuseAdapter, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        return self.session.readdir(path, cookie, max_entries);
    }

    pub fn statfs(self: *FuseAdapter, path: []const u8) ![]u8 {
        return self.session.statfs(path);
    }

    pub fn open(self: *FuseAdapter, path: []const u8, flags: u32) !mount_provider.OpenFile {
        return self.session.open(path, flags);
    }

    pub fn openAndStoreHandle(self: *FuseAdapter, path: []const u8, flags: u32) !u64 {
        return self.session.openAndStoreHandle(path, flags);
    }

    pub fn read(self: *FuseAdapter, file: mount_provider.OpenFile, off: u64, len: u32) ![]u8 {
        return self.session.read(file, off, len);
    }

    pub fn release(self: *FuseAdapter, file: mount_provider.OpenFile) !void {
        try self.session.release(file);
    }

    pub fn create(self: *FuseAdapter, path: []const u8, mode: u32, flags: u32) !mount_provider.OpenFile {
        return self.session.create(path, mode, flags);
    }

    pub fn createAndStoreHandle(self: *FuseAdapter, path: []const u8, mode: u32, flags: u32) !u64 {
        return self.session.createAndStoreHandle(path, mode, flags);
    }

    pub fn write(self: *FuseAdapter, file: mount_provider.OpenFile, off: u64, data: []const u8) !u32 {
        return self.session.write(file, off, data);
    }

    pub fn truncate(self: *FuseAdapter, path: []const u8, size: u64) !void {
        try self.session.truncate(path, size);
    }

    pub fn unlink(self: *FuseAdapter, path: []const u8) !void {
        try self.session.unlink(path);
    }

    pub fn mkdir(self: *FuseAdapter, path: []const u8) !void {
        try self.session.mkdir(path);
    }

    pub fn rmdir(self: *FuseAdapter, path: []const u8) !void {
        try self.session.rmdir(path);
    }

    pub fn rename(self: *FuseAdapter, old_path: []const u8, new_path: []const u8) !void {
        try self.session.rename(old_path, new_path);
    }

    pub fn symlink(self: *FuseAdapter, target: []const u8, link_path: []const u8) !void {
        try self.session.symlink(target, link_path);
    }

    pub fn setxattr(self: *FuseAdapter, path: []const u8, name: []const u8, value: []const u8, flags: u32) !void {
        try self.session.setxattr(path, name, value, flags);
    }

    pub fn getxattr(self: *FuseAdapter, path: []const u8, name: []const u8) ![]u8 {
        return self.session.getxattr(path, name);
    }

    pub fn listxattr(self: *FuseAdapter, path: []const u8) ![]u8 {
        return self.session.listxattr(path);
    }

    pub fn removexattr(self: *FuseAdapter, path: []const u8, name: []const u8) !void {
        try self.session.removexattr(path, name);
    }

    pub fn lock(self: *FuseAdapter, file: mount_provider.OpenFile, mode: mount_provider.LockMode, wait: bool) !void {
        try self.session.lock(file, mode, wait);
    }

    pub fn tryReconcileEndpointsIfIdle(
        self: *FuseAdapter,
        endpoint_configs: []const @import("acheron_fs_router").EndpointConfig,
    ) !bool {
        return self.session.tryReconcileEndpointsIfIdle(endpoint_configs);
    }

    pub fn tryKeepAliveIfIdle(self: *FuseAdapter) !bool {
        return self.session.tryKeepAliveIfIdle();
    }

    pub fn mount(self: *FuseAdapter, mountpoint: []const u8) !void {
        return self.mountWithBackend(mountpoint, .auto);
    }

    pub fn mountWithBackend(self: *FuseAdapter, mountpoint: []const u8, backend: MountBackend) !void {
        try validateLocalMountRequest(mountpoint, backend);
        if (active_adapter != null) return error.AlreadyMounted;

        var ops = std.mem.zeroes(c.struct_fuse_operations);
        if (builtin.os.tag == .windows) {
            ops.getattr = cGetattrWin;
            ops.readdir = cReaddirWin;
            ops.statfs = cStatfsWin;
            ops.rename = cRenameWin;
        } else if (builtin.os.tag == .macos) {
            ops.getattr = cGetattrDarwin;
            ops.readdir = cReaddirDarwin;
            ops.statfs = cStatfsDarwin;
            ops.rename = cRename;
        } else {
            ops.getattr = cGetattr;
            ops.readdir = cReaddir;
            ops.statfs = cStatfs;
            ops.rename = cRename;
        }
        ops.open = cOpen;
        if (builtin.os.tag == .windows) {
            ops.read = cReadWin;
            ops.write = cWriteWin;
            ops.truncate = cTruncateWin;
        } else {
            ops.read = cRead;
            ops.write = cWrite;
            ops.truncate = cTruncate;
        }
        ops.release = cRelease;
        if (builtin.os.tag == .windows) {
            ops.create = cCreateWin;
            ops.mkdir = cMkdirWin;
        } else {
            ops.create = cCreate;
            ops.mkdir = cMkdir;
        }
        ops.unlink = cUnlink;
        ops.rmdir = cRmdir;
        ops.symlink = cSymlink;
        // Leave xattr callbacks unset so the kernel/libfuse path fails fast.
        // Advertising no xattr surface is much cheaper than servicing repeated
        // ACL/SELinux probes on virtual Spiderweb namespace entries.
        ops.opendir = cOpendir;
        ops.releasedir = cReleasedir;
        ops.access = cAccess;
        if (builtin.os.tag != .windows) {
            ops.flock = cFlock;
        }

        var argv = std.ArrayListUnmanaged([*:0]u8){};
        defer {
            for (argv.items) |arg| freeArgZ(self.allocator, arg);
            argv.deinit(self.allocator);
        }

        try appendArgZ(self.allocator, &argv, "spiderweb-fs-mount");
        try appendArgZ(self.allocator, &argv, "-f");
        if (std.process.getEnvVarOwned(self.allocator, "SPIDERWEB_FUSE_DEBUG")) |value| {
            defer self.allocator.free(value);
            if (std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true")) {
                try appendArgZ(self.allocator, &argv, "-d");
            }
        } else |_| {}
        const mount_options = try buildMountOptions(self.allocator, mountpoint);
        defer self.allocator.free(mount_options);
        try appendArgZ(self.allocator, &argv, "-o");
        try appendArgZ(self.allocator, &argv, mount_options);
        try appendArgZ(self.allocator, &argv, mountpoint);

        active_adapter = self;
        defer active_adapter = null;

        var lib = try openMountLibrary(backend);
        defer lib.close();

        const argc: c_int = @intCast(argv.items.len);
        const argv_ptr: [*c][*c]u8 = @ptrCast(argv.items.ptr);
        const rc = if (builtin.os.tag == .macos)
            if (lib.lookup(FuseMainRealVersionedFn, "fuse_main_real_versioned")) |fuse_main_real_versioned|
                c.spiderweb_call_fuse_main_real_versioned(
                    @ptrCast(@constCast(fuse_main_real_versioned)),
                    argc,
                    argv_ptr,
                    &ops,
                    @sizeOf(c.struct_fuse_operations),
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
                return error.MissingFuseSymbol
        else if (lib.lookup(FuseMainRealVersionedFn, "fuse_main_real_versioned")) |fuse_main_real_versioned|
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

    fn lookupOpenHandle(self: *FuseAdapter, local_id: u64) ?mount_provider.OpenFile {
        return self.session.lookupOpenHandle(local_id);
    }

    fn releaseStoredHandle(self: *FuseAdapter, local_id: u64) void {
        self.session.releaseStoredHandle(local_id);
    }
};

pub fn mountpointMustExistBeforeMount(backend: FuseAdapter.MountBackend) bool {
    _ = backend;
    return switch (builtin.os.tag) {
        .windows, .macos => false,
        else => true,
    };
}

const minimum_macos_fskit_version = std.SemanticVersion{ .major = 15, .minor = 4, .patch = 0 };

fn isMacosFskitSupportedVersion(version: std.SemanticVersion) bool {
    return version.order(minimum_macos_fskit_version) != .lt;
}

pub fn isCurrentMacosFskitSupported() bool {
    if (builtin.os.tag != .macos) return false;

    // Use the host's runtime version rather than the compile target so local
    // mount support tracks the actual machine we're running on.
    const runtime_target = std.zig.system.resolveTargetQuery(.{}) catch return false;
    return isMacosFskitSupportedVersion(runtime_target.os.version_range.semver.min);
}

pub fn validateLocalMountRequest(mountpoint: []const u8, backend: FuseAdapter.MountBackend) !void {
    return validateMountRequestForOs(builtin.os.tag, mountpoint, backend, isCurrentMacosFskitSupported());
}

pub fn probeLocalMountBackend(backend: FuseAdapter.MountBackend) !void {
    try validateBackendForOs(builtin.os.tag, backend, isCurrentMacosFskitSupported());
    var lib = try openMountLibrary(backend);
    lib.close();
}

fn buildMountOptions(allocator: std.mem.Allocator, mountpoint: []const u8) ![]u8 {
    return buildMountOptionsForOs(allocator, builtin.os.tag, mountpoint);
}

fn buildMountOptionsForOs(allocator: std.mem.Allocator, os_tag: std.Target.Os.Tag, mountpoint: []const u8) ![]u8 {
    return switch (os_tag) {
        .windows => allocator.dupe(u8, "uid=-1,gid=-1,FileInfoTimeout=-1"),
        .macos => blk: {
            const volume_name = try macosVolumeNameFromMountpoint(allocator, mountpoint);
            defer allocator.free(volume_name);
            break :blk try std.fmt.allocPrint(
                allocator,
                "backend=fskit,volname={s},fsname=spiderweb#{s}",
                .{ volume_name, volume_name },
            );
        },
        else => allocator.dupe(u8, "default_permissions,attr_timeout=1,entry_timeout=1,negative_timeout=0"),
    };
}

fn macosVolumeNameFromMountpoint(allocator: std.mem.Allocator, mountpoint: []const u8) ![]u8 {
    const trimmed = std.mem.trimRight(u8, mountpoint, "/");
    const base = std.fs.path.basename(trimmed);
    const fallback = if (base.len == 0 or std.mem.eql(u8, base, "Volumes")) "spiderweb" else base;

    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    for (fallback) |ch| {
        const normalized = if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.') ch else '-';
        try out.append(allocator, normalized);
    }
    if (out.items.len == 0) try out.appendSlice(allocator, "spiderweb");
    return out.toOwnedSlice(allocator);
}

fn validateMountRequestForOs(
    os_tag: std.Target.Os.Tag,
    mountpoint: []const u8,
    backend: FuseAdapter.MountBackend,
    macos_supported: bool,
) !void {
    if (mountpoint.len == 0) return error.InvalidMountpoint;
    try validateBackendForOs(os_tag, backend, macos_supported);

    if (os_tag == .macos) {
        try validateMacosMountpoint(mountpoint);
    }
}

fn validateMacosMountpoint(mountpoint: []const u8) !void {
    const trimmed = std.mem.trimRight(u8, mountpoint, "/");
    if (!std.fs.path.isAbsolute(trimmed)) return error.InvalidMacosMountpoint;

    const normalized = try std.fs.path.resolvePosix(std.heap.page_allocator, &.{trimmed});
    defer std.heap.page_allocator.free(normalized);

    if (!std.mem.startsWith(u8, normalized, "/Volumes/")) return error.InvalidMacosMountpoint;

    const volume_name = normalized["/Volumes/".len..];
    if (volume_name.len == 0) return error.InvalidMacosMountpoint;
    if (std.mem.indexOfScalar(u8, volume_name, '/') != null) return error.InvalidMacosMountpoint;
}

fn validateBackendForOs(
    os_tag: std.Target.Os.Tag,
    backend: FuseAdapter.MountBackend,
    macos_supported: bool,
) !void {
    switch (os_tag) {
        .macos => switch (backend) {
            .auto, .fuse => {
                if (!macos_supported) return error.UnsupportedMacosVersion;
            },
            .native, .winfsp => return error.UnsupportedMountBackend,
        },
        .linux => switch (backend) {
            .auto, .fuse => {},
            .native, .winfsp => return error.UnsupportedOs,
        },
        .windows => switch (backend) {
            .native => return error.UnsupportedMountBackend,
            else => {},
        },
        else => return error.UnsupportedOs,
    }
}

fn openMountLibrary(backend: FuseAdapter.MountBackend) !std.DynLib {
    const candidates = try mountLibraryCandidatesForOs(builtin.os.tag, backend);
    for (candidates) |candidate| {
        if (std.DynLib.open(candidate)) |lib| return lib else |_| {}
    }
    if (builtin.os.tag == .macos) return error.MacFuseNotInstalled;
    return error.MountLibraryNotFound;
}

fn mountLibraryCandidatesForOs(os_tag: std.Target.Os.Tag, backend: FuseAdapter.MountBackend) ![]const []const u8 {
    return switch (os_tag) {
        .linux => switch (backend) {
            .auto, .fuse => &[_][]const u8{
                "libfuse3.so.4",
                "/lib/x86_64-linux-gnu/libfuse3.so.4",
                "/usr/lib/x86_64-linux-gnu/libfuse3.so.4",
                "libfuse3.so.3",
                "/lib/x86_64-linux-gnu/libfuse3.so.3",
                "/usr/lib/x86_64-linux-gnu/libfuse3.so.3",
                "libfuse3.so",
            },
            .native => error.UnsupportedMountBackend,
            .winfsp => error.UnsupportedOs,
        },
        .macos => switch (backend) {
            .auto, .fuse => &[_][]const u8{
                "/usr/local/lib/libfuse3.dylib",
                "/usr/local/lib/libfuse3.4.dylib",
                "/usr/local/lib/libfuse3.3.dylib",
                "/usr/local/lib/libfuse3.2.dylib",
                "/usr/local/lib/libfuse3.0.dylib",
                "/opt/homebrew/lib/libfuse3.dylib",
                "/opt/homebrew/lib/libfuse3.4.dylib",
                "/opt/homebrew/lib/libfuse3.3.dylib",
                "/Library/Frameworks/macfuse.framework/Versions/Current/lib/libfuse3.dylib",
                "/Library/Frameworks/macfuse.framework/Versions/Current/lib/libfuse3.4.dylib",
                "/Library/Filesystems/macfuse.fs/Contents/Resources/lib/libfuse3.dylib",
                "libfuse3.dylib",
            },
            .native, .winfsp => error.UnsupportedMountBackend,
        },
        .windows => switch (backend) {
            .auto, .fuse, .winfsp => &[_][]const u8{
                "winfsp-x64.dll",
                "winfsp-x86.dll",
                "winfsp.dll",
                "C:\\Program Files\\WinFsp\\bin\\winfsp-x64.dll",
                "C:\\Program Files\\WinFsp\\bin\\winfsp-x86.dll",
                "C:\\Program Files\\WinFsp\\bin\\winfsp.dll",
                "C:\\Program Files (x86)\\WinFsp\\bin\\winfsp-x64.dll",
                "C:\\Program Files (x86)\\WinFsp\\bin\\winfsp-x86.dll",
                "C:\\Program Files (x86)\\WinFsp\\bin\\winfsp.dll",
            },
            .native => error.UnsupportedMountBackend,
        },
        else => error.UnsupportedOs,
    };
}

fn appendArgZ(allocator: std.mem.Allocator, argv: *std.ArrayListUnmanaged([*:0]u8), arg: []const u8) !void {
    const owned = try allocator.dupeZ(u8, arg);
    try argv.append(allocator, @ptrCast(owned.ptr));
}

fn freeArgZ(allocator: std.mem.Allocator, arg: [*:0]u8) void {
    const len = std.mem.len(arg);
    allocator.free(arg[0 .. len + 1]);
}

fn cGetattrWin(path_c: [*c]const u8, st_c: [*c]c.struct_fuse_stat) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or st_c == null) return -fs_protocol.Errno.EINVAL;

    const path = std.mem.span(path_c);
    fuseTrace("getattr path={s}", .{path});
    const attr_json = adapter.getattr(path) catch |err| {
        fuseTrace("getattr error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    defer adapter.allocator.free(attr_json);

    parseAndFillStat(adapter.allocator, st_c, attr_json) catch |err| {
        fuseTrace("getattr parse error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    return 0;
}

fn cGetattr(path_c: [*c]const u8, st_c: [*c]c.struct_stat, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    _ = fi;
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or st_c == null) return -fs_protocol.Errno.EINVAL;

    const path = std.mem.span(path_c);
    fuseTrace("getattr path={s}", .{path});
    const attr_json = adapter.getattr(path) catch |err| {
        fuseTrace("getattr error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    defer adapter.allocator.free(attr_json);

    parseAndFillStat(adapter.allocator, st_c, attr_json) catch |err| {
        fuseTrace("getattr parse error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    return 0;
}

fn cGetattrDarwin(path_c: [*c]const u8, st_c: [*c]c.struct_fuse_darwin_attr, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    _ = fi;
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or st_c == null) return -fs_protocol.Errno.EINVAL;

    const path = std.mem.span(path_c);
    fuseTrace("getattr(darwin) path={s}", .{path});
    const attr_json = adapter.getattr(path) catch |err| {
        fuseTrace("getattr(darwin) error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    defer adapter.allocator.free(attr_json);

    parseAndFillStat(adapter.allocator, st_c, attr_json) catch |err| {
        fuseTrace("getattr(darwin) parse error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    return 0;
}

fn cReaddirWin(
    path_c: [*c]const u8,
    buf: ?*anyopaque,
    filler: c.fuse_fill_dir_t,
    off: c.fuse_off_t,
    fi: ?*c.struct_fuse_file_info,
) callconv(.c) c_int {
    _ = fi;

    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    fuseTrace("readdir path={s} off={d}", .{ path, off });

    const cookie: u64 = if (off <= 0)
        0
    else
        @intCast(off);
    const listing = adapter.readdir(path, cookie, 16384) catch |err| {
        fuseTrace("readdir provider error={s} path={s} cookie={d}", .{ @errorName(err), path, cookie });
        return toFuseError(err);
    };
    defer adapter.allocator.free(listing);
    var parsed = std.json.parseFromSlice(std.json.Value, adapter.allocator, listing, .{}) catch |err| {
        fuseTrace("readdir parse error={s}", .{@errorName(err)});
        return -fs_protocol.Errno.EIO;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        fuseTrace("readdir payload was not object", .{});
        return -fs_protocol.Errno.EIO;
    }
    const ents = parsed.value.object.get("ents") orelse {
        fuseTrace("readdir payload missing ents", .{});
        return -fs_protocol.Errno.EIO;
    };
    if (ents != .array) {
        fuseTrace("readdir ents was not array", .{});
        return -fs_protocol.Errno.EIO;
    }
    fuseTrace("readdir entries={d}", .{ents.array.items.len});

    if (filler == null) return -fs_protocol.Errno.EINVAL;
    var idx: u64 = 0;
    for (ents.array.items) |entry| {
        if (entry != .object) continue;
        const name_val = entry.object.get("name") orelse continue;
        if (name_val != .string) continue;
        const name_z = adapter.allocator.dupeZ(u8, name_val.string) catch return -fs_protocol.Errno.EIO;
        defer adapter.allocator.free(name_z);

        const next_cookie = std.math.add(u64, cookie, idx + 1) catch std.math.maxInt(u64);
        const next_off: c.fuse_off_t = std.math.cast(c.fuse_off_t, next_cookie) orelse 0;
        var stat_buf: c.struct_fuse_stat = std.mem.zeroes(c.struct_fuse_stat);
        var stat_ptr: [*c]const c.struct_fuse_stat = null;
        if (entry.object.get("attr")) |attr_val| {
            if (attr_val == .object) {
                if (parseAttrFromObject(attr_val.object)) |attr| {
                    fillStatFromParsedAttr(&stat_buf, attr);
                    stat_ptr = @ptrCast(&stat_buf);
                } else |_| {}
            }
        }
        if (filler.?(buf, @ptrCast(name_z.ptr), stat_ptr, next_off) != 0) break;
        idx += 1;
    }
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
    fuseTrace("readdir path={s} off={d}", .{ path, off });

    const cookie: u64 = if (builtin.os.tag == .macos)
        0
    else if (off <= 0)
        0
    else
        @intCast(off);
    const listing = adapter.readdir(path, cookie, 16384) catch |err| {
        fuseTrace("readdir provider error={s} path={s} cookie={d}", .{ @errorName(err), path, cookie });
        return toFuseError(err);
    };
    defer adapter.allocator.free(listing);
    fuseTrace("readdir payload={s}", .{listing});
    var parsed = std.json.parseFromSlice(std.json.Value, adapter.allocator, listing, .{}) catch |err| {
        fuseTrace("readdir parse error={s}", .{@errorName(err)});
        return -fs_protocol.Errno.EIO;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        fuseTrace("readdir payload was not object", .{});
        return -fs_protocol.Errno.EIO;
    }
    const ents = parsed.value.object.get("ents") orelse {
        fuseTrace("readdir payload missing ents", .{});
        return -fs_protocol.Errno.EIO;
    };
    if (ents != .array) {
        fuseTrace("readdir ents was not array", .{});
        return -fs_protocol.Errno.EIO;
    }
    fuseTrace("readdir entries={d}", .{ents.array.items.len});

    if (filler == null) return -fs_protocol.Errno.EINVAL;
    var idx: u64 = 0;
    for (ents.array.items) |entry| {
        if (entry != .object) continue;
        const name_val = entry.object.get("name") orelse continue;
        if (name_val != .string) continue;
        const name_z = adapter.allocator.dupeZ(u8, name_val.string) catch return -fs_protocol.Errno.EIO;
        defer adapter.allocator.free(name_z);

        const next_cookie = std.math.add(u64, cookie, idx + 1) catch std.math.maxInt(u64);
        const next_off: c.off_t = std.math.cast(c.off_t, next_cookie) orelse 0;
        var stat_buf: c.struct_stat = std.mem.zeroes(c.struct_stat);
        var stat_ptr: [*c]const c.struct_stat = null;
        if (entry.object.get("attr")) |attr_val| {
            if (attr_val == .object) {
                if (parseAttrFromObject(attr_val.object)) |attr| {
                    fillStatFromParsedAttr(&stat_buf, attr);
                    stat_ptr = @ptrCast(&stat_buf);
                } else |_| {}
            }
        }
        const filler_rc = filler.?(buf, @ptrCast(name_z.ptr), stat_ptr, next_off, c.FUSE_FILL_DIR_DEFAULTS);
        fuseTrace("readdir entry name={s} rc={d}", .{ name_val.string, filler_rc });
        if (filler_rc != 0) break;
        idx += 1;
    }
    return 0;
}

fn cReaddirDarwin(
    path_c: [*c]const u8,
    buf: ?*anyopaque,
    filler: c.fuse_darwin_fill_dir_t,
    off: c.off_t,
    fi: ?*c.struct_fuse_file_info,
    flags: c.enum_fuse_readdir_flags,
) callconv(.c) c_int {
    _ = fi;
    _ = flags;

    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    fuseTrace("readdir(darwin) path={s} off={d}", .{ path, off });

    // macFUSE/FSKit may start readdir with non-zero offsets for synthetic "."
    // and ".." entries. Spiderweb's namespace cookies are not POSIX dirent
    // positions, so Darwin uses a simple non-seekable listing path for now.
    const cookie: u64 = 0;
    const listing = adapter.readdir(path, cookie, 16384) catch |err| {
        fuseTrace("readdir(darwin) provider error={s} path={s} cookie={d}", .{ @errorName(err), path, cookie });
        return toFuseError(err);
    };
    defer adapter.allocator.free(listing);
    var parsed = std.json.parseFromSlice(std.json.Value, adapter.allocator, listing, .{}) catch |err| {
        fuseTrace("readdir(darwin) parse error={s}", .{@errorName(err)});
        return -fs_protocol.Errno.EIO;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        fuseTrace("readdir(darwin) payload was not object", .{});
        return -fs_protocol.Errno.EIO;
    }
    const ents = parsed.value.object.get("ents") orelse {
        fuseTrace("readdir(darwin) payload missing ents", .{});
        return -fs_protocol.Errno.EIO;
    };
    if (ents != .array) {
        fuseTrace("readdir(darwin) ents was not array", .{});
        return -fs_protocol.Errno.EIO;
    }

    if (filler == null) return -fs_protocol.Errno.EINVAL;

    const dot_entries = [_][]const u8{ ".", ".." };
    for (dot_entries) |name| {
        const filler_rc = filler.?(buf, @ptrCast(name.ptr), null, 0, c.FUSE_FILL_DIR_DEFAULTS);
        fuseTrace("readdir(darwin) special name={s} rc={d}", .{ name, filler_rc });
        if (filler_rc != 0) return 0;
    }

    var names = std.ArrayListUnmanaged([*:0]u8){};
    defer {
        for (names.items) |name_z| freeArgZ(adapter.allocator, name_z);
        names.deinit(adapter.allocator);
    }
    var stats = std.ArrayListUnmanaged(c.struct_fuse_darwin_attr){};
    defer stats.deinit(adapter.allocator);
    names.ensureTotalCapacity(adapter.allocator, ents.array.items.len) catch return -fs_protocol.Errno.EIO;
    stats.ensureTotalCapacity(adapter.allocator, ents.array.items.len) catch return -fs_protocol.Errno.EIO;

    for (ents.array.items) |entry| {
        if (entry != .object) continue;
        const name_val = entry.object.get("name") orelse continue;
        if (name_val != .string) continue;
        const name_z = adapter.allocator.dupeZ(u8, name_val.string) catch return -fs_protocol.Errno.EIO;
        names.appendAssumeCapacity(@ptrCast(name_z.ptr));
        const name_ptr = names.items[names.items.len - 1];

        const next_off: c.off_t = 0;
        var stat_ptr: [*c]const c.struct_fuse_darwin_attr = null;
        if (entry.object.get("attr")) |attr_val| {
            if (attr_val == .object) {
                if (parseAttrFromObject(attr_val.object)) |attr| {
                    stats.appendAssumeCapacity(std.mem.zeroes(c.struct_fuse_darwin_attr));
                    fillStatFromParsedAttr(&stats.items[stats.items.len - 1], attr);
                    stat_ptr = @ptrCast(&stats.items[stats.items.len - 1]);
                } else |_| {}
            }
        }
        const filler_rc = filler.?(buf, name_ptr, stat_ptr, next_off, c.FUSE_FILL_DIR_DEFAULTS);
        fuseTrace("readdir(darwin) entry name={s} rc={d}", .{ name_val.string, filler_rc });
        if (filler_rc != 0) break;
    }
    return 0;
}

fn cOpendir(path_c: [*c]const u8, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;

    const path = std.mem.span(path_c);
    fuseTrace("opendir path={s}", .{path});
    const attr_json = adapter.getattr(path) catch |err| return toFuseError(err);
    defer adapter.allocator.free(attr_json);

    const attr = parseAttr(adapter.allocator, attr_json) catch |err| return toFuseError(err);
    if (!attrIsDirectory(attr)) return -fs_protocol.Errno.ENOTDIR;
    if (builtin.os.tag == .macos and fi != null) {
        c.spiderweb_fi_set_nonseekable(fi.?, 1);
        c.spiderweb_fi_set_cache_readdir(fi.?, 0);
    }
    return 0;
}

fn cReleasedir(path_c: [*c]const u8, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    _ = path_c;
    _ = fi;
    return 0;
}

fn cAccess(path_c: [*c]const u8, mask: c_int) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;

    const path = std.mem.span(path_c);
    fuseTrace("access path={s} mask={d}", .{ path, mask });
    const attr_json = adapter.getattr(path) catch |err| return toFuseError(err);
    defer adapter.allocator.free(attr_json);
    return 0;
}

fn cStatfsWin(path_c: [*c]const u8, stbuf: [*c]c.struct_fuse_statvfs) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or stbuf == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    const statfs_json = adapter.statfs(path) catch |err| return toFuseError(err);
    defer adapter.allocator.free(statfs_json);
    parseAndFillStatvfs(adapter.allocator, stbuf, statfs_json) catch |err| return toFuseError(err);
    return 0;
}

fn cStatfs(path_c: [*c]const u8, stbuf: [*c]c.struct_statvfs) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or stbuf == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    fuseTrace("statfs path={s}", .{path});
    const statfs_json = adapter.statfs(path) catch |err| {
        fuseTrace("statfs error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    defer adapter.allocator.free(statfs_json);
    parseAndFillStatvfs(adapter.allocator, stbuf, statfs_json) catch |err| {
        fuseTrace("statfs parse error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    return 0;
}

fn cStatfsDarwin(path_c: [*c]const u8, stbuf: [*c]c.struct_statfs) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null or stbuf == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    fuseTrace("statfs(darwin) path={s}", .{path});
    const statfs_json = adapter.statfs(path) catch |err| {
        fuseTrace("statfs(darwin) error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    defer adapter.allocator.free(statfs_json);
    parseAndFillStatvfs(adapter.allocator, stbuf, statfs_json) catch |err| {
        fuseTrace("statfs(darwin) parse error path={s} err={s}", .{ path, @errorName(err) });
        return toFuseError(err);
    };
    return 0;
}

fn cOpen(path_c: [*c]const u8, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    const flags = if (fi) |info| @as(u32, @intCast(c.spiderweb_fi_get_flags(info))) else @as(u32, 0);
    fuseTrace("open path={s} flags={d}", .{ path, flags });
    if (fi) |info| {
        const local_id = adapter.openAndStoreHandle(path, flags) catch |err| return toFuseError(err);
        c.spiderweb_fi_set_fh(info, local_id);
    } else {
        const opened = adapter.open(path, flags) catch |err| return toFuseError(err);
        adapter.release(opened) catch {};
    }
    return 0;
}

fn cRead(path_c: [*c]const u8, buf: [*c]u8, size: usize, off: c.off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    if (off < 0) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    fuseTrace("read path={s} size={d} off={d}", .{ path, size, off });

    var open_file: mount_provider.OpenFile = undefined;
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

fn cReadWin(path_c: [*c]const u8, buf: [*c]u8, size: usize, off: c.fuse_off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    if (off < 0) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);

    var open_file: mount_provider.OpenFile = undefined;
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

    var open_file: mount_provider.OpenFile = undefined;
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
    if (written > size) {
        std.log.err(
            "fuse write reply exceeded request: path={s} requested={d} returned={d}",
            .{ path, size, written },
        );
        return -fs_protocol.Errno.EIO;
    }
    return @intCast(written);
}

fn cWriteWin(path_c: [*c]const u8, buf: [*c]const u8, size: usize, off: c.fuse_off_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    if (off < 0) return -fs_protocol.Errno.EINVAL;
    if (size > 0 and buf == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);

    var open_file: mount_provider.OpenFile = undefined;
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
    const path = if (path_c) |value| std.mem.span(value) else "";
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    fuseTrace("release path={s}", .{path});
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
    if (fi) |info| {
        const local_id = adapter.createAndStoreHandle(path, @intCast(mode), flags) catch |err| return toFuseError(err);
        c.spiderweb_fi_set_fh(info, local_id);
    } else {
        const opened = adapter.create(path, @intCast(mode), flags) catch |err| return toFuseError(err);
        adapter.release(opened) catch {};
    }
    return 0;
}

fn cCreateWin(path_c: [*c]const u8, mode: c.fuse_mode_t, fi: ?*c.struct_fuse_file_info) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (path_c == null) return -fs_protocol.Errno.EINVAL;
    const path = std.mem.span(path_c);
    const flags = if (fi) |info| @as(u32, @intCast(c.spiderweb_fi_get_flags(info))) else @as(u32, 2);
    if (fi) |info| {
        const local_id = adapter.createAndStoreHandle(path, @intCast(mode), flags) catch |err| return toFuseError(err);
        c.spiderweb_fi_set_fh(info, local_id);
    } else {
        const opened = adapter.create(path, @intCast(mode), flags) catch |err| return toFuseError(err);
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

fn cTruncateWin(path_c: [*c]const u8, size: c.fuse_off_t) callconv(.c) c_int {
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

fn cMkdirWin(path_c: [*c]const u8, mode: c.fuse_mode_t) callconv(.c) c_int {
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

fn cRenameWin(from_c: [*c]const u8, to_c: [*c]const u8) callconv(.c) c_int {
    const adapter = active_adapter orelse return -fs_protocol.Errno.EIO;
    if (from_c == null or to_c == null) return -fs_protocol.Errno.EINVAL;
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
    var open_file: mount_provider.OpenFile = undefined;
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

    const mode: mount_provider.LockMode = if ((op & c.LOCK_UN) != 0)
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
    kind_code: u8,
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

fn parseAndFillStat(allocator: std.mem.Allocator, st: anytype, attr_json: []const u8) !void {
    const attr = try parseAttr(allocator, attr_json);
    fillStatFromParsedAttr(st, attr);
}

fn parseAndFillStatvfs(allocator: std.mem.Allocator, st: anytype, statfs_json: []const u8) !void {
    const statfs = try parseStatfs(allocator, statfs_json);
    const Statvfs = @TypeOf(st.*);
    st.* = std.mem.zeroes(Statvfs);

    if (@hasField(Statvfs, "f_bsize")) st.*.f_bsize = safeStatCast(@TypeOf(st.*.f_bsize), statfs.bsize);
    if (@hasField(Statvfs, "f_frsize")) st.*.f_frsize = safeStatCast(@TypeOf(st.*.f_frsize), statfs.frsize);
    if (@hasField(Statvfs, "f_iosize")) st.*.f_iosize = safeStatCast(@TypeOf(st.*.f_iosize), statfs.frsize);
    if (@hasField(Statvfs, "f_blocks")) st.*.f_blocks = safeStatCast(@TypeOf(st.*.f_blocks), statfs.blocks);
    if (@hasField(Statvfs, "f_bfree")) st.*.f_bfree = safeStatCast(@TypeOf(st.*.f_bfree), statfs.bfree);
    if (@hasField(Statvfs, "f_bavail")) st.*.f_bavail = safeStatCast(@TypeOf(st.*.f_bavail), statfs.bavail);
    if (@hasField(Statvfs, "f_files")) st.*.f_files = safeStatCast(@TypeOf(st.*.f_files), statfs.files);
    if (@hasField(Statvfs, "f_ffree")) st.*.f_ffree = safeStatCast(@TypeOf(st.*.f_ffree), statfs.ffree);
    if (@hasField(Statvfs, "f_favail")) st.*.f_favail = safeStatCast(@TypeOf(st.*.f_favail), statfs.favail);
    if (@hasField(Statvfs, "f_namemax")) st.*.f_namemax = safeStatCast(@TypeOf(st.*.f_namemax), statfs.namemax);
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

    return parseAttrFromObject(parsed.value.object);
}

fn parseAttrFromObject(obj: std.json.ObjectMap) !ParsedAttr {
    const raw_mode: u32 = @intCast(try readRequiredU64(obj, "m"));
    const kind_code = parseOptionalKindCode(obj);
    return .{
        .id = try readRequiredU64(obj, "id"),
        .kind_code = kind_code,
        // Some remote nodes (notably Windows builds) may report mode=0 for root attrs.
        // FUSE rejects zero mode with EIO, so synthesize a sane default from kind.
        .mode = normalizeAttrMode(raw_mode, kind_code),
        .nlink = @intCast(try readRequiredU64(obj, "n")),
        .uid = @intCast(try readRequiredU64(obj, "u")),
        .gid = @intCast(try readRequiredU64(obj, "g")),
        .size = try readRequiredU64(obj, "sz"),
        .atime_ns = try readRequiredI64(obj, "at"),
        .mtime_ns = try readRequiredI64(obj, "mt"),
        .ctime_ns = try readRequiredI64(obj, "ct"),
    };
}

fn parseOptionalKindCode(obj: std.json.ObjectMap) u8 {
    const value = obj.get("k") orelse return 0;
    if (value != .integer or value.integer < 0) return 0;
    return @intCast(value.integer);
}

fn normalizeAttrMode(mode: u32, kind_code: u8) u32 {
    if (mode != 0) return mode;
    return switch (kind_code) {
        2 => 0o040755,
        1 => 0o100644,
        else => 0o100644,
    };
}

fn attrIsDirectory(attr: ParsedAttr) bool {
    if (attr.kind_code == 2) return true;
    return (normalizeAttrMode(attr.mode, attr.kind_code) & 0o170000) == 0o040000;
}

fn fillStatFromParsedAttr(st: anytype, attr: ParsedAttr) void {
    const Stat = @TypeOf(st.*);
    st.* = std.mem.zeroes(Stat);
    const effective = effectiveStatAttr(attr);

    if (@hasField(Stat, "st_ino")) st.*.st_ino = safeStatCast(@TypeOf(st.*.st_ino), effective.id);
    if (@hasField(Stat, "ino")) st.*.ino = safeStatCast(@TypeOf(st.*.ino), effective.id);
    if (@hasField(Stat, "st_mode")) st.*.st_mode = safeStatCast(@TypeOf(st.*.st_mode), effective.mode);
    if (@hasField(Stat, "mode")) st.*.mode = safeStatCast(@TypeOf(st.*.mode), effective.mode);
    if (@hasField(Stat, "st_nlink")) st.*.st_nlink = safeStatCast(@TypeOf(st.*.st_nlink), effective.nlink);
    if (@hasField(Stat, "nlink")) st.*.nlink = safeStatCast(@TypeOf(st.*.nlink), effective.nlink);
    if (@hasField(Stat, "st_uid")) st.*.st_uid = safeStatCast(@TypeOf(st.*.st_uid), effective.uid);
    if (@hasField(Stat, "uid")) st.*.uid = safeStatCast(@TypeOf(st.*.uid), effective.uid);
    if (@hasField(Stat, "st_gid")) st.*.st_gid = safeStatCast(@TypeOf(st.*.st_gid), effective.gid);
    if (@hasField(Stat, "gid")) st.*.gid = safeStatCast(@TypeOf(st.*.gid), effective.gid);
    if (@hasField(Stat, "st_size")) st.*.st_size = safeStatCast(@TypeOf(st.*.st_size), effective.size);
    if (@hasField(Stat, "size")) st.*.size = safeStatCast(@TypeOf(st.*.size), effective.size);

    if (@hasField(Stat, "st_atim")) {
        st.*.st_atim = makeTimespec(@TypeOf(st.*.st_atim), attr.atime_ns);
    } else if (@hasField(Stat, "st_atimespec")) {
        st.*.st_atimespec = makeTimespec(@TypeOf(st.*.st_atimespec), attr.atime_ns);
    } else if (@hasField(Stat, "atimespec")) {
        st.*.atimespec = makeTimespec(@TypeOf(st.*.atimespec), attr.atime_ns);
    }
    if (@hasField(Stat, "st_mtim")) {
        st.*.st_mtim = makeTimespec(@TypeOf(st.*.st_mtim), attr.mtime_ns);
    } else if (@hasField(Stat, "st_mtimespec")) {
        st.*.st_mtimespec = makeTimespec(@TypeOf(st.*.st_mtimespec), attr.mtime_ns);
    } else if (@hasField(Stat, "mtimespec")) {
        st.*.mtimespec = makeTimespec(@TypeOf(st.*.mtimespec), attr.mtime_ns);
    }
    if (@hasField(Stat, "st_ctim")) {
        st.*.st_ctim = makeTimespec(@TypeOf(st.*.st_ctim), attr.ctime_ns);
    } else if (@hasField(Stat, "st_ctimespec")) {
        st.*.st_ctimespec = makeTimespec(@TypeOf(st.*.st_ctimespec), attr.ctime_ns);
    } else if (@hasField(Stat, "ctimespec")) {
        st.*.ctimespec = makeTimespec(@TypeOf(st.*.ctimespec), attr.ctime_ns);
    }
    if (@hasField(Stat, "btimespec")) {
        st.*.btimespec = makeTimespec(@TypeOf(st.*.btimespec), attr.ctime_ns);
    }
    if (@hasField(Stat, "blksize")) {
        st.*.blksize = safeStatCast(@TypeOf(st.*.blksize), 4096);
    }
    if (@hasField(Stat, "blocks")) {
        const blocks = if (effective.size == 0) 0 else (effective.size + 511) / 512;
        st.*.blocks = safeStatCast(@TypeOf(st.*.blocks), blocks);
    }
}

const EffectiveStatAttr = struct {
    id: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
};

fn effectiveStatAttr(attr: ParsedAttr) EffectiveStatAttr {
    if (@import("builtin").os.tag != .windows) {
        return .{
            .id = attr.id,
            .mode = attr.mode,
            .nlink = attr.nlink,
            .uid = attr.uid,
            .gid = attr.gid,
            .size = attr.size,
        };
    }

    const mode = switch (attr.kind_code) {
        2 => @as(u32, 0o040777),
        else => @as(u32, 0o100666),
    };
    return .{
        .id = attr.id,
        .mode = mode,
        .nlink = attr.nlink,
        .uid = std.math.maxInt(u32),
        .gid = std.math.maxInt(u32) - 1,
        .size = attr.size,
    };
}

fn safeStatCast(comptime T: type, value: u64) T {
    return switch (@typeInfo(T)) {
        .int => |int_info| blk: {
            if (int_info.signedness == .signed) {
                const max_value: u64 = @intCast(std.math.maxInt(T));
                break :blk @intCast(@min(value, max_value));
            }
            break :blk std.math.cast(T, value) orelse std.math.maxInt(T);
        },
        else => @compileError("safeStatCast requires an integer destination type"),
    };
}

fn fuseTraceEnabled() bool {
    const Cache = struct {
        var cached: enum { unknown, disabled, enabled } = .unknown;
    };
    if (Cache.cached != .unknown) return Cache.cached == .enabled;

    const value = std.process.getEnvVarOwned(std.heap.page_allocator, "SPIDERWEB_FUSE_TRACE") catch {
        Cache.cached = .disabled;
        return false;
    };
    defer std.heap.page_allocator.free(value);

    const enabled = std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true");
    Cache.cached = if (enabled) .enabled else .disabled;
    return enabled;
}

fn fuseTrace(comptime fmt: []const u8, args: anytype) void {
    if (!fuseTraceEnabled()) return;
    std.debug.print("[spiderweb-fuse] " ++ fmt ++ "\n", args);
}

test "fs_fuse_adapter: safeStatCast clamps oversized values" {
    try std.testing.expectEqual(@as(u8, 255), safeStatCast(u8, 1024));
    try std.testing.expectEqual(@as(i16, 32767), safeStatCast(i16, 100_000));
    try std.testing.expectEqual(@as(u32, 42), safeStatCast(u32, 42));
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
        error.InvalidPayload, error.InvalidResponse, error.ProtocolError => -fs_protocol.Errno.EINVAL,
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

test "fs_fuse_adapter: parseAttr synthesizes mode when remote reports zero" {
    const allocator = std.testing.allocator;

    const dir_attr = try parseAttr(
        allocator,
        "{\"id\":7,\"k\":2,\"m\":0,\"n\":2,\"u\":0,\"g\":0,\"sz\":0,\"at\":0,\"mt\":0,\"ct\":0}",
    );
    try std.testing.expectEqual(@as(u32, 0o040755), dir_attr.mode);

    const file_attr = try parseAttr(
        allocator,
        "{\"id\":8,\"k\":1,\"m\":0,\"n\":1,\"u\":0,\"g\":0,\"sz\":3,\"at\":0,\"mt\":0,\"ct\":0}",
    );
    try std.testing.expectEqual(@as(u32, 0o100644), file_attr.mode);
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
    try std.testing.expectEqual(-fs_protocol.Errno.EINVAL, toFuseError(error.InvalidPayload));
    try std.testing.expectEqual(-fs_protocol.Errno.ENOSYS, toFuseError(error.OperationNotSupported));
}

test "fs_fuse_adapter: darwin validates supported mountpoints" {
    try validateMountRequestForOs(.macos, "/Volumes/spiderweb-demo", .auto, true);
    try validateMountRequestForOs(.macos, "/Volumes/spiderweb-demo/", .auto, true);
    try std.testing.expectError(
        error.InvalidMacosMountpoint,
        validateMountRequestForOs(.macos, "/tmp/spiderweb-demo", .auto, true),
    );
    try std.testing.expectError(
        error.InvalidMacosMountpoint,
        validateMountRequestForOs(.macos, "/Volumes", .auto, true),
    );
    try std.testing.expectError(
        error.InvalidMacosMountpoint,
        validateMountRequestForOs(.macos, "/Volumes/../tmp/spiderweb-demo", .auto, true),
    );
    try std.testing.expectError(
        error.InvalidMacosMountpoint,
        validateMountRequestForOs(.macos, "/Volumes/spiderweb-demo/nested", .auto, true),
    );
}

test "fs_fuse_adapter: darwin rejects unsupported backend and version" {
    try std.testing.expectError(
        error.UnsupportedMountBackend,
        validateMountRequestForOs(.macos, "/Volumes/spiderweb-demo", .winfsp, true),
    );
    try std.testing.expectError(
        error.UnsupportedMacosVersion,
        validateMountRequestForOs(.macos, "/Volumes/spiderweb-demo", .auto, false),
    );
}

test "fs_fuse_adapter: darwin fskit support is gated by runtime version" {
    try std.testing.expect(!isMacosFskitSupportedVersion(.{ .major = 15, .minor = 3, .patch = 9 }));
    try std.testing.expect(isMacosFskitSupportedVersion(.{ .major = 15, .minor = 4, .patch = 0 }));
    try std.testing.expect(isMacosFskitSupportedVersion(.{ .major = 15, .minor = 6, .patch = 0 }));
}

test "fs_fuse_adapter: darwin mount options prefer fskit with generated volume name" {
    const allocator = std.testing.allocator;
    const options = try buildMountOptionsForOs(allocator, .macos, "/Volumes/Spiderweb Demo");
    defer allocator.free(options);

    try std.testing.expect(std.mem.indexOf(u8, options, "backend=fskit") != null);
    try std.testing.expect(std.mem.indexOf(u8, options, "volname=Spiderweb-Demo") != null);
    try std.testing.expect(std.mem.indexOf(u8, options, "fsname=spiderweb#Spiderweb-Demo") != null);
}

test "fs_fuse_adapter: darwin library candidates use macfuse libfuse3" {
    const candidates = try mountLibraryCandidatesForOs(.macos, .auto);
    try std.testing.expect(candidates.len > 0);
    try std.testing.expectEqualStrings("/usr/local/lib/libfuse3.dylib", candidates[0]);
    var saw_framework = false;
    for (candidates) |candidate| {
        if (std.mem.indexOf(u8, candidate, "macfuse.framework") != null) {
            saw_framework = true;
            break;
        }
    }
    try std.testing.expect(saw_framework);
}
