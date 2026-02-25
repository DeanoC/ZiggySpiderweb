const std = @import("std");
const builtin = @import("builtin");
const fs_source_adapter = @import("fs_source_adapter.zig");
const c = if (builtin.os.tag == .windows)
    struct {}
else
    @cImport({
        @cInclude("sys/file.h");
        @cInclude("sys/stat.h");
        @cInclude("sys/xattr.h");
    });

const local_vtable = fs_source_adapter.VTable{
    .deinit = deinit,
    .prepare_export = prepareExport,
    .feature_caps = featureCaps,
    .supports_operation = supportsOperation,
};

pub fn init(allocator: std.mem.Allocator, source_kind: fs_source_adapter.SourceKind) !fs_source_adapter.SourceAdapter {
    const adapter = try allocator.create(LocalSourceAdapter);
    adapter.* = .{
        .source_kind = source_kind,
    };
    return .{
        .ctx = adapter,
        .vtable = &local_vtable,
    };
}

const LocalSourceAdapter = struct {
    source_kind: fs_source_adapter.SourceKind,
};

fn deinit(ctx: ?*anyopaque, allocator: std.mem.Allocator) void {
    const raw = ctx orelse return;
    const adapter: *LocalSourceAdapter = @ptrCast(@alignCast(raw));
    allocator.destroy(adapter);
}

fn prepareExport(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    path: []const u8,
) !fs_source_adapter.PreparedExport {
    const raw = ctx orelse return error.InvalidAdapterContext;
    const adapter: *LocalSourceAdapter = @ptrCast(@alignCast(raw));

    const root_real = std.fs.cwd().realpathAlloc(allocator, path) catch return error.InvalidExportPath;
    errdefer allocator.free(root_real);

    const stat = std.fs.cwd().statFile(root_real) catch return error.InvalidExportPath;
    if (stat.kind != .directory) return error.InvalidExportPath;

    return .{
        .root_real_path = root_real,
        .root_inode = inodeToU64(stat.inode),
        .default_caps = fs_source_adapter.defaultCapsForKind(adapter.source_kind),
    };
}

fn featureCaps(ctx: ?*anyopaque) fs_source_adapter.SourceCaps {
    const raw = ctx orelse return fs_source_adapter.defaultCapsForKind(.posix);
    const adapter: *LocalSourceAdapter = @ptrCast(@alignCast(raw));
    return fs_source_adapter.defaultCapsForKind(adapter.source_kind);
}

fn supportsOperation(ctx: ?*anyopaque, op: fs_source_adapter.Operation) bool {
    const raw = ctx orelse return false;
    const adapter: *LocalSourceAdapter = @ptrCast(@alignCast(raw));
    return supportsOperationForKind(adapter.source_kind, op);
}

pub fn supportsOperationForKind(source_kind: fs_source_adapter.SourceKind, op: fs_source_adapter.Operation) bool {
    return switch (source_kind) {
        .linux, .posix => true,
        .windows => switch (op) {
            .symlink, .setxattr, .getxattr, .listxattr, .removexattr => false,
            else => true,
        },
        .gdrive, .namespace => false,
    };
}

pub const LockMode = enum {
    shared,
    exclusive,
    unlock,
};

pub const LookupResult = struct {
    resolved_path: []u8,
    stat: std.fs.File.Stat,
};

pub const OpenResult = struct {
    file: std.fs.File,
    stat: std.fs.File.Stat,
};

pub fn lookupChildAbsolute(
    allocator: std.mem.Allocator,
    root_path: []const u8,
    parent_path: []const u8,
    name: []const u8,
) !LookupResult {
    const joined = try std.fs.path.join(allocator, &.{ parent_path, name });
    defer allocator.free(joined);

    if (!isWithinRoot(root_path, joined)) return error.AccessDenied;

    if (builtin.os.tag != .windows) {
        const joined_z = try allocator.dupeZ(u8, joined);
        defer allocator.free(joined_z);
        const lst = try lstatFileNoPanicZ(joined_z.ptr);
        if (lst.kind != .sym_link) {
            return .{
                .resolved_path = try allocator.dupe(u8, joined),
                .stat = lst,
            };
        }
    }

    const resolved = try std.fs.cwd().realpathAlloc(allocator, joined);
    errdefer allocator.free(resolved);
    if (!isWithinRoot(root_path, resolved)) return error.AccessDenied;

    const stat = if (builtin.os.tag == .windows)
        try std.fs.cwd().statFile(resolved)
    else blk: {
        const resolved_z = try allocator.dupeZ(u8, resolved);
        defer allocator.free(resolved_z);
        break :blk try statFileNoPanicZ(resolved_z.ptr);
    };
    return .{
        .resolved_path = resolved,
        .stat = stat,
    };
}

fn statFileNoPanicZ(path_z: [*:0]const u8) !std.fs.File.Stat {
    var st: c.struct_stat = std.mem.zeroes(c.struct_stat);
    while (true) {
        const rc = c.stat(path_z, &st);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return fileStatFromC(st),
            .INTR => continue,
            .ACCES, .PERM => return error.AccessDenied,
            .NOENT, .NOTDIR, .NOTCONN => return error.FileNotFound,
            else => |errno_no| return posixErrnoToError(errno_no),
        }
    }
}

fn lstatFileNoPanicZ(path_z: [*:0]const u8) !std.fs.File.Stat {
    var st: c.struct_stat = std.mem.zeroes(c.struct_stat);
    while (true) {
        const rc = c.lstat(path_z, &st);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return fileStatFromC(st),
            .INTR => continue,
            .ACCES, .PERM => return error.AccessDenied,
            .NOENT, .NOTDIR, .NOTCONN => return error.FileNotFound,
            else => |errno_no| return posixErrnoToError(errno_no),
        }
    }
}

fn fileStatFromC(st: c.struct_stat) std.fs.File.Stat {
    const mode: u32 = @intCast(st.st_mode);
    const atime = if (@hasField(c.struct_stat, "st_atim"))
        timespecToNs(st.st_atim)
    else if (@hasField(c.struct_stat, "st_atimespec"))
        timespecToNs(st.st_atimespec)
    else
        @as(i128, 0);
    const mtime = if (@hasField(c.struct_stat, "st_mtim"))
        timespecToNs(st.st_mtim)
    else if (@hasField(c.struct_stat, "st_mtimespec"))
        timespecToNs(st.st_mtimespec)
    else
        @as(i128, 0);
    const ctime = if (@hasField(c.struct_stat, "st_ctim"))
        timespecToNs(st.st_ctim)
    else if (@hasField(c.struct_stat, "st_ctimespec"))
        timespecToNs(st.st_ctimespec)
    else
        @as(i128, 0);
    const size_i128: i128 = @intCast(st.st_size);
    const size: u64 = if (size_i128 < 0) 0 else @intCast(size_i128);

    return .{
        .inode = @intCast(st.st_ino),
        .size = size,
        .mode = @intCast(mode),
        .kind = switch (mode & std.posix.S.IFMT) {
            std.posix.S.IFBLK => .block_device,
            std.posix.S.IFCHR => .character_device,
            std.posix.S.IFDIR => .directory,
            std.posix.S.IFIFO => .named_pipe,
            std.posix.S.IFLNK => .sym_link,
            std.posix.S.IFREG => .file,
            std.posix.S.IFSOCK => .unix_domain_socket,
            else => .unknown,
        },
        .atime = atime,
        .mtime = mtime,
        .ctime = ctime,
    };
}

fn timespecToNs(ts: anytype) i128 {
    return @as(i128, ts.tv_sec) * std.time.ns_per_s + @as(i128, ts.tv_nsec);
}

pub fn statAbsolute(path: []const u8) !std.fs.File.Stat {
    return std.fs.cwd().statFile(path);
}

pub fn openDirAbsolute(path: []const u8) !std.fs.Dir {
    return std.fs.openDirAbsolute(path, .{ .iterate = true });
}

pub fn openAbsolute(path: []const u8, mode: std.fs.File.OpenMode) !OpenResult {
    var file = try std.fs.openFileAbsolute(path, .{ .mode = mode });
    errdefer file.close();
    const stat = try file.stat();
    return .{
        .file = file,
        .stat = stat,
    };
}

pub fn symlinkAbsolute(target: []const u8, link_path: []const u8) !void {
    try std.fs.cwd().symLink(target, link_path, .{});
}

pub fn createExclusiveAbsolute(path: []const u8, mode: u32) !std.fs.File {
    return std.fs.createFileAbsolute(path, .{
        .read = true,
        .truncate = false,
        .exclusive = true,
        .mode = @intCast(mode),
    });
}

pub fn realpathAndStatAbsolute(allocator: std.mem.Allocator, path: []const u8) !LookupResult {
    const resolved = try std.fs.cwd().realpathAlloc(allocator, path);
    errdefer allocator.free(resolved);
    const stat = try std.fs.cwd().statFile(resolved);
    return .{
        .resolved_path = resolved,
        .stat = stat,
    };
}

pub fn truncateAbsolute(path: []const u8, size: u64) !void {
    var file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    defer file.close();
    try file.setEndPos(size);
}

pub fn deleteFileAbsolute(path: []const u8) !void {
    try std.fs.deleteFileAbsolute(path);
}

pub fn makeDirAbsolute(path: []const u8) !void {
    try std.fs.makeDirAbsolute(path);
}

pub fn deleteDirAbsolute(path: []const u8) !void {
    try std.fs.deleteDirAbsolute(path);
}

pub fn renameAbsolute(old_path: []const u8, new_path: []const u8) !void {
    try std.fs.renameAbsolute(old_path, new_path);
}

pub fn posixErrnoToError(errno_no: std.posix.E) anyerror {
    return switch (errno_no) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .ISDIR => error.IsDir,
        .EXIST => error.PathAlreadyExists,
        .NAMETOOLONG => error.NameTooLong,
        .ROFS => error.ReadOnlyFileSystem,
        .BADF => error.InvalidHandle,
        .INVAL => error.InvalidArgument,
        .NODATA => error.NoData,
        .AGAIN => error.WouldBlock,
        .RANGE => error.Range,
        .NOSPC => error.NoSpaceLeft,
        .NOSYS, .OPNOTSUPP => error.OperationNotSupported,
        else => error.UnexpectedErrno,
    };
}

pub fn lockFile(file: *std.fs.File, mode: LockMode, wait: bool) !void {
    if (builtin.os.tag == .windows) return error.OperationNotSupported;
    var flock_mode: c_int = switch (mode) {
        .shared => c.LOCK_SH,
        .exclusive => c.LOCK_EX,
        .unlock => c.LOCK_UN,
    };
    if (!wait and mode != .unlock) flock_mode |= c.LOCK_NB;

    while (true) {
        const fd: c_int = @intCast(file.handle);
        const rc = c.flock(fd, flock_mode);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |errno_no| return posixErrnoToError(errno_no),
        }
    }
}

pub fn setXattrAbsolute(
    allocator: std.mem.Allocator,
    path: []const u8,
    name: []const u8,
    value: []const u8,
    flags: u32,
) !void {
    if (builtin.os.tag == .windows) return error.OperationNotSupported;
    if (flags > std.math.maxInt(c_int)) return error.InvalidArgument;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);

    while (true) {
        const value_ptr = if (value.len == 0) null else @as(?*const anyopaque, @ptrCast(value.ptr));
        const rc = c.setxattr(path_z.ptr, name_z.ptr, value_ptr, value.len, @intCast(flags));
        switch (std.posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |errno_no| return posixErrnoToError(errno_no),
        }
    }
}

pub fn getXattrAbsolute(allocator: std.mem.Allocator, path: []const u8, name: []const u8) ![]u8 {
    if (builtin.os.tag == .windows) return error.OperationNotSupported;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);

    while (true) {
        const size_rc = c.getxattr(path_z.ptr, name_z.ptr, null, 0);
        switch (std.posix.errno(size_rc)) {
            .SUCCESS => {
                const needed: usize = @intCast(size_rc);
                if (needed == 0) return allocator.alloc(u8, 0);

                const out = try allocator.alloc(u8, needed);
                errdefer allocator.free(out);

                while (true) {
                    const rc = c.getxattr(path_z.ptr, name_z.ptr, out.ptr, out.len);
                    switch (std.posix.errno(rc)) {
                        .SUCCESS => {
                            const got: usize = @intCast(rc);
                            if (got == out.len) return out;
                            const trimmed = try allocator.dupe(u8, out[0..got]);
                            allocator.free(out);
                            return trimmed;
                        },
                        .INTR => continue,
                        .RANGE => break,
                        else => |errno_no| return posixErrnoToError(errno_no),
                    }
                }
            },
            .INTR => continue,
            else => |errno_no| return posixErrnoToError(errno_no),
        }
    }
}

pub fn listXattrAbsolute(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (builtin.os.tag == .windows) return error.OperationNotSupported;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    while (true) {
        const size_rc = c.listxattr(path_z.ptr, null, 0);
        switch (std.posix.errno(size_rc)) {
            .SUCCESS => {
                const needed: usize = @intCast(size_rc);
                if (needed == 0) return allocator.alloc(u8, 0);

                const out = try allocator.alloc(u8, needed);
                errdefer allocator.free(out);

                while (true) {
                    const rc = c.listxattr(path_z.ptr, out.ptr, out.len);
                    switch (std.posix.errno(rc)) {
                        .SUCCESS => {
                            const got: usize = @intCast(rc);
                            if (got == out.len) return out;
                            const trimmed = try allocator.dupe(u8, out[0..got]);
                            allocator.free(out);
                            return trimmed;
                        },
                        .INTR => continue,
                        .RANGE => break,
                        else => |errno_no| return posixErrnoToError(errno_no),
                    }
                }
            },
            .INTR => continue,
            else => |errno_no| return posixErrnoToError(errno_no),
        }
    }
}

pub fn removeXattrAbsolute(allocator: std.mem.Allocator, path: []const u8, name: []const u8) !void {
    if (builtin.os.tag == .windows) return error.OperationNotSupported;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);

    while (true) {
        const rc = c.removexattr(path_z.ptr, name_z.ptr);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => |errno_no| return posixErrnoToError(errno_no),
        }
    }
}

fn isWithinRoot(root: []const u8, target: []const u8) bool {
    var normalized_root = root;
    while (normalized_root.len > 1 and normalized_root[normalized_root.len - 1] == std.fs.path.sep) {
        normalized_root = normalized_root[0 .. normalized_root.len - 1];
    }

    if (normalized_root.len == 1 and normalized_root[0] == std.fs.path.sep) {
        return target.len > 0 and target[0] == std.fs.path.sep;
    }

    if (std.mem.eql(u8, normalized_root, target)) return true;
    if (!std.mem.startsWith(u8, target, normalized_root)) return false;
    if (target.len <= normalized_root.len) return false;
    return target[normalized_root.len] == std.fs.path.sep;
}

fn inodeToU64(inode: anytype) u64 {
    const InodeType = @TypeOf(inode);
    if (comptime @typeInfo(InodeType).int.signedness == .signed) {
        if (inode < 0) return 0;
    }
    return @intCast(inode);
}

test "fs_local_source_adapter: prepareExport resolves temp dir" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var adapter = try init(allocator, .posix);
    defer adapter.deinit(allocator);

    const prepared = try adapter.prepareExport(allocator, root);
    defer allocator.free(prepared.root_real_path);

    try std.testing.expect(prepared.root_inode > 0);
    try std.testing.expect(prepared.default_caps.case_sensitive);
}

test "fs_local_source_adapter: supportsOperationForKind reflects windows capability gaps" {
    try std.testing.expect(supportsOperationForKind(.linux, .setxattr));
    try std.testing.expect(supportsOperationForKind(.posix, .lock));
    try std.testing.expect(!supportsOperationForKind(.windows, .symlink));
    try std.testing.expect(!supportsOperationForKind(.windows, .getxattr));
    try std.testing.expect(supportsOperationForKind(.windows, .rename));
}

test "fs_local_source_adapter: isWithinRoot handles root and exact-prefix boundaries" {
    try std.testing.expect(isWithinRoot("/", "/"));
    try std.testing.expect(isWithinRoot("/", "/etc"));
    try std.testing.expect(isWithinRoot("/safe", "/safe"));
    try std.testing.expect(isWithinRoot("/safe", "/safe/project"));
    try std.testing.expect(!isWithinRoot("/safe", "/safeguard"));
}

test "fs_local_source_adapter: execution helpers cover basic file lifecycle" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    try temp.dir.writeFile(.{ .sub_path = "hello.txt", .data = "abc" });
    const looked = try lookupChildAbsolute(allocator, root, root, "hello.txt");
    defer allocator.free(looked.resolved_path);
    try std.testing.expectEqual(@as(u64, 3), looked.stat.size);

    const opened = try openAbsolute(looked.resolved_path, .read_only);
    defer opened.file.close();
    try std.testing.expectEqual(@as(u64, 3), opened.stat.size);

    const created_path = try std.fs.path.join(allocator, &.{ root, "new.txt" });
    defer allocator.free(created_path);
    var created = try createExclusiveAbsolute(created_path, 0o100644);
    created.close();

    try truncateAbsolute(created_path, 0);
    const renamed_path = try std.fs.path.join(allocator, &.{ root, "new-renamed.txt" });
    defer allocator.free(renamed_path);
    try renameAbsolute(created_path, renamed_path);
    try deleteFileAbsolute(renamed_path);

    const created_dir = try std.fs.path.join(allocator, &.{ root, "subdir" });
    defer allocator.free(created_dir);
    try makeDirAbsolute(created_dir);
    try deleteDirAbsolute(created_dir);
}
