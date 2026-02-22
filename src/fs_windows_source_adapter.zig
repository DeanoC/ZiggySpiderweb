const std = @import("std");
const builtin = @import("builtin");
const fs_source_adapter = @import("fs_source_adapter.zig");
const fs_protocol = @import("fs_protocol.zig");

pub const Win32Error = enum(u32) {
    ACCESS_DENIED = 5,
    FILE_NOT_FOUND = 2,
    PATH_NOT_FOUND = 3,
    ALREADY_EXISTS = 183,
    DISK_FULL = 112,
    DIR_NOT_EMPTY = 145,
    SHARING_VIOLATION = 32,
    LOCK_VIOLATION = 33,
    NOT_SUPPORTED = 50,
    INVALID_PARAMETER = 87,
};

const windows_vtable = fs_source_adapter.VTable{
    .deinit = deinit,
    .prepare_export = prepareExport,
    .feature_caps = featureCaps,
    .supports_operation = supportsOperation,
};

const WindowsSourceAdapter = struct {};

pub fn init(allocator: std.mem.Allocator) !fs_source_adapter.SourceAdapter {
    if (builtin.os.tag != .windows) return error.UnsupportedSourceHost;
    const adapter = try allocator.create(WindowsSourceAdapter);
    adapter.* = .{};
    return .{
        .ctx = adapter,
        .vtable = &windows_vtable,
    };
}

fn deinit(ctx: ?*anyopaque, allocator: std.mem.Allocator) void {
    const raw = ctx orelse return;
    const adapter: *WindowsSourceAdapter = @ptrCast(@alignCast(raw));
    allocator.destroy(adapter);
}

fn prepareExport(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    path: []const u8,
) !fs_source_adapter.PreparedExport {
    _ = ctx orelse return error.InvalidAdapterContext;
    const root_real = std.fs.cwd().realpathAlloc(allocator, path) catch return error.InvalidExportPath;
    errdefer allocator.free(root_real);

    const stat = statPath(root_real) catch return error.InvalidExportPath;
    if (stat.kind != .directory) return error.InvalidExportPath;

    return .{
        .root_real_path = root_real,
        .root_inode = inodeToU64(stat.inode),
        .default_caps = fs_source_adapter.defaultCapsForKind(.windows),
    };
}

fn featureCaps(ctx: ?*anyopaque) fs_source_adapter.SourceCaps {
    _ = ctx;
    return fs_source_adapter.defaultCapsForKind(.windows);
}

fn supportsOperation(ctx: ?*anyopaque, op: fs_source_adapter.Operation) bool {
    _ = ctx;
    return switch (op) {
        .symlink, .setxattr, .getxattr, .listxattr, .removexattr => false,
        else => true,
    };
}

pub fn normalizePathForWire(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, path.len);
    for (path, 0..) |ch, idx| {
        out[idx] = if (ch == '\\') '/' else ch;
    }
    return out;
}

pub fn normalizeNameForCache(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, name.len);
    for (name, 0..) |ch, idx| out[idx] = std.ascii.toLower(ch);
    return out;
}

pub fn win32ErrorToErrno(err_code: u32) i32 {
    return switch (err_code) {
        @intFromEnum(Win32Error.ACCESS_DENIED) => fs_protocol.Errno.EACCES,
        @intFromEnum(Win32Error.FILE_NOT_FOUND), @intFromEnum(Win32Error.PATH_NOT_FOUND) => fs_protocol.Errno.ENOENT,
        @intFromEnum(Win32Error.ALREADY_EXISTS) => fs_protocol.Errno.EEXIST,
        @intFromEnum(Win32Error.DISK_FULL) => fs_protocol.Errno.ENOSPC,
        @intFromEnum(Win32Error.DIR_NOT_EMPTY) => fs_protocol.Errno.ENOTEMPTY,
        @intFromEnum(Win32Error.SHARING_VIOLATION), @intFromEnum(Win32Error.LOCK_VIOLATION) => fs_protocol.Errno.EAGAIN,
        @intFromEnum(Win32Error.NOT_SUPPORTED) => fs_protocol.Errno.ENOSYS,
        @intFromEnum(Win32Error.INVALID_PARAMETER) => fs_protocol.Errno.EINVAL,
        else => fs_protocol.Errno.EIO,
    };
}

pub const LookupResult = struct {
    resolved_path: []u8,
    stat: std.fs.File.Stat,
};

pub const OpenResult = struct {
    file: std.fs.File,
    stat: std.fs.File.Stat,
};

pub const LockMode = enum {
    shared,
    exclusive,
    unlock,
};

pub fn lookupChildAbsolute(
    allocator: std.mem.Allocator,
    root_path: []const u8,
    parent_path: []const u8,
    name: []const u8,
) !LookupResult {
    const joined = try std.fs.path.join(allocator, &.{ parent_path, name });
    defer allocator.free(joined);

    const resolved = try std.fs.cwd().realpathAlloc(allocator, joined);
    errdefer allocator.free(resolved);
    if (!isWithinRoot(root_path, resolved)) return error.AccessDenied;

    const stat = try statPath(resolved);
    return .{
        .resolved_path = resolved,
        .stat = stat,
    };
}

pub fn statAbsolute(path: []const u8) !std.fs.File.Stat {
    return statPath(path);
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
    const stat = try statPath(resolved);
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

pub fn lockFile(file: *std.fs.File, mode: LockMode, wait: bool) !void {
    switch (mode) {
        .unlock => {
            file.*.unlock();
            return;
        },
        else => {},
    }

    const lock_mode: std.fs.File.Lock = switch (mode) {
        .shared => .shared,
        .exclusive => .exclusive,
        .unlock => unreachable,
    };

    if (wait) {
        file.*.lock(lock_mode) catch |err| switch (err) {
            error.FileLocksNotSupported => return error.OperationNotSupported,
            else => return err,
        };
        return;
    }

    // Zig 0.15.1 Windows stdlib lock API currently does not reliably support
    // non-blocking lock probing through tryLock for our target matrix.
    return error.OperationNotSupported;
}

fn isWithinRoot(root: []const u8, target: []const u8) bool {
    if (std.mem.eql(u8, root, target)) return true;
    if (!std.mem.startsWith(u8, target, root)) return false;
    if (target.len <= root.len) return false;
    return target[root.len] == std.fs.path.sep;
}

fn statPath(path: []const u8) !std.fs.File.Stat {
    return std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.IsDir => {
            var dir = if (std.fs.path.isAbsolute(path))
                try std.fs.openDirAbsolute(path, .{})
            else
                try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            return try dir.stat();
        },
        else => return err,
    };
}

fn inodeToU64(inode: anytype) u64 {
    const InodeType = @TypeOf(inode);
    if (comptime @typeInfo(InodeType).int.signedness == .signed) {
        if (inode < 0) return 0;
    }
    return @intCast(inode);
}

test "fs_windows_source_adapter: rejects non-windows hosts" {
    if (builtin.os.tag == .windows) return;
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedSourceHost, init(allocator));
}

test "fs_windows_source_adapter: normalizePathForWire canonicalizes separators" {
    const allocator = std.testing.allocator;
    const out = try normalizePathForWire(allocator, "C:\\Users\\Dev\\work");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("C:/Users/Dev/work", out);
}

test "fs_windows_source_adapter: normalizeNameForCache folds ASCII case" {
    const allocator = std.testing.allocator;
    const out = try normalizeNameForCache(allocator, "ReadMe.TXT");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("readme.txt", out);
}

test "fs_windows_source_adapter: win32ErrorToErrno maps common file errors" {
    try std.testing.expectEqual(fs_protocol.Errno.EACCES, win32ErrorToErrno(@intFromEnum(Win32Error.ACCESS_DENIED)));
    try std.testing.expectEqual(fs_protocol.Errno.ENOENT, win32ErrorToErrno(@intFromEnum(Win32Error.FILE_NOT_FOUND)));
    try std.testing.expectEqual(fs_protocol.Errno.EEXIST, win32ErrorToErrno(@intFromEnum(Win32Error.ALREADY_EXISTS)));
    try std.testing.expectEqual(fs_protocol.Errno.EAGAIN, win32ErrorToErrno(@intFromEnum(Win32Error.SHARING_VIOLATION)));
    try std.testing.expectEqual(fs_protocol.Errno.ENOSYS, win32ErrorToErrno(@intFromEnum(Win32Error.NOT_SUPPORTED)));
}

test "fs_windows_source_adapter: supportsOperation matrix reflects capability gaps" {
    try std.testing.expect(!supportsOperation(null, .setxattr));
    try std.testing.expect(!supportsOperation(null, .symlink));
    try std.testing.expect(supportsOperation(null, .rename));
    try std.testing.expect(supportsOperation(null, .lock));
}
