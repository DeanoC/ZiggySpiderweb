const std = @import("std");
const builtin = @import("builtin");

pub const SourceKind = enum {
    linux,
    posix,
    windows,
    gdrive,

    pub fn asString(self: SourceKind) []const u8 {
        return @tagName(self);
    }
};

pub const SourceCaps = struct {
    native_watch: bool,
    case_sensitive: bool,
    symlink: bool,
    xattr: bool,
    locks: bool,
    statfs: bool,
};

pub const Operation = enum {
    lookup,
    getattr,
    readdirp,
    open,
    read,
    close,
    create,
    write,
    truncate,
    unlink,
    mkdir,
    rmdir,
    rename,
    statfs,
    symlink,
    setxattr,
    getxattr,
    listxattr,
    removexattr,
    lock,
};

pub const PreparedExport = struct {
    root_real_path: []u8,
    root_inode: u64,
    default_caps: SourceCaps,
};

pub const VTable = struct {
    deinit: *const fn (ctx: ?*anyopaque, allocator: std.mem.Allocator) void,
    prepare_export: *const fn (ctx: ?*anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror!PreparedExport,
    feature_caps: *const fn (ctx: ?*anyopaque) SourceCaps,
    supports_operation: *const fn (ctx: ?*anyopaque, op: Operation) bool,
};

pub const SourceAdapter = struct {
    ctx: ?*anyopaque,
    vtable: *const VTable,

    pub fn deinit(self: *SourceAdapter, allocator: std.mem.Allocator) void {
        self.vtable.deinit(self.ctx, allocator);
        self.* = undefined;
    }

    pub fn prepareExport(self: *const SourceAdapter, allocator: std.mem.Allocator, path: []const u8) !PreparedExport {
        return self.vtable.prepare_export(self.ctx, allocator, path);
    }

    pub fn featureCaps(self: *const SourceAdapter) SourceCaps {
        return self.vtable.feature_caps(self.ctx);
    }

    pub fn supportsOperation(self: *const SourceAdapter, op: Operation) bool {
        return self.vtable.supports_operation(self.ctx, op);
    }
};

pub fn defaultSourceKindForHost() SourceKind {
    return switch (builtin.os.tag) {
        .linux => .linux,
        .windows => .windows,
        else => .posix,
    };
}

pub fn defaultCapsForKind(source_kind: SourceKind) SourceCaps {
    return switch (source_kind) {
        .linux => .{
            .native_watch = builtin.os.tag == .linux,
            .case_sensitive = true,
            .symlink = true,
            .xattr = true,
            .locks = true,
            .statfs = true,
        },
        .posix => .{
            .native_watch = false,
            .case_sensitive = true,
            .symlink = true,
            .xattr = true,
            .locks = true,
            .statfs = true,
        },
        .windows => .{
            .native_watch = builtin.os.tag == .windows,
            .case_sensitive = false,
            .symlink = false,
            .xattr = false,
            .locks = true,
            .statfs = true,
        },
        .gdrive => .{
            .native_watch = false,
            .case_sensitive = true,
            .symlink = false,
            .xattr = false,
            .locks = false,
            .statfs = true,
        },
    };
}

test "fs_source_adapter: host default kind is one of known variants" {
    const kind = defaultSourceKindForHost();
    try std.testing.expect(kind == .linux or kind == .windows or kind == .posix);
}
