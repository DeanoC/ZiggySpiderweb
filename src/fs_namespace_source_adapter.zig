const std = @import("std");
const fs_source_adapter = @import("fs_source_adapter.zig");

const namespace_vtable = fs_source_adapter.VTable{
    .deinit = deinit,
    .prepare_export = prepareExport,
    .feature_caps = featureCaps,
    .supports_operation = supportsOperation,
};

pub fn init() fs_source_adapter.SourceAdapter {
    return .{
        .ctx = null,
        .vtable = &namespace_vtable,
    };
}

fn deinit(ctx: ?*anyopaque, allocator: std.mem.Allocator) void {
    _ = ctx;
    _ = allocator;
}

fn prepareExport(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    path: []const u8,
) !fs_source_adapter.PreparedExport {
    _ = ctx;
    const role = if (path.len == 0) "default" else path;
    const root_path = try std.fmt.allocPrint(allocator, "namespace://{s}", .{role});

    var inode = std.hash.Wyhash.hash(0x4E41_4D45_5350_4143, root_path);
    if (inode == 0) inode = 1;

    return .{
        .root_real_path = root_path,
        .root_inode = inode,
        .default_caps = fs_source_adapter.defaultCapsForKind(.namespace),
    };
}

fn featureCaps(ctx: ?*anyopaque) fs_source_adapter.SourceCaps {
    _ = ctx;
    return fs_source_adapter.defaultCapsForKind(.namespace);
}

fn supportsOperation(ctx: ?*anyopaque, op: fs_source_adapter.Operation) bool {
    _ = ctx;
    return switch (op) {
        .lookup,
        .getattr,
        .readdirp,
        .open,
        .read,
        .close,
        .create,
        .write,
        .truncate,
        .unlink,
        .mkdir,
        .rmdir,
        .rename,
        .statfs,
        => true,
        .symlink,
        .setxattr,
        .getxattr,
        .listxattr,
        .removexattr,
        .lock,
        => false,
    };
}

test "fs_namespace_source_adapter: prepareExport builds synthetic root" {
    const allocator = std.testing.allocator;
    var adapter = init();
    defer adapter.deinit(allocator);

    const prepared = try adapter.prepareExport(allocator, "meta");
    defer allocator.free(prepared.root_real_path);

    try std.testing.expect(std.mem.startsWith(u8, prepared.root_real_path, "namespace://"));
    try std.testing.expect(prepared.root_inode != 0);
}
