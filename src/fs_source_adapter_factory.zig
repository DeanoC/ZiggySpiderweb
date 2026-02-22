const std = @import("std");
const fs_source_adapter = @import("fs_source_adapter.zig");
const fs_linux_source_adapter = @import("fs_linux_source_adapter.zig");
const fs_posix_source_adapter = @import("fs_posix_source_adapter.zig");
const fs_windows_source_adapter = @import("fs_windows_source_adapter.zig");
const fs_gdrive_source_adapter = @import("fs_gdrive_source_adapter.zig");
const fs_local_source_adapter = @import("fs_local_source_adapter.zig");

pub fn create(
    allocator: std.mem.Allocator,
    source_kind: fs_source_adapter.SourceKind,
) !fs_source_adapter.SourceAdapter {
    return switch (source_kind) {
        .linux => fs_linux_source_adapter.init(allocator),
        .posix => fs_posix_source_adapter.init(allocator),
        .windows => fs_windows_source_adapter.init(allocator),
        .gdrive => fs_gdrive_source_adapter.init(),
    };
}

test "fs_source_adapter_factory: linux and posix are supported" {
    const allocator = std.testing.allocator;

    var linux = try create(allocator, .linux);
    linux.deinit(allocator);

    var posix = try create(allocator, .posix);
    posix.deinit(allocator);
}

test "fs_source_adapter_factory: windows support follows host capability" {
    const allocator = std.testing.allocator;
    if (@import("builtin").os.tag == .windows) {
        var windows = try create(allocator, .windows);
        windows.deinit(allocator);
    } else {
        try std.testing.expectError(error.UnsupportedSourceHost, create(allocator, .windows));
    }
}

test "fs_source_adapter_factory: gdrive scaffold is supported" {
    const allocator = std.testing.allocator;
    var gdrive = try create(allocator, .gdrive);
    gdrive.deinit(allocator);
}

test "fs_source_adapter_factory: source capability matrix is consistent" {
    const allocator = std.testing.allocator;

    var linux = try create(allocator, .linux);
    defer linux.deinit(allocator);
    try std.testing.expect(linux.supportsOperation(.setxattr));
    try std.testing.expect(linux.supportsOperation(.lock));

    var posix = try create(allocator, .posix);
    defer posix.deinit(allocator);
    try std.testing.expect(posix.supportsOperation(.symlink));
    try std.testing.expect(posix.supportsOperation(.rename));

    var gdrive = try create(allocator, .gdrive);
    defer gdrive.deinit(allocator);
    try std.testing.expect(gdrive.supportsOperation(.create));
    try std.testing.expect(gdrive.supportsOperation(.write));
    try std.testing.expect(!gdrive.supportsOperation(.setxattr));
    try std.testing.expect(!gdrive.supportsOperation(.lock));

    if (@import("builtin").os.tag == .windows) {
        var windows = try create(allocator, .windows);
        defer windows.deinit(allocator);
        try std.testing.expect(!windows.supportsOperation(.setxattr));
        try std.testing.expect(windows.supportsOperation(.rename));
    } else {
        try std.testing.expect(!fs_local_source_adapter.supportsOperationForKind(.windows, .setxattr));
        try std.testing.expect(fs_local_source_adapter.supportsOperationForKind(.windows, .rename));
    }
}
