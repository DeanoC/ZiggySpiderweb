const std = @import("std");
const fs_source_adapter = @import("fs_source_adapter.zig");
const fs_local_source_adapter = @import("fs_local_source_adapter.zig");

pub fn init(allocator: std.mem.Allocator) !fs_source_adapter.SourceAdapter {
    return fs_local_source_adapter.init(allocator, .posix);
}

test "fs_posix_source_adapter: init prepares adapter" {
    const allocator = std.testing.allocator;
    var adapter = try init(allocator);
    defer adapter.deinit(allocator);
}
