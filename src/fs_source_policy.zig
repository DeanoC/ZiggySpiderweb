const std = @import("std");

pub const EndpointView = struct {
    read_only: ?bool = null,
    source_kind: ?[]const u8 = null,
    case_sensitive: ?bool = null,
};

pub const Operation = enum {
    read_data,
    write_data,
    create,
    remove,
    rename,
    statfs,
    symlink,
    xattr,
    locks,
};

const SourceKind = enum {
    linux,
    posix,
    windows,
    gdrive,
    unknown,
};

fn classify(kind: ?[]const u8) SourceKind {
    const raw = kind orelse return .unknown;
    if (std.ascii.eqlIgnoreCase(raw, "linux")) return .linux;
    if (std.ascii.eqlIgnoreCase(raw, "posix")) return .posix;
    if (std.ascii.eqlIgnoreCase(raw, "windows")) return .windows;
    if (std.ascii.eqlIgnoreCase(raw, "gdrive")) return .gdrive;
    return .unknown;
}

fn supportsKind(kind: SourceKind, op: Operation) bool {
    return switch (kind) {
        .linux => switch (op) {
            .read_data, .write_data, .create, .remove, .rename, .statfs, .symlink, .xattr, .locks => true,
        },
        .posix => switch (op) {
            .read_data, .write_data, .create, .remove, .rename, .statfs, .symlink, .xattr, .locks => true,
        },
        .windows => switch (op) {
            .read_data, .write_data, .create, .remove, .rename, .statfs, .locks => true,
            .symlink, .xattr => false,
        },
        .gdrive => switch (op) {
            .read_data, .write_data, .create, .remove, .rename, .statfs => true,
            .symlink, .xattr, .locks => false,
        },
        .unknown => switch (op) {
            .read_data, .write_data, .create, .remove, .rename, .statfs => true,
            .symlink, .xattr, .locks => false,
        },
    };
}

pub fn supports(endpoint: EndpointView, op: Operation) bool {
    return supportsKind(classify(endpoint.source_kind), op);
}

fn effectiveCaseSensitive(endpoint: EndpointView) bool {
    if (endpoint.case_sensitive) |value| return value;
    return switch (classify(endpoint.source_kind)) {
        .windows => false,
        else => true,
    };
}

pub fn allowsWritePathResolution(endpoint: EndpointView, require_writable: bool) bool {
    if (!require_writable) return true;
    if (!supports(endpoint, .write_data)) return false;
    return endpoint.read_only != true;
}

pub fn normalizeNameForCache(allocator: std.mem.Allocator, endpoint: EndpointView, name: []const u8) ![]u8 {
    if (effectiveCaseSensitive(endpoint)) return allocator.dupe(u8, name);

    const out = try allocator.alloc(u8, name.len);
    for (name, 0..) |ch, idx| out[idx] = std.ascii.toLower(ch);
    return out;
}

pub fn isCaseOnlyRenameNoop(endpoint: EndpointView, same_parent: bool, old_name: []const u8, new_name: []const u8) bool {
    if (effectiveCaseSensitive(endpoint)) return false;
    if (!same_parent) return false;
    return std.ascii.eqlIgnoreCase(old_name, new_name);
}

pub fn allowsCrossEndpointCopyFallback(src: EndpointView, dst: EndpointView) bool {
    if (src.read_only == true) return false;
    if (dst.read_only == true) return false;
    if (!supports(src, .read_data)) return false;
    if (!supports(src, .remove)) return false;
    if (!supports(dst, .create)) return false;
    if (!supports(dst, .write_data)) return false;
    if (!supports(dst, .rename)) return false;
    return supports(dst, .statfs);
}

test "fs_source_policy: write resolution respects readonly metadata" {
    try std.testing.expect(allowsWritePathResolution(.{ .read_only = null }, false));
    try std.testing.expect(allowsWritePathResolution(.{ .read_only = false }, true));
    try std.testing.expect(!allowsWritePathResolution(.{ .read_only = true }, true));
}

test "fs_source_policy: cache normalization follows case sensitivity" {
    const allocator = std.testing.allocator;
    const strict = try normalizeNameForCache(allocator, .{ .case_sensitive = true }, "ReadMe.TXT");
    defer allocator.free(strict);
    try std.testing.expectEqualStrings("ReadMe.TXT", strict);

    const folded = try normalizeNameForCache(allocator, .{ .case_sensitive = false }, "ReadMe.TXT");
    defer allocator.free(folded);
    try std.testing.expectEqualStrings("readme.txt", folded);

    const windows_default = try normalizeNameForCache(allocator, .{ .source_kind = "windows" }, "ReadMe.TXT");
    defer allocator.free(windows_default);
    try std.testing.expectEqualStrings("readme.txt", windows_default);
}

test "fs_source_policy: case-only rename noop on case-insensitive sources" {
    try std.testing.expect(!isCaseOnlyRenameNoop(.{ .case_sensitive = true }, true, "README.md", "readme.md"));
    try std.testing.expect(!isCaseOnlyRenameNoop(.{ .case_sensitive = false }, false, "README.md", "readme.md"));
    try std.testing.expect(isCaseOnlyRenameNoop(.{ .case_sensitive = false }, true, "README.md", "readme.md"));
}

test "fs_source_policy: cross-endpoint copy fallback requires writable endpoints" {
    try std.testing.expect(allowsCrossEndpointCopyFallback(.{ .read_only = false }, .{ .read_only = false }));
    try std.testing.expect(!allowsCrossEndpointCopyFallback(.{ .read_only = true }, .{ .read_only = false }));
    try std.testing.expect(!allowsCrossEndpointCopyFallback(.{ .read_only = false }, .{ .read_only = true }));
}

test "fs_source_policy: operation matrix exposes advanced capability gaps" {
    try std.testing.expect(!supports(.{ .source_kind = "gdrive" }, .xattr));
    try std.testing.expect(!supports(.{ .source_kind = "gdrive" }, .locks));
    try std.testing.expect(supports(.{ .source_kind = "linux" }, .xattr));
    try std.testing.expect(supports(.{ .source_kind = "posix" }, .symlink));
}
