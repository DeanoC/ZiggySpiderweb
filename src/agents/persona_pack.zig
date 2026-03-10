const std = @import("std");

pub const default_pack_id = "default";
pub const packs_dir_name = "persona-packs";
pub const manifest_filename = "pack.json";

pub fn isValidPackId(pack_id: []const u8) bool {
    if (pack_id.len == 0 or pack_id.len > 128) return false;
    for (pack_id) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '_' or char == '-') continue;
        return false;
    }
    return true;
}

pub fn resolvePackDir(
    allocator: std.mem.Allocator,
    assets_dir: []const u8,
    pack_id: []const u8,
) ![]u8 {
    if (!isValidPackId(pack_id)) return error.InvalidPersonaPackId;
    return std.fs.path.join(allocator, &.{ assets_dir, packs_dir_name, pack_id });
}

pub fn resolvePackFile(
    allocator: std.mem.Allocator,
    assets_dir: []const u8,
    pack_id: []const u8,
    filename: []const u8,
) ![]u8 {
    const pack_dir = try resolvePackDir(allocator, assets_dir, pack_id);
    defer allocator.free(pack_dir);
    return std.fs.path.join(allocator, &.{ pack_dir, filename });
}

pub fn ensurePackExists(
    allocator: std.mem.Allocator,
    assets_dir: []const u8,
    pack_id: []const u8,
) !void {
    const manifest_path = try resolvePackFile(allocator, assets_dir, pack_id, manifest_filename);
    defer allocator.free(manifest_path);
    try std.fs.cwd().access(manifest_path, .{});
}

pub fn readOptionalPackFile(
    allocator: std.mem.Allocator,
    assets_dir: []const u8,
    pack_id: []const u8,
    filename: []const u8,
    max_bytes: usize,
) !?[]u8 {
    const pack_file = try resolvePackFile(allocator, assets_dir, pack_id, filename);
    defer allocator.free(pack_file);
    return std.fs.cwd().readFileAlloc(allocator, pack_file, max_bytes) catch |err| switch (err) {
        error.FileNotFound => null,
        else => err,
    };
}
