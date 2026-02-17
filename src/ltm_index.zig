const std = @import("std");

pub const LtmIndexVersion = 1;

const INDEX_FILENAME = "archive-index.ndjson";

pub const ArchiveIndexRecord = struct {
    version: u32,
    timestamp_ms: i64,
    session_id: []const u8,
    reason: []const u8,
    archive_path: []const u8,
    next_id: u64,
    entry_count: usize,
    summary_count: usize,
};

pub fn appendArchiveIndex(
    allocator: std.mem.Allocator,
    archive_dir: []const u8,
    record: ArchiveIndexRecord,
) !void {
    var dir = try std.fs.cwd().makeOpenPath(archive_dir, .{});
    defer dir.close();

    const index_path = try std.fs.path.join(allocator, &.{ archive_dir, INDEX_FILENAME });
    defer allocator.free(index_path);

    var file = try std.fs.cwd().createFile(index_path, .{ .truncate = false });
    defer file.close();

    try file.seekFromEnd(0);

    const escaped_session = try jsonEscape(allocator, record.session_id);
    defer allocator.free(escaped_session);
    const escaped_reason = try jsonEscape(allocator, record.reason);
    defer allocator.free(escaped_reason);
    const escaped_path = try jsonEscape(allocator, record.archive_path);
    defer allocator.free(escaped_path);

    const line = try std.fmt.allocPrint(
        allocator,
        "{{\"version\":{d},\"timestamp_ms\":{d},\"session_id\":\"{s}\",\"reason\":\"{s}\",\"archive_path\":\"{s}\",\"next_id\":{d},\"entry_count\":{d},\"summary_count\":{d}}}\n",
        .{
            record.version,
            record.timestamp_ms,
            escaped_session,
            escaped_reason,
            escaped_path,
            record.next_id,
            record.entry_count,
            record.summary_count,
        },
    );
    defer allocator.free(line);

    try file.writeAll(line);
}

fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var output = std.ArrayListUnmanaged(u8){};
    defer output.deinit(allocator);

    for (input) |char| {
        switch (char) {
            '\\' => try output.appendSlice(allocator, "\\\\"),
            '"' => try output.appendSlice(allocator, "\\\""),
            '\n' => try output.appendSlice(allocator, "\\n"),
            '\r' => try output.appendSlice(allocator, "\\r"),
            '\t' => try output.appendSlice(allocator, "\\t"),
            else => try output.append(allocator, char),
        }
    }

    return output.toOwnedSlice(allocator);
}
