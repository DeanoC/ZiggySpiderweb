const std = @import("std");
const fs_router = @import("fs_router.zig");
const fs_fuse_adapter = @import("fs_fuse_adapter.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var endpoint_specs = std.ArrayListUnmanaged(fs_router.EndpointConfig){};
    defer endpoint_specs.deinit(allocator);

    var remaining = std.ArrayListUnmanaged([]const u8){};
    defer remaining.deinit(allocator);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--endpoint")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            try endpoint_specs.append(allocator, try parseEndpointFlag(args[i]));
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printHelp();
            return;
        } else {
            try remaining.append(allocator, args[i]);
        }
    }

    if (endpoint_specs.items.len == 0) {
        try endpoint_specs.append(allocator, .{
            .name = "a",
            .url = "ws://127.0.0.1:18891/v1/fs",
            .export_name = null,
        });
    }
    if (remaining.items.len == 0) {
        try printHelp();
        return error.InvalidArguments;
    }

    var router = try fs_router.Router.init(allocator, endpoint_specs.items);
    defer router.deinit();
    var adapter = fs_fuse_adapter.FuseAdapter.init(allocator, &router);
    defer adapter.deinit();

    const command = remaining.items[0];
    if (std.mem.eql(u8, command, "getattr")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        const attr = try adapter.getattr(remaining.items[1]);
        defer allocator.free(attr);
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{attr});
        defer allocator.free(line);
        try std.fs.File.stdout().writeAll(line);
        return;
    }

    if (std.mem.eql(u8, command, "readdir")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        const cookie = if (remaining.items.len >= 3) try std.fmt.parseInt(u64, remaining.items[2], 10) else 0;
        const max_entries = if (remaining.items.len >= 4) try std.fmt.parseInt(u32, remaining.items[3], 10) else 256;
        const listing = try adapter.readdir(remaining.items[1], cookie, max_entries);
        defer allocator.free(listing);
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{listing});
        defer allocator.free(line);
        try std.fs.File.stdout().writeAll(line);
        return;
    }

    if (std.mem.eql(u8, command, "cat")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        const file = try adapter.open(remaining.items[1], 0);
        defer adapter.release(file) catch {};

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(allocator);
        var offset: u64 = 0;
        const chunk_len: u32 = 256 * 1024;
        while (true) {
            const chunk = try adapter.read(file, offset, chunk_len);
            defer allocator.free(chunk);
            if (chunk.len == 0) break;
            try out.appendSlice(allocator, chunk);
            if (chunk.len < chunk_len) break;
            offset += chunk.len;
        }
        try std.fs.File.stdout().writeAll(out.items);
        return;
    }

    if (std.mem.eql(u8, command, "write")) {
        if (remaining.items.len < 3) return error.InvalidArguments;
        const path = remaining.items[1];
        const content = remaining.items[2];

        const file = adapter.open(path, 2) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            break :blk try adapter.create(path, 0o100644, 2);
        };
        defer adapter.release(file) catch {};

        try adapter.truncate(path, 0);
        _ = try adapter.write(file, 0, content);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "mkdir")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        try adapter.mkdir(remaining.items[1]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "rmdir")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        try adapter.rmdir(remaining.items[1]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "unlink")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        try adapter.unlink(remaining.items[1]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "rename")) {
        if (remaining.items.len < 3) return error.InvalidArguments;
        try adapter.rename(remaining.items[1], remaining.items[2]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "truncate")) {
        if (remaining.items.len < 3) return error.InvalidArguments;
        const size = try std.fmt.parseInt(u64, remaining.items[2], 10);
        try adapter.truncate(remaining.items[1], size);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "status")) {
        if (remaining.items.len > 2) return error.InvalidArguments;
        var force_probe = true;
        if (remaining.items.len == 2) {
            if (std.mem.eql(u8, remaining.items[1], "--no-probe")) {
                force_probe = false;
            } else {
                return error.InvalidArguments;
            }
        }
        const status = try router.statusJson(force_probe);
        defer allocator.free(status);
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{status});
        defer allocator.free(line);
        try std.fs.File.stdout().writeAll(line);
        return;
    }

    if (std.mem.eql(u8, command, "mount")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        try adapter.mount(remaining.items[1]);
        return;
    }

    std.log.err("unknown command: {s}", .{command});
    try printHelp();
    return error.InvalidArguments;
}

fn parseEndpointFlag(raw: []const u8) !fs_router.EndpointConfig {
    const eq_idx = std.mem.indexOfScalar(u8, raw, '=') orelse return error.InvalidEndpointFlag;
    const name = raw[0..eq_idx];
    if (name.len == 0) return error.InvalidEndpointFlag;

    const rhs = raw[eq_idx + 1 ..];
    if (rhs.len == 0) return error.InvalidEndpointFlag;

    if (std.mem.indexOfScalar(u8, rhs, '#')) |hash_idx| {
        const url = rhs[0..hash_idx];
        const export_name = rhs[hash_idx + 1 ..];
        if (url.len == 0 or export_name.len == 0) return error.InvalidEndpointFlag;
        return .{
            .name = name,
            .url = url,
            .export_name = export_name,
        };
    }

    return .{
        .name = name,
        .url = rhs,
        .export_name = null,
    };
}

fn printHelp() !void {
    const help =
        \\spiderweb-fs-mount - Distributed filesystem router client
        \\
        \\Usage:
        \\  spiderweb-fs-mount [--endpoint <name>=<ws-url>[#export]] <command> [args]
        \\
        \\Commands:
        \\  getattr <path>
        \\  readdir <path> [cookie] [max]
        \\  cat <path>
        \\  write <path> <content>
        \\  mkdir <path>
        \\  rmdir <path>
        \\  unlink <path>
        \\  rename <old> <new>
        \\  truncate <path> <size>
        \\  status [--no-probe]
        \\  mount <mountpoint>
        \\
        \\Examples:
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v1/fs#work readdir /a
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v1/fs cat /a/README.md
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v1/fs status
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v1/fs#work --endpoint a=ws://127.0.0.1:18892/v1/fs#work readdir /a
        \\    (repeat the same endpoint name to enable failover)
        \\
    ;
    try std.fs.File.stdout().writeAll(help);
}
