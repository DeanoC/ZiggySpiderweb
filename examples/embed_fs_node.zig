const std = @import("std");
const fs = @import("spiderweb_fs");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var exports = std.ArrayListUnmanaged(fs.ExportSpec){};
    defer exports.deinit(allocator);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--export")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            try exports.append(allocator, try parseExportFlag(args[i]));
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp();
            return;
        } else {
            std.log.err("unknown argument: {s}", .{arg});
            try printHelp();
            return error.InvalidArguments;
        }
    }

    if (exports.items.len == 0) {
        try exports.append(allocator, .{
            .name = "work",
            .path = ".",
            .ro = false,
            .desc = "embedded workspace export",
        });
    }

    var service = try fs.NodeService.init(allocator, exports.items);
    defer service.deinit();

    try std.fs.File.stdout().writeAll(
        "Embedded FS NodeService ready.\n" ++
            "Send NDJSON on stdin (one JSON request per line), receive one JSON response per line.\n" ++
            "Type 'exit' on a line to stop.\n",
    );

    const input = try std.fs.File.stdin().readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(input);

    var it = std.mem.splitScalar(u8, input, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "exit") or std.mem.eql(u8, line, "quit")) break;

        const response = service.handleRequestJson(line) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "error: {s}\n", .{@errorName(err)});
            defer allocator.free(msg);
            try std.fs.File.stdout().writeAll(msg);
            continue;
        };
        defer allocator.free(response);

        const out = try std.fmt.allocPrint(allocator, "{s}\n", .{response});
        defer allocator.free(out);
        try std.fs.File.stdout().writeAll(out);
    }
}

fn parseExportFlag(raw: []const u8) !fs.ExportSpec {
    const eq_index = std.mem.indexOfScalar(u8, raw, '=') orelse return error.InvalidFormat;
    const name = raw[0..eq_index];
    if (name.len == 0) return error.InvalidFormat;

    const rhs = raw[eq_index + 1 ..];
    if (rhs.len == 0) return error.InvalidFormat;

    var ro = false;
    var path = rhs;
    if (std.mem.endsWith(u8, rhs, ":ro")) {
        ro = true;
        path = rhs[0 .. rhs.len - 3];
    } else if (std.mem.endsWith(u8, rhs, ":rw")) {
        ro = false;
        path = rhs[0 .. rhs.len - 3];
    }
    if (path.len == 0) return error.InvalidFormat;

    return .{
        .name = name,
        .path = path,
        .ro = ro,
        .desc = "embedded export",
    };
}

fn printHelp() !void {
    const help =
        \\embed-fs-node - Example embedding of spiderweb_fs.NodeService
        \\
        \\Usage:
        \\  embed-fs-node [--export <name>=<path>[:ro|:rw]]
        \\
        \\Then send one JSON request per line, e.g.:
        \\  {"t":"req","id":1,"op":"HELLO","a":{}}
        \\  {"t":"req","id":2,"op":"EXPORTS","a":{}}
        \\
    ;
    try std.fs.File.stdout().writeAll(help);
}
