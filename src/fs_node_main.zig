const std = @import("std");
const fs_node_server = @import("fs_node_server.zig");
const fs_node_ops = @import("fs_node_ops.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var bind_addr: []const u8 = "127.0.0.1";
    var port: u16 = 18891;
    var exports = std.ArrayListUnmanaged(fs_node_ops.ExportSpec){};
    defer exports.deinit(allocator);
    var auth_token: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--bind")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            bind_addr = args[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--export")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            const spec = parseExportFlag(args[i]) catch return error.InvalidArguments;
            try exports.append(allocator, spec);
        } else if (std.mem.eql(u8, arg, "--auth-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            auth_token = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp();
            return;
        } else {
            std.log.err("unknown argument: {s}", .{arg});
            try printHelp();
            return error.InvalidArguments;
        }
    }

    if (auth_token == null) {
        const from_env = std.process.getEnvVarOwned(allocator, "SPIDERWEB_FS_NODE_AUTH_TOKEN") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        if (from_env) |raw| {
            const trimmed = std.mem.trim(u8, raw, " \t\r\n");
            if (trimmed.len > 0) {
                auth_token = try allocator.dupe(u8, trimmed);
            }
            allocator.free(raw);
        }
    }

    std.log.info("Starting spiderweb-fs-node on {s}:{d}", .{ bind_addr, port });
    if (auth_token != null) {
        std.log.info("FS node session auth enabled", .{});
    }
    if (exports.items.len == 0) {
        std.log.info("No exports configured via CLI; using default export name='work' path='.' rw", .{});
    } else {
        for (exports.items) |spec| {
            std.log.info("Export {s} => {s} ({s})", .{ spec.name, spec.path, if (spec.ro) "ro" else "rw" });
        }
    }

    try fs_node_server.run(allocator, bind_addr, port, exports.items, auth_token);
}

fn parseExportFlag(raw: []const u8) !fs_node_ops.ExportSpec {
    const eq_index = std.mem.indexOfScalar(u8, raw, '=') orelse return error.InvalidFormat;
    const name = raw[0..eq_index];
    if (name.len == 0) return error.InvalidFormat;

    const rhs = raw[eq_index + 1 ..];
    if (rhs.len == 0) return error.InvalidFormat;

    var ro = false;
    var path = rhs;
    var gdrive_credential_handle: ?[]const u8 = null;

    while (true) {
        if (std.mem.endsWith(u8, path, ":ro")) {
            ro = true;
            path = path[0 .. path.len - 3];
            continue;
        }
        if (std.mem.endsWith(u8, path, ":rw")) {
            ro = false;
            path = path[0 .. path.len - 3];
            continue;
        }

        const cred_idx = std.mem.lastIndexOf(u8, path, ":cred=") orelse break;
        const handle = path[cred_idx + ":cred=".len ..];
        if (handle.len == 0) return error.InvalidFormat;
        if (std.mem.indexOfScalar(u8, handle, ':') != null) break;
        gdrive_credential_handle = handle;
        path = path[0..cred_idx];
    }

    if (path.len == 0) return error.InvalidFormat;

    return .{
        .name = name,
        .path = path,
        .ro = ro,
        .gdrive_credential_handle = gdrive_credential_handle,
        .desc = null,
    };
}

fn printHelp() !void {
    const help =
        \\spiderweb-fs-node - Distributed filesystem node server
        \\
        \\Usage:
        \\  spiderweb-fs-node [--bind <addr>] [--port <port>] [--export <name>=<path>[:ro|:rw][:cred=<handle>]] [--auth-token <token>]
        \\
        \\Examples:
        \\  spiderweb-fs-node --export work=.:rw
        \\  spiderweb-fs-node --bind 0.0.0.0 --port 18891 --export repo=/home/user/repo:ro
        \\  spiderweb-fs-node --export cloud=drive:root:ro:cred=gdrive.team
        \\  spiderweb-fs-node --auth-token my-node-session-token
        \\  (or set SPIDERWEB_FS_NODE_AUTH_TOKEN in the environment)
        \\
    ;
    try std.fs.File.stdout().writeAll(help);
}
