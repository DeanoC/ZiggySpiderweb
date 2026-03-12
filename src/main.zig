const std = @import("std");

const server = @import("server_piai.zig");
const Config = @import("config.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var requested_help = false;
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            requested_help = true;
            break;
        }
    }

    if (requested_help) {
        const help =
            "Spiderweb v0.3.0 - Workspace Host for OpenClaw Protocol\n" ++
            "\n" ++
            "A WebSocket host that exposes Spiderweb workspaces, nodes, venoms, and the virtual filesystem.\n" ++
            "\n" ++
            "Usage: spiderweb [options]\n" ++
            "\n" ++
            "Options:\n" ++
            "  --bind <addr>    Bind address (default: from config or 127.0.0.1)\n" ++
            "  --port <port>    Port number (default: from config or 18790)\n" ++
            "  --help, -h       Show this help\n" ++
            "\n" ++
            "Workspace-first flow:\n" ++
            "  spiderweb-config first-run\n" ++
            "  spiderweb-control workspace_create '{\"name\":\"Demo\",\"vision\":\"Deliver the demo workspace\"}'\n" ++
            "  spiderweb-fs-mount --workspace-url ws://127.0.0.1:18790/ --workspace-id <workspace-id> mount ./workspace\n" ++
            "  spider-monkey run --workspace-root ./workspace\n" ++
            "\n";
        std.debug.print("{s}", .{help});
        return;
    }

    // Load config
    var config = Config.init(allocator, null) catch |err| {
        std.log.err("Failed to load config: {s}", .{@errorName(err)});
        return err;
    };
    defer config.deinit();

    if (std.mem.trim(u8, config.runtime.spider_web_root, " \t\r\n").len == 0) {
        const cwd = try std.process.getCwdAlloc(allocator);
        config.allocator.free(config.runtime.spider_web_root);
        config.runtime.spider_web_root = cwd;
    }
    try config.normalizeRuntimePathsFromSpiderWebRoot();

    std.log.info("Starting Spiderweb v0.3.0 (Workspace Host)", .{});
    std.log.info("Config: {s}", .{config.config_path});
    std.log.info("Workspace mount binary: {s}", .{config.runtime.sandbox_fs_mount_bin});

    // Override with CLI args if provided
    var port = config.server.port;
    var bind_addr = config.server.bind;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i < args.len) {
                port = try std.fmt.parseInt(u16, args[i], 10);
            }
        } else if (std.mem.eql(u8, arg, "--bind")) {
            i += 1;
            if (i < args.len) {
                bind_addr = args[i];
            }
        }
    }

    std.log.info("Binding to {s}:{d}", .{ bind_addr, port });

    if (config.runtime.ltm_directory.len == 0 or config.runtime.ltm_filename.len == 0) {
        std.log.err("Invalid runtime config: LTM store is required (`runtime.ltm_directory` and `runtime.ltm_filename` must be set)", .{});
        return error.MissingLtmStoreConfig;
    }

    // Start server
    try server.run(allocator, bind_addr, port, config.runtime);
}
