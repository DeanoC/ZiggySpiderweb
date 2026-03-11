const std = @import("std");
const Config = @import("config.zig");

fn println(comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt ++ "\n", args);
    try std.fs.File.stdout().writeAll(msg);
}

pub fn runFirstRun(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var non_interactive = false;
    var saw_legacy_provider_flag = false;
    var saw_legacy_model_flag = false;
    var saw_legacy_agent_flag = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--non-interactive")) {
            non_interactive = true;
        } else if (std.mem.eql(u8, args[i], "--provider")) {
            saw_legacy_provider_flag = true;
            if (i + 1 < args.len) i += 1;
        } else if (std.mem.eql(u8, args[i], "--model")) {
            saw_legacy_model_flag = true;
            if (i + 1 < args.len) i += 1;
        } else if (std.mem.eql(u8, args[i], "--agent")) {
            saw_legacy_agent_flag = true;
            if (i + 1 < args.len) i += 1;
        } else {
            std.log.err("Unknown first-run option: {s}", .{args[i]});
            return error.InvalidArguments;
        }
    }

    try std.fs.File.stdout().writeAll("\n");
    try std.fs.File.stdout().writeAll("╔═══════════════════════════════════════════════════════════════╗\n");
    try std.fs.File.stdout().writeAll("║                                                               ║\n");
    try std.fs.File.stdout().writeAll("║   Spiderweb - Workspace Setup                                 ║\n");
    try std.fs.File.stdout().writeAll("║                                                               ║\n");
    try std.fs.File.stdout().writeAll("╚═══════════════════════════════════════════════════════════════╝\n");
    try std.fs.File.stdout().writeAll("\n");

    var config = try Config.init(allocator, null);
    defer config.deinit();

    if (saw_legacy_provider_flag or saw_legacy_model_flag or saw_legacy_agent_flag) {
        try std.fs.File.stdout().writeAll(
            "Legacy provider/agent setup flags were ignored. Spiderweb now expects external workers such as Spider Monkey to own model and credential configuration.\n\n",
        );
    }

    try std.fs.File.stdout().writeAll("Spiderweb is configured as a workspace host and mounted-filesystem control plane.\n");
    try std.fs.File.stdout().writeAll("Provider selection, OAuth, and API-key setup belong in the external worker repo.\n");
    try std.fs.File.stdout().writeAll("If runtime.spider_web_root is empty, Spiderweb uses its current working directory as the default local workspace root.\n");

    if (!non_interactive) {
        try std.fs.File.stdout().writeAll("\n");
    }

    try std.fs.File.stdout().writeAll("╔═══════════════════════════════════════════════════════════════╗\n");
    try std.fs.File.stdout().writeAll("║  Setup Complete!                                              ║\n");
    try std.fs.File.stdout().writeAll("╚═══════════════════════════════════════════════════════════════╝\n");
    try println("\n  Config: {s}", .{config.config_path});
    try println("  Server: ws://{s}:{d}", .{ config.server.bind, config.server.port });
    try std.fs.File.stdout().writeAll("  Worker model: external filesystem agents\n");
    try std.fs.File.stdout().writeAll("\nManual v1 flow:\n");
    try std.fs.File.stdout().writeAll("  1. Start Spiderweb: spiderweb\n");
    try std.fs.File.stdout().writeAll("  2. Create a workspace: spiderweb-control workspace_create '{\"name\":\"Demo\",\"vision\":\"Mounted workspace\"}'\n");
    try std.fs.File.stdout().writeAll("  3. Mount it locally: spiderweb-fs-mount --url ws://127.0.0.1:18790/ --workspace-id <workspace-id> <mountpoint>\n");
    try std.fs.File.stdout().writeAll("  4. Start Spider Monkey: spider-monkey run --workspace-root <mountpoint>\n");
    try std.fs.File.stdout().writeAll("\nUseful commands:\n");
    try std.fs.File.stdout().writeAll("  spiderweb-config auth status\n");
    try std.fs.File.stdout().writeAll("  spiderweb-config config set-server --bind 0.0.0.0 --port 18790\n");
    try std.fs.File.stdout().writeAll("  spiderweb-control workspace_list\n");
    try std.fs.File.stdout().writeAll("\nInstall systemd service:\n");
    try std.fs.File.stdout().writeAll("  spiderweb-config config install-service\n");
}
