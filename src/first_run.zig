const std = @import("std");
const Config = @import("config.zig");
const credential_store = @import("credential_store.zig");
const ziggy_piai = @import("ziggy-piai");

fn print(comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try std.fs.File.stdout().writeAll(msg);
}

fn println(comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt ++ "\n", args);
    try std.fs.File.stdout().writeAll(msg);
}

pub fn runFirstRun(allocator: std.mem.Allocator, args: []const []const u8) !void {
    // Check for non-interactive mode
    var non_interactive = false;
    var provider_param: ?[]const u8 = null;
    var model_param: ?[]const u8 = null;
    var agent_name_param: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--non-interactive")) {
            non_interactive = true;
        } else if (std.mem.eql(u8, args[i], "--provider")) {
            i += 1;
            if (i < args.len) provider_param = args[i];
        } else if (std.mem.eql(u8, args[i], "--model")) {
            i += 1;
            if (i < args.len) model_param = args[i];
        } else if (std.mem.eql(u8, args[i], "--agent")) {
            i += 1;
            if (i < args.len) agent_name_param = args[i];
        }
    }

    // Print banner
    try std.fs.File.stdout().writeAll("\n");
    try std.fs.File.stdout().writeAll("╔═══════════════════════════════════════════════════════════════╗\n");
    try std.fs.File.stdout().writeAll("║                                                               ║\n");
    try std.fs.File.stdout().writeAll("║   ZiggySpiderweb - First Time Setup                           ║\n");
    try std.fs.File.stdout().writeAll("║                                                               ║\n");
    try std.fs.File.stdout().writeAll("╚═══════════════════════════════════════════════════════════════╝\n");
    try std.fs.File.stdout().writeAll("\n");

    // Step 1: Provider selection
    const provider_name, const model_name = if (non_interactive) blk: {
        const p = provider_param orelse {
            std.log.err("--provider required in non-interactive mode", .{});
            return error.InvalidArguments;
        };
        break :blk .{ p, model_param };
    } else blk: {
        break :blk try selectProviderInteractive(allocator);
    };

    // Step 2: Configure credentials
    try configureCredentials(allocator, provider_name, non_interactive);

    // Step 3: Create first agent
    const chosen_agent_name = if (non_interactive)
        agent_name_param orelse "ziggy"
    else
        try createAgentInteractive(agent_name_param);
    const agent_name = try normalizeAgentId(allocator, chosen_agent_name);
    defer allocator.free(agent_name);

    // Step 4: Save configuration
    {
        var config = try Config.init(allocator, null);
        defer config.deinit();
        try config.setProvider(provider_name, model_name);
        try config.setDefaultAgentId(agent_name);
        std.log.info("Configuration saved", .{});
    }

    // Step 5: Summary
    try std.fs.File.stdout().writeAll("\n");
    try std.fs.File.stdout().writeAll("╔═══════════════════════════════════════════════════════════════╗\n");
    try std.fs.File.stdout().writeAll("║  Setup Complete!                                              ║\n");
    try std.fs.File.stdout().writeAll("╚═══════════════════════════════════════════════════════════════╝\n");
    try println("\n  Provider: {s}/{s}", .{ provider_name, model_name orelse "default" });
    try println("  Agent: {s}", .{agent_name});
    try std.fs.File.stdout().writeAll("  Config: ~/.config/spiderweb/config.json\n");
    try std.fs.File.stdout().writeAll("\nNext steps:\n");
    try std.fs.File.stdout().writeAll("  Start server:    spiderweb\n");
    try print("  Connect client:  zss connect --url ws://127.0.0.1:18790/v1/agents/{s}/stream\n", .{agent_name});
    try std.fs.File.stdout().writeAll("\nInstall systemd service:\n");
    try std.fs.File.stdout().writeAll("  spiderweb-config config install-service\n");

    if (!non_interactive) {
        // Check if spiderweb is already running (via systemd or manual)
        const is_running = blk: {
            // Try to check if process exists (exact match)
            const result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &.{ "pgrep", "-x", "spiderweb" },
            }) catch break :blk false;
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);
            break :blk result.term == .Exited and result.term.Exited == 0;
        };

        if (!is_running) {
            try std.fs.File.stdout().writeAll("\nStart the server now? [Y/n]: ");
            var buf: [8]u8 = undefined;
            const n = try std.fs.File.stdin().read(buf[0..]);
            if (n == 0 or (buf[0] != 'n' and buf[0] != 'N')) {
                try std.fs.File.stdout().writeAll("\nStarting ZiggySpiderweb...\n");

                // Check if systemd user service exists
                const systemd_user_exists = blk: {
                    const home = std.process.getEnvVarOwned(allocator, "HOME") catch break :blk false;
                    defer allocator.free(home);
                    const path = std.fs.path.join(allocator, &.{ home, ".config/systemd/user/spiderweb.service" }) catch break :blk false;
                    defer allocator.free(path);
                    std.fs.accessAbsolute(path, .{}) catch break :blk false;
                    break :blk true;
                };

                // Check if systemd system service exists
                const systemd_system_exists = blk: {
                    std.fs.accessAbsolute("/etc/systemd/system/spiderweb.service", .{}) catch break :blk false;
                    break :blk true;
                };

                if (systemd_user_exists) {
                    // Use systemd user service
                    var child = std.process.Child.init(&.{ "systemctl", "--user", "start", "spiderweb" }, allocator);
                    _ = child.spawn() catch {};
                } else if (systemd_system_exists) {
                    // Use systemd system service
                    var child = std.process.Child.init(&.{ "sudo", "systemctl", "start", "spiderweb" }, allocator);
                    _ = child.spawn() catch {};
                } else {
                    // Start directly
                    var child = std.process.Child.init(&.{"spiderweb"}, allocator);
                    child.stdin_behavior = .Ignore;
                    child.stdout_behavior = .Ignore;
                    child.stderr_behavior = .Ignore;
                    _ = child.spawn() catch {};
                }
                std.Thread.sleep(1 * std.time.ns_per_s);
            }
        } else {
            try std.fs.File.stdout().writeAll("\nSpiderweb is already running.\n");
        }
    }
}

fn selectProviderInteractive(allocator: std.mem.Allocator) !struct { []const u8, ?[]const u8 } {
    try std.fs.File.stdout().writeAll("\nSelect your AI provider:\n\n");
    try std.fs.File.stdout().writeAll("Quick setup:\n");
    try std.fs.File.stdout().writeAll("  1) OpenAI        - GPT-4o, GPT-4.1\n");
    try std.fs.File.stdout().writeAll("  2) OpenAI Codex  - GPT-5.1, GPT-5.2, GPT-5.3 (with OAuth support)\n");
    try std.fs.File.stdout().writeAll("  3) Kimi Coding   - Kimi K2, K2.5 (Moonshot AI)\n");
    try std.fs.File.stdout().writeAll("\n  4) Manual setup  - Other providers\n");

    while (true) {
        try std.fs.File.stdout().writeAll("\nSelect [1-4]: ");
        var buf: [16]u8 = undefined;
        const n = try std.fs.File.stdin().read(buf[0..]);
        if (n == 0) {
            // EOF - probably piped without input, use default
            return .{ "openai", "gpt-4o-mini" };
        }

        const choice = std.mem.trim(u8, buf[0..n], " \r\n");

        if (std.mem.eql(u8, choice, "1")) {
            return .{ "openai", try selectModel(&.{ "gpt-4o-mini", "gpt-4.1-mini" }) };
        } else if (std.mem.eql(u8, choice, "2")) {
            return .{ "openai-codex", try selectModel(&.{ "gpt-5.1-codex-mini", "gpt-5.1", "gpt-5.3-codex", "gpt-5.3-codex-spark" }) };
        } else if (std.mem.eql(u8, choice, "3")) {
            return .{ "kimi-coding", try selectModel(&.{ "k2p5", "kimi-k2.5" }) };
        } else if (std.mem.eql(u8, choice, "4")) {
            try std.fs.File.stdout().writeAll("\nAvailable providers: openai, openai-codex, openai-codex-spark, kimi-coding\n");
            try std.fs.File.stdout().writeAll("Enter provider name: ");
            var name_buf: [64]u8 = undefined;
            const name_n = try std.fs.File.stdin().read(name_buf[0..]);
            if (name_n == 0) continue;

            try std.fs.File.stdout().writeAll("Enter model name: ");
            var model_buf: [64]u8 = undefined;
            const model_n = try std.fs.File.stdin().read(model_buf[0..]);

            return .{
                try allocator.dupe(u8, std.mem.trim(u8, name_buf[0..name_n], " \r\n")),
                if (model_n > 0) try allocator.dupe(u8, std.mem.trim(u8, model_buf[0..model_n], " \r\n")) else null,
            };
        }
    }
}

fn selectModel(models: []const []const u8) !?[]const u8 {
    try std.fs.File.stdout().writeAll("\nAvailable models:\n");
    for (models, 1..) |model, idx| {
        try print("  {d}) {s}\n", .{ idx, model });
    }
    try print("\nSelect [1-{d}]: ", .{models.len});

    var buf: [16]u8 = undefined;
    const n = try std.fs.File.stdin().read(buf[0..]);
    if (n == 0) return models[0];

    const choice = std.fmt.parseInt(usize, std.mem.trim(u8, buf[0..n], " \r\n"), 10) catch return models[0];
    if (choice < 1 or choice > models.len) return models[0];

    return models[choice - 1];
}

fn configureCredentials(allocator: std.mem.Allocator, provider_name: []const u8, non_interactive: bool) !void {
    _ = non_interactive;

    // Check for Codex OAuth
    if (std.mem.startsWith(u8, provider_name, "openai-codex")) {
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
        defer allocator.free(home);

        const codex_auth_path = try std.fs.path.join(allocator, &.{ home, ".codex", "auth.json" });
        defer allocator.free(codex_auth_path);

        if (std.fs.accessAbsolute(codex_auth_path, .{})) {
            try std.fs.File.stdout().writeAll("\nFound ~/.codex/auth.json - OAuth available\n");
            try std.fs.File.stdout().writeAll("Use Codex OAuth authentication? [Y/n]: ");

            var buf: [8]u8 = undefined;
            const n = try std.fs.File.stdin().read(buf[0..]);
            if (n == 0 or (buf[0] != 'n' and buf[0] != 'N')) {
                try std.fs.File.stdout().writeAll("Using Codex OAuth\n");
                return;
            }
        } else |_| {
            // No auth.json found
        }
    }

    // Check for environment variable
    if (ziggy_piai.env_api_keys.getEnvApiKey(allocator, provider_name)) |key| {
        defer allocator.free(key);
        try print("\nFound API key in environment for {s}\n", .{provider_name});
        return;
    }

    // Check secure store
    const store = credential_store.CredentialStore.init(allocator);
    if (store.getProviderApiKey(provider_name)) |key| {
        defer allocator.free(key);
        try print("\nFound API key in secure storage for {s}\n", .{provider_name});
        return;
    }

    // Prompt for API key
    try std.fs.File.stdout().writeAll("\nAPI Key Setup\n");
    try std.fs.File.stdout().writeAll("Your API key will be stored securely using secret-tool.\n\n");
    try std.fs.File.stdout().writeAll("Enter API key: ");

    var key_buf: [256]u8 = undefined;
    const key_n = try std.fs.File.stdin().read(key_buf[0..]);
    if (key_n == 0) return;
    const key = std.mem.trim(u8, key_buf[0..key_n], " \r\n");

    if (!store.supportsSecureStorage()) {
        try std.fs.File.stdout().writeAll("\nWarning: No secure credential backend available.\n");
        try std.fs.File.stdout().writeAll("Set the API key via environment variable instead.\n");
        return;
    }

    try store.setProviderApiKey(provider_name, key);
    try std.fs.File.stdout().writeAll("API key stored securely\n");
}

fn createAgentInteractive(default_name: ?[]const u8) ![]const u8 {
    try std.fs.File.stdout().writeAll("\n");
    try std.fs.File.stdout().writeAll("Name your first agent:\n");
    try print("  [default: {s}]: ", .{default_name orelse "ziggy"});

    var buf: [64]u8 = undefined;
    const n = try std.fs.File.stdin().read(buf[0..]);

    if (n == 0) {
        return default_name orelse "ziggy";
    }

    return std.mem.trim(u8, buf[0..n], " \r\n");
}

fn normalizeAgentId(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return allocator.dupe(u8, "ziggy");

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var last_dash = false;
    for (trimmed) |ch| {
        const lower = std.ascii.toLower(ch);
        if (std.ascii.isAlphanumeric(lower) or lower == '_' or lower == '-' or lower == '.') {
            try out.append(allocator, lower);
            last_dash = false;
            continue;
        }

        if (!last_dash) {
            try out.append(allocator, '-');
            last_dash = true;
        }
    }

    while (out.items.len > 0 and out.items[0] == '-') {
        _ = out.orderedRemove(0);
    }
    while (out.items.len > 0 and out.items[out.items.len - 1] == '-') {
        _ = out.pop();
    }

    if (out.items.len == 0) {
        out.deinit(allocator);
        return allocator.dupe(u8, "ziggy");
    }

    return out.toOwnedSlice(allocator);
}
