const std = @import("std");
const Config = @import("config.zig");
const credential_store = @import("credential_store.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "config")) {
        try handleConfigCommand(allocator, args[2..]);
    } else {
        std.log.err("Unknown command: {s}", .{command});
        try printUsage();
        return error.UnknownCommand;
    }
}

fn handleConfigCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        // Show current config
        var config = try Config.init(allocator, null);
        defer config.deinit();
        const store = credential_store.CredentialStore.init(allocator);

        var key_source: []const u8 = "env";
        if (store.getProviderApiKey(config.provider.name)) |key| {
            allocator.free(key);
            key_source = "secure-store";
        } else if (config.provider.api_key != null) {
            key_source = "legacy-config";
        }

        const stdout_file = std.fs.File.stdout();
        var buf: [1024]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Config: {s}\n  Bind: {s}:{d}\n  Provider: {s}/{s}\n  API Key Source: {s}\n  Secure Backend: {s}\n  Log: {s}\n", .{
            config.config_path,
            config.server.bind,
            config.server.port,
            config.provider.name,
            config.provider.model orelse "(default)",
            key_source,
            store.backendName(),
            config.log.level,
        });
        try stdout_file.writeAll(msg);
        return;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "set-provider")) {
        if (args.len < 2) {
            std.log.err("Usage: config set-provider <name> [model]", .{});
            return error.InvalidArguments;
        }

        var config = try Config.init(allocator, null);
        defer config.deinit();

        const provider = args[1];
        const model = if (args.len >= 3) args[2] else null;

        try config.setProvider(provider, model);
        std.log.info("Set provider to {s} (model: {s})", .{ provider, model orelse "default" });
    } else if (std.mem.eql(u8, subcommand, "set-server")) {
        if (args.len < 3) {
            std.log.err("Usage: config set-server --bind <addr> --port <port>", .{});
            return error.InvalidArguments;
        }

        var config = try Config.init(allocator, null);
        defer config.deinit();

        var bind: ?[]const u8 = null;
        var port: ?u16 = null;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--bind")) {
                i += 1;
                if (i < args.len) bind = args[i];
            } else if (std.mem.eql(u8, args[i], "--port")) {
                i += 1;
                if (i < args.len) port = try std.fmt.parseInt(u16, args[i], 10);
            }
        }

        try config.setServer(bind, port);
        std.log.info("Updated server config", .{});
    } else if (std.mem.eql(u8, subcommand, "set-key")) {
        if (args.len < 2) {
            std.log.err("Usage: config set-key <api-key> [provider]", .{});
            return error.InvalidArguments;
        }

        var config = try Config.init(allocator, null);
        defer config.deinit();
        const provider_name = if (args.len >= 3) args[2] else config.provider.name;

        const store = credential_store.CredentialStore.init(allocator);
        if (!store.supportsSecureStorage()) {
            std.log.err("No secure credential backend available (expected `secret-tool` on Linux)", .{});
            std.log.info("Use provider-specific environment variables until secure storage is available.", .{});
            return error.SecureStoreUnavailable;
        }

        try store.setProviderApiKey(provider_name, args[1]);

        // Purge legacy plaintext key from config if present.
        if (config.provider.api_key) |legacy| {
            allocator.free(legacy);
            config.provider.api_key = null;
            try config.save();
        }

        std.log.info("API key stored in secure backend '{s}' for provider '{s}'", .{ store.backendName(), provider_name });
    } else if (std.mem.eql(u8, subcommand, "clear-key")) {
        var config = try Config.init(allocator, null);
        defer config.deinit();
        const provider_name = if (args.len >= 2) args[1] else config.provider.name;

        const store = credential_store.CredentialStore.init(allocator);
        if (!store.supportsSecureStorage()) {
            std.log.err("No secure credential backend available (expected `secret-tool` on Linux)", .{});
            return error.SecureStoreUnavailable;
        }

        try store.clearProviderApiKey(provider_name);
        std.log.info("Cleared secure API key for provider '{s}'", .{provider_name});
    } else if (std.mem.eql(u8, subcommand, "set-log")) {
        if (args.len < 2) {
            std.log.err("Usage: config set-log <level>", .{});
            return error.InvalidArguments;
        }

        var config = try Config.init(allocator, null);
        defer config.deinit();

        try config.setLogLevel(args[1]);
        std.log.info("Set log level to {s}", .{args[1]});
    } else if (std.mem.eql(u8, subcommand, "path")) {
        var config = try Config.init(allocator, null);
        defer config.deinit();

        const stdout_file = std.fs.File.stdout();
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{s}\n", .{config.config_path});
        try stdout_file.writeAll(msg);
    } else {
        std.log.err("Unknown config command: {s}", .{subcommand});
        std.log.info("Available: set-provider, set-server, set-key, clear-key, set-log, path", .{});
        return error.UnknownCommand;
    }
}

fn printUsage() !void {
    const usage =
        \\ZiggySpiderweb Configuration Tool
        \\
        \\Usage:
        \\  spiderweb-config config              Show current config
        \\  spiderweb-config config path         Show config file path
        \\  spiderweb-config config set-provider <name> [model]
        \\  spiderweb-config config set-server --bind <addr> --port <port>
        \\  spiderweb-config config set-key <api-key> [provider]
        \\  spiderweb-config config clear-key [provider]
        \\  spiderweb-config config set-log <debug|info|warn|error>
        \\
        \\Examples:
        \\  spiderweb-config config set-provider openai gpt-4o
        \\  spiderweb-config config set-provider kimi-coding kimi-k2.5
        \\  spiderweb-config config set-server --bind 0.0.0.0 --port 9000
        \\  spiderweb-config config set-key sk-... openai
        \\  spiderweb-config config clear-key openai
        \\
    ;
    const stdout_file = std.fs.File.stdout();
    try stdout_file.writeAll(usage);
}
