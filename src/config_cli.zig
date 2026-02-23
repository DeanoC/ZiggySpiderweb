const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const credential_store = @import("credential_store.zig");
const ziggy_piai = @import("ziggy-piai");
const first_run = @import("first_run.zig");
const oauth_cli = @import("oauth_cli.zig");

const auth_tokens_filename = "auth_tokens.json";

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
    } else if (std.mem.eql(u8, command, "auth")) {
        try handleAuthCommand(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "first-run")) {
        try first_run.runFirstRun(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "oauth")) {
        try oauth_cli.run(allocator, args[2..]);
    } else {
        std.log.err("Unknown command: {s}", .{command});
        try printUsage();
        return error.UnknownCommand;
    }
}

fn handleAuthCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const subcommand = if (args.len > 0) args[0] else "help";

    if (std.mem.eql(u8, subcommand, "path")) {
        var config = try Config.init(allocator, null);
        defer config.deinit();
        const path = try resolveAuthTokensPath(allocator, config.runtime.ltm_directory, config.config_path);
        defer allocator.free(path);
        const out = try std.fmt.allocPrint(allocator, "{s}\n", .{path});
        defer allocator.free(out);
        try std.fs.File.stdout().writeAll(out);
        return;
    }

    if (std.mem.eql(u8, subcommand, "reset")) {
        var confirmed = false;
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--yes")) {
                confirmed = true;
                continue;
            }
            std.log.err("Unknown auth reset arg: {s}", .{arg});
            return error.InvalidArguments;
        }
        if (!confirmed) {
            std.log.err("Refusing to reset auth tokens without --yes", .{});
            std.log.info("Run: spiderweb-config auth reset --yes", .{});
            return error.InvalidArguments;
        }

        var config = try Config.init(allocator, null);
        defer config.deinit();
        const path = try resolveAuthTokensPath(allocator, config.runtime.ltm_directory, config.config_path);
        defer allocator.free(path);
        const admin_token = try makeOpaqueToken(allocator, "sw-admin");
        defer allocator.free(admin_token);
        const user_token = try makeOpaqueToken(allocator, "sw-user");
        defer allocator.free(user_token);
        try persistAuthTokens(allocator, path, admin_token, user_token);

        std.log.warn("Emergency auth token reset completed.", .{});
        std.log.warn("  path:  {s}", .{path});
        std.log.warn("  admin: {s}", .{admin_token});
        std.log.warn("  user:  {s}", .{user_token});
        std.log.warn("Restart spiderweb to apply new tokens for subsequent connections.", .{});
        return;
    }

    try printAuthUsage();
}

fn handleConfigCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        // Show current config
        var config = try Config.init(allocator, null);
        defer config.deinit();
        const store = credential_store.CredentialStore.init(allocator);

        var key_source: []const u8 = "missing";
        if (store.getProviderApiKey(config.provider.name)) |key| {
            allocator.free(key);
            key_source = "secure-store";
        } else if (ziggy_piai.env_api_keys.getEnvApiKey(allocator, config.provider.name)) |key| {
            allocator.free(key);
            key_source = "environment";
        }

        const stdout_file = std.fs.File.stdout();
        var buf: [1024]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Config: {s}\n  Bind: {s}:{d}\n  Provider: {s}/{s}\n  Default Agent: {s}\n  Spider Web Root: {s}\n  API Key Source: {s}\n  Secure Backend: {s}\n  Log: {s}\n", .{
            config.config_path,
            config.server.bind,
            config.server.port,
            config.provider.name,
            config.provider.model orelse "(default)",
            config.runtime.default_agent_id,
            config.runtime.spider_web_root,
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
            return error.SecureStoreUnavailable;
        }

        try store.setProviderApiKey(provider_name, args[1]);
        // Re-save config to scrub any legacy plaintext provider.api_key fields.
        try config.save();

        std.log.info("API key stored in secure backend '{s}' for provider '{s}' and rewrote config", .{ store.backendName(), provider_name });
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
        // Re-save config to scrub any legacy plaintext provider.api_key fields.
        try config.save();
        std.log.info("Cleared secure API key for provider '{s}' and rewrote config", .{provider_name});
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
    } else if (std.mem.eql(u8, subcommand, "install-service")) {
        try installSystemdService(allocator);
    } else {
        std.log.err("Unknown config command: {s}", .{subcommand});
        std.log.info("Available: set-provider, set-server, set-key, clear-key, set-log, path, install-service", .{});
        return error.UnknownCommand;
    }
}

fn installSystemdService(allocator: std.mem.Allocator) !void {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        std.log.err("Could not get HOME directory", .{});
        return error.MissingHome;
    };
    defer allocator.free(home);

    const repo_dir = try std.fs.path.join(allocator, &.{ home, ".local", "share", "ziggy-spiderweb" });
    defer allocator.free(repo_dir);

    const working_dir = blk: {
        std.fs.accessAbsolute(repo_dir, .{}) catch break :blk home;
        break :blk repo_dir;
    };

    const service_dir = try std.fs.path.join(allocator, &.{ home, ".config", "systemd", "user" });
    defer allocator.free(service_dir);

    try std.fs.cwd().makePath(service_dir);

    const service_path = try std.fs.path.join(allocator, &.{ service_dir, "spiderweb.service" });
    defer allocator.free(service_path);

    const service_content =
        \\[Unit]
        \\Description=ZiggySpiderweb AI Agent Gateway
        \\After=network.target
        \\
        \\[Service]
        \\Type=simple
        \\ExecStart={s}/.local/bin/spiderweb
        \\WorkingDirectory={s}
        \\Restart=on-failure
        \\RestartSec=5
        \\
        \\[Install]
        \\WantedBy=default.target
        \\
    ;

    var buf: [1024]u8 = undefined;
    const content = try std.fmt.bufPrint(&buf, service_content, .{ home, working_dir });

    const file = try std.fs.cwd().createFile(service_path, .{});
    defer file.close();
    try file.writeAll(content);

    std.log.info("Systemd service installed to {s}", .{service_path});
    std.log.info("Enable with: systemctl --user enable --now spiderweb", .{});
}

fn resolveAuthTokensPath(
    allocator: std.mem.Allocator,
    ltm_directory: []const u8,
    config_path: []const u8,
) ![]u8 {
    const storage_dir = try resolveRuntimeStorageDirectory(allocator, ltm_directory, config_path);
    defer allocator.free(storage_dir);
    try std.fs.cwd().makePath(storage_dir);
    return std.fs.path.join(allocator, &.{ storage_dir, auth_tokens_filename });
}

fn resolveRuntimeStorageDirectory(
    allocator: std.mem.Allocator,
    ltm_directory: []const u8,
    config_path: []const u8,
) ![]u8 {
    const runtime_base = try resolveRuntimeBaseDirectory(allocator, config_path);
    defer allocator.free(runtime_base);
    return resolveRuntimeStorageDirectoryWithBase(allocator, ltm_directory, runtime_base);
}

fn resolveRuntimeStorageDirectoryWithBase(
    allocator: std.mem.Allocator,
    ltm_directory: []const u8,
    runtime_base: []const u8,
) ![]u8 {
    const base_dir = std.mem.trim(u8, ltm_directory, " \t\r\n");
    if (std.fs.path.isAbsolute(base_dir)) return allocator.dupe(u8, base_dir);
    if (base_dir.len == 0) return allocator.dupe(u8, runtime_base);
    return std.fs.path.join(allocator, &.{ runtime_base, base_dir });
}

fn resolveRuntimeBaseDirectory(allocator: std.mem.Allocator, config_path: []const u8) ![]u8 {
    if (try detectServiceWorkingDirectory(allocator)) |service_dir| return service_dir;
    return resolveConfigDirectory(allocator, config_path);
}

fn detectServiceWorkingDirectory(allocator: std.mem.Allocator) !?[]u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch null;
    if (home) |home_dir| {
        defer allocator.free(home_dir);
        const user_service_path = try std.fs.path.join(allocator, &.{ home_dir, ".config", "systemd", "user", "spiderweb.service" });
        defer allocator.free(user_service_path);
        if (try parseServiceWorkingDirectory(allocator, user_service_path)) |dir| return dir;
    }

    if (try parseServiceWorkingDirectory(allocator, "/etc/systemd/system/spiderweb.service")) |dir| return dir;
    return null;
}

fn parseServiceWorkingDirectory(allocator: std.mem.Allocator, service_path: []const u8) !?[]u8 {
    const contents = readFileAllocAny(allocator, service_path, 128 * 1024) catch |err| switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        => return null,
        else => return err,
    };
    defer allocator.free(contents);

    var lines = std.mem.tokenizeAny(u8, contents, "\r\n");
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t");
        if (line.len == 0) continue;
        if (line[0] == '#' or line[0] == ';') continue;
        if (!std.mem.startsWith(u8, line, "WorkingDirectory=")) continue;

        const value = std.mem.trim(u8, line["WorkingDirectory=".len..], " \t\"");
        if (value.len == 0) continue;
        if (std.fs.path.isAbsolute(value)) return try allocator.dupe(u8, value);
        const service_dir = std.fs.path.dirname(service_path) orelse ".";
        return try std.fs.path.join(allocator, &.{ service_dir, value });
    }
    return null;
}

fn readFileAllocAny(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
        defer file.close();
        return file.readToEndAlloc(allocator, max_bytes);
    }
    return std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
}

fn resolveConfigDirectory(allocator: std.mem.Allocator, config_path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(config_path)) {
        const dir = std.fs.path.dirname(config_path) orelse "/";
        return allocator.dupe(u8, dir);
    }
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    const absolute_config_path = try std.fs.path.join(allocator, &.{ cwd, config_path });
    defer allocator.free(absolute_config_path);
    const dir = std.fs.path.dirname(absolute_config_path) orelse cwd;
    return allocator.dupe(u8, dir);
}

fn makeOpaqueToken(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    var random_bytes: [24]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var encoded_buf: [std.base64.url_safe_no_pad.Encoder.calcSize(random_bytes.len)]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buf, &random_bytes);
    return std.fmt.allocPrint(allocator, "{s}_{s}", .{ prefix, encoded });
}

fn persistAuthTokens(
    allocator: std.mem.Allocator,
    path: []const u8,
    admin_token: []const u8,
    user_token: []const u8,
) !void {
    const Persisted = struct {
        schema: u32 = 1,
        admin_token: []const u8,
        user_token: []const u8,
        updated_at_ms: i64,
    };

    const payload = Persisted{
        .schema = 1,
        .admin_token = admin_token,
        .user_token = user_token,
        .updated_at_ms = std.time.milliTimestamp(),
    };
    const bytes = try std.json.Stringify.valueAlloc(allocator, payload, .{
        .emit_null_optional_fields = false,
        .whitespace = .indent_2,
    });
    defer allocator.free(bytes);

    var file = try std.fs.cwd().createFile(path, .{
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();
    if (builtin.os.tag != .windows) {
        try file.chmod(0o600);
    }
    try file.writeAll(bytes);
}

fn printAuthUsage() !void {
    const usage =
        \\Auth token recovery commands:
        \\  spiderweb-config auth path
        \\  spiderweb-config auth reset --yes
        \\
        \\`auth reset --yes` regenerates BOTH admin and user tokens in auth_tokens.json.
        \\Use only for emergency recovery (for example lost admin token).
        \\
    ;
    try std.fs.File.stdout().writeAll(usage);
}

fn printUsage() !void {
    const usage =
        \\ZiggySpiderweb Configuration Tool
        \\
        \\Usage:
        \\  spiderweb-config auth path
        \\  spiderweb-config auth reset --yes
        \\  spiderweb-config first-run [--non-interactive] [--provider <name>] [--model <model>] [--agent <name>]
        \\  spiderweb-config oauth login <provider> [--enterprise-domain <domain>] [--no-set-provider]
        \\  spiderweb-config oauth clear <provider>
        \\  spiderweb-config config              Show current config
        \\  spiderweb-config config path         Show config file path
        \\  spiderweb-config config set-provider <name> [model]
        \\  spiderweb-config config set-server --bind <addr> --port <port>
        \\  spiderweb-config config set-key <api-key> [provider]
        \\  spiderweb-config config clear-key [provider]
        \\  spiderweb-config config set-log <debug|info|warn|error>
        \\  spiderweb-config config install-service     Install systemd service
        \\
        \\Examples:
        \\  spiderweb-config first-run
        \\  spiderweb-config first-run --non-interactive --provider openai-codex --agent ziggy
        \\  spiderweb-config oauth login openai-codex
        \\  spiderweb-config oauth login github-copilot --enterprise-domain github.example.com
        \\  spiderweb-config auth path
        \\  spiderweb-config auth reset --yes
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

test "config_cli: resolve runtime storage directory keeps absolute ltm path" {
    const allocator = std.testing.allocator;
    const resolved = try resolveRuntimeStorageDirectoryWithBase(allocator, "/var/lib/spiderweb/ltm", "/ignored/base");
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings("/var/lib/spiderweb/ltm", resolved);
}

test "config_cli: resolve runtime storage directory joins relative ltm path with runtime base" {
    const allocator = std.testing.allocator;
    const resolved = try resolveRuntimeStorageDirectoryWithBase(allocator, ".spiderweb-ltm", "/srv/spiderweb");
    defer allocator.free(resolved);
    const expected = try std.fs.path.join(allocator, &.{ "/srv/spiderweb", ".spiderweb-ltm" });
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, resolved);
}

test "config_cli: parse service working directory from unit file" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{
        .sub_path = "spiderweb.service",
        .data =
        \\[Unit]
        \\Description=ZiggySpiderweb
        \\
        \\[Service]
        \\WorkingDirectory=/opt/ziggy-spiderweb
        \\ExecStart=/usr/bin/spiderweb
        \\
        ,
    });

    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const service_path = try std.fs.path.join(allocator, &.{ root, "spiderweb.service" });
    defer allocator.free(service_path);

    const parsed = (try parseServiceWorkingDirectory(allocator, service_path)) orelse return error.TestExpectedWorkingDirectory;
    defer allocator.free(parsed);
    try std.testing.expectEqualStrings("/opt/ziggy-spiderweb", parsed);
}
