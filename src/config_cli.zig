const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const native_mount_support = @import("acheron/native_mount_support.zig");
const first_run = @import("first_run.zig");

const auth_tokens_filename = "auth_tokens.json";

const AuthStatusSnapshot = struct {
    admin_token: []u8,
    user_token: []u8,

    fn deinit(self: *AuthStatusSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.admin_token);
        allocator.free(self.user_token);
        self.* = undefined;
    }
};

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
        const path = try resolveAuthTokensPath(allocator, config.runtime.ltm_directory, config.runtime.spider_web_root, config.config_path);
        defer allocator.free(path);
        const out = try std.fmt.allocPrint(allocator, "{s}\n", .{path});
        defer allocator.free(out);
        try std.fs.File.stdout().writeAll(out);
        return;
    }

    if (std.mem.eql(u8, subcommand, "status")) {
        var reveal_tokens = false;
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--reveal")) {
                reveal_tokens = true;
                continue;
            }
            std.log.err("Unknown auth status arg: {s}", .{arg});
            return error.InvalidArguments;
        }

        var config = try Config.init(allocator, null);
        defer config.deinit();
        const path = try resolveAuthTokensPath(allocator, config.runtime.ltm_directory, config.runtime.spider_web_root, config.config_path);
        defer allocator.free(path);

        var snapshot = try loadAuthStatusSnapshot(allocator, path);
        defer snapshot.deinit(allocator);

        const admin_display_owned = if (reveal_tokens)
            null
        else
            try maskTokenForDisplay(allocator, snapshot.admin_token);
        defer if (admin_display_owned) |value| allocator.free(value);

        const user_display_owned = if (reveal_tokens)
            null
        else
            try maskTokenForDisplay(allocator, snapshot.user_token);
        defer if (user_display_owned) |value| allocator.free(value);

        const admin_display = if (admin_display_owned) |value| value else snapshot.admin_token;
        const user_display = if (user_display_owned) |value| value else snapshot.user_token;

        const out = try std.fmt.allocPrint(
            allocator,
            "Auth status\n  admin_token: {s}\n  user_token:  {s}\n  path:        {s}\n",
            .{ admin_display, user_display, path },
        );
        defer allocator.free(out);
        try std.fs.File.stdout().writeAll(out);
        if (!reveal_tokens) {
            try std.fs.File.stdout().writeAll("  note: tokens are masked; run `spiderweb-config auth status --reveal` for full values\n");
        }
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
        const path = try resolveAuthTokensPath(allocator, config.runtime.ltm_directory, config.runtime.spider_web_root, config.config_path);
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

        const stdout_file = std.fs.File.stdout();
        var buf: [1024]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "Config: {s}\n  Bind: {s}:{d}\n  Spider Web Root: {s}\n  Runtime Storage: {s}/{s}\n  Log: {s}\n", .{
            config.config_path,
            config.server.bind,
            config.server.port,
            config.runtime.spider_web_root,
            config.runtime.ltm_directory,
            config.runtime.ltm_filename,
            config.log.level,
        });
        try stdout_file.writeAll(msg);
        try stdout_file.writeAll("  Note: AI provider and worker configuration now lives with the external worker (for example Spider Monkey).\n");
        return;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "set-server")) {
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
        try installService(allocator);
    } else if (std.mem.eql(u8, subcommand, "uninstall-service")) {
        try uninstallService(allocator);
    } else if (std.mem.eql(u8, subcommand, "service-status")) {
        try printServiceStatus(allocator);
    } else if (std.mem.eql(u8, subcommand, "install-fs-extension")) {
        try installFsExtension(allocator);
    } else if (std.mem.eql(u8, subcommand, "uninstall-fs-extension")) {
        try uninstallFsExtension(allocator);
    } else if (std.mem.eql(u8, subcommand, "fs-extension-status")) {
        try printFsExtensionStatus(allocator);
    } else {
        std.log.err("Unknown config command: {s}", .{subcommand});
        std.log.info("Available: set-server, set-log, path, install-service, uninstall-service, service-status, install-fs-extension, uninstall-fs-extension, fs-extension-status", .{});
        return error.UnknownCommand;
    }
}

const ServiceManager = enum {
    systemd_user,
    launchd_user,
    unsupported,
};

const service_name = "spiderweb";

const CommandResult = struct {
    stdout: []u8,
    stderr: []u8,
    term: std.process.Child.Term,

    fn deinit(self: *CommandResult, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

fn installService(allocator: std.mem.Allocator) !void {
    return switch (detectServiceManager()) {
        .systemd_user => installSystemdUserService(allocator),
        .launchd_user => installLaunchdUserService(allocator),
        .unsupported => error.UnsupportedPlatform,
    };
}

fn uninstallService(allocator: std.mem.Allocator) !void {
    return switch (detectServiceManager()) {
        .systemd_user => uninstallSystemdUserService(allocator),
        .launchd_user => uninstallLaunchdUserService(allocator),
        .unsupported => error.UnsupportedPlatform,
    };
}

fn printServiceStatus(allocator: std.mem.Allocator) !void {
    return switch (detectServiceManager()) {
        .systemd_user => printSystemdUserServiceStatus(allocator),
        .launchd_user => printLaunchdUserServiceStatus(allocator),
        .unsupported => error.UnsupportedPlatform,
    };
}

fn installFsExtension(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    var status = try native_mount_support.detectInstallStatus(allocator);
    defer status.deinit(allocator);

    if (!status.supported_os) return error.UnsupportedMacosVersion;
    const source_app_path = status.source_app_path orelse {
        std.log.err("Could not find a built SpiderwebFSKit.app. Build it from platform/macos first.", .{});
        return error.NativeFsExtensionNotInstalled;
    };
    if (std.fs.path.dirname(status.app_path)) |dir| try makePathAny(dir);

    _ = try deleteTreeIfExistsAny(status.app_path);
    try runCommandSuccess(allocator, &.{ "ditto", source_app_path, status.app_path });

    if (pathExists(status.extension_path)) {
        if (try runCommandBestEffort(allocator, &.{ "pluginkit", "-a", status.extension_path })) |result| {
            var owned = result;
            owned.deinit(allocator);
        }
        if (try runCommandBestEffort(allocator, &.{ "pluginkit", "-e", "use", "-i", native_mount_support.extension_bundle_id })) |result| {
            var owned = result;
            owned.deinit(allocator);
        }
    }
    if (try runCommandBestEffort(allocator, &.{ "open", "-a", status.app_path })) |result| {
        var owned = result;
        owned.deinit(allocator);
    }
    native_mount_support.openSystemSettingsForFsExtension();

    std.log.info("Installed SpiderwebFSKit.app to {s}", .{status.app_path});
    std.log.info("If macOS prompts for approval, enable the file system extension in System Settings -> General -> Login Items & Extensions.", .{});
}

fn uninstallFsExtension(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    var status = try native_mount_support.detectInstallStatus(allocator);
    defer status.deinit(allocator);

    if (pathExists(status.extension_path)) {
        if (try runCommandBestEffort(allocator, &.{ "pluginkit", "-r", status.extension_path })) |result| {
            var owned = result;
            owned.deinit(allocator);
        }
    }
    _ = try deleteTreeIfExistsAny(status.app_path);
    _ = try deleteTreeIfExistsAny(status.request_dir);

    std.log.info("Removed SpiderwebFSKit.app from {s}", .{status.app_path});
}

fn printFsExtensionStatus(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .macos) return error.UnsupportedPlatform;

    var status = try native_mount_support.detectInstallStatus(allocator);
    defer status.deinit(allocator);

    const out = try std.fmt.allocPrint(
        allocator,
        "FS extension manager: native-fskit\n  supported_os:             {s}\n  installed_app:            {s}\n  built_app_source:         {s}\n  extension_bundle:         {s}\n  helper_executable:        {s}\n  runtime_manifest:         {s}\n  extension_present:        {s}\n  helper_present:           {s}\n  runtime_ready:            {s}\n  signing_identity:         {s}\n  app_group_entitlements:   {s}\n  extension_fs_entitlement: {s}\n  registered:               {s}\n  module_enabled:           {s}\n  ready:                    {s}\n  request_dir:              {s}\n",
        .{
            if (status.supported_os) "yes" else "no",
            status.app_path,
            status.source_app_path orelse "(not found)",
            status.extension_path,
            status.helper_path,
            status.runtime_ready_manifest_path,
            if (status.extension_present) "yes" else "no",
            if (status.helper_present) "yes" else "no",
            if (status.runtime_ready) "yes" else "no",
            if (status.signing_identity_available) "yes" else "no",
            if (status.app_group_entitled) "yes" else "no",
            if (status.extension_fskit_entitled) "yes" else "no",
            if (status.extension_registered) "yes" else "no",
            if (status.module_enabled) "yes" else "no",
            if (status.ready()) "yes" else "no",
            status.request_dir,
        },
    );
    defer allocator.free(out);
    try std.fs.File.stdout().writeAll(out);
}

fn detectServiceManager() ServiceManager {
    return switch (builtin.os.tag) {
        .linux => .systemd_user,
        .macos => .launchd_user,
        else => .unsupported,
    };
}

fn installSystemdUserService(allocator: std.mem.Allocator) !void {
    const exec_path = try resolveServiceExecutablePath(allocator);
    defer allocator.free(exec_path);
    const working_dir = try defaultServiceWorkingDirectory(allocator);
    defer allocator.free(working_dir);
    const service_path = try systemdUserServicePath(allocator);
    defer allocator.free(service_path);

    if (std.fs.path.dirname(service_path)) |dir| try makePathAny(dir);

    const content = try std.fmt.allocPrint(
        allocator,
        \\[Unit]
        \\Description=Spiderweb Workspace Host
        \\After=network.target
        \\
        \\[Service]
        \\Type=simple
        \\ExecStart={s}
        \\WorkingDirectory={s}
        \\Restart=on-failure
        \\RestartSec=5
        \\
        \\[Install]
        \\WantedBy=default.target
        \\
    ,
        .{ exec_path, working_dir },
    );
    defer allocator.free(content);

    var file = try createFileAny(service_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);

    try runCommandSuccess(allocator, &.{ "systemctl", "--user", "daemon-reload" });
    try runCommandSuccess(allocator, &.{ "systemctl", "--user", "enable", "--now", service_name });

    std.log.info("Installed and started systemd user service at {s}", .{service_path});
}

fn uninstallSystemdUserService(allocator: std.mem.Allocator) !void {
    const service_path = try systemdUserServicePath(allocator);
    defer allocator.free(service_path);

    if (try runCommandBestEffort(allocator, &.{ "systemctl", "--user", "disable", "--now", service_name })) |result| {
        var owned_result = result;
        owned_result.deinit(allocator);
    }
    _ = try deleteFileIfExistsAny(service_path);
    if (try runCommandBestEffort(allocator, &.{ "systemctl", "--user", "daemon-reload" })) |result| {
        var owned_result = result;
        owned_result.deinit(allocator);
    }

    std.log.info("Removed systemd user service definition at {s}", .{service_path});
}

fn printSystemdUserServiceStatus(allocator: std.mem.Allocator) !void {
    const service_path = try systemdUserServicePath(allocator);
    defer allocator.free(service_path);
    const installed = pathExists(service_path);

    if (!installed) {
        const out = try std.fmt.allocPrint(
            allocator,
            "Service manager: systemd\n  unit:      {s}\n  installed: no\n",
            .{service_path},
        );
        defer allocator.free(out);
        try std.fs.File.stdout().writeAll(out);
        return;
    }

    var enabled = try runCommandBestEffort(allocator, &.{ "systemctl", "--user", "is-enabled", service_name });
    defer if (enabled) |*value| value.deinit(allocator);
    var active = try runCommandBestEffort(allocator, &.{ "systemctl", "--user", "is-active", service_name });
    defer if (active) |*value| value.deinit(allocator);

    const enabled_text = if (enabled) |value|
        commandResultSummary(value, "unknown")
    else
        "unknown";
    const active_text = if (active) |value|
        commandResultSummary(value, "unknown")
    else
        "unknown";

    const out = try std.fmt.allocPrint(
        allocator,
        "Service manager: systemd\n  unit:      {s}\n  installed: yes\n  enabled:   {s}\n  active:    {s}\n",
        .{ service_path, enabled_text, active_text },
    );
    defer allocator.free(out);
    try std.fs.File.stdout().writeAll(out);
}

fn installLaunchdUserService(allocator: std.mem.Allocator) !void {
    const exec_path = try resolveServiceExecutablePath(allocator);
    defer allocator.free(exec_path);
    const working_dir = try defaultServiceWorkingDirectory(allocator);
    defer allocator.free(working_dir);
    const plist_path = try launchdPlistPath(allocator);
    defer allocator.free(plist_path);

    if (std.fs.path.dirname(plist_path)) |dir| try makePathAny(dir);

    const content = try std.fmt.allocPrint(
        allocator,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key>
        \\  <string>{s}</string>
        \\  <key>ProgramArguments</key>
        \\  <array>
        \\    <string>{s}</string>
        \\  </array>
        \\  <key>WorkingDirectory</key>
        \\  <string>{s}</string>
        \\  <key>RunAtLoad</key>
        \\  <true/>
        \\  <key>KeepAlive</key>
        \\  <true/>
        \\</dict>
        \\</plist>
        \\
    ,
        .{ service_name, exec_path, working_dir },
    );
    defer allocator.free(content);

    var file = try createFileAny(plist_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);

    const domain_target = try launchdDomainTarget(allocator);
    defer allocator.free(domain_target);
    const service_target = try launchdServiceTarget(allocator);
    defer allocator.free(service_target);

    if (try runCommandBestEffort(allocator, &.{ "launchctl", "bootout", domain_target, plist_path })) |result| {
        var owned_result = result;
        owned_result.deinit(allocator);
    }
    try runCommandSuccess(allocator, &.{ "launchctl", "bootstrap", domain_target, plist_path });
    try runCommandSuccess(allocator, &.{ "launchctl", "kickstart", "-k", service_target });

    std.log.info("Installed and started launchd user service at {s}", .{plist_path});
}

fn uninstallLaunchdUserService(allocator: std.mem.Allocator) !void {
    const plist_path = try launchdPlistPath(allocator);
    defer allocator.free(plist_path);
    const domain_target = try launchdDomainTarget(allocator);
    defer allocator.free(domain_target);
    const service_target = try launchdServiceTarget(allocator);
    defer allocator.free(service_target);

    if (try runCommandBestEffort(allocator, &.{ "launchctl", "bootout", domain_target, plist_path })) |result| {
        var owned_result = result;
        owned_result.deinit(allocator);
    }
    if (try runCommandBestEffort(allocator, &.{ "launchctl", "bootout", service_target })) |result| {
        var owned_result = result;
        owned_result.deinit(allocator);
    }
    _ = try deleteFileIfExistsAny(plist_path);

    std.log.info("Removed launchd user service definition at {s}", .{plist_path});
}

fn printLaunchdUserServiceStatus(allocator: std.mem.Allocator) !void {
    const plist_path = try launchdPlistPath(allocator);
    defer allocator.free(plist_path);
    const installed = pathExists(plist_path);
    const service_target = try launchdServiceTarget(allocator);
    defer allocator.free(service_target);

    var printed = if (installed)
        try runCommandBestEffort(allocator, &.{ "launchctl", "print", service_target })
    else
        null;
    defer if (printed) |*value| value.deinit(allocator);

    const out = try std.fmt.allocPrint(
        allocator,
        "Service manager: launchd\n  plist:      {s}\n  installed:  {s}\n  loaded:     {s}\n",
        .{
            plist_path,
            if (installed) "yes" else "no",
            if (printed != null and commandExitedSuccessfully(printed.?)) "yes" else "no",
        },
    );
    defer allocator.free(out);
    try std.fs.File.stdout().writeAll(out);
}

fn resolveServiceExecutablePath(allocator: std.mem.Allocator) ![]u8 {
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);
    const self_dir = std.fs.path.dirname(self_path) orelse return error.InvalidExecutablePath;

    const sibling = try std.fs.path.join(allocator, &.{ self_dir, "spiderweb" });
    if (pathExists(sibling)) return sibling;
    allocator.free(sibling);

    const home = try requireHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".local", "bin", "spiderweb" });
}

fn defaultServiceWorkingDirectory(allocator: std.mem.Allocator) ![]u8 {
    const home = try requireHomeDir(allocator);
    defer allocator.free(home);

    const repo_dir = try std.fs.path.join(allocator, &.{ home, ".local", "share", "ziggy-spiderweb" });
    if (pathExists(repo_dir)) return repo_dir;
    allocator.free(repo_dir);

    return currentShellWorkingDirectory(allocator);
}

fn requireHomeDir(allocator: std.mem.Allocator) ![]u8 {
    return std.process.getEnvVarOwned(allocator, "HOME") catch {
        std.log.err("Could not get HOME directory", .{});
        return error.MissingHome;
    };
}

fn systemdUserServicePath(allocator: std.mem.Allocator) ![]u8 {
    const home = try requireHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".config", "systemd", "user", "spiderweb.service" });
}

fn launchdPlistPath(allocator: std.mem.Allocator) ![]u8 {
    const home = try requireHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, "Library", "LaunchAgents", "spiderweb.plist" });
}

fn launchdDomainTarget(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "gui/{d}", .{std.posix.getuid()});
}

fn launchdServiceTarget(allocator: std.mem.Allocator) ![]u8 {
    const domain_target = try launchdDomainTarget(allocator);
    defer allocator.free(domain_target);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ domain_target, service_name });
}

fn runCommandCapture(allocator: std.mem.Allocator, argv: []const []const u8) !CommandResult {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 128 * 1024,
    });
    return .{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .term = result.term,
    };
}

fn runCommandSuccess(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    var result = try runCommandCapture(allocator, argv);
    defer result.deinit(allocator);
    if (commandExitedSuccessfully(result)) return;

    const stderr_text = trimmedCommandText(result.stderr);
    const stdout_text = trimmedCommandText(result.stdout);
    if (stderr_text.len > 0) {
        std.log.err("command failed: {s}", .{stderr_text});
    } else if (stdout_text.len > 0) {
        std.log.err("command failed: {s}", .{stdout_text});
    } else {
        std.log.err("command failed: {s}", .{argv[0]});
    }
    return error.CommandFailed;
}

fn runCommandBestEffort(allocator: std.mem.Allocator, argv: []const []const u8) !?CommandResult {
    return runCommandCapture(allocator, argv) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
}

fn commandExitedSuccessfully(result: CommandResult) bool {
    return switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn commandResultSummary(result: CommandResult, fallback: []const u8) []const u8 {
    const stdout_text = trimmedCommandText(result.stdout);
    if (stdout_text.len > 0) return stdout_text;
    const stderr_text = trimmedCommandText(result.stderr);
    if (stderr_text.len > 0) return stderr_text;
    return fallback;
}

fn trimmedCommandText(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \t\r\n");
}

fn resolveAuthTokensPath(
    allocator: std.mem.Allocator,
    ltm_directory: []const u8,
    spider_web_root: []const u8,
    config_path: []const u8,
) ![]u8 {
    const storage_dir = try resolveRuntimeStorageDirectory(allocator, ltm_directory, spider_web_root, config_path);
    defer allocator.free(storage_dir);
    try makePathAny(storage_dir);
    return std.fs.path.join(allocator, &.{ storage_dir, auth_tokens_filename });
}

fn resolveRuntimeStorageDirectory(
    allocator: std.mem.Allocator,
    ltm_directory: []const u8,
    spider_web_root: []const u8,
    config_path: []const u8,
) ![]u8 {
    const runtime_base = try resolveRuntimeBaseDirectory(allocator, ltm_directory, spider_web_root, config_path);
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

fn resolveRuntimeBaseDirectory(
    allocator: std.mem.Allocator,
    ltm_directory: []const u8,
    spider_web_root: []const u8,
    config_path: []const u8,
) ![]u8 {
    _ = config_path;
    const configured_root = std.mem.trim(u8, spider_web_root, " \t\r\n");
    if (configured_root.len > 0 and !std.mem.eql(u8, configured_root, "/")) {
        if (std.fs.path.isAbsolute(configured_root)) return allocator.dupe(u8, configured_root);
        const cwd = try currentShellWorkingDirectory(allocator);
        defer allocator.free(cwd);
        return std.fs.path.join(allocator, &.{ cwd, configured_root });
    }

    if (try detectServiceWorkingDirectory(allocator)) |service_dir| {
        if (try currentDirectoryOwnsRuntimeStorage(allocator, ltm_directory)) {
            defer allocator.free(service_dir);
            return currentShellWorkingDirectory(allocator);
        }
        return service_dir;
    }

    const cwd = try currentShellWorkingDirectory(allocator);
    if (cwd.len > 0 and !std.mem.eql(u8, cwd, "/")) return cwd;
    allocator.free(cwd);
    return currentShellWorkingDirectory(allocator);
}

fn currentDirectoryOwnsRuntimeStorage(allocator: std.mem.Allocator, ltm_directory: []const u8) !bool {
    const cwd = try currentShellWorkingDirectory(allocator);
    defer allocator.free(cwd);
    if (cwd.len == 0 or std.mem.eql(u8, cwd, "/")) return false;

    const storage_dir = try resolveRuntimeStorageDirectoryWithBase(allocator, ltm_directory, cwd);
    defer allocator.free(storage_dir);

    const auth_tokens_path = try std.fs.path.join(allocator, &.{ storage_dir, auth_tokens_filename });
    defer allocator.free(auth_tokens_path);
    return pathExists(auth_tokens_path);
}

fn pathExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.accessAbsolute(path, .{}) catch return false;
        return true;
    }
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn currentShellWorkingDirectory(allocator: std.mem.Allocator) ![]u8 {
    const env_pwd = std.process.getEnvVarOwned(allocator, "PWD") catch null;
    if (env_pwd) |pwd| {
        if (pwd.len > 0 and std.fs.path.isAbsolute(pwd)) return pwd;
        allocator.free(pwd);
    }
    return std.process.getCwdAlloc(allocator);
}

fn detectServiceWorkingDirectory(allocator: std.mem.Allocator) !?[]u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch null;
    if (home) |home_dir| {
        defer allocator.free(home_dir);
        const launchd_path = try std.fs.path.join(allocator, &.{ home_dir, "Library", "LaunchAgents", "spiderweb.plist" });
        defer allocator.free(launchd_path);
        if (try parseServiceWorkingDirectory(allocator, launchd_path)) |dir| return dir;
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

    if (std.mem.indexOf(u8, contents, "<plist") != null) {
        return extractPlistStringValue(allocator, contents, "WorkingDirectory");
    }

    return parseSystemdWorkingDirectory(allocator, contents, service_path);
}

fn parseSystemdWorkingDirectory(
    allocator: std.mem.Allocator,
    contents: []const u8,
    service_path: []const u8,
) !?[]u8 {
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

fn extractPlistStringValue(
    allocator: std.mem.Allocator,
    contents: []const u8,
    key_name: []const u8,
) !?[]u8 {
    const key_tag = try std.fmt.allocPrint(allocator, "<key>{s}</key>", .{key_name});
    defer allocator.free(key_tag);

    const key_idx = std.mem.indexOf(u8, contents, key_tag) orelse return null;
    const after_key = contents[key_idx + key_tag.len ..];
    const string_start_rel = std.mem.indexOf(u8, after_key, "<string>") orelse return null;
    const value_start = string_start_rel + "<string>".len;
    const value_end_rel = std.mem.indexOf(u8, after_key[value_start..], "</string>") orelse return null;
    const value = std.mem.trim(u8, after_key[value_start .. value_start + value_end_rel], " \t\r\n");
    if (value.len == 0) return null;
    return try allocator.dupe(u8, value);
}

fn readFileAllocAny(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
        defer file.close();
        return file.readToEndAlloc(allocator, max_bytes);
    }
    return std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
}

fn makePathAny(path: []const u8) !void {
    if (path.len == 0) return;
    if (std.fs.path.isAbsolute(path)) {
        var root_dir = try std.fs.openDirAbsolute("/", .{});
        defer root_dir.close();
        const rel_dir = std.mem.trimLeft(u8, path, "/");
        if (rel_dir.len == 0) return;
        root_dir.makePath(rel_dir) catch |err| switch (err) {
            error.PathAlreadyExists => return,
            else => return err,
        };
        return;
    }
    std.fs.cwd().makePath(path) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        else => return err,
    };
}

fn createFileAny(path: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return std.fs.createFileAbsolute(path, flags);
    }
    return std.fs.cwd().createFile(path, flags);
}

fn deleteFileIfExistsAny(path: []const u8) !bool {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.deleteFileAbsolute(path) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }
    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn deleteTreeIfExistsAny(path: []const u8) !bool {
    if (!pathExists(path)) return false;

    if (std.fs.path.isAbsolute(path)) {
        var root_dir = try std.fs.openDirAbsolute("/", .{});
        defer root_dir.close();
        const rel_path = std.mem.trimLeft(u8, path, "/");
        if (rel_path.len == 0) return false;
        try root_dir.deleteTree(rel_path);
        return true;
    }

    try std.fs.cwd().deleteTree(path);
    return true;
}

fn makeOpaqueToken(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    var random_bytes: [24]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var encoded_buf: [std.base64.url_safe_no_pad.Encoder.calcSize(random_bytes.len)]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buf, &random_bytes);
    return std.fmt.allocPrint(allocator, "{s}_{s}", .{ prefix, encoded });
}

fn maskTokenForDisplay(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    if (token.len == 0) return allocator.dupe(u8, "(empty)");
    if (token.len <= 8) return allocator.dupe(u8, "****");
    return std.fmt.allocPrint(
        allocator,
        "{s}...{s}",
        .{ token[0..4], token[token.len - 4 ..] },
    );
}

fn loadAuthStatusSnapshot(allocator: std.mem.Allocator, path: []const u8) !AuthStatusSnapshot {
    const raw = try readFileAllocAny(allocator, path, 64 * 1024);
    defer allocator.free(raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;

    const admin_val = parsed.value.object.get("admin_token") orelse return error.InvalidResponse;
    if (admin_val != .string or admin_val.string.len == 0) return error.InvalidResponse;
    const user_val = parsed.value.object.get("user_token") orelse return error.InvalidResponse;
    if (user_val != .string or user_val.string.len == 0) return error.InvalidResponse;

    return .{
        .admin_token = try allocator.dupe(u8, admin_val.string),
        .user_token = try allocator.dupe(u8, user_val.string),
    };
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

    var file = try createFileAny(path, .{
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
        \\  spiderweb-config auth status [--reveal]
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
        \\Spiderweb Configuration Tool
        \\
        \\Usage:
        \\  spiderweb-config auth path
        \\  spiderweb-config auth status [--reveal]
        \\  spiderweb-config auth reset --yes
        \\  spiderweb-config first-run [--non-interactive]
        \\  spiderweb-config config              Show current config
        \\  spiderweb-config config path         Show config file path
        \\  spiderweb-config config set-server --bind <addr> --port <port>
        \\  spiderweb-config config set-log <debug|info|warn|error>
        \\  spiderweb-config config install-service
        \\  spiderweb-config config uninstall-service
        \\  spiderweb-config config service-status
        \\  spiderweb-config config install-fs-extension
        \\  spiderweb-config config uninstall-fs-extension
        \\  spiderweb-config config fs-extension-status
        \\
        \\Examples:
        \\  spiderweb-config first-run
        \\  spiderweb-config first-run --non-interactive
        \\  spiderweb-config auth path
        \\  spiderweb-config auth status --reveal
        \\  spiderweb-config auth reset --yes
        \\  spiderweb-config config set-server --bind 0.0.0.0 --port 9000
        \\  spiderweb-config config install-service
        \\  spiderweb-config config service-status
        \\  spiderweb-config config install-fs-extension
        \\  spiderweb-config config fs-extension-status
        \\
        \\Workspace-first flow:
        \\  spiderweb-control workspace_create '{"name":"Demo","vision":"Deliver the demo workspace"}'
        \\  spiderweb-fs-mount --workspace-id <workspace-id> ./workspace
        \\  note: macOS auto mounts use macFUSE for now; use --mount-backend native when explicitly testing the FSKit path
        \\  spider-monkey run --workspace-root ./workspace
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
        \\Description=Spiderweb
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

test "config_cli: parse working directory from launchd plist" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{
        .sub_path = "spiderweb.plist",
        .data =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key>
        \\  <string>spiderweb</string>
        \\  <key>WorkingDirectory</key>
        \\  <string>/Users/example/Spiderweb</string>
        \\</dict>
        \\</plist>
        ,
    });

    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const plist_path = try std.fs.path.join(allocator, &.{ root, "spiderweb.plist" });
    defer allocator.free(plist_path);

    const parsed = (try parseServiceWorkingDirectory(allocator, plist_path)) orelse return error.TestExpectedWorkingDirectory;
    defer allocator.free(parsed);
    try std.testing.expectEqualStrings("/Users/example/Spiderweb", parsed);
}
