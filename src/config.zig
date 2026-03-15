const std = @import("std");
const builtin = @import("builtin");

const Config = @This();

pub const ServerConfig = struct {
    bind: []const u8 = "127.0.0.1",
    port: u16 = 18790,
};

pub const LogConfig = struct {
    level: []const u8 = "info",
};

pub const RuntimeConfig = struct {
    inbound_queue_max: usize = 512,
    brain_tick_queue_max: usize = 256,
    outbound_queue_max: usize = 512,
    control_queue_max: usize = 128,
    connection_worker_threads: usize = 16,
    connection_queue_max: usize = 128,
    runtime_worker_threads: usize = 2,
    runtime_request_queue_max: usize = 128,
    chat_operation_timeout_ms: u64 = 300_000,
    control_operation_timeout_ms: u64 = 5_000,
    run_checkpoint_interval_steps: usize = 1,
    run_auto_resume_on_boot: bool = true,
    tool_retry_max_attempts: usize = 3,
    tool_lease_timeout_ms: u64 = 30_000,
    max_inflight_tool_calls_per_run: usize = 1,
    max_run_steps: usize = 1024,
    default_agent_id: []const u8 = "",
    spider_web_root: []const u8 = "",
    ltm_directory: []const u8 = ".spiderweb-ltm",
    ltm_filename: []const u8 = "runtime-memory.db",
    assets_dir: []const u8 = "templates",
    agents_dir: []const u8 = "agents",
    sandbox_enabled: bool = builtin.os.tag == .linux and !builtin.is_test,
    sandbox_mounts_root: []const u8 = "/var/lib/spiderweb/mounts",
    sandbox_rootfs_base_ref: []const u8 = "debian:bookworm-slim",
    sandbox_rootfs_store_root: []const u8 = "/var/lib/spiderweb/rootfs/base",
    sandbox_overlay_root: []const u8 = "/var/lib/spiderweb/rootfs/overlays",
    sandbox_snapshot_root: []const u8 = "/var/lib/spiderweb/rootfs/snapshots",
    sandbox_launcher: []const u8 = "bwrap",
    sandbox_fs_mount_bin: []const u8 = "spiderweb-fs-mount",

    pub fn clone(self: RuntimeConfig, allocator: std.mem.Allocator) !RuntimeConfig {
        return .{
            .inbound_queue_max = self.inbound_queue_max,
            .brain_tick_queue_max = self.brain_tick_queue_max,
            .outbound_queue_max = self.outbound_queue_max,
            .control_queue_max = self.control_queue_max,
            .connection_worker_threads = self.connection_worker_threads,
            .connection_queue_max = self.connection_queue_max,
            .runtime_worker_threads = self.runtime_worker_threads,
            .runtime_request_queue_max = self.runtime_request_queue_max,
            .chat_operation_timeout_ms = self.chat_operation_timeout_ms,
            .control_operation_timeout_ms = self.control_operation_timeout_ms,
            .run_checkpoint_interval_steps = self.run_checkpoint_interval_steps,
            .run_auto_resume_on_boot = self.run_auto_resume_on_boot,
            .tool_retry_max_attempts = self.tool_retry_max_attempts,
            .tool_lease_timeout_ms = self.tool_lease_timeout_ms,
            .max_inflight_tool_calls_per_run = self.max_inflight_tool_calls_per_run,
            .max_run_steps = self.max_run_steps,
            .default_agent_id = try allocator.dupe(u8, self.default_agent_id),
            .spider_web_root = try allocator.dupe(u8, self.spider_web_root),
            .ltm_directory = try allocator.dupe(u8, self.ltm_directory),
            .ltm_filename = try allocator.dupe(u8, self.ltm_filename),
            .assets_dir = try allocator.dupe(u8, self.assets_dir),
            .agents_dir = try allocator.dupe(u8, self.agents_dir),
            .sandbox_enabled = self.sandbox_enabled,
            .sandbox_mounts_root = try allocator.dupe(u8, self.sandbox_mounts_root),
            .sandbox_rootfs_base_ref = try allocator.dupe(u8, self.sandbox_rootfs_base_ref),
            .sandbox_rootfs_store_root = try allocator.dupe(u8, self.sandbox_rootfs_store_root),
            .sandbox_overlay_root = try allocator.dupe(u8, self.sandbox_overlay_root),
            .sandbox_snapshot_root = try allocator.dupe(u8, self.sandbox_snapshot_root),
            .sandbox_launcher = try allocator.dupe(u8, self.sandbox_launcher),
            .sandbox_fs_mount_bin = try allocator.dupe(u8, self.sandbox_fs_mount_bin),
        };
    }

    pub fn deinit(self: *RuntimeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.default_agent_id);
        allocator.free(self.spider_web_root);
        allocator.free(self.ltm_directory);
        allocator.free(self.ltm_filename);
        allocator.free(self.assets_dir);
        allocator.free(self.agents_dir);
        allocator.free(self.sandbox_mounts_root);
        allocator.free(self.sandbox_rootfs_base_ref);
        allocator.free(self.sandbox_rootfs_store_root);
        allocator.free(self.sandbox_overlay_root);
        allocator.free(self.sandbox_snapshot_root);
        allocator.free(self.sandbox_launcher);
        allocator.free(self.sandbox_fs_mount_bin);
    }
};

allocator: std.mem.Allocator,
server: ServerConfig,
log: LogConfig,
runtime: RuntimeConfig,
config_path: []const u8,

const default_config =
    \\{
    \\  "server": {
    \\    "bind": "127.0.0.1",
    \\    "port": 18790
    \\  },
    \\  "log": {
    \\    "level": "info"
    \\  },
    \\  "runtime": {
    \\    "inbound_queue_max": 512,
    \\    "brain_tick_queue_max": 256,
    \\    "outbound_queue_max": 512,
    \\    "control_queue_max": 128,
    \\    "connection_worker_threads": 16,
    \\    "connection_queue_max": 128,
    \\    "runtime_worker_threads": 2,
    \\    "runtime_request_queue_max": 128,
    \\    "chat_operation_timeout_ms": 300000,
    \\    "control_operation_timeout_ms": 5000,
    \\    "run_checkpoint_interval_steps": 1,
    \\    "run_auto_resume_on_boot": true,
    \\    "tool_retry_max_attempts": 3,
    \\    "tool_lease_timeout_ms": 30000,
    \\    "max_inflight_tool_calls_per_run": 1,
    \\    "max_run_steps": 1024,
    \\    "default_agent_id": "",
    \\    "spider_web_root": "",
    \\    "ltm_directory": ".spiderweb-ltm",
    \\    "ltm_filename": "runtime-memory.db",
    \\    "assets_dir": "templates",
    \\    "agents_dir": "agents"
    \\  }
    \\}
;

const SandboxPathDefaults = struct {
    mounts_root: []u8,
    rootfs_store_root: []u8,
    overlay_root: []u8,
    snapshot_root: []u8,

    fn deinit(self: *SandboxPathDefaults, allocator: std.mem.Allocator) void {
        allocator.free(self.mounts_root);
        allocator.free(self.rootfs_store_root);
        allocator.free(self.overlay_root);
        allocator.free(self.snapshot_root);
        self.* = undefined;
    }
};

fn resolveSandboxPathDefaults(allocator: std.mem.Allocator) !SandboxPathDefaults {
    if (builtin.os.tag != .linux) {
        return .{
            .mounts_root = try allocator.dupe(u8, "/var/lib/spiderweb/mounts"),
            .rootfs_store_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/base"),
            .overlay_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/overlays"),
            .snapshot_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/snapshots"),
        };
    }

    if (std.posix.geteuid() == 0) {
        return .{
            .mounts_root = try allocator.dupe(u8, "/var/lib/spiderweb/mounts"),
            .rootfs_store_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/base"),
            .overlay_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/overlays"),
            .snapshot_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/snapshots"),
        };
    }

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch null;
    if (home == null) {
        return .{
            .mounts_root = try allocator.dupe(u8, "/var/lib/spiderweb/mounts"),
            .rootfs_store_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/base"),
            .overlay_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/overlays"),
            .snapshot_root = try allocator.dupe(u8, "/var/lib/spiderweb/rootfs/snapshots"),
        };
    }
    defer allocator.free(home.?);

    const xdg_state_home = std.process.getEnvVarOwned(allocator, "XDG_STATE_HOME") catch null;
    defer if (xdg_state_home) |value| allocator.free(value);

    const sandbox_root = blk: {
        if (xdg_state_home) |raw_state_home| {
            const state_home = std.mem.trim(u8, raw_state_home, " \t\r\n");
            if (state_home.len > 0) {
                break :blk try std.fs.path.join(allocator, &.{ state_home, "ziggy-spiderweb", "sandbox" });
            }
        }
        break :blk try std.fs.path.join(allocator, &.{ home.?, ".local", "state", "ziggy-spiderweb", "sandbox" });
    };
    defer allocator.free(sandbox_root);
    return .{
        .mounts_root = try std.fs.path.join(allocator, &.{ sandbox_root, "mounts" }),
        .rootfs_store_root = try std.fs.path.join(allocator, &.{ sandbox_root, "rootfs", "base" }),
        .overlay_root = try std.fs.path.join(allocator, &.{ sandbox_root, "rootfs", "overlays" }),
        .snapshot_root = try std.fs.path.join(allocator, &.{ sandbox_root, "rootfs", "snapshots" }),
    };
}

pub fn init(allocator: std.mem.Allocator, config_path: ?[]const u8) !Config {
    const path = config_path orelse try defaultConfigPath(allocator);
    var sandbox_defaults = try resolveSandboxPathDefaults(allocator);
    defer sandbox_defaults.deinit(allocator);

    var self = Config{
        .allocator = allocator,
        .server = .{
            .bind = try allocator.dupe(u8, "127.0.0.1"),
            .port = 18790,
        },
        .log = .{
            .level = try allocator.dupe(u8, "info"),
        },
        .runtime = .{
            .inbound_queue_max = 512,
            .brain_tick_queue_max = 256,
            .outbound_queue_max = 512,
            .control_queue_max = 128,
            .connection_worker_threads = 16,
            .connection_queue_max = 128,
            .runtime_worker_threads = 2,
            .runtime_request_queue_max = 128,
            .chat_operation_timeout_ms = 300_000,
            .control_operation_timeout_ms = 5_000,
            .run_checkpoint_interval_steps = 1,
            .run_auto_resume_on_boot = true,
            .tool_retry_max_attempts = 3,
            .tool_lease_timeout_ms = 30_000,
            .max_inflight_tool_calls_per_run = 1,
            .max_run_steps = 1024,
            .default_agent_id = try allocator.dupe(u8, ""),
            .spider_web_root = try allocator.dupe(u8, ""),
            .ltm_directory = try allocator.dupe(u8, ".spiderweb-ltm"),
            .ltm_filename = try allocator.dupe(u8, "runtime-memory.db"),
            .assets_dir = try allocator.dupe(u8, "templates"),
            .agents_dir = try allocator.dupe(u8, "agents"),
            .sandbox_enabled = builtin.os.tag == .linux and !builtin.is_test,
            .sandbox_mounts_root = try allocator.dupe(u8, sandbox_defaults.mounts_root),
            .sandbox_rootfs_base_ref = try allocator.dupe(u8, "debian:bookworm-slim"),
            .sandbox_rootfs_store_root = try allocator.dupe(u8, sandbox_defaults.rootfs_store_root),
            .sandbox_overlay_root = try allocator.dupe(u8, sandbox_defaults.overlay_root),
            .sandbox_snapshot_root = try allocator.dupe(u8, sandbox_defaults.snapshot_root),
            .sandbox_launcher = try allocator.dupe(u8, "bwrap"),
            .sandbox_fs_mount_bin = try allocator.dupe(u8, "spiderweb-fs-mount"),
        },
        .config_path = path,
    };
    errdefer self.deinit();

    // Try to load existing config
    self.load() catch |err| {
        if (err == error.FileNotFound) {
            // Create default config
            try self.save();
            std.log.info("Created default config at {s}", .{path});
        } else if (err == error.InvalidConfig) {
            return err;
        } else {
            std.log.warn("Failed to load config: {s}, using defaults", .{@errorName(err)});
        }
    };

    try self.validateRuntimeConfig();
    return self;
}

pub fn normalizeRuntimePathsFromSpiderWebRoot(self: *Config) !void {
    const root = std.mem.trim(u8, self.runtime.spider_web_root, " \t\r\n");
    if (root.len == 0) return;

    try self.normalizeRuntimeDirPath(&self.runtime.assets_dir, root);
    try self.normalizeRuntimeDirPath(&self.runtime.agents_dir, root);
    try self.normalizeRuntimeExecutablePath(&self.runtime.sandbox_fs_mount_bin, root);
}

pub fn deinit(self: *Config) void {
    self.allocator.free(self.config_path);
    self.allocator.free(self.server.bind);
    self.allocator.free(self.log.level);
    self.runtime.deinit(self.allocator);
}

fn defaultConfigPath(allocator: std.mem.Allocator) ![]const u8 {
    const configured = std.process.getEnvVarOwned(allocator, "SPIDERWEB_CONFIG") catch null;
    if (configured) |path| {
        if (path.len > 0) return path;
        allocator.free(path);
    }

    if (@import("builtin").os.tag == .windows) {
        const home = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch {
            const cwd = std.process.getCwdAlloc(allocator) catch return try allocator.dupe(u8, ".spiderweb.json");
            defer allocator.free(cwd);
            return try std.fs.path.join(allocator, &.{ cwd, ".spiderweb.json" });
        };
        defer allocator.free(home);
        return try std.fs.path.join(allocator, &.{ home, ".spiderweb.json" });
    }

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        const cwd = std.process.getCwdAlloc(allocator) catch return try allocator.dupe(u8, ".spiderweb.json");
        defer allocator.free(cwd);
        return try std.fs.path.join(allocator, &.{ cwd, ".spiderweb.json" });
    };
    defer allocator.free(home);

    return try std.fs.path.join(allocator, &.{ home, ".config", "spiderweb", "config.json" });
}

pub fn load(self: *Config) !void {
    const file = if (std.fs.path.isAbsolute(self.config_path))
        try std.fs.openFileAbsolute(self.config_path, .{ .mode = .read_only })
    else
        try std.fs.cwd().openFile(self.config_path, .{ .mode = .read_only });
    defer file.close();

    const contents = try file.readToEndAlloc(self.allocator, 1024 * 1024);
    defer self.allocator.free(contents);

    var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, contents, .{});
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidConfig;

    // Server config
    if (root.object.get("server")) |server_val| {
        if (server_val == .object) {
            if (server_val.object.get("bind")) |bind| {
                if (bind == .string) {
                    self.allocator.free(self.server.bind);
                    self.server.bind = try self.allocator.dupe(u8, bind.string);
                }
            }
            if (server_val.object.get("port")) |port| {
                if (port == .integer) {
                    self.server.port = @intCast(port.integer);
                }
            }
        }
    }

    // Log config
    if (root.object.get("log")) |log_val| {
        if (log_val == .object) {
            if (log_val.object.get("level")) |level| {
                if (level == .string) {
                    self.allocator.free(self.log.level);
                    self.log.level = try self.allocator.dupe(u8, level.string);
                }
            }
        }
    }

    if (root.object.get("runtime")) |runtime_val| {
        if (runtime_val == .object) {
            if (runtime_val.object.get("inbound_queue_max")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.inbound_queue_max = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("brain_tick_queue_max")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.brain_tick_queue_max = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("outbound_queue_max")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.outbound_queue_max = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("control_queue_max")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.control_queue_max = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("connection_worker_threads")) |value| {
                if (value == .integer and value.integer >= 0) {
                    self.runtime.connection_worker_threads = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("connection_queue_max")) |value| {
                if (value == .integer and value.integer >= 0) {
                    self.runtime.connection_queue_max = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("runtime_worker_threads")) |value| {
                if (value == .integer and value.integer >= 0) {
                    self.runtime.runtime_worker_threads = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("runtime_request_queue_max")) |value| {
                if (value == .integer and value.integer >= 0) {
                    self.runtime.runtime_request_queue_max = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("chat_operation_timeout_ms")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.chat_operation_timeout_ms = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("control_operation_timeout_ms")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.control_operation_timeout_ms = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("run_checkpoint_interval_steps")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.run_checkpoint_interval_steps = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("run_auto_resume_on_boot")) |value| {
                if (value == .bool) {
                    self.runtime.run_auto_resume_on_boot = value.bool;
                }
            }
            if (runtime_val.object.get("tool_retry_max_attempts")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.tool_retry_max_attempts = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("tool_lease_timeout_ms")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.tool_lease_timeout_ms = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("max_inflight_tool_calls_per_run")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.max_inflight_tool_calls_per_run = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("max_run_steps")) |value| {
                if (value == .integer and value.integer > 0) {
                    self.runtime.max_run_steps = @intCast(value.integer);
                }
            }
            if (runtime_val.object.get("default_agent_id")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.default_agent_id);
                    self.runtime.default_agent_id = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("spider_web_root")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.spider_web_root);
                    self.runtime.spider_web_root = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("ltm_directory")) |value| {
                if (value == .string) {
                    self.allocator.free(self.runtime.ltm_directory);
                    self.runtime.ltm_directory = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("ltm_filename")) |value| {
                if (value == .string) {
                    self.allocator.free(self.runtime.ltm_filename);
                    self.runtime.ltm_filename = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("assets_dir")) |value| {
                if (value == .string) {
                    self.allocator.free(self.runtime.assets_dir);
                    self.runtime.assets_dir = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("agents_dir")) |value| {
                if (value == .string) {
                    self.allocator.free(self.runtime.agents_dir);
                    self.runtime.agents_dir = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("sandbox_mounts_root")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.sandbox_mounts_root);
                    self.runtime.sandbox_mounts_root = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("sandbox_rootfs_base_ref")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.sandbox_rootfs_base_ref);
                    self.runtime.sandbox_rootfs_base_ref = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("sandbox_rootfs_store_root")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.sandbox_rootfs_store_root);
                    self.runtime.sandbox_rootfs_store_root = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("sandbox_overlay_root")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.sandbox_overlay_root);
                    self.runtime.sandbox_overlay_root = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("sandbox_snapshot_root")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.sandbox_snapshot_root);
                    self.runtime.sandbox_snapshot_root = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("sandbox_launcher")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.sandbox_launcher);
                    self.runtime.sandbox_launcher = try self.allocator.dupe(u8, value.string);
                }
            }
            if (runtime_val.object.get("sandbox_fs_mount_bin")) |value| {
                if (value == .string and value.string.len > 0) {
                    self.allocator.free(self.runtime.sandbox_fs_mount_bin);
                    self.runtime.sandbox_fs_mount_bin = try self.allocator.dupe(u8, value.string);
                }
            }
        }
    }

    try self.validateRuntimeConfig();
}

fn validateRuntimeConfig(self: *Config) !void {
    if (!runtimeRequiresSandboxValidation(self.runtime)) return;

    const mounts_root = try requireAbsoluteRuntimePath("runtime.sandbox_mounts_root", self.runtime.sandbox_mounts_root);
    const rootfs_store_root = try requireAbsoluteRuntimePath("runtime.sandbox_rootfs_store_root", self.runtime.sandbox_rootfs_store_root);
    const overlay_root = try requireAbsoluteRuntimePath("runtime.sandbox_overlay_root", self.runtime.sandbox_overlay_root);
    const snapshot_root = try requireAbsoluteRuntimePath("runtime.sandbox_snapshot_root", self.runtime.sandbox_snapshot_root);

    _ = try requireRuntimeField("runtime.sandbox_rootfs_base_ref", self.runtime.sandbox_rootfs_base_ref);
    _ = try requireRuntimeField("runtime.sandbox_launcher", self.runtime.sandbox_launcher);
    _ = try requireRuntimeField("runtime.sandbox_fs_mount_bin", self.runtime.sandbox_fs_mount_bin);
    try ensureRuntimePathsDoNotOverlap(
        "runtime.sandbox_mounts_root",
        mounts_root,
        "runtime.sandbox_rootfs_store_root",
        rootfs_store_root,
    );
    try ensureRuntimePathsDoNotOverlap(
        "runtime.sandbox_mounts_root",
        mounts_root,
        "runtime.sandbox_overlay_root",
        overlay_root,
    );
    try ensureRuntimePathsDoNotOverlap(
        "runtime.sandbox_mounts_root",
        mounts_root,
        "runtime.sandbox_snapshot_root",
        snapshot_root,
    );
    try ensureRuntimePathsDoNotOverlap(
        "runtime.sandbox_rootfs_store_root",
        rootfs_store_root,
        "runtime.sandbox_overlay_root",
        overlay_root,
    );
    try ensureRuntimePathsDoNotOverlap(
        "runtime.sandbox_rootfs_store_root",
        rootfs_store_root,
        "runtime.sandbox_snapshot_root",
        snapshot_root,
    );
    try ensureRuntimePathsDoNotOverlap(
        "runtime.sandbox_overlay_root",
        overlay_root,
        "runtime.sandbox_snapshot_root",
        snapshot_root,
    );
}

fn requireRuntimeField(field_name: []const u8, value: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) {
        if (!builtin.is_test) {
            std.log.err("invalid config: {s} is required and cannot be empty", .{field_name});
        }
        return error.InvalidConfig;
    }
    return trimmed;
}

fn trimTrailingSlashes(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 1 and out[out.len - 1] == '/') {
        out = out[0 .. out.len - 1];
    }
    return out;
}

fn requireAbsoluteRuntimePath(field_name: []const u8, value: []const u8) ![]const u8 {
    const trimmed = trimTrailingSlashes(try requireRuntimeField(field_name, value));
    if (!std.fs.path.isAbsolute(trimmed)) {
        if (!builtin.is_test) {
            std.log.err(
                "invalid config: {s} must be an absolute path, got '{s}'",
                .{ field_name, trimmed },
            );
        }
        return error.InvalidConfig;
    }
    return trimmed;
}

fn pathIsAncestorOrEqual(ancestor: []const u8, path: []const u8) bool {
    if (ancestor.len == 0 or path.len == 0) return false;
    if (!std.mem.startsWith(u8, path, ancestor)) return false;
    if (ancestor.len == path.len) return true;
    if (std.mem.eql(u8, ancestor, "/")) return true;
    return path[ancestor.len] == '/';
}

fn ensureRuntimePathsDoNotOverlap(
    field_a: []const u8,
    path_a: []const u8,
    field_b: []const u8,
    path_b: []const u8,
) !void {
    if (pathIsAncestorOrEqual(path_a, path_b) or pathIsAncestorOrEqual(path_b, path_a)) {
        if (!builtin.is_test) {
            std.log.err(
                "invalid config: {s}='{s}' overlaps {s}='{s}'",
                .{ field_a, path_a, field_b, path_b },
            );
        }
        return error.InvalidConfig;
    }
}

fn runtimeRequiresSandboxValidation(runtime: RuntimeConfig) bool {
    return builtin.os.tag == .linux and runtime.sandbox_enabled;
}
pub fn save(self: Config) !void {
    // Ensure parent directory exists
    if (std.fs.path.dirname(self.config_path)) |dir| {
        if (std.fs.path.isAbsolute(dir)) {
            var root_dir = try std.fs.openDirAbsolute("/", .{});
            defer root_dir.close();
            const rel_dir = std.mem.trimLeft(u8, dir, "/");
            if (rel_dir.len > 0) {
                root_dir.makePath(rel_dir) catch |err| {
                    if (err != error.PathAlreadyExists) return err;
                };
            }
        } else {
            std.fs.cwd().makePath(dir) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }
    }

    const file = if (std.fs.path.isAbsolute(self.config_path))
        try std.fs.createFileAbsolute(self.config_path, .{ .truncate = true })
    else
        try std.fs.cwd().createFile(self.config_path, .{ .truncate = true });
    defer file.close();

    // Write JSON manually for control using a buffer for formatting
    var buf: [1024]u8 = undefined;

    try file.writeAll("{\n");

    // Server
    try file.writeAll("  \"server\": {\n");
    const server_line1 = try std.fmt.bufPrint(&buf, "    \"bind\": \"{s}\",\n", .{self.server.bind});
    try file.writeAll(server_line1);
    const server_line2 = try std.fmt.bufPrint(&buf, "    \"port\": {d}\n", .{self.server.port});
    try file.writeAll(server_line2);
    try file.writeAll("  },\n");

    // Log
    try file.writeAll("  \"log\": {\n");
    const log_line = try std.fmt.bufPrint(&buf, "    \"level\": \"{s}\"\n", .{self.log.level});
    try file.writeAll(log_line);
    try file.writeAll("  },\n");

    try file.writeAll("  \"runtime\": {\n");
    const inbound_line = try std.fmt.bufPrint(&buf, "    \"inbound_queue_max\": {d},\n", .{self.runtime.inbound_queue_max});
    try file.writeAll(inbound_line);
    const tick_line = try std.fmt.bufPrint(&buf, "    \"brain_tick_queue_max\": {d},\n", .{self.runtime.brain_tick_queue_max});
    try file.writeAll(tick_line);
    const outbound_line = try std.fmt.bufPrint(&buf, "    \"outbound_queue_max\": {d},\n", .{self.runtime.outbound_queue_max});
    try file.writeAll(outbound_line);
    const control_line = try std.fmt.bufPrint(&buf, "    \"control_queue_max\": {d},\n", .{self.runtime.control_queue_max});
    try file.writeAll(control_line);
    const worker_threads_line = try std.fmt.bufPrint(&buf, "    \"connection_worker_threads\": {d},\n", .{self.runtime.connection_worker_threads});
    try file.writeAll(worker_threads_line);
    const connection_queue_line = try std.fmt.bufPrint(&buf, "    \"connection_queue_max\": {d},\n", .{self.runtime.connection_queue_max});
    try file.writeAll(connection_queue_line);
    const runtime_workers_line = try std.fmt.bufPrint(&buf, "    \"runtime_worker_threads\": {d},\n", .{self.runtime.runtime_worker_threads});
    try file.writeAll(runtime_workers_line);
    const runtime_queue_line = try std.fmt.bufPrint(&buf, "    \"runtime_request_queue_max\": {d},\n", .{self.runtime.runtime_request_queue_max});
    try file.writeAll(runtime_queue_line);
    const chat_timeout_line = try std.fmt.bufPrint(&buf, "    \"chat_operation_timeout_ms\": {d},\n", .{self.runtime.chat_operation_timeout_ms});
    try file.writeAll(chat_timeout_line);
    const control_timeout_line = try std.fmt.bufPrint(&buf, "    \"control_operation_timeout_ms\": {d},\n", .{self.runtime.control_operation_timeout_ms});
    try file.writeAll(control_timeout_line);
    const run_checkpoint_line = try std.fmt.bufPrint(&buf, "    \"run_checkpoint_interval_steps\": {d},\n", .{self.runtime.run_checkpoint_interval_steps});
    try file.writeAll(run_checkpoint_line);
    const run_auto_resume_line = try std.fmt.bufPrint(&buf, "    \"run_auto_resume_on_boot\": {},\n", .{self.runtime.run_auto_resume_on_boot});
    try file.writeAll(run_auto_resume_line);
    const retry_attempts_line = try std.fmt.bufPrint(&buf, "    \"tool_retry_max_attempts\": {d},\n", .{self.runtime.tool_retry_max_attempts});
    try file.writeAll(retry_attempts_line);
    const lease_timeout_line = try std.fmt.bufPrint(&buf, "    \"tool_lease_timeout_ms\": {d},\n", .{self.runtime.tool_lease_timeout_ms});
    try file.writeAll(lease_timeout_line);
    const inflight_line = try std.fmt.bufPrint(&buf, "    \"max_inflight_tool_calls_per_run\": {d},\n", .{self.runtime.max_inflight_tool_calls_per_run});
    try file.writeAll(inflight_line);
    const max_run_steps_line = try std.fmt.bufPrint(&buf, "    \"max_run_steps\": {d},\n", .{self.runtime.max_run_steps});
    try file.writeAll(max_run_steps_line);
    const default_agent_line = try std.fmt.bufPrint(&buf, "    \"default_agent_id\": \"{s}\",\n", .{self.runtime.default_agent_id});
    try file.writeAll(default_agent_line);
    const spider_web_root_line = try std.fmt.bufPrint(&buf, "    \"spider_web_root\": \"{s}\",\n", .{self.runtime.spider_web_root});
    try file.writeAll(spider_web_root_line);
    const ltm_dir_line = try std.fmt.bufPrint(&buf, "    \"ltm_directory\": \"{s}\",\n", .{self.runtime.ltm_directory});
    try file.writeAll(ltm_dir_line);
    const ltm_file_line = try std.fmt.bufPrint(&buf, "    \"ltm_filename\": \"{s}\",\n", .{self.runtime.ltm_filename});
    try file.writeAll(ltm_file_line);
    const assets_dir_line = try std.fmt.bufPrint(&buf, "    \"assets_dir\": \"{s}\",\n", .{self.runtime.assets_dir});
    try file.writeAll(assets_dir_line);
    const agents_dir_line = try std.fmt.bufPrint(&buf, "    \"agents_dir\": \"{s}\",\n", .{self.runtime.agents_dir});
    try file.writeAll(agents_dir_line);
    const sandbox_mounts_line = try std.fmt.bufPrint(&buf, "    \"sandbox_mounts_root\": \"{s}\",\n", .{self.runtime.sandbox_mounts_root});
    try file.writeAll(sandbox_mounts_line);
    const sandbox_rootfs_base_line = try std.fmt.bufPrint(&buf, "    \"sandbox_rootfs_base_ref\": \"{s}\",\n", .{self.runtime.sandbox_rootfs_base_ref});
    try file.writeAll(sandbox_rootfs_base_line);
    const sandbox_rootfs_store_line = try std.fmt.bufPrint(&buf, "    \"sandbox_rootfs_store_root\": \"{s}\",\n", .{self.runtime.sandbox_rootfs_store_root});
    try file.writeAll(sandbox_rootfs_store_line);
    const sandbox_overlay_line = try std.fmt.bufPrint(&buf, "    \"sandbox_overlay_root\": \"{s}\",\n", .{self.runtime.sandbox_overlay_root});
    try file.writeAll(sandbox_overlay_line);
    const sandbox_snapshot_line = try std.fmt.bufPrint(&buf, "    \"sandbox_snapshot_root\": \"{s}\",\n", .{self.runtime.sandbox_snapshot_root});
    try file.writeAll(sandbox_snapshot_line);
    const sandbox_launcher_line = try std.fmt.bufPrint(&buf, "    \"sandbox_launcher\": \"{s}\",\n", .{self.runtime.sandbox_launcher});
    try file.writeAll(sandbox_launcher_line);
    const sandbox_fs_mount_line = try std.fmt.bufPrint(&buf, "    \"sandbox_fs_mount_bin\": \"{s}\"\n", .{self.runtime.sandbox_fs_mount_bin});
    try file.writeAll(sandbox_fs_mount_line);
    try file.writeAll("  }\n");

    try file.writeAll("}\n");
}

pub fn setServer(self: *Config, bind: ?[]const u8, port: ?u16) !void {
    if (bind) |b| {
        self.allocator.free(self.server.bind);
        self.server.bind = try self.allocator.dupe(u8, b);
    }
    if (port) |p| {
        self.server.port = p;
    }

    try self.save();
}

pub fn setLogLevel(self: *Config, level: []const u8) !void {
    self.allocator.free(self.log.level);
    self.log.level = try self.allocator.dupe(u8, level);
    try self.save();
}

pub fn setDefaultAgentId(self: *Config, agent_id: []const u8) !void {
    self.allocator.free(self.runtime.default_agent_id);
    self.runtime.default_agent_id = try self.allocator.dupe(u8, agent_id);
    try self.save();
}

fn normalizeRuntimeDirPath(self: *Config, field: *[]const u8, root: []const u8) !void {
    if (std.fs.path.isAbsolute(field.*)) return;
    const joined = try std.fs.path.join(self.allocator, &.{ root, field.* });
    self.allocator.free(field.*);
    field.* = joined;
}

fn normalizeRuntimeExecutablePath(self: *Config, field: *[]const u8, root: []const u8) !void {
    if (!runtimePathLooksRelativeFilesystemPath(field.*)) return;
    const joined = try std.fs.path.join(self.allocator, &.{ root, field.* });
    self.allocator.free(field.*);
    field.* = joined;
}

fn runtimePathLooksRelativeFilesystemPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.fs.path.isAbsolute(path)) return false;
    if (path[0] == '.') return true;
    return std.mem.indexOfAny(u8, path, "/\\") != null;
}

test "Config defaults" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_root, "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    try std.testing.expectEqualStrings("127.0.0.1", config.server.bind);
    try std.testing.expectEqual(@as(u16, 18790), config.server.port);
    try std.testing.expectEqual(@as(usize, 512), config.runtime.inbound_queue_max);
    try std.testing.expectEqual(@as(usize, 16), config.runtime.connection_worker_threads);
    try std.testing.expectEqual(@as(usize, 2), config.runtime.runtime_worker_threads);
    try std.testing.expectEqual(@as(usize, 128), config.runtime.runtime_request_queue_max);
    try std.testing.expectEqual(@as(u64, 300_000), config.runtime.chat_operation_timeout_ms);
    try std.testing.expectEqual(@as(u64, 5_000), config.runtime.control_operation_timeout_ms);
    try std.testing.expectEqual(@as(usize, 1), config.runtime.run_checkpoint_interval_steps);
    try std.testing.expect(config.runtime.run_auto_resume_on_boot);
    try std.testing.expectEqual(@as(usize, 3), config.runtime.tool_retry_max_attempts);
    try std.testing.expectEqual(@as(u64, 30_000), config.runtime.tool_lease_timeout_ms);
    try std.testing.expectEqual(@as(usize, 1), config.runtime.max_inflight_tool_calls_per_run);
    try std.testing.expectEqual(@as(usize, 1024), config.runtime.max_run_steps);
    try std.testing.expectEqualStrings("", config.runtime.default_agent_id);
    try std.testing.expectEqualStrings("", config.runtime.spider_web_root);
    try std.testing.expectEqualStrings(".spiderweb-ltm", config.runtime.ltm_directory);
}

test "Config ignores deprecated runtime.sandbox_enabled field and does not persist it" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_root, "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    config.runtime.sandbox_enabled = true;

    const legacy_contents =
        \\{
        \\  "runtime": {
        \\    "sandbox_enabled": false
        \\  }
        \\}
    ;
    try std.fs.cwd().writeFile(.{
        .sub_path = cfg_path,
        .data = legacy_contents,
    });

    try config.load();
    try std.testing.expect(config.runtime.sandbox_enabled);

    try config.save();
    const saved = try std.fs.cwd().readFileAlloc(allocator, cfg_path, 1024 * 64);
    defer allocator.free(saved);
    try std.testing.expect(std.mem.indexOf(u8, saved, "\"sandbox_enabled\"") == null);
}

test "Config validation allows disabled sandbox runtime" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_root, "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    config.runtime.sandbox_enabled = false;
    try config.validateRuntimeConfig();
}

test "Config validation rejects overlapping sandbox roots" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_root, "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    config.allocator.free(config.runtime.sandbox_mounts_root);
    config.runtime.sandbox_mounts_root = try allocator.dupe(u8, "/tmp/spiderweb-overlap");
    config.allocator.free(config.runtime.sandbox_overlay_root);
    config.runtime.sandbox_overlay_root = try allocator.dupe(u8, "/tmp/spiderweb-overlap");

    try std.testing.expectError(error.InvalidConfig, config.validateRuntimeConfig());
}

test "Config validation rejects empty rootfs base ref" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_root, "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    config.allocator.free(config.runtime.sandbox_rootfs_base_ref);
    config.runtime.sandbox_rootfs_base_ref = try allocator.dupe(u8, "   ");

    try std.testing.expectError(error.InvalidConfig, config.validateRuntimeConfig());
}

test "Config normalizes runtime paths from spider_web_root" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_root, "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    config.allocator.free(config.runtime.spider_web_root);
    config.runtime.spider_web_root = try allocator.dupe(u8, tmp_root);

    try config.normalizeRuntimePathsFromSpiderWebRoot();

    const expected_assets = try std.fs.path.join(allocator, &.{ tmp_root, "templates" });
    defer allocator.free(expected_assets);
    const expected_agents = try std.fs.path.join(allocator, &.{ tmp_root, "agents" });
    defer allocator.free(expected_agents);

    try std.testing.expectEqualStrings(expected_assets, config.runtime.assets_dir);
    try std.testing.expectEqualStrings(expected_agents, config.runtime.agents_dir);
    try std.testing.expectEqualStrings("spiderweb-fs-mount", config.runtime.sandbox_fs_mount_bin);
}

test "Config normalizes relative sandbox_fs_mount_bin from spider_web_root" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_root, "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    config.allocator.free(config.runtime.spider_web_root);
    config.runtime.spider_web_root = try allocator.dupe(u8, tmp_root);
    config.allocator.free(config.runtime.sandbox_fs_mount_bin);
    config.runtime.sandbox_fs_mount_bin = try allocator.dupe(u8, "zig-out/bin/spiderweb-fs-mount");

    try config.normalizeRuntimePathsFromSpiderWebRoot();

    const expected_bin = try std.fs.path.join(allocator, &.{ tmp_root, "zig-out", "bin", "spiderweb-fs-mount" });
    defer allocator.free(expected_bin);
    try std.testing.expectEqualStrings(expected_bin, config.runtime.sandbox_fs_mount_bin);
}
