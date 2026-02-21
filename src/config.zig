const std = @import("std");
const credential_store = @import("credential_store.zig");

const Config = @This();

pub const ProviderConfig = struct {
    name: []const u8,
    model: ?[]const u8 = null,
    api_key: ?[]const u8 = null, // Test-only injection path (not loaded/saved by config CLI).
    base_url: ?[]const u8 = null,
};

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
    connection_worker_threads: usize = 4,
    connection_queue_max: usize = 128,
    runtime_worker_threads: usize = 2,
    runtime_request_queue_max: usize = 128,
    chat_operation_timeout_ms: u64 = 120_000,
    control_operation_timeout_ms: u64 = 5_000,
    default_agent_id: []const u8 = "default",
    ltm_directory: []const u8 = ".spiderweb-ltm",
    ltm_filename: []const u8 = "runtime-memory.db",
    assets_dir: []const u8 = "templates",
    agents_dir: []const u8 = "agents",

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
            .default_agent_id = try allocator.dupe(u8, self.default_agent_id),
            .ltm_directory = try allocator.dupe(u8, self.ltm_directory),
            .ltm_filename = try allocator.dupe(u8, self.ltm_filename),
            .assets_dir = try allocator.dupe(u8, self.assets_dir),
            .agents_dir = try allocator.dupe(u8, self.agents_dir),
        };
    }

    pub fn deinit(self: *RuntimeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.default_agent_id);
        allocator.free(self.ltm_directory);
        allocator.free(self.ltm_filename);
        allocator.free(self.assets_dir);
        allocator.free(self.agents_dir);
    }
};

allocator: std.mem.Allocator,
server: ServerConfig,
provider: ProviderConfig,
log: LogConfig,
runtime: RuntimeConfig,
config_path: []const u8,

const default_config =
    \\{
    \\  "server": {
    \\    "bind": "127.0.0.1",
    \\    "port": 18790
    \\  },
    \\  "provider": {
    \\    "name": "openai",
    \\    "model": "gpt-4o-mini"
    \\  },
    \\  "log": {
    \\    "level": "info"
    \\  },
    \\  "runtime": {
    \\    "inbound_queue_max": 512,
    \\    "brain_tick_queue_max": 256,
    \\    "outbound_queue_max": 512,
    \\    "control_queue_max": 128,
    \\    "connection_worker_threads": 4,
    \\    "connection_queue_max": 128,
    \\    "runtime_worker_threads": 2,
    \\    "runtime_request_queue_max": 128,
    \\    "chat_operation_timeout_ms": 120000,
    \\    "control_operation_timeout_ms": 5000,
    \\    "default_agent_id": "default",
    \\    "ltm_directory": ".spiderweb-ltm",
    \\    "ltm_filename": "runtime-memory.db",
    \\    "assets_dir": "templates",
    \\    "agents_dir": "agents"
    \\  }
    \\}
;

pub fn init(allocator: std.mem.Allocator, config_path: ?[]const u8) !Config {
    const path = config_path orelse try defaultConfigPath(allocator);

    var self = Config{
        .allocator = allocator,
        .server = .{
            .bind = try allocator.dupe(u8, "127.0.0.1"),
            .port = 18790,
        },
        .provider = .{
            .name = try allocator.dupe(u8, "openai"),
            .model = try allocator.dupe(u8, "gpt-4o-mini"),
            .api_key = null,
            .base_url = null,
        },
        .log = .{
            .level = try allocator.dupe(u8, "info"),
        },
        .runtime = .{
            .inbound_queue_max = 512,
            .brain_tick_queue_max = 256,
            .outbound_queue_max = 512,
            .control_queue_max = 128,
            .connection_worker_threads = 4,
            .connection_queue_max = 128,
            .runtime_worker_threads = 2,
            .runtime_request_queue_max = 128,
            .chat_operation_timeout_ms = 120_000,
            .control_operation_timeout_ms = 5_000,
            .default_agent_id = try allocator.dupe(u8, "default"),
            .ltm_directory = try allocator.dupe(u8, ".spiderweb-ltm"),
            .ltm_filename = try allocator.dupe(u8, "runtime-memory.db"),
            .assets_dir = try allocator.dupe(u8, "templates"),
            .agents_dir = try allocator.dupe(u8, "agents"),
        },
        .config_path = path,
    };

    // Try to load existing config
    self.load() catch |err| {
        if (err == error.FileNotFound) {
            // Create default config
            try self.save();
            std.log.info("Created default config at {s}", .{path});
        } else {
            std.log.warn("Failed to load config: {s}, using defaults", .{@errorName(err)});
        }
    };

    return self;
}

pub fn deinit(self: *Config) void {
    self.allocator.free(self.config_path);
    self.allocator.free(self.server.bind);
    self.allocator.free(self.provider.name);
    if (self.provider.model) |m| self.allocator.free(m);
    if (self.provider.api_key) |k| self.allocator.free(k);
    if (self.provider.base_url) |b| self.allocator.free(b);
    self.allocator.free(self.log.level);
    self.runtime.deinit(self.allocator);
}

fn defaultConfigPath(allocator: std.mem.Allocator) ![]const u8 {
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

    // Provider config
    if (root.object.get("provider")) |provider_val| {
        if (provider_val == .object) {
            if (provider_val.object.get("name")) |name| {
                if (name == .string) {
                    self.allocator.free(self.provider.name);
                    self.provider.name = try self.allocator.dupe(u8, name.string);
                }
            }
            if (provider_val.object.get("model")) |model| {
                if (model == .string) {
                    if (self.provider.model) |m| self.allocator.free(m);
                    self.provider.model = try self.allocator.dupe(u8, model.string);
                }
            }
            if (provider_val.object.get("base_url")) |url| {
                if (url == .string) {
                    if (self.provider.base_url) |b| self.allocator.free(b);
                    self.provider.base_url = try self.allocator.dupe(u8, url.string);
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
                    if (runtime_val.object.get("default_agent_id")) |value| {
                        if (value == .string and value.string.len > 0) {
                            self.allocator.free(self.runtime.default_agent_id);
                            self.runtime.default_agent_id = try self.allocator.dupe(u8, value.string);
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
                }
            }
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

    // Provider
    try file.writeAll("  \"provider\": {\n");
    const provider_name = try std.fmt.bufPrint(&buf, "    \"name\": \"{s}\"", .{self.provider.name});
    try file.writeAll(provider_name);
    if (self.provider.model) |m| {
        const model_line = try std.fmt.bufPrint(&buf, ",\n    \"model\": \"{s}\"", .{m});
        try file.writeAll(model_line);
    }
    if (self.provider.base_url) |b| {
        const url_line = try std.fmt.bufPrint(&buf, ",\n    \"base_url\": \"{s}\"", .{b});
        try file.writeAll(url_line);
    }
    try file.writeAll("\n  },\n");

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
    const default_agent_line = try std.fmt.bufPrint(&buf, "    \"default_agent_id\": \"{s}\",\n", .{self.runtime.default_agent_id});
    try file.writeAll(default_agent_line);
    const ltm_dir_line = try std.fmt.bufPrint(&buf, "    \"ltm_directory\": \"{s}\",\n", .{self.runtime.ltm_directory});
    try file.writeAll(ltm_dir_line);
    const ltm_file_line = try std.fmt.bufPrint(&buf, "    \"ltm_filename\": \"{s}\",\n", .{self.runtime.ltm_filename});
    try file.writeAll(ltm_file_line);
    const assets_dir_line = try std.fmt.bufPrint(&buf, "    \"assets_dir\": \"{s}\",\n", .{self.runtime.assets_dir});
    try file.writeAll(assets_dir_line);
    const agents_dir_line = try std.fmt.bufPrint(&buf, "    \"agents_dir\": \"{s}\"\n", .{self.runtime.agents_dir});
    try file.writeAll(agents_dir_line);
    try file.writeAll("  }\n");

    try file.writeAll("}\n");
}
pub fn setProvider(self: *Config, name: []const u8, model: ?[]const u8) !void {
    self.allocator.free(self.provider.name);
    self.provider.name = try self.allocator.dupe(u8, name);

    if (model) |m| {
        if (self.provider.model) |old| self.allocator.free(old);
        self.provider.model = try self.allocator.dupe(u8, m);
    }

    try self.save();
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

pub fn getApiKey(self: Config, allocator: std.mem.Allocator) !?[]const u8 {
    const store = credential_store.CredentialStore.init(allocator);
    return store.getProviderApiKey(self.provider.name);
}

test "Config defaults" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const cfg_path = try std.fs.path.join(allocator, &.{ tmp_dir.sub_path[0..], "config.json" });

    var config = try Config.init(allocator, cfg_path);
    defer config.deinit();

    try std.testing.expectEqualStrings("openai", config.provider.name);
    try std.testing.expectEqualStrings("gpt-4o-mini", config.provider.model.?);
    try std.testing.expectEqualStrings("127.0.0.1", config.server.bind);
    try std.testing.expectEqual(@as(u16, 18790), config.server.port);
    try std.testing.expectEqual(@as(usize, 512), config.runtime.inbound_queue_max);
    try std.testing.expectEqual(@as(usize, 4), config.runtime.connection_worker_threads);
    try std.testing.expectEqual(@as(usize, 2), config.runtime.runtime_worker_threads);
    try std.testing.expectEqual(@as(usize, 128), config.runtime.runtime_request_queue_max);
    try std.testing.expectEqual(@as(u64, 120_000), config.runtime.chat_operation_timeout_ms);
    try std.testing.expectEqual(@as(u64, 5_000), config.runtime.control_operation_timeout_ms);
    try std.testing.expectEqualStrings("default", config.runtime.default_agent_id);
    try std.testing.expectEqualStrings(".spiderweb-ltm", config.runtime.ltm_directory);
}
