const std = @import("std");

const Config = @This();

pub const ProviderConfig = struct {
    name: []const u8,
    model: ?[]const u8 = null,
    api_key: ?[]const u8 = null, // Only used if keyring not available
    base_url: ?[]const u8 = null,
};

pub const ServerConfig = struct {
    bind: []const u8 = "127.0.0.1",
    port: u16 = 18790,
};

pub const LogConfig = struct {
    level: []const u8 = "info",
};

allocator: std.mem.Allocator,
server: ServerConfig,
provider: ProviderConfig,
log: LogConfig,
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
}

fn defaultConfigPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        return allocator.dupe(u8, ".spiderweb.json");
    };
    defer allocator.free(home);

    return try std.fs.path.join(allocator, &.{ home, ".config", "spiderweb", "config.json" });
}

pub fn load(self: *Config) !void {
    const file = try std.fs.openFileAbsolute(self.config_path, .{ .mode = .read_only });
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
            if (provider_val.object.get("api_key")) |key| {
                if (key == .string) {
                    if (self.provider.api_key) |k| self.allocator.free(k);
                    self.provider.api_key = try self.allocator.dupe(u8, key.string);
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
}
pub fn save(self: Config) !void {
    // Ensure parent directory exists
    if (std.fs.path.dirname(self.config_path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }

    const file = try std.fs.createFileAbsolute(self.config_path, .{ .truncate = true });
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
    if (self.provider.api_key) |k| {
        const key_line = try std.fmt.bufPrint(&buf, ",\n    \"api_key\": \"{s}\"", .{k});
        try file.writeAll(key_line);
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

pub fn getApiKey(self: Config, allocator: std.mem.Allocator) !?[]const u8 {
    // Priority: 1) Config file, 2) Environment variable
    if (self.provider.api_key) |key| {
        return try allocator.dupe(u8, key);
    }

    // Try environment variable based on provider
    const env_var = switch (self.provider.name[0]) {
        'o' => if (std.mem.startsWith(u8, self.provider.name, "openai-codex"))
            "OPENAI_CODEX_API_KEY"
        else
            "OPENAI_API_KEY",
        'k' => "KIMI_API_KEY",
        else => "OPENAI_API_KEY",
    };

    return std.process.getEnvVarOwned(allocator, env_var) catch null;
}

test "Config defaults" {
    const allocator = std.testing.allocator;
    const config = try Config.init(allocator, null);
    defer config.deinit();

    try std.testing.expectEqualStrings("openai", config.provider.name);
    try std.testing.expectEqualStrings("gpt-4o-mini", config.provider.model.?);
    try std.testing.expectEqualStrings("127.0.0.1", config.server.bind);
    try std.testing.expectEqual(@as(u16, 18790), config.server.port);
}
