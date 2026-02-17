const builtin = @import("builtin");
const std = @import("std");

pub const CredentialError = error{
    SecureStoreUnavailable,
    InvalidProvider,
    StoreFailed,
    ClearFailed,
};

pub const Backend = enum {
    linux_secret_tool,
    none,
};

const service_name = "ziggyspiderweb";
const key_kind = "provider_api_key";

pub const CredentialStore = struct {
    allocator: std.mem.Allocator,
    backend: Backend,

    pub fn init(allocator: std.mem.Allocator) CredentialStore {
        return .{
            .allocator = allocator,
            .backend = detectBackend(allocator),
        };
    }

    pub fn backendName(self: CredentialStore) []const u8 {
        return switch (self.backend) {
            .linux_secret_tool => "linux-secret-tool",
            .none => "none",
        };
    }

    pub fn supportsSecureStorage(self: CredentialStore) bool {
        return self.backend != .none;
    }

    pub fn getProviderApiKey(self: CredentialStore, provider_name: []const u8) ?[]u8 {
        if (!isValidProvider(provider_name)) return null;
        return switch (self.backend) {
            .linux_secret_tool => lookupLinuxSecretTool(self.allocator, provider_name),
            .none => null,
        };
    }

    pub fn setProviderApiKey(self: CredentialStore, provider_name: []const u8, api_key: []const u8) CredentialError!void {
        if (!isValidProvider(provider_name)) return CredentialError.InvalidProvider;
        return switch (self.backend) {
            .linux_secret_tool => storeLinuxSecretTool(self.allocator, provider_name, api_key) catch CredentialError.StoreFailed,
            .none => CredentialError.SecureStoreUnavailable,
        };
    }

    pub fn clearProviderApiKey(self: CredentialStore, provider_name: []const u8) CredentialError!void {
        if (!isValidProvider(provider_name)) return CredentialError.InvalidProvider;
        return switch (self.backend) {
            .linux_secret_tool => clearLinuxSecretTool(self.allocator, provider_name) catch CredentialError.ClearFailed,
            .none => CredentialError.SecureStoreUnavailable,
        };
    }
};

fn detectBackend(allocator: std.mem.Allocator) Backend {
    if (builtin.os.tag == .linux and commandExists(allocator, "secret-tool")) {
        return .linux_secret_tool;
    }
    return .none;
}

fn commandExists(allocator: std.mem.Allocator, command: []const u8) bool {
    var child = std.process.Child.init(&[_][]const u8{ command, "--help" }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch return false;
    _ = child.wait() catch return false;
    return true;
}

fn isValidProvider(provider_name: []const u8) bool {
    if (provider_name.len == 0) return false;
    for (provider_name) |ch| {
        if (std.ascii.isAlphanumeric(ch)) continue;
        if (ch == '-' or ch == '_' or ch == '.') continue;
        return false;
    }
    return true;
}

fn lookupLinuxSecretTool(allocator: std.mem.Allocator, provider_name: []const u8) ?[]u8 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "secret-tool",
            "lookup",
            "service",
            service_name,
            "kind",
            key_kind,
            "provider",
            provider_name,
        },
        .max_output_bytes = 32 * 1024,
    }) catch return null;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) return null,
        else => return null,
    }

    const trimmed = std.mem.trimRight(u8, result.stdout, "\r\n");
    if (trimmed.len == 0) return null;
    return allocator.dupe(u8, trimmed) catch null;
}

fn storeLinuxSecretTool(allocator: std.mem.Allocator, provider_name: []const u8, api_key: []const u8) !void {
    const label = try std.fmt.allocPrint(allocator, "ZiggySpiderweb {s} API key", .{provider_name});
    defer allocator.free(label);

    var child = std.process.Child.init(&[_][]const u8{
        "secret-tool",
        "store",
        "--label",
        label,
        "service",
        service_name,
        "kind",
        key_kind,
        "provider",
        provider_name,
    }, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;

    try child.spawn();
    errdefer _ = child.kill() catch {};

    if (child.stdin) |*stdin_pipe| {
        try stdin_pipe.writeAll(api_key);
        stdin_pipe.close();
        child.stdin = null;
    }

    var stderr_bytes: ?[]u8 = null;
    defer if (stderr_bytes) |bytes| allocator.free(bytes);
    if (child.stderr) |*stderr_pipe| {
        stderr_bytes = stderr_pipe.readToEndAlloc(allocator, 16 * 1024) catch null;
    }

    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                if (stderr_bytes) |bytes| {
                    const err_text = std.mem.trim(u8, bytes, " \t\r\n");
                    if (err_text.len > 0) {
                        std.log.warn("secret-tool store failed: {s}", .{err_text});
                    }
                }
                return error.CommandFailed;
            }
        },
        else => return error.CommandFailed,
    }
}

fn clearLinuxSecretTool(allocator: std.mem.Allocator, provider_name: []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "secret-tool",
            "clear",
            "service",
            service_name,
            "kind",
            key_kind,
            "provider",
            provider_name,
        },
        .max_output_bytes = 16 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code == 0 or code == 1) return,
        else => {},
    }
    return error.CommandFailed;
}

test "credential_store: provider validation rejects unsafe names" {
    try std.testing.expect(!isValidProvider(""));
    try std.testing.expect(!isValidProvider("../openai"));
    try std.testing.expect(!isValidProvider("openai codex"));
    try std.testing.expect(isValidProvider("openai-codex"));
    try std.testing.expect(isValidProvider("kimi_code"));
}

test "credential_store: init selects a backend enum" {
    const store = CredentialStore.init(std.testing.allocator);
    switch (store.backend) {
        .linux_secret_tool, .none => {},
    }
}
