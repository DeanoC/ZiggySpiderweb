const std = @import("std");
const Config = @import("config.zig");
const provider_models = @import("provider_models.zig");
const ziggy_piai = @import("ziggy-piai");

const codex_oauth = ziggy_piai.oauth.openai_codex;
const provider_oauth = ziggy_piai.oauth.provider_oauth;
const provider_login_oauth = ziggy_piai.oauth.provider_login_oauth;

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

fn readLineTrimmedAlloc(allocator: std.mem.Allocator, max_len: usize) !?[]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var stdin = std.fs.File.stdin();
    var saw_any = false;
    var byte: [1]u8 = undefined;
    while (true) {
        const n = try stdin.read(byte[0..]);
        if (n == 0) break;
        saw_any = true;

        const ch = byte[0];
        if (ch == '\n') break;
        if (ch == '\r') continue;

        if (out.items.len >= max_len) return error.InputTooLong;
        try out.append(allocator, ch);
    }

    if (!saw_any and out.items.len == 0) return null;

    const trimmed = std.mem.trim(u8, out.items, " \t");
    if (trimmed.len == 0) {
        out.deinit(allocator);
        return try allocator.dupe(u8, "");
    }
    const dup = try allocator.dupe(u8, trimmed);
    out.deinit(allocator);
    return dup;
}

fn providerStorageName(provider: []const u8) []const u8 {
    if (std.mem.eql(u8, provider, "openai-codex-spark")) return "openai-codex";
    return provider;
}

fn isSupportedProvider(provider: []const u8) bool {
    return std.mem.eql(u8, provider, "openai-codex") or
        std.mem.eql(u8, provider, "openai-codex-spark") or
        std.mem.eql(u8, provider, "anthropic") or
        std.mem.eql(u8, provider, "google-gemini-cli") or
        std.mem.eql(u8, provider, "google-antigravity") or
        std.mem.eql(u8, provider, "github-copilot");
}

fn promptAuthorizationCode(allocator: std.mem.Allocator, auth_url: []const u8, expected_state: []const u8) ![]u8 {
    try println("", .{});
    try println("Open this URL in your browser:", .{});
    try println("  {s}", .{auth_url});
    try println("", .{});
    try println("After login, paste the full callback URL (or code#state):", .{});
    try print("> ", .{});

    const raw = (try readLineTrimmedAlloc(allocator, 8192)) orelse return error.MissingAuthorizationCode;
    defer allocator.free(raw);

    const parsed = try codex_oauth.parseAuthorizationInput(allocator, raw);
    defer {
        if (parsed.code) |v| allocator.free(v);
        if (parsed.state) |v| allocator.free(v);
    }

    const code = parsed.code orelse return error.MissingAuthorizationCode;
    const state = parsed.state orelse return error.StateMismatch;
    if (!std.mem.eql(u8, state, expected_state)) return error.StateMismatch;
    return allocator.dupe(u8, code);
}

fn saveProviderCredsFromLoginFlow(
    allocator: std.mem.Allocator,
    provider: []const u8,
    creds: provider_login_oauth.OAuthCredentials,
) !void {
    var stored = provider_oauth.OAuthCredentials{
        .access = try allocator.dupe(u8, creds.access),
        .refresh = try allocator.dupe(u8, creds.refresh),
        .expires_at_ms = creds.expires_at_ms,
        .project_id = if (creds.project_id) |v| try allocator.dupe(u8, v) else null,
        .enterprise_url = if (creds.enterprise_url) |v| try allocator.dupe(u8, v) else null,
    };
    defer provider_oauth.freeOAuthCredentials(allocator, &stored);
    try provider_oauth.savePiOAuthCredentials(allocator, providerStorageName(provider), stored);
}

fn saveProviderCredsFromCodexFlow(allocator: std.mem.Allocator, creds: codex_oauth.OAuthCredentials) !void {
    var stored = provider_oauth.OAuthCredentials{
        .access = try allocator.dupe(u8, creds.access),
        .refresh = try allocator.dupe(u8, creds.refresh),
        .expires_at_ms = creds.expires_at_ms,
        .project_id = null,
        .enterprise_url = null,
    };
    defer provider_oauth.freeOAuthCredentials(allocator, &stored);
    try provider_oauth.savePiOAuthCredentials(allocator, "openai-codex", stored);
}

fn printAuthPath(allocator: std.mem.Allocator) void {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch return;
    defer allocator.free(home);
    const auth_path = provider_oauth.piAuthPathFromHome(allocator, home) orelse return;
    defer allocator.free(auth_path);
    std.log.info("Saved OAuth credentials to {s}", .{auth_path});
}

fn runOpenAICodexLogin(allocator: std.mem.Allocator) !void {
    var flow = try codex_oauth.createAuthorizationFlow(allocator, "pi");
    defer codex_oauth.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try codex_oauth.exchangeAuthorizationCode(allocator, code, flow.verifier, codex_oauth.REDIRECT_URI);
    defer codex_oauth.freeCredentials(allocator, &creds);

    try saveProviderCredsFromCodexFlow(allocator, creds);
}

fn runGoogleGeminiCliLogin(allocator: std.mem.Allocator) !void {
    var flow = try provider_login_oauth.createGoogleGeminiCliAuthorizationFlow(allocator);
    defer provider_login_oauth.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try provider_login_oauth.exchangeGoogleGeminiCliAuthorizationCode(allocator, code, flow.verifier);
    defer provider_login_oauth.freeOAuthCredentials(allocator, &creds);

    try saveProviderCredsFromLoginFlow(allocator, "google-gemini-cli", creds);
}

fn runGoogleAntigravityLogin(allocator: std.mem.Allocator) !void {
    var flow = try provider_login_oauth.createGoogleAntigravityAuthorizationFlow(allocator);
    defer provider_login_oauth.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try provider_login_oauth.exchangeGoogleAntigravityAuthorizationCode(allocator, code, flow.verifier);
    defer provider_login_oauth.freeOAuthCredentials(allocator, &creds);

    try saveProviderCredsFromLoginFlow(allocator, "google-antigravity", creds);
}

fn runAnthropicLogin(allocator: std.mem.Allocator) !void {
    var flow = try provider_login_oauth.createAnthropicAuthorizationFlow(allocator);
    defer provider_login_oauth.freeAuthorizationFlow(allocator, &flow);

    const code = try promptAuthorizationCode(allocator, flow.url, flow.state);
    defer allocator.free(code);

    var creds = try provider_login_oauth.exchangeAnthropicAuthorizationCode(allocator, code, flow.state, flow.verifier);
    defer provider_login_oauth.freeOAuthCredentials(allocator, &creds);

    try saveProviderCredsFromLoginFlow(allocator, "anthropic", creds);
}

fn runGitHubCopilotLogin(allocator: std.mem.Allocator, enterprise_domain: ?[]const u8) !void {
    var device_flow = try provider_login_oauth.startGitHubCopilotDeviceFlow(allocator, enterprise_domain);
    defer provider_login_oauth.freeDeviceCodeFlow(allocator, &device_flow);

    try println("", .{});
    try println("Complete GitHub Copilot device login:", .{});
    try println("  URL:  {s}", .{device_flow.verification_uri});
    try println("  Code: {s}", .{device_flow.user_code});
    try println("", .{});
    try println("Waiting for authorization...", .{});

    const device_access_token = try provider_login_oauth.pollGitHubCopilotDeviceAccessToken(
        allocator,
        device_flow.device_code,
        device_flow.interval_seconds,
        device_flow.expires_in_seconds,
        enterprise_domain,
    );
    defer allocator.free(device_access_token);

    var creds = try provider_login_oauth.refreshGitHubCopilotToken(allocator, device_access_token, enterprise_domain);
    defer provider_login_oauth.freeOAuthCredentials(allocator, &creds);

    try saveProviderCredsFromLoginFlow(allocator, "github-copilot", creds);
}

fn setProviderIfRequested(allocator: std.mem.Allocator, provider: []const u8, set_provider: bool) !void {
    if (!set_provider) return;
    var config = try Config.init(allocator, null);
    defer config.deinit();

    var model_to_set: ?[]const u8 = null;
    if (std.mem.eql(u8, config.provider.name, provider)) {
        if (config.provider.model) |existing| {
            model_to_set = provider_models.remapLegacyModel(provider, existing) orelse existing;
        }
    }
    if (model_to_set == null) {
        model_to_set = provider_models.preferredDefaultModel(provider);
    }

    try config.setProvider(provider, model_to_set);
    std.log.info("Set provider to {s} (model: {s})", .{ provider, model_to_set orelse "default" });
}

fn runLogin(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.log.err("Usage: oauth login <provider> [--enterprise-domain <domain>] [--no-set-provider]", .{});
        return error.InvalidArguments;
    }

    const provider = args[0];
    if (!isSupportedProvider(provider)) {
        std.log.err("Unsupported OAuth provider: {s}", .{provider});
        return error.InvalidArguments;
    }

    var set_provider = true;
    var enterprise_domain: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--no-set-provider")) {
            set_provider = false;
        } else if (std.mem.eql(u8, args[i], "--enterprise-domain")) {
            i += 1;
            if (i >= args.len) {
                std.log.err("Missing value for --enterprise-domain", .{});
                return error.InvalidArguments;
            }
            enterprise_domain = args[i];
        } else {
            std.log.err("Unknown oauth login option: {s}", .{args[i]});
            return error.InvalidArguments;
        }
    }

    if (std.mem.eql(u8, provider, "openai-codex") or std.mem.eql(u8, provider, "openai-codex-spark")) {
        try runOpenAICodexLogin(allocator);
    } else if (std.mem.eql(u8, provider, "google-gemini-cli")) {
        try runGoogleGeminiCliLogin(allocator);
    } else if (std.mem.eql(u8, provider, "google-antigravity")) {
        try runGoogleAntigravityLogin(allocator);
    } else if (std.mem.eql(u8, provider, "anthropic")) {
        try runAnthropicLogin(allocator);
    } else if (std.mem.eql(u8, provider, "github-copilot")) {
        try runGitHubCopilotLogin(allocator, enterprise_domain);
    } else {
        return error.InvalidArguments;
    }

    try setProviderIfRequested(allocator, provider, set_provider);
    printAuthPath(allocator);
}

fn runClear(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        std.log.err("Usage: oauth clear <provider>", .{});
        return error.InvalidArguments;
    }
    const provider = args[0];
    if (!isSupportedProvider(provider)) {
        std.log.err("Unsupported OAuth provider: {s}", .{provider});
        return error.InvalidArguments;
    }
    try provider_oauth.removePiAuthProviderEntry(allocator, providerStorageName(provider));
    std.log.info("Removed OAuth credentials for provider {s}", .{providerStorageName(provider)});
}

fn printUsage() !void {
    const usage =
        \\OAuth credential management
        \\
        \\Usage:
        \\  spiderweb-config oauth login <provider> [--enterprise-domain <domain>] [--no-set-provider]
        \\  spiderweb-config oauth clear <provider>
        \\
        \\Supported providers:
        \\  openai-codex
        \\  openai-codex-spark
        \\  anthropic
        \\  google-gemini-cli
        \\  google-antigravity
        \\  github-copilot
        \\
    ;
    try std.fs.File.stdout().writeAll(usage);
}

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        try printUsage();
        return error.InvalidArguments;
    }

    const subcommand = args[0];
    if (std.mem.eql(u8, subcommand, "login")) {
        try runLogin(allocator, args[1..]);
    } else if (std.mem.eql(u8, subcommand, "clear")) {
        try runClear(allocator, args[1..]);
    } else if (std.mem.eql(u8, subcommand, "--help") or std.mem.eql(u8, subcommand, "-h")) {
        try printUsage();
    } else {
        std.log.err("Unknown oauth command: {s}", .{subcommand});
        try printUsage();
        return error.UnknownCommand;
    }
}
