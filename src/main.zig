const std = @import("std");

const server = @import("server_piai.zig");
const Config = @import("config.zig");

comptime {
    _ = @import("agent_runtime.zig");
    _ = @import("brain_context.zig");
    _ = @import("brain_tools.zig");
    _ = @import("brain_specialization.zig");
    _ = @import("ziggy-runtime-hooks").event_bus;
    _ = @import("ziggy-run-orchestrator").run_engine;
    _ = @import("hook_registry.zig");
    _ = @import("system_hooks.zig");
    _ = @import("ziggy-memory-store").ltm_store;
    _ = @import("ziggy-memory-store").memory;
    _ = @import("memory_schema.zig");
    _ = @import("ziggy-memory-store").memid;
    _ = @import("prompt_compiler.zig");
    _ = @import("spider-protocol").protocol;
    _ = @import("ziggy-memory-store").run_store;
    _ = @import("ziggy-tool-runtime").tool_registry;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load config
    var config = Config.init(allocator, null) catch |err| {
        std.log.err("Failed to load config: {s}", .{@errorName(err)});
        return err;
    };
    defer config.deinit();

    std.log.info("Starting Spiderweb v0.3.0 (Pi AI)", .{});
    std.log.info("Config: {s}", .{config.config_path});
    std.log.info("Provider: {s}/{s}", .{ config.provider.name, config.provider.model orelse "default" });
    std.log.info("Default agent route: {s}", .{config.runtime.default_agent_id});

    // Override with CLI args if provided
    var port = config.server.port;
    var bind_addr = config.server.bind;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i < args.len) {
                port = try std.fmt.parseInt(u16, args[i], 10);
            }
        } else if (std.mem.eql(u8, arg, "--bind")) {
            i += 1;
            if (i < args.len) {
                bind_addr = args[i];
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            const help =
                "Spiderweb v0.3.0 - Pi AI Gateway for OpenClaw Protocol\n" ++
                "\n" ++
                "A WebSocket gateway that proxies OpenClaw protocol messages to Pi AI providers.\n" ++
                "\n" ++
                "Usage: spiderweb [options]\n" ++
                "\n" ++
                "Options:\n" ++
                "  --bind <addr>    Bind address (default: from config or 127.0.0.1)\n" ++
                "  --port <port>    Port number (default: from config or 18790)\n" ++
                "  --help, -h       Show this help\n" ++
                "\n" ++
                "Configuration:\n" ++
                "  spiderweb-config oauth login <provider> [--enterprise-domain <domain>] [--no-set-provider]\n" ++
                "  spiderweb-config oauth clear <provider>\n" ++
                "  spiderweb-config config              Show current config\n" ++
                "  spiderweb-config config set-provider <name> [model]\n" ++
                "  spiderweb-config config set-key <api-key> [provider]\n" ++
                "  spiderweb-config config clear-key [provider]\n" ++
                "\n" ++
                "API key resolution order: secure credential backend (Linux: secret-tool), then provider OAuth/env keys.\n";
            std.debug.print("{s}", .{help});
            return;
        }
    }

    std.log.info("Binding to {s}:{d}", .{ bind_addr, port });

    if (config.runtime.ltm_directory.len == 0 or config.runtime.ltm_filename.len == 0) {
        std.log.err("Invalid runtime config: LTM store is required (`runtime.ltm_directory` and `runtime.ltm_filename` must be set)", .{});
        return error.MissingLtmStoreConfig;
    }

    // Start server
    try server.run(allocator, bind_addr, port, config.provider, config.runtime);
}
