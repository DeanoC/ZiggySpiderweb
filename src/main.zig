const std = @import("std");

const server = @import("server_piai.zig");
const Config = @import("config.zig");

comptime {
    _ = @import("agent_runtime.zig");
    _ = @import("brain_context.zig");
    _ = @import("brain_tools.zig");
    _ = @import("brain_specialization.zig");
    _ = @import("event_bus.zig");
    _ = @import("hook_registry.zig");
    _ = @import("system_hooks.zig");
    _ = @import("ltm_store.zig");
    _ = @import("memory.zig");
    _ = @import("memid.zig");
    _ = @import("protocol.zig");
    _ = @import("tool_registry.zig");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load config
    var config = Config.init(allocator, null) catch |err| {
        std.log.warn("Failed to load config: {s}, using defaults", .{@errorName(err)});
        // Continue with defaults
        const cfg = Config{
            .allocator = allocator,
            .server = .{},
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
                .chat_operation_timeout_ms = 30_000,
                .control_operation_timeout_ms = 5_000,
                .ltm_directory = try allocator.dupe(u8, ".spiderweb-ltm"),
                .ltm_filename = try allocator.dupe(u8, "runtime-memory.db"),
            },
            .config_path = try allocator.dupe(u8, ".spiderweb.json"),
        };
        // Need to handle deinit, but we already have an error path
        std.log.info("Starting ZiggySpiderweb v0.2.0 (Pi AI)", .{});
        try server.run(allocator, cfg.server.bind, cfg.server.port, cfg.provider, cfg.runtime);
        return;
    };
    defer config.deinit();

    std.log.info("Starting ZiggySpiderweb v0.2.0 (Pi AI)", .{});
    std.log.info("Config: {s}", .{config.config_path});
    std.log.info("Provider: {s}/{s}", .{ config.provider.name, config.provider.model orelse "default" });

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
                "ZiggySpiderweb v0.2.0 - Pi AI Gateway for OpenClaw Protocol\n" ++
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
                "  spiderweb-config config              Show current config\n" ++
                "  spiderweb-config config set-provider <name> [model]\n" ++
                "  spiderweb-config config set-key <api-key>\n" ++
                "\n" ++
                "Environment (used as fallback for API keys):\n" ++
                "  OPENAI_API_KEY       OpenAI API key\n" ++
                "  ANTHROPIC_API_KEY    Anthropic API key\n" ++
                "  OPENAI_CODEX_API_KEY OpenAI Codex API key (optional)\n";
            std.debug.print("{s}", .{help});
            return;
        }
    }

    std.log.info("Binding to {s}:{d}", .{ bind_addr, port });

    // Start server
    try server.run(allocator, bind_addr, port, config.provider, config.runtime);
}
