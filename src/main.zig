const std = @import("std");

const server = @import("server_piai.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("Starting ZiggySpiderweb v0.2.0 (Pi AI)", .{});

    // Parse CLI args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var port: u16 = 18790;
    var bind_addr: []const u8 = "127.0.0.1";

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
                "  --bind <addr>    Bind address (default: 127.0.0.1)\n" ++
                "  --port <port>    Port number (default: 18790)\n" ++
                "  --help, -h       Show this help\n" ++
                "\n" ++
                "Environment:\n" ++
                "  OPENAI_API_KEY       OpenAI API key\n" ++
                "  ANTHROPIC_API_KEY    Anthropic API key\n" ++
                "  OPENAI_CODEX_API_KEY OpenAI Codex API key (optional)\n"
            ;
            std.debug.print("{s}", .{help});
            return;
        }
    }

    std.log.info("Binding to {s}:{d}", .{ bind_addr, port });

    // Start server
    try server.run(allocator, bind_addr, port);
}
