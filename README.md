# ZiggySpiderweb

An echo gateway for the OpenClaw protocol. Linux-only, minimal dependencies.

## Purpose

ZiggySpiderweb validates the OpenClaw protocol layer by providing a simple echo service that:
- Accepts WebSocket connections from ZiggyStarClaw
- Performs OpenClaw auth handshake
- Echoes back all messages with "Echo: " prefix

## Quick Start

```bash
# Build
cd ziggy-spiderweb
zig build

# Run on default port 18790
./zig-out/bin/spiderweb

# Or specify custom port
./zig-out/bin/spiderweb --port 9000

# View help
./zig-out/bin/spiderweb --help
```

## Configuration

### ZiggyStarClaw

Point ZSC to Spiderweb instead of the default OpenClaw gateway:

```json
{
  "gateway": {
    "url": "ws://127.0.0.1:18790"
  }
}
```

Or use the `--gateway` CLI flag:

```bash
ziggystarclaw --gateway ws://127.0.0.1:18790
```

## Architecture

```
ZiggyStarClaw (Client)
    │ WebSocket
    ▼
┌─────────────────┐
│  HTTP Upgrade   │  ← /v1/agents/{agentId}/stream
├─────────────────┤
│   Auth Parse    │  ← deviceKey/deviceAuth (memory-only)
├─────────────────┤
│  Session ACK    │  ← sessionKey generation
├─────────────────┤
│   Echo Loop     │  ← session.send → session.receive
└─────────────────┘
```

## Protocol Support

| Feature | Status |
|---------|--------|
| WebSocket upgrade | ✅ |
| Auth handshake | ✅ |
| Session management | ✅ |
| session.send/receive | ✅ |
| Heartbeat ping/pong | ✅ |
| TLS | ❌ (localhost only) |
| Persistent auth | ❌ (memory only) |

## Development

```bash
# Run tests
zig build test

# Build with Tracy profiling
zig build -Denable_ztracy=true

# Run with debug logging
ZIG_LOG_LEVEL=debug ./zig-out/bin/spiderweb
```

## License

MIT
