# ZiggySpiderweb 🕸️

[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An **OpenClaw protocol echo gateway** for testing and development. Built in Zig, Linux-only, zero external dependencies.

## What is it?

ZiggySpiderweb validates the OpenClaw protocol by providing a simple echo service that:
- Accepts WebSocket connections from any OpenClaw-compatible client
- Performs the OpenClaw handshake (auth + session ACK)
- Echoes back all messages with an "Echo: " prefix

Perfect for:
- Testing OpenClaw client implementations
- Protocol validation during development
- CI/CD testing without a full OpenClaw gateway

## Quick Start

```bash
# Clone and build
git clone https://github.com/DeanoC/ZiggySpiderweb.git
cd ZiggySpiderweb
zig build

# Run on default port 18790
./zig-out/bin/spiderweb

# Or specify custom port
./zig-out/bin/spiderweb --port 9000

# Test with websocat
echo '{"type":"session.send","content":"Hello"}' | websocat ws://127.0.0.1:18790/v1/agents/test/stream
```

## Testing with ZiggyStarClaw

Use the new gateway testing commands:

```bash
# Ping test (handshake only)
zsc --gateway-test ping ws://127.0.0.1:18790/v1/agents/test/stream

# Echo test (full round-trip)
zsc --gateway-test echo ws://127.0.0.1:18790/v1/agents/test/stream

# Protocol probe (compatibility check)
zsc --gateway-test probe ws://127.0.0.1:18790/v1/agents/test/stream
```

## Architecture

```
OpenClaw Client (ZiggyStarClaw, OpenClaw, etc.)
    │ WebSocket
    ▼
┌─────────────────┐
│  HTTP Upgrade   │  ← GET /v1/agents/{agentId}/stream
├─────────────────┤
│  WebSocket Key  │  ← Sec-WebSocket-Key validation
├─────────────────┤
│  Session ACK    │  ← {"type":"session.ack",...}
├─────────────────┤
│   Echo Loop     │  ← {"type":"session.send"} → "Echo: {...}"
└─────────────────┘
```

## Protocol Support

| Feature | Status | Notes |
|---------|--------|-------|
| WebSocket RFC 6455 | ✅ | Full handshake + framing |
| OpenClaw handshake | ✅ | session.ack with agentId |
| Session management | ✅ | In-memory only |
| session.send/receive | ✅ | Echo prefix |
| JSON-RPC framing | ✅ | Standard OpenClaw |
| TLS | ❌ | Localhost dev only |
| Persistent auth | ❌ | Memory-only (ephemeral) |

## Development

```bash
# Run tests
zig build test

# Build optimized release
zig build --release=safe

# Run with debug logging
ZIG_LOG_LEVEL=debug ./zig-out/bin/spiderweb
```

## Related Projects

- [ZiggyStarClaw](https://github.com/DeanoC/ZiggyStarClaw) - OpenClaw client with gateway testing
- [OpenClaw](https://github.com/openclaw/openclaw) - The main gateway implementation

## License

MIT © 2026 DeanoC

See [LICENSE](LICENSE) for details.
