# ZiggySpiderweb 🕸️

[![Zig](https://img.shields.io/badge/Zig-0.15.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An **OpenClaw protocol gateway** that proxies requests to Pi AI providers (OpenAI, Codex, Kimi). Built in Zig, Linux-only.

## What is it?

ZiggySpiderweb is an OpenClaw-compatible WebSocket gateway that:
- Accepts OpenClaw protocol connections from any compatible client
- Proxies messages to AI providers via Pi AI abstraction
- Streams responses back through OpenClaw protocol

**Supported Providers:**
- OpenAI (GPT-4o, GPT-4o-mini)
- OpenAI Codex (GPT-5.1, GPT-5.2, GPT-5.3 variants)
- Kimi Coding (K2, K2.5 series)

## Quick Start

```bash
# Clone and build
git clone https://github.com/DeanoC/ZiggySpiderweb.git
cd ZiggySpiderweb
zig build

# Set your API key (choose one)
export OPENAI_API_KEY="sk-..."
# OR
export KIMI_API_KEY="your-kimi-key"
# OR use existing Codex OAuth: ~/.codex/auth.json

# Run on default port 18790
./zig-out/bin/spiderweb

# Or specify custom port
./zig-out/bin/spiderweb --port 9000
```

## Testing with ZiggyStarClaw

```bash
# Test connectivity
zsc --gateway-test ping ws://127.0.0.1:18790/v1/agents/test/stream

# Send a message (requires API key)
zsc --gateway-test echo ws://127.0.0.1:18790/v1/agents/test/stream

# Protocol compatibility check
zsc --gateway-test probe ws://127.0.0.1:18790/v1/agents/test/stream
```

## API Key Configuration

Spiderweb uses Pi AI's key resolution (tries in order):

| Provider | Environment Variables | Fallback |
|----------|------------------------|----------|
| OpenAI | `OPENAI_API_KEY` | - |
| OpenAI Codex | `OPENAI_CODEX_API_KEY` | `~/.codex/auth.json` (OAuth) → `OPENAI_API_KEY` |
| Kimi | `KIMI_API_KEY`, `KIMICODE_API_KEY` | `ANTHROPIC_API_KEY` |

## Architecture

```
OpenClaw Client (ZSC, OpenClaw, etc.)
    │ WebSocket / OpenClaw Protocol
    ▼
┌─────────────────┐
│  HTTP Upgrade   │  ← GET /v1/agents/{agentId}/stream
├─────────────────┤
│  Session ACK    │  ← {"type":"session.ack",...}
├─────────────────┤
│  OpenClaw Parse │  ← {"type":"session.send",...}
├─────────────────┤
│   Pi AI Stream  │  → HTTP POST to provider
├─────────────────┤
│  Response Stream│  ← SSE deltas → OpenClaw frames
└─────────────────┘
```

## Protocol Support

| Feature | Status |
|---------|--------|
| WebSocket RFC 6455 | ✅ |
| OpenClaw handshake | ✅ |
| Session management | ✅ |
| session.send/receive | ✅ |
| Conversation history | ✅ (per session) |
| Streaming responses | ✅ |
| Multi-provider | ✅ (16 models) |
| TLS | ❌ (localhost only) |

## Development

```bash
# Run tests
zig build test

# Build optimized release
zig build --release=safe

# Run with debug logging
zig build run -- --port 18791
```

## Related Projects

- [ziggy-piai](https://github.com/DeanoC/ziggy-piai) - Pi AI provider abstraction
- [ZiggyStarClaw](https://github.com/DeanoC/ZiggyStarClaw) - OpenClaw client
- [OpenClaw](https://github.com/openclaw/openclaw) - Main gateway implementation

## License

MIT © 2026 DeanoC

See [LICENSE](LICENSE) for details.
