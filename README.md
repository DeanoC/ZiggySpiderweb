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

### Automated Install (Recommended for Debian/Ubuntu)

The fastest way to get started on Linux:

```bash
# One-line install - downloads, builds, configures, and runs
curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh | bash
```

This script will:
1. Check and install dependencies (Zig, secret-tool, jq, etc.)
2. Clone and build ZiggySpiderweb
3. Prompt for AI provider and API key
4. Configure secure credential storage
5. Name your first agent
6. Start the server

### Manual Install

```bash
# Clone and build
git clone https://github.com/DeanoC/ZiggySpiderweb.git
cd ZiggySpiderweb
zig build

# Store provider key in secure credential backend (Linux: secret-tool)
./zig-out/bin/spiderweb-config config set-key sk-... openai

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

## Configuration

Spiderweb uses a JSON config file at `~/.config/spiderweb/config.json`.

### Quick Config

```bash
# View current config
spiderweb-config config

# Set provider and model
spiderweb-config config set-provider openai gpt-4o
spiderweb-config config set-provider kimi-coding kimi-k2.5
spiderweb-config config set-provider openai-codex gpt-5.3-codex

# Store API key in secure credential backend (Linux: `secret-tool`)
spiderweb-config config set-key sk-your-key-here openai
spiderweb-config config clear-key openai

# Change bind address/port
spiderweb-config config set-server --bind 0.0.0.0 --port 9000

# Set log level
spiderweb-config config set-log debug
```

### Runtime Queue/Timeout Keys

Runtime execution now uses a bounded request queue plus fixed runtime workers.

`runtime` keys in `~/.config/spiderweb/config.json`:
- `runtime_worker_threads`
- `runtime_request_queue_max`
- `chat_operation_timeout_ms`
- `control_operation_timeout_ms`

Notes:
- Older inflight-style runtime gating keys are no longer used.
- Protocol input should use `session.send`; legacy `chat.send` is rejected.

### World Tools (Provider-Driven)

World tools are executed through provider tool-calling during `session.send`.

- Runtime supplies tool schemas to the configured provider.
- Provider emits tool calls.
- Runtime executes tools and feeds results back to provider.
- Clients receive `tool.event` and `memory.event` frames as part of the normal response stream.

Implemented tool names:

- `file.read`
- `file.write`
- `file.list`
- `search.code`
- `shell.exec`

### API Key Storage

**Priority order:**
1. **Secure credential store** - Set via `spiderweb-config config set-key ...`
2. **Environment variable fallback** - Provider-specific env keys (for example `OPENAI_API_KEY`)

**Security Note:** `spiderweb-config config set-key` does not write plaintext keys to config.
On Linux, secure storage uses the desktop keyring via `secret-tool`.
If no secure backend is available, configure provider keys via environment variables.

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
