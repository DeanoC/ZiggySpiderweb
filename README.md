# ZiggySpiderweb 🕸️

[![Zig](https://img.shields.io/badge/Zig-0.15.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An **AI agent gateway** that connects agents to Pi AI providers (OpenAI, Codex, Kimi). Built in Zig, Linux-only.

## What is it?

ZiggySpiderweb is a WebSocket gateway that runs AI agents with:
- Direct agent connections via WebSocket
- Message routing to AI providers via Pi AI abstraction
- Streaming responses with tool execution support

**Supported Providers:**
- OpenAI (GPT-4o, GPT-4.1, GPT-5.3-codex-spark)
- OpenAI Codex (GPT-5.1, GPT-5.2, GPT-5.3 variants)
- Kimi Coding (K2, K2.5 series)

**Authentication:**
- API keys: Stored securely via Linux secret-tool or environment variables
- OAuth: Automatic Codex token refresh from `~/.codex/auth.json` (if you've authenticated with `codex` CLI)

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
- `run_checkpoint_interval_steps`
- `run_auto_resume_on_boot`
- `tool_retry_max_attempts`
- `tool_lease_timeout_ms`
- `max_inflight_tool_calls_per_run`
- `max_run_steps`
- `default_agent_id`

Notes:
- Older inflight-style runtime gating keys are no longer used.
- Protocol input should use `session.send`; legacy `chat.send` is rejected.

### Debug Stream Log Files

When debug streaming is enabled (`debug.subscribe`), server-side copies of `debug.event` frames are appended to:

- `<runtime.ltm_directory>/debug-stream.ndjson`

Retention behavior:

- Rotates at ~8 MiB per live file.
- Rotated files are archived as `debug-stream-<timestamp>.ndjson`.
- If `gzip` is available on the host, rotated archives are compressed to `.ndjson.gz`.
- Keeps the newest 8 archives and prunes older files.

### Agent Run API

Spiderweb now supports a run-oriented control path:

- `agent.run.start`
- `agent.run.step`
- `agent.run.resume`
- `agent.run.pause`
- `agent.run.cancel`
- `agent.run.status`
- `agent.run.events`
- `agent.run.list`

`session.send` remains supported and acts as a compatibility shim for chat-style turns.

### World Tools (Provider-Driven)

World tools are executed through provider tool-calling during `session.send`.

- Runtime supplies tool schemas to the configured provider.
- Provider emits tool calls.
- Runtime executes tools and feeds results back to provider.
- Clients receive `tool.event` and `memory.event` frames as part of the normal response stream.

Implemented tool names:

- `file_read`
- `file_write`
- `file_list`
- `search_code`
- `shell_exec`

### API Key Storage

**Priority order:**
1. **Secure credential store** - Set via `spiderweb-config config set-key ...`
2. **Environment variable fallback** - Provider-specific env keys (for example `OPENAI_API_KEY`)

**Security Note:** `spiderweb-config config set-key` does not write plaintext keys to config.
On Linux, secure storage uses the desktop keyring via `secret-tool`.
If no secure backend is available, configure provider keys via environment variables.

### Environment Variables

Spiderweb supports multiple ways to provide API keys via environment variables:

**OpenAI:**
- `OPENAI_API_KEY` - Standard API key

**OpenAI Codex:**
- `OPENAI_CODEX_API_KEY` - Dedicated Codex API key
- `OPENAI_API_KEY` - Falls back to standard OpenAI key
- **OAuth:** Automatically reads `~/.codex/auth.json` if you've authenticated via the `codex` CLI

**OpenAI Codex Spark:**
- `OPENAI_CODEX_SPARK_API_KEY` - Dedicated Spark API key
- `OPENAI_CODEX_API_KEY` - Falls back to Codex key
- `OPENAI_API_KEY` - Falls back to standard OpenAI key
- **OAuth:** Automatically reads `~/.codex/auth.json`

**Kimi Coding:**
- `KIMICODE_API_KEY` - Preferred
- `KIMI_API_KEY` - Alternative
- `ANTHROPIC_API_KEY` - Falls back to Anthropic key

**Anthropic (if using directly):**
- `ANTHROPIC_API_KEY`

**Azure OpenAI:**
- `AZURE_OPENAI_API_KEY`

### OAuth Token Refresh

When using OpenAI Codex providers, Spiderweb automatically:
1. Reads tokens from `~/.codex/auth.json` (created by the `codex` CLI)
2. Refreshes expired tokens using the refresh token
3. Writes updated tokens back to `~/.codex/auth.json`

This allows seamless Codex usage without manual API key management if you've already authenticated with:
```bash
codex auth login
```

## Architecture

```
OpenClaw Client (ZSC, OpenClaw, etc.)
    │ WebSocket / OpenClaw Protocol
    ▼
┌─────────────────┐
│  HTTP Upgrade   │  ← GET /v1/agents/{agentId}/stream
├─────────────────┤
│  Session ACK    │  ← {"type":"connect.ack",...}
├─────────────────┤
│ Optional Bootstrap│ ← {"type":"session.receive",...} on first connect
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

## Ops Runbook

- First agent bootstrap: `docs/FIRST_AGENT_BOOTSTRAP_RUNBOOK.md`

## Development

```bash
# Run tests
zig build test

# Build optimized release
zig build --release=safe

# Run with debug logging
zig build run -- --port 18791
```

## Module Migration Notes

Spiderweb now imports shared modules directly:

- `ziggy-spider-protocol`
- `ziggy-memory-store`
- `ziggy-tool-runtime`
- `ziggy-runtime-hooks` (wave-2 extraction now includes `event_bus`, `hook_primitives`, and `hook_registry_engine`)

Compatibility wrapper files (`src/protocol*.zig`, `src/memory*.zig`, `src/run_store.zig`, `src/tool_*.zig`) were marked for removal on February 22, 2026 with a target of `v0.3.0`, and are now removed. Use direct module imports in new code.

## Related Projects

- [ziggy-piai](https://github.com/DeanoC/ziggy-piai) - Pi AI provider abstraction
- [ZiggyStarClaw](https://github.com/DeanoC/ZiggyStarClaw) - OpenClaw client
- [OpenClaw](https://github.com/openclaw/openclaw) - Main gateway implementation

## License

MIT © 2026 DeanoC

See [LICENSE](LICENSE) for details.
