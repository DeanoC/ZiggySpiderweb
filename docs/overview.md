# ZiggySpiderweb Overview

ZiggySpiderweb is a WebSocket gateway and **Acheron-based distributed RPC filesystem** that lets agents operate in a unified, project-scoped namespace while talking to AI providers.

## Vision

Agents shouldn’t need bespoke APIs to work across machines or services. The core idea is a filesystem-shaped world where chat, tools, files, and remote services are just paths.

Key pillars:
- Unified-v2 control plane for agents, projects, and sessions.
- Acheron WorldFS that projects multi-node workspaces + services into a single namespace.
- Provider-backed chat with streaming + tool execution.
- Service catalog + policy-gated access to remote capabilities.

## Supported Providers

- OpenAI (GPT-4o, GPT-4.1, GPT-5.3-codex-spark)
- OpenAI Codex (GPT-5.1, GPT-5.2, GPT-5.3 variants)
- Kimi Coding (K2, K2.5 series)

## Authentication

- API keys stored via Linux secret-tool or env vars.
- OAuth: automatic Codex token refresh from `~/.codex/auth.json`.

## Testing with ZiggyStarClaw

```bash
# Test connectivity
zsc --gateway-test ping ws://127.0.0.1:18790

# Send a message (requires API key)
zsc --gateway-test echo ws://127.0.0.1:18790

# Protocol compatibility check
zsc --gateway-test probe ws://127.0.0.1:18790
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

Runtime execution uses bounded queues and fixed worker pools. `runtime` keys in `~/.config/spiderweb/config.json`:

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
- Use unified v2 control + Acheron APIs (`control.version`, `control.connect`, `acheron.t_version`, `acheron.t_attach`).
- Legacy websocket chat envelopes (`session.send`, `chat.send`) are rejected on the unified v2 gateway path.

### Debug Stream Log Files

When debug streaming is enabled (`debug.subscribe`), server-side copies of `debug.event` frames are appended to:

- `<runtime.ltm_directory>/debug-stream.ndjson`

Retention behavior:

- Rotates at ~8 MiB per live file.
- Rotated files are archived as `debug-stream-<timestamp>.ndjson`.
- If `gzip` is available on the host, rotated archives are compressed to `.ndjson.gz`.
- Keeps the newest 8 archives and prunes older files.

### Agent Run API

Spiderweb supports a run-oriented control path:

- `agent.run.start`
- `agent.run.step`
- `agent.run.resume`
- `agent.run.pause`
- `agent.run.cancel`
- `agent.run.status`
- `agent.run.events`
- `agent.run.list`

Run/chat flows should use Acheron filesystem contract paths under `/agents/self/*`.

### World Tools (Provider-Driven)

World tools execute through provider tool-calling via Acheron job/chat flows.

- Runtime supplies tool schemas to the provider.
- Provider emits tool calls.
- Runtime executes tools and feeds results back to provider.
- Clients receive `tool.event` and `memory.event` frames.

Implemented tool names:

- `file_read`
- `file_write`
- `file_list`
- `search_code`
- `shell_exec`

## API Key Storage

**Priority order:**
1. Secure credential store (`spiderweb-config config set-key ...`)
2. Environment variable fallback (for example `OPENAI_API_KEY`)

**Security Note:** `spiderweb-config config set-key` does not write plaintext keys to config.

### Environment Variables

**OpenAI:**
- `OPENAI_API_KEY`

**OpenAI Codex:**
- `OPENAI_CODEX_API_KEY`
- `OPENAI_API_KEY` (fallback)
- OAuth reads `~/.codex/auth.json`

**OpenAI Codex Spark:**
- `OPENAI_CODEX_SPARK_API_KEY`
- `OPENAI_CODEX_API_KEY` (fallback)
- `OPENAI_API_KEY` (fallback)
- OAuth reads `~/.codex/auth.json`

**Kimi Coding:**
- `KIMICODE_API_KEY` (preferred)
- `KIMI_API_KEY` (alternate)
- `ANTHROPIC_API_KEY` (fallback)

**Anthropic (direct):**
- `ANTHROPIC_API_KEY`

**Azure OpenAI:**
- `AZURE_OPENAI_API_KEY`

### OAuth Token Refresh

When using OpenAI Codex providers, Spiderweb automatically:
1. Reads tokens from `~/.codex/auth.json` (created by the `codex` CLI)
2. Refreshes expired tokens using the refresh token
3. Writes updated tokens back to `~/.codex/auth.json`

To authenticate:
```bash
codex auth login
```

## Architecture (Legacy Diagram)

```
OpenClaw Client (ZSC, OpenClaw, etc.)
    │ WebSocket / OpenClaw Protocol
    ▼
┌─────────────────┐
│  HTTP Upgrade   │  ← GET /
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

For current architecture, see `docs/design/architecture.md`.

## Distributed Filesystem (Acheron)

Two binaries provide the distributed filesystem protocol from `docs/design/filesystem.md`:

```bash
# Start a node server exporting the current directory as RW
./zig-out/bin/spiderweb-fs-node --export work=.:rw

# Run as a paired node daemon (invite flow) and keep lease refreshed
./zig-out/bin/spiderweb-fs-node \
  --export work=.:rw \
  --control-url ws://127.0.0.1:18790/ \
  --pair-mode invite \
  --invite-token invite-abc123 \
  --node-name clawz \
  --fs-url ws://10.0.0.8:18891/v2/fs

# Run request/approval pairing flow (creates pending request, then retries approval)
./zig-out/bin/spiderweb-fs-node \
  --export work=.:rw \
  --control-url ws://127.0.0.1:18790/ \
  --pair-mode request \
  --node-name edge-1

# Advertise terminal services + labels to node service catalog
./zig-out/bin/spiderweb-fs-node \
  --export work=.:rw \
  --control-url ws://127.0.0.1:18790/ \
  --pair-mode request \
  --node-name edge-1 \
  --terminal-id 1 \
  --terminal-id 2 \
  --label site=hq \
  --label tier=edge

# List root entries through the mount/router client
./zig-out/bin/spiderweb-fs-mount \
  --endpoint a=ws://127.0.0.1:18891/v2/fs#work@/src \
  readdir /

# Read through an explicit mount prefix
./zig-out/bin/spiderweb-fs-mount \
  --endpoint a=ws://127.0.0.1:18891/v2/fs#work@/src \
  cat /src/README.md

# Read/write paths through the routed namespace (default mount is /<name> when @/mount is omitted)
./zig-out/bin/spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs#work cat /a/README.md
./zig-out/bin/spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs#work write /a/.tmp-fs-test "hello"

# Hydrate mounts from spiderweb control workspace_status (active project for current attached agent/session)
./zig-out/bin/spiderweb-fs-mount \
  --workspace-url ws://127.0.0.1:18790/ \
  readdir /

# Keep mounted endpoints synced from control.workspace_status while running FUSE
./zig-out/bin/spiderweb-fs-mount \
  --workspace-url ws://127.0.0.1:18790/ \
  --workspace-sync-interval-ms 5000 \
  mount /mnt/spiderweb

# Endpoint health/failover status
./zig-out/bin/spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs#work status

# Failover: configure multiple endpoints with the same mount path ("/a")
./zig-out/bin/spiderweb-fs-mount \
  --endpoint a=ws://127.0.0.1:18891/v2/fs#work@/a \
  --endpoint b=ws://127.0.0.1:18892/v2/fs#work@/a \
  readdir /a
```

Notes:
- Transport is unified v2 WebSocket JSON using `channel=acheron` and `type=acheron.t_fs_*` / `acheron.r_fs_*` / `acheron.e_fs_*` / `acheron.err_fs`.
- JSON READ/WRITE payloads use `data_b64` for file bytes.
- `mount` is wired through libfuse3 at runtime (loads `libfuse3.so.3` and uses `fusermount3`).
- Router health checks each endpoint and fails over within a shared mount-path group.
- `spiderweb-fs-mount status` includes top-level router metrics, including `failover_events_total`.

## More Docs

- `docs/protocols/acheron-worldfs.md`
- `docs/protocols/control-agent-session.md`
- `docs/runtime/tool-system.md`
- `docs/operations/first-agent-bootstrap.md`
