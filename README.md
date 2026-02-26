# ZiggySpiderweb 🕸️

[![CI](https://github.com/DeanoC/ZiggySpiderweb/actions/workflows/ci.yml/badge.svg)](https://github.com/DeanoC/ZiggySpiderweb/actions/workflows/ci.yml)
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

## Distributed Filesystem (Experimental)

Two new binaries provide the distributed filesystem protocol from `design_docs/FileSystem.md`:

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

# Hydrate mounts from spiderweb control workspace_status (active project for default agent)
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
- `mount` is now wired through libfuse3 at runtime (loads `libfuse3.so.3` and uses `fusermount3`).
- Router health checks each endpoint and fails over within a shared mount-path group.
- `spiderweb-fs-mount status` now includes top-level router metrics, including `failover_events_total`.
- `spiderweb-fs-mount mount` can run a workspace sync loop (`--workspace-sync-interval-ms`) that periodically reconciles endpoint topology from `control.workspace_status`.
- `spiderweb-fs-mount` supports `--project-id <id> [--project-token <token>]` to fetch/sync mounts for a specific project instead of the active agent binding.
- Workspace sync listens for push topology events via `control.debug_subscribe`:
  - full-refresh events: `control.workspace_topology`
  - project-scoped delta events: `control.workspace_topology_delta` (applied directly when `--project-id` is set)
  - polling fallback remains enabled.
- Control-plane project mutations (`project_update`, `project_delete`, `project_mount_set`, `project_mount_remove`, `project_activate`) require a `project_token` returned by `control.project_create`.
- Project token lifecycle control ops are available: `control.project_token_rotate` and `control.project_token_revoke`.
- `control.ping`/`control.pong` is now a lightweight liveness probe (`payload: {}`), and metrics moved to `control.metrics`.
- Control clients must negotiate `control.version` (`{"protocol":"unified-v2"}`) before other control operations.
- Runtime Acheron clients must negotiate `acheron.t_version` first (`"version":"acheron-1"`).
- FS node/router sessions must negotiate `acheron.t_fs_hello` first with payload `{"protocol":"unified-v2-fs","proto":2}`; `auth_token` is optional and enforced when node session auth is enabled.
- Optional control mutation gate: set `SPIDERWEB_CONTROL_OPERATOR_TOKEN`; protected mutations require matching `payload.operator_token`.
- Optional encrypted control-plane state snapshots: set `SPIDERWEB_CONTROL_STATE_KEY_HEX` to a 64-char AES-256 key (hex).
- Optional HTTP observability endpoint: set `SPIDERWEB_METRICS_PORT`; then:
  - `GET /livez` returns process liveness
  - `GET /readyz` returns readiness
  - `GET /metrics` returns Prometheus text format
  - `GET /metrics.json` returns control-plane metrics JSON
- `spiderweb-control` CLI negotiates `control.version` + `control.connect` and executes a single control op for scripting/debug use.
- Spiderweb can host a local in-process `/v2/fs` node (same protocol as external nodes) with:
  - `SPIDERWEB_LOCAL_NODE_EXPORT_PATH` (required to enable)
  - `SPIDERWEB_LOCAL_NODE_EXPORT_NAME` (optional, default `work`)
  - `SPIDERWEB_LOCAL_NODE_EXPORT_RO` (optional boolean)
  - `SPIDERWEB_LOCAL_NODE_NAME`, `SPIDERWEB_LOCAL_NODE_FS_URL`, `SPIDERWEB_LOCAL_NODE_LEASE_TTL_MS`, `SPIDERWEB_LOCAL_NODE_HEARTBEAT_MS` (optional registration/lease settings)
- External `spiderweb-fs-node` can enforce session auth on `/v2/fs` using `--auth-token` (or `SPIDERWEB_FS_NODE_AUTH_TOKEN`).
- External `spiderweb-fs-node` now supports control-plane daemon mode (`--control-url`) with:
  - pairing via `--pair-mode invite --invite-token <token>` or `--pair-mode request`
  - persisted node credentials/state (`--state-file`, default `.spiderweb-fs-node-state.json`)
  - background lease refresh with reconnect backoff (`--refresh-interval-ms`, `--reconnect-backoff-ms`, `--reconnect-backoff-max-ms`)
  - `--control-auth-token` (or `SPIDERWEB_AUTH_TOKEN`) for control websocket auth
- Node/server now emits `acheron.e_fs_inval` / `acheron.e_fs_inval_dir` invalidations and router caches are invalidated on receipt.
- Node/server now broadcasts mutation invalidations to other connected FS clients (server-push fanout).
- Node/server uses a native Linux `inotify` watcher when available, with scanner fallback for out-of-band local FS invalidations.
- Router now keeps a background event-pump websocket per endpoint so idle mounts can ingest pushed invalidations.
- `EXPORTS` includes source metadata (`source_kind`, `source_id`, and initial `caps`) as a foundation for heterogeneous source routing.
- Router now parses export metadata from `EXPORTS` and uses it for capability-aware writable routing (write-intent path resolution skips read-only exports in an alias group when possible).
- Node-side export registration now uses a formal source-adapter contract with explicit `linux`/`posix` adapters, a host-gated `windows` adapter with real execution helpers, and a `gdrive` adapter with read-path support (`LOOKUP`, `GETATTR`, `READDIRP`, `OPEN`, `READ`, `CLOSE`) plus write-path support in API mode (`CREATE`, `WRITE`, `TRUNCATE`, `MKDIR`, `UNLINK`, `RMDIR`, `RENAME`).
- Google Drive API mode is opt-in: set `SPIDERWEB_GDRIVE_ENABLE_API=1` and provide an access token via `SPIDERWEB_GDRIVE_ACCESS_TOKEN` (or `GDRIVE_ACCESS_TOKEN` / `GOOGLE_DRIVE_ACCESS_TOKEN`).
- For long-running gdrive sessions, per-export credential handles are supported (`:cred=<handle>` on `--export` or `ExportSpec.gdrive_credential_handle` in library mode).
- Credential-handle secret values can be either a plain access token or a JSON OAuth bundle (`client_id`, `client_secret`, `refresh_token`, optional `access_token`, `expires_at_ms`) and are auto-refreshed against OAuth token endpoints.
- GDrive endpoints are overridable for testing/dev via `SPIDERWEB_GDRIVE_API_BASE_URL`, `SPIDERWEB_GDRIVE_UPLOAD_BASE_URL`, and `SPIDERWEB_GDRIVE_OAUTH_BASE_URL`.
- In API mode, gdrive exports now poll the Drive Changes feed and emit invalidation events (`INVAL` / `INVAL_DIR`) to keep mounted caches fresh.
- Changes polling now persists per-export page tokens (`gdrive_changes_v1` state) through credential storage when secure storage is available.
- Move/rename invalidations are parent-aware in API mode: node cache now tracks Drive parent IDs and invalidates old/new parent dirs when change metadata includes parent updates.
- GDrive write flushes now use resumable chunk upload sessions (default chunk size `256 KiB`) and enforce optimistic generation checks before commit.
- Router cache lookups now normalize names for case-insensitive exports, and case-only same-directory renames on case-insensitive sources are guarded as no-ops.
- Without API mode enabled, `gdrive` exports stay scaffolded and expose `.gdrive-status.txt` for diagnostics.

### Embedding As A Library

The filesystem stack is also exposed as module `spiderweb_fs` (`src/fs_lib.zig`) for multi-use programs.

```zig
const fs = @import("spiderweb_fs");

var service = try fs.NodeService.init(allocator, &[_]fs.ExportSpec{
    .{
        .name = "work",
        .path = ".",
        .ro = false,
        .source_kind = fs.SourceKind.linux,
        .source_id = "linux:work",
    },
});
defer service.deinit();

const response = try service.handleRequestJson("{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_hello\",\"tag\":1,\"payload\":{\"protocol\":\"unified-v2-fs\",\"proto\":2}}");
defer allocator.free(response);
```

Example program in this repo:
- Build: `zig build example-embed-fs-node`
- Run: `./zig-out/bin/embed-fs-node --export work=.:rw`

Multi-service embedding example (FS + health + echo in one process):
- Build: `zig build example-embed-multi-service-node`
- Run: `./zig-out/bin/embed-multi-service-node --port 19910 --export work=.:rw`
- Routes: `/v2/fs`, `/v1/health`, `/v1/echo`

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
- `ziggy-run-orchestrator` (run lifecycle engine + run-step orchestration helpers)

Compatibility wrapper files (`src/protocol*.zig`, `src/memory*.zig`, `src/run_store.zig`, `src/tool_*.zig`) were marked for removal on February 22, 2026 with a target of `v0.3.0`, and are now removed. Use direct module imports in new code.

Unified v2 FS/control migration details:
- `docs/UNIFIED_V2_FS_MIGRATION.md`

## Related Projects

- [ziggy-piai](https://github.com/DeanoC/ziggy-piai) - Pi AI provider abstraction
- [ZiggyStarClaw](https://github.com/DeanoC/ZiggyStarClaw) - OpenClaw client
- [OpenClaw](https://github.com/openclaw/openclaw) - Main gateway implementation

## License

MIT © 2026 DeanoC

See [LICENSE](LICENSE) for details.
