# Deployment Scripts

SystemD-based deployment scripts for Spiderweb.

## Quick Install

```bash
cd scripts
sudo PROVIDER_NAME=openai-codex PROVIDER_MODEL=gpt-5.3-codex ./install-systemd.sh
```

This will:
- Build the project in ReleaseSafe mode
- Create `spiderweb` system user
- Install binaries to `/opt/spiderweb/`
- Install config to `/etc/spiderweb/`
- Create data/logs directories
- Install and enable systemd service

## Configuration

Edit config after install:
```bash
sudo spiderweb-config config
# or directly:
sudo nano /etc/spiderweb/config.json
```

Set credentials for the active provider:
```bash
# API key providers
sudo OPENAI_API_KEY="sk-..." ./install-systemd.sh

# OAuth providers (run as service user so tokens are stored for that account)
sudo -u spiderweb HOME=/home/spiderweb SPIDERWEB_CONFIG=/etc/spiderweb/config.json /opt/spiderweb/bin/spiderweb-config oauth login openai-codex --no-set-provider

# Optional: set provider explicitly in config
sudo SPIDERWEB_CONFIG=/etc/spiderweb/config.json spiderweb-config config set-provider openai-codex gpt-5.1-codex-mini
```

## Service Management

```bash
# Start/stop/restart
sudo systemctl start spiderweb
sudo systemctl stop spiderweb
sudo systemctl restart spiderweb

# View logs
sudo journalctl -u spiderweb -f

# Check status
sudo systemctl status spiderweb
```

## Update

After pulling new code:
```bash
sudo ./scripts/update.sh
```

## Uninstall

```bash
sudo ./scripts/uninstall.sh
```

This removes everything but backs up config to `/root/spiderweb-config-backup-*/`.

## Full Reset (Double Confirm)

```bash
./scripts/full-reset.sh
```

This performs a full local + system cleanup for fresh-install testing and requires two separate confirmations before any cleanup starts.

## Acheron Smoke Check

Run a preflight check that validates the active workspace topology before starting runtime workloads:

```bash
./scripts/acheron-smoke.sh
```

Optional environment overrides:

```bash
SPIDERWEB_URL=ws://127.0.0.1:18790/ \
SPIDERWEB_PROJECT_ID=system \
SPIDERWEB_AUTH_TOKEN=sw-admin-... \
EXPECTED_NODES=node-1,node-3 \
./scripts/acheron-smoke.sh
```

More smoke options:

```bash
SPIDERWEB_AUTH_TOKEN_FILE="$HOME/.local/share/ziggy-spiderweb/.spiderweb-ltm/auth_tokens.json" \
SMOKE_TIMEOUT_SEC=20 \
SMOKE_FAIL_ON_DEGRADED=0 \
./scripts/acheron-smoke.sh
```

What it checks:
- `control.workspace_status` returns a valid payload
- workspace availability is not degraded/missing (unless `SMOKE_FAIL_ON_DEGRADED=0`)
- every active mount path is readable through `spiderweb-fs-mount`
- expected node IDs (if provided) are present in active mounts

## Namespace Mount Smoke Check

Run a standalone namespace-mode smoke check for `spiderweb-fs-mount`:

Linux:
```bash
SPIDERWEB_PROJECT_ID=system ./scripts/acheron-namespace-smoke.sh
```

Windows:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acheron-namespace-smoke.ps1
```

Optional overrides:

```bash
SPIDERWEB_URL=ws://127.0.0.1:18790/ \
SPIDERWEB_PROJECT_ID=system \
SPIDERWEB_AUTH_TOKEN=sw-admin-... \
SPIDERWEB_AGENT_ID=external-smoke \
SMOKE_USE_OS_MOUNT=1 \
SMOKE_MOUNTPOINT=/tmp/spiderweb-fs-smoke \
./scripts/acheron-namespace-smoke.sh
```

What it checks:
- namespace mode attaches successfully and `status --no-probe` reports `mode == "namespace"`
- `/agents`, `/nodes`, and `/global` are readable
- `/meta/protocol.json` is readable and valid JSON
- a writable routed filesystem export can create and read back a smoke file
- a synthetic namespace mutation (default: `mkdir /agents/__spiderweb_fs_mount_smoke__`) fails as expected
- when `SMOKE_USE_OS_MOUNT=1`, the same namespace is also validated through a real local mountpoint

## Acheron Chaos Restart Check

Run active read/list probes while restarting the user service mid-run:

```bash
./scripts/acheron-chaos-restart.sh
```

Optional overrides:

```bash
SPIDERWEB_SERVICE=spiderweb.service \
SPIDERWEB_PROJECT_ID=system \
CHAOS_ITERATIONS=40 \
CHAOS_RESTART_AT=12 \
CHAOS_INTERVAL_MS=500 \
CHAOS_LIST_PATH=/nodes \
CHAOS_ATTR_PATH=/nodes \
./scripts/acheron-chaos-restart.sh
```

What it checks:
- repeated `readdir` and `getattr` operations during a forced service restart
- at least one successful probe before restart
- at least three successful probes after restart (recovery validated)

## Multi-Node Runtime Harness

Run end-to-end checks across multiple nodes (including reconnect + persistence marker):

```bash
SPIDERWEB_URL=ws://127.0.0.1:18790/ \
SPIDERWEB_AUTH_TOKEN=sw-admin-... \
EXPECTED_NODES=node-1,node-2 \
EXPECTED_SERVICES=echo-main \
RECONNECT_NODE_ID=node-2 \
PERSISTENCE_NODE_ID=node-2 \
PERSISTENCE_SERVICE_ID=echo-main \
./scripts/acheron-multi-node-runtime.sh
```

Companion runbook (Linux + Windows node setup):

- `docs/MULTI_NODE_RUNTIME_HARNESS.md`

## Mother Bootstrap Provider Canary

Run an end-to-end first-run bootstrap canary against a real provider:

```bash
./scripts/manual-mother-provider-canary.sh
```

What it validates:
- Mother-only first connect (`bootstrap_only=true`)
- provider-backed Mother chat response over Acheron
- first project provisioning with `vision`
- first non-system agent create + `HATCH.md` scaffold
- successful `control.session_attach` to provisioned project/agent
- bootstrap mode exit (`bootstrap_only=false`)

Useful overrides:

```bash
KEEP_CANARY_DIR=1 ./scripts/manual-mother-provider-canary.sh
CANARY_PROVIDER_NAME=openai CANARY_PROVIDER_MODEL=gpt-4o-mini ./scripts/manual-mother-provider-canary.sh
```

## Mother-Driven Agent Workflow E2E

Run an end-to-end canary for project/agent/mount/bind/resolve.

```bash
./scripts/manual-mother-agent-e2e.sh
```

Modes:

- `MOTHER_E2E_MODE=provider_chat` (default): Mother does setup work via chat/tool use.
- `MOTHER_E2E_MODE=deterministic`: script writes control files directly (CI-friendly, no provider call required).

What it validates:
- first connect starts in bootstrap mode (`bootstrap_only=true`)
- provider-backed Mother chat can execute a multi-step workflow
- Mother creates a new non-system project and first agent
- Mother performs `mount`, `bind`, and `resolve` via `/global/mounts/control/*.json`
- result verification confirms mounted path and bind target
- attach to the Mother-created `(project_id, agent_id)` succeeds and bootstrap mode exits

Useful overrides:

```bash
KEEP_CANARY_DIR=1 ./scripts/manual-mother-agent-e2e.sh
PROJECT_NAME=my-e2e AGENT_ID=my-e2e-agent ./scripts/manual-mother-agent-e2e.sh
CANARY_PROVIDER_NAME=openai-codex CANARY_PROVIDER_MODEL=gpt-5.3-codex ./scripts/manual-mother-agent-e2e.sh
MOTHER_E2E_MODE=deterministic ./scripts/manual-mother-agent-e2e.sh
MOTHER_E2E_MODE=provider_chat CANARY_PROVIDER_NAME=openai-codex CANARY_PROVIDER_MODEL=gpt-5.3-codex ./scripts/manual-mother-agent-e2e.sh
```

Run both deterministic + provider-chat in one command (uses `~/.codex/auth.json` automatically when present):

```bash
./scripts/mother-agent-e2e-suite.sh

# force provider mode on/off
RUN_PROVIDER_CHAT=1 ./scripts/mother-agent-e2e-suite.sh
RUN_PROVIDER_CHAT=0 ./scripts/mother-agent-e2e-suite.sh

# CI usage (reuse prior build artifacts)
SKIP_BUILD=1 ./scripts/mother-agent-e2e-suite.sh
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INSTALL_USER` | `spiderweb` | System user to create |
| `INSTALL_DIR` | `/opt/spiderweb` | Binary installation path |
| `CONFIG_DIR` | `/etc/spiderweb` | Config directory |
| `SERVICE_NAME` | `spiderweb` | systemd service name |
| `PORT` | `18790` | Default listening port |
| `BIND_ADDR` | `0.0.0.0` | Default bind address |
| `PROVIDER_NAME` | required | Provider written to generated config (required for new/overwrite installs) |
| `PROVIDER_MODEL` | required | Model written to generated config (required for new/overwrite installs) |
| `OVERWRITE_CONFIG` | `0` | If `1`, replace existing `/etc/spiderweb/config.json` |
| `OPENAI_API_KEY` | unset | Writes `OPENAI_API_KEY` to service env file when provider is `openai` |
| `OPENAI_CODEX_API_KEY` | unset | Writes `OPENAI_CODEX_API_KEY` for `openai-codex*` providers |

Example with custom settings:
```bash
sudo PORT=8080 BIND_ADDR=0.0.0.0 PROVIDER_NAME=openai-codex PROVIDER_MODEL=gpt-5.3-codex ./install-systemd.sh
```

Current system-project scope note:
- `SPIDER_WEB_ROOT` defaults to `/`, so the `system` project (Mother) is host-wide by default.
- Restrict scope by setting `SPIDER_WEB_ROOT` to a narrower path during install.
