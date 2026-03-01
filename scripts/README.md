# Deployment Scripts

SystemD-based deployment scripts for ZiggySpiderWeb.

## Quick Install

```bash
cd scripts
sudo ./install-systemd.sh
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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INSTALL_USER` | `spiderweb` | System user to create |
| `INSTALL_DIR` | `/opt/spiderweb` | Binary installation path |
| `CONFIG_DIR` | `/etc/spiderweb` | Config directory |
| `SERVICE_NAME` | `spiderweb` | systemd service name |
| `PORT` | `18790` | Default listening port |
| `BIND_ADDR` | `0.0.0.0` | Default bind address |
| `PROVIDER_NAME` | `openai` | Provider written to generated config |
| `PROVIDER_MODEL` | `gpt-4o-mini` | Model written to generated config |
| `OVERWRITE_CONFIG` | `0` | If `1`, replace existing `/etc/spiderweb/config.json` |
| `OPENAI_API_KEY` | unset | Writes `OPENAI_API_KEY` to service env file when provider is `openai` |
| `OPENAI_CODEX_API_KEY` | unset | Writes `OPENAI_CODEX_API_KEY` for `openai-codex*` providers |

Example with custom settings:
```bash
sudo PORT=8080 BIND_ADDR=0.0.0.0 ./install-systemd.sh
```
