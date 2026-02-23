# ZiggySpiderweb Test Environment

Docker-based testing environment for ZiggySpiderweb. This creates a clean, disposable Debian container for testing the install script and Spiderweb functionality without affecting your main server.

## Quick Start

```bash
# Build and start the test environment
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build

# Enter the running container
docker exec -it spiderweb-test bash

# Inside the container, run the install script
./install.sh
```

## Manual Testing

```bash
# Build the image
docker build -t spiderweb-test .

# Run interactively
docker run -it --rm --name spiderweb-test spiderweb-test

# Run with API key from environment (for automated testing)
docker run -it --rm \
  -e SPIDERWEB_PROVIDER=openai \
  -e SPIDERWEB_MODEL=gpt-4o-mini \
  -e SPIDERWEB_API_KEY=sk-xxx \
  spiderweb-test

# Run with port forwarding (to test from host)
docker run -it --rm \
  -p 18790:18790 \
  --name spiderweb-test \
  spiderweb-test
```

## Testing the Install Script

```bash
# Test the full interactive install
curl -fsSL https://raw.githubusercontent.com/DeanoC/ZiggySpiderweb/main/install.sh | bash

# Or run with pre-configured values (non-interactive mode coming soon)
```

## Embedded Multi-Service Integration Test

This repo also includes a local CI-style integration test for the embeddable
filesystem + health services example.

```bash
# Run directly
bash test-env/test-embed-multi-service.sh

# Or through make
cd test-env && make test-embed-multi-service
```

What it validates:
- boots `embed-multi-service-node` with a temporary export
- probes `/v2/fs` via `spiderweb-fs-mount` (`readdir` + `cat`)
- probes `/v1/health` with a raw WebSocket handshake and validates `ok: true`

Useful env vars:
- `PORT` (default `21910`)
- `BIND_ADDR` (default `127.0.0.1`)
- `SKIP_BUILD=1` to skip `zig build` if binaries are already built

## Distributed Workspace Failover Test

This test exercises the control-plane + mount integration flow end-to-end:
- starts `spiderweb`
- starts two `embed-multi-service-node` filesystem nodes
- negotiates `control.version` (`unified-v2`) then runs `control.node_invite_create`, `control.node_join`, `control.project_create`, `control.project_mount_set`, and `control.project_activate` with project mutation auth (`project_token`)
- restarts `spiderweb` and verifies control-plane state is recovered from persisted LTM snapshot
- updates mounts live (`/src` -> `/live`) and validates the mount client converges to the new path
- mounts both nodes at the same project mount path (`/src`) as a failover group
- verifies reads initially come from node A/B, kills the active node, and verifies failover
- restarts the stopped node, rejoins/remounts it, then kills the surviving node to verify second failover convergence

```bash
# Run directly
bash test-env/test-distributed-workspace.sh

# Or through make
cd test-env && make test-distributed-workspace
cd test-env && make test-distributed-workspace-encrypted
cd test-env && make test-distributed-workspace-operator-token
cd test-env && make test-distributed-soak-chaos
```

Useful env vars:
- `SPIDERWEB_PORT` (default `28790`)
- `NODE1_PORT` (default `28911`)
- `NODE2_PORT` (default `28912`)
- `BIND_ADDR` (default `127.0.0.1`)
- `SPIDERWEB_CONTROL_OPERATOR_TOKEN` (optional; include `operator_token` in protected mutations if enabled)
- `SPIDERWEB_CONTROL_STATE_KEY_HEX` (optional; enables encrypted control-plane snapshot storage)
- `ASSERT_OPERATOR_TOKEN_GATE=1` (optional; assert mutation deny/allow behavior before the main workflow)
- `SPIDERWEB_METRICS_PORT` (optional; enables HTTP `/livez`, `/readyz`, `/metrics` (Prometheus), `/metrics.json` (JSON))
- `SKIP_BUILD=1` to skip `zig build` if binaries are already built

## Soak / Chaos Suite

Runs the distributed workspace flow repeatedly with randomized ports and optional auth/encryption modes.

```bash
# Run directly
bash test-env/test-distributed-soak-chaos.sh

# Or through make
cd test-env && make test-distributed-soak-chaos
```

Useful env vars:
- `SOAK_ITERATIONS` (default `10`)
- `SOAK_ENABLE_OPERATOR_MODE=0|1` (default `1`)
- `SOAK_ENABLE_ENCRYPTED_MODE=0|1` (default `1`)

## Wiping and Restarting

```bash
# Stop and remove container (data is lost - this is the point!)
docker-compose down

# Remove the image to force rebuild
docker-compose down --rmi local

# Start fresh
docker-compose up --build
```

## Files

- `Dockerfile` - Minimal Debian with dependencies pre-installed
- `docker-compose.yml` - Container orchestration
- `test-install.sh` - Automated test of the install script
