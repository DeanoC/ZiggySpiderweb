# Multi-Node Runtime Harness

This harness validates the end-to-end node runtime flow across Linux and
Windows nodes:

- pairing
- service/runtime discoverability
- reconnect handling
- runtime config persistence restore
- GUI visibility checks

## 1) Prerequisites

- Spiderweb server running (for example `ws://<server>:18790/`)
- `spiderweb-control` and `spiderweb-fs-mount` built on the server host
- `spiderweb-fs-node` built on Linux and Windows
- admin auth token available (`SPIDERWEB_AUTH_TOKEN`)

Optional:

- `zss` and `zss-gui` for interactive verification

## 2) Start Linux Node

Run a Linux node with manifests enabled (example):

```bash
./zig-out/bin/spiderweb-fs-node \
  --export "work=.:rw" \
  --control-url "ws://<server>:18790/" \
  --control-auth-token "<admin-token>" \
  --pair-mode request \
  --node-name "linux-edge" \
  --services-dir ./examples/services.d
```

Approve pairing if running in request mode:

```bash
spiderweb-control --url "ws://<server>:18790/" --auth-token "<admin-token>" pairing pending '{}'
```

## 3) Start Windows Node

Create invite:

```bash
spiderweb-control --url "ws://<server>:18790/" --auth-token "<admin-token>" node_invite_create '{}'
```

On Windows (PowerShell):

```powershell
.\spiderweb-fs-node.exe `
  --export "work=D:\Projects:rw" `
  --control-url "ws://<server>:18790/" `
  --control-auth-token "<admin-token>" `
  --pair-mode invite `
  --invite-token "<invite-token>" `
  --node-name "win-edge" `
  --services-dir ".\examples\services.d"
```

## 4) Automated Harness Script

Run from `ZiggySpiderweb`:

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

What it checks:

- expected nodes mount into workspace view
- expected services exist in `control.node_service_get`
- runtime surface exists (`config.json`, `status.json`, `health.json`)
- reconnect flap (offline -> online) for `RECONNECT_NODE_ID`
- persistence marker survives reconnect/startup for target service

## 5) Manifest Hot Reload Check

While node is running, edit a manifest in `--services-dir` (or a file given via
`--service-manifest`) and wait for the reload interval (default 2000ms, set via
`--manifest-reload-interval-ms`).

Then verify catalog update:

```bash
spiderweb-control --url "ws://<server>:18790/" --auth-token "<admin-token>" node_service_get '{"node_id":"node-2"}'
```

Expected:

- service add/remove/metadata change appears without restarting node process

## 6) GUI Visibility Check

Start `zss-gui`, connect to server URL, and verify:

- both Linux and Windows nodes appear in node tree
- service mounts are visible under `/nodes/<node>/...`
- runtime files render in filesystem panel (`control/*`, `health.json`, `status.json`)
- runtime actions (enable/disable/restart/invoke/config-set) are available

