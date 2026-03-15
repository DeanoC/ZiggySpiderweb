# Deployment Scripts

Deployment and maintenance helpers for the workspace-host version of Spiderweb.

These scripts are Linux-specific. On macOS, use `spiderweb-config config install-service` to install the per-user `launchd` service instead.

## Quick Install

```bash
cd scripts
sudo ./install-systemd.sh
```

This installs Spiderweb as a systemd-managed workspace host. It does not install or configure AI providers. External workers such as Spider Monkey should be deployed separately.

Useful overrides:

```bash
sudo PORT=18880 BIND_ADDR=127.0.0.1 SPIDER_WEB_ROOT=/srv/spiderweb ./install-systemd.sh
sudo OVERWRITE_CONFIG=1 ./install-systemd.sh
```

## Service Management

```bash
sudo systemctl start spiderweb
sudo systemctl stop spiderweb
sudo systemctl restart spiderweb
sudo systemctl status spiderweb
sudo journalctl -u spiderweb -f
```

## Workspace Flow

After the service is running:

```bash
export SPIDERWEB_CONFIG=/etc/spiderweb/config.json
spiderweb-config auth status --reveal
spiderweb-control --url ws://127.0.0.1:18790/ --auth-token <admin-token> workspace_create '{"name":"Demo","vision":"Mounted workspace","template_id":"dev"}'
spiderweb-fs-mount --workspace-url ws://127.0.0.1:18790/ --auth-token <admin-or-user-token> --workspace-id <workspace-id> mount ./workspace
```

Then start an external worker, for example Spider Monkey, against the mounted directory.

## Update

```bash
sudo ./scripts/update.sh
```

## Uninstall

```bash
sudo ./scripts/uninstall.sh
```

## Full Reset

```bash
./scripts/full-reset.sh
```

## Smoke Checks

Preflight:

```bash
./scripts/acheron-smoke.sh
```

Namespace-mode mount smoke:

```bash
./scripts/acheron-namespace-smoke.sh
```

Restart chaos test:

```bash
./scripts/acheron-chaos-restart.sh
```

Multi-node harness:

```bash
./scripts/acheron-multi-node-runtime.sh
```

## Removed Legacy Flows

The old Mother/provider bootstrap and embedded-runtime canary scripts were removed as part of the Spider Monkey split. Spiderweb no longer owns provider credentials, provider-backed chat, or Mother/system onboarding.
