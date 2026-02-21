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

Set your API key:
```bash
export OPENAI_API_KEY="sk-..."
# Or use the config CLI:
sudo spiderweb-config set-key "sk-..."
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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INSTALL_USER` | `spiderweb` | System user to create |
| `INSTALL_DIR` | `/opt/spiderweb` | Binary installation path |
| `CONFIG_DIR` | `/etc/spiderweb` | Config directory |
| `SERVICE_NAME` | `spiderweb` | systemd service name |
| `PORT` | `18790` | Default listening port |
| `BIND_ADDR` | `127.0.0.1` | Default bind address |

Example with custom settings:
```bash
sudo PORT=8080 BIND_ADDR=0.0.0.0 ./install-systemd.sh
```
