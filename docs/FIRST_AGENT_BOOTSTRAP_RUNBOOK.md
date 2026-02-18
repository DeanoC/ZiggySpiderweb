# First Agent Bootstrap Ops Runbook

This runbook is for bringing up the first live agent (for example `ziggy`) and validating bootstrap behavior end-to-end.

## 1) Verify Config

Check `~/.config/spiderweb/config.json`:

- `server.bind` and `server.port` are reachable from your client machine
- `provider.name` and `provider.model` are valid
- `runtime.default_agent_id` is set to your first agent id (for example `ziggy`)
- `runtime.ltm_directory` and `runtime.ltm_filename` are set

Quick check:

```bash
spiderweb-config config
```

## 2) Start Spiderweb

```bash
spiderweb
```

For remote LAN testing:

- bind with `0.0.0.0`
- open firewall for the configured port

## 3) Connect from Client

Use base websocket URL (routing is internal):

```text
ws://<host>:<port>
```

Do not require direct route paths for normal startup chat.

## 4) Expected Connect Sequence

On first connect for a new/default agent:

1. server sends `connect.ack` immediately
2. server may send one bootstrap `session.receive` message

On later connects:

1. server sends `connect.ack`
2. no bootstrap message (unless bootstrap marker/memory was reset)

## 5) Quick Wire Test

```bash
printf '{"id":"c1","type":"connect"}\n' | websocat -n1 ws://127.0.0.1:18790
```

Then send a chat turn:

```bash
printf '{"id":"m1","type":"session.send","content":"hello"}\n' | websocat -n1 ws://127.0.0.1:18790
```

## 6) Troubleshooting

- `connection refused`
  - server not running, wrong bind address, wrong port, or firewall block
- `missing provider API key`
  - configure secure key storage or provider env var
- `provider stream failed`
  - verify provider auth/token, model name, and upstream provider status
  - for Codex debugging:
    - run with `ZIGGY_DEBUG_CODEX_ERRORS=1 spiderweb`
- connects but no bootstrap
  - expected after first successful bootstrap
  - inspect/reset bootstrap marker memory if you need to force bootstrap again

## 7) Operational Notes

- Identity memories (`system.soul`, `system.agent`, `system.identity`) are rehydrated from persisted LTM on restart.
- Bootstrap and chat use the runtime queue; ACK is intentionally immediate so client connection state is not blocked by provider latency.
