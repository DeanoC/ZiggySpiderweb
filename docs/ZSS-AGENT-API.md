# ZSS Agent Discovery & Session Control API

This document describes the current unified-v2 control operations used by ZSS for agent discovery and session control.

## Unified-v2 Control Handshake

Clients must negotiate control first:

1. `control.version`
2. `control.connect`

Only after that should clients send additional control operations.

## Agent Discovery (Implemented)

### `control.agent_list`

Request:

```json
{
  "channel": "control",
  "type": "control.agent_list",
  "id": "req-agent-list"
}
```

Response payload:

```json
{
  "agents": [
    {
      "id": "mother",
      "name": "Mother",
      "description": "Primary orchestrator",
      "is_default": true,
      "identity_loaded": true,
      "needs_hatching": false,
      "capabilities": ["chat", "plan"]
    }
  ]
}
```

### `control.agent_get`

Request:

```json
{
  "channel": "control",
  "type": "control.agent_get",
  "id": "req-agent-get",
  "payload": {
    "agent_id": "mother"
  }
}
```

Response payload:

```json
{
  "agent": {
    "id": "mother",
    "name": "Mother",
    "description": "Primary orchestrator",
    "is_default": true,
    "identity_loaded": true,
    "needs_hatching": false,
    "capabilities": ["chat", "plan"]
  }
}
```

Errors:
- `agent_not_found`
- `missing_field`
- `invalid_payload`

## Session Control (Current)

Available session operations today:
- `control.session_attach`
- `control.session_status`
- `control.session_resume`
- `control.session_list`
- `control.session_close`

These provide in-connection session switching/listing. Persistent "restore last active session with summary" remains planned work in `docs/plan-agent-discovery-restore.md`.
