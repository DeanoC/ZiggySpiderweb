# Unified-v2 Control: Agents & Sessions

This document describes the control-plane handshake plus the agent discovery and session control operations that Spiderweb implements today.

## Handshake (Required)

All control operations require an explicit negotiation:

1. `control.version` with payload `{"protocol":"unified-v2"}`
2. `control.connect`

`control.version_ack` returns protocol + FS protocol hints:
- `protocol` (currently `unified-v2`)
- `fsrpc_runtime` (currently `acheron-1`)
- `fsrpc_node` (currently `unified-v2-fs`)
- `fsrpc_node_proto` (currently `2`)

`control.connect_ack` returns session binding and gating information:
- `agent_id`
- `project_id` (nullable)
- `session` (current session key)
- `protocol`
- `role` (`admin` | `user`)
- `bootstrap_only` (bool)
- `bootstrap_message` (nullable)
- `requires_session_attach` (bool)
- `connect_gate` (nullable `{code,message}`)

## Agent Discovery

### `control.agent_list`
Returns all agent registry entries.

### `control.agent_get`
Requires payload `{"agent_id":"<id>"}`.

Agent fields:
- `id`
- `name`
- `description`
- `is_default`
- `identity_loaded`
- `needs_hatching`
- `capabilities` (array of `chat`, `code`, `plan`, `research`)

Errors:
- `agent_not_found`
- `missing_field`
- `invalid_payload`

## Session Control

Supported operations:
- `control.session_attach`
- `control.session_status`
- `control.session_resume`
- `control.session_list`
- `control.session_close`
- `control.session_restore`
- `control.session_history`

### `control.session_attach`
Payload:
- `session_key` (required)
- `agent_id` (required)
- `project_id` (optional)
- `project_token` (optional)

Notes:
- User role cannot attach to the system agent/project.
- When no non-system project exists, users will be gated until an admin provisions one.
- If a project requires a token, `project_token` is required for token-scoped actions.

Response payload:
- `session_key`
- `agent_id`
- `project_id` (nullable)
- `workspace` (workspace status snapshot)
- `attach` (runtime attach state snapshot)

### `control.session_status`
Payload:
- `session_key` (optional; defaults to active session)

Response payload:
- `session_key`
- `agent_id`
- `project_id` (nullable)
- `attach` (runtime attach state snapshot)
- `session_last_activity_ms`
- `session_stale`
- `agent_last_heartbeat_ms`
- `agent_stale`
- `recoverable`

### `control.session_resume`
Payload:
- `session_key` (required)

### `control.session_list`
Response payload:
- `active_session`
- `sessions[]` entries with `session_key`, `agent_id`, `project_id`

### `control.session_close`
Payload:
- `session_key` (required)

### `control.session_restore`
Payload:
- `agent_id` (optional)

Response payload:
- `{"found":false}` when no persisted session exists
- `{"found":true,"session":{...}}` when a session is available

Returned `session` fields:
- `session_key`
- `agent_id`
- `project_id`
- `last_active_ms`
- `message_count`
- `summary` (nullable)

### `control.session_history`
Payload:
- `agent_id` (optional)
- `limit` (optional, default 10, max 100)

Response payload:
- `sessions` list (newest-first)

## Related Control Operations

- `control.project_*`, `control.workspace_status` for project provisioning
- `control.node_*` and `control.node_service_*` for node lifecycle and service catalog
- `control.auth_status`, `control.auth_rotate` for control-plane tokens
- `control.audit_tail` for audit trail

## Implementation Notes

Primary references:
- `src/server_piai.zig`
- `src/agent_registry.zig`
- `ZiggySpiderProtocol/src/unified_types.zig`
