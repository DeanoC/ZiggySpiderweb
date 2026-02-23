# Unified v2 FS/Control Migration

This release is **unified v2 only**. Legacy compatibility paths were removed.

## Breaking Protocol Changes

1. FS wire type names are canonicalized:
- old: `fsrpc.fs_t_*`, `fsrpc.fs_r_*`, `fsrpc.fs_evt_*`, `fsrpc.fs_error`
- new: `fsrpc.t_fs_*`, `fsrpc.r_fs_*`, `fsrpc.e_fs_*`, `fsrpc.err_fs`

2. Envelope contract is strict in unified v2:
- `channel` is required on every message (`control` or `fsrpc`)
- `type` must match the selected channel namespace
- legacy/implicit compatibility names are rejected

3. Control protocol negotiation is mandatory:
- first control message must be `control.version`
- payload must include `{"protocol":"unified-v2"}`

4. Runtime fsrpc negotiation is mandatory:
- first runtime fsrpc message must be `fsrpc.t_version`
- `version` must be `styx-lite-1`

5. FS node/session negotiation is mandatory:
- first FS message must be `fsrpc.t_fs_hello`
- payload must include `{"protocol":"unified-v2-fs","proto":2}`
- if FS session auth is enabled, payload must also include `{"auth_token":"..."}` with a matching token

6. `control.ping` is liveness-only:
- `control.pong` payload is now `{}`
- use `control.metrics` for control-plane metrics

## New Control Capabilities

1. Project token lifecycle:
- `control.project_token_rotate`
- `control.project_token_revoke`

2. Optional workspace selection:
- `control.workspace_status` accepts optional payload `{"project_id":"<id>"}`
- `spiderweb-fs-mount` supports `--project-id <id>`

## New Optional Hardening/Ops Flags

1. `SPIDERWEB_CONTROL_OPERATOR_TOKEN`
- when set, protected control mutations require `payload.operator_token`

2. `SPIDERWEB_CONTROL_STATE_KEY_HEX`
- 64 hex chars (AES-256 key)
- enables encryption-at-rest for control-plane snapshots

3. `SPIDERWEB_METRICS_PORT`
- enables:
  - `GET /livez` (liveness)
  - `GET /readyz` (readiness)
  - `GET /metrics` (Prometheus text)
  - `GET /metrics.json` (JSON metrics)

4. `SPIDERWEB_FS_NODE_AUTH_TOKEN` / `spiderweb-fs-node --auth-token`
- enables FS session auth enforcement on `/v2/fs`
- router/mount clients pass `auth_token` in `fsrpc.t_fs_hello` when provided by workspace topology

## Minimal Client Flow (Control)

1. `control.version` (`{"protocol":"unified-v2"}`)
2. `control.connect`
3. normal control operations (`control.metrics`, `control.workspace_status`, project/node ops, etc.)

`spiderweb-control` now automates this negotiation and sends a single control operation.

## Minimal Client Flow (Runtime fsrpc)

1. `fsrpc.t_version` (`"version":"styx-lite-1"`)
2. `fsrpc.t_attach`
3. remaining fsrpc operations
