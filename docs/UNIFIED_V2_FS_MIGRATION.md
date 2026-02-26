# Unified v2 FS/Control Migration

This release is **unified v2 only**. Legacy compatibility paths were removed.

## Breaking Protocol Changes

1. FS wire type names are canonicalized:
- old: `acheron.fs_t_*`, `acheron.fs_r_*`, `acheron.fs_evt_*`, `acheron.fs_error`
- new: `acheron.t_fs_*`, `acheron.r_fs_*`, `acheron.e_fs_*`, `acheron.err_fs`

2. Envelope contract is strict in unified v2:
- `channel` is required on every message (`control` or `acheron`)
- `type` must match the selected channel namespace
- legacy/implicit compatibility names are rejected

3. Control protocol negotiation is mandatory:
- first control message must be `control.version`
- payload must include `{"protocol":"unified-v2"}`

4. Runtime Acheron negotiation is mandatory:
- first runtime Acheron message must be `acheron.t_version`
- `version` must be `acheron-1`

5. FS node/session negotiation is mandatory:
- first FS message must be `acheron.t_fs_hello`
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
- `control.workspace_status` accepts optional payload `{"project_id":"<id>","project_token":"<token>"}`.
- explicit `project_id` selection now requires either a matching `project_token` or an existing active binding for that agent.
- `spiderweb-fs-mount` supports `--project-id <id> [--project-token <token>]`
- workspace topology mount entries now expose both `online` (`bool`) and `state` (`online`, `degraded`, `missing`) fields.
- when multiple mounts share a `mount_path`, control-plane selection is deterministic and availability-aware (`online` > `degraded` > `missing`, then latest lease expiry).

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
- router/mount clients pass `auth_token` in `acheron.t_fs_hello` when provided by workspace topology

## Minimal Client Flow (Control)

1. `control.version` (`{"protocol":"unified-v2"}`)
2. `control.connect`
3. normal control operations (`control.metrics`, `control.workspace_status`, project/node ops, etc.)

`spiderweb-control` now automates this negotiation and sends a single control operation.

## Minimal Client Flow (Runtime Acheron)

1. `acheron.t_version` (`"version":"acheron-1"`)
2. `acheron.t_attach`
3. remaining Acheron operations
