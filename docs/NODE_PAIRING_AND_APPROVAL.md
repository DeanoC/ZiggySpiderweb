# Node Pairing and Approval

This document defines how nodes become trusted members of Spiderweb.

## Pairing Modes

- Invite-based pairing:
  - Operator creates an invite token (`control.node_invite_create`).
  - Node redeems invite (`control.node_join`) and receives node credentials.
- Manual approval pairing:
  - Node submits a pending request (`control.node_join_request`).
  - Operator reviews queue (`control.node_join_pending_list`).
  - Operator approves (`control.node_join_approve`) or denies (`control.node_join_deny`).

Both modes result in the same node identity material:

- `node_id`
- `node_secret`
- `lease_token`
- `lease_expires_at_ms`

## Control Operations

### `control.node_join_request`

Request payload:

```json
{
  "node_name": "desktop-west",
  "fs_url": "ws://10.0.0.8:18891/v2/fs",
  "platform": { "os": "linux", "arch": "amd64", "runtime_kind": "native" }
}
```

Response payload includes:

- `request_id`
- `node_name`
- `fs_url`
- `platform`
- `requested_at_ms`

### `control.node_join_pending_list`

Request payload may be `{}`.

Response payload:

```json
{
  "pending": [
    {
      "request_id": "pending-join-1",
      "node_name": "desktop-west",
      "fs_url": "ws://10.0.0.8:18891/v2/fs",
      "platform": { "os": "linux", "arch": "amd64", "runtime_kind": "native" },
      "requested_at_ms": 1739900000000
    }
  ]
}
```

### `control.node_join_approve`

Request payload:

```json
{
  "request_id": "pending-join-1",
  "lease_ttl_ms": 900000
}
```

Response is the same join credential envelope as `control.node_join`.

### `control.node_join_deny`

Request payload:

```json
{
  "request_id": "pending-join-1"
}
```

Response payload:

```json
{
  "denied": true,
  "request_id": "pending-join-1"
}
```

## Auth and Role Expectations

- Approval queue operations are admin-only.
- Approval queue operations require operator-scope auth token if configured.
- `control.node_join_request` is intentionally non-admin to allow unpaired join proposals.

## Node Daemon Loop (`spiderweb-fs-node`)

`spiderweb-fs-node` can now run as a pairing/lease daemon when `--control-url` is set.

Behavior:

- Loads persisted node state from `--state-file` (default `.spiderweb-fs-node-state.json`).
- If not paired:
  - `--pair-mode invite`: calls `control.node_join` using `--invite-token`.
  - `--pair-mode request`: calls `control.node_join_request`, then retries `control.node_join_approve`.
- Once paired, uses `node_secret` as FS session auth token (unless `--auth-token` is explicitly provided).
- Runs a background lease refresh loop via `control.node_lease_refresh`.
- Publishes node capability/service metadata via `control.node_service_upsert`:
  - FS provider enabled by default.
  - terminal providers from `--terminal-id`.
  - labels from `--label`.
- Persists updated lease fields (`lease_token`, `lease_expires_at_ms`) after each successful refresh.
- Uses reconnect backoff for both pairing retries and lease refresh failures.

Key flags:

- `--control-url <ws://host:port/>`
- `--control-auth-token <token>` (or `SPIDERWEB_AUTH_TOKEN`)
- `--pair-mode invite|request`
- `--invite-token <token>` (required for invite mode)
- `--node-name <name>`
- `--fs-url <ws://host:port/v2/fs>` (advertised node URL)
- `--state-file <path>`
- `--lease-ttl-ms <ms>`
- `--refresh-interval-ms <ms>`
- `--reconnect-backoff-ms <ms>`
- `--reconnect-backoff-max-ms <ms>`
- `--no-fs-service` (disable default FS service advertisement)
- `--terminal-id <id>` (repeatable)
- `--label <key=value>` (repeatable)
