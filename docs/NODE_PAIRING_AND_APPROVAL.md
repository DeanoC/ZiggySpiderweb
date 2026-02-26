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

