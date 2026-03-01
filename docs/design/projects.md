# Projects (Current Model)

Projects are the unit of workspace composition and access policy in Spiderweb. They are managed by the control plane and surfaced in WorldFS under `/projects/<project_id>`.

## Project Fields (Control Payload)

`control.project_*` responses include:

- `project_id`
- `name`
- `vision`
- `status`
- `kind` (for example `system_builtin` or `user`)
- `is_delete_protected`
- `token_locked`
- `created_at_ms`
- `updated_at_ms`
- `project_token` (admin only / when requested)
- `access_policy`

## Workspace & Mounts

A project’s workspace is built from mounts that map node exports into project paths. The control plane exposes:

- `control.project_mount_set`
- `control.project_mount_remove`
- `control.project_mount_list`
- `control.workspace_status`

WorldFS projects the workspace into:

- `/projects/<project_id>/fs`
- `/projects/<project_id>/nodes`
- `/projects/<project_id>/agents`
- `/projects/<project_id>/meta`

`/projects/<project_id>/meta` includes `workspace_status.json`, `mounts.json`, `desired_mounts.json`, `actual_mounts.json`, `drift.json`, and availability/health summaries.

## Tokens & Access Policy

Projects can require a token for specific actions. The access policy supports action-scoped checks:

- `read`
- `observe`
- `invoke`
- `mount`
- `admin`

Admin tokens bypass project token checks. User tokens must satisfy the project’s policy and any service-level permissions.

## Implementation Pointers

- Control plane: `src/fs_control_plane.zig`
- Control gateway: `src/server_piai.zig`
- WorldFS projection: `src/fsrpc_session.zig`
