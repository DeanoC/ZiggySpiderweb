# Agent + Project Policy (Acheron)

Status: active

This document captures the baseline policy for agent/project access in the Acheron world model.

## Baseline Rules

- `mother` is the primary system agent and is bound to project `system`.
- Project `system` is admin-only for non-primary agents.
- User-role sessions can access non-system projects when policy/token checks pass.
- Projects without a token are open to authenticated user/admin sessions (subject to per-action access policy and service permissions).
- Projects with a token require that token for token-scoped actions unless the actor is admin.
- Admin sessions bypass project token requirements.

## Action Model

Project action checks are enforced per operation:

- `read`
- `observe`
- `invoke`
- `mount`
- `admin`

Service-level invoke also requires service permissions (`PERMISSIONS.json`) and project action `invoke`.

## Workspace Projection Rules

- Workspace mounts are selected availability-aware (`online` > `degraded` > `missing`).
- Invoke-capable mounts are omitted for non-admin actors when project `invoke` policy or service permissions deny invoke access.
- Tokenless projects expose mutable mount operations to user/admin roles unless explicit action policy denies them.

## Runtime Binding Expectations

- Every active runtime binding has an `(agent_id, project_id)` tuple.
- If a project is unavailable or denied for a principal, attach/restore falls back to an allowed target; otherwise the binding remains unavailable.
- System target fallback is reserved for admin and primary-system behavior.

## Related Sources

- `src/fs_control_plane.zig`
- `src/server_piai.zig`
- `docs/security/auth-session-safety.md`
- `docs/security/secret-visibility.md`
