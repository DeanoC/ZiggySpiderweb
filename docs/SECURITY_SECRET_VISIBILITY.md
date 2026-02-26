# Security: Secret Visibility

This document defines when node secrets are exposed in control-plane responses.

## Default Rule

Node auth material is not exposed to normal agent views.

In workspace topology payloads (`control.workspace_status`), `fs_auth_token` is:

- `null` for non-primary agents
- present only for the primary/system agent (`mother` by default)

## Rationale

- Prevent accidental propagation of node credentials into general agent context.
- Keep least-privilege defaults for project and workspace inspection.
- Preserve privileged operator/system workflows that require direct token visibility.

## Current Surface

Applies to mount entries in:

- `mounts`
- `desired_mounts`
- `actual_mounts`

within `control.workspace_status` payloads.

## Future Direction

Longer-term, these static node secrets should be replaced with scoped and expiring credentials bound to:

- project
- mount path
- session
- TTL

