# Agent Management and Sub-Brains

Two namespaces cover agent topology management:

- `/agents/self/agents` for agent inventory and creation
- `/agents/self/sub_brains` for per-agent sub-brain lifecycle

Common operation mapping:

- `list`: read inventory/state
- `create` (agents): create a new managed agent workspace
- `upsert` (sub_brains): create or update a sub-brain config
- `delete` (sub_brains): remove a sub-brain config

Capability and permission notes:

- Agent creation requires agent provisioning capability.
- Sub-brain mutations require sub-brain management capability.
- Always inspect `PERMISSIONS.json` and `CAPS.json` before mutations.

Safe mutation workflow:

1. List current state first.
2. Submit the narrowest mutation payload needed.
3. Check `status.json` then `result.json`.
4. Re-list to verify final state matches intent.

Avoid editing multiple management namespaces in one step unless the runtime and
policy explicitly guarantee ordering and rollback behavior.
