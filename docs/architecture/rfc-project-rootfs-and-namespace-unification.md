# RFC: Project RootFS and Namespace Unification

Status: Proposed  
Owner: Spiderweb runtime  
Updated: 2026-03-03

## Summary

Spiderweb currently exposes multiple path "worlds" to agents:

1. Host paths (for operators), e.g. `/safe/...`
2. Acheron WorldFS paths, e.g. `/nodes/local/fs/safe/...`
3. Internal sandbox paths, e.g. `/underworld/...`

This is functionally workable but cognitively expensive. Agents can see different path semantics between `file_*` operations and terminal operations, which causes repeated routing mistakes and confusing operator guidance.

This RFC proposes a unified model:

- A project runs in an isolated project root filesystem (Project RootFS, Debian-based by default).
- Acheron is mounted as the runtime namespace seen by tools and terminal, with one canonical path model.
- Internal sandbox mountpoints (like `/underworld`) become implementation details and are never surfaced to agents/operators.

The goal is for Spiderweb to act as an "agent OS" hosted by the underlying Linux machine.

## Motivation

### Current pain points

- Path duality: shell commands can observe internal sandbox mountpoints while Acheron file APIs expect namespace paths.
- Control-plane operations (project mounts, bind paths) accept canonical world paths while agents often attempt internal paths.
- UI and agent prompts need special-case path translation logic, increasing complexity.

### Desired properties

- One mental model for agent path reasoning.
- Consistent behavior across terminal and file tools.
- Better project isolation and reproducibility via image + overlay + snapshots.
- Explicit capability boundaries through mounts rather than implicit host visibility.

## Design Goals

- **Single runtime namespace per agent session**.
- **Project isolation by default** (filesystem/process/tooling context).
- **Deterministic environment capture** (base image + overlay + snapshot).
- **Host filesystem access only through explicit project mounts**.
- **No user-facing internal mount paths**.

## Non-Goals

- Replacing Linux process isolation primitives in this RFC.
- Defining a full package ecosystem policy beyond "Debian-compatible apt support in project rootfs".
- Solving multi-tenant policy model in one pass.

## Proposed Model

## 1. Project RootFS

Each project has:

- `base image` (versioned, immutable; default Debian minimal)
- `writable overlay` (project mutable state)
- optional `ephemeral session layer` (per-run transient writes)

This produces an effective rootfs for the project runtime.

## 2. Unified Agent Namespace

Terminal and `file_read/file_write/file_list` operate in the same namespace root (`/` from the agent perspective).

Canonical mounts inside the namespace:

- `/agents` - agent-local control/services
- `/nodes` - node/resource services
- `/global` - global docs/templates/runtime topics
- `/workspace` - project workspace convenience mount (optional alias)

`/nodes/local/fs` remains the canonical bridge to host-mounted paths.

## 3. Host Access as Mount Capability

Host paths are never assumed globally visible. They are attached explicitly:

- host `/safe/...` mounted to project namespace path(s)
- project mounts and binds remain control-plane governed
- agents reason in namespace paths, not raw host paths

## 4. Internal Path Hygiene

Paths such as `/underworld/...` are internal-only and must not appear in:

- agent prompts/instructions
- GUI operator messages
- error guidance intended for operators

## 5. Snapshot and Reproducibility

Project state can be captured as:

- `base image ref`
- `overlay snapshot id`
- optional mount manifest fingerprint

This allows deterministic rollback, migration, and reproducible agent runs.

## Path Semantics Contract

For operators:

- Host path: `/safe/...`
- Agent path: `/nodes/local/fs/safe/...`

For agents:

- Use only namespace paths (`/agents`, `/nodes`, `/global`, `/workspace`).
- Do not use internal mountpoint paths.

For runtime:

- Internal mountpoint may exist, but must be hidden from agent-facing contracts.

## Security Model Implications

- Capability is conveyed by namespace attachment (mount/bind), not by broad host visibility.
- Project rootfs boundary provides strong default separation between projects.
- Host write authority can be narrowed to mounted subtrees and explicit policy actions.

## Migration Plan

## Phase 0: Contract Cleanup (short-term)

- Remove `/underworld` references from prompts/docs/operator messages.
- Normalize mount guidance to `/nodes/local/fs/...`.
- Add tests that reject internal path leakage in user-facing text.

## Phase 1: Namespace Consistency

- Ensure terminal CWD/root semantics align with file tool namespace view.
- Add parity tests (`pwd`, `file_list`, `ls`) for same root interpretation.

## Phase 2: Project RootFS Runtime

- Introduce project rootfs lifecycle (base image + overlay).
- Run agent runtime inside project rootfs namespace.
- Keep Acheron mounts stable at canonical top-level paths.

## Phase 3: Snapshot/Restore

- Add overlay snapshot export/import.
- Attach run metadata (`base`, `overlay`, `mount digest`) to run/session records.

## Phase 4: Policy Hardening

- Require explicit mount grants for host path exposure.
- Add per-project defaults that start from zero host mounts.

## Acceptance Criteria

1. `shell_exec("pwd")` returns canonical namespace root (not internal mountpoint).
2. `file_list(".")` and terminal `ls` reflect the same root namespace.
3. Agent-visible messages never contain `/underworld`.
4. Mount operation examples and prompts use `/nodes/local/fs/...` (or relative mount-control forms).
5. Project snapshot can recreate filesystem state for a subsequent run.

## Alternatives Considered

1. **Keep current model and improve prompts only**
   - Rejected: does not eliminate structural mismatch.

2. **Expose host root directly inside sandbox**
   - Rejected: weak isolation and policy ambiguity.

3. **Drop terminal support in favor of file tools**
   - Rejected: terminal workflows are essential for software tasks.

## Inferno/Plan9 Alignment

This direction intentionally aligns with proven Inferno/Plan9 ideas:

- per-context namespace composition
- file protocol as universal service surface
- capability via mounts/binds

Modern additions are:

- container/image distribution
- overlay snapshots
- cloud provider/runtime integrations

## Open Questions

1. Rootfs image lifecycle ownership: per-project pinned image vs global cache policy.
2. Apt/package policy: unrestricted vs allowlisted repositories.
3. Snapshot portability format and storage backend.
4. Performance baseline for cold-start rootfs + mount assembly.

## Implementation Pointers

- Runtime/sandbox assembly: `src/sandbox_runtime.zig`
- Agent/worldfs projection: `src/fsrpc_session.zig`
- Control-plane mounts/projects: `src/fs_control_plane.zig`
- Gateway/session attach flow: `src/server_piai.zig`
