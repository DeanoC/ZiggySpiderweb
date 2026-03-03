# Implementation Plan: Hard Cut to Unified Project RootFS Namespace

Status: Proposed  
Owner: Spiderweb runtime  
Updated: 2026-03-03

## Decision

Spiderweb will do a hard cut to the unified Project RootFS + namespace model.

- No backward-compat runtime path.
- No legacy protocol fallback.
- No dual path semantics between terminal and `file_*` tools.

Any pre-cut client/config/runtime that does not satisfy the new contract must fail fast with explicit error messages.

## Scope

In scope:

- Unified agent filesystem semantics (`/` is one canonical namespace view).
- Project rootfs lifecycle (base image + overlay + snapshot).
- Inferno-style `mount` vs `bind` semantics and authorization split.
- System-project Mother authority for project provisioning/mount operations.
- Session attach/protocol hard cut to required payload fields.

Out of scope:

- Multi-tenant policy redesign beyond system-vs-project authority.
- Cross-version compatibility layer.

## Hard-Cut Rules (Non-Negotiable)

1. Remove all agent/operator-visible `/underworld` paths.
2. Remove legacy attach fallback behavior (for example, missing `project_id` fallback binding).
3. Remove "best effort" downgrade paths for legacy API variants.
4. Remove configuration modes that bypass Acheron namespace contracts.
5. Remove behavior where project creation moves Mother out of system context.

## Workstreams

## WS1: Namespace Unification (Terminal + File Tools)

Goal: `shell_exec`, `file_read`, `file_write`, and `file_list` all operate on one namespace contract.

Primary files:

- `src/sandbox_runtime.zig`
- `src/fsrpc_session.zig`

Tasks:

- Make agent-visible `/` map to the canonical namespace root.
- Ensure `pwd`, `ls`, and `file_list(".")` observe the same root and entries.
- Hide internal mountpoint plumbing from all user-facing responses/errors.
- Add invariants that reject internal path leakage in chat/error output.

Exit criteria:

- Path parity integration tests pass for terminal + file tools.
- No `/underworld` in prompts, runtime messages, or operator guidance.

## WS2: Project RootFS Runtime

Goal: each project executes inside a minimal Debian-based rootfs with overlay layers.

Primary files:

- `src/sandbox_runtime.zig`
- `src/runtime_server.zig`

Tasks:

- Implement project rootfs assembly (`base image` + `writable overlay` + optional ephemeral layer).
- Mount canonical Acheron namespaces (`/agents`, `/nodes`, `/global`, optional `/workspace`) into that rootfs.
- Persist snapshot metadata (`base ref`, `overlay id`, mount manifest digest).

Exit criteria:

- New project run always boots in project rootfs.
- Snapshot restore reproduces filesystem state deterministically.

## WS3: Mount/Bind Contract and Authorization

Goal: strict split between capability import (`mount`) and namespace composition (`bind`).

Primary files:

- `src/fs_control_plane.zig`
- `src/server_piai.zig`

Tasks:

- Enforce separate authorization checks for `mount` and `bind`.
- Guarantee `bind` cannot increase authority beyond currently mounted paths.
- Keep host-path exposure explicit and policy-driven through mount grants.
- Ensure system Mother can provision mounts for target projects while staying in system project context.

Exit criteria:

- `mount` and `bind` are independently enforced in control endpoints.
- Mother can create folder + mount for `proj-*` without project-context switch.
- Non-system agents cannot perform system-level project assignment operations.

## WS4: Setup/Provisioning Flow as Project State

Goal: setup completion is state-driven, durable, and agent-owned (not connection-owned).

Primary files:

- `src/first_run.zig`
- `src/agent_runtime.zig`
- `src/server_piai.zig`

Tasks:

- Store setup-required/setup-complete state in project-owned persistent files/state records.
- Remove interview loop bugs where role confirmation repeats after valid input.
- Ensure runtime restart resumes pending setup transaction safely.
- Keep setup orchestration in Mother instructions + project state transitions, not special one-off UI pathing.

Exit criteria:

- Setup interview completes once and transitions to active state.
- Project + first agent are discoverable via control-plane listing after completion.

## WS5: Protocol and Session Attach Hard Cut

Goal: session attach uses only the new required payload contract.

Primary files:

- `src/server_piai.zig`
- `src/connection_dispatcher.zig`
- `src/websocket_transport.zig`

Tasks:

- Require `project_id` (and any other mandatory fields) at attach time.
- Remove fallback branch that binds to implicit/default session on invalid payload.
- Return deterministic machine-readable errors for invalid attach payloads.

Exit criteria:

- Legacy/partial payloads fail with explicit `invalid_payload` errors.
- No implicit fallback binding path remains.

## WS6: Config Hard Cut

Goal: runtime cannot start in unsupported/ambiguous modes.

Primary files:

- `src/config.zig`
- `src/main.zig`

Tasks:

- Reject startup when Acheron/sandbox contracts are disabled or invalid.
- Reject ambiguous defaults that hide missing required provider/runtime settings.
- Emit startup diagnostics that explicitly name missing required fields.

Exit criteria:

- "No Acheron"/invalid sandbox mode is not runnable.
- Misconfiguration fails at startup, not during live agent action.

## Test Plan (Automation First)

## Contract Tests

- Path parity: `pwd` == namespace root; `ls` and `file_list` equivalence.
- Leak guard: no `/underworld` in user-visible messages/prompts/errors.
- Attach validation: missing required fields returns deterministic failure; no fallback binding.

## Integration/E2E

- Fresh reset/install + first setup interview + project/agent provisioning.
- Runtime restart during setup interview; resume and complete without data loss.
- Mother system task: create host folder and mount for `proj-1` while remaining in `system`.
- Post-setup discoverability: project and agent lists show expected entries.

## Regression

- Windows GUI connect/send flow remains stable under reconnect.
- Session attach errors are surfaced clearly in GUI logs (no silent fallback behavior).

## Cutover Sequence

1. Land all workstreams on one release branch with failing legacy tests removed.
2. Add/green all hard-cut contract tests.
3. Run reset/install + end-to-end setup/mount test suite on Linux host + Windows GUI client.
4. Ship one incompatible release (single cut line).
5. Reject all legacy clients/configs at runtime attach/startup with clear errors.

## Rollback Strategy

Rollback is binary/version rollback only.

- Restore previous runtime binary/config bundle.
- Restore pre-cut snapshots/backups.

No in-place backward-compat shims will be introduced in the cut release.

## Definition of Done

1. Hard-cut rules are enforced in runtime and validated by automated tests.
2. Mother can perform system-level provisioning and mount orchestration for projects without context drift.
3. Agents operate with one filesystem mental model for terminal and `file_*`.
4. Legacy attach/config paths are removed (not deprecated).
5. Project setup is durable state flow, not connection-bound flow.
