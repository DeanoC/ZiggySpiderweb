# External Codex Machine-Independence Plan

This plan starts from the now-stable external-agent baseline:

- the installer-first Linux harness is working
- the external Codex agent self-bootstraps from inside the mounted workspace
- the release-backed repeatability batch passed 2 out of 2 fresh runs
- the remaining gaps are machine-independence gaps, not functional E2E gaps

The stable repeatability evidence is in:

- `/safe/Safe/wizball-codex/repeatability-noprobe-v0.3.0/repeatability_summary.json`
- `/safe/Safe/wizball-codex/repeatability-noprobe-v0.3.0/repeatability_summary.md`

## Current Stable Baseline

What is already true:

- `reliability_ok=true` on repeated fresh runs
- `workspace_bootstrap_ok=true` on repeated fresh runs
- the external agent can discover the namespace, write `home.ensure`, generate the game, run the walkthrough, and pass the validator
- `search_code_bridge` is no longer observed in the stable repeatability batch

What is still not true:

- `machine_independence_ok=false`

The repeated remaining gaps are:

- `codex_home`
- `terminal_runtime`
- `git_runtime`

These were observed on both runs in the stable repeatability batch.

## Goal

Move from:

- stable external-agent E2E

to:

- stable external-agent E2E with `machine_independence_ok=true`

without changing the core workspace model:

- Spiderweb owns the long-lived workspace
- external agents join through the mounted namespace
- the workspace can outlive the agent
- the harness must not add Codex-only project shaping after mount

## Scope Boundaries

In scope:

- generic Spiderweb-side surfaces that any external agent could use
- launch/runtime isolation that can be justified as agent attachment support
- clearer acceptance/reporting for machine-independence

Out of scope for this phase:

- changing the workspace goal or the text-adventure task
- reintroducing Codex-specific workspace binds
- treating one-off harness hacks as the final product model

## Phase 1: Codex Home Independence

Problem:

- Codex still writes to host `~/.codex`
- this keeps `codex_home` red even though `/services/home` is present

Required end state:

- Codex state lives under mounted durable agent home
- no host `~/.codex` reads or writes are needed for the strict path

Planned work:

1. Keep `/services/home/control/ensure.json` as the canonical bootstrap action.
2. Define the mounted home contract clearly:
   - durable per-agent home
   - mounted path exposed predictably inside the namespace
   - stable XDG subpaths for config, cache, state, and data
3. Add a strict launch mode that points:
   - `HOME`
   - `XDG_CONFIG_HOME`
   - `XDG_CACHE_HOME`
   - `XDG_DATA_HOME`
   - `XDG_STATE_HOME`
   - `TMPDIR`
   into that mounted home before Codex starts.
4. Keep `existing_login` as a debug mode only.
5. Make strict acceptance require no host-home usage.

Key constraint:

- this is not a workspace-bootstrap problem anymore; it is a launch/runtime binding problem

Acceptance:

- `codex_home` disappears from the usage report
- repeated strict runs stay green for reliability and bootstrap

## Phase 2: Terminal Runtime Independence

Problem:

- Codex still uses host shell/coreutils
- `terminal_runtime` remains red even though `/services/terminal` is project-bound

Required end state:

- shell/tool execution needed by the external agent is fulfilled through a generic terminal bridge backed by Spiderweb services

Planned work:

1. Define a generic external-agent terminal bridge contract:
   - external agent issues shell-style commands
   - bridge forwards execution through `/services/terminal`
   - stdout, stderr, and exit status are surfaced locally
2. Prefer generic attachment/runtime support over Codex-only workspace shaping.
3. Prototype a launch profile that sets `SHELL` to the bridge entrypoint before the agent starts.
4. Update reporting so host shell usage is only tolerated in debug mode, not the strict path.

Acceptance:

- `terminal_runtime` disappears from the strict usage report
- the external agent still completes the same repeatability batch

## Phase 3: Git Runtime Independence

Problem:

- Codex still invokes host git
- `git_runtime` remains red even though `/services/git` is project-bound

Required end state:

- git-like repo introspection used by the external agent routes through a generic git bridge

Planned work:

1. Define the minimum generic git bridge surface needed for external agents:
   - repo detection
   - simple status/introspection
   - file-list and diff-style queries used during attach/startup
2. Provide a strict launch path where git resolution prefers the bridge rather than host git.
3. Fail loudly in strict mode if the agent needs unsupported git behavior.
4. Keep host git available only in debug mode.

Acceptance:

- `git_runtime` disappears from the strict usage report
- strict runs still pass the full text-adventure E2E

## Phase 4: Strict Machine-Independence Mode

Once the three gaps above are closed, add an explicit strict mode.

Strict mode requirements:

- no host `~/.codex`
- no host terminal/coreutils dependency
- no host git dependency
- no host checkout reads
- same 2-run repeatability batch remains green

Planned work:

1. Add a top-level strict acceptance flag in reporting.
2. Split debug vs strict launch modes clearly in docs and harness output.
3. Run the full repeatability batch in strict mode.
4. Keep the current existing-login path as an operator/debug path only.

Acceptance:

- `reliability_ok=true`
- `workspace_bootstrap_ok=true`
- `machine_independence_ok=true`
- repeated strict runs succeed

## Reporting Follow-Ups

The current reporting is good enough to drive this phase, but it should be tightened in parallel:

1. keep the per-run timeline milestones
2. keep the gap-frequency rollup
3. add a strict-mode summary line once strict mode exists
4. continue to distinguish:
   - workspace/bootstrap success
   - machine-independence failure

## Immediate Next Tasks

Recommended order:

1. design the mounted-home strict launch path
2. prototype the terminal bridge contract
3. prototype the git bridge contract
4. add strict-mode reporting and rerun the repeatability batch

This keeps work aligned with the now-proven stable external-agent baseline instead of reopening the already-solved functional E2E path.
