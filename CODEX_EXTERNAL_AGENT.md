# Codex External Agent Guide

This is the operator guide for the external Codex end-to-end harness. Spiderweb owns the hosted workspace, namespace, control plane, and remote-node topology. Codex stays outside Spiderweb and works through the mounted filesystem contract.

The harness entrypoint for this flow is `test-env/test-external-codex-workspace.sh`.

The current milestone is agent-driven workspace bootstrap, not Codex-specific harness shaping. The harness creates a generic shared workspace baseline. The mounted external agent must then discover the environment and bootstrap itself from inside the namespace.

## Current Recommendation

Use a Linux host for the documented Codex E2E path.

- install the host tools first with `./install.sh`
- keep Spiderweb’s runtime root separate from the Codex project tree
- use one clean standalone `spiderweb-fs-node` for `/nodes/local/fs` and one standalone node for `/shared_data`
- mount the workspace with `spiderweb-fs-mount --namespace-url ...`
- launch plain Codex from `/nodes/local/fs`, or deliberately fall back to a prepared handoff

Windows `spiderweb-fs-mount` remains useful for separate client validation, but the new external Codex harness is Linux-first.

## Installer-First Linux Flow

### 1. Clone with submodules

```bash
git clone --recurse-submodules https://github.com/DeanoC/Spiderweb.git
cd Spiderweb
```

If you already cloned without submodules:

```bash
git submodule update --init --recursive
```

### 2. Install the host toolchain

Use the installer-first path instead of treating the harness as a source-build-only workflow:

```bash
./install.sh
spiderweb-config auth status --reveal
```

That installs the Linux host surface used by the harness:

- `spiderweb`
- `spiderweb-config`
- `spiderweb-control`
- `spiderweb-fs-mount`
- `spiderweb-fs-node`

If the namespace mount runs on a different Linux machine, install the standalone mount client there:

```bash
./install-fs-mount.sh
```

### 3. Start Spiderweb

```bash
spiderweb
```

Create a workspace once the host is up:

```bash
spiderweb-control \
  --auth-token <admin-token> \
  workspace_create \
  '{"name":"Codex Demo","vision":"External Codex workspace"}'
```

## Standalone Remote Node

The new harness uses a standalone `spiderweb-fs-node` remote node instead of assuming everything lives on the Spiderweb host filesystem.

Typical invite-flow start:

```bash
spiderweb-fs-node \
  --export "work=/srv/codex-fixture:rw" \
  --control-url "ws://127.0.0.1:18790/" \
  --control-auth-token "<admin-token>" \
  --pair-mode invite \
  --invite-token "<invite-token>" \
  --node-name "codex-e2e-node"
```

Notes:

- `SPIDERWEB_AUTH_TOKEN` can supply control auth when `--control-url` is used.
- The node can run on a different machine than the Spiderweb host.
- The namespace should expose that node through project metadata, not through hard-coded path assumptions.

## Namespace Mount For Codex

Use namespace mode for the harness. That is the path which exposes `/meta`, `/projects`, `/services`, `/nodes`, and `/agents` together:

```bash
spiderweb-fs-mount \
  --namespace-url ws://127.0.0.1:18790/ \
  --workspace-id <workspace-id> \
  --auth-token <admin-or-user-token> \
  --agent-id codex \
  --session-key main \
  mount /mnt/spiderweb-codex
```

Codex itself does not need a Spiderweb-specific runtime binary. It only needs filesystem access to the mounted namespace.

## External Codex E2E Harness

The new end-to-end entrypoint is:

```bash
bash test-env/test-external-codex-workspace.sh
```

Or through `make`:

```bash
cd test-env
make test-external-codex-workspace
make test-external-codex-repeatability
make test-external-codex-cli-matrix
make package-external-codex-repro
```

What this harness is expected to cover:

- installer-first Linux host flow
- generic `dev`-template workspace baseline plus standalone workspace/remote node lifecycle
- namespace mount with `spiderweb-fs-mount --namespace-url ...`
- pinned plain Codex bootstrap, auth, launch, or manual handoff preparation
- agent-driven in-workspace bootstrap through generic `/services/*`
- validation and report artifact capture

When you need to compare Codex CLI versions or launch modes, use:

```bash
bash test-env/test-external-codex-cli-matrix.sh
```

The matrix runner reuses the main external-Codex harness and writes:

- `matrix_summary.json`
- `matrix_summary.md`
- one subdirectory per case, each with the usual handoff/report artifacts

When you need to prove the new agent-bootstrap milestone is stable across repeated live runs, use:

```bash
bash test-env/test-external-codex-repeatability.sh
```

That repeatability runner writes:

- `repeatability_summary.json`
- `repeatability_summary.md`
- one subdirectory per run, each with the usual live harness artifacts

When you need a ready-to-file upstream repro bundle, use:

```bash
bash test-env/package-external-codex-repro.sh
```

That packager collects selected matrix cases and writes:

- `README.md`
- `BUG_REPORT.md`
- `repro_manifest.json`
- `source_summaries/`
- `cases/`
- an optional `.tar.gz` archive

## Codex Launch Modes

The harness should expose these launch controls:

- `CODEX_MODE=auto`: try to launch a live Codex session. If no usable launcher is available, or the live launch cannot proceed, switch to the dedicated fallback handoff behavior and still preserve the run artifacts.
- `CODEX_MODE=live`: require a live Codex launch. Launch failure is a harness failure; do not auto-downgrade.
- `CODEX_MODE=manual`: skip live Codex launch and go straight to the dedicated handoff package.
- `CODEX_BIN`: override the detected Codex binary.
- `CODEX_CLI_VERSION`: pinned plain Codex CLI version to verify or install. Default: `0.111.0`.
- `CODEX_AUTH_MODE=auto|api_key|existing_login`: choose isolated API-key auth or an existing login. `auto` prefers API-key auth when `OPENAI_API_KEY` is present.
- `CODEX_API_KEY_ENV`: environment variable name for API-key auth. Default: `OPENAI_API_KEY`.
- `CODEX_LAUNCH_CMD`: override the detected Codex launcher when the default command is not correct for the machine running the harness.
- `CODEX_TIMEOUT_SECONDS`: bound the live Codex phase so the harness cannot hang forever on an upstream CLI regression. Default: `900`.
- `CODEX_IDLE_TIMEOUT_SECONDS`: optional idle cutoff for the live Codex phase. Default: `0` (disabled), because `codex exec --json` can spend long periods silently reasoning before the next visible tool or file event.
- `CODEX_JSON_EVENTS=1`: inject `--json` into common `codex exec` launch templates and preserve the raw event stream in `logs/codex.stdout.log`.
- `CODEX_USE_PTY=1`: wrap the live launch in `script(1)` so Codex runs in a terminal-like session and preserves `logs/codex.pty.log`.
- `CODEX_DISABLE_COLLABORATION_MODES=1`: inject `--disable collaboration_modes` into common `codex exec` templates unless you opt out.
- `CODEX_DISABLE_APPS=1`: inject `--disable apps` by default because the current live Spiderweb path is more reliable without the apps surface in non-interactive `exec`.
- `CODEX_DISABLE_SHELL_SNAPSHOT=1`: inject `--disable shell_snapshot` by default because the current live Spiderweb path is more reliable without shell snapshotting in non-interactive `exec`.
- `CODEX_ALLOW_HOST_CODEX_HOME=1`: temporarily allow writes under host `~/.codex` for reliability while still reporting them as a `codex_home` machine-independence gap.

Practical rule:

- use `auto` for operator convenience
- use `live` for strict E2E validation
- use `manual` when you want the environment prepared but will attach Codex yourself

For current Linux live runs, prefer the default launcher and isolated API-key auth. Existing-login auth is also acceptable for now when you need to reuse an already prepared host `~/.codex` state:

```bash
CODEX_MODE=live \
CODEX_AUTH_MODE=api_key \
OPENAI_API_KEY=... \
bash test-env/test-external-codex-workspace.sh
```

If you do need to override the launcher, use a template that keeps Codex rooted in `/nodes/local/fs` and adds only the metadata/data directories it needs:

```bash
CODEX_MODE=live \
CODEX_AUTH_MODE=api_key \
OPENAI_API_KEY=... \
CODEX_LAUNCH_CMD='cat {prompt_file} | {codex_bin} exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox --ephemeral --add-dir {namespace_meta_dir} --add-dir {project_meta_dir} --add-dir {shared_data_dir} --add-dir {artifact_dir} -C {workspace_root} -o {artifact_dir}/codex_last_message.txt -' \
bash test-env/test-external-codex-workspace.sh
```

## Output Artifacts

Each run should preserve the same high-signal artifacts:

- `codex_exec_summary.json`
- `codex_usage_report.json`
- `codex_usage_report.md`
- `bootstrap_provenance.json`
- `game_validation.json`
- `codex_handoff/`

`codex_handoff/` is the dedicated resume package for manual continuation. It should contain the workspace and mount context Codex needs when the live launch is skipped or unavailable.

`codex_exec_summary.json` is the quick diagnosis artifact for live stalls. It records:

- whether Codex JSON events were detected
- the last observed event type
- the last completed item type
- the last agent message, if one was emitted
- an inferred stall stage such as `after_tool_result` or `after_agent_message`

The usage report distinguishes:

- `reliability_ok`: no disallowed writes outside the mounted workspace plus harness-owned runtime roots
- `workspace_bootstrap_ok`: the mounted agent read the bootstrap metadata and completed the required in-workspace bootstrap actions
- `machine_independence_ok`: no host-runtime gaps observed
- `project_bound_services`: services actually bound under `/services/*`
- `namespace_visible_services`: services visible somewhere in the namespace, even if not project-bound under `/services/*`
- `external_prereqs_observed`: declared external prerequisites, such as the operator-installed Codex runtime
- `candidate_venom_gaps`: inferred gaps such as `codex_home`, `terminal_runtime`, `git_runtime`, and `search_code_bridge`

## Dedicated Fallback Behavior

The fallback path is deliberate. It should not silently replace the live run with an opaque no-op.

When fallback is used:

- the namespace mount and remote-node setup are still treated as the source of truth
- the harness writes the dedicated `codex_handoff/` package for a later/manual Codex run
- usage and validation artifacts are still emitted so the operator can inspect what happened
- the reason for fallback should be visible in the handoff/report output
- the handoff README should include the last observed Codex event summary when live JSON events were captured

This is the main difference between `CODEX_MODE=auto` and `CODEX_MODE=live`.

## What A Fresh Codex Should Read First

Once Codex is dropped into the mounted workspace, the minimum discovery order should be:

1. `/meta/protocol.json`
2. `/projects/<project_id>/meta/mounted_services.json`
3. `/projects/<project_id>/meta/workspace_status.json`
4. `/projects/<project_id>/meta/venom_packages.json`
5. `/projects/<project_id>/meta/agent_bootstrap.json`
6. `/services/<service>/README.md`
7. `/services/<service>/OPS.json`
8. `/services/<service>/SCHEMA.json`
9. `/services/<service>/CAPS.json`
10. `/agents/<agent_id>/`

## Agent-Driven Bootstrap Contract

The attached agent, not the harness, should perform these steps after mount:

1. Read `agent_bootstrap.json`.
2. Ensure its durable home through `/services/home/control/ensure.json`.
3. Verify the required generic `/services/*` entries.
4. If a required service is missing, repair it through `/services/mounts/control/bind.json` using the fallback namespace roots described in `agent_bootstrap.json`.
5. Optionally register worker-private venoms through `/services/workers/control/register.json` when the task needs them.
6. Perform the workspace task and validation.

Persistence model for this milestone:

- shared workspace/project binds are persistent
- `/home/<agent>` is durable per agent
- worker loopback state is ephemeral and should be recreated after detach if needed

Plain Codex is the current test agent, but this contract is intended to work for other external agents too. Because launch-time hooks are intentionally out of scope, plain Codex may still observe `codex_home`, `terminal_runtime`, or `git_runtime` gaps even after `workspace_bootstrap_ok` passes. Those are follow-on machine-independence items, not reasons to let the harness bootstrap on the agent’s behalf.

What this gives Codex:

- protocol and namespace shape
- which services are actually mounted into the current project
- current workspace health and path topology
- the live control-file contract for each service
- the agent identity files Spiderweb seeded for the current `agent_id`

For the current external Codex harness, the important writable/data paths inside the namespace are:

- local writable project tree: `/nodes/local/fs`
- remote shared seed data: `/shared_data`

In the current harness, Spiderweb’s own runtime root is intentionally not the Codex project tree. That separation keeps `agents/` and `templates/` out of Codex’s cwd and makes the workspace topology match what a fresh user should see.

## Minimal Codex Prompt

Use something close to this when placing a fresh Codex into a Spiderweb mount:

```text
You are operating inside a Spiderweb-mounted workspace.
Treat the filesystem as the contract.
Treat /nodes/local/fs as the writable project tree and /shared_data as the required remote input mount.
Inspect /meta/protocol.json, /projects/<project_id>/meta/mounted_services.json, and /projects/<project_id>/meta/workspace_status.json first.
Read only the fields you need; do not dump whole metadata files back into the terminal.
After the discovery reads, create the deliverable files immediately and iterate only if validation fails.
```

## Practical Operator Rule

Right now, the safest external Codex story is:

- host Spiderweb on Linux
- use installer-first binaries for the host flow
- attach remote content with standalone `spiderweb-fs-node`
- mount the namespace with `spiderweb-fs-mount`
- treat project metadata discovery as stable
- use the dedicated fallback handoff when live Codex launch is unavailable
