# Spiderweb Test Environment

Docker-based testing environment for Spiderweb. This creates a clean, disposable Debian container for testing the install script and Spiderweb functionality without affecting your main server.

## Quick Start

```bash
# Build and start the test environment
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build

# Enter the running container
docker exec -it spiderweb-test bash

# Inside the container, run the install script
./install.sh
```

## Manual Testing

```bash
# Build the image
docker build -t spiderweb-test .

# Run interactively
docker run -it --rm --name spiderweb-test spiderweb-test

# Run with API key from environment (for automated testing)
docker run -it --rm \
  -e SPIDERWEB_PROVIDER=openai \
  -e SPIDERWEB_MODEL=gpt-4o-mini \
  -e SPIDERWEB_API_KEY=sk-xxx \
  spiderweb-test

# Run with port forwarding (to test from host)
docker run -it --rm \
  -p 18790:18790 \
  --name spiderweb-test \
  spiderweb-test
```

## Testing the Install Script

```bash
# Test the full interactive install
curl -fsSL https://raw.githubusercontent.com/DeanoC/Spiderweb/main/install.sh | bash

# Or drive a non-interactive install explicitly
SPIDERWEB_NON_INTERACTIVE=1 \
SPIDERWEB_INSTALL_ZSS=0 \
SPIDERWEB_INSTALL_SYSTEMD=0 \
SPIDERWEB_START_AFTER_INSTALL=0 \
bash ./install.sh

# Release-binary path
SPIDERWEB_NON_INTERACTIVE=1 \
SPIDERWEB_INSTALL_SOURCE=release \
SPIDERWEB_RELEASE_ARCHIVE_URL=https://github.com/DeanoC/Spiderweb/releases/download/v0.3.0/spiderweb-linux-x86_64.tar.gz \
SPIDERWEB_RELEASE_ARCHIVE_SHA256=<sha256> \
SPIDERWEB_INSTALL_ZSS=0 \
SPIDERWEB_INSTALL_SYSTEMD=0 \
SPIDERWEB_START_AFTER_INSTALL=0 \
bash ./install.sh
```

## External Codex Workspace E2E Harness

This harness documents and exercises the Linux-first external Codex operator path:

- installer-first host flow (`./install.sh` on the Spiderweb host)
- generic `dev`-template workspace baseline that can outlive any one agent session
- isolated Spiderweb runtime root plus a clean standalone local workspace node
- standalone `spiderweb-fs-node` as the remote filesystem node under test
- namespace mount via `spiderweb-fs-mount --namespace-url ...`
- plain Codex launch in live or manual-handoff mode
- agent-driven in-workspace bootstrap, validation, and report artifact capture

Mounted namespace paths used by the harness:

- local writable project tree: `/nodes/local/fs`
- remote shared seed data: `/shared_data`
- project metadata: `/projects/<project_id>/meta/*`
- namespace metadata: `/meta/*`
- generic project services: `/services/*`

Run it directly from the repo root:

```bash
bash test-env/test-external-codex-workspace.sh
```

Or through `make`:

```bash
cd test-env && make test-external-codex-workspace
```

Repeatability runner:

```bash
cd test-env && make test-external-codex-repeatability
```

Compatibility matrix runner:

```bash
cd test-env && make test-external-codex-cli-matrix
```

Repro bundle packager:

```bash
cd test-env && make package-external-codex-repro
```

Codex launch controls:

- `CODEX_MODE=auto`: try a live Codex launch, then fall back to the dedicated handoff package if the launcher is unavailable or the live step cannot proceed
- `CODEX_MODE=live`: require a real Codex launch; launch failure fails the harness
- `CODEX_MODE=manual`: skip live launch and prepare the manual handoff package only
- `CODEX_BIN`: override the detected Codex binary
- `CODEX_CLI_VERSION`: pinned plain Codex CLI version the harness expects. Default: `0.111.0`
- `CODEX_AUTH_MODE=auto|api_key|existing_login`: choose isolated API-key auth or an existing login. `auto` prefers API-key auth when `OPENAI_API_KEY` is set
- `CODEX_API_KEY_ENV`: environment variable name to read for `api_key` mode. Default: `OPENAI_API_KEY`
- `CODEX_LAUNCH_CMD`: override the detected launcher when the default `codex exec` template is not correct for the machine
- `CODEX_TIMEOUT_SECONDS`: maximum seconds to allow the live Codex phase before the harness fails with a diagnostic handoff/report. Default: `900`
- `CODEX_IDLE_TIMEOUT_SECONDS`: optional idle cutoff for the live Codex phase. Default: `0` (disabled), because `codex exec --json` can spend long periods silently reasoning before the next visible tool or file event.
- `CODEX_JSON_EVENTS=1`: inject `--json` into common `codex exec` launch templates and preserve the raw Codex event stream in `logs/codex.stdout.log`
- `CODEX_USE_PTY=1`: wrap the live Codex launch in `script(1)` so the run behaves like a real terminal session and preserves `logs/codex.pty.log`
- `CODEX_DISABLE_COLLABORATION_MODES=1`: inject `--disable collaboration_modes` into common `codex exec` templates unless disabled
- `CODEX_DISABLE_APPS=1`: inject `--disable apps` by default because the current live Spiderweb path is more reliable without the apps surface in non-interactive `exec`
- `CODEX_DISABLE_SHELL_SNAPSHOT=1`: inject `--disable shell_snapshot` by default because the current live Spiderweb path is more reliable without shell snapshotting in non-interactive `exec`
- `CODEX_ALLOW_HOST_CODEX_HOME=1`: temporarily allow writes under host `~/.codex` for reliability while still reporting them as a `codex_home` machine-independence gap
- `SPIDERWEB_INSTALL_SOURCE=auto|source|release`: choose whether the harness compiles Spiderweb locally or installs from a prebuilt archive. Default: `auto`, which currently resolves to the published `v0.3.0` release asset in the external Codex harness
- `SPIDERWEB_RELEASE_ARCHIVE_URL`: release asset URL to use when `SPIDERWEB_INSTALL_SOURCE=release`. Default in the external Codex harness: `https://github.com/DeanoC/Spiderweb/releases/download/v0.3.0/spiderweb-linux-x86_64.tar.gz`
- `SPIDERWEB_RELEASE_ARCHIVE_SHA256`: optional checksum for the release archive
- `SPIDERWEB_RELEASE_VERSION`: label recorded in installer output for the chosen release build. Default in the external Codex harness: `v0.3.0`

Current note:

- The external Codex harness now defaults to the published `v0.3.0` release asset to avoid rebuilding Spiderweb on every run. Set `SPIDERWEB_INSTALL_SOURCE=source` when you explicitly want a local source build instead.

Expected output artifacts:

- `codex_exec_summary.json`
- `codex_usage_report.json`
- `codex_usage_report.md`
- `bootstrap_provenance.json`
- `game_validation.json`
- `codex_handoff/`

Repeatability artifacts:

- `repeatability_summary.json`
- `repeatability_summary.md`
- one subdirectory per run, each containing the normal live harness artifacts

Repeatability interruption behavior:

- if you intentionally stop the repeatability runner mid-batch, it now writes partial `repeatability_summary.json` and `repeatability_summary.md` files from whatever artifacts already exist
- interrupted runs are marked with `interrupted=true` plus an `interrupt_reason`, so you can still see whether the run had already reached bootstrap, validation, or report generation

Matrix runner artifacts:

- `matrix_summary.json`
- `matrix_summary.md`
- one subdirectory per case, each containing the normal live harness artifacts

Repro bundle artifacts:

- `README.md`
- `BUG_REPORT.md`
- `repro_manifest.json`
- `source_summaries/`
- `cases/`
- optional `*.tar.gz` bundle

Usage report result semantics:

- `reliability_ok`: true only when the run stayed inside the mounted workspace plus harness-owned runtime roots, plus any explicit temporary host-write allowlists
- `workspace_bootstrap_ok`: true only when the attached agent read the bootstrap metadata and performed the required in-workspace bootstrap actions
- `machine_independence_ok`: true only when no host-runtime gaps were observed
- `project_bound_services`: services bound under `/services/*` for the mounted workspace
- `namespace_visible_services`: services visible somewhere in the namespace, even if not project-bound under `/services/*`
- `external_prereqs_observed`: declared external prerequisites observed during the run, such as the operator-installed Codex runtime
- `candidate_venom_gaps`: inferred local-runtime gaps such as `codex_home`, `terminal_runtime`, `git_runtime`, and `search_code_bridge`

Fallback behavior:

- `auto` does not silently skip the Codex step
- the harness should still preserve the namespace-mounted workspace context
- `codex_handoff/` is the dedicated resume package for manual continuation
- `codex_exec_summary.json` captures the last observed Codex event, last completed item, and inferred stall stage from the live `--json` event stream
- validation and usage reports should still be written in fallback/manual mode

Operator notes:

- prefer the installer-first Linux path for this harness; use `./install-fs-mount.sh` only when the namespace mount happens on a separate Linux machine
- the harness is about the standalone node + namespace story, not the older routed `--workspace-url` only flow
- the clean writable project tree is `/nodes/local/fs`; Spiderweb’s own runtime root is kept separate from that workspace on purpose
- the harness creates only a generic `dev`-template workspace baseline; after attach, the external agent is responsible for reading `/projects/<project_id>/meta/agent_bootstrap.json` and bootstrapping itself from inside the workspace
- `agent_bootstrap.json` is the generic contract for discovery order, preferred `/services/*` usage, self-home provisioning, service verification/repair, and persistence semantics
- shared project binds persist across agent detach/reattach, while worker-private loopback state is expected to be ephemeral
- `CODEX_AUTH_MODE=api_key` is still the strict fresh-install path, but `existing_login` is temporarily acceptable for reliability because host `~/.codex` writes are allowlisted by default while still reported as a `codex_home` machine-independence gap
- `CODEX_LAUNCH_CMD` is optional; the harness can build a default launcher around the pinned `codex exec` flow
- the default live launcher now preserves both `logs/codex.stdout.log` and `logs/codex.pty.log`, which makes it much easier to distinguish “still progressing” from “stopped after a tool result”
- `test-env/test-external-codex-cli-matrix.sh` is the fast way to compare pinned Codex CLI versions and PTY/JSON launch modes against the same Spiderweb scenario
- `test-env/test-external-codex-repeatability.sh` is the fast way to prove the new `workspace_bootstrap_ok` milestone stays green across multiple live runs on the same machine
- `test-env/package-external-codex-repro.sh` collects the matrix outputs into a single upstream-ready repro pack with a generated bug report
- custom launch templates may use `{codex_bin}`, `{workspace_root}`, `{namespace_root}`, `{namespace_meta_dir}`, `{project_meta_dir}`, `{shared_data_dir}`, `{prompt_file}`, and `{artifact_dir}`
- the default artifact directory is now outside the repo checkout so the harness does not create false host-repo leakage by itself
- the current milestone is `workspace_bootstrap_ok`; plain Codex still cannot fully clear `codex_home`, `terminal_runtime`, and `git_runtime` under the no-launch-hook rule, so `machine_independence_ok` remains the follow-on milestone
- if you still want to override the launcher, a working template is:

```bash
CODEX_MODE=live \
CODEX_AUTH_MODE=api_key \
OPENAI_API_KEY=... \
CODEX_LAUNCH_CMD='cat {prompt_file} | {codex_bin} exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox --ephemeral --add-dir {namespace_meta_dir} --add-dir {project_meta_dir} --add-dir {shared_data_dir} --add-dir {artifact_dir} -C {workspace_root} -o {artifact_dir}/codex_last_message.txt -' \
bash test-env/test-external-codex-workspace.sh
```

## Embedded Multi-Service Integration Test

This repo also includes a local CI-style integration test for the embeddable
filesystem + health services example.

```bash
# Run directly
bash test-env/test-embed-multi-service.sh

# Or through make
cd test-env && make test-embed-multi-service
```

What it validates:
- boots `embed-multi-service-node` with a temporary export
- probes `/v2/fs` via `spiderweb-fs-mount` (`readdir` + `cat`)
- probes `/v1/health` with a raw WebSocket handshake and validates `ok: true`

Useful env vars:
- `PORT` (default `21910`)
- `BIND_ADDR` (default `127.0.0.1`)
- `SKIP_BUILD=1` to skip `zig build` if binaries are already built

## Distributed Workspace Failover Test

This test exercises the control-plane + mount integration flow end-to-end:
- starts `spiderweb`
- starts two `embed-multi-service-node` filesystem nodes
- negotiates `control.version` (`unified-v2`) then runs `control.node_invite_create`, `control.node_join`, `control.project_create`, `control.project_mount_set`, and `control.project_activate` with project mutation auth (`project_token`)
- restarts `spiderweb` and verifies control-plane state is recovered from persisted LTM snapshot
- updates mounts live (`/src` -> `/live`) and validates the mount client converges to the new path
- mounts both nodes at the same project mount path (`/src`) as a failover group
- verifies reads initially come from node A/B, kills the active node, and verifies failover
- restarts the stopped node, rejoins/remounts it, then kills the surviving node to verify second failover convergence

Additional focused scenarios:
- `test-distributed-workspace-bootstrap.sh`: validates `control.project_up` bootstrap output and workspace desired/actual/drift schema.
- `test-distributed-workspace-drift.sh`: forces a desired/actual mismatch and verifies drift + reconcile diagnostics.
- `test-distributed-workspace-matrix.sh`: runs failover/reconnect/bootstrap/drift as one matrix entrypoint.

```bash
# Run directly
bash test-env/test-distributed-workspace.sh

# Or through make
cd test-env && make test-distributed-workspace
cd test-env && make test-distributed-workspace-bootstrap
cd test-env && make test-distributed-workspace-drift
cd test-env && make test-distributed-workspace-matrix
cd test-env && make test-distributed-workspace-encrypted
cd test-env && make test-distributed-workspace-operator-token
cd test-env && make test-distributed-soak-chaos
cd test-env && make test-unified-v2-protocol
```

Useful env vars:
- `SPIDERWEB_PORT` (default `28790`)
- `NODE1_PORT` (default `28911`)
- `NODE2_PORT` (default `28912`)
- `BIND_ADDR` (default `127.0.0.1`)
- `SPIDERWEB_CONTROL_OPERATOR_TOKEN` (optional; include `operator_token` in protected mutations if enabled)
- `SPIDERWEB_CONTROL_STATE_KEY_HEX` (optional; enables encrypted control-plane snapshot storage)
- `ASSERT_OPERATOR_TOKEN_GATE=1` (optional; assert mutation deny/allow behavior before the main workflow)
- `SPIDERWEB_METRICS_PORT` (optional; enables HTTP `/livez`, `/readyz`, `/metrics` (Prometheus), `/metrics.json` (JSON))
- `SKIP_BUILD=1` to skip `zig build` if binaries are already built

## Unified v2 Protocol Validation

Validates protocol-level contract points used in release checks:
- control negotiation order (`control.version` -> `control.connect`)
- runtime Acheron negotiation order (`acheron.t_version` -> `acheron.t_attach`)
- standalone FS routing order (`acheron.t_fs_hello` must come first)
- standalone FS HELLO auth-token enforcement (`--auth-token`)
- source-level envelope/type guard in core client code paths

```bash
# Run directly
bash test-env/test-unified-v2-protocol.sh

# Or through make
cd test-env && make test-unified-v2-protocol
```

Useful env vars:
- `SPIDERWEB_PORT` (default `28794`)
- `FS_NODE_PORT` (default `28931`)
- `BIND_ADDR` (default `127.0.0.1`)
- `SKIP_BUILD=1` to skip `zig build` if binaries are already built

## Soak / Chaos Suite

Runs the distributed workspace flow repeatedly with randomized ports and optional auth/encryption modes.

```bash
# Run directly
bash test-env/test-distributed-soak-chaos.sh

# Or through make
cd test-env && make test-distributed-soak-chaos
```

Useful env vars:
- `SOAK_ITERATIONS` (default `10`)
- `SOAK_ENABLE_OPERATOR_MODE=0|1` (default `1`)
- `SOAK_ENABLE_ENCRYPTED_MODE=0|1` (default `1`)

## Wiping and Restarting

```bash
# Stop and remove container (data is lost - this is the point!)
docker-compose down

# Remove the image to force rebuild
docker-compose down --rmi local

# Start fresh
docker-compose up --build
```

## Files

- `Dockerfile` - Minimal Debian with dependencies pre-installed
- `docker-compose.yml` - Container orchestration
- `test-install.sh` - Automated test of the install script
