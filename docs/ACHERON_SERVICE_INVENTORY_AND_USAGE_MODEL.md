# Acheron Service Inventory and Agent Usage Model (v1)

Status: active planning baseline (Issue #73)

This document defines the first production service set for Acheron and how
agents must discover, select, invoke, and recover when services are degraded.

## 1. Goals

- Standardize service delivery across node runtime forms:
  - statically linked (built-in)
  - dynamic native plugin (`native_proc`, `native_inproc`)
  - WASM plugin (`wasm`)
- Keep the namespace Plan9-style: services are mounted filesystem contracts,
  not only function endpoints.
- Make agent behavior deterministic for discovery, invoke, fallback, and errors.
- Define policy defaults compatible with current project token model.

## 2. Service Inventory Matrix (v1)

Legend:
- Runtime form: `builtin`, `native_proc`, `native_inproc`, `wasm`
- Maturity: `ready`, `next`, `later`
- Risk: `low`, `medium`, `high`, `critical`

| Service Class | Service ID Pattern | Runtime Form | Platforms | Maturity | Risk | Permission Baseline |
|---|---|---|---|---|---|---|
| Filesystem | `fs` | `builtin` | linux/windows/macos | ready | medium | `allow_roles:["admin","user"]`, project action `read/mount/invoke` |
| Terminal PTY | `terminal-<id>` | `builtin` (`native_proc` contract) | linux/windows/macos | ready | high | `allow_roles:["admin","user"]`, `require_project_token` for locked projects |
| Agent Memory | `memory` (agent namespace) | internal runtime tool bridge | server-hosted | ready | high | bound to `/agents/self`, project action `invoke` |
| Web Search | `web_search` (agent namespace) | internal runtime tool bridge (later node-backed) | server-hosted, future node-specific | ready | medium | `allow_roles:["admin","user"]`, network policy constrained |
| Camera Capture | `camera[-<id>]` | `native_proc` (device), optional `wasm` post-process | windows/macos/android/ios (linux optional) | next | high | user/admin, explicit device grant, token recommended |
| Screen Capture | `screen[-<id>]` | `native_proc` | windows/macos/linux desktop | next | high | user/admin, explicit device grant, token recommended |
| Cloud Drive FS | `drive-gdrive[-<id>]` | `native_proc` + fs adapter | all (OAuth capable) | next | medium | user/admin, token required for write mounts |
| Document Transform | `doc-pdf-md` | `wasm` preferred | all (wasm runner) | next | low | user/admin, no device access |
| Browser Fetch/Extract | `web-fetch` | `native_proc` or `wasm` | all | next | medium | user/admin, network policy constrained |
| Remote Desktop | `remote-desktop[-<id>]` | `native_proc` | windows/macos/linux desktop | later | critical | admin default, explicit per-project allow |
| Audio I/O | `audio[-<id>]` | `native_proc` | windows/macos/android/ios | later | high | user/admin with explicit consent |

## 3. Runtime Form Guidance

Use these defaults when designing a new service:

- `builtin`:
  - choose when host integration is essential and cross-platform code is small
  - examples: `fs`, base `terminal`
- `native_proc`:
  - default for device/system integrations and crash isolation
  - examples: `camera`, `screen`, `web-fetch`
- `native_inproc`:
  - use only for trusted, performance-sensitive plugins
  - requires strict ABI/version pinning
- `wasm`:
  - default for portable transforms and untrusted compute
  - examples: document conversion, parsing/normalization pipelines

## 4. Agent Usage Contract

### 4.1 Discovery Order

Agents should resolve services in this order:

1. Read `/agents/self/services/SERVICES.json` for stable index entries.
2. For node-scoped work, inspect `/nodes/<node_id>/services/SERVICES.json`.
3. Inspect service contract files before invoke:
   - `README.md`
   - `SCHEMA.json`
   - `TEMPLATE.json`
   - `CAPS.json`
   - `OPS.json`
   - `PERMISSIONS.json`
   - `STATUS.json`
4. Prefer services where `state=online`; use `degraded` only with fallback plan.

### 4.2 Invoke Contract (Namespace-first)

For every invoke-capable service:

1. Resolve invoke target from `OPS.json` (`invoke` or `paths.invoke`), else use
   `control/invoke.json`.
2. If no payload exists yet, read `TEMPLATE.json` (or `template.json`) and use it
   as the initial invoke payload.
3. Write JSON payload to invoke file.
4. Treat write success as acceptance, not completion.
5. Read `status.json` and `result.json` (or service-documented equivalents).
6. For long-running jobs, use event wait:
   - write selectors to `/agents/self/events/control/wait.json`
   - blocking read `/agents/self/events/next.json`
7. For single known endpoint waits, blocking read on that endpoint is valid when
   endpoint supports it.

### 4.3 Retry and Fallback Rules

Agent runtime should apply these defaults:

- Retry policy:
  - transient failures (`timeout`, `connection reset`, temporary `degraded`):
    retry up to 2 times with exponential backoff (500ms, 2s)
  - no retry for explicit permission/policy errors
- Fallback selection:
  1. same `service_id` on another online node in project
  2. same `kind` on another online node
  3. agent namespace equivalent (`/agents/self/<service>`)
  4. if none, return actionable failure with required operator action
- Degraded mode behavior:
  - allow read-only operations where contract indicates safe behavior
  - avoid mutating operations unless no alternative and user confirms

### 4.4 User-Facing Failure Messaging

Agent responses should include:

- attempted service path and node
- failure class: permission, unavailable, timeout, invalid payload, runtime error
- next action: retry, choose alternate node, request token, request device grant

Response template:

`Unable to run <operation> via <service_path> on <node_id>: <reason>.`
`Next: <one concrete recovery step>.`

## 5. Policy Baseline

These defaults are aligned with current project model:

- tokenless project: user/admin can access and mutate unless access policy denies
- token-protected project: user requires project token for token-scoped actions
- admin bypass remains enabled
- system project remains admin-only except primary system behavior

### 5.1 Service Permission Templates

Service manifests should start from one of these templates.

1. General compute/network (`web_search`, `doc-pdf-md`, `web-fetch`):

```json
{
  "allow_roles": ["admin", "user"],
  "default": "deny-by-default"
}
```

2. Filesystem and drive mounts (`fs`, `drive-gdrive-*`):

```json
{
  "allow_roles": ["admin", "user"],
  "default": "deny-by-default",
  "require_project_token": false
}
```

3. Device capture (`camera-*`, `screen-*`, `audio-*`):

```json
{
  "allow_roles": ["admin", "user"],
  "default": "deny-by-default",
  "require_project_token": true,
  "device": "restricted"
}
```

4. Privileged host control (`remote-desktop-*`, pairing/admin helpers):

```json
{
  "allow_roles": ["admin"],
  "default": "deny-by-default",
  "require_project_token": true
}
```

### 5.2 Project Action Recommendations

Recommended `access_policy.actions` defaults:

- Tokenless non-system projects:
  - `read`: allow user/admin
  - `observe`: allow user/admin
  - `invoke`: allow user/admin
  - `mount`: allow user/admin
  - `admin`: admin only
- Token-protected projects:
  - same as above but user actions require token binding
- System project:
  - all actions admin only (except primary `mother` runtime)

## 6. First-Wave Roadmap (Phase 12+)

Priority order and implementation ownership placeholders.

| Priority | Service | Target Runtime | Repos | Owner | Why Now |
|---|---|---|---|---|---|
| 1 | `terminal-v2` sessionized namespace | builtin + runtime state | Protocol, Node, Spiderweb, StarSpider | `owner:node-runtime` | Highest daily utility for coding/ops |
| 2 | `screen-main` capture service | `native_proc` | Node, Protocol, Spiderweb, StarSpider | `owner:desktop-integrations` | Needed for visual diagnostics and UX agents |
| 3 | `camera-main` still capture service | `native_proc` | Node, Protocol, Spiderweb, StarSpider | `owner:desktop-integrations` | Common desktop/mobile capability |
| 4 | `drive-gdrive-main` namespace mount | `native_proc` + fs adapter | Protocol, Node, Spiderweb | `owner:cloud-connectors` | High-value file federation use case |
| 5 | `doc-pdf-md` transform service | `wasm` | Node, Protocol, Spiderweb | `owner:wasm-runtime` | Safe portable conversion primitive |

### 6.1 Acceptance Criteria Per Service

Each first-wave service must ship with:

- manifest + contract files (`README.md`, `SCHEMA.json`, `CAPS.json`, `OPS.json`,
  `RUNTIME.json`, `PERMISSIONS.json`)
- integration tests:
  - node advertises service catalog correctly
  - WorldFS projects mount and expose invoke path correctly
  - permission and token gating behavior validated for user/admin
- failure-path tests:
  - service offline/degraded
  - invalid payload
  - timeout behavior
- client acceptance:
  - `zss` CLI invoke/read flow documented and tested
  - `zss-gui` debug visibility for state/result/error

### 6.2 Rollout Gates

Promote service from `next` to `ready` only when:

1. Linux CI + Windows cross-build pass.
2. Multi-node runtime harness validates discovery and invoke.
3. Policy tests confirm no privilege escalation path.
4. Operator runbook exists for install, permissions, and troubleshooting.

## 7. Repository/Module Boundaries

- `ZiggySpiderProtocol`:
  - shared runtime ABI, manifest schema, runtime manager, adapters
- `ZiggySpiderNode`:
  - node daemon, built-in services, plugin/wasm loading, platform drivers
- `ZiggySpiderweb`:
  - control-plane service catalog, policy enforcement, Acheron projection
- `ZiggyStarSpider`:
  - CLI/GUI discovery, invoke UX, diagnostics

New services should be designed protocol-first in `ZiggySpiderProtocol`, then
implemented in `ZiggySpiderNode`, enforced/projected in `ZiggySpiderweb`, and
surfaced in `ZiggyStarSpider`.

## 8. Follow-Up Execution Issues

Create one execution issue per prioritized service with:

- scope and contract files
- repo touch list
- test matrix (linux/windows/mac where relevant)
- rollout checklist

This planning document is the baseline source for those execution issues.
