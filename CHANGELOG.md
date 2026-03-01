# Changelog

All notable changes to this project are documented in this file.

## 0.3.0 - 2026-02-22

### Protocol and Contract
- Unified v2 parser contract is now strict:
  - `channel` is required
  - `type` must match the selected channel namespace
  - legacy/implicit compatibility envelopes are rejected
- Added protocol contract tests in `ZiggySpiderProtocol` for canonical v2 control/acheron naming and strict envelope validation.

### Control Plane, Projects, and Nodes
- Local spiderweb filesystem node remains protocol-identical to external nodes and is surfaced as a standard project mount endpoint.
- Workspace mount payloads now include `fs_auth_token` for FS session auth propagation.
- Added project-scoped topology delta push events (`control.workspace_topology_delta`) in addition to full refresh events (`control.workspace_topology`).

### Filesystem Routing and Auth
- Added optional FS session auth on `/v2/fs` via `auth_token` in `acheron.t_fs_hello`.
- Added `spiderweb-fs-node --auth-token` and `SPIDERWEB_FS_NODE_AUTH_TOKEN` for auth enforcement on standalone nodes.
- Router now propagates per-endpoint auth token during HELLO negotiation (initial + health probes + event pumps).

### Observability and Health
- Metrics HTTP endpoint now serves:
  - `/metrics` as Prometheus text format
  - `/metrics.json` as JSON (backward-compatible JSON surface retained)
- Added `/livez` and `/readyz` health endpoints.

### Tooling and Integration
- Added `spiderweb-control` CLI for control-plane operations with automatic `control.version` + `control.connect` negotiation.
- Added dedicated integration test wrappers:
  - `test-distributed-workspace-encrypted.sh` (`SPIDERWEB_CONTROL_STATE_KEY_HEX`)
  - `test-distributed-workspace-operator-token.sh` (`SPIDERWEB_CONTROL_OPERATOR_TOKEN`)
- Added operator-token deny/allow assertions into distributed test flow (`ASSERT_OPERATOR_TOKEN_GATE=1`).
- Added long-running soak/chaos harness: `test-distributed-soak-chaos.sh`.

### Docs
- Updated migration guidance in `docs/protocols/unified-v2-fs-migration.md`.
- Updated `README.md` and `test-env/README.md` for auth, metrics, health, and new test targets.
