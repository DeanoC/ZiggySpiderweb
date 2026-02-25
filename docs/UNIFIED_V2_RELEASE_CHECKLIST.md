# Unified v2 Release Checklist

## Protocol
- [ ] Confirm all clients send explicit `channel` (`control` / `acheron`).
- [ ] Confirm all clients use canonical unified v2 type names.
- [ ] Verify control negotiation order:
  1. `control.version` (`{"protocol":"unified-v2"}`)
  2. `control.connect`
- [ ] Verify runtime Acheron negotiation order:
  1. `acheron.t_version` (`"version":"acheron-1"`)
  2. `acheron.t_attach`
- [ ] Verify FS routing negotiation order:
  1. `acheron.t_fs_hello` (`{"protocol":"unified-v2-fs","proto":2,...}`)

## Auth and Security
- [ ] If enabling control mutation gate, set `SPIDERWEB_CONTROL_OPERATOR_TOKEN` and validate protected operations require `payload.operator_token`.
- [ ] If enabling encrypted control-plane snapshots, set `SPIDERWEB_CONTROL_STATE_KEY_HEX` (64 hex chars).
- [ ] If enabling FS session auth on standalone nodes, set `spiderweb-fs-node --auth-token` (or `SPIDERWEB_FS_NODE_AUTH_TOKEN`) and verify router HELLO includes matching `auth_token`.

## Observability
- [ ] Set `SPIDERWEB_METRICS_PORT` and verify:
  - [ ] `GET /livez` returns 200
  - [ ] `GET /readyz` returns 200
  - [ ] `GET /metrics` returns Prometheus text
  - [ ] `GET /metrics.json` returns JSON metrics

## Integration Validation
- [ ] `cd test-env && make test-distributed-workspace`
- [ ] `cd test-env && make test-distributed-workspace-bootstrap`
- [ ] `cd test-env && make test-distributed-workspace-drift`
- [ ] `cd test-env && make test-distributed-workspace-matrix`
- [ ] `cd test-env && make test-distributed-workspace-encrypted`
- [ ] `cd test-env && make test-distributed-workspace-operator-token`
- [ ] `cd test-env && make test-distributed-soak-chaos`

## Client / Tooling Updates
- [ ] Update automation/scripts to use `spiderweb-control` for control-plane calls where appropriate.
- [ ] Update mount workflows using project pinning (`--project-id`) to benefit from project-scoped topology deltas.
