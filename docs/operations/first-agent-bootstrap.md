# Mother Bootstrap Runbook

This runbook validates first-boot behavior where only `mother` + `system` exist, then verifies first project/agent provisioning.

## Fast Path: Provider-Backed Manual Canary

Run:

```bash
./scripts/manual-mother-provider-canary.sh
```

What this checks:

1. `control.connect` returns `control.connect_ack` bound to `mother/system` with `bootstrap_only=true`.
2. A real provider-backed Mother reply is produced over Acheron chat.
3. First project is created with required `vision`.
4. First non-system agent is created via Acheron (`/agents/self/agents/control/create.json`).
5. Created agent has `agent.json` + `HATCH.md` scaffold.
6. `control.session_attach` to the new project/agent succeeds.
7. Post-bootstrap `control.connect` reports `bootstrap_only=false`.

If it fails with `provider request invalid`, fix provider credentials/model in:

- `~/.config/spiderweb/config.json`

and rerun.

Useful options:

```bash
KEEP_CANARY_DIR=1 ./scripts/manual-mother-provider-canary.sh
CANARY_PROVIDER_NAME=openai CANARY_PROVIDER_MODEL=gpt-4o-mini ./scripts/manual-mother-provider-canary.sh
```

## Mother-Driven Operations E2E

Run:

```bash
./scripts/manual-mother-agent-e2e.sh
```

What this additionally checks:

1. Mother performs project + agent provisioning from chat/tool execution (not only external control calls).
2. Mother executes mount/bind/resolve through `/agents/self/mounts/control/*.json`.
3. Script verifies resulting mount/bind state and successful `session_attach` to the Mother-created context.

## Protocol Notes (Current Behavior)

- `control.connect` returns `control.connect_ack` even when context selection is needed.
- Context gating is exposed in payload fields:
  - `requires_session_attach`
  - `connect_gate` (`code`/`message`)
- Bootstrap mode indicator:
  - `bootstrap_only=true`
  - non-null `bootstrap_message`

## Important Constraints

- Mother is system-locked (`project_id=system`) and user role cannot attach to Mother.
- Project creation requires non-empty `vision`.
- Unified v2 gateway rejects legacy websocket chat envelopes (`session.send`, `chat.send`).
