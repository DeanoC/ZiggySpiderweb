# Mission Contracts

Long-running use cases should keep their detailed working state in files, not in Spiderweb's core mission schema.

Mission records may expose a generic `contract` bundle with:

- `contract_id`
- `context_path`
- `state_path`
- `artifact_root`

How to use it:

1. Read the mission record from `/services/missions/result.json` or `/services/missions/control/get.json` when the workspace binds it. The canonical local origin is `/nodes/local/venoms/missions/*`, and `/global/missions/*` is the compatibility alias when no workspace service bind is available yet.
2. If `contract` is present, materialize its files under `/nodes/local/fs/...` with `/services/missions/control/bootstrap_contract.json` when they do not exist yet.
3. Read `context_path` before acting.
4. Read `state_path` to resume the current loop and avoid repeating work.
5. Write findings, logs, reports, and patches under `artifact_root`.
6. Update the mission `contract` only when the workspace files move or you promote work into a new artifact root.

Field roles:

- `contract_id`: stable use-case contract name, for example `spider_monkey/pr_review@v1`
- `context_path`: mostly-stable mission context and policy snapshot
- `state_path`: mutable working state and latest summary
- `artifact_root`: directory for outputs such as findings, validation reports, logs, and patches

Keep use-case-specific details in the contract files themselves. The kernel should stay generic.
