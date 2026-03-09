# PR Review Workflow

Contract id:

- `spider_monkey/pr_review@v1`

This use case reviews a pull request using workspace-mounted services and records its detailed state in workspace files referenced by the mission `contract`.

Recommended contract file roles:

- `context_path`: repository identity, PR metadata, review policy, checkout root, default commands
- `state_path`: current phase, last synced head SHA, open threads, validation summary, current recommendation
- `artifact_root`: durable outputs such as findings, validation reports, review drafts, logs, and patches

Recommended artifact layout under `artifact_root`:

- `findings.json`
- `validation.json`
- `recommendation.json`
- `thread-actions.json`
- `review-comment.md`
- `logs/`
- `patches/`

Suggested loop:

1. Read the mission `contract`, then load `context_path` and `state_path`.
2. Discover available services through `/global/venoms/VENOMS.json`.
3. Use mounted Git/GitHub, terminal, search, and memory services to inspect the PR.
4. Persist intermediate conclusions into `state_path` instead of relying on chat context alone.
5. Write durable outputs into `artifact_root`.
6. Request approval through `/global/missions/control/request_approval.json` before push or merge when policy requires it.

The mission record should track lifecycle and approvals. PR-specific reasoning, review state, and outputs belong in the workspace files.
