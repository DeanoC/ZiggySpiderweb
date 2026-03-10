# Repository Services

Spiderweb exposes first-class repository services through the Acheron namespace:

- `/services/git`
- `/services/github_pr`

Use these before reaching for raw shell commands when the task is about repository checkout, diff inspection, or GitHub pull-request synchronization. `/global/*` remains the current local-service origin, but agents should prefer the workspace-bound `/services/*` paths whenever they are available.

## Git service

Control files:

- `/services/git/control/sync_checkout.json`
- `/services/git/control/status.json`
- `/services/git/control/diff_range.json`
- `/services/git/control/invoke.json`

Practical guidance:

1. Use `sync_checkout` to create or refresh a deterministic checkout under `/nodes/local/fs/...`.
2. Use `status` to inspect HEAD, branch state, dirty status, and changed files relative to a base ref.
3. Use `diff_range` when you need an explicit base/head comparison and diff summary.
4. Keep `checkout_path` inside the canonical namespace, not a host-internal path.

## GitHub PR service

Control files:

- `/services/github_pr/control/ingest_event.json`
- `/services/github_pr/control/sync.json`
- `/services/github_pr/control/publish_review.json`
- `/services/github_pr/control/invoke.json`

Practical guidance:

1. Use `sync` to refresh provider PR metadata through the GitHub REST API.
2. Use `ingest_event` to normalize provider webhook-style payloads into Acheron and emit `/global/events/sources/agent/github_pr.json`.
3. When a repo has already been onboarded through `/services/pr_review/control/configure_repo.json`, `ingest_event` will reuse those defaults for auto-intake, checkout path, review commands, and approval policy unless the event payload overrides them.
4. Use `publish_review` for top-level review publication.
5. Thread-level comment actions may still require follow-up handling in this phase, so keep `thread_actions` durable in review artifacts even when publication is dry-run only.
6. Prefer `dry_run:true` when planning or previewing an operator-facing action.
