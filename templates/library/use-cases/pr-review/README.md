# PR Review Workflow

Contract id:

- `spider_monkey/pr_review@v1`

This use case reviews a pull request using workspace-mounted services and records its detailed state in workspace files referenced by the mission `contract`.

Preferred bound service entrypoint:

- `/services/pr_review/control/configure_repo.json`
- `/services/pr_review/control/get_repo.json`
- `/services/pr_review/control/list_repos.json`
- `/services/pr_review/control/intake.json`
- `/services/pr_review/control/start.json`
- `/services/pr_review/control/sync.json`
- `/services/pr_review/control/run_validation.json`
- `/services/pr_review/control/record_validation.json`
- `/services/pr_review/control/draft_review.json`
- `/services/pr_review/control/save_draft.json`
- `/services/pr_review/control/record_review.json`
- `/services/pr_review/control/advance.json`
- `/services/pr_review/control/invoke.json` with `{"op":"intake","arguments":{...}}`

Fallback origin:

- `/nodes/local/venoms/*` is the canonical local-service origin when no project-bound `/services/*` path is available yet.
- `/global/*` remains as a compatibility alias.
- Resolve the live service path from `/meta/workspace_services.json` when possible instead of assuming `/services/*` is mounted.

Supporting service Venoms:

- `/services/git/control/sync_checkout.json`
- `/services/git/control/status.json`
- `/services/git/control/diff_range.json`
- `/services/github_pr/control/ingest_event.json`
- `/services/github_pr/control/sync.json`
- `/services/github_pr/control/publish_review.json`

Recommended contract file roles:

- `context_path`: repository identity, PR metadata, review policy, checkout root, default commands
- `state_path`: current phase, last synced head SHA, open threads, validation summary, current recommendation
- `artifact_root`: durable outputs such as findings, validation reports, review drafts, logs, and patches

Recommended artifact layout under `artifact_root`:

- `draft-review.json`
- `review-comment-draft.md`
- `drafts/`
- `findings.json`
- `validation.json`
- `recommendation.json`
- `thread-actions.json`
- `review-comment.md`
- `services/provider-sync.json`
- `services/checkout.json`
- `services/repo-status.json`
- `services/diff-range.json`
- `services/publish-review.json`
- `logs/`
- `patches/`

Suggested loop:

1. Onboard or update each monitored repository through `/services/pr_review/control/configure_repo.json`. The canonical repo catalog lives at `/nodes/local/fs/pr-review/state/repos.json`.
2. Use `/services/pr_review/control/get_repo.json` and `/services/pr_review/control/list_repos.json` to inspect the current onboarding state before taking action.
3. Prefer `/services/github_pr/control/ingest_event.json` for provider-driven PR intake. It normalizes the GitHub event, emits `/global/events/sources/agent/github_pr.json`, and auto-creates or reuses the matching `pr_review` mission.
4. If the event payload omits repo-specific defaults, `github_pr ingest_event` will fill them from the configured repo record. Explicit event fields still win.
5. Load a PR through `/services/pr_review/control/intake.json` when you want provider metadata captured as part of mission bootstrap from a manual/operator flow. Use `/services/pr_review/control/start.json` only when a lower-level caller already has the PR metadata locally.
6. Read the mission `contract`, then load `context_path` and `state_path`.
7. Use `/services/pr_review/control/advance.json` for the deterministic runner step. It can resume a blocked/planning mission, wait on `/global/events/...`, perform the next sync/validation pass, and return `runner.status` plus `runner.next_action` like `draft_review` or `revise_review` without hard-coding review judgment into Zig.
8. Use `/services/pr_review/control/sync.json` when you need lower-level control over provider/repo sync, or when a higher-level agent wants to override the deterministic runner step.
9. Use `/services/pr_review/control/run_validation.json` to execute the configured review commands through the resolved terminal service path, persist per-command service captures, and refresh the latest validation summary in state.
10. Use `/services/pr_review/control/record_validation.json` only when a higher-level agent wants to write a custom validation artifact instead of running commands through the built-in validation runner.
11. Use `/services/pr_review/control/draft_review.json` when you want Spider Monkey to read the mission contract, inspect the saved artifacts, and persist the next review draft through Acheron. On the first draft, the draft artifact files do not exist yet, so treat them as outputs to create rather than evidence to inspect.
12. Use `/services/pr_review/control/save_draft.json` to create or update the latest review draft, keep the current draft files in sync, and write immutable revision snapshots under `drafts/`. A minimal valid payload includes `mission_id`, `summary`, `findings`, `recommendation`, and `review_comment`.
13. Use `/services/pr_review/control/record_review.json` to persist findings, recommendation, review-comment drafts, thread-action snapshots, and optionally `publish_review`. If `findings` and `recommendation` are omitted, it will promote the latest saved draft-review artifact automatically.
14. Discover available services through `/projects/<project_id>/meta/mounted_services.json` first, then fall back to `/nodes/local/venoms/VENOMS.json` for the local catalog if needed. `/global/venoms/VENOMS.json` remains the compatibility discovery index.
15. Use `/services/git/control/sync_checkout.json` to create or refresh the repo checkout under the mission workspace.
16. Use `/services/github_pr/control/sync.json` to load provider PR metadata when GitHub context needs to be refreshed.
17. Use `/services/git/control/status.json` and `/services/git/control/diff_range.json` for deterministic changed-file and branch-state inspection.
18. Use mounted terminal, search, and memory services to validate findings and gather supporting evidence.
19. Use `/services/github_pr/control/publish_review.json` for top-level review publication when policy allows it.
20. Request approval through `/services/missions/control/request_approval.json` before push or merge when policy requires it.

Example orchestration payloads:

```json
{
  "mission_id": "mission-123",
  "phase": "ready_for_checkout",
  "provider_sync": { "dry_run": true },
  "sync_checkout": { "head_branch": "feature/pr-123" },
  "repo_status": true,
  "diff_range": { "base_branch": "main", "head_ref": "HEAD" }
}
```

```json
{
  "mission_id": "mission-123"
}
```

```json
{
  "mission_id": "mission-123",
  "findings": [],
  "recommendation": { "decision": "comment", "summary": "Looks good overall" },
  "review_comment": "No blocking issues found.",
  "publish_review": { "dry_run": true }
}
```

The mission record should track lifecycle and approvals. PR-specific reasoning, review state, and outputs belong in the workspace files.
