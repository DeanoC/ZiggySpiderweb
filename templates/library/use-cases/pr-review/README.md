# PR Review Workflow

Contract id:

- `spider_monkey/pr_review@v1`

This use case reviews a pull request using workspace-mounted services and records its detailed state in workspace files referenced by the mission `contract`.

Service entrypoint:

- `/global/pr_review/control/intake.json`
- `/global/pr_review/control/start.json`
- `/global/pr_review/control/sync.json`
- `/global/pr_review/control/run_validation.json`
- `/global/pr_review/control/record_validation.json`
- `/global/pr_review/control/record_review.json`
- `/global/pr_review/control/invoke.json` with `{"op":"intake","arguments":{...}}`

Supporting service Venoms:

- `/global/git/control/sync_checkout.json`
- `/global/git/control/status.json`
- `/global/git/control/diff_range.json`
- `/global/github_pr/control/ingest_event.json`
- `/global/github_pr/control/sync.json`
- `/global/github_pr/control/publish_review.json`

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
- `services/provider-sync.json`
- `services/checkout.json`
- `services/repo-status.json`
- `services/diff-range.json`
- `services/publish-review.json`
- `logs/`
- `patches/`

Suggested loop:

1. Prefer `/global/github_pr/control/ingest_event.json` for provider-driven PR intake. It normalizes the GitHub event, emits `/global/events/sources/agent/github_pr.json`, and auto-creates or reuses the matching `pr_review` mission.
2. Load a PR through `/global/pr_review/control/intake.json` when you want provider metadata captured as part of mission bootstrap from a manual/operator flow. Use `/global/pr_review/control/start.json` only when a lower-level caller already has the PR metadata locally.
3. Read the mission `contract`, then load `context_path` and `state_path`.
4. Use `/global/pr_review/control/sync.json` to advance the review phase, keep `state_path` current, and optionally orchestrate provider/repo sync through `provider_sync`, `sync_checkout`, `repo_status`, and `diff_range` blocks.
5. Use `/global/pr_review/control/run_validation.json` to execute the configured review commands through `/global/terminal`, persist per-command service captures, and refresh the latest validation summary in state.
6. Use `/global/pr_review/control/record_validation.json` only when a higher-level agent wants to write a custom validation artifact instead of running commands through the built-in validation runner.
7. Use `/global/pr_review/control/record_review.json` to persist findings, recommendation, review-comment drafts, thread-action snapshots, and optionally `publish_review`.
8. Discover available services through `/global/venoms/VENOMS.json`.
9. Use `/global/git/control/sync_checkout.json` to create or refresh the repo checkout under the mission workspace.
10. Use `/global/github_pr/control/sync.json` to load provider PR metadata when GitHub context needs to be refreshed.
11. Use `/global/git/control/status.json` and `/global/git/control/diff_range.json` for deterministic changed-file and branch-state inspection.
12. Use mounted terminal, search, and memory services to validate findings and gather supporting evidence.
13. Use `/global/github_pr/control/publish_review.json` for top-level review publication when policy allows it.
14. Request approval through `/global/missions/control/request_approval.json` before push or merge when policy requires it.

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
