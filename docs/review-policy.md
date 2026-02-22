# Ziggy Shared PR Review Policy

This document is the source of truth for PR review and merge policy across Ziggy repositories.

## Branch Protection
- Direct pushes to `main` are not allowed.
- All updates to `main` must go through a pull request.

## Codex Review Handling
- `chatgpt-codex-connector` review is required before merge.
- All Codex review threads/conversations must be resolved before merge.
- If any `P1` feedback is raised, the fix must be pushed and a follow-up review must be requested with `@codex review` before merge.
- `P2` and `P3` feedback is non-blocking for merge, but must be tracked as GitHub issues and linked from the PR.

## Merge Mode
- Auto-merge is disabled.
- Merges are manual only, by a human or AI maintainer, when they decide risk is acceptable.
