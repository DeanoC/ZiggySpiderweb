# Ziggy PR Review Policy (Repository Policy)

This document mirrors the repository guidelines in `AGENTS.md`.

## Branch Protection
- Direct pushes to the default branch are not allowed.
- All updates to the default branch must go through a pull request.

## Codex Review Handling
- `chatgpt-codex-connector` review is required before merge.
- All Codex review threads must be resolved before merge.
- The first Codex review is automatic on PR open; follow-up `@codex review` requests are optional after additional pushes.

## Merge Mode
- Auto-merge is allowed only when there are zero open Codex comments/threads.
- Otherwise, merge manually once all comments are addressed.
