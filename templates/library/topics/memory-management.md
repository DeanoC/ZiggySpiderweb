# Memory Management

Use this guide when context pressure rises and you need to decide what to keep, summarize, or evict.

## Keep vs Evict

Keep:

- active goal, current step, and success criteria
- hard constraints, policies, and user preferences
- decisions that changed plan direction
- unresolved blockers and open questions
- canonical artifact paths (files, jobs, service endpoints)

Evict first:

- duplicate notes that restate the same fact
- stale plans for completed or abandoned branches
- large raw outputs that are reproducible (logs, listings, search dumps)
- resolved error traces once root cause and fix are recorded
- low-value chatter that does not affect next actions

## Summarize Before Evict

When dropping detailed state, preserve intent and outcomes in a short durable summary:

1. Record why the work happened (goal/constraint).
2. Record what changed (files, services, config, runtime state).
3. Record why it changed (decision and tradeoff).
4. Record what remains open (next action or blocker).

Suggested summary shape:

- `objective`: what this branch was trying to achieve
- `changes`: concrete outputs and paths
- `decisions`: key choices and rationale
- `open_items`: unresolved risks or follow-ups

## Context Pressure Heuristic

- Above 50% context usage: stop adding raw detail, start compacting aggressively.
- Above 70% context usage: keep only action-critical state and durable summaries.
- If near limit: write a summary first, then evict verbose entries.

## Operational Pattern

- Search memory for existing entries before creating new ones.
- Mutate/append existing memory when continuing the same thread.
- Create a new memory branch only when objective/scope changes.
- Evict after summary is persisted and references are preserved.

Related operational contract:

- `/global/library/topics/memory-workflows.md`
