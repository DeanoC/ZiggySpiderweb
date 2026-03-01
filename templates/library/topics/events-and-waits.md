# Events and Waits

Use blocking single-source reads first when you know exactly what you are waiting for:

- `/agents/self/jobs/<job-id>/status.json`
- `/agents/self/jobs/<job-id>/result.txt`

Use multi-source waits only when one-of-many sources can unblock the flow.

1. Write wait selector payload to `/agents/self/events/control/wait.json`.
2. Read `/agents/self/events/next.json` to block for the first matching event.
3. Reconfigure selectors if the blocking conditions change.

Recommended selector style:

- Keep `paths` minimal and explicit.
- Prefer deterministic source paths over broad patterns.
- Set `timeout_ms` intentionally so loops can recover and re-plan.

Synthetic signals can be emitted through `/agents/self/events/control/signal.json` for
agent/hook/user channels when orchestration layers need explicit wake-up events.
