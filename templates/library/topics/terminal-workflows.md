# Terminal Workflows

Terminal service root:

- `/agents/self/terminal`

Control files:

- `/agents/self/terminal/control/create.json`
- `/agents/self/terminal/control/resume.json`
- `/agents/self/terminal/control/close.json`
- `/agents/self/terminal/control/write.json`
- `/agents/self/terminal/control/read.json`
- `/agents/self/terminal/control/resize.json`
- `/agents/self/terminal/control/exec.json`
- `/agents/self/terminal/control/invoke.json`

Runtime files:

- `/agents/self/terminal/status.json`
- `/agents/self/terminal/result.json`
- `/agents/self/terminal/current.json`
- `/agents/self/terminal/sessions.json`

## Choose the right pattern

- Use `exec` for one command and immediate output.
- Use `create` + `write` + `read` for interactive or multi-step work.
- Use `resume` when the session exists but is not active.
- Use `close` to terminate explicitly when work is done.

## One-shot execution

Write:

- path: `/agents/self/terminal/control/exec.json`
- payload: `{"command":"git status --short"}`

Then read:

- `/agents/self/terminal/status.json`
- `/agents/self/terminal/result.json`

If you need explicit routing through the generic endpoint:

- path: `/agents/self/terminal/control/invoke.json`
- payload: `{"op":"exec","arguments":{"command":"git status --short"}}`

## Interactive session workflow

1. Create session:
   - path: `/agents/self/terminal/control/create.json`
   - payload: `{"session_id":"build","cwd":"."}`
2. Send input:
   - path: `/agents/self/terminal/control/write.json`
   - payload: `{"session_id":"build","input":"npm test","append_newline":true}`
3. Read output:
   - path: `/agents/self/terminal/control/read.json`
   - payload: `{"session_id":"build","timeout_ms":1000,"max_bytes":65536}`
4. Repeat write/read until complete.
5. Close:
   - path: `/agents/self/terminal/control/close.json`
   - payload: `{"session_id":"build"}`

## Payload notes

- `write.json` can use `input` (utf-8 text) or `data_b64` (binary-safe).
- `read.json` returns base64 output data in `result.data_b64`.
- `resize.json` requires `cols` and `rows`.
- `resume.json` and `close.json` require `session_id` unless a current session exists.

## State and error handling

- `status.json` is authoritative for operation state (`idle|running|done|failed`) and the active tool.
- `result.json` contains structured success/error payloads.
- Common failure classes:
  - missing session (`enoent`)
  - closed session (`eperm`)
  - invalid payload (`invalid`)
  - platform/runtime backend unavailable (`unsupported` or `unavailable`)

## Practical guidance

- Prefer deterministic commands and explicit working directories.
- Keep `session_id` stable within one task stream.
- Read after each write; do not assume command completion without checking output.
- For long-running commands, alternate `read.json` calls with event/job waits as needed.
