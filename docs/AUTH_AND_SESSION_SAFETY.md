# Spiderweb Auth + Session Safety

This runbook documents authentication/token behavior and session rebind safety in unified-v2.

## 1. Token Roles

- `admin` token:
  - full control-plane access, including auth token rotation/status
  - can attach to the primary/default agent and Spiderweb system project
- `user` token:
  - reduced privileges
  - cannot attach to the primary agent
  - cannot attach to the Spiderweb system project

WebSocket connections must send `Authorization: Bearer <token>`. Missing/invalid tokens are rejected with `provider_auth_failed`.

## 2. First Run Token Generation

On first startup Spiderweb creates role tokens if no persisted file exists.

- storage file: `<runtime.ltm_directory>/auth_tokens.json`
- fallback when `runtime.ltm_directory` is empty: `./auth_tokens.json`

The server logs generated values once at startup. Capture and store them securely.

## 3. Rotation + Status Operations

Control operations (admin only):

- `control.auth_status` returns current `admin_token`, `user_token`, and storage path.
- `control.auth_rotate` with payload `{ "role": "admin" | "user" }` rotates one token role and persists to disk.

Expected failures:

- user token calling either endpoint -> `control.error` with `code=forbidden`

## 4. Session Rebind Safety (`session_busy`)

Spiderweb now rejects unsafe session rebind/project attach operations when jobs are still queued/running:

- `control.session_attach` returns `control.error` with `code=session_busy` when:
  - rebind is requested for a session whose current agent still has in-flight jobs
  - a project attach is requested for an agent that still has in-flight jobs

This prevents project/agent context changes mid-job.

## 5. Recovery Steps

When `session_busy` is returned:

1. Wait for queued/running jobs to complete (or resume/inspect from client).
2. Retry `control.session_attach` once agent job state is terminal.
3. If an auth token is compromised, rotate immediately with admin token and redistribute updated tokens.

Lost admin token emergency recovery:

1. Stop or quiesce Spiderweb operations.
2. Run `spiderweb-config auth reset --yes` on the Spiderweb host.
3. Record the printed admin/user tokens and store them securely.
4. Restart Spiderweb and update client-side stored role tokens.
