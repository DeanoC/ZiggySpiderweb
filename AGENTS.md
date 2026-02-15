# Repository Guidelines

## Project Structure & Module Organization
This repository is a Zig project with source in `src/` and documentation in `README.md` and `design_docs/`.

- `src/main.zig` starts the gateway and parses CLI flags.
- `src/server_piai.zig` hosts the websocket/event-loop server and OpenClaw message flow.
- `src/protocol.zig` contains protocol parsing and response builders.
- `src/config.zig` handles config loading/saving and API-key resolution.
- `src/config_cli.zig` implements `spiderweb-config` commands.
- Tests are inlined with `test` blocks (currently in source files, not separate test folders).

## Build, Test, and Development Commands
- `zig build` — compiles both binaries: `spiderweb` and `spiderweb-config`.
- `zig build test` — runs all Zig test blocks (currently includes config defaults test).
- `zig build --release=safe` — builds an optimized safe release binary.
- `zig build run -- --port 18790 --bind 127.0.0.1` — runs the server from the build system.
- `zig build run -- --help` — prints runtime usage.
- `zig fmt src/*.zig` — formats Zig source using the standard formatter.

## Coding Style & Naming Conventions
- Follow Zig style used in existing files: 4-space indentation, UTF-8 plain text.
- Use `snake_case` for variables/functions/constants where possible; `PascalCase` for types and public structs/enums.
- Keep errors explicit with `try`/`catch`; prefer early returns for failures.
- Use small, single-purpose functions and short, actionable comments only when behavior is non-obvious.

## Testing Guidelines
- Add new behavior tests as `test "descriptive name"` blocks near related code.
- Prefer focused unit tests and avoid relying on network calls in unit tests.
- For behavior changes, run `zig build test` before finishing.
- If behavior depends on protocol or client interoperability, add a short manual verification section in the PR (example command run).

## Commit & Pull Request Guidelines
- Commit messages in this repo are mostly imperative and often prefixed by type (`fix:`, `refactor`, `Add ...`).
- Suggested format: `type(scope): short imperative summary` (e.g., `fix(config): preserve default log level when env missing`).
- PRs should include:
  - Purpose and impact summary.
  - Commands run (`zig build`, `zig build test`).
  - Notes for any environment/config changes (provider keys, bind settings, log levels).
- Remove secrets before sharing logs/screenshots; this project stores API keys in plain text config if set via CLI.

## Architecture & Runtime Notes
- The process runs as a Linux-targeted websocket gateway and expects OpenClaw-compatible clients.
- Core flow: `OpenClaw connect → websocket handshake → chat message parsing → provider stream proxy → OpenClaw frames`.
- Keep protocol paths and message types stable (`/v1/agents/{agentId}/stream`) to preserve client compatibility.
