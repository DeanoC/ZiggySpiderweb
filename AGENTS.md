# Repository Guidelines

## Project Structure & Module Organization
This repository is part of the Ziggy* codebase and is primarily a Zig project.

- `src/` contains runtime/library source files.
- `build.zig` defines build targets and dependency wiring.
- `build.zig.zon` contains package metadata and dependency pins.
- `README.md` documents setup, architecture notes, and usage.
- Tests are implemented with Zig `test` blocks and, where present, files under `tests/`.

## Build, Test, and Development Commands
- `zig build` - build all configured artifacts for this repository.
- `zig build test` - run the repository test suite.
- `zig build --release=safe` - build optimized safe artifacts.
- `zig fmt src/*.zig` - format Zig source files.
- If source code changes, run `zig build` and `zig build test` and confirm both pass before pushing.

## Coding Style & Naming Conventions
- Follow Zig style and keep code `zig fmt` clean.
- Use `snake_case` for functions/variables/constants where possible.
- Use `PascalCase` for public types (`struct`, `enum`, `union`).
- Prefer explicit error handling with `try`/`catch` and early returns.
- Keep functions focused and add concise comments only where behavior is non-obvious.

## Testing Guidelines
- Add tests close to the changed behavior using descriptive names.
- Prefer focused tests with deterministic inputs.
- For behavior changes, include both success and failure-path coverage where practical.
- Run `zig build test` before opening or updating a PR.

## Commit & Pull Request Guidelines
- Use clear, imperative commit messages (Conventional prefixes like `feat:`, `fix:`, `refactor:` are preferred).
- PR descriptions should include:
  - Summary of purpose and impact.
  - Commands run (`zig build`, `zig build test`).
  - Notes on compatibility/config changes when relevant.

## Branch Protection And Review Gate
- Direct pushes to `main` are not allowed.
- All changes that update `main` must go through a pull request.
- A PR must not be merged until `chatgpt-codex-connector` (including variants like `chatgpt-codex-connector[bot]`) has reviewed it.
- Do not merge while any review comments from that reviewer remain outstanding.
- Address each comment and resolve each review thread before merging.

## Compatibility Policy
- Until `1.0.0`, backward compatibility is not guaranteed.
- Breaking changes are allowed during early development, but should be documented in PR notes.
