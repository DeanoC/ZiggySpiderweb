# HATCH.md System (Legacy Design Notes)

## Status (as of February 17, 2026)

`HATCH.md` support in this repository is currently **not active on the runtime websocket path**.

The active gateway protocol is runtime-native:
- input: `connect`, `session.send`, `agent.control`, `ping`
- output: `connect.ack`, `session.receive`, `tool.event`, `memory.event`, `agent.state`, `error`

Legacy chat input (`chat.send`) is rejected, and the websocket server does not currently route
`agent.create` / `agent.hatch` style message handling.

## Why This File Exists

The codebase still contains an `agent_registry` module with a HATCH-based lifecycle concept
(agent birth certificate, hatching completion, identity scaffolding). This document captures that
design intent so it can be reintroduced safely later, but it should not be read as current
runtime behavior.

## Legacy HATCH Concept

The intended model was:
1. create an agent directory with `HATCH.md`
2. let the agent read `HATCH.md` and write identity files (`SOUL.md`, `AGENT.md`, etc.)
3. mark hatching complete and remove `HATCH.md`

This remains useful as a design pattern, but it is not wired into the current websocket runtime
flow.

## Current Protocol Guidance

Use the runtime message model documented in `README.md`:
- send work with `session.send`
- control runtime with `agent.control`
- do not rely on `chat.send` or first-boot chat routing

If you need onboarding UX today, implement it at the client/app layer (outside server protocol
routing), or stage filesystem bootstrap before runtime session traffic begins.

## If HATCH Is Reintroduced

Before enabling HATCH flows again, align all of the following in one change:
1. protocol parser and message-type table
2. websocket server routing/handlers
3. docs in this file and `README.md`
4. end-to-end tests for first-boot and hatching completion

This avoids drift where docs describe flows that transport no longer supports.
