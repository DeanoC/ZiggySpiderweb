# Clean-Slate Implementation Plan: Agent Runtime Design (MemId-Explicit Active Memory)

## Summary
Implement a clean agent runtime where each brain loop operates on structured Active Memory entries that always expose `MemId` and tier metadata (`RAM` or `ROM`). The LLM never sees anonymous text-only memory; every memory item is addressable for `memory.mutate` and `memory.evict`.

## Key Requirement Locked In
Active Memory presented to each brain is structured JSON and each item includes:
1. Canonical `mem_id` (string, full MemId format).
2. `tier` (`"ram"` or `"rom"`).
3. `version` (explicit numeric version or `null` when latest alias is used).
4. `kind` (`message|summary|tool_result|state|note` etc).
5. `content` (payload object/string).
6. `mutable` (`true` for RAM entries writable via tools, `false` for ROM).

This format is mandatory in Observe stage and in tool result injection.

## Scope and Non-Goals
In scope:
- `design_docs/ARCHITECTURE.md`
- `design_docs/Agents/AgentLoop.md`
- `design_docs/Agents/BrainTools.md`
- `design_docs/Agents/Memory.md`
- `design_docs/GLOSSARY.md`

Non-goals:
- Supporting old message contracts, old memory IDs, or old worker orchestration behavior.
- Migration of legacy state/storage formats.
- Any requirements from `design_docs/Agents/AgentDesign.md` or `design_docs/FileSystem.md`.

## Active Memory Contract (Authoritative)
```json
{
  "active_memory": {
    "brain": "primary",
    "items": [
      {
        "mem_id": "<EOT>Agent:primary:task_plan:12<EOT>",
        "tier": "ram",
        "version": 12,
        "kind": "message",
        "mutable": true,
        "created_at_ms": 1739660000000,
        "content": {
          "role": "assistant",
          "text": "Plan draft..."
        }
      },
      {
        "mem_id": "<EOT>Agent:primary:system_clock:1<EOT>",
        "tier": "rom",
        "version": 1,
        "kind": "state",
        "mutable": false,
        "created_at_ms": 1739660001000,
        "content": {
          "now_iso8601": "2026-02-16T12:00:00Z"
        }
      }
    ]
  }
}
```

## Clean Architecture Target
1. Single runtime entrypoint for all agent behavior.
2. Brain-first execution model:
- Primary brain loop plus sub-brain loops.
- Each loop executes `Observe -> Mutate -> Results`.
3. Memory model is spec-native only:
- Active Memory = RAM + ROM.
- LTM shared across brains in same agent.
- MemId is canonical identity across RAM/LTM with optional version.
4. Brain Tools are the only internal control plane:
- `memory.*`, `wait.for`, `talk.*`.
5. Queue-driven execution with bounded worker pools and explicit backpressure.

## Required Structural Changes
1. Replace orchestration model:
- Deprecate current plan/worker simulation path as runtime authority.
- Runtime loop becomes authoritative for goal handling and task progression.
2. Replace memory identity model:
- Remove numeric `MemoryID` public usage.
- Introduce MemId parser/formatter and versioned addressing.
3. Replace tool model for agent-internal actions:
- Brain Tools become explicit, typed, and validated.
- Generic tool invocation remains only for world tools.
4. Replace event handling:
- Add dedicated event bus for `User|Agent|Time|Hook` events.
- Wait semantics enforced by runtime state (including TalkId correlation).

## Implementation Phases

### Phase 1: Core Types and Runtime Skeleton
Files:
- `src/agent_runtime.zig` (new)
- `src/brain_context.zig` (new)
- `src/memid.zig` (new)
- `src/event_bus.zig` (new)

Deliverables:
1. `MemId` struct with parse/format/validate and optional version field.
2. `BrainContext` with explicit RAM, ROM, inbox/outbox, pending tool-use list.
3. `AgentRuntime` with loop scheduler and per-brain run queues.
4. `EventBus` with enqueue/dequeue/clear semantics and TalkId index support.

Acceptance:
- Runtime can create agent with primary + one sub-brain.
- One loop tick executes without invoking legacy orchestration code.
- MemId round-trip tests pass.

### Phase 2: Spec-Native Memory System
Files:
- `src/memory.zig` (rewrite)
- `src/ltm_store.zig` (rewrite interfaces around MemId/version)

Deliverables:
1. RAM store keyed by MemId, scoped per brain.
2. ROM store immutable from brain tools.
3. LTM store keyed by MemId base identity + versioned payload rows.
4. COW mutation rules for versioning.
5. `memory.search` backend primitives (keyword baseline; vector/tag extension points included in API).
6. `ActiveMemoryItem` struct matching the JSON contract.
7. Explicit serializer `toActiveMemoryJson(...)`.
8. ROM enforcement in mutation/eviction path.

Acceptance:
- `memory.create` issues unique MemId names under agent/sub-brain namespace.
- `memory.mutate` creates new LTM version when persisted.
- `memory.load` supports latest and historical version selection.
- Observe payload always includes `mem_id` for each memory item.

### Phase 3: Brain Tools Engine
Files:
- `src/brain_tools.zig` (new)
- `src/tool_registry.zig` (update schema/registration)
- `src/server_piai.zig` (wire runtime tool execution path)

Deliverables:
1. Implement full Brain Tool set:
- `memory.load`
- `memory.evict`
- `memory.mutate`
- `memory.create`
- `memory.search`
- `wait.for`
- `talk.user`
- `talk.agent`
- `talk.brain`
- `talk.log`
2. Implement strict argument validation and typed results.
3. Implement TalkId generator:
- Monotonic per brain, wraps, never emits `0`.
4. Enforce rule:
- `wait.for` requires at least one prior `talk.*` in same tool-use list.
5. Tight memory args:
- `memory.mutate` requires `mem_id`.
- `memory.evict` requires `mem_id`.
- `memory.load` takes `mem_id` plus optional paging fields.

Acceptance:
- Tool schemas are generated with exact required fields.
- Invalid calls return deterministic failures.
- `talk.* + wait.for` correlated flow works end-to-end.
- Memory tool responses echo canonical resolved `mem_id` and `version`.

### Phase 4: Loop Semantics and Result Materialization
Files:
- `src/agent_runtime.zig`
- `src/brain_context.zig`
- `src/memory.zig`

Deliverables:
1. Observe stage reads active memory snapshot and pending events.
2. Mutate stage executes ordered tool-use list sequentially.
3. Results stage writes tool outputs as memory artifacts and enqueues follow-up events.
4. Eviction stores artifacts to LTM and returns MemId handles.
5. End-of-loop durable sync checkpoint for memory/event consistency.
6. Observe stage builds LLM context from structured active-memory JSON entries only.

Acceptance:
- Multiple ticks maintain coherent brain-local RAM.
- Tool results become queryable memory entries.
- Evicted memory can be reloaded from LTM by MemId.
- No text-only anonymous memory representation is exposed to the brain.

### Phase 5: Server Integration (Clean Protocol Contract)
Files:
- `src/server_piai.zig`
- `src/protocol.zig`

Deliverables:
1. Replace request handling path to dispatch into `AgentRuntime`.
2. Define runtime-native message contract (clean break from legacy assumptions).
3. Keep only message types needed by runtime model (connect/session/chat/control/progress/state/memory/tool events).
4. Remove legacy code paths tied to old orchestration or compatibility framing.

Acceptance:
- User message enters runtime as `User` event and produces agent output via loop.
- Agent control commands map to runtime lifecycle actions.
- Heartbeat/progress emitted from runtime state, not legacy worker counters.

### Phase 6: Concurrency and Backpressure Hardening
Files:
- `src/agent_runtime.zig`
- `src/server_piai.zig`
- `src/config.zig` (if runtime knobs are externalized)

Deliverables:
1. Bounded queues for:
- inbound requests
- brain ticks
- outbound messages
- control events
2. Fixed worker pools for runtime execution.
3. Overload handling with immediate explicit failures (no hanging).
4. Timeouts standardized by operation class.

Acceptance:
- Queue saturation returns overload response quickly.
- Main thread remains non-blocking for external I/O.
- Runtime remains responsive under concurrent session load.

## Public API / Interface Changes
1. New core types:
- `MemId`
- `TalkId`
- `Event`, `EventType`
- `BrainContext`, `AgentRuntime`
2. New storage contract:
- Versioned memory retrieval and mutation by MemId.
3. New tool contract:
- Brain Tools are typed first-class runtime APIs.
4. Protocol contract:
- Clean message model aligned to runtime, with no legacy compatibility layer.

## Test Plan
Unit tests:
1. MemId format/parse/invalid cases.
2. Memory tier rules (RAM/ROM/LTM) and versioning semantics.
3. Active-memory serialization includes `mem_id` for every RAM/ROM entry.
4. Brain tool validation and success/failure paths.
5. Event bus matching, TalkId correlation, clear-on-consume behavior.
6. Loop stage transitions and tool result persistence.

Integration tests:
1. User message triggers primary brain loop and user-visible response.
2. `talk.agent` between brains with matching `wait.for`.
3. Memory lifecycle:
- create -> mutate -> evict -> load historical version.
4. Queue pressure behavior and bounded processing.
5. Agent control actions (pause/resume/cancel/state) at runtime level.
6. Brain mutates/evicts by `mem_id` observed in prior active-memory payload.
7. ROM mutation and ROM eviction are rejected deterministically.

Load/stability checks:
1. Multi-session concurrent loops.
2. Repeated wait/time events without deadlock.
3. Sustained memory churn with eviction and reload cycles.

## Defaults and Assumptions
1. The runtime contract is authoritative; no compatibility obligations.
2. LTM uses SQLite as current persistence backend, but with rewritten schema/API centered on MemId.
3. Vector/tag search are API-visible but can initially use keyword fallback until dedicated index implementation lands.
4. Brain loops are deterministic per tool-use-list order, with no parallel execution inside a single list.
5. Sub-brains are independent loop actors that only coordinate via events + shared LTM.
6. Active Memory JSON is the sole brain-facing representation and always includes canonical `mem_id`.
