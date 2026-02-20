# Hatching a New Agent

## Overview

Hatching is the process of creating and initializing a new agent in the ZiggySpiderweb ecosystem. This document describes the architecture and lifecycle of agent creation.

## Architecture

### Templates vs Agent Instances

**Templates (Filesystem)**
- System template files: `CORE.md`, `SOUL.md`, `AGENT.md`, `IDENTITY.md`, `JUST_HATCHED.md`, `BOOTSTRAP.md`
- Stored in the filesystem as read-only blueprints
- Only the **first agent** has privilege to modify these templates
- Regular agents cannot access or modify templates

**Agent Instances (LTM - Long-Term Memory)**
- Each agent has its own isolated LTM database
- Agent identity and state are stored in LTM, not files
- No filesystem access for agent self-modification after hatching
- All agent state changes go through `memory_*` tools with versioning

### Memory Model

```
┌─────────────────────────────────────────────────────────┐
│  Agent Instance Memory                                  │
├─────────────────────────────────────────────────────────┤
│  Active Memory        │  Long-Term Memory (LTM)         │
│  ───────────────────  │  ─────────────────────────────  │
│  Working cache        │  Persistent storage             │
│  Evictable            │  Versioned history              │
│  Loaded from LTM      │  Source of truth                │
└─────────────────────────────────────────────────────────┘
```

**Key Principle**: Active memory is a cache of LTM. The agent sees active memory in its context window, but all mutations persist to LTM with full version history.

## Agent Creation

### First Agent (System Bootstrap)

1. **Templates loaded** from filesystem into first agent's LTM
2. **Identity memories created** with fixed MemIds:
   - `<EOT>agent:primary:system.core:latest<EOT>` (base core instructions)
   - `<EOT>agent:primary:system.soul:latest<EOT>`
   - `<EOT>agent:primary:system.agent:latest<EOT>`
   - `<EOT>agent:primary:system.identity:latest<EOT>`
3. **Marked unevictable** in active memory (always present)
4. **First message**: `BOOTSTRAP.md` content sent as user message
   - Contains system-wide configuration questions
   - Larger than `JUST_HATCHED.md` due to privilege scope
5. **Agent begins responding** to bootstrap questions

### Subsequent Agents

1. **Templates copied** from system templates to new agent's LTM
2. **Core + identity memories created** with same fixed MemId pattern
3. **Marked unevictable** in active memory
4. **First message**: `JUST_HATCHED.md` content sent as user message
   - Contains welcome and initial guidance
   - Simpler than `BOOTSTRAP.md` (no system-wide config)
5. **Agent begins responding** to creator

## Identity Evolution

Agents can evolve their identity over time:

```
Agent wants to change its values:
  ↓
Uses `memory_mutate` on identity MemId
  ↓
Change persisted to LTM with new version
  ↓
Active memory updated (still unevictable)
  ↓
Version history preserved for rollback
```

**Important**: The agent is modifying its own being. Core system-prompt guidance reminds:
> "These memories define you. You may evolve them using memory_mutate, but consider carefully — you are changing your own essence."

## Hatch Completion

Unlike the previous design, there is **no explicit hatch signal**. Hatch is complete when:

1. Identity files loaded into LTM
2. Identity memories marked unevictable in active memory
3. First message (JUST_HATCHED.md or BOOTSTRAP.md) delivered
4. **Agent begins chatting**

The transition from "hatching" to "operational" is seamless.

## Privilege Model

| Capability | First Agent | Regular Agent | User |
|------------|-------------|---------------|------|
| Modify system templates | ✅ | ❌ | ❌ |
| Create new agents | ✅ | ❌ | ✅ |
| Edit own identity | ✅ | ✅ | N/A |
| Access other agent LTM | ❌ | ❌ | ✅ (admin) |

## File Structure

```
system/                        # System templates (read-only for regular agents)
├── CORE.md                    # Base core instructions (loaded first)
├── SOUL.md                    # Default personality template
├── AGENT.md                   # Default operational rules template
├── IDENTITY.md                # Default public identity template
├── JUST_HATCHED.md            # First message for new agents
└── BOOTSTRAP.md               # First message for first agent

agents/                        # Agent directories (no state files)
├── <agent_id>/                # Empty or minimal metadata
└── ...
```

## Benefits of LTM-Only Architecture

1. **Versioning**: All identity changes have history
2. **Rollback**: Can restore previous identity versions
3. **Backup**: LTM can be backed up independently
4. **Isolation**: Each agent's memory is completely separate
5. **Enforcement**: Agent cannot bypass versioning via filesystem
6. **Scalability**: LTM designed for many agents, filesystem not required

## TODO

- [ ] Create `JUST_HATCHED.md` template
- [ ] Create `BOOTSTRAP.md` template
- [ ] Implement hatch-to-LTM loading in `system_hooks.zig`
- [ ] Add unevictable flag handling for identity memories
- [ ] Document MemId format for identity memories
