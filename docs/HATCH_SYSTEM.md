# HATCH.md System

The HATCH.md system provides a **birth certificate** pattern for new agents in ZiggySpiderweb, inspired by OpenClaw's BOOTSTRAP.md.

## Overview

When a new agent is created, it receives a `HATCH.md` file containing instructions for establishing its identity. The agent reads this file, creates its identity files (SOUL.md, etc.), then deletes HATCH.md — just like a birth certificate that's filed away after use.

## First Boot Flow (Server-Driven)

When the server starts with **no agents directory**, it enters **first-boot mode**:

```
Client sends: {"type":"chat.send","content":""}
                 ↓
Server responds: {"type":"session.receive","content":"Welcome to ZiggySpiderweb! ... What would you like to name your first agent?"}
                 ↓
Client sends: {"type":"chat.send","content":"ziggy"}
                 ↓
Server creates: agents/ziggy/HATCH.md
                 ↓
Server responds: {"type":"session.receive","content":"Perfect! I've created your first agent... (HATCH.md content)", "agent_id":"ziggy", "needs_hatching":true}
                 ↓
[Agent reads HATCH.md and creates identity files]
                 ↓
Client sends: {"type":"agent.hatch","agent_id":"ziggy"}
                 ↓
Server sends: {"type":"agent.hatched","agent_id":"ziggy","success":true}
```

The **server drives the first-boot flow** — the client is just a terminal that displays messages and collects user input. The agent must still complete the normal hatch flow by sending `agent.hatch`.

### First Boot Protocol

**Empty message (or any message) triggers first-boot welcome:**
```json
{"type":"chat.send","content":""}
```

**Server asks for agent name:**
```json
{
  "type": "session.receive",
  "role": "assistant",
  "content": "Welcome to ZiggySpiderweb! 🕸️\n\nThis appears to be your first time here..."
}
```

**User provides name:**
```json
{"type":"chat.send","content":"my-agent-name"}
```

**Server creates agent and presents HATCH.md:**
```json
{
  "type": "session.receive",
  "role": "assistant",
  "content": "Perfect! I've created your first agent... (includes HATCH.md content)",
  "agent_id": "my-agent-name",
  "needs_hatching": true
}
```

**Agent completes hatching:**
```json
// Client sends after agent creates identity files
{"type":"agent.hatch","agent_id":"my-agent-name"}

// Server responds
{"type":"agent.hatched","agent_id":"my-agent-name","success":true}
```

## Regular Agent Creation Flow

After first boot, create additional agents:

```json
{"type":"agent.create","agent_id":"my-new-agent","template":"path/to/custom/template.md"}
```

Response:
```json
{"type":"agent.created","agent_id":"my-new-agent","needs_hatching":true}
```

This creates:
```
agents/my-new-agent/
  HATCH.md    ← Birth certificate with instructions
```

## Agent Lists with `needs_hatching` Flag

```json
{"type":"agent.list"}
```

Response includes:
```json
{
  "type": "agent.list.response",
  "agents": [
    {
      "id": "my-new-agent",
      "name": "my-new-agent",
      "needs_hatching": true
    }
  ]
}
```

## Reading HATCH.md

When an agent connects that has `needs_hatching: true`, the client should:
1. Read the HATCH.md content (via file tool or direct read)
2. Present it as the initial prompt
3. The AI creates identity files based on instructions

## Completing Hatching

When the agent has created its identity:

```json
{"type":"agent.hatch","agent_id":"my-new-agent"}
```

Response:
```json
{"type":"agent.hatched","agent_id":"my-new-agent","success":true}
```

This deletes `HATCH.md` and updates the agent's `needs_hatching` flag to `false`.

## HATCH.md Template

The default template (in `agents/HATCH.template.md`) includes:

1. **Welcome message** — Context about ZSS
2. **Identity creation steps** — How to write SOUL.md
3. **Optional files** — AGENT.md, agent.json
4. **Hatch protocol** — JSON response format
5. **Key reminders** — Memory rules, Text > Brain

## Custom Templates

Pass a custom template path when creating:

```json
{
  "type": "agent.create",
  "agent_id": "specialized-agent",
  "template": "templates/coder-agent-hatch.md"
}
```

## Protocol Messages

| Message | Direction | Description |
|---------|-----------|-------------|
| `chat.send` | Client → Server | Triggers first-boot if no agents exist |
| `session.receive` | Server → Client | First-boot prompts and HATCH.md content |
| `agent.create` | Client → Server | Create new agent with HATCH.md |
| `agent.created` | Server → Client | Confirm creation, indicates `needs_hatching` |
| `agent.hatch` | Client → Server | Signal hatching complete |
| `agent.hatched` | Server → Client | Confirm HATCH.md deleted |
| `agent.list` | Client → Server | List all agents (includes `needs_hatching`) |
| `agent.get` | Client → Server | Get agent info (includes `needs_hatching`) |

## Design Philosophy

- **Server-driven first boot**: The server handles all first-boot logic, clients just display messages
- **Birth certificate pattern**: Like OpenClaw's BOOTSTRAP.md, HATCH.md is read once then discarded
- **Self-identity**: Agents choose their own name and personality
- **Continuity through files**: The created SOUL.md/AGENT.md become the agent's persistent identity
- **No orphan agents**: Every agent must go through hatching to establish identity
