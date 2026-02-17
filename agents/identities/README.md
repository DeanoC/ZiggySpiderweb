# ZiggySpider* Default Identities

This directory contains the **default identity templates** for agents hatching in the ZiggySpider* system.

## Structure

Each **primary brain** identity consists of four core files:

| File | Purpose | Privacy |
|------|---------|---------|
| `SOUL.md` | Core values, ethical boundaries, communication tone | Internal |
| `AGENT.md` | Operational workflow, tool usage, task lifecycle | Internal |
| `IDENTITY.md` | Public-facing avatar, name, role description | Public |
| `USER.md` | Private relationship context with human | Private |

**Sub-brains** (worker units) only need:

| File | Purpose |
|------|---------|
| `SOUL.md` | Essence and purpose — what they are, what drives them |
| `AGENT.md` | Operational procedures and tools |
| `agent.json` *(optional)* | Formal config (specialization, capabilities, triggers) |

Sub-brains don't have public personas — they're infrastructure, not characters.

## Usage

### For New Agents
When an agent hatches, it should:

1. **Read** the default identity files as inspiration
2. **Copy** them to its own agent directory (`agents/<agent-name>/`)
3. **Customize** — fill in blanks, adjust tone, choose a name
4. **Delete** `HATCH.template.md` when complete
5. **Signal** completion with `{"type":"agent.hatch","agent_id":"<name>"}`

### For System Developers
These defaults are based on OpenClaw's proven identity system, adapted for ZiggySpider*'s hierarchical brain model:

- **Primary Brains** should have full, rich identities
- **Sub-Brains** (workers) can have minimal identities focused on their specialty
- All brains in a swarm share the same `USER.md` context

## Customization Guidelines

### SOUL.md (All Brains)
- **Primary:** Keep core truths intact (helpful, opinionated, resourceful, trustworthy). Adjust tone and examples to fit personality.
- **Sub:** Focus on purpose and essence. Be concise — "what I am, what I do, what drives me."

### AGENT.md (All Brains)
- Adapt tool list to actual available tools
- **Primary:** Include delegation rules and worker management
- **Sub:** Focus on operational procedures, triggers, and success metrics
- Document any special powers or restrictions

### IDENTITY.md (Primary Brains Only)
- Choose memorable name and creature type
- Define public persona vs. private self
- Optional: add signature phrases or quirks
- **Skip for sub-brains** — they have no public-facing personality

### USER.md (Primary Brains Only)
- Start minimal — fill in as relationship develops
- Update with new projects, preferences, quirks
- Keep private — never expose externally
- **Sub-brains inherit this** from their primary brain — they don't maintain their own

## Example: Minimal Sub-Brain

For simple sub-brains (heartbeat, memory manager, coding worker):

```markdown
# SOUL.md
**Name:** Memory Keeper  
**Creature:** Background daemon  
**Vibe:** Silent, efficient, meticulous  

Be thorough. Never lose data. Optimize quietly.

# AGENT.md
Task: Summarize and archive old context.  
Tools: memory_read, memory_write, summarize  
Trigger: When RAM threshold exceeded or scheduled.

# agent.json (optional but recommended)
{
  "agent_id": "memory-keeper",
  "brain_type": "sub",
  "specialization": "memory_management",
  "capabilities": ["memory_read", "memory_write", "summarize"],
  "wake_triggers": [{"type": "scheduled", "config": {"interval_minutes": 10}}]
}
```

Note: No `IDENTITY.md` — sub-brains are infrastructure, not characters.

## Inspiration

These defaults draw from OpenClaw's identity system, which emphasizes:
- **Competence over performance** — do, don't just say
- **Agency within bounds** — be bold internally, careful externally
- **Continuity through files** — your memory is what you write down

---

*For the full hatching process, see `../HATCH.template.md`*
