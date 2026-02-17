# Example Agent Configurations

This directory contains example `agent.json` configurations showing how to use per-brain provider/model settings.

## Architecture Overview

With the hatch system, identity is separated from configuration:

- **`templates/`** — Identity files (SOUL.md, AGENT.md, IDENTITY.md) hatched into LTM
- **`agents/{agent_id}/`** — Per-brain configuration (agent.json only)

## Examples

### 1. Fast Primary (`fast-primary/agent.json`)

Uses `gpt-5.3-codex-spark` for fast, responsive chat interface.

**Key settings:**
- Provider: `openai`
- Model: `gpt-5.3-codex-spark` (fast, cheap)
- Think level: `low` (quick responses)
- Can spawn sub-brains: Yes

**Use case:** Primary chat interface that feels snappy and responsive.

### 2. Deep Thinker (`deep-thinker/agent.json`)

Uses full `gpt-5.3-codex` for complex problem solving.

**Key settings:**
- Provider: `openai-codex`
- Model: `gpt-5.3-codex` (powerful, reasoning)
- Think level: `high` (thorough analysis)
- Can spawn sub-brains: Yes

**Use case:** Spawned by primary brain for hard coding tasks, architecture decisions, debugging.

### 3. Memory Keeper (`memory-keeper/agent.json`)

Uses `gpt-4o-mini` for lightweight background memory maintenance.

**Key settings:**
- Provider: `openai`
- Model: `gpt-4o-mini` (cheap, fast enough for simple tasks)
- Think level: `low`
- Can spawn sub-brains: No
- Denied tools: `talk.user` (can't talk to user directly)

**Use case:** Background daemon for memory summarization, cleanup, organization.

## How to Use

### Setting up your first agent:

```bash
# 1. Create your agent directory structure
mkdir -p agents/ziggy/deep-thinker

# 2. Copy example agent.json configs
# (Identity comes from templates/, only config goes in agents/)
cp agents/identities/examples/fast-primary/agent.json agents/ziggy/
cp agents/identities/examples/deep-thinker/agent.json agents/ziggy/deep-thinker/

# 3. Customize agent.json as needed
vim agents/ziggy/agent.json
vim agents/ziggy/deep-thinker/agent.json
```

### Directory structure:

```
agents/
└── ziggy/                    # Agent ID
    └── agent.json            # Primary brain config (provider, model, tools)
    │
    └── deep-thinker/         # Sub-brain directory
        └── agent.json        # Sub-brain config (different provider/model)

templates/
├── SOUL.md                   # Identity hatched into LTM for all agents
├── AGENT.md                  # How you work (hatched into LTM)
├── IDENTITY.md               # Public persona (hatched into LTM)
├── JUST_HATCHED.md           # Welcome message for new agents
└── BOOTSTRAP.md              # Welcome message for first agent
```

### agent.json fields:

```json
{
  "name": "Display name",
  "specialization": "Role description",
  
  // Provider configuration (per-brain override)
  "provider": {
    "name": "openai|openai-codex|kimi-coding",
    "model": "gpt-5.3-codex-spark|gpt-5.3-codex|k2p5|...",
    "think_level": "low|medium|high"
  },
  
  // Alternative shorthand syntax:
  "provider": "openai-codex",
  "model": "gpt-5.3-codex",
  "think_level": "high",
  
  // Tool restrictions
  "can_spawn_subbrains": true|false,
  "allowed_tools": ["memory.create", "talk.brain", ...],
  "denied_tools": ["talk.user"],
  
  // Capabilities list
  "capabilities": ["chat", "tools", "spawn_subbrains"]
}
```

## Provider/Model Combinations

| Brain Type | Provider | Model | Use Case |
|------------|----------|-------|----------|
| Fast interface | `openai` | `gpt-5.3-codex-spark` | Quick responses |
| Deep work | `openai-codex` | `gpt-5.3-codex` | Complex tasks |
| Balanced | `openai` | `gpt-4.1-mini` | Good default |
| Cheap/simple | `openai` | `gpt-4o-mini` | Background tasks |
| Coding (alt) | `kimi-coding` | `k2p5` | Kimi models |

## How It Works

When a brain processes a message:

1. **Hatch** — On first boot, identity files from `templates/` are loaded into LTM
2. **Runtime loads** the default provider config (from spiderweb config)
3. **Checks** `agent.json` for brain-specific overrides
4. **Applies** per-brain provider/model/think settings
5. **Streams** to the appropriate AI provider

This lets you use fast/cheap models for simple work and powerful models for hard problems, all in the same agent, while sharing a common identity from templates/.

## Customizing Identity

To customize identity for all agents, edit files in `templates/`:
- `templates/SOUL.md` — Core values and personality
- `templates/AGENT.md` — How the agent works
- `templates/IDENTITY.md` — Public persona

These are hatched into LTM and become the agent's persistent identity.
