# Example Agent Configurations

This directory contains example agent configurations showing how to use per-brain provider/model settings.

## Examples

### 1. Fast Primary (`fast-primary/`)

Uses `gpt-5.3-codex-spark` for fast, responsive chat interface.

**Key settings:**
- Provider: `openai`
- Model: `gpt-5.3-codex-spark` (fast, cheap)
- Think level: `low` (quick responses)
- Can spawn sub-brains: Yes

**Use case:** Primary chat interface that feels snappy and responsive.

### 2. Deep Thinker (`deep-thinker/`)

Uses full `gpt-5.3-codex` for complex problem solving.

**Key settings:**
- Provider: `openai-codex`
- Model: `gpt-5.3-codex` (powerful, reasoning)
- Think level: `high` (thorough analysis)
- Can spawn sub-brains: Yes

**Use case:** Spawned by primary brain for hard coding tasks, architecture decisions, debugging.

### 3. Memory Keeper (`memory-keeper/`)

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
# 1. Create your agent directory
mkdir -p agents/ziggy/deep-thinker
mkdir -p agents/ziggy/memory-keeper

# 2. Copy example configs
cp agents/identities/examples/fast-primary/* agents/ziggy/
cp agents/identities/examples/deep-thinker/* agents/ziggy/deep-thinker/
cp agents/identities/examples/memory-keeper/* agents/ziggy/memory-keeper/

# 3. Customize as needed
vim agents/ziggy/agent.json
vim agents/ziggy/SOUL.md
vim agents/ziggy/deep-thinker/agent.json
```

### Directory structure:

```
agents/
└── ziggy/                    # Agent ID
    ├── SOUL.md               # Core identity (hatched into LTM)
    ├── AGENT.md              # How you work (hatched into LTM)
    ├── IDENTITY.md           # Public persona (hatched into LTM)
    ├── agent.json            # Primary brain config
    │
    ├── deep-thinker/         # Sub-brain directory
    │   ├── SOUL.md
    │   ├── AGENT.md
    │   ├── IDENTITY.md
    │   └── agent.json        # Sub-brain config with different model
    │
    └── memory-keeper/        # Another sub-brain
        ├── SOUL.md
        ├── AGENT.md
        ├── IDENTITY.md
        └── agent.json
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

1. **Runtime loads** the default provider config (from spiderweb config)
2. **Checks** `agent.json` for brain-specific overrides
3. **Applies** per-brain provider/model/think settings
4. **Streams** to the appropriate AI provider

This lets you use fast/cheap models for simple work and powerful models for hard problems, all in the same agent.
