# Sub-Brain Templates

Sub-brain templates in `templates/sub-brains/` define reusable specialist configurations.

## Available Templates

### `coder.json` - Code Specialist
**Default:** openai-codex/gpt-5.3-codex

Capabilities: code generation, review, debugging, architecture

ROM entries:
- `system:coding_guidelines` - Clean code principles
- `system:language_preferences` - Language selection guidance  
- `system:testing_requirements` - Testing standards

### `memory-keeper.json` - Memory Daemon
**Default:** openai/gpt-4o-mini

Capabilities: memory optimization, summarization, archival

ROM entries:
- `system:memory_policy` - When to summarize/archive
- `system:summarization_rules` - What to preserve

### `writer.json` - Content Creator
**Default:** openai/gpt-4.1-mini

Capabilities: docs, technical writing, editing

ROM entries:
- `system:writing_style` - Voice and style guide
- `system:documentation_standards` - Doc formatting

### `researcher.json` - Knowledge Seeker
**Default:** openai-codex/gpt-5.3-codex

Capabilities: web search, synthesis, fact-checking

ROM entries:
- `system:research_method` - Verification approach
- `system:analysis_framework` - Analysis patterns

## Template Structure

```json
{
  "name": "Human-readable name",
  "specialization": "Role description",
  "default_provider": {
    "name": "provider",
    "model": "model-id",
    "think_level": "low|medium|high"
  },
  "capabilities": ["skill1", "skill2"],
  "rom_entries": [
    {"key": "system:xxx", "value": "Guidance text"}
  ],
  "allowed_tools": ["tool.*"],
  "denied_tools": ["talk.user"],
  "can_spawn_subbrains": false
}
```

## Using Templates

In your agent config:

```json
{
  "agent_id": "my-agent",
  "primary": { ... },
  "sub_brains": {
    "my-coder": {
      "template": "coder",
      "provider": {
        "model": "gpt-5.3-codex"
      },
      "rom_overrides": [
        {"key": "system:project_preferences", "value": "Project-specific prefs"}
      ]
    }
  }
}
```

### Override Rules

1. **`provider`** - Override any provider field (name, model, think_level)
2. **`rom_overrides`** - Add/replace ROM entries (merged with template)
3. **`allowed_tools`** - Full replacement (not merged)
4. **`denied_tools`** - Full replacement (not merged)
5. **`can_spawn_subbrains`** - Override boolean

If no template specified, define everything inline:

```json
{
  "sub_brains": {
    "custom-brain": {
      "provider": { "name": "openai", "model": "gpt-4o" },
      "capabilities": ["chat"],
      "allowed_tools": ["talk.user"]
    }
  }
}
```

## Creating New Templates

1. Copy an existing template
2. Modify name, specialization, capabilities
3. Add relevant `rom_entries` for context
4. Set appropriate default provider
5. Save to `templates/sub-brains/{name}.json`
