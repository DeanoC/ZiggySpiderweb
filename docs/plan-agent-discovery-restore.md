# Implementation Plan: Agent Discovery and Session Restore

**Issue:** [#9 - Agent discovery and restore](https://github.com/DeanoC/ZiggySpiderweb/issues/9)

## Overview
Enable clients to discover available agents, identify the default agent, and restore their last active chat session to continue where they left off.

---

## Phase 1: Agent Registry and Discovery (MVP)

### 1.1 Agent Registry Service
**File:** `src/agent_registry.zig` (new)

```zig
const AgentInfo = struct {
    id: []const u8,
    name: []const u8,
    description: []const u8,
    is_default: bool,
    capabilities: []const []const u8, // ["chat", "code", "plan"]
    identity_loaded: bool, // SOUL.md, AGENT.md, etc. present
};

const AgentRegistry = struct {
    // Scan agents/ directory for subdirectories
    // Each subdirectory = one agent
    // Load agent.json or parse from identity files
};
```

**Behavior:**
- Scan `./agents/` directory at startup
- Each subdirectory = one agent
- Read `agent.json` if present, or infer from identity files
- Mark first agent as default if no default specified

### 1.2 Agent Discovery Protocol
**New message types:**

```json
// Client -> Server
{"type": "agent.list"}

// Server -> Client
{
  "type": "agent.list.response",
  "agents": [
    {"id": "default", "name": "Assistant", "is_default": true, ...},
    {"id": "coder", "name": "Code Expert", "is_default": false, ...}
  ]
}
```

```json
// Client -> Server
{"type": "agent.get", "agent_id": "coder"}

// Server -> Client
{
  "type": "agent.info",
  "agent": {"id": "coder", "name": "Code Expert", ...}
}
```

---

## Phase 2: Session Persistence for Restore

### 2.1 Session Metadata Storage
**Extend:** `src/ltm_store.zig`

Add table: `session_metadata`
```sql
CREATE TABLE session_metadata (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    last_active_ms INTEGER NOT NULL,
    message_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true
);
```

**Behavior:**
- Update `last_active_ms` on every message
- Mark session inactive after 24h of inactivity (configurable)
- Keep last N sessions per agent (configurable, default 10)

### 2.2 Last Session Query
**New protocol:**

```json
// Client -> Server
{"type": "session.restore", "agent_id": "default"}

// Server -> Client
{
  "type": "session.restore.response",
  "found": true,
  "session": {
    "session_key": "abc123...",
    "agent_id": "default",
    "last_active": "2026-02-15T12:00:00Z",
    "message_count": 42,
    "summary": "Discussion about API design..."
  }
}
```

**Server logic:**
1. Look up most recent active session for agent_id
2. Return session_key if found
3. Client uses session_key to connect with `?session=abc123...`

---

## Phase 3: Session Summary for UI

### 3.1 Generate Session Summary
**Extend:** LTM store or new `src/session_summary.zig`

When session is archived/summarized:
- Use LLM to generate 1-sentence summary
- Store in session_metadata.summary
- Used by client to show "Continue: API design discussion..."

### 3.2 List Recent Sessions
**New protocol:**

```json
// Client -> Server
{"type": "session.history", "agent_id": "default", "limit": 5}

// Server -> Client
{
  "type": "session.history.response",
  "sessions": [
    {"session_key": "abc...", "summary": "API design", "last_active": "..."},
    {"session_key": "def...", "summary": "Bug fix planning", "last_active": "..."}
  ]
}
```

---

## Phase 4: Client Integration

### 4.1 ZSS CLI Changes
**New commands:**
```bash
# List agents
zss agents list

# Switch agent
zss agent use coder

# Restore last session (auto on connect)
zss chat restore

# List recent sessions
zss session history --limit 5
```

### 4.2 ZSS-GUI Changes
**New UI:**
- Agent picker dropdown (populated from `agent.list`)
- "Continue last chat" button on connect
- Session history sidebar showing recent sessions with summaries

---

## Implementation Order

1. **Week 1:** Agent registry + `agent.list` protocol
2. **Week 2:** Session metadata table + `session.restore`
3. **Week 3:** Session summary generation + `session.history`
4. **Week 4:** ZSS CLI integration
5. **Week 5:** ZSS-GUI integration

---

## Protocol Summary

| Message | Direction | Purpose |
|---------|-----------|---------|
| `agent.list` | C→S | Get all agents |
| `agent.list.response` | S→C | Agent list |
| `agent.get` | C→S | Get specific agent |
| `agent.info` | S→C | Agent details |
| `session.restore` | C→S | Find last session |
| `session.restore.response` | S→C | Session key or not found |
| `session.history` | C→S | List recent sessions |
| `session.history.response` | S→C | Session list with summaries |

---

## Files to Modify/Create

**New:**
- `src/agent_registry.zig`
- `src/session_summary.zig` (optional, can use existing LTM)

**Modify:**
- `src/server_piai.zig` - Add protocol handlers
- `src/ltm_store.zig` - Add session_metadata table
- `src/protocol.zig` - Add new message types

**Client (separate repos):**
- `ZiggyStarSpider/src/cli/` - New commands
- `ZiggyStarSpider-gui/src/gui/` - Agent picker, session restore UI

---

## Success Criteria

- [x] Client can list available agents
- [x] Client can identify default agent
- [x] Client can restore last active session
- [x] Session history shows summaries
- [x] Works across client reconnects
- [ ] Sessions properly archived after timeout
