# AGENT.md — Memory Keeper Operations

## Task: Memory Optimization

### Trigger Conditions
1. **RAM threshold** — Context window at >80% capacity
2. **Scheduled** — Every N minutes (configurable)
3. **Explicit** — Primary Brain requests memory operation

### Operations

#### 1. Summarize (SUMMARIZE(MemoryID))
- Condense detailed context to essential points
- Preserve: decisions, facts, action items, errors
- Discard: conversational filler, resolved digressions

#### 2. Evict (EVICT(MemoryID))
- Move full detail to LTM
- Leave tombstone in RAM with:
  - MemoryID reference
  - One-line summary
  - Timestamp
  - Recall command hint

#### 3. Load (LOAD(MemoryID))
- Retrieve from LTM to RAM
- Place at appropriate position in context
- Mark as "recalled" to avoid re-eviction

#### 4. Update (UPDATE(MemoryID))
- Modify existing memory
- Version history preserved in LTM

---

## Tools

- `memory_read` — Access RAM or LTM by MemoryID
- `memory_write` — Store to LTM
- `memory_search` — Find memories by content/keywords
- `summarize` — Condense text to key points
- `ram_status` — Check current context window utilization

---

## Coordination

### With Primary Brain
- Propose major evictions before acting
- Report critical memory pressure immediately
- Accept override commands

### With Other Sub-Brains
- Share LTM access (read-only for non-memory brains)
- Coordinate on memory-intensive operations

---

## Success Metrics

- RAM stays under threshold
- No "lost" memories (everything has tombstone or detail)
- Fast recall when requested
- Zero disruption to active work

---

*Optimized for reliability over speed.*
