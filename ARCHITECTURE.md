# Spiderweb Architecture Principles

> Core design principles for ZiggySpiderweb development.

## 1. Never Block the Main Thread

The main thread must never perform I/O that could block indefinitely.

- **Accept connections immediately** - spawn a thread per connection
- **Never `await` external services** on the main thread (DB, AI APIs, etc.)
- **Use timeouts everywhere** - default 30s for AI, 5s for internal ops
- **Fail fast** - if a resource isn't available, return error immediately

## 2. Queue Everything

All work goes through queues. No direct execution.

```
Request → Queue → Worker Pool → Response
```

- **Incoming connections**: TCP accept queue
- **AI requests**: Job queue with priority
- **Outgoing WebSocket messages**: Send queue per connection
- **Config reloads**: Control queue

## 3. Worker Pool Pattern

Fixed-size worker pools process queues. Never spawn unlimited threads.

- **Connection workers**: Handle WebSocket lifecycle
- **AI workers**: Process Pi AI requests (configurable concurrency)
- **IO workers**: File system, config, logging operations

## 4. Backpressure & Flow Control

When queues fill up, apply backpressure rather than drop or block.

- **Queue limits**: Bounded channels with explicit capacity
- **Rate limiting**: Per-client and global rate limits
- **Graceful degradation**: Return 503 when overloaded, never hang

## 5. Stateless Core

The core server is stateless. All state is external.

- **No in-memory sessions** - use external session store if needed
- **Config reloadable** - SIGHUP reloads without restart
- **Horizontal ready** - design for multiple instances behind load balancer

## 6. Structured Logging

Every significant event is logged with context.

- **Request ID propagation** - trace requests across queues
- **Structured JSON logs** - machine parseable
- **Log levels**: debug (dev), info (default), warn (issues), error (failures)

## 7. Graceful Shutdown

Clean shutdown on SIGTERM with draining.

1. Stop accepting new connections
2. Drain job queues (with timeout)
3. Close active connections gracefully
4. Exit cleanly

## Implementation Guidelines

### Adding a New Feature

1. **Define the job type** - what work needs to be done?
2. **Create a queue** - bounded channel for the job type
3. **Spawn worker pool** - fixed number of workers
4. **Add metrics** - queue depth, processing time, errors
5. **Document in this file** - update principles if needed

### Code Patterns

**Good - Queued AI Request:**
```zig
// Main thread: enqueue and return immediately
const job = AiJob{ .request = request, .response_queue = response_q };
try ai_queue.send(job);

// Worker thread: process
while (ai_queue.pop()) |job| {
    const response = processAiRequest(job.request);
    job.response_queue.send(response);
}
```

**Bad - Blocking Main Thread:**
```zig
// DON'T DO THIS
const response = try http_client.fetch(url); // Blocks!
```

## Consequences

Following these principles means:

- ✅ Predictable latency - no surprise stalls
- ✅ Resilient to slow clients - can't hog resources
- ✅ Observable - queues expose system health
- ✅ Testable - workers are isolated units
- ⚠️ More complex - queues add indirection
- ⚠️ Higher memory use - queued items need space

## References

- [C10K Problem](http://www.kegel.com/c10k.html) - Why non-blocking matters
- [The Tail at Scale](https://research.google/pubs/pub40801/) - Why queues help
- [Zig Concurrency Patterns](https://ziglang.org/documentation/master/) - Async/await in Zig

---

*Update this doc when adding new architectural patterns. Keep it the source of truth for Spiderweb design decisions.*

## Vision: Project-Oriented Assistant

Beyond a simple chat gateway, Spiderweb is an **agent runtime** where autonomous agents work on user projects with pro-active, hierarchical agency.

### Three-Layer Agency Model

```
User (sets goals, gives direction)
    ↓
PM/Planner Agent (orchestrates, manages project state)
    ├── Breaks goals into tasks
    ├── Spawns workers for execution
    ├── Handles blockers (speculates, plans ahead)
    └── Reports progress to user
        ↓
Workers (execute tasks, report back)
    ├── Implementation workers
    ├── Research workers  
    └── Background workers (heartbeats, crons)
```

### Key Behaviors

**User-First, Not Task-First**
- Chat is the primary interface - user always knows what's happening
- Agents work *toward* user goals, not autonomously *around* them
- Pro-active suggestions happen in chat, not silently

**Pro-Active When Blocked**
- If current tasks are blocked (CI red, waiting on PR), PM can:
  - Add speculative work that fits the project
  - Research related topics
  - Update documentation
  - Plan future phases
- User sees "I couldn't do X, so I started Y which helps with Z"

**Hierarchical Task Management**
- Projects contain goals
- Goals break into tasks
- Tasks spawn workers
- Dependencies tracked, workers run in parallel when possible

### Memory Model (Session vs Context vs Memory)

Lessons from MindSwarm: separate three concepts OpenClaw conflates:

| Concept | Purpose | Persistence |
|---------|---------|-------------|
| **Current Chat** | Active conversation with user | Yes (for restart/continuity) |
| **Working Memory** | Agent's scratchpad, task context | Ephemeral (task lifetime) |
| **Long-term Memory** | Past chats, project knowledge, lessons | Searchable, retrievable |

**Chat lifecycle:**
1. User chats, agent responds
2. User: `/new` → Current chat stored to memory, fresh chat starts
3. User: "Continue yesterday's discussion about X" → Memory recall loads context

### Why This Differs from OpenClaw

| OpenClaw | Spiderweb |
|----------|-----------|
| Sessions = chat channels (Discord threads, etc.) | Chat = one active conversation |
| Sessions used for ephemeral things (heartbeats) | Workers have internal context, no "session" |
| Session switching is UI navigation | `/new` stores chat, starts fresh |
| Memory mixed with session | Explicit memory system |
| Reactive (waits for user) | Pro-active (works on goals, reports) |

### Why This Differs from MindSwarm

| MindSwarm | Spiderweb |
|-----------|-----------|
| Task-first autonomous agents | User-first chat-oriented |
| Agents do things, maybe tell user | User knows what agents are doing |
| Multi-agent swarm optimization | Hierarchical PM + workers |
| Focus on emergent behavior | Focus on reliable project progress |

### Soft Workflows

Rather than rigid pipelines with fixed steps, **agent intelligence drives the flow**.

- **No rigid DAGs** - agents decide what to do based on context
- **Goals, not scripts** - "Refactor the rendering system" not "Step 1: grep for RenderContext..."
- **Adaptive execution** - if a path fails, agent tries alternatives
- **Human review gates** - agent proposes, user approves for significant changes

Example workflow:
```
User: "Add texture compression to the asset pipeline"
    ↓
PM Agent: Plans approach
    ├── Worker: Examines current texture loading code
    ├── Worker: Researches compression formats
    └── Worker: Implements (proposes changes via chat)
    ↓
User reviews, suggests tweaks
    ↓
PM Agent: Adjusts, finalizes
```

The agent decides the *how*, user steers the *what*.

### Virtual Filesystem (Plan9/Inferno Style)

Agents work in a **unified namespace** that aggregates multiple storage backends behind a FUSE filesystem.

```
/spiderweb/
├── workspace/              # Agent's local working directory
├── nodes/
│   ├── user-windows/       # Windows machine (WebSocket node)
│   │   └── D:/Projects/MyGame/
│   ├── user-mac/           # Mac (if paired)
│   └── cloud-vps/          # Remote build server
├── cloud/
│   ├── dropbox/            # Cloud storage
│   └── s3-bucket/          # S3 compatible
└── shared/
    └── game-assets/        # Shared texture/sound libraries
```

**Why this matters:**
- **Game dev workflows** - Agent can read textures from Windows D:, process them, write to cloud
- **No complex setup** - Uses existing WebSocket node transport, no SFTP/SMB
- **Unified interface** - Agents use normal file operations regardless of backend
- **Transparent to AI** - Pi AI just sees paths, doesn't need to know about transport

**Implementation:**
- FUSE filesystem on Linux (primary host)
- Node handlers for remote filesystem ops via WebSocket
- Caching layer for performance
- Permission model (read-only vs read-write per mount)

**Example agent interaction:**
```
Agent: "I see you have textures in /nodes/user-windows/D/Projects/MyGame/Textures/
        that aren't compressed. Should I:
        1. Compress them in place
        2. Create compressed copies in /workspace/compressed/
        3. Set up a build pipeline that compresses on export?"

User: "Option 2, and also check /cloud/dropbox/shared-assets/ for duplicates"
```

For the vision to work, Spiderweb needs:

1. **Job Queue with Priorities** - User requests > PM planning > background workers
2. **Project State Store** - Goals, tasks, dependencies, blockers
3. **Worker Lifecycle Management** - Spawn, monitor, timeout, report
4. **Chat-Centric Event System** - All significant events surface in chat
5. **Memory System** - Store/recall chats, searchable by content
6. **Pi AI Integration** - The "brain" for PM agent and workers

### Current Status

- v0.1: Echo gateway ✓
- v0.2: Pi AI integration ✓  
- v0.3: Queue-based job system (in progress)
- v0.4: Project/task data model
- v0.5: PM agent with pro-active planning
- v1.0: Full project-oriented assistant
