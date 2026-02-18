# ZSS Agent Discovery & Session Restore API

**For ZSS Client Implementors**

This document describes the protocol messages for agent discovery and session restore features.

---

## Agent Discovery

## Connect Behavior

On websocket `connect`, the server replies with:

1. `connect.ack`
2. Optional `session.receive` bootstrap message for first-time agent initialization

Clients should always handle multiple frames after a single `connect` request.

---

### List Available Agents

**Request:**
```json
{"type": "agent.list"}
```

**Response:**
```json
{
  "type": "agent.list.response",
  "request": "...",
  "agents": [
    {
      "id": "default",
      "name": "Assistant",
      "description": "General purpose AI assistant",
      "is_default": true,
      "identity_loaded": false
    },
    {
      "id": "coder",
      "name": "Code Expert",
      "description": "Specialized in programming tasks",
      "is_default": false,
      "identity_loaded": true
    }
  ]
}
```

### Get Specific Agent

**Request:**
```json
{"type": "agent.get", "agent_id": "coder"}
```

Or get default:
```json
{"type": "agent.get"}
```

**Response:**
```json
{
  "type": "agent.info",
  "request": "...",
  "agent": {
    "id": "coder",
    "name": "Code Expert",
    "description": "Specialized in programming tasks",
    "is_default": false,
    "identity_loaded": true
  }
}
```

---

## Session Restore

### Restore Last Active Session

**Request:**
```json
{"type": "session.restore", "agent_id": "default"}
```

**Success Response:**
```json
{
  "type": "session.restore.response",
  "request": "...",
  "found": true,
  "session": {
    "session_key": "abc123...",
    "agent_id": "default",
    "last_active_ms": 1707993600000,
    "message_count": 42,
    "summary": "Discussion about API design..."
  }
}
```

**Not Found Response:**
```json
{
  "type": "session.restore.response",
  "request": "...",
  "found": false
}
```

### Connect with Restored Session

Use the `session_key` from restore response:
```
ws://server:18790/new?session=abc123...
```

### List Recent Sessions

**Request:**
```json
{"type": "session.history", "agent_id": "default", "limit": 5}
```

**Response:**
```json
{
  "type": "session.history.response",
  "request": "...",
  "sessions": [
    {
      "session_key": "abc123...",
      "last_active_ms": 1707993600000,
      "message_count": 42,
      "summary": "API design discussion"
    },
    {
      "session_key": "def456...",
      "last_active_ms": 1707907200000,
      "message_count": 15,
      "summary": "Bug fix planning"
    }
  ]
}
```

---

## Implementation Example (ZSS CLI)

```zig
// Connect and discover agents
pub fn connectAndSelectAgent(allocator: Allocator, client: *WebSocketClient) ![]const u8 {
    // Get default agent
    try client.send(\{"type": "agent.get"\});
    
    const response = try client.readTimeout(5000);
    defer allocator.free(response);
    
    // Parse response and extract agent_id
    // ... JSON parsing ...
    
    return agent_id;
}

// Restore last session
pub fn restoreSession(allocator: Allocator, client: *WebSocketClient, agent_id: []const u8) !?[]const u8 {
    const json = try std.fmt.allocPrint(allocator, 
        \"{"type":"session.restore","agent_id":"{s}"}\", 
        .{agent_id});
    defer allocator.free(json);
    
    try client.send(json);
    
    const response = try client.readTimeout(5000);
    defer allocator.free(response);
    
    // Parse response
    // If found: return session_key
    // If not found: return null
}

// Connect with restored session
pub fn connectWithSession(base_url: []const u8, session_key: []const u8) !WebSocketClient {
    const url = try std.fmt.allocPrint(allocator, "{s}/new?session={s}", 
        .{base_url, session_key});
    defer allocator.free(url);
    
    var client = WebSocketClient.init(allocator, url, "");
    try client.connect();
    return client;
}
```

---

## Implementation Example (ZSS-GUI)

### Agent Picker UI

```zig
// On connect, request agent list
fn onConnect(client: *WebSocketClient) !void {
    try client.send(\{"type": "agent.list"\});
}

// Handle agent list response
fn handleAgentList(response: []const u8) !void {
    // Parse JSON
    // Populate dropdown with agents
    // Mark default agent as selected
}

// User selects agent from dropdown
fn onAgentSelected(agent_id: []const u8) !void {
    // Request session restore
    const json = try std.fmt.allocPrint(allocator,
        \"{"type":"session.restore","agent_id":"{s}"}\",
        .{agent_id});
    try client.send(json);
}

// Handle restore response
fn handleRestoreResponse(response: []const u8) !void {
    // If found:
    //   - Show "Continue last chat: {summary}"
    //   - Button: "Continue" → connect with session_key
    //   - Button: "New Chat" → connect without session
    //
    // If not found:
    //   - Show "Start new chat"
}
```

### Session History Sidebar

```zig
// Request recent sessions
fn loadSessionHistory(agent_id: []const u8) !void {
    const json = try std.fmt.allocPrint(allocator,
        \"{"type":"session.history","agent_id":"{s}","limit":10}\",
        .{agent_id});
    try client.send(json);
}

// Display sessions in sidebar
fn displaySessionHistory(sessions: []Session) void {
    // For each session:
    // - Show summary
    // - Show message count
    // - Show relative time (e.g., "2 hours ago")
    // - Click to restore that session
}
```

---

## Error Handling

**Error Response:**
```json
{"type": "error", "message": "LTM store not available"}
```

Common errors:
- LTM store not available (SQLite not configured)
- Agent not found
- Session not found

---

## Complete Flow Example

```
1. User opens ZSS-GUI
2. GUI connects to ws://server:18790/new
3. GUI sends: {"type": "agent.list"}
4. GUI receives agent list
5. GUI displays agent picker, selects default
6. GUI sends: {"type": "session.restore", "agent_id": "default"}
7. Server responds with last session (or not found)
8. If session found:
   - Show "Continue API design discussion?"
   - User clicks "Continue"
   - GUI reconnects with ?session=abc123...
   - Chat continues from where left off
9. If no session:
   - Show "Start new chat"
   - User begins fresh conversation
```

---

## Notes

- Sessions are automatically tracked on server (no client action needed)
- Sessions marked inactive after 24h of inactivity
- Only active sessions are returned by `session.restore`
- Session history includes up to 20 recent sessions per agent
- Session summaries are LLM-generated when session is archived
