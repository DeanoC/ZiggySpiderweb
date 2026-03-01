const std = @import("std");
const agent_runtime = @import("agent_runtime.zig");
const memory = @import("ziggy-memory-store").memory;
const memid = @import("ziggy-memory-store").memid;
const protocol = @import("ziggy-spider-protocol").protocol;

pub const POLICY_MEM_NAME = "system.policy";
pub const LOOP_CONTRACT_MEM_NAME = "system.loop_contract";
pub const TOOL_CONTRACT_MEM_NAME = "system.tool_contract";
pub const COMPLETION_CONTRACT_MEM_NAME = "system.completion_contract";

pub const GOAL_ACTIVE_MEM_NAME = "goal.active";
pub const PLAN_CURRENT_MEM_NAME = "plan.current";
pub const RUN_PENDING_MEM_NAME = "run.pending";
pub const CONTEXT_SUMMARY_MEM_NAME = "context.summary";
pub const USER_PREFERENCES_MEM_NAME = "user.preferences";

pub const POLICY_ROM_KEY = "policy:runtime";
pub const LOOP_CONTRACT_ROM_KEY = "contract:loop";
pub const TOOL_CONTRACT_ROM_KEY = "contract:tools";
pub const COMPLETION_CONTRACT_ROM_KEY = "contract:completion";

pub const POLICY_TEXT =
    \\You are a deterministic run agent.
    \\Output exactly one JSON object per turn.
    \\Protocol is tool_calls-only: emit exactly one tool call per turn.
    \\Zero tool calls is invalid.
    \\Do not emit ambiguous freeform status text when an action is required.
    \\Prefer concrete tool execution over narration.
    \\Runtime state blocks are internal system context, not user-uploaded snapshots.
    \\Never claim the user sent you a memory/state snapshot unless they explicitly did.
;

pub const LOOP_CONTRACT_TEXT =
    \\Run cycle: Observe -> Decide -> Act -> Integrate -> Checkpoint.
    \\When history is sparse, discover capabilities first via /agents/self/services/SERVICES.json.
    \\If blocked, continue using wait-capable filesystem operations.
    \\Prefer single-source blocking reads for waits (job status/result); use events/control/wait.json + events/next.json only for one-of-many sources.
    \\If tool output is invalid or includes error.code/error.message, emit the smallest corrective tool step.
;

pub const TOOL_CONTRACT_TEXT =
    \\Use only these runtime tools: file_read, file_write, file_list.
    \\Use JSON object args that match the tool schema; file_read/file_write support wait_until_ready (default true).
    \\For file_* tool args, prefer workspace-relative Acheron paths (for example: agents/self/...).
    \\Do not use talk_* tools.
    \\Do not call memory_* directly; use Acheron paths under /agents/self/memory/control/*.json.
    \\Access web search, code search, terminal, sub-brains, and agent management via Acheron namespaces under /agents/self.
    \\Before claiming a capability is unavailable, check `/agents/self/services/SERVICES.json` and relevant first-class namespaces.
    \\Use agent_namespace for agent-local capabilities and node scope for node-specific capabilities.
    \\If `/agents/self/web_search` exists, do not claim you cannot do web search; invoke the web search service.
    \\To reply to user/admin, write text to agents/self/chat/control/reply.
    \\Treat /agents/self/chat/control/input as inbound user/admin input channel (do not use it for outbound replies).
    \\Internal thought telemetry is exposed at /agents/self/thoughts/* and is observational (not chat).
    \\Use `/agents/self/terminal/control/*.json` when terminal execution is required.
;

pub const COMPLETION_CONTRACT_TEXT =
    \\Represent completion via state/data updates, not protocol markers.
    \\If criteria are not met, emit the smallest next tool step.
    \\If waiting on user/event, use wait-capable filesystem paths.
;

const MemorySeed = struct {
    name: []const u8,
    kind: []const u8,
    content: []const u8,
    write_protected: bool,
    unevictable: bool,
    overwrite_existing: bool,
};

const memory_seeds = [_]MemorySeed{
    .{ .name = POLICY_MEM_NAME, .kind = "system.instructions", .content = POLICY_TEXT, .write_protected = true, .unevictable = true, .overwrite_existing = true },
    .{ .name = LOOP_CONTRACT_MEM_NAME, .kind = "system.instructions", .content = LOOP_CONTRACT_TEXT, .write_protected = true, .unevictable = true, .overwrite_existing = true },
    .{ .name = TOOL_CONTRACT_MEM_NAME, .kind = "system.instructions", .content = TOOL_CONTRACT_TEXT, .write_protected = true, .unevictable = true, .overwrite_existing = true },
    .{ .name = COMPLETION_CONTRACT_MEM_NAME, .kind = "system.instructions", .content = COMPLETION_CONTRACT_TEXT, .write_protected = true, .unevictable = true, .overwrite_existing = true },
    .{ .name = GOAL_ACTIVE_MEM_NAME, .kind = "goal.active", .content = "No explicit active goal set.", .write_protected = false, .unevictable = false, .overwrite_existing = false },
    .{ .name = PLAN_CURRENT_MEM_NAME, .kind = "plan.current", .content = "No active plan.", .write_protected = false, .unevictable = false, .overwrite_existing = false },
    .{ .name = RUN_PENDING_MEM_NAME, .kind = "run.pending", .content = "No pending run dependencies.", .write_protected = false, .unevictable = false, .overwrite_existing = false },
    .{ .name = CONTEXT_SUMMARY_MEM_NAME, .kind = "context.summary", .content = "No context summary yet.", .write_protected = false, .unevictable = false, .overwrite_existing = false },
    .{ .name = USER_PREFERENCES_MEM_NAME, .kind = "user.preferences", .content = "No explicit user preferences captured.", .write_protected = false, .unevictable = false, .overwrite_existing = false },
};

pub fn ensureRuntimeInstructionMemories(runtime: *agent_runtime.AgentRuntime, brain_name: []const u8) !void {
    for (memory_seeds) |seed| {
        try ensureMemory(runtime, brain_name, seed);
    }
}

pub fn setActiveGoal(runtime: *agent_runtime.AgentRuntime, brain_name: []const u8, goal_text: []const u8) !void {
    try setMemoryText(runtime, brain_name, GOAL_ACTIVE_MEM_NAME, "goal.active", goal_text, false, false, true);
}

fn ensureMemory(runtime: *agent_runtime.AgentRuntime, brain_name: []const u8, seed: MemorySeed) !void {
    try setMemoryText(
        runtime,
        brain_name,
        seed.name,
        seed.kind,
        seed.content,
        seed.write_protected,
        seed.unevictable,
        seed.overwrite_existing,
    );
}

fn setMemoryText(
    runtime: *agent_runtime.AgentRuntime,
    brain_name: []const u8,
    name: []const u8,
    kind: []const u8,
    text: []const u8,
    write_protected: bool,
    unevictable: bool,
    overwrite_existing: bool,
) !void {
    const allocator = runtime.allocator;

    const escaped = try protocol.jsonEscape(allocator, text);
    defer allocator.free(escaped);
    const content_json = try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    defer allocator.free(content_json);

    const mem_id = try buildLatestMemId(allocator, runtime.agent_id, brain_name, name);
    defer allocator.free(mem_id);

    var existing = runtime.active_memory.load(mem_id, null) catch |err| switch (err) {
        memory.MemoryError.NotFound => null,
        else => return err,
    };

    if (existing) |*item| {
        defer item.deinit(allocator);
        if (!overwrite_existing) return;
        if (std.mem.eql(u8, item.content_json, content_json)) return;

        if (!item.mutable) {
            var removed = runtime.active_memory.removeActiveNoHistory(item.mem_id) catch |err| switch (err) {
                memory.MemoryError.NotFound => null,
                else => return err,
            };
            if (removed) |*removed_item| removed_item.deinit(allocator);

            var recreated = try runtime.active_memory.create(
                brain_name,
                name,
                kind,
                content_json,
                write_protected,
                unevictable,
            );
            recreated.deinit(allocator);
            return;
        }

        var mutated = runtime.active_memory.mutate(item.mem_id, content_json) catch |err| switch (err) {
            memory.MemoryError.NotFound => blk: {
                const recreated = try runtime.active_memory.create(
                    brain_name,
                    name,
                    kind,
                    content_json,
                    write_protected,
                    unevictable,
                );
                break :blk recreated;
            },
            else => return err,
        };
        defer mutated.deinit(allocator);
        return;
    }

    var created = try runtime.active_memory.create(
        brain_name,
        name,
        kind,
        content_json,
        write_protected,
        unevictable,
    );
    created.deinit(allocator);
}

fn buildLatestMemId(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    brain_name: []const u8,
    name: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}{s}:{s}:{s}:latest{s}",
        .{ memid.EOT_MARKER, agent_id, brain_name, name, memid.EOT_MARKER },
    );
}

test "memory_schema: ensures runtime instruction memories" {
    const allocator = std.testing.allocator;
    var runtime = try agent_runtime.AgentRuntime.init(allocator, "agent-memory-schema", &.{}, .{});
    defer runtime.deinit();

    try ensureRuntimeInstructionMemories(&runtime, "primary");

    const snapshot = try runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);

    var saw_policy = false;
    var saw_goal = false;
    for (snapshot) |item| {
        const parsed = memid.MemId.parse(item.mem_id) catch continue;
        if (std.mem.eql(u8, parsed.name, POLICY_MEM_NAME)) saw_policy = true;
        if (std.mem.eql(u8, parsed.name, GOAL_ACTIVE_MEM_NAME)) saw_goal = true;
    }

    try std.testing.expect(saw_policy);
    try std.testing.expect(saw_goal);
}
