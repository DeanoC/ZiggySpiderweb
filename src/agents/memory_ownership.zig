const std = @import("std");
const memid = @import("ziggy-memory-store").memid;

pub const SOUL_MEM_NAME = "system.soul";
pub const AGENT_MEM_NAME = "system.agent";
pub const IDENTITY_MEM_NAME = "system.identity";
pub const BASE_CORE_MEM_NAME = "system.core";

pub const POLICY_MEM_NAME = "system.policy";
pub const LOOP_CONTRACT_MEM_NAME = "system.loop_contract";
pub const TOOL_CONTRACT_MEM_NAME = "system.tool_contract";
pub const COMPLETION_CONTRACT_MEM_NAME = "system.completion_contract";

pub const GOAL_ACTIVE_MEM_NAME = "goal.active";
pub const PLAN_CURRENT_MEM_NAME = "plan.current";
pub const RUN_PENDING_MEM_NAME = "run.pending";
pub const CONTEXT_SUMMARY_MEM_NAME = "context.summary";
pub const USER_PREFERENCES_MEM_NAME = "user.preferences";

pub const MemoryOwnership = enum {
    kernel_managed,
    agent_identity,
    working_memory,
    unclassified,
};

pub const MemoryOwnershipSpec = struct {
    ownership: MemoryOwnership,
    write_protected: bool,
    unevictable: bool,
};

pub fn ownershipLabel(ownership: MemoryOwnership) []const u8 {
    return switch (ownership) {
        .kernel_managed => "kernel_managed",
        .agent_identity => "agent_identity",
        .working_memory => "working_memory",
        .unclassified => "unclassified",
    };
}

pub fn specForName(name: []const u8) MemoryOwnershipSpec {
    return switch (classifyName(name)) {
        .kernel_managed => .{
            .ownership = .kernel_managed,
            .write_protected = true,
            .unevictable = true,
        },
        .agent_identity => .{
            .ownership = .agent_identity,
            .write_protected = false,
            .unevictable = true,
        },
        .working_memory => .{
            .ownership = .working_memory,
            .write_protected = false,
            .unevictable = false,
        },
        .unclassified => .{
            .ownership = .unclassified,
            .write_protected = false,
            .unevictable = false,
        },
    };
}

pub fn classifyName(name: []const u8) MemoryOwnership {
    if (isKernelManagedName(name)) return .kernel_managed;
    if (isAgentIdentityName(name)) return .agent_identity;
    if (isWorkingMemoryName(name)) return .working_memory;
    return .unclassified;
}

pub fn ownershipLabelForName(name: []const u8) []const u8 {
    return ownershipLabel(classifyName(name));
}

pub fn ownershipLabelFromMemId(mem_id_value: []const u8) ?[]const u8 {
    return ownershipLabel((ownershipFromMemId(mem_id_value) orelse return null));
}

pub fn ownershipFromMemId(mem_id_value: []const u8) ?MemoryOwnership {
    const parsed = memid.MemId.parse(mem_id_value) catch return null;
    return classifyName(parsed.name);
}

pub fn isKernelManagedName(name: []const u8) bool {
    return std.mem.eql(u8, name, BASE_CORE_MEM_NAME) or
        std.mem.eql(u8, name, POLICY_MEM_NAME) or
        std.mem.eql(u8, name, LOOP_CONTRACT_MEM_NAME) or
        std.mem.eql(u8, name, TOOL_CONTRACT_MEM_NAME) or
        std.mem.eql(u8, name, COMPLETION_CONTRACT_MEM_NAME);
}

pub fn isAgentIdentityName(name: []const u8) bool {
    return std.mem.eql(u8, name, SOUL_MEM_NAME) or
        std.mem.eql(u8, name, AGENT_MEM_NAME) or
        std.mem.eql(u8, name, IDENTITY_MEM_NAME);
}

pub fn isWorkingMemoryName(name: []const u8) bool {
    return std.mem.eql(u8, name, GOAL_ACTIVE_MEM_NAME) or
        std.mem.eql(u8, name, PLAN_CURRENT_MEM_NAME) or
        std.mem.eql(u8, name, RUN_PENDING_MEM_NAME) or
        std.mem.eql(u8, name, CONTEXT_SUMMARY_MEM_NAME) or
        std.mem.eql(u8, name, USER_PREFERENCES_MEM_NAME);
}

test "memory_ownership: specs separate kernel identity and working memory" {
    const core = specForName(BASE_CORE_MEM_NAME);
    try std.testing.expectEqual(MemoryOwnership.kernel_managed, core.ownership);
    try std.testing.expect(core.write_protected);
    try std.testing.expect(core.unevictable);

    const soul = specForName(SOUL_MEM_NAME);
    try std.testing.expectEqual(MemoryOwnership.agent_identity, soul.ownership);
    try std.testing.expect(!soul.write_protected);
    try std.testing.expect(soul.unevictable);

    const goal = specForName(GOAL_ACTIVE_MEM_NAME);
    try std.testing.expectEqual(MemoryOwnership.working_memory, goal.ownership);
    try std.testing.expect(!goal.write_protected);
    try std.testing.expect(!goal.unevictable);
}
