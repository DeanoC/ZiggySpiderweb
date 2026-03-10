const std = @import("std");
const unified = @import("spider-protocol").unified;

pub const Action = enum {
    refresh,
    approve,
    deny,
    invites_refresh,
    invites_create,
};

pub fn seedDebugSurface(self: anytype, debug_root: u32) !void {
    const pairing_dir = try self.addDir(debug_root, "pairing", false);
    const control_dir = try self.addDir(pairing_dir, "control", false);
    const invites_dir = try self.addDir(pairing_dir, "invites", false);
    const invites_control_dir = try self.addDir(invites_dir, "control", false);
    try self.addDirectoryDescriptors(
        pairing_dir,
        "Pairing Queue",
        "{\"kind\":\"pairing_queue\",\"entries\":[\"pending.json\",\"last_result.json\",\"last_error.json\",\"control\",\"invites\"]}",
        "{\"read\":true,\"write\":false}",
        "Node pairing review queue. Read pending requests and use control files to approve, deny, or refresh.",
    );
    try self.addDirectoryDescriptors(
        control_dir,
        "Pairing Control",
        "{\"kind\":\"pairing_control\",\"writes\":{\"approve.json\":\"control.node_join_approve payload\",\"deny.json\":\"control.node_join_deny payload\",\"refresh\":\"refresh pending queue snapshot\"}}",
        "{\"approve\":true,\"deny\":true,\"refresh\":true}",
        "Write JSON payloads to approve/deny request IDs. Write any content to refresh the queue snapshot.",
    );
    try self.addDirectoryDescriptors(
        invites_dir,
        "Invite Tokens",
        "{\"kind\":\"pairing_invites\",\"entries\":[\"active.json\",\"last_result.json\",\"last_error.json\",\"control\"]}",
        "{\"read\":true,\"write\":false}",
        "Invite-based pairing tokens. Create invite tokens and refresh active invite listings.",
    );
    try self.addDirectoryDescriptors(
        invites_control_dir,
        "Invite Control",
        "{\"kind\":\"pairing_invite_control\",\"writes\":{\"create.json\":\"control.node_invite_create payload\",\"refresh\":\"refresh active invite snapshot\"}}",
        "{\"create\":true,\"refresh\":true}",
        "Write optional invite JSON payload to create tokens. Write any content to refresh active invite snapshot.",
    );

    const pending_json = try loadPendingNodeJoinsJson(self);
    defer self.allocator.free(pending_json);
    const invites_json = try loadActiveNodeInvitesJson(self);
    defer self.allocator.free(invites_json);
    self.pairing_pending_id = try self.addFile(pairing_dir, "pending.json", pending_json, false, .none);
    self.pairing_last_result_id = try self.addFile(pairing_dir, "last_result.json", "{\"status\":\"idle\"}", false, .none);
    self.pairing_last_error_id = try self.addFile(pairing_dir, "last_error.json", "null", false, .none);
    _ = try self.addFile(control_dir, "approve.json", "", true, .pairing_approve);
    _ = try self.addFile(control_dir, "deny.json", "", true, .pairing_deny);
    _ = try self.addFile(control_dir, "refresh", "", true, .pairing_refresh);
    self.pairing_invites_active_id = try self.addFile(invites_dir, "active.json", invites_json, false, .none);
    self.pairing_invites_last_result_id = try self.addFile(invites_dir, "last_result.json", "{\"status\":\"idle\"}", false, .none);
    self.pairing_invites_last_error_id = try self.addFile(invites_dir, "last_error.json", "null", false, .none);
    _ = try self.addFile(invites_control_dir, "create.json", "", true, .pairing_invites_create);
    _ = try self.addFile(invites_control_dir, "refresh", "", true, .pairing_invites_refresh);
}

pub fn handleControlWrite(self: anytype, action: Action, raw_input: []const u8) !usize {
    const written = raw_input.len;
    const payload = std.mem.trim(u8, raw_input, " \t\r\n");
    if (!isActionAuthorized(self, action, payload)) {
        try setResultError(self, action, "OperatorAuthFailed");
        return written;
    }
    const plane = self.control_plane orelse {
        try setResultError(self, action, "ControlPlaneUnavailable");
        return written;
    };

    switch (action) {
        .refresh => {
            const list_json = plane.listPendingNodeJoins(if (payload.len == 0) "{}" else payload) catch |err| {
                try setResultError(self, action, @errorName(err));
                try refreshPendingSnapshot(self);
                return written;
            };
            defer self.allocator.free(list_json);
            try setResultSuccess(self, action, list_json);
            try setPendingContent(self, list_json);
            return written;
        },
        .approve => {
            const approve_json = plane.approvePendingNodeJoin(payload) catch |err| {
                try setResultError(self, action, @errorName(err));
                try refreshPendingSnapshot(self);
                return written;
            };
            defer self.allocator.free(approve_json);
            try setResultSuccess(self, action, approve_json);
            try refreshPendingSnapshot(self);
            return written;
        },
        .deny => {
            const deny_json = plane.denyPendingNodeJoin(payload) catch |err| {
                try setResultError(self, action, @errorName(err));
                try refreshPendingSnapshot(self);
                return written;
            };
            defer self.allocator.free(deny_json);
            try setResultSuccess(self, action, deny_json);
            try refreshPendingSnapshot(self);
            return written;
        },
        .invites_refresh => {
            const invites_json = plane.listNodeInvites(if (payload.len == 0) "{}" else payload) catch |err| {
                try setResultError(self, action, @errorName(err));
                try refreshInvitesSnapshot(self);
                return written;
            };
            defer self.allocator.free(invites_json);
            try setResultSuccess(self, action, invites_json);
            try setInvitesContent(self, invites_json);
            return written;
        },
        .invites_create => {
            const create_json = plane.createNodeInvite(if (payload.len == 0) "{}" else payload) catch |err| {
                try setResultError(self, action, @errorName(err));
                try refreshInvitesSnapshot(self);
                return written;
            };
            defer self.allocator.free(create_json);
            try setResultSuccess(self, action, create_json);
            try refreshInvitesSnapshot(self);
            return written;
        },
    }
}

fn loadPendingNodeJoinsJson(self: anytype) ![]u8 {
    const plane = self.control_plane orelse return self.allocator.dupe(u8, "{\"pending\":[]}");
    return plane.listPendingNodeJoins("{}") catch blk: {
        break :blk try self.allocator.dupe(u8, "{\"pending\":[]}");
    };
}

fn loadActiveNodeInvitesJson(self: anytype) ![]u8 {
    const plane = self.control_plane orelse return self.allocator.dupe(u8, "{\"invites\":[]}");
    return plane.listNodeInvites("{}") catch blk: {
        break :blk try self.allocator.dupe(u8, "{\"invites\":[]}");
    };
}

fn isActionAuthorized(self: anytype, action: Action, payload: []const u8) bool {
    const operator_token = self.control_operator_token orelse return true;
    if (action == .invites_create or action == .invites_refresh) return true;
    if (payload.len == 0) return false;

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const token_value = parsed.value.object.get("operator_token") orelse return false;
    if (token_value != .string or token_value.string.len == 0) return false;
    return secureTokenEql(operator_token, token_value.string);
}

fn secureTokenEql(expected: []const u8, candidate: []const u8) bool {
    if (expected.len != candidate.len) return false;
    var diff: u8 = 0;
    for (expected, candidate) |lhs, rhs| {
        diff |= lhs ^ rhs;
    }
    return diff == 0;
}

fn actionName(action: Action) []const u8 {
    return switch (action) {
        .refresh => "refresh",
        .approve => "approve",
        .deny => "deny",
        .invites_refresh => "invites_refresh",
        .invites_create => "invites_create",
    };
}

fn setPendingContent(self: anytype, payload: []const u8) !void {
    if (self.pairing_pending_id == 0) return;
    try self.setFileContent(self.pairing_pending_id, payload);
}

fn refreshPendingSnapshot(self: anytype) !void {
    if (self.pairing_pending_id == 0) return;
    const payload = try loadPendingNodeJoinsJson(self);
    defer self.allocator.free(payload);
    try setPendingContent(self, payload);
}

fn setInvitesContent(self: anytype, payload: []const u8) !void {
    if (self.pairing_invites_active_id == 0) return;
    try self.setFileContent(self.pairing_invites_active_id, payload);
}

fn refreshInvitesSnapshot(self: anytype) !void {
    if (self.pairing_invites_active_id == 0) return;
    const payload = try loadActiveNodeInvitesJson(self);
    defer self.allocator.free(payload);
    try setInvitesContent(self, payload);
}

fn setResultSuccess(self: anytype, action: Action, payload: []const u8) !void {
    const result_node_id, const error_node_id = switch (action) {
        .refresh, .approve, .deny => .{ self.pairing_last_result_id, self.pairing_last_error_id },
        .invites_refresh, .invites_create => .{ self.pairing_invites_last_result_id, self.pairing_invites_last_error_id },
    };
    if (result_node_id != 0) {
        const action_name = actionName(action);
        const escaped_action = try unified.jsonEscape(self.allocator, action_name);
        defer self.allocator.free(escaped_action);
        const result_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":true,\"action\":\"{s}\",\"at_ms\":{d},\"response\":{s}}}",
            .{ escaped_action, std.time.milliTimestamp(), payload },
        );
        defer self.allocator.free(result_json);
        try self.setFileContent(result_node_id, result_json);
    }
    if (error_node_id != 0) {
        try self.setFileContent(error_node_id, "null");
    }
}

fn setResultError(self: anytype, action: Action, error_name: []const u8) !void {
    const result_node_id, const error_node_id = switch (action) {
        .refresh, .approve, .deny => .{ self.pairing_last_result_id, self.pairing_last_error_id },
        .invites_refresh, .invites_create => .{ self.pairing_invites_last_result_id, self.pairing_invites_last_error_id },
    };
    const action_name = actionName(action);
    const escaped_action = try unified.jsonEscape(self.allocator, action_name);
    defer self.allocator.free(escaped_action);
    const escaped_error = try unified.jsonEscape(self.allocator, error_name);
    defer self.allocator.free(escaped_error);
    const payload = try std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":false,\"action\":\"{s}\",\"error\":\"{s}\",\"at_ms\":{d}}}",
        .{ escaped_action, escaped_error, std.time.milliTimestamp() },
    );
    defer self.allocator.free(payload);
    if (result_node_id != 0) {
        try self.setFileContent(result_node_id, payload);
    }
    if (error_node_id != 0) {
        try self.setFileContent(error_node_id, payload);
    }
}
