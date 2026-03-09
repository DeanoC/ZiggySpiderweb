const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");

const missions_filename = "missions.json";
const max_recent_events: usize = 64;
const max_recent_artifacts: usize = 32;

pub const MissionStoreError = error{
    MissionNotFound,
    InvalidMissionState,
    InvalidStateTransition,
    ApprovalPending,
    ApprovalNotPending,
    InvalidMissionRecord,
};

pub const MissionState = enum {
    planning,
    running,
    waiting_for_approval,
    blocked,
    recovering,
    completed,
    failed,
    cancelled,
};

pub const MissionActor = struct {
    actor_type: []u8,
    actor_id: []u8,

    fn deinit(self: *MissionActor, allocator: std.mem.Allocator) void {
        allocator.free(self.actor_type);
        allocator.free(self.actor_id);
        self.* = undefined;
    }

    fn cloneOwned(self: MissionActor, allocator: std.mem.Allocator) !MissionActor {
        return .{
            .actor_type = try allocator.dupe(u8, self.actor_type),
            .actor_id = try allocator.dupe(u8, self.actor_id),
        };
    }
};

pub const MissionActorInput = struct {
    actor_type: []const u8,
    actor_id: []const u8,
};

pub const MissionArtifact = struct {
    kind: []u8,
    path: ?[]u8 = null,
    summary: ?[]u8 = null,
    created_at_ms: i64,

    fn deinit(self: *MissionArtifact, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        if (self.path) |value| allocator.free(value);
        if (self.summary) |value| allocator.free(value);
        self.* = undefined;
    }

    fn cloneOwned(self: MissionArtifact, allocator: std.mem.Allocator) !MissionArtifact {
        return .{
            .kind = try allocator.dupe(u8, self.kind),
            .path = if (self.path) |value| try allocator.dupe(u8, value) else null,
            .summary = if (self.summary) |value| try allocator.dupe(u8, value) else null,
            .created_at_ms = self.created_at_ms,
        };
    }
};

pub const MissionArtifactInput = struct {
    kind: []const u8,
    path: ?[]const u8 = null,
    summary: ?[]const u8 = null,
};

pub const MissionApproval = struct {
    approval_id: []u8,
    action_kind: []u8,
    message: []u8,
    payload_json: ?[]u8 = null,
    requested_at_ms: i64,
    requested_by: MissionActor,
    resolved_at_ms: i64 = 0,
    resolved_by: ?MissionActor = null,
    resolution_note: ?[]u8 = null,
    resolution: ?[]u8 = null,

    fn deinit(self: *MissionApproval, allocator: std.mem.Allocator) void {
        allocator.free(self.approval_id);
        allocator.free(self.action_kind);
        allocator.free(self.message);
        if (self.payload_json) |value| allocator.free(value);
        self.requested_by.deinit(allocator);
        if (self.resolved_by) |*value| value.deinit(allocator);
        if (self.resolution_note) |value| allocator.free(value);
        if (self.resolution) |value| allocator.free(value);
        self.* = undefined;
    }

    fn cloneOwned(self: MissionApproval, allocator: std.mem.Allocator) !MissionApproval {
        return .{
            .approval_id = try allocator.dupe(u8, self.approval_id),
            .action_kind = try allocator.dupe(u8, self.action_kind),
            .message = try allocator.dupe(u8, self.message),
            .payload_json = if (self.payload_json) |value| try allocator.dupe(u8, value) else null,
            .requested_at_ms = self.requested_at_ms,
            .requested_by = try self.requested_by.cloneOwned(allocator),
            .resolved_at_ms = self.resolved_at_ms,
            .resolved_by = if (self.resolved_by) |value| try value.cloneOwned(allocator) else null,
            .resolution_note = if (self.resolution_note) |value| try allocator.dupe(u8, value) else null,
            .resolution = if (self.resolution) |value| try allocator.dupe(u8, value) else null,
        };
    }
};

pub const MissionEvent = struct {
    seq: u64,
    event_type: []u8,
    payload_json: []u8,
    created_at_ms: i64,

    fn deinit(self: *MissionEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.event_type);
        allocator.free(self.payload_json);
        self.* = undefined;
    }

    fn cloneOwned(self: MissionEvent, allocator: std.mem.Allocator) !MissionEvent {
        return .{
            .seq = self.seq,
            .event_type = try allocator.dupe(u8, self.event_type),
            .payload_json = try allocator.dupe(u8, self.payload_json),
            .created_at_ms = self.created_at_ms,
        };
    }
};

pub const MissionRecord = struct {
    mission_id: []u8,
    use_case: []u8,
    title: ?[]u8 = null,
    stage: []u8,
    state: MissionState,
    agent_id: ?[]u8 = null,
    project_id: ?[]u8 = null,
    run_id: ?[]u8 = null,
    workspace_root: ?[]u8 = null,
    worktree_name: ?[]u8 = null,
    created_by: MissionActor,
    created_at_ms: i64,
    updated_at_ms: i64,
    last_heartbeat_ms: i64 = 0,
    checkpoint_seq: u64 = 0,
    recovery_count: u64 = 0,
    recovery_reason: ?[]u8 = null,
    blocked_reason: ?[]u8 = null,
    summary: ?[]u8 = null,
    next_event_seq: u64 = 1,
    pending_approval: ?MissionApproval = null,
    artifacts: std.ArrayListUnmanaged(MissionArtifact) = .{},
    events: std.ArrayListUnmanaged(MissionEvent) = .{},

    pub fn deinit(self: *MissionRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.mission_id);
        allocator.free(self.use_case);
        if (self.title) |value| allocator.free(value);
        allocator.free(self.stage);
        if (self.agent_id) |value| allocator.free(value);
        if (self.project_id) |value| allocator.free(value);
        if (self.run_id) |value| allocator.free(value);
        if (self.workspace_root) |value| allocator.free(value);
        if (self.worktree_name) |value| allocator.free(value);
        self.created_by.deinit(allocator);
        if (self.recovery_reason) |value| allocator.free(value);
        if (self.blocked_reason) |value| allocator.free(value);
        if (self.summary) |value| allocator.free(value);
        if (self.pending_approval) |*value| value.deinit(allocator);
        for (self.artifacts.items) |*item| item.deinit(allocator);
        self.artifacts.deinit(allocator);
        for (self.events.items) |*item| item.deinit(allocator);
        self.events.deinit(allocator);
        self.* = undefined;
    }

    pub fn cloneOwned(self: MissionRecord, allocator: std.mem.Allocator) !MissionRecord {
        var cloned = MissionRecord{
            .mission_id = try allocator.dupe(u8, self.mission_id),
            .use_case = try allocator.dupe(u8, self.use_case),
            .title = if (self.title) |value| try allocator.dupe(u8, value) else null,
            .stage = try allocator.dupe(u8, self.stage),
            .state = self.state,
            .agent_id = if (self.agent_id) |value| try allocator.dupe(u8, value) else null,
            .project_id = if (self.project_id) |value| try allocator.dupe(u8, value) else null,
            .run_id = if (self.run_id) |value| try allocator.dupe(u8, value) else null,
            .workspace_root = if (self.workspace_root) |value| try allocator.dupe(u8, value) else null,
            .worktree_name = if (self.worktree_name) |value| try allocator.dupe(u8, value) else null,
            .created_by = try self.created_by.cloneOwned(allocator),
            .created_at_ms = self.created_at_ms,
            .updated_at_ms = self.updated_at_ms,
            .last_heartbeat_ms = self.last_heartbeat_ms,
            .checkpoint_seq = self.checkpoint_seq,
            .recovery_count = self.recovery_count,
            .recovery_reason = if (self.recovery_reason) |value| try allocator.dupe(u8, value) else null,
            .blocked_reason = if (self.blocked_reason) |value| try allocator.dupe(u8, value) else null,
            .summary = if (self.summary) |value| try allocator.dupe(u8, value) else null,
            .next_event_seq = self.next_event_seq,
            .pending_approval = if (self.pending_approval) |value| try value.cloneOwned(allocator) else null,
        };
        errdefer cloned.deinit(allocator);

        for (self.artifacts.items) |item| try cloned.artifacts.append(allocator, try item.cloneOwned(allocator));
        for (self.events.items) |item| try cloned.events.append(allocator, try item.cloneOwned(allocator));
        return cloned;
    }
};

pub const MissionFilter = struct {
    state: ?MissionState = null,
    use_case: ?[]const u8 = null,
    agent_id: ?[]const u8 = null,
    project_id: ?[]const u8 = null,
};

pub const CreateMissionInput = struct {
    use_case: []const u8,
    title: ?[]const u8 = null,
    stage: ?[]const u8 = null,
    agent_id: ?[]const u8 = null,
    project_id: ?[]const u8 = null,
    run_id: ?[]const u8 = null,
    workspace_root: ?[]const u8 = null,
    worktree_name: ?[]const u8 = null,
    created_by: MissionActorInput,
};

pub const CheckpointInput = struct {
    stage: ?[]const u8 = null,
    summary: ?[]const u8 = null,
    artifact: ?MissionArtifactInput = null,
};

pub const ServiceInvocationInput = struct {
    stage: ?[]const u8 = null,
    summary: ?[]const u8 = null,
    service_path: []const u8,
    invoke_path: []const u8,
    request_payload_json: []const u8,
    result_payload_json: ?[]const u8 = null,
    status_payload_json: ?[]const u8 = null,
    artifact: MissionArtifactInput,
    actor: MissionActorInput,
};

pub const RecoveryInput = struct {
    reason: []const u8,
    stage: ?[]const u8 = null,
    summary: ?[]const u8 = null,
};

pub const RequestApprovalInput = struct {
    action_kind: []const u8,
    message: []const u8,
    payload_json: ?[]const u8 = null,
    stage: ?[]const u8 = null,
    requested_by: MissionActorInput,
};

pub const ResolveApprovalInput = struct {
    note: ?[]const u8 = null,
    resolved_by: MissionActorInput,
};

pub const TransitionInput = struct {
    next_state: MissionState,
    stage: ?[]const u8 = null,
    reason: ?[]const u8 = null,
    summary: ?[]const u8 = null,
    actor: MissionActorInput,
};

pub const MissionStore = struct {
    allocator: std.mem.Allocator,
    path: ?[]u8 = null,
    missions: std.ArrayListUnmanaged(MissionRecord) = .{},
    next_mission_seq: u64 = 1,
    next_approval_seq: u64 = 1,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, runtime_config: Config.RuntimeConfig) MissionStore {
        var store = MissionStore{
            .allocator = allocator,
        };
        store.path = initPath(allocator, runtime_config.ltm_directory) catch |err| blk: {
            std.log.warn("mission store persistence disabled: {s}", .{@errorName(err)});
            break :blk null;
        };
        if (store.path) |path| {
            store.loadFromPath(path) catch |err| {
                std.log.warn("mission store recovery failed: {s}", .{@errorName(err)});
            };
        }
        return store;
    }

    pub fn initWithPath(allocator: std.mem.Allocator, path: ?[]const u8) !MissionStore {
        var store = MissionStore{
            .allocator = allocator,
            .path = if (path) |value| try allocator.dupe(u8, value) else null,
        };
        errdefer if (store.path) |value| allocator.free(value);
        if (store.path) |value| {
            const dir = std.fs.path.dirname(value) orelse ".";
            try ensureDirectoryExists(dir);
            _ = std.fs.cwd().openFile(value, .{ .mode = .read_only }) catch |err| switch (err) {
                error.FileNotFound => null,
                else => return err,
            };
            try store.loadFromPath(value);
        }
        return store;
    }

    pub fn deinit(self: *MissionStore) void {
        if (self.path) |value| self.allocator.free(value);
        for (self.missions.items) |*item| item.deinit(self.allocator);
        self.missions.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn create(self: *MissionStore, allocator: std.mem.Allocator, input: CreateMissionInput) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now_ms = std.time.milliTimestamp();
        const mission_id = try std.fmt.allocPrint(
            self.allocator,
            "mission-{d}-{d}",
            .{ now_ms, self.next_mission_seq },
        );
        errdefer self.allocator.free(mission_id);
        self.next_mission_seq += 1;

        var record = MissionRecord{
            .mission_id = mission_id,
            .use_case = try self.allocator.dupe(u8, input.use_case),
            .title = if (input.title) |value| try self.allocator.dupe(u8, value) else null,
            .stage = try self.allocator.dupe(u8, input.stage orelse "planning"),
            .state = .planning,
            .agent_id = if (input.agent_id) |value| try self.allocator.dupe(u8, value) else null,
            .project_id = if (input.project_id) |value| try self.allocator.dupe(u8, value) else null,
            .run_id = if (input.run_id) |value| try self.allocator.dupe(u8, value) else null,
            .workspace_root = if (input.workspace_root) |value| try self.allocator.dupe(u8, value) else null,
            .worktree_name = if (input.worktree_name) |value| try self.allocator.dupe(u8, value) else null,
            .created_by = .{
                .actor_type = try self.allocator.dupe(u8, input.created_by.actor_type),
                .actor_id = try self.allocator.dupe(u8, input.created_by.actor_id),
            },
            .created_at_ms = now_ms,
            .updated_at_ms = now_ms,
        };
        errdefer record.deinit(self.allocator);

        const create_payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"state\":\"{s}\",\"stage\":\"{s}\",\"use_case\":\"{s}\"}}",
            .{ missionStateName(record.state), record.stage, record.use_case },
        );
        defer self.allocator.free(create_payload);
        try appendEventLocked(self.allocator, &record, "mission.created", create_payload, now_ms);

        try self.missions.append(self.allocator, record);
        self.persistCurrentStateLocked() catch |err| {
            var removed = self.missions.pop().?;
            removed.deinit(self.allocator);
            self.next_mission_seq -= 1;
            return err;
        };
        return self.missions.items[self.missions.items.len - 1].cloneOwned(allocator);
    }

    pub fn listOwned(self: *MissionStore, allocator: std.mem.Allocator, filter: MissionFilter) ![]MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        var out = std.ArrayListUnmanaged(MissionRecord){};
        errdefer {
            for (out.items) |*item| item.deinit(allocator);
            out.deinit(allocator);
        }
        for (self.missions.items) |item| {
            if (!matchesFilter(item, filter)) continue;
            try out.append(allocator, try item.cloneOwned(allocator));
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn getOwned(self: *MissionStore, allocator: std.mem.Allocator, mission_id: []const u8) !?MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();
        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return null;
        return try self.missions.items[index].cloneOwned(allocator);
    }

    pub fn recordHeartbeat(self: *MissionStore, allocator: std.mem.Allocator, mission_id: []const u8, stage: ?[]const u8) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return MissionStoreError.MissionNotFound;
        const record = &self.missions.items[index];
        const now_ms = std.time.milliTimestamp();
        record.last_heartbeat_ms = now_ms;
        record.updated_at_ms = now_ms;
        if (stage) |value| try replaceOptionalString(self.allocator, &record.stage, value);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"stage\":\"{s}\",\"last_heartbeat_ms\":{d}}}",
            .{ record.stage, record.last_heartbeat_ms },
        );
        defer self.allocator.free(payload);
        try appendEventLocked(self.allocator, record, "mission.heartbeat", payload, now_ms);
        try self.persistCurrentStateLocked();
        return record.cloneOwned(allocator);
    }

    pub fn recordCheckpoint(self: *MissionStore, allocator: std.mem.Allocator, mission_id: []const u8, input: CheckpointInput) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return MissionStoreError.MissionNotFound;
        const record = &self.missions.items[index];
        if (isTerminalState(record.state)) return MissionStoreError.InvalidStateTransition;

        const now_ms = std.time.milliTimestamp();
        record.updated_at_ms = now_ms;
        record.checkpoint_seq += 1;
        if (input.stage) |value| try replaceOptionalString(self.allocator, &record.stage, value);
        if (input.summary) |value| try replaceOptionalOwnedString(self.allocator, &record.summary, value);
        if (input.artifact) |artifact| try appendArtifactLocked(self.allocator, record, artifact, now_ms);

        const artifact_json = if (input.artifact) |artifact| blk: {
            const kind = try jsonStringOrNull(self.allocator, artifact.kind);
            defer self.allocator.free(kind);
            const path_json = if (artifact.path) |value| try jsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(path_json);
            const summary_json = if (artifact.summary) |value| try jsonStringOrNull(self.allocator, value) else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(summary_json);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"kind\":{s},\"path\":{s},\"summary\":{s}}}",
                .{ kind, path_json, summary_json },
            );
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(artifact_json);

        const summary_json = if (record.summary) |value|
            try jsonStringOrNull(self.allocator, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(summary_json);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"checkpoint_seq\":{d},\"stage\":\"{s}\",\"summary\":{s},\"artifact\":{s}}}",
            .{ record.checkpoint_seq, record.stage, summary_json, artifact_json },
        );
        defer self.allocator.free(payload);
        try appendEventLocked(self.allocator, record, "mission.checkpoint", payload, now_ms);
        try self.persistCurrentStateLocked();
        return record.cloneOwned(allocator);
    }

    pub fn recordServiceInvocation(
        self: *MissionStore,
        allocator: std.mem.Allocator,
        mission_id: []const u8,
        input: ServiceInvocationInput,
    ) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return MissionStoreError.MissionNotFound;
        const record = &self.missions.items[index];
        if (isTerminalState(record.state) or record.state == .waiting_for_approval) {
            return MissionStoreError.InvalidStateTransition;
        }

        const now_ms = std.time.milliTimestamp();
        record.updated_at_ms = now_ms;
        if (input.stage) |value| try replaceOptionalString(self.allocator, &record.stage, value);
        if (input.summary) |value| try replaceOptionalOwnedString(self.allocator, &record.summary, value);
        try appendArtifactLocked(self.allocator, record, input.artifact, now_ms);

        const service_path_json = try jsonStringOrNull(self.allocator, input.service_path);
        defer self.allocator.free(service_path_json);
        const invoke_path_json = try jsonStringOrNull(self.allocator, input.invoke_path);
        defer self.allocator.free(invoke_path_json);
        const summary_json = if (record.summary) |value|
            try jsonStringOrNull(self.allocator, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(summary_json);
        const result_json = if (input.result_payload_json) |value|
            try self.allocator.dupe(u8, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(result_json);
        const status_json = if (input.status_payload_json) |value|
            try self.allocator.dupe(u8, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(status_json);
        const actor_type_json = try jsonStringOrNull(self.allocator, input.actor.actor_type);
        defer self.allocator.free(actor_type_json);
        const actor_id_json = try jsonStringOrNull(self.allocator, input.actor.actor_id);
        defer self.allocator.free(actor_id_json);
        const artifact_kind_json = try jsonStringOrNull(self.allocator, input.artifact.kind);
        defer self.allocator.free(artifact_kind_json);
        const artifact_path_json = if (input.artifact.path) |value|
            try jsonStringOrNull(self.allocator, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(artifact_path_json);
        const artifact_summary_json = if (input.artifact.summary) |value|
            try jsonStringOrNull(self.allocator, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(artifact_summary_json);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"stage\":\"{s}\",\"summary\":{s},\"service_path\":{s},\"invoke_path\":{s},\"request\":{s},\"result\":{s},\"status\":{s},\"artifact\":{{\"kind\":{s},\"path\":{s},\"summary\":{s}}},\"actor\":{{\"actor_type\":{s},\"actor_id\":{s}}}}}",
            .{
                record.stage,
                summary_json,
                service_path_json,
                invoke_path_json,
                input.request_payload_json,
                result_json,
                status_json,
                artifact_kind_json,
                artifact_path_json,
                artifact_summary_json,
                actor_type_json,
                actor_id_json,
            },
        );
        defer self.allocator.free(payload);
        try appendEventLocked(self.allocator, record, "mission.service_invoked", payload, now_ms);
        try self.persistCurrentStateLocked();
        return record.cloneOwned(allocator);
    }

    pub fn requestApproval(self: *MissionStore, allocator: std.mem.Allocator, mission_id: []const u8, input: RequestApprovalInput) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return MissionStoreError.MissionNotFound;
        const record = &self.missions.items[index];
        if (record.pending_approval != null) return MissionStoreError.ApprovalPending;
        if (!canTransition(record.state, .waiting_for_approval)) return MissionStoreError.InvalidStateTransition;

        const now_ms = std.time.milliTimestamp();
        const approval_id = try std.fmt.allocPrint(
            self.allocator,
            "approval-{d}-{d}",
            .{ now_ms, self.next_approval_seq },
        );
        errdefer self.allocator.free(approval_id);
        self.next_approval_seq += 1;

        record.pending_approval = .{
            .approval_id = approval_id,
            .action_kind = try self.allocator.dupe(u8, input.action_kind),
            .message = try self.allocator.dupe(u8, input.message),
            .payload_json = if (input.payload_json) |value| try self.allocator.dupe(u8, value) else null,
            .requested_at_ms = now_ms,
            .requested_by = .{
                .actor_type = try self.allocator.dupe(u8, input.requested_by.actor_type),
                .actor_id = try self.allocator.dupe(u8, input.requested_by.actor_id),
            },
        };
        errdefer {
            if (record.pending_approval) |*value| value.deinit(self.allocator);
            record.pending_approval = null;
        }
        if (input.stage) |value| try replaceOptionalString(self.allocator, &record.stage, value);
        record.state = .waiting_for_approval;
        record.updated_at_ms = now_ms;
        try replaceOptionalOwnedString(self.allocator, &record.blocked_reason, input.message);

        const payload_json = if (record.pending_approval.?.payload_json) |value|
            try jsonStringOrNull(self.allocator, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(payload_json);
        const message_json = try jsonStringOrNull(self.allocator, input.message);
        defer self.allocator.free(message_json);
        const action_json = try jsonStringOrNull(self.allocator, input.action_kind);
        defer self.allocator.free(action_json);
        const event_payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"approval_id\":\"{s}\",\"action_kind\":{s},\"message\":{s},\"payload\":{s}}}",
            .{ record.pending_approval.?.approval_id, action_json, message_json, payload_json },
        );
        defer self.allocator.free(event_payload);
        try appendEventLocked(self.allocator, record, "mission.approval_requested", event_payload, now_ms);
        try self.persistCurrentStateLocked();
        return record.cloneOwned(allocator);
    }

    pub fn resolveApproval(
        self: *MissionStore,
        allocator: std.mem.Allocator,
        mission_id: []const u8,
        approved: bool,
        input: ResolveApprovalInput,
    ) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return MissionStoreError.MissionNotFound;
        const record = &self.missions.items[index];
        if (record.pending_approval == null) return MissionStoreError.ApprovalNotPending;

        const next_state: MissionState = if (approved) .running else .blocked;
        if (!canTransition(record.state, next_state)) return MissionStoreError.InvalidStateTransition;

        const now_ms = std.time.milliTimestamp();
        var approval = record.pending_approval.?;
        approval.resolved_at_ms = now_ms;
        approval.resolved_by = .{
            .actor_type = try self.allocator.dupe(u8, input.resolved_by.actor_type),
            .actor_id = try self.allocator.dupe(u8, input.resolved_by.actor_id),
        };
        approval.resolution_note = if (input.note) |value| try self.allocator.dupe(u8, value) else null;
        approval.resolution = try self.allocator.dupe(u8, if (approved) "approved" else "rejected");

        const note_json = if (input.note) |value|
            try jsonStringOrNull(self.allocator, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(note_json);
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"approval_id\":\"{s}\",\"resolution\":\"{s}\",\"note\":{s}}}",
            .{ approval.approval_id, approval.resolution.?, note_json },
        );
        defer self.allocator.free(payload);

        record.pending_approval = null;
        record.state = next_state;
        record.updated_at_ms = now_ms;
        if (approved) {
            if (record.blocked_reason) |value| {
                self.allocator.free(value);
                record.blocked_reason = null;
            }
        } else {
            try replaceOptionalOwnedString(self.allocator, &record.blocked_reason, approval.message);
        }

        approval.deinit(self.allocator);
        try appendEventLocked(
            self.allocator,
            record,
            if (approved) "mission.approval_approved" else "mission.approval_rejected",
            payload,
            now_ms,
        );
        try self.persistCurrentStateLocked();
        return record.cloneOwned(allocator);
    }

    pub fn recordRecovery(self: *MissionStore, allocator: std.mem.Allocator, mission_id: []const u8, input: RecoveryInput) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return MissionStoreError.MissionNotFound;
        const record = &self.missions.items[index];
        if (!canTransition(record.state, .recovering)) return MissionStoreError.InvalidStateTransition;

        const now_ms = std.time.milliTimestamp();
        record.state = .recovering;
        record.updated_at_ms = now_ms;
        record.recovery_count += 1;
        try replaceOptionalOwnedString(self.allocator, &record.recovery_reason, input.reason);
        if (input.stage) |value| try replaceOptionalString(self.allocator, &record.stage, value);
        if (input.summary) |value| try replaceOptionalOwnedString(self.allocator, &record.summary, value);

        const reason_json = try jsonStringOrNull(self.allocator, input.reason);
        defer self.allocator.free(reason_json);
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"recovery_count\":{d},\"reason\":{s},\"stage\":\"{s}\"}}",
            .{ record.recovery_count, reason_json, record.stage },
        );
        defer self.allocator.free(payload);
        try appendEventLocked(self.allocator, record, "mission.recovery_recorded", payload, now_ms);
        try self.persistCurrentStateLocked();
        return record.cloneOwned(allocator);
    }

    pub fn transition(self: *MissionStore, allocator: std.mem.Allocator, mission_id: []const u8, input: TransitionInput) !MissionRecord {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = findMissionIndexLocked(self.missions.items, mission_id) orelse return MissionStoreError.MissionNotFound;
        const record = &self.missions.items[index];
        if (record.pending_approval != null and input.next_state != .cancelled and input.next_state != .waiting_for_approval) {
            return MissionStoreError.ApprovalPending;
        }
        if (!canTransition(record.state, input.next_state)) return MissionStoreError.InvalidStateTransition;

        const now_ms = std.time.milliTimestamp();
        const from_state = record.state;
        record.state = input.next_state;
        record.updated_at_ms = now_ms;
        if (input.stage) |value| try replaceOptionalString(self.allocator, &record.stage, value);
        if (input.summary) |value| try replaceOptionalOwnedString(self.allocator, &record.summary, value);

        switch (input.next_state) {
            .blocked => {
                if (input.reason) |value| {
                    try replaceOptionalOwnedString(self.allocator, &record.blocked_reason, value);
                }
            },
            .running => {
                if (record.blocked_reason) |value| {
                    self.allocator.free(value);
                    record.blocked_reason = null;
                }
            },
            .completed, .failed, .cancelled => {
                if (input.reason) |value| try replaceOptionalOwnedString(self.allocator, &record.summary, value);
            },
            else => {},
        }

        const reason_json = if (input.reason) |value|
            try jsonStringOrNull(self.allocator, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(reason_json);
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"from\":\"{s}\",\"to\":\"{s}\",\"stage\":\"{s}\",\"reason\":{s},\"actor_type\":\"{s}\",\"actor_id\":\"{s}\"}}",
            .{
                missionStateName(from_state),
                missionStateName(record.state),
                record.stage,
                reason_json,
                input.actor.actor_type,
                input.actor.actor_id,
            },
        );
        defer self.allocator.free(payload);
        try appendEventLocked(self.allocator, record, "mission.state_transition", payload, now_ms);
        try self.persistCurrentStateLocked();
        return record.cloneOwned(allocator);
    }

    fn loadFromPath(self: *MissionStore, path: []const u8) !void {
        const raw = std.fs.cwd().readFileAlloc(self.allocator, path, 8 * 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.allocator.free(raw);

        const PersistedMissionEvent = struct {
            seq: u64,
            event_type: []const u8,
            payload_json: []const u8,
            created_at_ms: i64,
        };
        const PersistedMissionArtifact = struct {
            kind: []const u8,
            path: ?[]const u8 = null,
            summary: ?[]const u8 = null,
            created_at_ms: i64,
        };
        const PersistedMissionApproval = struct {
            approval_id: []const u8,
            action_kind: []const u8,
            message: []const u8,
            payload_json: ?[]const u8 = null,
            requested_at_ms: i64,
            requested_by_actor_type: []const u8,
            requested_by_actor_id: []const u8,
            resolved_at_ms: i64 = 0,
            resolved_by_actor_type: ?[]const u8 = null,
            resolved_by_actor_id: ?[]const u8 = null,
            resolution_note: ?[]const u8 = null,
            resolution: ?[]const u8 = null,
        };
        const PersistedMissionRecord = struct {
            mission_id: []const u8,
            use_case: []const u8,
            title: ?[]const u8 = null,
            stage: []const u8,
            state: []const u8,
            agent_id: ?[]const u8 = null,
            project_id: ?[]const u8 = null,
            run_id: ?[]const u8 = null,
            workspace_root: ?[]const u8 = null,
            worktree_name: ?[]const u8 = null,
            created_by_actor_type: []const u8,
            created_by_actor_id: []const u8,
            created_at_ms: i64,
            updated_at_ms: i64,
            last_heartbeat_ms: i64 = 0,
            checkpoint_seq: u64 = 0,
            recovery_count: u64 = 0,
            recovery_reason: ?[]const u8 = null,
            blocked_reason: ?[]const u8 = null,
            summary: ?[]const u8 = null,
            next_event_seq: u64 = 1,
            pending_approval: ?PersistedMissionApproval = null,
            artifacts: ?[]PersistedMissionArtifact = null,
            events: ?[]PersistedMissionEvent = null,
        };
        const Persisted = struct {
            schema: u32 = 1,
            next_mission_seq: u64 = 1,
            next_approval_seq: u64 = 1,
            missions: ?[]PersistedMissionRecord = null,
            updated_at_ms: i64 = 0,
        };

        const parsed = try std.json.parseFromSlice(Persisted, self.allocator, raw, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();

        self.next_mission_seq = @max(parsed.value.next_mission_seq, 1);
        self.next_approval_seq = @max(parsed.value.next_approval_seq, 1);
        const persisted_missions = parsed.value.missions orelse return;
        for (persisted_missions) |item| {
            var record = MissionRecord{
                .mission_id = try self.allocator.dupe(u8, item.mission_id),
                .use_case = try self.allocator.dupe(u8, item.use_case),
                .title = if (item.title) |value| try self.allocator.dupe(u8, value) else null,
                .stage = try self.allocator.dupe(u8, item.stage),
                .state = parseMissionState(item.state) orelse return MissionStoreError.InvalidMissionRecord,
                .agent_id = if (item.agent_id) |value| try self.allocator.dupe(u8, value) else null,
                .project_id = if (item.project_id) |value| try self.allocator.dupe(u8, value) else null,
                .run_id = if (item.run_id) |value| try self.allocator.dupe(u8, value) else null,
                .workspace_root = if (item.workspace_root) |value| try self.allocator.dupe(u8, value) else null,
                .worktree_name = if (item.worktree_name) |value| try self.allocator.dupe(u8, value) else null,
                .created_by = .{
                    .actor_type = try self.allocator.dupe(u8, item.created_by_actor_type),
                    .actor_id = try self.allocator.dupe(u8, item.created_by_actor_id),
                },
                .created_at_ms = item.created_at_ms,
                .updated_at_ms = item.updated_at_ms,
                .last_heartbeat_ms = item.last_heartbeat_ms,
                .checkpoint_seq = item.checkpoint_seq,
                .recovery_count = item.recovery_count,
                .recovery_reason = if (item.recovery_reason) |value| try self.allocator.dupe(u8, value) else null,
                .blocked_reason = if (item.blocked_reason) |value| try self.allocator.dupe(u8, value) else null,
                .summary = if (item.summary) |value| try self.allocator.dupe(u8, value) else null,
                .next_event_seq = item.next_event_seq,
            };
            errdefer record.deinit(self.allocator);

            if (item.pending_approval) |approval| {
                record.pending_approval = .{
                    .approval_id = try self.allocator.dupe(u8, approval.approval_id),
                    .action_kind = try self.allocator.dupe(u8, approval.action_kind),
                    .message = try self.allocator.dupe(u8, approval.message),
                    .payload_json = if (approval.payload_json) |value| try self.allocator.dupe(u8, value) else null,
                    .requested_at_ms = approval.requested_at_ms,
                    .requested_by = .{
                        .actor_type = try self.allocator.dupe(u8, approval.requested_by_actor_type),
                        .actor_id = try self.allocator.dupe(u8, approval.requested_by_actor_id),
                    },
                    .resolved_at_ms = approval.resolved_at_ms,
                    .resolved_by = if (approval.resolved_by_actor_type != null and approval.resolved_by_actor_id != null) .{
                        .actor_type = try self.allocator.dupe(u8, approval.resolved_by_actor_type.?),
                        .actor_id = try self.allocator.dupe(u8, approval.resolved_by_actor_id.?),
                    } else null,
                    .resolution_note = if (approval.resolution_note) |value| try self.allocator.dupe(u8, value) else null,
                    .resolution = if (approval.resolution) |value| try self.allocator.dupe(u8, value) else null,
                };
            }

            if (item.artifacts) |artifacts| {
                for (artifacts) |artifact| {
                    try record.artifacts.append(self.allocator, .{
                        .kind = try self.allocator.dupe(u8, artifact.kind),
                        .path = if (artifact.path) |value| try self.allocator.dupe(u8, value) else null,
                        .summary = if (artifact.summary) |value| try self.allocator.dupe(u8, value) else null,
                        .created_at_ms = artifact.created_at_ms,
                    });
                }
            }
            if (item.events) |events| {
                for (events) |event| {
                    try record.events.append(self.allocator, .{
                        .seq = event.seq,
                        .event_type = try self.allocator.dupe(u8, event.event_type),
                        .payload_json = try self.allocator.dupe(u8, event.payload_json),
                        .created_at_ms = event.created_at_ms,
                    });
                }
            }
            try self.missions.append(self.allocator, record);
        }
    }

    fn persistCurrentStateLocked(self: *MissionStore) !void {
        const path = self.path orelse return;

        const PersistedMissionEvent = struct {
            seq: u64,
            event_type: []const u8,
            payload_json: []const u8,
            created_at_ms: i64,
        };
        const PersistedMissionArtifact = struct {
            kind: []const u8,
            path: ?[]const u8 = null,
            summary: ?[]const u8 = null,
            created_at_ms: i64,
        };
        const PersistedMissionApproval = struct {
            approval_id: []const u8,
            action_kind: []const u8,
            message: []const u8,
            payload_json: ?[]const u8 = null,
            requested_at_ms: i64,
            requested_by_actor_type: []const u8,
            requested_by_actor_id: []const u8,
            resolved_at_ms: i64 = 0,
            resolved_by_actor_type: ?[]const u8 = null,
            resolved_by_actor_id: ?[]const u8 = null,
            resolution_note: ?[]const u8 = null,
            resolution: ?[]const u8 = null,
        };
        const PersistedMissionRecord = struct {
            mission_id: []const u8,
            use_case: []const u8,
            title: ?[]const u8 = null,
            stage: []const u8,
            state: []const u8,
            agent_id: ?[]const u8 = null,
            project_id: ?[]const u8 = null,
            run_id: ?[]const u8 = null,
            workspace_root: ?[]const u8 = null,
            worktree_name: ?[]const u8 = null,
            created_by_actor_type: []const u8,
            created_by_actor_id: []const u8,
            created_at_ms: i64,
            updated_at_ms: i64,
            last_heartbeat_ms: i64 = 0,
            checkpoint_seq: u64 = 0,
            recovery_count: u64 = 0,
            recovery_reason: ?[]const u8 = null,
            blocked_reason: ?[]const u8 = null,
            summary: ?[]const u8 = null,
            next_event_seq: u64 = 1,
            pending_approval: ?PersistedMissionApproval = null,
            artifacts: ?[]PersistedMissionArtifact = null,
            events: ?[]PersistedMissionEvent = null,
        };
        const Persisted = struct {
            schema: u32 = 1,
            next_mission_seq: u64,
            next_approval_seq: u64,
            missions: ?[]PersistedMissionRecord = null,
            updated_at_ms: i64,
        };

        const persisted_missions = if (self.missions.items.len == 0)
            null
        else
            try self.allocator.alloc(PersistedMissionRecord, self.missions.items.len);
        defer if (persisted_missions) |items| self.allocator.free(items);

        if (persisted_missions) |items| {
            for (self.missions.items, 0..) |mission, idx| {
                const artifacts = if (mission.artifacts.items.len == 0)
                    null
                else
                    try self.allocator.alloc(PersistedMissionArtifact, mission.artifacts.items.len);
                errdefer if (artifacts) |value| self.allocator.free(value);
                if (artifacts) |artifact_items| {
                    for (mission.artifacts.items, 0..) |artifact, artifact_idx| {
                        artifact_items[artifact_idx] = .{
                            .kind = artifact.kind,
                            .path = artifact.path,
                            .summary = artifact.summary,
                            .created_at_ms = artifact.created_at_ms,
                        };
                    }
                }

                const events = if (mission.events.items.len == 0)
                    null
                else
                    try self.allocator.alloc(PersistedMissionEvent, mission.events.items.len);
                errdefer if (events) |value| self.allocator.free(value);
                if (events) |event_items| {
                    for (mission.events.items, 0..) |event, event_idx| {
                        event_items[event_idx] = .{
                            .seq = event.seq,
                            .event_type = event.event_type,
                            .payload_json = event.payload_json,
                            .created_at_ms = event.created_at_ms,
                        };
                    }
                }

                items[idx] = .{
                    .mission_id = mission.mission_id,
                    .use_case = mission.use_case,
                    .title = mission.title,
                    .stage = mission.stage,
                    .state = missionStateName(mission.state),
                    .agent_id = mission.agent_id,
                    .project_id = mission.project_id,
                    .run_id = mission.run_id,
                    .workspace_root = mission.workspace_root,
                    .worktree_name = mission.worktree_name,
                    .created_by_actor_type = mission.created_by.actor_type,
                    .created_by_actor_id = mission.created_by.actor_id,
                    .created_at_ms = mission.created_at_ms,
                    .updated_at_ms = mission.updated_at_ms,
                    .last_heartbeat_ms = mission.last_heartbeat_ms,
                    .checkpoint_seq = mission.checkpoint_seq,
                    .recovery_count = mission.recovery_count,
                    .recovery_reason = mission.recovery_reason,
                    .blocked_reason = mission.blocked_reason,
                    .summary = mission.summary,
                    .next_event_seq = mission.next_event_seq,
                    .pending_approval = if (mission.pending_approval) |approval| .{
                        .approval_id = approval.approval_id,
                        .action_kind = approval.action_kind,
                        .message = approval.message,
                        .payload_json = approval.payload_json,
                        .requested_at_ms = approval.requested_at_ms,
                        .requested_by_actor_type = approval.requested_by.actor_type,
                        .requested_by_actor_id = approval.requested_by.actor_id,
                        .resolved_at_ms = approval.resolved_at_ms,
                        .resolved_by_actor_type = if (approval.resolved_by) |value| value.actor_type else null,
                        .resolved_by_actor_id = if (approval.resolved_by) |value| value.actor_id else null,
                        .resolution_note = approval.resolution_note,
                        .resolution = approval.resolution,
                    } else null,
                    .artifacts = artifacts,
                    .events = events,
                };
            }
        }

        const payload = Persisted{
            .next_mission_seq = self.next_mission_seq,
            .next_approval_seq = self.next_approval_seq,
            .missions = persisted_missions,
            .updated_at_ms = std.time.milliTimestamp(),
        };
        const bytes = try std.json.Stringify.valueAlloc(self.allocator, payload, .{
            .emit_null_optional_fields = false,
            .whitespace = .indent_2,
        });
        defer self.allocator.free(bytes);
        if (persisted_missions) |items| {
            for (items) |item| {
                if (item.artifacts) |value| self.allocator.free(value);
                if (item.events) |value| self.allocator.free(value);
            }
        }

        const file = try std.fs.cwd().createFile(path, .{
            .truncate = true,
            .mode = 0o600,
        });
        defer file.close();
        if (builtin.os.tag != .windows) {
            try file.chmod(0o600);
        }
        try file.writeAll(bytes);
    }
};

pub fn missionStateName(state: MissionState) []const u8 {
    return @tagName(state);
}

pub fn parseMissionState(raw: []const u8) ?MissionState {
    return std.meta.stringToEnum(MissionState, raw);
}

pub fn deinitMissionList(allocator: std.mem.Allocator, missions: []MissionRecord) void {
    for (missions) |*item| item.deinit(allocator);
    allocator.free(missions);
}

fn initPath(allocator: std.mem.Allocator, ltm_directory: []const u8) !?[]u8 {
    const base = std.mem.trim(u8, ltm_directory, " \t\r\n");
    if (base.len == 0) return null;
    try ensureDirectoryExists(base);
    return try std.fs.path.join(allocator, &.{ base, missions_filename });
}

fn ensureDirectoryExists(path: []const u8) !void {
    if (path.len == 0 or std.mem.eql(u8, path, ".")) return;
    try std.fs.cwd().makePath(path);
}

fn matchesFilter(record: MissionRecord, filter: MissionFilter) bool {
    if (filter.state) |value| {
        if (record.state != value) return false;
    }
    if (filter.use_case) |value| {
        if (!std.mem.eql(u8, record.use_case, value)) return false;
    }
    if (filter.agent_id) |value| {
        if (record.agent_id == null or !std.mem.eql(u8, record.agent_id.?, value)) return false;
    }
    if (filter.project_id) |value| {
        if (record.project_id == null or !std.mem.eql(u8, record.project_id.?, value)) return false;
    }
    return true;
}

fn findMissionIndexLocked(items: []MissionRecord, mission_id: []const u8) ?usize {
    for (items, 0..) |item, idx| {
        if (std.mem.eql(u8, item.mission_id, mission_id)) return idx;
    }
    return null;
}

fn isTerminalState(state: MissionState) bool {
    return switch (state) {
        .completed, .failed, .cancelled => true,
        else => false,
    };
}

fn canTransition(current: MissionState, next: MissionState) bool {
    if (current == next) return true;
    return switch (current) {
        .planning => switch (next) {
            .running, .waiting_for_approval, .blocked, .cancelled, .failed => true,
            else => false,
        },
        .running => switch (next) {
            .waiting_for_approval, .blocked, .recovering, .completed, .failed, .cancelled => true,
            else => false,
        },
        .waiting_for_approval => switch (next) {
            .running, .blocked, .cancelled => true,
            else => false,
        },
        .blocked => switch (next) {
            .running, .recovering, .failed, .cancelled => true,
            else => false,
        },
        .recovering => switch (next) {
            .running, .waiting_for_approval, .blocked, .failed, .cancelled => true,
            else => false,
        },
        .completed, .failed, .cancelled => false,
    };
}

fn replaceOptionalOwnedString(
    allocator: std.mem.Allocator,
    slot: *?[]u8,
    value: []const u8,
) !void {
    const next = try allocator.dupe(u8, value);
    if (slot.*) |existing| allocator.free(existing);
    slot.* = next;
}

fn replaceOptionalString(
    allocator: std.mem.Allocator,
    slot: *[]u8,
    value: []const u8,
) !void {
    const next = try allocator.dupe(u8, value);
    allocator.free(slot.*);
    slot.* = next;
}

fn appendArtifactLocked(
    allocator: std.mem.Allocator,
    record: *MissionRecord,
    artifact: MissionArtifactInput,
    created_at_ms: i64,
) !void {
    if (record.artifacts.items.len >= max_recent_artifacts) {
        var removed = record.artifacts.orderedRemove(0);
        removed.deinit(allocator);
    }
    try record.artifacts.append(allocator, .{
        .kind = try allocator.dupe(u8, artifact.kind),
        .path = if (artifact.path) |value| try allocator.dupe(u8, value) else null,
        .summary = if (artifact.summary) |value| try allocator.dupe(u8, value) else null,
        .created_at_ms = created_at_ms,
    });
}

fn appendEventLocked(
    allocator: std.mem.Allocator,
    record: *MissionRecord,
    event_type: []const u8,
    payload_json: []const u8,
    created_at_ms: i64,
) !void {
    if (record.events.items.len >= max_recent_events) {
        var removed = record.events.orderedRemove(0);
        removed.deinit(allocator);
    }
    try record.events.append(allocator, .{
        .seq = record.next_event_seq,
        .event_type = try allocator.dupe(u8, event_type),
        .payload_json = try allocator.dupe(u8, payload_json),
        .created_at_ms = created_at_ms,
    });
    record.next_event_seq += 1;
}

fn jsonStringOrNull(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const escaped = try std.json.Stringify.valueAlloc(allocator, value, .{});
    return escaped;
}

test "mission_store: create checkpoint recover and transition records state" {
    const allocator = std.testing.allocator;
    var store = try MissionStore.initWithPath(allocator, null);
    defer store.deinit();

    var created = try store.create(allocator, .{
        .use_case = "pr_review",
        .title = "Review PR #123",
        .created_by = .{ .actor_type = "agent", .actor_id = "worker-a" },
    });
    defer created.deinit(allocator);
    try std.testing.expectEqual(MissionState.planning, created.state);

    var running = try store.transition(allocator, created.mission_id, .{
        .next_state = .running,
        .stage = "collecting_context",
        .actor = .{ .actor_type = "agent", .actor_id = "worker-a" },
    });
    defer running.deinit(allocator);
    try std.testing.expectEqual(MissionState.running, running.state);

    var checkpointed = try store.recordCheckpoint(allocator, created.mission_id, .{
        .summary = "Scanned changed files",
        .artifact = .{ .kind = "notes", .summary = "review notes" },
    });
    defer checkpointed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), checkpointed.checkpoint_seq);
    try std.testing.expectEqual(@as(usize, 1), checkpointed.artifacts.items.len);

    var recovering = try store.recordRecovery(allocator, created.mission_id, .{
        .reason = "runtime_restart",
        .stage = "restoring_context",
    });
    defer recovering.deinit(allocator);
    try std.testing.expectEqual(MissionState.recovering, recovering.state);
    try std.testing.expectEqual(@as(u64, 1), recovering.recovery_count);

    var completed = try store.transition(allocator, created.mission_id, .{
        .next_state = .running,
        .actor = .{ .actor_type = "agent", .actor_id = "worker-a" },
    });
    defer completed.deinit(allocator);
    try std.testing.expectEqual(MissionState.running, completed.state);

    var final_record = try store.transition(allocator, created.mission_id, .{
        .next_state = .completed,
        .summary = "Mission complete",
        .actor = .{ .actor_type = "agent", .actor_id = "worker-a" },
    });
    defer final_record.deinit(allocator);
    try std.testing.expectEqual(MissionState.completed, final_record.state);
    try std.testing.expect(std.mem.eql(u8, final_record.summary.?, "Mission complete"));
}

test "mission_store: approval flow gates transition and persists resolution" {
    const allocator = std.testing.allocator;
    var store = try MissionStore.initWithPath(allocator, null);
    defer store.deinit();

    var created = try store.create(allocator, .{
        .use_case = "dangerous_change",
        .created_by = .{ .actor_type = "agent", .actor_id = "builder" },
    });
    defer created.deinit(allocator);

    var running = try store.transition(allocator, created.mission_id, .{
        .next_state = .running,
        .actor = .{ .actor_type = "agent", .actor_id = "builder" },
    });
    defer running.deinit(allocator);

    var waiting = try store.requestApproval(allocator, created.mission_id, .{
        .action_kind = "push_branch",
        .message = "Push fix branch to origin",
        .requested_by = .{ .actor_type = "agent", .actor_id = "builder" },
    });
    defer waiting.deinit(allocator);
    try std.testing.expectEqual(MissionState.waiting_for_approval, waiting.state);
    try std.testing.expect(waiting.pending_approval != null);

    try std.testing.expectError(MissionStoreError.ApprovalPending, store.transition(allocator, created.mission_id, .{
        .next_state = .completed,
        .actor = .{ .actor_type = "agent", .actor_id = "builder" },
    }));

    var approved = try store.resolveApproval(allocator, created.mission_id, true, .{
        .note = "Looks good",
        .resolved_by = .{ .actor_type = "admin", .actor_id = "deano" },
    });
    defer approved.deinit(allocator);
    try std.testing.expectEqual(MissionState.running, approved.state);
    try std.testing.expect(approved.pending_approval == null);
}

test "mission_store: service invocation records artifact and event" {
    const allocator = std.testing.allocator;
    var store = try MissionStore.initWithPath(allocator, null);
    defer store.deinit();

    var created = try store.create(allocator, .{
        .use_case = "pr_review",
        .created_by = .{ .actor_type = "agent", .actor_id = "planner" },
    });
    defer created.deinit(allocator);

    var running = try store.transition(allocator, created.mission_id, .{
        .next_state = .running,
        .stage = "collecting_context",
        .actor = .{ .actor_type = "agent", .actor_id = "planner" },
    });
    defer running.deinit(allocator);

    var invoked = try store.recordServiceInvocation(allocator, created.mission_id, .{
        .stage = "reviewing",
        .summary = "Created memory note",
        .service_path = "/global/memory",
        .invoke_path = "/global/memory/control/invoke.json",
        .request_payload_json = "{\"op\":\"create\",\"arguments\":{\"name\":\"review-note\"}}",
        .result_payload_json = "{\"ok\":true,\"result\":{\"memory_path\":\"/global/memory/items/review-note\"},\"error\":null}",
        .status_payload_json = "{\"state\":\"done\",\"tool\":\"memory_create\",\"updated_at_ms\":1,\"error\":null}",
        .artifact = .{
            .kind = "service_result",
            .path = "/global/memory/result.json",
            .summary = "Created review note",
        },
        .actor = .{ .actor_type = "agent", .actor_id = "planner" },
    });
    defer invoked.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), invoked.artifacts.items.len);
    try std.testing.expect(std.mem.eql(u8, invoked.stage, "reviewing"));
    try std.testing.expect(std.mem.eql(u8, invoked.summary.?, "Created memory note"));
    try std.testing.expectEqualStrings("service_result", invoked.artifacts.items[0].kind);
    try std.testing.expectEqualStrings("/global/memory/result.json", invoked.artifacts.items[0].path.?);
    try std.testing.expect(invoked.events.items.len >= 3);
    const latest_event = invoked.events.items[invoked.events.items.len - 1];
    try std.testing.expectEqualStrings("mission.service_invoked", latest_event.event_type);
    try std.testing.expect(std.mem.indexOf(u8, latest_event.payload_json, "\"service_path\":\"/global/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest_event.payload_json, "\"actor_type\":\"agent\"") != null);
}

test "mission_store: persists records across restart" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, "missions.json" });
    defer allocator.free(path);

    {
        var first = try MissionStore.initWithPath(allocator, path);
        defer first.deinit();
        var created = try first.create(allocator, .{
            .use_case = "pr_review",
            .title = "Persistent mission",
            .created_by = .{ .actor_type = "agent", .actor_id = "builder" },
        });
        defer created.deinit(allocator);
        var running = try first.transition(allocator, created.mission_id, .{
            .next_state = .running,
            .stage = "working",
            .actor = .{ .actor_type = "agent", .actor_id = "builder" },
        });
        defer running.deinit(allocator);
        var checkpoint = try first.recordCheckpoint(allocator, created.mission_id, .{
            .summary = "checkpoint one",
        });
        defer checkpoint.deinit(allocator);
    }

    var second = try MissionStore.initWithPath(allocator, path);
    defer second.deinit();
    const list = try second.listOwned(allocator, .{});
    defer deinitMissionList(allocator, list);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqual(MissionState.running, list[0].state);
    try std.testing.expectEqual(@as(u64, 1), list[0].checkpoint_seq);
    try std.testing.expect(std.mem.eql(u8, list[0].stage, "working"));
}
