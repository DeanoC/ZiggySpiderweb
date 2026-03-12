const std = @import("std");
const builtin = @import("builtin");
const unified = @import("spider-protocol").unified;
const protocol = @import("spider-protocol").protocol;
const shared_exec = @import("spiderweb_node").chat_runtime_exec;
const runtime_handle_mod = @import("../agents/runtime_handle.zig");
const chat_job_index = @import("../agents/chat_job_index.zig");
const tool_executor_mod = @import("ziggy-tool-runtime").tool_executor;
const job_projection = @import("job_projection.zig");
const shared_node = @import("spiderweb_node");
const workspace_policy = @import("../workspaces/policy.zig");
const control_plane_mod = @import("control_plane.zig");
const acheron_router = @import("router.zig");
const agent_config = @import("../agents/agent_config.zig");
const agent_registry = @import("../agents/agent_registry.zig");
const mission_store_mod = @import("../mission_store.zig");
const search_services_venom = @import("../venoms/search_services.zig");
const chat_venom = @import("../venoms/chat.zig");
const events_venom = @import("../venoms/events.zig");
const pairing_venom = @import("../venoms/pairing.zig");
const jobs_venom = @import("../venoms/jobs.zig");
const terminal_venom = @import("../venoms/terminal.zig");
const mounts_venom = @import("../venoms/mounts.zig");
const home_venom = @import("../venoms/home.zig");
const workers_venom = @import("../venoms/workers.zig");
const venom_packages_service_venom = @import("../venoms/venom_packages_service.zig");
const agents_venom = @import("../venoms/agents.zig");
const workspaces_venom = @import("../venoms/workspaces.zig");
const git_venom = @import("../venoms/git.zig");
const github_pr_venom = @import("../venoms/github_pr.zig");
const missions_venom = @import("../venoms/missions.zig");
const pr_review_venom = @import("../venoms/pr_review.zig");
const venom_packages = @import("../venom_packages.zig");

const NodeKind = enum {
    dir,
    file,
};

const SpecialKind = enum {
    none,
    chat_input,
    chat_reply,
    job_status,
    job_result,
    job_log,
    agent_venoms_index,
    node_venom_events_log,
    web_search_invoke,
    web_search_search,
    search_code_invoke,
    search_code_search,
    agents_invoke,
    agents_list,
    agents_create,
    home_invoke,
    home_ensure,
    workers_invoke,
    workers_register,
    workers_heartbeat,
    workers_detach,
    venom_packages_invoke,
    venom_packages_list,
    venom_packages_get,
    venom_packages_install,
    venom_packages_remove,
    projects_invoke,
    projects_list,
    projects_get,
    projects_up,
    git_invoke,
    git_sync_checkout,
    git_status,
    git_diff_range,
    github_pr_invoke,
    github_pr_sync,
    github_pr_ingest_event,
    github_pr_publish_review,
    pr_review_invoke,
    pr_review_configure_repo,
    pr_review_get_repo,
    pr_review_list_repos,
    pr_review_intake,
    pr_review_start,
    pr_review_sync,
    pr_review_run_validation,
    pr_review_record_validation,
    pr_review_draft_review,
    pr_review_save_draft,
    pr_review_record_review,
    pr_review_advance,
    missions_invoke,
    missions_invoke_service,
    missions_create,
    missions_list,
    missions_get,
    missions_heartbeat,
    missions_checkpoint,
    missions_bootstrap_contract,
    missions_recover,
    missions_request_approval,
    missions_approve,
    missions_reject,
    missions_resume,
    missions_block,
    missions_complete,
    missions_fail,
    missions_cancel,
    mounts_invoke,
    mounts_list,
    mounts_mount,
    mounts_mkdir,
    mounts_unmount,
    mounts_bind,
    mounts_unbind,
    mounts_resolve,
    event_wait_config,
    event_signal,
    event_next,
    pairing_refresh,
    pairing_approve,
    pairing_deny,
    pairing_invites_refresh,
    pairing_invites_create,
    terminal_v2_invoke,
    terminal_v2_create,
    terminal_v2_resume,
    terminal_v2_close,
    terminal_v2_exec,
    terminal_v2_write,
    terminal_v2_read,
    terminal_v2_resize,
};

const default_wait_timeout_ms: i64 = events_venom.default_wait_timeout_ms;
const wait_poll_interval_ms: u64 = events_venom.wait_poll_interval_ms;
const debug_stream_log_max_bytes: usize = 2 * 1024 * 1024;
const max_signal_events: usize = events_venom.max_signal_events;
const local_fs_world_prefix = "/nodes/local/fs";
const worker_reap_grace_ms: i64 = 60_000;

const agent_create_capabilities = [_][]const u8{
    "agents.create",
    "agent.create",
    "agents.manage",
    "agent_manage",
    "agent_admin",
    "provision_agents",
    "plan",
};

const WaitSourceKind = events_venom.WaitSourceKind;
const WaitSource = events_venom.WaitSource;
const SignalEventType = events_venom.SignalEventType;
const SignalEvent = events_venom.SignalEvent;
const WaitCandidate = events_venom.WaitCandidate;

const WriteOutcome = struct {
    written: usize,
    job_name: ?[]u8 = null,
    correlation_id: ?[]u8 = null,
    chat_reply_content: ?[]u8 = null,
};

const BoundVenomProxyPath = struct {
    venom_id: []const u8,
    remote_path: []const u8,
    project_id: ?[]const u8 = null,
    agent_id: ?[]const u8 = null,
};

const BoundVenomProxyAttrSummary = struct {
    kind: NodeKind,
    writable: bool,
};

const AsyncChatRuntimeContext = struct {
    allocator: std.mem.Allocator,
    runtime_handle: *runtime_handle_mod.RuntimeHandle,
    job_index: *chat_job_index.ChatJobIndex,
    control_plane: ?*control_plane_mod.ControlPlane = null,
    emit_debug: bool = false,
    agent_id: ?[]u8 = null,
    job_name: ?[]u8 = null,
    input: ?[]u8 = null,
    correlation_id: ?[]u8 = null,

    fn deinit(self: *AsyncChatRuntimeContext) void {
        if (self.agent_id) |value| self.allocator.free(value);
        if (self.job_name) |value| self.allocator.free(value);
        if (self.input) |value| self.allocator.free(value);
        if (self.correlation_id) |value| self.allocator.free(value);
        self.runtime_handle.release();
        self.allocator.destroy(self);
    }
};

const PathBind = struct {
    bind_path: []u8,
    target_path: []u8,

    fn deinit(self: *PathBind, allocator: std.mem.Allocator) void {
        allocator.free(self.bind_path);
        allocator.free(self.target_path);
        self.* = undefined;
    }
};

const ScopedVenomBinding = struct {
    venom_id: []u8,
    scope: []u8,
    venom_path: []u8,
    provider_node_id: ?[]u8 = null,
    provider_venom_path: ?[]u8 = null,
    endpoint_path: ?[]u8 = null,
    invoke_path: ?[]u8 = null,

    fn deinit(self: *ScopedVenomBinding, allocator: std.mem.Allocator) void {
        allocator.free(self.venom_id);
        allocator.free(self.scope);
        allocator.free(self.venom_path);
        if (self.provider_node_id) |value| allocator.free(value);
        if (self.provider_venom_path) |value| allocator.free(value);
        if (self.endpoint_path) |value| allocator.free(value);
        if (self.invoke_path) |value| allocator.free(value);
        self.* = undefined;
    }
};

const PairingAction = pairing_venom.Action;

const TerminalSession = terminal_venom.SessionState;

const Node = struct {
    id: u32,
    parent: ?u32,
    kind: NodeKind,
    name: []u8,
    writable: bool,
    content: []u8,
    children: std.StringHashMapUnmanaged(u32) = .{},
    special: SpecialKind = .none,

    fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.content);
        self.children.deinit(allocator);
        self.* = undefined;
    }
};

const FidState = struct {
    node_id: u32,
    is_open: bool = false,
    mode: []const u8 = "r",
};

pub const ToolPayloadErrorInfo = struct {
    code: []u8,
    message: []u8,

    pub fn deinit(self: ToolPayloadErrorInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.message);
    }
};

pub const AgentRunSuccessInfo = struct {
    run_id: []u8,
    state: []u8,
    assistant_output: ?[]u8 = null,
    step_count: u64 = 0,
    checkpoint_seq: u64 = 0,

    pub fn deinit(self: *AgentRunSuccessInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.run_id);
        allocator.free(self.state);
        if (self.assistant_output) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const AgentRunOutcome = union(enum) {
    success: AgentRunSuccessInfo,
    failure: ToolPayloadErrorInfo,

    pub fn deinit(self: *AgentRunOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |*value| value.deinit(allocator),
            .failure => |value| value.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const InternalFsrpcErrorInfo = struct {
    code: []u8,
    message: []u8,

    pub fn deinit(self: InternalFsrpcErrorInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.message);
    }
};

const InternalFsrpcIds = struct {
    attach_fid: u32,
    walk_fid: u32,
    tag_base: u32,
};

const WorkerPresence = struct {
    agent_id: []u8,
    last_seen_ms: i64,
    expires_at_ms: i64,

    fn deinit(self: *WorkerPresence, allocator: std.mem.Allocator) void {
        allocator.free(self.agent_id);
        self.* = undefined;
    }
};

fn deinitResponseFrames(allocator: std.mem.Allocator, frames: [][]u8) void {
    for (frames) |frame| allocator.free(frame);
    allocator.free(frames);
}

fn executeWithRuntimeHandle(
    raw_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    request_json: []const u8,
    emit_debug: bool,
) ![][]u8 {
    _ = allocator;
    const runtime_handle: *runtime_handle_mod.RuntimeHandle = @ptrCast(@alignCast(raw_ctx orelse return error.InvalidContext));
    return runtime_handle.handleMessageFramesWithDebug(request_json, emit_debug);
}

fn deinitResponseFramesWithContext(_: ?*anyopaque, allocator: std.mem.Allocator, frames: [][]u8) void {
    deinitResponseFrames(allocator, frames);
}

pub const Session = struct {
    pub const NamespaceOptions = struct {
        project_id: ?[]const u8 = null,
        project_token: ?[]const u8 = null,
        agents_dir: []const u8 = "agents",
        assets_dir: []const u8 = "templates",
        projects_dir: []const u8 = "projects",
        local_fs_export_root: ?[]const u8 = null,
        control_plane: ?*control_plane_mod.ControlPlane = null,
        mission_store: ?*mission_store_mod.MissionStore = null,
        control_operator_token: ?[]const u8 = null,
        actor_type: ?[]const u8 = null,
        actor_id: ?[]const u8 = null,
        is_admin: bool = false,
    };

    allocator: std.mem.Allocator,
    runtime_handle: *runtime_handle_mod.RuntimeHandle,
    job_index: *chat_job_index.ChatJobIndex,
    agent_id: []u8,
    actor_type: []u8,
    actor_id: []u8,
    project_id: ?[]u8 = null,
    active_namespace_project_id: ?[]u8 = null,
    project_token: ?[]u8 = null,
    agents_dir: []u8,
    assets_dir: []u8,
    projects_dir: []u8,
    local_fs_export_root: ?[]u8 = null,
    control_plane: ?*control_plane_mod.ControlPlane = null,
    mission_store: ?*mission_store_mod.MissionStore = null,
    control_operator_token: ?[]u8 = null,
    is_admin: bool = false,

    nodes: std.AutoHashMapUnmanaged(u32, Node) = .{},
    fids: std.AutoHashMapUnmanaged(u32, FidState) = .{},
    next_node_id: u32 = 1,
    next_internal_fsrpc_seq: u32 = 1,

    root_id: u32 = 0,
    nodes_root_id: u32 = 0,
    jobs_root_id: u32 = 0,
    chat_input_id: u32 = 0,
    thoughts_latest_id: u32 = 0,
    thoughts_history_id: u32 = 0,
    thoughts_status_id: u32 = 0,
    agent_venoms_index_id: u32 = 0,
    active_agent_venoms_index_id: u32 = 0,
    active_project_venoms_index_id: u32 = 0,
    node_venom_events_log_id: u32 = 0,
    event_next_id: u32 = 0,
    debug_stream_log_id: u32 = 0,
    pairing_pending_id: u32 = 0,
    pairing_last_result_id: u32 = 0,
    pairing_last_error_id: u32 = 0,
    pairing_invites_active_id: u32 = 0,
    pairing_invites_last_result_id: u32 = 0,
    pairing_invites_last_error_id: u32 = 0,
    terminal_status_id: u32 = 0,
    terminal_result_id: u32 = 0,
    terminal_sessions_id: u32 = 0,
    terminal_current_id: u32 = 0,
    sub_brains_status_id: u32 = 0,
    sub_brains_result_id: u32 = 0,
    agents_status_id: u32 = 0,
    agents_result_id: u32 = 0,
    projects_status_id: u32 = 0,
    projects_result_id: u32 = 0,
    git_status_id: u32 = 0,
    git_result_id: u32 = 0,
    git_status_alias_id: u32 = 0,
    git_result_alias_id: u32 = 0,
    github_pr_status_id: u32 = 0,
    github_pr_result_id: u32 = 0,
    github_pr_status_alias_id: u32 = 0,
    github_pr_result_alias_id: u32 = 0,
    pr_review_status_id: u32 = 0,
    pr_review_result_id: u32 = 0,
    pr_review_status_alias_id: u32 = 0,
    pr_review_result_alias_id: u32 = 0,
    missions_status_id: u32 = 0,
    missions_result_id: u32 = 0,
    missions_status_alias_id: u32 = 0,
    missions_result_alias_id: u32 = 0,
    mounts_status_id: u32 = 0,
    mounts_result_id: u32 = 0,
    mounts_status_alias_id: u32 = 0,
    mounts_result_alias_id: u32 = 0,
    home_status_id: u32 = 0,
    home_result_id: u32 = 0,
    home_status_alias_id: u32 = 0,
    home_result_alias_id: u32 = 0,
    workers_status_id: u32 = 0,
    workers_result_id: u32 = 0,
    workers_status_alias_id: u32 = 0,
    workers_result_alias_id: u32 = 0,
    venom_packages_status_id: u32 = 0,
    venom_packages_result_id: u32 = 0,
    venom_packages_status_alias_id: u32 = 0,
    venom_packages_result_alias_id: u32 = 0,
    wait_sources: std.ArrayListUnmanaged(WaitSource) = .{},
    wait_timeout_ms: i64 = default_wait_timeout_ms,
    wait_event_seq: u64 = 1,
    signal_events: std.ArrayListUnmanaged(SignalEvent) = .{},
    next_signal_seq: u64 = 1,
    terminal_sessions: std.StringHashMapUnmanaged(TerminalSession) = .{},
    current_terminal_session_id: ?[]u8 = null,
    next_terminal_session_seq: u64 = 1,
    next_thought_seq: u64 = 1,
    thought_job_sync_counts: std.StringHashMapUnmanaged(usize) = .{},
    worker_presence: std.StringHashMapUnmanaged(WorkerPresence) = .{},
    project_binds: std.ArrayListUnmanaged(PathBind) = .{},
    scoped_venom_bindings: std.ArrayListUnmanaged(ScopedVenomBinding) = .{},
    node_aliases: std.AutoHashMapUnmanaged(u32, u32) = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        runtime_handle: *runtime_handle_mod.RuntimeHandle,
        job_index: *chat_job_index.ChatJobIndex,
        agent_id: []const u8,
    ) !Session {
        return initWithOptions(allocator, runtime_handle, job_index, agent_id, .{});
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        runtime_handle: *runtime_handle_mod.RuntimeHandle,
        job_index: *chat_job_index.ChatJobIndex,
        agent_id: []const u8,
        options: NamespaceOptions,
    ) !Session {
        const owned_agent = try allocator.dupe(u8, agent_id);
        errdefer allocator.free(owned_agent);
        const owned_project = if (options.project_id) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_project) |value| allocator.free(value);
        const owned_project_token = if (options.project_token) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_project_token) |value| allocator.free(value);
        const actor_type_value = options.actor_type orelse "agent";
        const owned_actor_type = try allocator.dupe(u8, actor_type_value);
        errdefer allocator.free(owned_actor_type);
        const actor_id_value = options.actor_id orelse agent_id;
        const owned_actor_id = try allocator.dupe(u8, actor_id_value);
        errdefer allocator.free(owned_actor_id);
        const owned_agents_dir = try allocator.dupe(u8, options.agents_dir);
        errdefer allocator.free(owned_agents_dir);
        const owned_assets_dir = try allocator.dupe(u8, options.assets_dir);
        errdefer allocator.free(owned_assets_dir);
        const owned_projects_dir = try allocator.dupe(u8, options.projects_dir);
        errdefer allocator.free(owned_projects_dir);
        const owned_local_fs_export_root = if (options.local_fs_export_root) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_local_fs_export_root) |value| allocator.free(value);
        const owned_control_operator_token = if (options.control_operator_token) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_control_operator_token) |value| allocator.free(value);
        runtime_handle.retain();
        errdefer runtime_handle.release();

        var self = Session{
            .allocator = allocator,
            .runtime_handle = runtime_handle,
            .job_index = job_index,
            .agent_id = owned_agent,
            .actor_type = owned_actor_type,
            .actor_id = owned_actor_id,
            .project_id = owned_project,
            .project_token = owned_project_token,
            .agents_dir = owned_agents_dir,
            .assets_dir = owned_assets_dir,
            .projects_dir = owned_projects_dir,
            .local_fs_export_root = owned_local_fs_export_root,
            .control_plane = options.control_plane,
            .mission_store = options.mission_store,
            .control_operator_token = owned_control_operator_token,
            .is_admin = options.is_admin,
        };
        try self.seedNamespace();
        return self;
    }

    pub fn deinit(self: *Session) void {
        self.clearWaitSources();
        self.clearSignalEvents();
        self.clearTerminalSessions();
        self.clearProjectBinds();
        self.clearScopedVenomBindings();
        self.clearThoughtJobSyncCounts();
        self.clearWorkerPresence();
        self.node_aliases.deinit(self.allocator);
        var it = self.nodes.iterator();
        while (it.next()) |entry| {
            var node = entry.value_ptr.*;
            node.deinit(self.allocator);
        }
        self.nodes.deinit(self.allocator);
        self.fids.deinit(self.allocator);
        self.allocator.free(self.agent_id);
        self.allocator.free(self.actor_type);
        self.allocator.free(self.actor_id);
        if (self.project_id) |value| self.allocator.free(value);
        if (self.active_namespace_project_id) |value| self.allocator.free(value);
        if (self.project_token) |value| self.allocator.free(value);
        self.allocator.free(self.agents_dir);
        self.allocator.free(self.assets_dir);
        self.allocator.free(self.projects_dir);
        if (self.local_fs_export_root) |value| self.allocator.free(value);
        if (self.control_operator_token) |value| self.allocator.free(value);
        self.runtime_handle.release();
        self.* = undefined;
    }

    fn clearWorkerPresence(self: *Session) void {
        var it = self.worker_presence.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var presence = entry.value_ptr.*;
            presence.deinit(self.allocator);
        }
        self.worker_presence.deinit(self.allocator);
        self.worker_presence = .{};
    }

    pub fn setRuntimeBinding(
        self: *Session,
        runtime_handle: *runtime_handle_mod.RuntimeHandle,
        agent_id: []const u8,
    ) !void {
        try self.setRuntimeBindingWithOptions(
            runtime_handle,
            agent_id,
            .{
                .project_id = self.project_id,
                .project_token = self.project_token,
                .agents_dir = self.agents_dir,
                .assets_dir = self.assets_dir,
                .projects_dir = self.projects_dir,
                .local_fs_export_root = self.local_fs_export_root,
                .control_plane = self.control_plane,
                .mission_store = self.mission_store,
                .control_operator_token = self.control_operator_token,
                .actor_type = self.actor_type,
                .actor_id = self.actor_id,
                .is_admin = self.is_admin,
            },
        );
    }

    pub fn setRuntimeBindingWithOptions(
        self: *Session,
        runtime_handle: *runtime_handle_mod.RuntimeHandle,
        agent_id: []const u8,
        options: NamespaceOptions,
    ) !void {
        const rebound = try Session.initWithOptions(self.allocator, runtime_handle, self.job_index, agent_id, options);

        var previous = self.*;
        self.* = rebound;
        previous.deinit();
    }

    fn shouldEmitRuntimeDebugFrames(self: *const Session) bool {
        return self.debug_stream_log_id != 0;
    }

    fn recordRuntimeFrameForDebug(self: *Session, request_id: []const u8, frame: []const u8) !void {
        if (!self.shouldEmitRuntimeDebugFrames()) return;
        const debug_frame = try self.normalizeRuntimeFrameToDebugEvent(request_id, frame);
        defer self.allocator.free(debug_frame);

        try self.appendDebugStreamLogLine(debug_frame);
    }

    fn normalizeRuntimeFrameToDebugEvent(self: *Session, request_id: []const u8, frame: []const u8) ![]u8 {
        if (std.mem.indexOf(u8, frame, "\"type\":\"debug.event\"") != null) {
            return self.allocator.dupe(u8, frame);
        }

        const escaped_request_id = try unified.jsonEscape(self.allocator, request_id);
        defer self.allocator.free(escaped_request_id);

        const frame_type_json = blk: {
            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, frame, .{}) catch {
                break :blk try self.allocator.dupe(u8, "null");
            };
            defer parsed.deinit();
            if (parsed.value != .object) break :blk try self.allocator.dupe(u8, "null");
            const type_value = parsed.value.object.get("type") orelse break :blk try self.allocator.dupe(u8, "null");
            if (type_value != .string) break :blk try self.allocator.dupe(u8, "null");
            const escaped_type = try unified.jsonEscape(self.allocator, type_value.string);
            defer self.allocator.free(escaped_type);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_type});
        };
        defer self.allocator.free(frame_type_json);

        const payload_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"request_id\":\"{s}\",\"frame_type\":{s},\"frame\":{s}}}",
            .{ escaped_request_id, frame_type_json, frame },
        );
        defer self.allocator.free(payload_json);

        return protocol.buildDebugEvent(
            self.allocator,
            request_id,
            "runtime.frame",
            payload_json,
        );
    }

    fn appendDebugStreamLogLine(self: *Session, line: []const u8) !void {
        if (self.control_plane) |plane| {
            plane.appendDebugStreamEvent(self.agent_id, line);
        }
        if (self.debug_stream_log_id == 0) return;
        const node_ptr = self.nodes.getPtr(self.debug_stream_log_id) orelse return;
        if (node_ptr.kind != .file) return;

        var merged = std.ArrayListUnmanaged(u8){};
        defer merged.deinit(self.allocator);
        if (node_ptr.content.len > 0) {
            try merged.appendSlice(self.allocator, node_ptr.content);
            try merged.append(self.allocator, '\n');
        }
        try merged.appendSlice(self.allocator, line);

        const tail = if (merged.items.len <= debug_stream_log_max_bytes) blk: {
            break :blk merged.items;
        } else blk: {
            var start = merged.items.len - debug_stream_log_max_bytes;
            if (start > 0) {
                if (std.mem.indexOfScalarPos(u8, merged.items, start, '\n')) |nl| {
                    start = nl + 1;
                }
            }
            break :blk merged.items[start..];
        };

        const next = try self.allocator.dupe(u8, tail);
        self.allocator.free(node_ptr.content);
        node_ptr.content = next;
    }

    fn appendDebugEventsFromLogText(
        allocator: std.mem.Allocator,
        plane: *control_plane_mod.ControlPlane,
        agent_id: []const u8,
        log_text: []const u8,
    ) !void {
        var cursor: usize = 0;
        while (cursor < log_text.len) {
            const line_end = std.mem.indexOfScalarPos(u8, log_text, cursor, '\n') orelse log_text.len;
            const line = std.mem.trim(u8, log_text[cursor..line_end], " \t\r\n");
            if (line.len > 0 and line[0] == '{') {
                var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
                    cursor = if (line_end < log_text.len) line_end + 1 else line_end;
                    continue;
                };
                defer parsed.deinit();
                if (parsed.value == .object) {
                    const type_value = parsed.value.object.get("type") orelse {
                        cursor = if (line_end < log_text.len) line_end + 1 else line_end;
                        continue;
                    };
                    if (type_value == .string and std.mem.eql(u8, type_value.string, "debug.event")) {
                        plane.appendDebugStreamEvent(agent_id, line);
                    }
                }
            }
            cursor = if (line_end < log_text.len) line_end + 1 else line_end;
        }
    }

    fn syncDebugStreamLogFromControlPlane(self: *Session) !void {
        if (self.debug_stream_log_id == 0) return;
        const plane = self.control_plane orelse return;
        const snapshot = try plane.snapshotDebugStream(self.allocator, self.agent_id);
        defer self.allocator.free(snapshot);
        try self.setFileContent(self.debug_stream_log_id, snapshot);
    }

    fn syncNodeVenomEventsLogFromControlPlane(self: *Session) !void {
        if (self.node_venom_events_log_id == 0) return;
        const plane = self.control_plane orelse return;
        const snapshot = try plane.snapshotNodeVenomEvents(
            self.allocator,
            self.project_id,
            self.agent_id,
            self.project_token,
            self.is_admin,
            0,
        );
        defer self.allocator.free(snapshot);
        try self.setFileContent(self.node_venom_events_log_id, snapshot);
    }

    pub fn handle(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const msg_type = msg.acheron_type orelse {
            return unified.buildFsrpcError(self.allocator, msg.tag, "invalid_type", "missing acheron message type");
        };

        return switch (msg_type) {
            .t_version => self.handleVersion(msg),
            .t_attach => self.handleAttach(msg),
            .t_walk => self.handleWalk(msg),
            .t_open => self.handleOpen(msg),
            .t_read => self.handleRead(msg),
            .t_write => self.handleWrite(msg),
            .t_stat => self.handleStat(msg),
            .t_clunk => self.handleClunk(msg),
            .t_flush => self.handleFlush(msg),
            else => unified.buildFsrpcError(self.allocator, msg.tag, "unsupported", "unsupported acheron operation"),
        };
    }

    fn handleVersion(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const msize = msg.msize orelse 1_048_576;
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"msize\":{d},\"version\":\"acheron-1\"}}",
            .{msize},
        );
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_version, msg.tag, payload);
    }

    fn handleAttach(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");
        try self.fids.put(self.allocator, fid, .{ .node_id = self.root_id });

        const escaped_project_id = if (self.project_id) |project_id|
            try unified.jsonEscape(self.allocator, project_id)
        else
            null;
        defer if (escaped_project_id) |value| self.allocator.free(value);
        const project_id_json = if (escaped_project_id) |value|
            try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{value})
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(project_id_json);
        const debug_visible = self.lookupChild(self.root_id, "debug") != null;
        const services_visible = self.lookupChild(self.root_id, "services") != null;
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"qid\":{{\"path\":{d},\"type\":\"dir\"}},\"layout\":\"unified-v2-fs\",\"project_id\":{s},\"roots\":[\"nodes\",\"agents\",\"global\"{s}{s}],\"dynamic_bind_paths\":{s},\"bind_count\":{d}}}",
            .{
                self.root_id,
                project_id_json,
                if (services_visible) ",\"services\"" else "",
                if (debug_visible) ",\"debug\"" else "",
                if (self.project_binds.items.len > 0) "true" else "false",
                self.project_binds.items.len,
            },
        );
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_attach, msg.tag, payload);
    }

    fn handleWalk(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");
        const newfid = msg.newfid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "newfid is required");

        const start = self.fids.get(fid) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "enoent", "unknown fid");
        var node_id = start.node_id;

        for (msg.path) |segment| {
            if (std.mem.eql(u8, segment, ".")) continue;
            if (std.mem.eql(u8, segment, "..")) {
                if (self.nodes.get(node_id)) |current| {
                    if (current.parent) |parent_id| node_id = parent_id;
                }
                continue;
            }

            self.refreshDynamicDirectory(node_id) catch |err| {
                std.log.warn("dynamic directory refresh failed during walk: {s}", .{@errorName(err)});
            };
            const next = (try self.resolveWalkChild(node_id, segment)) orelse {
                return unified.buildFsrpcError(self.allocator, msg.tag, "enoent", "walk segment not found");
            };
            node_id = next;
        }

        try self.fids.put(self.allocator, newfid, .{ .node_id = node_id });
        const node = self.nodes.get(node_id) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "eio", "missing node");

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"qid\":{{\"path\":{d},\"type\":\"{s}\"}},\"walked\":{d}}}",
            .{ node_id, kindName(node.kind), msg.path.len },
        );
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_walk, msg.tag, payload);
    }

    fn handleOpen(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");

        var state = self.fids.get(fid) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "enoent", "unknown fid");
        const node = self.nodes.get(state.node_id) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "eio", "missing node");

        const mode = msg.mode orelse "r";
        const wants_write = std.mem.indexOfScalar(u8, mode, 'w') != null;
        if (node.kind == .dir and wants_write) {
            return unified.buildFsrpcError(self.allocator, msg.tag, "eisdir", "directories are read-only opens");
        }
        if (node.kind == .file and wants_write and !node.writable) {
            return unified.buildFsrpcError(self.allocator, msg.tag, "eperm", "file is read-only");
        }

        state.is_open = true;
        state.mode = mode;
        try self.fids.put(self.allocator, fid, state);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"qid\":{{\"path\":{d},\"type\":\"{s}\"}},\"iounit\":65536}}",
            .{ node.id, kindName(node.kind) },
        );
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_open, msg.tag, payload);
    }

    fn handleRead(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");
        const offset = msg.offset orelse 0;
        const count = msg.count orelse 65536;

        const state = self.fids.get(fid) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "enoent", "unknown fid");
        const node = self.nodes.get(state.node_id) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "eio", "missing node");

        if (node.kind == .dir) {
            self.refreshDynamicDirectory(state.node_id) catch |err| {
                std.log.warn("dynamic directory refresh failed during read: {s}", .{@errorName(err)});
            };
        }

        var data_owned: ?[]u8 = null;
        defer if (data_owned) |value| self.allocator.free(value);

        const data = switch (node.kind) {
            .dir => blk: {
                data_owned = try self.renderDirListing(state.node_id);
                break :blk data_owned.?;
            },
            .file => blk: {
                var used_bound_proxy = false;
                if (try self.tryReadBoundVenomProxyFile(state.node_id)) |proxied| {
                    defer self.allocator.free(proxied);
                    try self.setFileContent(state.node_id, proxied);
                    used_bound_proxy = true;
                }
                if (offset == 0 and !used_bound_proxy) {
                    _ = try self.syncLocalFsFileNode(state.node_id);
                    if (state.node_id == self.debug_stream_log_id) {
                        try self.syncDebugStreamLogFromControlPlane();
                    }
                    switch (node.special) {
                        .job_status => {
                            try self.refreshJobNodeFromIndex(state.node_id, node.special);
                        },
                        .job_result => {
                            try self.refreshJobNodeFromIndex(state.node_id, node.special);
                        },
                        .job_log => {
                            try self.refreshJobNodeFromIndex(state.node_id, node.special);
                        },
                        .agent_venoms_index => {
                            try self.refreshScopedVenomIndexes();
                        },
                        .node_venom_events_log => {
                            try self.syncNodeVenomEventsLogFromControlPlane();
                        },
                        .event_next => {
                            data_owned = try self.handleEventNextRead();
                            try self.setFileContent(state.node_id, data_owned.?);
                        },
                        else => {},
                    }
                }
                const refreshed = self.nodes.get(state.node_id) orelse {
                    return unified.buildFsrpcError(self.allocator, msg.tag, "eio", "missing node");
                };
                break :blk refreshed.content;
            },
        };

        const start = std.math.cast(usize, offset) orelse {
            return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "read offset is out of range");
        };

        if (start >= data.len) {
            const payload = "{\"data_b64\":\"\",\"n\":0,\"eof\":true}";
            return unified.buildFsrpcResponse(self.allocator, .r_read, msg.tag, payload);
        }

        const requested_end = std.math.add(usize, start, @as(usize, count)) catch std.math.maxInt(usize);
        const end = @min(data.len, requested_end);
        const chunk = data[start..end];
        const encoded = try unified.encodeDataB64(self.allocator, chunk);
        defer self.allocator.free(encoded);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"data_b64\":\"{s}\",\"n\":{d},\"eof\":{s}}}",
            .{ encoded, chunk.len, if (end >= data.len) "true" else "false" },
        );
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_read, msg.tag, payload);
    }

    fn refreshDynamicDirectory(self: *Session, dir_id: u32) !void {
        try self.reapExpiredWorkerNodes();
        try self.refreshWorkerPresenceStatuses();
        if (dir_id == self.nodes_root_id) {
            try self.addNodeDirectoriesFromControlPlane(self.nodes_root_id);
        }
        try self.refreshLocalFsDirectory(dir_id);
        try self.refreshBoundVenomProxyDirectory(dir_id);
    }

    fn refreshLocalFsDirectory(self: *Session, dir_id: u32) !void {
        const host_path = (try self.localFsNodeHostPath(dir_id)) orelse return;
        defer self.allocator.free(host_path);

        var host_dir = if (std.fs.path.isAbsolute(host_path))
            std.fs.openDirAbsolute(host_path, .{ .iterate = true }) catch return
        else
            std.fs.cwd().openDir(host_path, .{ .iterate = true }) catch return;
        defer host_dir.close();

        var iterator = host_dir.iterate();
        while (try iterator.next()) |entry| {
            if (entry.name.len == 0) continue;
            if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
            if (self.lookupChild(dir_id, entry.name) != null) continue;

            switch (entry.kind) {
                .directory => _ = try self.addDir(dir_id, entry.name, false),
                .file, .sym_link, .unknown => _ = try self.addFile(dir_id, entry.name, "", true, .none),
                else => {},
            }
        }
    }

    fn localFsNodeHostPath(self: *Session, node_id: u32) !?[]u8 {
        if (self.local_fs_export_root == null) return null;
        const absolute_path = try self.nodeAbsolutePath(node_id);
        defer self.allocator.free(absolute_path);
        if (!pathMatchesPrefixBoundary(absolute_path, local_fs_world_prefix)) return null;
        return try self.resolveMissionContractHostPath(absolute_path);
    }

    fn resolveLocalFsSafeHostPath(self: *Session, host_path: []const u8) !?[]u8 {
        const export_root = self.local_fs_export_root orelse return null;
        const resolved_root = if (std.fs.path.isAbsolute(export_root))
            std.fs.realpathAlloc(self.allocator, export_root) catch return null
        else
            std.fs.cwd().realpathAlloc(self.allocator, export_root) catch return null;
        defer self.allocator.free(resolved_root);

        const resolved_host = if (std.fs.path.isAbsolute(host_path))
            std.fs.realpathAlloc(self.allocator, host_path) catch return null
        else
            std.fs.cwd().realpathAlloc(self.allocator, host_path) catch return null;
        errdefer self.allocator.free(resolved_host);

        if (!pathMatchesPrefixBoundary(resolved_host, resolved_root)) return null;
        return resolved_host;
    }

    fn syncLocalFsFileNode(self: *Session, node_id: u32) !bool {
        const host_path = (try self.localFsNodeHostPath(node_id)) orelse return false;
        defer self.allocator.free(host_path);

        const safe_host_path = (try self.resolveLocalFsSafeHostPath(host_path)) orelse return false;
        defer self.allocator.free(safe_host_path);

        var file = if (std.fs.path.isAbsolute(safe_host_path))
            std.fs.openFileAbsolute(safe_host_path, .{}) catch return false
        else
            std.fs.cwd().openFile(safe_host_path, .{}) catch return false;
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);
        try self.setFileContent(node_id, content);
        return true;
    }

    fn handleWrite(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");
        const data = msg.data orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "write requires data");
        const offset = msg.offset orelse 0;

        const state = self.fids.get(fid) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "enoent", "unknown fid");
        const node = self.nodes.get(state.node_id) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "eio", "missing node");
        if (node.kind != .file) return unified.buildFsrpcError(self.allocator, msg.tag, "eisdir", "write requires file fid");
        if (!node.writable) return unified.buildFsrpcError(self.allocator, msg.tag, "eperm", "file is read-only");

        var written: usize = data.len;
        var job_name: ?[]u8 = null;
        var correlation_id: ?[]u8 = null;
        var chat_reply_content: ?[]u8 = null;
        defer if (job_name) |value| self.allocator.free(value);
        defer if (correlation_id) |value| self.allocator.free(value);
        defer if (chat_reply_content) |value| self.allocator.free(value);
        if (isTerminalV2Special(node.special) and !self.canInvokeTerminalNamespace(state.node_id)) {
            return unified.buildFsrpcError(
                self.allocator,
                msg.tag,
                "eperm",
                "terminal invoke access denied by permissions",
            );
        }
        if (try self.tryWriteBoundVenomProxyFile(state.node_id, offset, data)) |proxied| {
            written = proxied.written;
            job_name = proxied.job_name;
            correlation_id = proxied.correlation_id;
            chat_reply_content = proxied.chat_reply_content;
        } else switch (node.special) {
            .chat_input => {
                const outcome = try self.handleChatInputWrite(msg, data);
                written = outcome.written;
                job_name = outcome.job_name;
                correlation_id = outcome.correlation_id;
            },
            .chat_reply => {
                const outcome = try self.handleChatReplyWrite(state.node_id, data);
                written = outcome.written;
                chat_reply_content = outcome.chat_reply_content;
            },
            .job_status => {
                const outcome = self.handleJobStatusWrite(state.node_id, offset, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "job status payload must be a JSON object with state=queued|running|done|failed and optional error",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .job_result => {
                const outcome = try self.handleJobResultWrite(state.node_id, offset, data);
                written = outcome.written;
            },
            .job_log => {
                const outcome = try self.handleJobLogWrite(state.node_id, offset, data);
                written = outcome.written;
            },
            .event_wait_config => {
                const outcome = self.handleEventWaitConfigWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "wait.json payload must include non-empty paths[] and optional timeout_ms",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .event_signal => {
                const outcome = self.handleEventSignalWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "signal.json payload must be an object with event_type=user|agent|hook and optional parameter/payload",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .web_search_invoke,
            .web_search_search,
            .search_code_invoke,
            .search_code_search,
            => {
                const outcome = self.handleSearchNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "search payload must be a JSON object; invoke accepts optional op/tool_name plus arguments/args",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "search invoke access denied by permissions",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .mounts_invoke,
            .mounts_list,
            .mounts_mount,
            .mounts_mkdir,
            .mounts_unmount,
            .mounts_bind,
            .mounts_unbind,
            .mounts_resolve,
            => {
                const outcome = self.handleMountsNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "mounts payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "mounts/binds operation denied by project policy",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .home_invoke,
            .home_ensure,
            => {
                const outcome = self.handleHomeNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "home payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "home operation denied by project policy",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .workers_invoke,
            .workers_register,
            .workers_heartbeat,
            .workers_detach,
            => {
                const outcome = self.handleWorkersNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "workers payload is invalid for requested operation",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .venom_packages_invoke,
            .venom_packages_list,
            .venom_packages_get,
            .venom_packages_install,
            .venom_packages_remove,
            => {
                const outcome = self.handleVenomPackagesNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "venom_packages payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "venom package operation denied by policy",
                        );
                    },
                    error.AlreadyExists => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eexist",
                            "venom package already installed",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .agents_invoke => {
                const outcome = self.handleAgentsInvokeWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "agents invoke payload must include op=list|create and optional arguments/args",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "agent creation requires capability",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .agents_list => {
                const outcome = self.handleAgentsListWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "agents list payload must be empty or a JSON object",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .agents_create => {
                const outcome = self.handleAgentsCreateWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "agents create payload requires agent_id (or id) and optional metadata/project fields",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "agent creation requires capability",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .projects_invoke,
            .projects_list,
            .projects_get,
            .projects_up,
            => {
                const outcome = self.handleWorkspacesNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "workspace payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "workspace operation denied by policy",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .git_invoke,
            .git_sync_checkout,
            .git_status,
            .git_diff_range,
            => {
                const outcome = self.handleGitNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "git payload is invalid for requested operation",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .github_pr_invoke,
            .github_pr_sync,
            .github_pr_ingest_event,
            .github_pr_publish_review,
            => {
                const outcome = self.handleGitHubPrNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "github_pr payload is invalid for requested operation",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .pr_review_invoke,
            .pr_review_configure_repo,
            .pr_review_get_repo,
            .pr_review_list_repos,
            .pr_review_intake,
            .pr_review_start,
            .pr_review_sync,
            .pr_review_run_validation,
            .pr_review_record_validation,
            .pr_review_draft_review,
            .pr_review_save_draft,
            .pr_review_record_review,
            .pr_review_advance,
            => {
                const outcome = self.handlePrReviewNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "pr_review payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "pr_review operation denied by policy",
                        );
                    },
                    error.NotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "pr_review mission not found",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .missions_invoke,
            .missions_invoke_service,
            .missions_create,
            .missions_list,
            .missions_get,
            .missions_heartbeat,
            .missions_checkpoint,
            .missions_recover,
            .missions_request_approval,
            .missions_approve,
            .missions_reject,
            .missions_resume,
            .missions_block,
            .missions_complete,
            .missions_fail,
            .missions_cancel,
            => {
                const outcome = self.handleMissionsNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "missions payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "missions operation requires admin approval privileges",
                        );
                    },
                    error.NotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "mission not found",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .pairing_refresh => {
                const outcome = try self.handlePairingControlWrite(.refresh, data);
                written = outcome.written;
            },
            .pairing_approve => {
                const outcome = try self.handlePairingControlWrite(.approve, data);
                written = outcome.written;
            },
            .pairing_deny => {
                const outcome = try self.handlePairingControlWrite(.deny, data);
                written = outcome.written;
            },
            .pairing_invites_refresh => {
                const outcome = try self.handlePairingControlWrite(.invites_refresh, data);
                written = outcome.written;
            },
            .pairing_invites_create => {
                const outcome = try self.handlePairingControlWrite(.invites_create, data);
                written = outcome.written;
            },
            .terminal_v2_invoke => {
                const outcome = self.handleTerminalV2InvokeWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal invoke payload must include op=create|resume|close|write|read|resize|exec or matching fields",
                        );
                    },
                    error.TerminalSessionNotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "terminal session not found",
                        );
                    },
                    error.TerminalSessionClosed => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "terminal session is closed",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    error.TerminalPtyUnavailable => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unavailable",
                            "pty backend unavailable: install util-linux script",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .terminal_v2_create => {
                const outcome = self.handleTerminalV2CreateWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal create payload must be a JSON object with optional session_id/label/cwd",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    error.TerminalPtyUnavailable => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unavailable",
                            "pty backend unavailable: install util-linux script",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .terminal_v2_resume => {
                const outcome = self.handleTerminalV2ResumeWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal resume payload must include session_id",
                        );
                    },
                    error.TerminalSessionNotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "terminal session not found",
                        );
                    },
                    error.TerminalSessionClosed => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "terminal session is closed",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .terminal_v2_close => {
                const outcome = self.handleTerminalV2CloseWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal close payload must include session_id or use an active session",
                        );
                    },
                    error.TerminalSessionNotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "terminal session not found",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .terminal_v2_exec => {
                const outcome = self.handleTerminalV2ExecWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal exec payload must include command or argv (optional session_id/cwd)",
                        );
                    },
                    error.TerminalSessionNotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "terminal session not found",
                        );
                    },
                    error.TerminalSessionClosed => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "terminal session is closed",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .terminal_v2_write => {
                const outcome = self.handleTerminalV2WriteWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal write payload must include input/command/data_b64 (optional session_id)",
                        );
                    },
                    error.TerminalSessionNotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "terminal session not found",
                        );
                    },
                    error.TerminalSessionClosed => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "terminal session is closed",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .terminal_v2_read => {
                const outcome = self.handleTerminalV2ReadWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal read payload must be object with optional session_id/max_bytes/timeout_ms",
                        );
                    },
                    error.TerminalSessionNotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "terminal session not found",
                        );
                    },
                    error.TerminalSessionClosed => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "terminal session is closed",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .terminal_v2_resize => {
                const outcome = self.handleTerminalV2ResizeWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "terminal resize payload must include cols and rows (optional session_id)",
                        );
                    },
                    error.TerminalSessionNotFound => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "enoent",
                            "terminal session not found",
                        );
                    },
                    error.TerminalSessionClosed => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "terminal session is closed",
                        );
                    },
                    error.UnsupportedPlatform => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "unsupported",
                            "pty terminal sessions are currently supported on linux only",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            else => {
                self.writeFileContent(state.node_id, offset, data) catch |err| switch (err) {
                    error.InvalidOffset => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "write offset is out of range",
                        );
                    },
                    else => return err,
                };
            },
        }

        const payload = if (job_name) |job| blk: {
            const escaped = try unified.jsonEscape(self.allocator, job);
            defer self.allocator.free(escaped);
            const result_path = try self.buildJobResultPathForNode(state.node_id, job);
            defer self.allocator.free(result_path);
            const escaped_result_path = try unified.jsonEscape(self.allocator, result_path);
            defer self.allocator.free(escaped_result_path);
            if (correlation_id) |corr| {
                const escaped_corr = try unified.jsonEscape(self.allocator, corr);
                defer self.allocator.free(escaped_corr);
                break :blk try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"n\":{d},\"job\":\"{s}\",\"result_path\":\"{s}\",\"correlation_id\":\"{s}\"}}",
                    .{ written, escaped, escaped_result_path, escaped_corr },
                );
            }
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"n\":{d},\"job\":\"{s}\",\"result_path\":\"{s}\"}}",
                .{ written, escaped, escaped_result_path },
            );
        } else if (chat_reply_content) |reply| blk: {
            const escaped_reply = try unified.jsonEscape(self.allocator, reply);
            defer self.allocator.free(escaped_reply);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"n\":{d},\"chat_reply\":{{\"delivered\":true,\"content\":\"{s}\"}}}}",
                .{ written, escaped_reply },
            );
        } else try std.fmt.allocPrint(self.allocator, "{{\"n\":{d}}}", .{written});
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_write, msg.tag, payload);
    }

    fn handleStat(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");
        const state = self.fids.get(fid) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "enoent", "unknown fid");
        const node = self.nodes.get(state.node_id) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "eio", "missing node");

        if (try self.buildBoundVenomProxyStatPayload(state.node_id)) |payload| {
            defer self.allocator.free(payload);
            return unified.buildFsrpcResponse(self.allocator, .r_stat, msg.tag, payload);
        }

        const escaped_name = try unified.jsonEscape(self.allocator, node.name);
        defer self.allocator.free(escaped_name);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":{d},\"name\":\"{s}\",\"kind\":\"{s}\",\"size\":{d},\"mode\":{d},\"writable\":{s}}}",
            .{ node.id, escaped_name, kindName(node.kind), node.content.len, nodeMode(node), if (node.writable) "true" else "false" },
        );
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_stat, msg.tag, payload);
    }

    fn handleClunk(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");
        _ = self.fids.remove(fid);
        return unified.buildFsrpcResponse(self.allocator, .r_clunk, msg.tag, "{}");
    }

    fn handleFlush(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        return unified.buildFsrpcResponse(self.allocator, .r_flush, msg.tag, "{}");
    }

    fn seedNamespace(self: *Session) !void {
        var policy = try workspace_policy.loadWorkspacePolicy(
            self.allocator,
            .{
                .agent_id = self.agent_id,
                .project_id = self.project_id,
                .agents_dir = self.agents_dir,
                .projects_dir = self.projects_dir,
            },
        );
        defer policy.deinit(self.allocator);
        if (self.active_namespace_project_id) |value| self.allocator.free(value);
        self.active_namespace_project_id = try self.allocator.dupe(u8, policy.project_id);
        const show_debug = policy.show_debug or self.is_admin;

        self.root_id = try self.addDir(null, "/", false);
        const nodes_root = try self.addDir(self.root_id, "nodes", false);
        self.nodes_root_id = nodes_root;
        const agents_root = try self.addDir(self.root_id, "agents", false);
        const projects_root = try self.addDir(self.root_id, "projects", false);
        const global_root = try self.addDir(self.root_id, "global", false);
        const meta_root = try self.addDir(self.root_id, "meta", false);
        const debug_root: ?u32 = if (show_debug)
            try self.addDir(self.root_id, "debug", false)
        else
            null;

        try self.addDirectoryDescriptors(
            nodes_root,
            "Nodes",
            "{\"kind\":\"collection\",\"entries\":\"node directories\",\"shape\":\"/nodes/<node_id>/{services,fs,camera,screen,user,terminal}\"}",
            "{\"read\":true,\"write\":false}",
            "Connected node resources are surfaced here.",
        );
        try self.addDirectoryDescriptors(
            agents_root,
            "Agents",
            "{\"kind\":\"collection\",\"entries\":\"agent directories\",\"shape\":\"/agents/<agent_id>\"}",
            "{\"read\":true,\"write\":true}",
            "Agent identities attached to this project namespace.",
        );
        try self.addDirectoryDescriptors(
            projects_root,
            "Projects",
            "{\"kind\":\"collection\",\"entries\":\"project directories\",\"shape\":\"/projects/<project_id>/{fs,nodes,agents,meta}\"}",
            "{\"read\":true,\"write\":false}",
            "Attached-session compatibility view for project metadata and links.",
        );
        try self.addDirectoryDescriptors(
            global_root,
            "Global",
            "{\"kind\":\"collection\",\"entries\":\"global namespaces\",\"shape\":\"/global/<venom_id>\"}",
            "{\"read\":true,\"write\":false}",
            "System-wide stable namespaces shared across agents/projects.",
        );
        try self.addNodeDirectoriesFromControlPlane(nodes_root);
        for (policy.nodes.items) |node| {
            if (self.lookupChild(nodes_root, node.id) != null) continue;
            try self.addNodeDirectory(nodes_root, node, false);
        }
        try self.seedLocalCatalogServiceNamespaces(global_root);

        const active_agent_dir = try self.addDir(agents_root, self.agent_id, false);
        _ = try self.addFile(active_agent_dir, "README.md", "Active agent identity in this project namespace.\n", false, .none);
        const active_agent_venoms_dir = try self.addDir(active_agent_dir, "venoms", false);
        try self.addDirectoryDescriptors(
            active_agent_venoms_dir,
            "Agent Venoms",
            "{\"kind\":\"venom_index\",\"files\":[\"VENOMS.json\"],\"roots\":[\"/agents/<agent_id>/venoms/<venom_id>\",\"/nodes/<node_id>/venoms/<venom_id>\"]}",
            "{\"discover\":true,\"invoke_via_paths\":true}",
            "Active-agent Venom bindings plus raw node Venom discovery.",
        );
        self.active_agent_venoms_index_id = try self.addFile(
            active_agent_venoms_dir,
            "VENOMS.json",
            "[]",
            false,
            .agent_venoms_index,
        );
        const agent_venoms_dir = try self.addDir(global_root, "venoms", false);
        try self.addDirectoryDescriptors(
            agent_venoms_dir,
            "Venoms",
            "{\"kind\":\"venom_index\",\"files\":[\"VENOMS.json\",\"node-venom-events.ndjson\"],\"roots\":[\"/nodes/<node_id>/venoms/<venom_id>\",\"/global/<venom_id>\"]}",
            "{\"discover\":true,\"invoke_via_paths\":true}",
            "Project-wide Venom discovery index plus retained node Venom change history.",
        );
        self.agent_venoms_index_id = try self.addFile(
            agent_venoms_dir,
            "VENOMS.json",
            "[]",
            false,
            .agent_venoms_index,
        );
        self.node_venom_events_log_id = try self.addFile(
            agent_venoms_dir,
            "node-venom-events.ndjson",
            "",
            false,
            .node_venom_events_log,
        );

        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
            if (std.mem.eql(u8, agent_name, self.agent_id)) continue;
            const agent_dir = try self.addDir(agents_root, agent_name, false);
            _ = try self.addFile(agent_dir, "README.md", "Visible peer agent entry.\n", false, .none);
            const link = try std.fmt.allocPrint(self.allocator, "/agents/{s}\n", .{agent_name});
            defer self.allocator.free(link);
            _ = try self.addFile(agent_dir, "LINK.txt", link, false, .none);
        }

        const project_dir = try self.addDir(projects_root, policy.project_id, false);
        const project_fs_dir = try self.addDir(project_dir, "fs", false);
        const project_nodes_dir = try self.addDir(project_dir, "nodes", false);
        const project_agents_dir = try self.addDir(project_dir, "agents", false);
        const project_meta_dir = try self.addDir(project_dir, "meta", false);
        const project_venoms_dir = try self.addDir(project_dir, "venoms", false);
        try self.addDirectoryDescriptors(
            project_dir,
            "Project",
            "{\"kind\":\"project\",\"children\":[\"fs\",\"nodes\",\"agents\",\"venoms\",\"meta\"]}",
            "{\"read\":true,\"write\":false}",
            "Attached-session compatibility projection for the active project.",
        );
        try self.addDirectoryDescriptors(
            project_fs_dir,
            "Project Mounts",
            "{\"kind\":\"collection\",\"entries\":\"mount links\",\"source\":\"control.workspace_status mounts\"}",
            "{\"read\":true,\"write\":false}",
            "Mount links for the active project compatibility view.",
        );
        try self.addDirectoryDescriptors(
            project_nodes_dir,
            "Project Nodes",
            "{\"kind\":\"collection\",\"entries\":\"node links\",\"source\":\"control.workspace_status selected mounts\"}",
            "{\"read\":true,\"write\":false}",
            "Node links for the active project compatibility view.",
        );
        try self.addDirectoryDescriptors(
            project_agents_dir,
            "Project Agents",
            "{\"kind\":\"collection\",\"entries\":\"agent links\",\"scope\":\"project\",\"targets\":\"/projects/<project_id>/agents/<agent_id>\"}",
            "{\"read\":true,\"write\":false}",
            "Agent links visible within this project context.",
        );
        try self.addDirectoryDescriptors(
            project_venoms_dir,
            "Project Venoms",
            "{\"kind\":\"venom_index\",\"files\":[\"VENOMS.json\"],\"roots\":[\"/projects/<project_id>/venoms/<venom_id>\",\"/nodes/<node_id>/venoms/<venom_id>\"]}",
            "{\"discover\":true,\"invoke_via_paths\":true}",
            "Project-scoped Venom bindings plus raw node Venom discovery.",
        );
        self.active_project_venoms_index_id = try self.addFile(
            project_venoms_dir,
            "VENOMS.json",
            "[]",
            false,
            .agent_venoms_index,
        );
        try self.addDirectoryDescriptors(
            project_meta_dir,
            "Project Metadata",
            "{\"kind\":\"metadata\",\"files\":[\"topology.json\",\"nodes.json\",\"agents.json\",\"sources.json\",\"contracts.json\",\"paths.json\",\"summary.json\",\"alerts.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"binds.json\",\"mounted_services.json\",\"venom_packages.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"]}",
            "{\"read\":true,\"write\":false}",
            "Project topology and availability metadata.",
        );

        const workspace_status_json = try self.loadProjectWorkspaceStatus(policy.project_id);
        defer if (workspace_status_json) |value| self.allocator.free(value);
        const loaded_live_mounts = if (workspace_status_json) |json|
            try self.addProjectFsLinksFromWorkspaceStatus(project_fs_dir, nodes_root, policy, json)
        else
            false;
        if (!loaded_live_mounts) try self.addProjectFsLinksFromPolicy(project_fs_dir, policy);
        try self.addProjectNodeLinksFromPolicy(project_nodes_dir, policy);
        const loaded_live_nodes = if (workspace_status_json) |json|
            try self.addProjectNodeLinksFromWorkspaceStatus(project_nodes_dir, policy, json)
        else
            false;

        const active_agent_target = try std.fmt.allocPrint(
            self.allocator,
            "/projects/{s}/agents/{s}\n",
            .{ policy.project_id, self.agent_id },
        );
        defer self.allocator.free(active_agent_target);
        _ = try self.addFile(project_agents_dir, self.agent_id, active_agent_target, false, .none);
        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
            if (std.mem.eql(u8, agent_name, self.agent_id)) continue;
            const target = try std.fmt.allocPrint(
                self.allocator,
                "/projects/{s}/agents/{s}\n",
                .{ policy.project_id, agent_name },
            );
            defer self.allocator.free(target);
            _ = try self.addFile(project_agents_dir, agent_name, target, false, .none);
        }

        try self.addProjectMetaFiles(
            project_meta_dir,
            policy,
            workspace_status_json,
            loaded_live_mounts,
            loaded_live_nodes,
        );

        if (debug_root) |dir_id| {
            try self.addDirectoryDescriptors(
                dir_id,
                "Debug",
                "{\"kind\":\"debug\",\"entries\":[\"README.md\",\"stream.log\",\"pairing\"]}",
                "{\"read\":true,\"write\":false}",
                "Privileged debug surface.",
            );
            self.debug_stream_log_id = try self.addFile(dir_id, "stream.log", "", false, .none);
            try self.addDebugPairingSurface(dir_id);
        }

        try self.addDirectoryDescriptors(
            meta_root,
            "Meta",
            "{\"kind\":\"meta\",\"entries\":[\"protocol.json\",\"view.json\",\"workspace_status.json\",\"workspace_availability.json\",\"workspace_health.json\",\"workspace_alerts.json\",\"workspace_binds.json\",\"workspace_services.json\",\"venom_packages.json\"]}",
            "{\"read\":true,\"write\":false}",
            "Attached-session compatibility metadata.",
        );
        const protocol_json =
            "{\"channel\":\"acheron\",\"version\":\"acheron-1\",\"layout\":\"acheron-namespace-project-contract-v2\",\"ops\":[\"t_version\",\"t_attach\",\"t_walk\",\"t_open\",\"t_read\",\"t_write\",\"t_stat\",\"t_clunk\",\"t_flush\"]}";
        _ = try self.addFile(meta_root, "protocol.json", protocol_json, false, .none);
        const escaped_agent = try unified.jsonEscape(self.allocator, self.agent_id);
        defer self.allocator.free(escaped_agent);
        const escaped_project = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project);
        const view_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"show_debug\":{s},\"nodes\":{d},\"visible_agents\":{d},\"project_links\":{d}}}",
            .{
                escaped_agent,
                escaped_project,
                if (show_debug) "true" else "false",
                policy.nodes.items.len,
                policy.visible_agents.items.len,
                policy.project_links.items.len,
            },
        );
        defer self.allocator.free(view_json);
        _ = try self.addFile(meta_root, "view.json", view_json, false, .none);
        if (workspace_status_json) |status_json| {
            _ = try self.addFile(meta_root, "workspace_status.json", status_json, false, .none);
            if (try self.extractWorkspaceAvailability(status_json)) |availability_json| {
                defer self.allocator.free(availability_json);
                _ = try self.addFile(meta_root, "workspace_availability.json", availability_json, false, .none);
            } else {
                _ = try self.addFile(meta_root, "workspace_availability.json", "{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0}", false, .none);
            }
            if (try self.extractWorkspaceHealth(status_json)) |health_json| {
                defer self.allocator.free(health_json);
                _ = try self.addFile(meta_root, "workspace_health.json", health_json, false, .none);
            } else {
                _ = try self.addFile(meta_root, "workspace_health.json", "{\"state\":\"unknown\",\"availability\":{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0},\"drift_count\":0,\"reconcile_state\":\"unknown\",\"queue_depth\":0}", false, .none);
            }
            if (try self.extractWorkspaceAlerts(status_json)) |alerts_json| {
                defer self.allocator.free(alerts_json);
                _ = try self.addFile(meta_root, "workspace_alerts.json", alerts_json, false, .none);
            } else {
                _ = try self.addFile(meta_root, "workspace_alerts.json", "[]", false, .none);
            }
        } else {
            const fallback_status = try self.buildFallbackWorkspaceStatusJson(policy);
            defer self.allocator.free(fallback_status);
            _ = try self.addFile(meta_root, "workspace_status.json", fallback_status, false, .none);
            _ = try self.addFile(meta_root, "workspace_availability.json", "{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0}", false, .none);
            _ = try self.addFile(meta_root, "workspace_health.json", "{\"state\":\"unknown\",\"availability\":{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0},\"drift_count\":0,\"reconcile_state\":\"unknown\",\"queue_depth\":0}", false, .none);
            _ = try self.addFile(meta_root, "workspace_alerts.json", "[]", false, .none);
        }

        try self.refreshProjectBindsFromControlPlane();
        try self.materializeProjectBindPrefixDirectories();
        if (self.lookupChild(self.root_id, "services")) |services_root| {
            try self.addDirectoryDescriptors(
                services_root,
                "Services",
                "{\"kind\":\"collection\",\"entries\":\"workspace service binds\",\"shape\":\"/services/<venom_id>/{README.md,SCHEMA.json,CAPS.json,OPS.json,STATUS.json,status.json,result.json,control/*}\"}",
                "{\"read\":true,\"write\":false}",
                "Workspace-bound service paths projected from the active workspace binds.",
            );
        }

        try self.registerExistingGlobalVenomBinding(global_root, "chat", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "jobs", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "events", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "web_search", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "search_code", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "terminal", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "mounts", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "workers", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "agents", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "workspaces", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "thoughts", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "git", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "github_pr", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "missions", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "pr_review", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "library", "global_namespace");
        const preferred_fs_node_id = try self.resolvePreferredBoundVenomNodeId("fs");
        defer if (preferred_fs_node_id) |value| self.allocator.free(value);
        _ = try self.seedBoundGlobalFsNamespace(global_root, preferred_fs_node_id orelse "local");
        try self.seedActiveScopedVenomBindings(active_agent_venoms_dir, project_venoms_dir, policy.project_id);
        try self.refreshScopedVenomIndexes();
        try self.addWorkspaceServiceDiscoveryFiles(meta_root, project_meta_dir);
    }

    fn addProjectMetaFiles(
        self: *Session,
        project_meta_dir: u32,
        policy: workspace_policy.WorkspacePolicy,
        workspace_status_json: ?[]const u8,
        loaded_live_mounts: bool,
        loaded_live_nodes: bool,
    ) !void {
        const topology_json = try self.buildProjectTopologyJson(policy);
        defer self.allocator.free(topology_json);
        _ = try self.addFile(project_meta_dir, "topology.json", topology_json, false, .none);
        const agents_json = try self.buildProjectAgentsJson(policy);
        defer self.allocator.free(agents_json);
        _ = try self.addFile(project_meta_dir, "agents.json", agents_json, false, .none);
        const contracts_json = try self.buildProjectContractsJson(policy.project_id);
        defer self.allocator.free(contracts_json);
        _ = try self.addFile(project_meta_dir, "contracts.json", contracts_json, false, .none);
        const paths_json = try self.buildProjectPathsJson(policy);
        defer self.allocator.free(paths_json);
        _ = try self.addFile(project_meta_dir, "paths.json", paths_json, false, .none);

        if (workspace_status_json) |status_json| {
            var nodes_from_workspace = false;
            if (try self.extractWorkspaceNodes(status_json)) |nodes_json| {
                defer self.allocator.free(nodes_json);
                _ = try self.addFile(project_meta_dir, "nodes.json", nodes_json, false, .none);
                nodes_from_workspace = true;
            } else {
                const fallback_nodes = try self.buildFallbackProjectNodesJson(policy);
                defer self.allocator.free(fallback_nodes);
                _ = try self.addFile(project_meta_dir, "nodes.json", fallback_nodes, false, .none);
            }
            const sources_json = try self.buildProjectSourcesJson(
                policy.project_id,
                true,
                loaded_live_mounts,
                loaded_live_nodes,
                nodes_from_workspace,
            );
            defer self.allocator.free(sources_json);
            _ = try self.addFile(project_meta_dir, "sources.json", sources_json, false, .none);
            const summary_json = try self.buildProjectSummaryJson(
                policy,
                status_json,
                loaded_live_mounts,
                loaded_live_nodes,
                nodes_from_workspace,
            );
            defer self.allocator.free(summary_json);
            _ = try self.addFile(project_meta_dir, "summary.json", summary_json, false, .none);
            if (try self.extractWorkspaceAlerts(status_json)) |alerts_json| {
                defer self.allocator.free(alerts_json);
                _ = try self.addFile(project_meta_dir, "alerts.json", alerts_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "alerts.json", "[]", false, .none);
            }
            _ = try self.addFile(project_meta_dir, "workspace_status.json", status_json, false, .none);
            if (try self.extractWorkspaceMounts(status_json)) |mounts_json| {
                defer self.allocator.free(mounts_json);
                _ = try self.addFile(project_meta_dir, "mounts.json", mounts_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "mounts.json", "[]", false, .none);
            }
            if (try self.extractWorkspaceDesiredMounts(status_json)) |desired_mounts_json| {
                defer self.allocator.free(desired_mounts_json);
                _ = try self.addFile(project_meta_dir, "desired_mounts.json", desired_mounts_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "desired_mounts.json", "[]", false, .none);
            }
            if (try self.extractWorkspaceActualMounts(status_json)) |actual_mounts_json| {
                defer self.allocator.free(actual_mounts_json);
                _ = try self.addFile(project_meta_dir, "actual_mounts.json", actual_mounts_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "actual_mounts.json", "[]", false, .none);
            }
            if (try self.extractWorkspaceDrift(status_json)) |drift_json| {
                defer self.allocator.free(drift_json);
                _ = try self.addFile(project_meta_dir, "drift.json", drift_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "drift.json", "{\"count\":0,\"items\":[]}", false, .none);
            }
            if (try self.extractWorkspaceReconcile(status_json)) |reconcile_json| {
                defer self.allocator.free(reconcile_json);
                _ = try self.addFile(project_meta_dir, "reconcile.json", reconcile_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "reconcile.json", "{\"reconcile_state\":\"unknown\",\"last_reconcile_ms\":0,\"last_success_ms\":0,\"last_error\":null,\"queue_depth\":0}", false, .none);
            }
            if (try self.extractWorkspaceAvailability(status_json)) |availability_json| {
                defer self.allocator.free(availability_json);
                _ = try self.addFile(project_meta_dir, "availability.json", availability_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "availability.json", "{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0}", false, .none);
            }
            if (try self.extractWorkspaceHealth(status_json)) |health_json| {
                defer self.allocator.free(health_json);
                _ = try self.addFile(project_meta_dir, "health.json", health_json, false, .none);
            } else {
                _ = try self.addFile(project_meta_dir, "health.json", "{\"state\":\"unknown\",\"availability\":{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0},\"drift_count\":0,\"reconcile_state\":\"unknown\",\"queue_depth\":0}", false, .none);
            }
            return;
        }

        const fallback_status = try self.buildFallbackWorkspaceStatusJson(policy);
        defer self.allocator.free(fallback_status);
        const fallback_nodes = try self.buildFallbackProjectNodesJson(policy);
        defer self.allocator.free(fallback_nodes);
        _ = try self.addFile(project_meta_dir, "nodes.json", fallback_nodes, false, .none);
        const fallback_sources = try self.buildProjectSourcesJson(policy.project_id, false, false, false, false);
        defer self.allocator.free(fallback_sources);
        _ = try self.addFile(project_meta_dir, "sources.json", fallback_sources, false, .none);
        const fallback_summary = try self.buildProjectSummaryJson(policy, null, false, false, false);
        defer self.allocator.free(fallback_summary);
        _ = try self.addFile(project_meta_dir, "summary.json", fallback_summary, false, .none);
        _ = try self.addFile(project_meta_dir, "alerts.json", "[]", false, .none);
        _ = try self.addFile(project_meta_dir, "workspace_status.json", fallback_status, false, .none);
        _ = try self.addFile(project_meta_dir, "mounts.json", "[]", false, .none);
        _ = try self.addFile(project_meta_dir, "desired_mounts.json", "[]", false, .none);
        _ = try self.addFile(project_meta_dir, "actual_mounts.json", "[]", false, .none);
        _ = try self.addFile(project_meta_dir, "drift.json", "{\"count\":0,\"items\":[]}", false, .none);
        _ = try self.addFile(project_meta_dir, "reconcile.json", "{\"reconcile_state\":\"unknown\",\"last_reconcile_ms\":0,\"last_success_ms\":0,\"last_error\":null,\"queue_depth\":0}", false, .none);
        _ = try self.addFile(project_meta_dir, "availability.json", "{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0}", false, .none);
        _ = try self.addFile(project_meta_dir, "health.json", "{\"state\":\"unknown\",\"availability\":{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0},\"drift_count\":0,\"reconcile_state\":\"unknown\",\"queue_depth\":0}", false, .none);
    }

    fn addWorkspaceServiceDiscoveryFiles(self: *Session, meta_root: u32, project_meta_dir: u32) !void {
        const binds_json = try self.buildProjectBindsArrayJson();
        defer self.allocator.free(binds_json);
        _ = try self.addFile(project_meta_dir, "binds.json", binds_json, false, .none);
        _ = try self.addFile(meta_root, "workspace_binds.json", binds_json, false, .none);

        const services_json = try self.buildMountedServicesJson();
        defer self.allocator.free(services_json);
        _ = try self.addFile(project_meta_dir, "mounted_services.json", services_json, false, .none);
        _ = try self.addFile(meta_root, "workspace_services.json", services_json, false, .none);

        const packages_json = try self.buildVenomPackagesJson();
        defer self.allocator.free(packages_json);
        _ = try self.addFile(project_meta_dir, "venom_packages.json", packages_json, false, .none);
        _ = try self.addFile(meta_root, "venom_packages.json", packages_json, false, .none);
    }

    pub fn refreshWorkspaceServiceDiscoveryFiles(self: *Session) !void {
        const meta_root = self.lookupChild(self.root_id, "meta") orelse return;
        const projects_root = self.lookupChild(self.root_id, "projects") orelse return;
        const active_project_id = self.active_namespace_project_id orelse self.project_id orelse return;
        const project_dir = self.lookupChild(projects_root, active_project_id) orelse return;
        const project_meta_dir = self.lookupChild(project_dir, "meta") orelse return;
        return self.addWorkspaceServiceDiscoveryFiles(meta_root, project_meta_dir);
    }

    fn buildVenomPackagesJson(self: *Session) ![]u8 {
        if (self.control_plane) |plane| {
            return plane.listVenomPackages();
        }
        return venom_packages.buildPackagesJson(self.allocator);
    }

    fn buildProjectBindsArrayJson(self: *Session) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.append(self.allocator, '[');
        for (self.project_binds.items, 0..) |bind, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const escaped_bind = try unified.jsonEscape(self.allocator, bind.bind_path);
            defer self.allocator.free(escaped_bind);
            const escaped_target = try unified.jsonEscape(self.allocator, bind.target_path);
            defer self.allocator.free(escaped_target);
            try out.writer(self.allocator).print(
                "{{\"bind_path\":\"{s}\",\"target_path\":\"{s}\"}}",
                .{ escaped_bind, escaped_target },
            );
        }
        try out.append(self.allocator, ']');
        return out.toOwnedSlice(self.allocator);
    }

    fn buildMountedServicesJson(self: *Session) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.append(self.allocator, '[');
        var first = true;

        for (self.project_binds.items) |bind| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try self.appendMountedServiceBindJson(&out, bind);
        }

        for (self.scoped_venom_bindings.items) |binding| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try self.appendDirectMountedServiceJson(&out, binding);
        }

        try out.append(self.allocator, ']');
        return out.toOwnedSlice(self.allocator);
    }

    fn appendMountedServiceBindJson(self: *Session, out: *std.ArrayListUnmanaged(u8), bind: PathBind) !void {
        var selected: ?*const ScopedVenomBinding = null;
        for (self.scoped_venom_bindings.items) |*binding| {
            if (!pathMatchesPrefixBoundary(bind.target_path, binding.venom_path)) continue;
            if (selected == null or binding.venom_path.len > selected.?.venom_path.len) selected = binding;
        }

        const escaped_bind = try unified.jsonEscape(self.allocator, bind.bind_path);
        defer self.allocator.free(escaped_bind);
        const escaped_target = try unified.jsonEscape(self.allocator, bind.target_path);
        defer self.allocator.free(escaped_target);

        if (selected) |binding| {
            const escaped_venom_id = try unified.jsonEscape(self.allocator, binding.venom_id);
            defer self.allocator.free(escaped_venom_id);
            const escaped_scope = try unified.jsonEscape(self.allocator, binding.scope);
            defer self.allocator.free(escaped_scope);
            const escaped_source = try unified.jsonEscape(self.allocator, binding.venom_path);
            defer self.allocator.free(escaped_source);
            const invoke_json = if (binding.invoke_path) |invoke_path| blk: {
                if (try self.rebaseBoundServicePath(bind.bind_path, bind.target_path, invoke_path)) |rebased| {
                    defer self.allocator.free(rebased);
                    const escaped = try unified.jsonEscape(self.allocator, rebased);
                    defer self.allocator.free(escaped);
                    break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
                }
                break :blk try self.allocator.dupe(u8, "null");
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(invoke_json);
            const provider_node_json = if (binding.provider_node_id) |value| blk: {
                const escaped = try unified.jsonEscape(self.allocator, value);
                defer self.allocator.free(escaped);
                break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(provider_node_json);
            const provider_path_json = if (binding.provider_venom_path) |value| blk: {
                const escaped = try unified.jsonEscape(self.allocator, value);
                defer self.allocator.free(escaped);
                break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(provider_path_json);
            const endpoint_json = if (binding.endpoint_path) |value| blk: {
                const escaped = try unified.jsonEscape(self.allocator, value);
                defer self.allocator.free(escaped);
                break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(endpoint_json);

            try out.writer(self.allocator).print(
                "{{\"kind\":\"venom\",\"exposure\":\"project_bind\",\"venom_id\":\"{s}\",\"scope\":\"{s}\",\"path\":\"{s}\",\"target_path\":\"{s}\",\"source_path\":\"{s}\",\"provider_node_id\":{s},\"provider_venom_path\":{s},\"endpoint_path\":{s},\"invoke_path\":{s}}}",
                .{
                    escaped_venom_id,
                    escaped_scope,
                    escaped_bind,
                    escaped_target,
                    escaped_source,
                    provider_node_json,
                    provider_path_json,
                    endpoint_json,
                    invoke_json,
                },
            );
            return;
        }

        try out.writer(self.allocator).print(
            "{{\"kind\":\"path_bind\",\"exposure\":\"project_bind\",\"path\":\"{s}\",\"target_path\":\"{s}\"}}",
            .{ escaped_bind, escaped_target },
        );
    }

    fn appendDirectMountedServiceJson(self: *Session, out: *std.ArrayListUnmanaged(u8), binding: ScopedVenomBinding) !void {
        const escaped_venom_id = try unified.jsonEscape(self.allocator, binding.venom_id);
        defer self.allocator.free(escaped_venom_id);
        const escaped_scope = try unified.jsonEscape(self.allocator, binding.scope);
        defer self.allocator.free(escaped_scope);
        const escaped_path = try unified.jsonEscape(self.allocator, binding.venom_path);
        defer self.allocator.free(escaped_path);
        const provider_node_json = if (binding.provider_node_id) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(provider_node_json);
        const provider_path_json = if (binding.provider_venom_path) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(provider_path_json);
        const endpoint_json = if (binding.endpoint_path) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(endpoint_json);
        const invoke_json = if (binding.invoke_path) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(invoke_json);

        try out.writer(self.allocator).print(
            "{{\"kind\":\"venom\",\"exposure\":\"direct\",\"venom_id\":\"{s}\",\"scope\":\"{s}\",\"path\":\"{s}\",\"provider_node_id\":{s},\"provider_venom_path\":{s},\"endpoint_path\":{s},\"invoke_path\":{s}}}",
            .{
                escaped_venom_id,
                escaped_scope,
                escaped_path,
                provider_node_json,
                provider_path_json,
                endpoint_json,
                invoke_json,
            },
        );
    }

    fn rebaseBoundServicePath(
        self: *Session,
        bind_path: []const u8,
        target_path: []const u8,
        absolute_path: []const u8,
    ) !?[]u8 {
        if (!pathMatchesPrefixBoundary(absolute_path, target_path)) return null;
        const suffix = absolute_path[target_path.len..];
        if (suffix.len == 0) return try self.allocator.dupe(u8, bind_path);
        if (std.mem.eql(u8, bind_path, "/")) return try std.fmt.allocPrint(self.allocator, "{s}", .{suffix});
        return try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ bind_path, suffix });
    }

    fn addDebugPairingSurface(self: *Session, debug_root: u32) !void {
        return pairing_venom.seedDebugSurface(self, debug_root);
    }

    pub fn refreshProjectBindsFromControlPlane(self: *Session) !void {
        self.clearProjectBinds();
        const plane = self.control_plane orelse return;
        const project_id = self.project_id orelse return;
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const payload = if (self.project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
                .{ escaped_project, escaped_token },
            );
        } else try std.fmt.allocPrint(self.allocator, "{{\"project_id\":\"{s}\"}}", .{escaped_project});
        defer self.allocator.free(payload);

        const binds_json = plane.listProjectBindsWithRole(payload, self.is_admin) catch return;
        defer self.allocator.free(binds_json);
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, binds_json, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;
        const binds_value = parsed.value.object.get("binds") orelse return;
        if (binds_value != .array) return;
        for (binds_value.array.items) |bind_value| {
            if (bind_value != .object) continue;
            const bind_path = bind_value.object.get("bind_path") orelse continue;
            const target_path = bind_value.object.get("target_path") orelse continue;
            if (bind_path != .string or bind_path.string.len == 0) continue;
            if (target_path != .string or target_path.string.len == 0) continue;
            try self.project_binds.append(self.allocator, .{
                .bind_path = try self.allocator.dupe(u8, bind_path.string),
                .target_path = try self.allocator.dupe(u8, target_path.string),
            });
        }
    }

    fn materializeProjectBindPrefixDirectories(self: *Session) !void {
        for (self.project_binds.items) |bind| {
            try self.materializeBindPrefixDirectories(bind.bind_path);
        }
    }

    fn materializeBindPrefixDirectories(self: *Session, bind_path: []const u8) !void {
        var segments = std.ArrayListUnmanaged([]const u8){};
        defer segments.deinit(self.allocator);

        var iter = std.mem.splitScalar(u8, bind_path, '/');
        while (iter.next()) |segment| {
            if (segment.len == 0) continue;
            try segments.append(self.allocator, segment);
        }
        if (segments.items.len <= 1) return;

        var parent_id = self.root_id;
        for (segments.items[0 .. segments.items.len - 1]) |segment| {
            const existing = self.lookupChild(parent_id, segment);
            if (existing) |child_id| {
                const child = self.nodes.get(child_id) orelse return error.MissingNode;
                if (child.kind != .dir) return error.InvalidPayload;
                parent_id = child_id;
                continue;
            }
            parent_id = try self.addDir(parent_id, segment, false);
        }
    }

    fn addNodeDirectoriesFromControlPlane(self: *Session, nodes_root: u32) !void {
        const plane = self.control_plane orelse return;
        const payload_json = plane.listNodes() catch return;
        defer self.allocator.free(payload_json);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;
        const nodes_value = parsed.value.object.get("nodes") orelse return;
        if (nodes_value != .array) return;

        for (nodes_value.array.items) |node_value| {
            if (node_value != .object) continue;
            const node_id_value = node_value.object.get("node_id") orelse continue;
            if (node_id_value != .string or node_id_value.string.len == 0) continue;
            if (self.lookupChild(nodes_root, node_id_value.string) != null) continue;

            const fs_available = blk: {
                if (node_value.object.get("fs_url")) |fs_url_value| {
                    if (fs_url_value == .string and fs_url_value.string.len > 0) break :blk true;
                }
                break :blk false;
            };

            var discovered = workspace_policy.WorkspaceNodePolicy{
                .id = try self.allocator.dupe(u8, node_id_value.string),
                .resources = .{
                    .fs = fs_available,
                    .camera = false,
                    .screen = false,
                    .user = false,
                },
            };
            defer {
                self.allocator.free(discovered.id);
                for (discovered.terminals.items) |terminal_id| self.allocator.free(terminal_id);
                discovered.terminals.deinit(self.allocator);
            }
            try self.addNodeDirectory(nodes_root, discovered, false);
        }
    }

    fn lookupLocalNodeVenomsRoot(self: *Session) ?u32 {
        const nodes_root = self.lookupChild(self.root_id, "nodes") orelse return null;
        const local_node_dir = self.lookupChild(nodes_root, "local") orelse return null;
        return self.lookupChild(local_node_dir, "venoms");
    }

    fn buildNodeVenomsIndexJson(self: *Session, venoms_root_id: u32) ![]u8 {
        const venoms_root = self.nodes.get(venoms_root_id) orelse return error.MissingNode;
        if (venoms_root.kind != .dir) return error.NotDir;

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.append(self.allocator, '[');
        var first = true;

        var it = venoms_root.children.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, "VENOMS.json")) continue;

            const venom_dir_id = entry.value_ptr.*;
            const venom_dir = self.nodes.get(venom_dir_id) orelse continue;
            if (venom_dir.kind != .dir) continue;
            if (!self.canInvokeVenomDirectory(venom_dir_id)) continue;

            const status_id = self.lookupChild(venom_dir_id, "STATUS.json") orelse continue;
            const status_node = self.nodes.get(status_id) orelse continue;
            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, status_node.content, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;

            const status_obj = parsed.value.object;
            const venom_id = if (status_obj.get("venom_id")) |value|
                if (value == .string and value.string.len > 0) value.string else entry.key_ptr.*
            else
                entry.key_ptr.*;
            const kind = if (status_obj.get("kind")) |value|
                if (value == .string and value.string.len > 0) value.string else "service"
            else
                "service";
            const state = if (status_obj.get("state")) |value|
                if (value == .string and value.string.len > 0) value.string else "namespace"
            else
                "namespace";
            const endpoint = if (status_obj.get("endpoint")) |value|
                if (value == .string and value.string.len > 0) value.string else ""
            else
                "";
            try self.appendVenomIndexEntry(&out, &first, venom_id, kind, state, endpoint);
        }

        try out.append(self.allocator, ']');
        return out.toOwnedSlice(self.allocator);
    }

    fn refreshNodeVenomsIndex(self: *Session, node_id: []const u8) !void {
        const nodes_root = self.lookupChild(self.root_id, "nodes") orelse return;
        const node_dir_id = self.lookupChild(nodes_root, node_id) orelse return;
        const venoms_root_id = self.lookupChild(node_dir_id, "venoms") orelse return;
        const index_id = self.lookupChild(venoms_root_id, "VENOMS.json") orelse return;
        const content = try self.buildNodeVenomsIndexJson(venoms_root_id);
        defer self.allocator.free(content);
        try self.setFileContent(index_id, content);
    }

    fn cloneNodeSubtree(self: *Session, source_id: u32, target_parent_id: u32, alias_name: ?[]const u8) !u32 {
        const source = self.nodes.get(source_id) orelse return error.MissingNode;
        const name = alias_name orelse source.name;
        const target_id = switch (source.kind) {
            .dir => try self.addDir(target_parent_id, name, source.writable),
            .file => try self.addFile(target_parent_id, name, source.content, source.writable, source.special),
        };
        try self.registerNodeAliasPair(source_id, target_id);
        if (source.kind == .dir) {
            var it = source.children.iterator();
            while (it.next()) |entry| {
                _ = try self.cloneNodeSubtree(entry.value_ptr.*, target_id, null);
            }
        }
        return target_id;
    }

    fn registerNodeAliasPair(self: *Session, source_id: u32, alias_id: u32) !void {
        if (source_id == 0 or alias_id == 0 or source_id == alias_id) return;
        try self.node_aliases.put(self.allocator, source_id, alias_id);
        try self.node_aliases.put(self.allocator, alias_id, source_id);
    }

    pub fn ensureAliasedSubtree(self: *Session, source_id: u32) !void {
        const source = self.nodes.get(source_id) orelse return error.MissingNode;
        if (self.node_aliases.get(source_id)) |alias_id| {
            if (source.kind == .file) {
                try self.setFileContentRaw(alias_id, source.content);
                return;
            }
            var existing_it = source.children.iterator();
            while (existing_it.next()) |entry| {
                try self.ensureAliasedSubtree(entry.value_ptr.*);
            }
            return;
        }

        const parent_id = source.parent orelse return;
        const alias_parent_id = self.node_aliases.get(parent_id) orelse return;
        const alias_id = if (self.lookupChild(alias_parent_id, source.name)) |existing|
            existing
        else switch (source.kind) {
            .dir => try self.addDir(alias_parent_id, source.name, source.writable),
            .file => try self.addFile(alias_parent_id, source.name, source.content, source.writable, source.special),
        };
        try self.registerNodeAliasPair(source_id, alias_id);

        if (source.kind == .file) {
            try self.setFileContentRaw(alias_id, source.content);
            return;
        }

        var child_it = source.children.iterator();
        while (child_it.next()) |entry| {
            try self.ensureAliasedSubtree(entry.value_ptr.*);
        }
    }

    fn registerLocalCatalogVenomBinding(self: *Session, venom_id: []const u8, scope: []const u8) !void {
        const local_venoms_root = self.lookupLocalNodeVenomsRoot() orelse return;
        const venom_dir_id = self.lookupChild(local_venoms_root, venom_id) orelse return;
        const venom_path = try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/{s}", .{venom_id});
        defer self.allocator.free(venom_path);
        const endpoint_path = blk: {
            if (try self.firstVenomMountPath(venom_dir_id)) |value| break :blk value;
            break :blk try self.venomEndpointPath(venom_dir_id);
        };
        defer if (endpoint_path) |value| self.allocator.free(value);
        const invoke_path = try self.deriveVenomInvokePath("local", venom_id, venom_dir_id);
        defer if (invoke_path) |value| self.allocator.free(value);

        try self.registerScopedVenomBinding(
            venom_id,
            scope,
            venom_path,
            "local",
            venom_path,
            endpoint_path,
            invoke_path,
        );
    }

    fn cloneLocalCatalogVenomAlias(self: *Session, source_dir: u32, global_root: u32, venom_id: []const u8) !u32 {
        return self.cloneNodeSubtree(source_dir, global_root, venom_id);
    }

    fn seedLocalCatalogServiceNamespaces(self: *Session, global_root: u32) !void {
        const local_venoms_root = self.lookupLocalNodeVenomsRoot() orelse return;

        const library_dir = try self.addDir(local_venoms_root, "library", false);
        try self.seedGlobalLibraryNamespaceAt(library_dir, "/nodes/local/venoms/library");
        try self.seedBuiltinPackageMetadata(library_dir, "library");
        _ = try self.cloneLocalCatalogVenomAlias(library_dir, global_root, "library");

        const venom_packages_dir = try self.addDir(local_venoms_root, "venom_packages", false);
        try self.seedVenomPackagesNamespaceAt(venom_packages_dir, "/nodes/local/venoms/venom_packages");
        try self.seedBuiltinPackageMetadata(venom_packages_dir, "venom_packages");
        const venom_packages_alias_dir = try self.cloneLocalCatalogVenomAlias(venom_packages_dir, global_root, "venom_packages");
        self.venom_packages_status_alias_id = self.lookupChild(venom_packages_alias_dir, "status.json") orelse 0;
        self.venom_packages_result_alias_id = self.lookupChild(venom_packages_alias_dir, "result.json") orelse 0;

        const chat_dir = try self.addDir(local_venoms_root, "chat", false);
        try self.seedChatNamespaceAt(chat_dir, "/nodes/local/venoms/chat", "/nodes/local/venoms/jobs");
        try self.seedBuiltinPackageMetadata(chat_dir, "chat");
        _ = try self.cloneLocalCatalogVenomAlias(chat_dir, global_root, "chat");

        const jobs_dir = try self.addDir(local_venoms_root, "jobs", false);
        try self.seedJobsNamespaceAt(jobs_dir, "/nodes/local/venoms/jobs");
        try self.seedJobsFromIndex();
        try self.seedBuiltinPackageMetadata(jobs_dir, "jobs");
        _ = try self.cloneLocalCatalogVenomAlias(jobs_dir, global_root, "jobs");

        const thoughts_dir = try self.addDir(local_venoms_root, "thoughts", false);
        try self.seedThoughtsNamespaceAt(thoughts_dir, "/nodes/local/venoms/thoughts");
        try self.seedBuiltinPackageMetadata(thoughts_dir, "thoughts");
        _ = try self.cloneLocalCatalogVenomAlias(thoughts_dir, global_root, "thoughts");

        const events_dir = try self.addDir(local_venoms_root, "events", false);
        try self.seedEventsNamespaceAt(events_dir, "/nodes/local/venoms/events");
        try self.seedBuiltinPackageMetadata(events_dir, "events");
        _ = try self.cloneLocalCatalogVenomAlias(events_dir, global_root, "events");

        const home_dir = try self.addDir(local_venoms_root, "home", false);
        try self.seedAgentHomeNamespaceAt(home_dir, "/nodes/local/venoms/home");
        try self.seedBuiltinPackageMetadata(home_dir, "home");
        const home_alias_dir = try self.cloneLocalCatalogVenomAlias(home_dir, global_root, "home");
        self.home_status_alias_id = self.lookupChild(home_alias_dir, "status.json") orelse 0;
        self.home_result_alias_id = self.lookupChild(home_alias_dir, "result.json") orelse 0;

        const workers_dir = try self.addDir(local_venoms_root, "workers", false);
        try workers_venom.seedNamespaceAt(self, workers_dir, "/nodes/local/venoms/workers");
        try self.seedBuiltinPackageMetadata(workers_dir, "workers");
        const workers_alias_dir = try self.cloneLocalCatalogVenomAlias(workers_dir, global_root, "workers");
        self.workers_status_alias_id = self.lookupChild(workers_alias_dir, "status.json") orelse 0;
        self.workers_result_alias_id = self.lookupChild(workers_alias_dir, "result.json") orelse 0;

        const web_search_dir = try self.addDir(local_venoms_root, "web_search", false);
        try self.seedAgentWebSearchNamespaceAt(web_search_dir, "/nodes/local/venoms/web_search");
        try self.seedBuiltinPackageMetadata(web_search_dir, "web_search");
        _ = try self.cloneLocalCatalogVenomAlias(web_search_dir, global_root, "web_search");

        const search_code_dir = try self.addDir(local_venoms_root, "search_code", false);
        try self.seedAgentSearchCodeNamespaceAt(search_code_dir, "/nodes/local/venoms/search_code");
        try self.seedBuiltinPackageMetadata(search_code_dir, "search_code");
        _ = try self.cloneLocalCatalogVenomAlias(search_code_dir, global_root, "search_code");

        const terminal_dir = try self.addDir(local_venoms_root, "terminal", false);
        try self.seedAgentTerminalNamespaceAt(terminal_dir, "/nodes/local/venoms/terminal");
        try self.seedBuiltinPackageMetadata(terminal_dir, "terminal");
        _ = try self.cloneLocalCatalogVenomAlias(terminal_dir, global_root, "terminal");

        const mounts_dir = try self.addDir(local_venoms_root, "mounts", false);
        try self.seedAgentMountsNamespaceAt(mounts_dir, "/nodes/local/venoms/mounts");
        try self.seedBuiltinPackageMetadata(mounts_dir, "mounts");
        const mounts_alias_dir = try self.cloneLocalCatalogVenomAlias(mounts_dir, global_root, "mounts");
        self.mounts_status_alias_id = self.lookupChild(mounts_alias_dir, "status.json") orelse 0;
        self.mounts_result_alias_id = self.lookupChild(mounts_alias_dir, "result.json") orelse 0;

        const agents_dir = try self.addDir(local_venoms_root, "agents", false);
        try self.seedAgentAgentsNamespaceAt(agents_dir, "/nodes/local/venoms/agents");
        try self.seedBuiltinPackageMetadata(agents_dir, "agents");
        _ = try self.cloneLocalCatalogVenomAlias(agents_dir, global_root, "agents");

        const workspaces_dir = try self.addDir(local_venoms_root, "workspaces", false);
        try self.seedAgentWorkspacesNamespaceAt(workspaces_dir, "/nodes/local/venoms/workspaces");
        try self.seedBuiltinPackageMetadata(workspaces_dir, "workspaces");
        _ = try self.cloneLocalCatalogVenomAlias(workspaces_dir, global_root, "workspaces");

        if (self.local_fs_export_root != null) {
            const git_dir = try self.addDir(local_venoms_root, "git", false);
            try self.seedAgentGitNamespaceAt(git_dir, "/nodes/local/venoms/git");
            try self.seedBuiltinPackageMetadata(git_dir, "git");
            const git_alias_dir = try self.cloneLocalCatalogVenomAlias(git_dir, global_root, "git");
            self.git_status_alias_id = self.lookupChild(git_alias_dir, "status.json") orelse 0;
            self.git_result_alias_id = self.lookupChild(git_alias_dir, "result.json") orelse 0;

            const github_pr_dir = try self.addDir(local_venoms_root, "github_pr", false);
            try self.seedAgentGitHubPrNamespaceAt(github_pr_dir, "/nodes/local/venoms/github_pr");
            try self.seedBuiltinPackageMetadata(github_pr_dir, "github_pr");
            const github_pr_alias_dir = try self.cloneLocalCatalogVenomAlias(github_pr_dir, global_root, "github_pr");
            self.github_pr_status_alias_id = self.lookupChild(github_pr_alias_dir, "status.json") orelse 0;
            self.github_pr_result_alias_id = self.lookupChild(github_pr_alias_dir, "result.json") orelse 0;
        }

        if (self.mission_store != null) {
            const missions_dir = try self.addDir(local_venoms_root, "missions", false);
            try self.seedAgentMissionsNamespaceAt(missions_dir, "/nodes/local/venoms/missions");
            try self.seedBuiltinPackageMetadata(missions_dir, "missions");
            const missions_alias_dir = try self.cloneLocalCatalogVenomAlias(missions_dir, global_root, "missions");
            self.missions_status_alias_id = self.lookupChild(missions_alias_dir, "status.json") orelse 0;
            self.missions_result_alias_id = self.lookupChild(missions_alias_dir, "result.json") orelse 0;

            if (self.local_fs_export_root != null) {
                const pr_review_dir = try self.addDir(local_venoms_root, "pr_review", false);
                try self.seedAgentPrReviewNamespaceAt(pr_review_dir, "/nodes/local/venoms/pr_review");
                try self.seedBuiltinPackageMetadata(pr_review_dir, "pr_review");
                const pr_review_alias_dir = try self.cloneLocalCatalogVenomAlias(pr_review_dir, global_root, "pr_review");
                self.pr_review_status_alias_id = self.lookupChild(pr_review_alias_dir, "status.json") orelse 0;
                self.pr_review_result_alias_id = self.lookupChild(pr_review_alias_dir, "result.json") orelse 0;
            }
        }

        try self.refreshNodeVenomsIndex("local");
        try self.registerLocalCatalogVenomBinding("library", "node_catalog");
        try self.registerLocalCatalogVenomBinding("venom_packages", "node_catalog");
        try self.registerLocalCatalogVenomBinding("chat", "node_catalog");
        try self.registerLocalCatalogVenomBinding("jobs", "node_catalog");
        try self.registerLocalCatalogVenomBinding("thoughts", "node_catalog");
        try self.registerLocalCatalogVenomBinding("events", "node_catalog");
        try self.registerLocalCatalogVenomBinding("workers", "node_catalog");
        try self.registerLocalCatalogVenomBinding("web_search", "node_catalog");
        try self.registerLocalCatalogVenomBinding("search_code", "node_catalog");
        try self.registerLocalCatalogVenomBinding("terminal", "node_catalog");
        try self.registerLocalCatalogVenomBinding("mounts", "node_catalog");
        try self.registerLocalCatalogVenomBinding("agents", "node_catalog");
        try self.registerLocalCatalogVenomBinding("workspaces", "node_catalog");
        if (self.local_fs_export_root != null) {
            try self.registerLocalCatalogVenomBinding("git", "node_catalog");
            try self.registerLocalCatalogVenomBinding("github_pr", "node_catalog");
        }
        if (self.mission_store != null) {
            try self.registerLocalCatalogVenomBinding("missions", "node_catalog");
            if (self.local_fs_export_root != null) {
                try self.registerLocalCatalogVenomBinding("pr_review", "node_catalog");
            }
        }
    }

    fn addProjectFsLinksFromPolicy(
        self: *Session,
        project_fs_dir: u32,
        policy: workspace_policy.WorkspacePolicy,
    ) !void {
        for (policy.project_links.items) |link| {
            const target = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/{s}\n", .{ link.node_id, link.resource });
            defer self.allocator.free(target);
            _ = try self.addFile(project_fs_dir, link.name, target, false, .none);
        }
    }

    fn addProjectFsLinksFromWorkspaceStatus(
        self: *Session,
        project_fs_dir: u32,
        nodes_root: u32,
        policy: workspace_policy.WorkspacePolicy,
        workspace_status_json: []const u8,
    ) !bool {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        const mounts_value = parsed.value.object.get("mounts") orelse return false;
        if (mounts_value != .array or mounts_value.array.items.len == 0) return false;

        var added = false;
        for (mounts_value.array.items) |mount_value| {
            if (mount_value != .object) continue;
            const node_id_value = mount_value.object.get("node_id") orelse continue;
            if (node_id_value != .string or node_id_value.string.len == 0) continue;
            if (!try self.ensurePolicyNodeFsTarget(nodes_root, policy, node_id_value.string)) continue;
            const mount_path_value = mount_value.object.get("mount_path") orelse continue;
            if (mount_path_value != .string or mount_path_value.string.len == 0) continue;

            const link_name = try projectMountPathToLinkName(self.allocator, mount_path_value.string);
            defer self.allocator.free(link_name);
            if (self.lookupChild(project_fs_dir, link_name) != null) continue;

            const target = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/fs\n", .{node_id_value.string});
            defer self.allocator.free(target);
            _ = try self.addFile(project_fs_dir, link_name, target, false, .none);
            added = true;
        }
        return added;
    }

    fn ensurePolicyNodeFsTarget(
        self: *Session,
        nodes_root: u32,
        policy: workspace_policy.WorkspacePolicy,
        node_id: []const u8,
    ) !bool {
        for (policy.nodes.items) |node| {
            if (!std.mem.eql(u8, node.id, node_id)) continue;
            if (!node.resources.fs) return false;

            if (self.lookupChild(nodes_root, node_id)) |node_dir| {
                if (self.lookupChild(node_dir, "fs") == null) {
                    _ = try self.addDir(node_dir, "fs", false);
                }
                return true;
            }

            try self.addNodeDirectory(nodes_root, node, false);
            return true;
        }
        return false;
    }

    fn addProjectNodeLinksFromPolicy(
        self: *Session,
        project_nodes_dir: u32,
        policy: workspace_policy.WorkspacePolicy,
    ) !void {
        for (policy.nodes.items) |node| {
            if (self.lookupChild(project_nodes_dir, node.id) != null) continue;
            const target = try std.fmt.allocPrint(self.allocator, "/nodes/{s}\n", .{node.id});
            defer self.allocator.free(target);
            _ = try self.addFile(project_nodes_dir, node.id, target, false, .none);
        }
    }

    fn addProjectNodeLinksFromWorkspaceStatus(
        self: *Session,
        project_nodes_dir: u32,
        policy: workspace_policy.WorkspacePolicy,
        workspace_status_json: []const u8,
    ) !bool {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        const mounts_value = parsed.value.object.get("mounts") orelse return false;
        if (mounts_value != .array or mounts_value.array.items.len == 0) return false;

        var added = false;
        for (mounts_value.array.items) |mount_value| {
            if (mount_value != .object) continue;
            const node_id_value = mount_value.object.get("node_id") orelse continue;
            if (node_id_value != .string or node_id_value.string.len == 0) continue;
            if (!policyIncludesNode(policy, node_id_value.string)) continue;
            if (self.lookupChild(project_nodes_dir, node_id_value.string) != null) continue;
            const target = try std.fmt.allocPrint(self.allocator, "/nodes/{s}\n", .{node_id_value.string});
            defer self.allocator.free(target);
            _ = try self.addFile(project_nodes_dir, node_id_value.string, target, false, .none);
            added = true;
        }
        return added;
    }

    fn policyAllowsNodeFs(policy: workspace_policy.WorkspacePolicy, node_id: []const u8) bool {
        for (policy.nodes.items) |node| {
            if (!std.mem.eql(u8, node.id, node_id)) continue;
            return node.resources.fs;
        }
        return false;
    }

    fn policyIncludesNode(policy: workspace_policy.WorkspacePolicy, node_id: []const u8) bool {
        for (policy.nodes.items) |node| {
            if (std.mem.eql(u8, node.id, node_id)) return true;
        }
        return false;
    }

    fn addNodeDirectory(
        self: *Session,
        nodes_root: u32,
        node: workspace_policy.WorkspaceNodePolicy,
        discovered_from_workspace: bool,
    ) !void {
        const node_dir = try self.addDir(nodes_root, node.id, false);
        var resource_view = try self.addNodeVenoms(node_dir, node);
        defer resource_view.deinit(self.allocator);

        const node_schema = "{\"kind\":\"node\",\"children\":\"services + mount roots\"}";
        const node_caps = try std.fmt.allocPrint(
            self.allocator,
            "{{\"fs\":{s},\"camera\":{s},\"screen\":{s},\"user\":{s},\"terminal\":{s}}}",
            .{
                if (resource_view.fs) "true" else "false",
                if (resource_view.camera) "true" else "false",
                if (resource_view.screen) "true" else "false",
                if (resource_view.user) "true" else "false",
                if (resource_view.terminals.items.len > 0) "true" else "false",
            },
        );
        defer self.allocator.free(node_caps);
        try self.addDirectoryDescriptors(
            node_dir,
            "Node Endpoint",
            node_schema,
            node_caps,
            if (discovered_from_workspace)
                "Node discovered from live project workspace mounts."
            else
                "Node resource roots. Entries may be unavailable based on policy.",
        );
        try self.addNodeRuntimeMetadataFiles(node_dir, node.id, discovered_from_workspace);

        if (resource_view.fs and self.lookupChild(node_dir, "fs") == null) _ = try self.addDir(node_dir, "fs", false);
        if (resource_view.camera and self.lookupChild(node_dir, "camera") == null) _ = try self.addDir(node_dir, "camera", false);
        if (resource_view.screen and self.lookupChild(node_dir, "screen") == null) _ = try self.addDir(node_dir, "screen", false);
        if (resource_view.user and self.lookupChild(node_dir, "user") == null) _ = try self.addDir(node_dir, "user", false);
        if (resource_view.terminals.items.len > 0) {
            const terminal_root = if (self.lookupChild(node_dir, "terminal")) |existing| existing else try self.addDir(node_dir, "terminal", false);
            for (resource_view.terminals.items) |terminal_id| {
                if (self.lookupChild(terminal_root, terminal_id) == null) {
                    _ = try self.addDir(terminal_root, terminal_id, false);
                }
            }
        }

        for (resource_view.roots.items) |root_name| {
            if (self.lookupChild(node_dir, root_name) == null) {
                _ = try self.addDir(node_dir, root_name, false);
            }
        }
    }

    fn addNodeRuntimeMetadataFiles(
        self: *Session,
        node_dir: u32,
        node_id: []const u8,
        discovered_from_workspace: bool,
    ) !void {
        if (try self.loadNodeControlPayload(node_id)) |node_payload_json| {
            defer self.allocator.free(node_payload_json);
            _ = try self.addFile(node_dir, "NODE.json", node_payload_json, false, .none);
            if (try self.buildNodeStatusFromControlPayload(node_id, node_payload_json)) |status_json| {
                defer self.allocator.free(status_json);
                _ = try self.addFile(node_dir, "STATUS.json", status_json, false, .none);
                return;
            }
        }

        const fallback_status = try self.buildFallbackNodeStatusJson(node_id, discovered_from_workspace);
        defer self.allocator.free(fallback_status);
        _ = try self.addFile(node_dir, "STATUS.json", fallback_status, false, .none);
    }

    fn loadNodeControlPayload(self: *Session, node_id: []const u8) !?[]u8 {
        const plane = self.control_plane orelse return null;
        const escaped_node_id = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node_id);
        const request_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"node_id\":\"{s}\"}}",
            .{escaped_node_id},
        );
        defer self.allocator.free(request_json);
        return plane.getNode(request_json) catch null;
    }

    fn buildNodeStatusFromControlPayload(
        self: *Session,
        node_id: []const u8,
        node_payload_json: []const u8,
    ) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, node_payload_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const node_value = parsed.value.object.get("node") orelse return null;
        if (node_value != .object) return null;

        const node_name = if (node_value.object.get("node_name")) |value|
            if (value == .string and value.string.len > 0) value.string else node_id
        else
            node_id;
        const fs_url = if (node_value.object.get("fs_url")) |value|
            if (value == .string) value.string else ""
        else
            "";
        const lease_expires_at_ms = if (node_value.object.get("lease_expires_at_ms")) |value|
            if (value == .integer) value.integer else @as(i64, 0)
        else
            0;
        const last_seen_ms = if (node_value.object.get("last_seen_ms")) |value|
            if (value == .integer) value.integer else @as(i64, 0)
        else
            0;
        const joined_at_ms = if (node_value.object.get("joined_at_ms")) |value|
            if (value == .integer) value.integer else @as(i64, 0)
        else
            0;

        const online = lease_expires_at_ms > std.time.milliTimestamp();
        const escaped_node_id = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node_id);
        const escaped_node_name = try unified.jsonEscape(self.allocator, node_name);
        defer self.allocator.free(escaped_node_name);
        const escaped_fs_url = try unified.jsonEscape(self.allocator, fs_url);
        defer self.allocator.free(escaped_fs_url);

        const status_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"node_id\":\"{s}\",\"node_name\":\"{s}\",\"state\":\"{s}\",\"online\":{s},\"lease_expires_at_ms\":{d},\"last_seen_ms\":{d},\"joined_at_ms\":{d},\"fs_url\":\"{s}\",\"source\":\"control_plane\"}}",
            .{
                escaped_node_id,
                escaped_node_name,
                if (online) "online" else "degraded",
                if (online) "true" else "false",
                lease_expires_at_ms,
                last_seen_ms,
                joined_at_ms,
                escaped_fs_url,
            },
        );
        return status_json;
    }

    fn buildFallbackNodeStatusJson(
        self: *Session,
        node_id: []const u8,
        discovered_from_workspace: bool,
    ) ![]u8 {
        const escaped_node_id = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node_id);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"node_id\":\"{s}\",\"state\":\"{s}\",\"online\":{s},\"source\":\"{s}\"}}",
            .{
                escaped_node_id,
                if (discovered_from_workspace) "unknown" else "configured",
                if (discovered_from_workspace) "false" else "true",
                if (discovered_from_workspace) "workspace_discovery" else "policy",
            },
        );
    }

    pub fn addDirectoryDescriptors(
        self: *Session,
        dir_id: u32,
        title: []const u8,
        schema_json: []const u8,
        caps_json: []const u8,
        instructions: []const u8,
    ) !void {
        const readme = try std.fmt.allocPrint(
            self.allocator,
            "# {s}\n\n{s}\n",
            .{ title, instructions },
        );
        defer self.allocator.free(readme);
        _ = try self.addFile(dir_id, "README.md", readme, false, .none);
        _ = try self.addFile(dir_id, "SCHEMA.json", schema_json, false, .none);
        _ = try self.addFile(dir_id, "CAPS.json", caps_json, false, .none);
    }

    pub fn ensureWorkerLoopbackNode(self: *Session, worker_id: []const u8, agent_id: []const u8, venoms: []const []const u8) !void {
        const nodes_root = self.lookupChild(self.root_id, "nodes") orelse return error.InvalidPayload;
        const node_dir_id = if (self.lookupChild(nodes_root, worker_id)) |existing|
            existing
        else
            try self.addDir(nodes_root, worker_id, false);

        try self.ensureWorkerFile(node_dir_id, "README.md", "External worker node projected into this mounted workspace session.\n", false, .none);
        try self.ensureWorkerFile(node_dir_id, "SCHEMA.json", "{\"kind\":\"node\",\"children\":\"venoms + worker metadata\"}", false, .none);
        try self.ensureWorkerFile(node_dir_id, "CAPS.json", "{\"worker_owned\":true,\"venoms\":true}", false, .none);
        const status_json = try self.renderWorkerNodeStatusJson(worker_id, agent_id);
        defer self.allocator.free(status_json);
        try self.ensureWorkerFile(node_dir_id, "STATUS.json", status_json, false, .none);
        try self.ensureWorkerFile(node_dir_id, "NODE.json", status_json, false, .none);

        const venoms_root_id = if (self.lookupChild(node_dir_id, "venoms")) |existing|
            existing
        else
            try self.addDir(node_dir_id, "venoms", false);
        try self.ensureWorkerFile(
            venoms_root_id,
            "README.md",
            "Worker-owned loopback venoms. External agents may read and write these files directly within the mounted workspace.\n",
            false,
            .none,
        );
        try self.ensureWorkerFile(
            venoms_root_id,
            "SCHEMA.json",
            "{\"kind\":\"collection\",\"entries\":\"worker venoms\",\"shape\":\"/nodes/<worker_id>/venoms/<venom_id>/{README.md,SCHEMA.json,CAPS.json,OPS.json,STATUS.json,status.json,result.json,control/*}\"}",
            false,
            .none,
        );
        try self.ensureWorkerFile(venoms_root_id, "CAPS.json", "{\"discover\":true,\"invoke_via_paths\":true,\"worker_owned\":true}", false, .none);
        try self.ensureWorkerFile(venoms_root_id, "VENOMS.json", "[]", false, .none);

        for (venoms) |venom_id| {
            if (std.mem.eql(u8, venom_id, "memory")) {
                const memory_dir_id = if (self.lookupChild(venoms_root_id, "memory")) |existing|
                    existing
                else
                    try self.addDir(venoms_root_id, "memory", false);
                const base_path = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/venoms/memory", .{worker_id});
                defer self.allocator.free(base_path);
                try workers_venom.seedPassiveWorkerMemoryNamespaceAt(self, memory_dir_id, base_path, worker_id, agent_id);
                try self.seedBuiltinPackageMetadata(memory_dir_id, "memory");
            } else if (std.mem.eql(u8, venom_id, "sub_brains")) {
                const sub_brains_dir_id = if (self.lookupChild(venoms_root_id, "sub_brains")) |existing|
                    existing
                else
                    try self.addDir(venoms_root_id, "sub_brains", false);
                const base_path = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/venoms/sub_brains", .{worker_id});
                defer self.allocator.free(base_path);
                try workers_venom.seedPassiveWorkerSubBrainsNamespaceAt(self, sub_brains_dir_id, base_path, worker_id, agent_id);
                try self.seedBuiltinPackageMetadata(sub_brains_dir_id, "sub_brains");
            } else {
                var package = (try self.cloneWorkerVenomPackage(venom_id)) orelse continue;
                defer package.deinit(self.allocator);

                const venom_dir_id = if (self.lookupChild(venoms_root_id, venom_id)) |existing|
                    existing
                else
                    try self.addDir(venoms_root_id, venom_id, false);
                const base_path = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/venoms/{s}", .{ worker_id, venom_id });
                defer self.allocator.free(base_path);
                try self.seedGenericWorkerLoopbackVenomNamespaceAt(venom_dir_id, base_path, worker_id, agent_id, package);
            }
        }

        try self.refreshNodeVenomsIndex(worker_id);
        try self.refreshScopedVenomIndexes();
    }

    pub fn recordWorkerHeartbeat(self: *Session, worker_id: []const u8, agent_id: []const u8, ttl_ms: u64) !void {
        const now_ms = std.time.milliTimestamp();
        const expires_at_ms = now_ms + @as(i64, @intCast(ttl_ms));
        const entry = try self.worker_presence.getOrPut(self.allocator, worker_id);
        if (entry.found_existing) {
            if (!std.mem.eql(u8, entry.value_ptr.agent_id, agent_id)) {
                self.allocator.free(entry.value_ptr.agent_id);
                entry.value_ptr.agent_id = try self.allocator.dupe(u8, agent_id);
            }
            entry.value_ptr.last_seen_ms = now_ms;
            entry.value_ptr.expires_at_ms = expires_at_ms;
            return;
        }

        entry.key_ptr.* = try self.allocator.dupe(u8, worker_id);
        entry.value_ptr.* = .{
            .agent_id = try self.allocator.dupe(u8, agent_id),
            .last_seen_ms = now_ms,
            .expires_at_ms = expires_at_ms,
        };
    }

    pub fn detachWorkerLoopbackNode(self: *Session, worker_id: []const u8) anyerror!void {
        if (self.worker_presence.fetchRemove(worker_id)) |removed| {
            self.allocator.free(removed.key);
            var presence = removed.value;
            presence.deinit(self.allocator);
        }

        const nodes_root = self.lookupChild(self.root_id, "nodes") orelse return;
        const worker_node_dir_id = self.lookupChild(nodes_root, worker_id) orelse return;

        try self.deleteNodeRecursive(worker_node_dir_id);
        try self.refreshScopedVenomIndexes();
    }

    fn refreshWorkerPresenceStatuses(self: *Session) !void {
        var it = self.worker_presence.iterator();
        while (it.next()) |entry| {
            const worker_id = entry.key_ptr.*;
            const presence = entry.value_ptr.*;
            const nodes_root = self.lookupChild(self.root_id, "nodes") orelse continue;
            const node_dir_id = self.lookupChild(nodes_root, worker_id) orelse continue;
            const status_json = try self.renderWorkerNodeStatusJson(worker_id, presence.agent_id);
            defer self.allocator.free(status_json);
            if (self.lookupChild(node_dir_id, "STATUS.json")) |status_id| {
                try self.setFileContent(status_id, status_json);
            }
            if (self.lookupChild(node_dir_id, "NODE.json")) |node_json_id| {
                try self.setFileContent(node_json_id, status_json);
            }
        }
    }

    fn reapExpiredWorkerNodes(self: *Session) !void {
        var expired = std.ArrayListUnmanaged([]const u8){};
        defer expired.deinit(self.allocator);

        const now_ms = std.time.milliTimestamp();
        var it = self.worker_presence.iterator();
        while (it.next()) |entry| {
            const presence = entry.value_ptr.*;
            if (presence.expires_at_ms <= 0) continue;
            if (now_ms <= presence.expires_at_ms + worker_reap_grace_ms) continue;
            try expired.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
        }
        defer for (expired.items) |worker_id| self.allocator.free(worker_id);

        for (expired.items) |worker_id| {
            try self.detachWorkerLoopbackNode(worker_id);
        }
    }

    fn renderWorkerNodeStatusJson(self: *Session, worker_id: []const u8, default_agent_id: []const u8) ![]u8 {
        const now_ms = std.time.milliTimestamp();
        var agent_id = default_agent_id;
        var last_seen_ms: i64 = 0;
        var expires_at_ms: i64 = 0;
        if (self.worker_presence.get(worker_id)) |presence| {
            agent_id = presence.agent_id;
            last_seen_ms = presence.last_seen_ms;
            expires_at_ms = presence.expires_at_ms;
        }
        const online = expires_at_ms > now_ms;
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"node_id\":\"{s}\",\"node_name\":\"{s}\",\"state\":\"{s}\",\"online\":{s},\"agent_id\":\"{s}\",\"last_seen_ms\":{d},\"expires_at_ms\":{d},\"source\":\"worker_registration\"}}",
            .{
                worker_id,
                worker_id,
                if (online) "worker_attached" else "worker_stale",
                if (online) "true" else "false",
                agent_id,
                last_seen_ms,
                expires_at_ms,
            },
        );
    }

    fn deleteNodeRecursive(self: *Session, node_id: u32) !void {
        if (node_id == self.root_id) return;
        const node = self.nodes.get(node_id) orelse return;

        var child_ids = std.ArrayListUnmanaged(u32){};
        defer child_ids.deinit(self.allocator);
        if (node.kind == .dir) {
            var it = node.children.iterator();
            while (it.next()) |entry| {
                try child_ids.append(self.allocator, entry.value_ptr.*);
            }
        }
        for (child_ids.items) |child_id| {
            try self.deleteNodeRecursive(child_id);
        }

        if (self.node_aliases.fetchRemove(node_id)) |removed_alias| {
            _ = self.node_aliases.remove(removed_alias.value);
        }

        if (node.parent) |parent_id| {
            var parent = self.nodes.getPtr(parent_id) orelse return error.MissingNode;
            _ = parent.children.fetchRemove(node.name);
        }

        const removed = self.nodes.fetchRemove(node_id) orelse return;
        var doomed = removed.value;
        doomed.deinit(self.allocator);
    }

    fn ensureWorkerFile(
        self: *Session,
        parent_id: u32,
        name: []const u8,
        content: []const u8,
        writable: bool,
        special: SpecialKind,
    ) !void {
        if (self.lookupChild(parent_id, name)) |existing| {
            try self.setFileContent(existing, content);
            return;
        }
        _ = try self.addFile(parent_id, name, content, writable, special);
    }

    fn seedAgentHomeNamespace(self: *Session, home_dir: u32) !void {
        return home_venom.seedNamespace(self, home_dir);
    }

    fn seedAgentHomeNamespaceAt(self: *Session, home_dir: u32, base_path: []const u8) !void {
        return home_venom.seedNamespaceAt(self, home_dir, base_path);
    }

    fn seedVenomPackagesNamespaceAt(self: *Session, packages_dir: u32, base_path: []const u8) !void {
        return venom_packages_service_venom.seedNamespaceAt(self, packages_dir, base_path);
    }

    fn seedAgentWebSearchNamespace(self: *Session, web_search_dir: u32) !void {
        return search_services_venom.seedWebSearchNamespace(self, web_search_dir);
    }

    fn seedAgentWebSearchNamespaceAt(self: *Session, web_search_dir: u32, base_path: []const u8) !void {
        return search_services_venom.seedWebSearchNamespaceAt(self, web_search_dir, base_path);
    }

    fn seedAgentSearchCodeNamespace(self: *Session, search_code_dir: u32) !void {
        return search_services_venom.seedSearchCodeNamespace(self, search_code_dir);
    }

    fn seedAgentSearchCodeNamespaceAt(self: *Session, search_code_dir: u32, base_path: []const u8) !void {
        return search_services_venom.seedSearchCodeNamespaceAt(self, search_code_dir, base_path);
    }

    fn seedAgentTerminalNamespace(self: *Session, terminal_dir: u32) !void {
        return terminal_venom.seedNamespace(self, terminal_dir);
    }

    fn seedAgentTerminalNamespaceAt(self: *Session, terminal_dir: u32, base_path: []const u8) !void {
        return terminal_venom.seedNamespaceAt(self, terminal_dir, base_path);
    }

    fn seedAgentGitNamespace(self: *Session, git_dir: u32) !void {
        return git_venom.seedNamespace(self, git_dir);
    }

    fn seedAgentGitNamespaceAt(self: *Session, git_dir: u32, base_path: []const u8) !void {
        return git_venom.seedNamespaceAt(self, git_dir, base_path);
    }

    fn seedAgentGitHubPrNamespace(self: *Session, github_pr_dir: u32) !void {
        return github_pr_venom.seedNamespace(self, github_pr_dir);
    }

    fn seedAgentGitHubPrNamespaceAt(self: *Session, github_pr_dir: u32, base_path: []const u8) !void {
        return github_pr_venom.seedNamespaceAt(self, github_pr_dir, base_path);
    }

    fn seedAgentMountsNamespace(self: *Session, mounts_dir: u32) !void {
        return mounts_venom.seedNamespace(self, mounts_dir);
    }

    fn seedAgentMountsNamespaceAt(self: *Session, mounts_dir: u32, base_path: []const u8) !void {
        return mounts_venom.seedNamespaceAt(self, mounts_dir, base_path);
    }

    fn seedAgentAgentsNamespace(self: *Session, agents_dir: u32) !void {
        return self.seedAgentAgentsNamespaceAt(agents_dir, "/global/agents");
    }

    fn seedAgentAgentsNamespaceAt(self: *Session, agents_dir: u32, base_path: []const u8) !void {
        return agents_venom.seedNamespaceAt(self, agents_dir, base_path);
    }

    fn seedAgentWorkspacesNamespace(self: *Session, workspaces_dir: u32) !void {
        return self.seedAgentWorkspacesNamespaceAt(workspaces_dir, "/global/workspaces");
    }

    fn seedAgentWorkspacesNamespaceAt(self: *Session, workspaces_dir: u32, base_path: []const u8) !void {
        return workspaces_venom.seedNamespaceAt(self, workspaces_dir, base_path);
    }

    fn seedChatNamespaceAt(self: *Session, chat_dir: u32, base_path: []const u8, jobs_path: []const u8) !void {
        return chat_venom.seedNamespaceAt(self, chat_dir, base_path, jobs_path);
    }

    fn seedJobsNamespaceAt(self: *Session, jobs_dir: u32, base_path: []const u8) !void {
        return jobs_venom.seedNamespaceAt(self, jobs_dir, base_path);
    }

    fn seedThoughtsNamespaceAt(self: *Session, thoughts_dir: u32, base_path: []const u8) !void {
        const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
        defer self.allocator.free(escaped_base_path);
        const shape_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"kind\":\"venom\",\"venom_id\":\"thoughts\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,latest.txt,history.ndjson,status.json}}\"}}",
            .{escaped_base_path},
        );
        defer self.allocator.free(shape_json);
        try self.addDirectoryDescriptors(
            thoughts_dir,
            "Thoughts",
            shape_json,
            "{\"read\":true,\"write\":false,\"discoverable\":true}",
            "Runtime internal thought stream (not chat output).",
        );
        _ = try self.addFile(
            thoughts_dir,
            "README.md",
            shared_node.venom_contracts.thoughts.readme_md,
            false,
            .none,
        );
        _ = try self.addFile(
            thoughts_dir,
            "SCHEMA.json",
            shared_node.venom_contracts.thoughts.schema_json,
            false,
            .none,
        );
        _ = try self.addFile(
            thoughts_dir,
            "CAPS.json",
            shared_node.venom_contracts.thoughts.caps_json,
            false,
            .none,
        );
        _ = try self.addFile(thoughts_dir, "OPS.json", shared_node.venom_contracts.thoughts.ops_json, false, .none);
        self.thoughts_latest_id = try self.addFile(thoughts_dir, "latest.txt", "", false, .none);
        self.thoughts_history_id = try self.addFile(thoughts_dir, "history.ndjson", "", false, .none);
        self.thoughts_status_id = try self.addFile(
            thoughts_dir,
            "status.json",
            shared_node.venom_contracts.thoughts.initial_status_json,
            false,
            .none,
        );
    }

    fn seedEventsNamespaceAt(self: *Session, events_dir: u32, base_path: []const u8) !void {
        return events_venom.seedNamespaceAt(self, events_dir, base_path);
    }

    fn seedAgentPrReviewNamespace(self: *Session, pr_review_dir: u32) !void {
        return pr_review_venom.seedNamespace(self, pr_review_dir);
    }

    fn seedAgentPrReviewNamespaceAt(self: *Session, pr_review_dir: u32, base_path: []const u8) !void {
        return pr_review_venom.seedNamespaceAt(self, pr_review_dir, base_path);
    }

    fn seedGlobalLibraryNamespace(self: *Session, library_dir: u32) !void {
        return self.seedGlobalLibraryNamespaceAt(library_dir, "/global/library");
    }

    fn seedGlobalLibraryNamespaceAt(self: *Session, library_dir: u32, base_path: []const u8) !void {
        const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
        defer self.allocator.free(escaped_base_path);
        const shape_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"kind\":\"venom\",\"venom_id\":\"library\",\"shape\":\"{s}/{{Index.md,README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,topics/*,use-cases/*}}\"}}",
            .{escaped_base_path},
        );
        defer self.allocator.free(shape_json);
        try self.addDirectoryDescriptors(
            library_dir,
            "Global Library",
            shape_json,
            "{\"invoke\":false,\"operations\":[],\"discoverable\":true,\"read_only\":true}",
            "Stable, system-wide documentation for common Spiderweb/Acheron operations.",
        );
        _ = try self.addFile(
            library_dir,
            "OPS.json",
            "{\"model\":\"static_docs\",\"transport\":\"filesystem\",\"paths\":{\"index\":\"Index.md\",\"topics\":\"topics/*\",\"use_cases\":\"use-cases/*\"},\"operations\":{}}",
            false,
            .none,
        );
        _ = try self.addFile(
            library_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"global\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            library_dir,
            "STATUS.json",
            "{\"venom_id\":\"library\",\"state\":\"namespace\",\"has_invoke\":false}",
            false,
            .none,
        );
        const topics_dir = try self.addDir(library_dir, "topics", false);
        const index_content = try self.loadGlobalLibraryIndexFromAssets();
        defer self.allocator.free(index_content);
        _ = try self.addFile(
            library_dir,
            "Index.md",
            index_content,
            false,
            .none,
        );

        const loaded_topics = try self.seedGlobalLibraryTopicsFromAssets(topics_dir);
        if (!loaded_topics) try self.seedDefaultGlobalLibraryTopics(topics_dir);

        const use_cases_dir = try self.addDir(library_dir, "use-cases", false);
        _ = try self.seedGlobalLibrarySubtreeFromAssets(use_cases_dir, "use-cases");
    }

    fn loadGlobalLibraryIndexFromAssets(self: *Session) ![]u8 {
        const index_path = try std.fs.path.join(self.allocator, &.{ self.assets_dir, "library", "Index.md" });
        defer self.allocator.free(index_path);
        return std.fs.cwd().readFileAlloc(self.allocator, index_path, 512 * 1024) catch
            self.allocator.dupe(u8, defaultGlobalLibraryIndexMd());
    }

    fn seedGlobalLibraryTopicsFromAssets(self: *Session, topics_dir: u32) !bool {
        const topics_path = try std.fs.path.join(self.allocator, &.{ self.assets_dir, "library", "topics" });
        defer self.allocator.free(topics_path);

        var topics_fs = std.fs.cwd().openDir(topics_path, .{ .iterate = true }) catch return false;
        defer topics_fs.close();

        var iterator = topics_fs.iterate();
        var loaded_any = false;
        while (try iterator.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
            const content = topics_fs.readFileAlloc(self.allocator, entry.name, 512 * 1024) catch continue;
            defer self.allocator.free(content);
            _ = try self.addFile(topics_dir, entry.name, content, false, .none);
            loaded_any = true;
        }
        return loaded_any;
    }

    fn seedGlobalLibrarySubtreeFromAssets(
        self: *Session,
        parent_dir: u32,
        relative_subtree: []const u8,
    ) !bool {
        const host_path = try std.fs.path.join(self.allocator, &.{ self.assets_dir, "library", relative_subtree });
        defer self.allocator.free(host_path);

        var host_dir = std.fs.cwd().openDir(host_path, .{ .iterate = true }) catch return false;
        defer host_dir.close();

        var iterator = host_dir.iterate();
        var loaded_any = false;
        while (try iterator.next()) |entry| {
            switch (entry.kind) {
                .file => {
                    const content = host_dir.readFileAlloc(self.allocator, entry.name, 512 * 1024) catch continue;
                    defer self.allocator.free(content);
                    _ = try self.addFile(parent_dir, entry.name, content, false, .none);
                    loaded_any = true;
                },
                .directory => {
                    const child_dir = try self.addDir(parent_dir, entry.name, false);
                    const child_relative = try std.fs.path.join(self.allocator, &.{ relative_subtree, entry.name });
                    defer self.allocator.free(child_relative);
                    if (try self.seedGlobalLibrarySubtreeFromAssets(child_dir, child_relative)) {
                        loaded_any = true;
                    }
                },
                else => {},
            }
        }
        return loaded_any;
    }

    fn seedDefaultGlobalLibraryTopics(self: *Session, topics_dir: u32) !void {
        _ = try self.addFile(
            topics_dir,
            "getting-started.md",
            defaultGlobalLibraryTopicGettingStarted(),
            false,
            .none,
        );
        _ = try self.addFile(
            topics_dir,
            "service-discovery.md",
            defaultGlobalLibraryTopicServiceDiscovery(),
            false,
            .none,
        );
        _ = try self.addFile(
            topics_dir,
            "events-and-waits.md",
            defaultGlobalLibraryTopicEventsAndWaits(),
            false,
            .none,
        );
        _ = try self.addFile(
            topics_dir,
            "search-services.md",
            defaultGlobalLibraryTopicSearchServices(),
            false,
            .none,
        );
        _ = try self.addFile(
            topics_dir,
            "terminal-workflows.md",
            defaultGlobalLibraryTopicTerminalWorkflows(),
            false,
            .none,
        );
        _ = try self.addFile(
            topics_dir,
            "memory-workflows.md",
            defaultGlobalLibraryTopicMemoryWorkflows(),
            false,
            .none,
        );
        _ = try self.addFile(
            topics_dir,
            "project-mounts-and-binds.md",
            defaultGlobalLibraryTopicProjectMountsAndBinds(),
            false,
            .none,
        );
        _ = try self.addFile(
            topics_dir,
            "agent-management-and-sub-brains.md",
            defaultGlobalLibraryTopicAgentManagementAndSubBrains(),
            false,
            .none,
        );
    }

    fn handleTerminalV2InvokeWrite(self: *Session, invoke_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleInvokeWrite(self, invoke_node_id, raw_input) };
    }

    fn handleTerminalV2CreateWrite(self: *Session, create_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleCreateWrite(self, create_node_id, raw_input) };
    }

    fn handleTerminalV2ResumeWrite(self: *Session, resume_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleResumeWrite(self, resume_node_id, raw_input) };
    }

    fn handleTerminalV2CloseWrite(self: *Session, close_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleCloseWrite(self, close_node_id, raw_input) };
    }

    fn handleTerminalV2WriteWrite(self: *Session, write_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleWriteWrite(self, write_node_id, raw_input) };
    }

    fn handleTerminalV2ReadWrite(self: *Session, read_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleReadWrite(self, read_node_id, raw_input) };
    }

    fn handleTerminalV2ResizeWrite(self: *Session, resize_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleResizeWrite(self, resize_node_id, raw_input) };
    }

    fn handleTerminalV2ExecWrite(self: *Session, exec_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        return .{ .written = try terminal_venom.handleExecWrite(self, exec_node_id, raw_input) };
    }

    pub fn buildTerminalExecArgsJson(
        self: *Session,
        obj: std.json.ObjectMap,
        session_cwd: ?[]const u8,
    ) ![]u8 {
        return terminal_venom.buildExecArgsJson(self, obj, session_cwd);
    }

    pub fn appendShellSingleQuoted(self: *Session, out: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
        return terminal_venom.appendShellSingleQuoted(self, out, value);
    }

    pub fn sessionJsonObjectOptionalString(self: *Session, obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
        _ = self;
        return jsonObjectOptionalString(obj, key);
    }

    pub fn sessionJsonObjectOptionalBool(self: *Session, obj: std.json.ObjectMap, key: []const u8) !?bool {
        _ = self;
        return jsonObjectOptionalBool(obj, key);
    }

    pub fn sessionJsonObjectOptionalU64(self: *Session, obj: std.json.ObjectMap, key: []const u8) !?u64 {
        _ = self;
        return jsonObjectOptionalU64(obj, key);
    }

    fn buildProjectTopologyJson(self: *Session, policy: workspace_policy.WorkspacePolicy) ![]u8 {
        const escaped_project = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project);
        const escaped_agent = try unified.jsonEscape(self.allocator, self.agent_id);
        defer self.allocator.free(escaped_agent);

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.writer(self.allocator).print(
            "{{\"project_id\":\"{s}\",\"agent_id\":\"{s}\",\"nodes\":[",
            .{ escaped_project, escaped_agent },
        );
        for (policy.nodes.items, 0..) |node, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const escaped_node_id = try unified.jsonEscape(self.allocator, node.id);
            defer self.allocator.free(escaped_node_id);
            try out.writer(self.allocator).print(
                "{{\"id\":\"{s}\",\"resources\":{{\"fs\":{s},\"camera\":{s},\"screen\":{s},\"user\":{s}}},\"terminals\":[",
                .{
                    escaped_node_id,
                    if (node.resources.fs) "true" else "false",
                    if (node.resources.camera) "true" else "false",
                    if (node.resources.screen) "true" else "false",
                    if (node.resources.user) "true" else "false",
                },
            );
            for (node.terminals.items, 0..) |terminal_id, term_idx| {
                if (term_idx != 0) try out.append(self.allocator, ',');
                const escaped_terminal = try unified.jsonEscape(self.allocator, terminal_id);
                defer self.allocator.free(escaped_terminal);
                try out.writer(self.allocator).print("\"{s}\"", .{escaped_terminal});
            }
            try out.appendSlice(self.allocator, "]}");
        }
        try out.appendSlice(self.allocator, "],\"project_links\":[");
        for (policy.project_links.items, 0..) |link, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const target = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/{s}", .{ link.node_id, link.resource });
            defer self.allocator.free(target);
            const escaped_name = try unified.jsonEscape(self.allocator, link.name);
            defer self.allocator.free(escaped_name);
            const escaped_node_id = try unified.jsonEscape(self.allocator, link.node_id);
            defer self.allocator.free(escaped_node_id);
            const escaped_resource = try unified.jsonEscape(self.allocator, link.resource);
            defer self.allocator.free(escaped_resource);
            const escaped_target = try unified.jsonEscape(self.allocator, target);
            defer self.allocator.free(escaped_target);
            try out.writer(self.allocator).print(
                "{{\"name\":\"{s}\",\"node_id\":\"{s}\",\"resource\":\"{s}\",\"target\":\"{s}\"}}",
                .{ escaped_name, escaped_node_id, escaped_resource, escaped_target },
            );
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    fn buildFallbackProjectNodesJson(self: *Session, policy: workspace_policy.WorkspacePolicy) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "[");
        for (policy.nodes.items, 0..) |node, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const escaped_node_id = try unified.jsonEscape(self.allocator, node.id);
            defer self.allocator.free(escaped_node_id);
            try out.writer(self.allocator).print(
                "{{\"node_id\":\"{s}\",\"state\":\"unknown\",\"mounts\":0}}",
                .{escaped_node_id},
            );
        }
        try out.appendSlice(self.allocator, "]");
        return out.toOwnedSlice(self.allocator);
    }

    fn buildProjectAgentsJson(self: *Session, policy: workspace_policy.WorkspacePolicy) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "[");
        const escaped_self_name = try unified.jsonEscape(self.allocator, self.agent_id);
        defer self.allocator.free(escaped_self_name);
        const self_target = try std.fmt.allocPrint(self.allocator, "/agents/{s}", .{self.agent_id});
        defer self.allocator.free(self_target);
        const escaped_self_target = try unified.jsonEscape(self.allocator, self_target);
        defer self.allocator.free(escaped_self_target);
        try out.writer(self.allocator).print(
            "{{\"name\":\"{s}\",\"target\":\"{s}\",\"kind\":\"active\"}}",
            .{ escaped_self_name, escaped_self_target },
        );
        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
            if (std.mem.eql(u8, agent_name, self.agent_id)) continue;
            const escaped_agent_name = try unified.jsonEscape(self.allocator, agent_name);
            defer self.allocator.free(escaped_agent_name);
            const target = try std.fmt.allocPrint(self.allocator, "/agents/{s}", .{agent_name});
            defer self.allocator.free(target);
            const escaped_target = try unified.jsonEscape(self.allocator, target);
            defer self.allocator.free(escaped_target);
            try out.writer(self.allocator).print(
                ",{{\"name\":\"{s}\",\"target\":\"{s}\",\"kind\":\"visible\"}}",
                .{ escaped_agent_name, escaped_target },
            );
        }
        try out.appendSlice(self.allocator, "]");
        return out.toOwnedSlice(self.allocator);
    }

    fn buildProjectContractsJson(self: *Session, project_id: []const u8) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project_id);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"version\":\"acheron-namespace-project-contract-v2\",\"project_id\":\"{s}\",\"top_level_roots\":[\"/nodes\",\"/agents\",\"/global\",\"/services\"],\"project_metadata_files\":[\"topology.json\",\"nodes.json\",\"agents.json\",\"sources.json\",\"contracts.json\",\"paths.json\",\"summary.json\",\"alerts.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"binds.json\",\"mounted_services.json\",\"venom_packages.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"],\"links\":{{\"nodes_root\":\"/nodes\",\"agents_root\":\"/agents\",\"global_root\":\"/global\",\"services_root\":\"/services\",\"workspace_control\":\"/global/workspaces\",\"workspace_status\":\"/global/workspaces/control/invoke.json\",\"workspace_binds\":\"/projects/{s}/meta/binds.json\",\"workspace_services\":\"/projects/{s}/meta/mounted_services.json\",\"venom_packages\":\"/projects/{s}/meta/venom_packages.json\"}}}}",
            .{ escaped_project_id, escaped_project_id, escaped_project_id, escaped_project_id },
        );
    }

    fn buildProjectPathsJson(self: *Session, policy: workspace_policy.WorkspacePolicy) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project_id);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"nodes_root\":\"/nodes\",\"agents_root\":\"/agents\",\"services\":{{\"root\":\"/services\",\"mounted_services_meta\":\"/projects/{s}/meta/mounted_services.json\"}},\"packages\":{{\"meta\":\"/projects/{s}/meta/venom_packages.json\"}},\"global\":{{\"root\":\"/global\",\"library\":\"/global/library\",\"workspaces\":\"/global/workspaces\",\"chat\":\"/global/chat\",\"jobs\":\"/global/jobs\",\"mounts\":\"/global/mounts\",\"debug\":{s}}}}}",
            .{
                escaped_project_id,
                escaped_project_id,
                escaped_project_id,
                if (policy.show_debug or self.is_admin) "\"/debug\"" else "null",
            },
        );
    }

    fn buildProjectSourcesJson(
        self: *Session,
        project_id: []const u8,
        has_workspace_status: bool,
        fs_from_workspace: bool,
        project_nodes_from_workspace: bool,
        nodes_meta_from_workspace: bool,
    ) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project_id);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"workspace_status\":\"{s}\",\"project_fs\":\"{s}\",\"project_nodes\":\"{s}\",\"nodes_meta\":\"{s}\",\"project_binds\":\"control_plane\",\"mounted_services\":\"namespace_projection\"}}",
            .{
                escaped_project_id,
                if (has_workspace_status) "control_plane" else "policy",
                if (fs_from_workspace) "workspace_mounts" else "policy_links",
                if (project_nodes_from_workspace) "workspace_mounts" else "policy_nodes",
                if (nodes_meta_from_workspace) "workspace_mounts" else "policy_nodes",
            },
        );
    }

    fn buildProjectSummaryJson(
        self: *Session,
        policy: workspace_policy.WorkspacePolicy,
        workspace_status_json: ?[]const u8,
        loaded_live_mounts: bool,
        loaded_live_nodes: bool,
        nodes_meta_from_workspace: bool,
    ) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project_id);

        var policy_agent_links: usize = 1;
        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
            if (std.mem.eql(u8, agent_name, self.agent_id)) continue;
            policy_agent_links += 1;
        }

        var workspace_mount_links: usize = 0;
        var workspace_node_links: usize = 0;
        var reconcile_state: []const u8 = "unknown";
        var reconcile_state_owned: ?[]u8 = null;
        defer if (reconcile_state_owned) |owned| self.allocator.free(owned);
        var queue_depth: i64 = 0;
        var health_state: []const u8 = "unknown";

        if (workspace_status_json) |status_json| {
            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, status_json, .{}) catch null;
            if (parsed) |*status_parsed| {
                defer status_parsed.deinit();
                if (status_parsed.value == .object) {
                    if (status_parsed.value.object.get("reconcile_state")) |value| {
                        if (value == .string and value.string.len > 0) {
                            reconcile_state_owned = try self.allocator.dupe(u8, value.string);
                            reconcile_state = reconcile_state_owned.?;
                        }
                    }
                    if (status_parsed.value.object.get("queue_depth")) |value| {
                        if (value == .integer and value.integer >= 0) queue_depth = value.integer;
                    }

                    var missing: i64 = 0;
                    var degraded: i64 = 0;
                    var drift_count: i64 = 0;
                    if (status_parsed.value.object.get("availability")) |availability_value| {
                        if (availability_value == .object) {
                            if (availability_value.object.get("missing")) |value| {
                                if (value == .integer and value.integer >= 0) missing = value.integer;
                            }
                            if (availability_value.object.get("degraded")) |value| {
                                if (value == .integer and value.integer >= 0) degraded = value.integer;
                            }
                        }
                    }
                    if (status_parsed.value.object.get("drift")) |drift_value| {
                        if (drift_value == .object) {
                            if (drift_value.object.get("count")) |value| {
                                if (value == .integer and value.integer >= 0) drift_count = value.integer;
                            }
                        }
                    }

                    if (status_parsed.value.object.get("mounts")) |mounts_value| {
                        if (mounts_value == .array) {
                            workspace_mount_links = mounts_value.array.items.len;
                            var nodes_seen = std.StringHashMapUnmanaged(void){};
                            defer nodes_seen.deinit(self.allocator);
                            for (mounts_value.array.items) |mount_value| {
                                if (mount_value != .object) continue;
                                const node_id_value = mount_value.object.get("node_id") orelse continue;
                                if (node_id_value != .string or node_id_value.string.len == 0) continue;
                                if (!nodes_seen.contains(node_id_value.string)) {
                                    try nodes_seen.put(self.allocator, node_id_value.string, {});
                                }
                            }
                            workspace_node_links = nodes_seen.count();
                        }
                    }

                    health_state = if (missing > 0)
                        "missing"
                    else if (degraded > 0 or drift_count > 0 or queue_depth > 0 or std.mem.eql(u8, reconcile_state, "degraded"))
                        "degraded"
                    else if (std.mem.eql(u8, reconcile_state, "unknown"))
                        "unknown"
                    else
                        "healthy";
                }
            }
        }

        const source_workspace_status = if (workspace_status_json != null) "control_plane" else "policy";
        const source_project_fs = if (loaded_live_mounts) "workspace_mounts" else "policy_links";
        const source_project_nodes = if (loaded_live_nodes) "workspace_mounts" else "policy_nodes";
        const source_nodes_meta = if (nodes_meta_from_workspace) "workspace_mounts" else "policy_nodes";
        const project_mount_links = if (loaded_live_mounts and workspace_mount_links > 0) workspace_mount_links else policy.project_links.items.len;
        const project_node_links = if (loaded_live_nodes and workspace_node_links > 0) workspace_node_links else policy.nodes.items.len;

        const escaped_health_state = try unified.jsonEscape(self.allocator, health_state);
        defer self.allocator.free(escaped_health_state);
        const escaped_reconcile_state = try unified.jsonEscape(self.allocator, reconcile_state);
        defer self.allocator.free(escaped_reconcile_state);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"sources\":{{\"workspace_status\":\"{s}\",\"project_fs\":\"{s}\",\"project_nodes\":\"{s}\",\"nodes_meta\":\"{s}\"}},\"counts\":{{\"policy_nodes\":{d},\"policy_links\":{d},\"visible_agents\":{d},\"project_agent_links\":{d},\"project_node_links\":{d},\"project_mount_links\":{d}}},\"health\":{{\"state\":\"{s}\",\"reconcile_state\":\"{s}\",\"queue_depth\":{d}}}}}",
            .{
                escaped_project_id,
                source_workspace_status,
                source_project_fs,
                source_project_nodes,
                source_nodes_meta,
                policy.nodes.items.len,
                policy.project_links.items.len,
                policy.visible_agents.items.len,
                policy_agent_links,
                project_node_links,
                project_mount_links,
                escaped_health_state,
                escaped_reconcile_state,
                queue_depth,
            },
        );
    }

    fn extractWorkspaceAlerts(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        var missing: i64 = 0;
        var degraded: i64 = 0;
        var drift_count: i64 = 0;
        var queue_depth: i64 = 0;
        var reconcile_state: []const u8 = "unknown";

        if (parsed.value.object.get("availability")) |availability_value| {
            if (availability_value == .object) {
                if (availability_value.object.get("missing")) |value| {
                    if (value == .integer and value.integer >= 0) missing = value.integer;
                }
                if (availability_value.object.get("degraded")) |value| {
                    if (value == .integer and value.integer >= 0) degraded = value.integer;
                }
            }
        }
        if (parsed.value.object.get("drift")) |drift_value| {
            if (drift_value == .object) {
                if (drift_value.object.get("count")) |value| {
                    if (value == .integer and value.integer >= 0) drift_count = value.integer;
                }
            }
        }
        if (parsed.value.object.get("queue_depth")) |value| {
            if (value == .integer and value.integer >= 0) queue_depth = value.integer;
        }
        if (parsed.value.object.get("reconcile_state")) |value| {
            if (value == .string and value.string.len > 0) reconcile_state = value.string;
        }

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "[");
        var first = true;

        if (missing > 0) {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try out.writer(self.allocator).print(
                "{{\"id\":\"missing_mounts\",\"severity\":\"error\",\"count\":{d},\"message\":\"missing mounts detected\"}}",
                .{missing},
            );
        }
        if (degraded > 0) {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try out.writer(self.allocator).print(
                "{{\"id\":\"degraded_mounts\",\"severity\":\"warning\",\"count\":{d},\"message\":\"degraded mounts detected\"}}",
                .{degraded},
            );
        }
        if (drift_count > 0) {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try out.writer(self.allocator).print(
                "{{\"id\":\"workspace_drift\",\"severity\":\"warning\",\"count\":{d},\"message\":\"workspace drift detected\"}}",
                .{drift_count},
            );
        }
        if (std.mem.eql(u8, reconcile_state, "degraded")) {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try out.appendSlice(self.allocator, "{\"id\":\"reconcile_degraded\",\"severity\":\"warning\",\"message\":\"reconcile state degraded\"}");
        }
        if (queue_depth > 0) {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try out.writer(self.allocator).print(
                "{{\"id\":\"reconcile_queue\",\"severity\":\"info\",\"count\":{d},\"message\":\"reconcile queue pending\"}}",
                .{queue_depth},
            );
        }

        try out.appendSlice(self.allocator, "]");
        const rendered = try out.toOwnedSlice(self.allocator);
        return rendered;
    }

    fn loadProjectWorkspaceStatus(self: *Session, project_id: []const u8) !?[]u8 {
        const plane = self.control_plane orelse return null;
        const escaped_project_id = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project_id);
        const request_json = if (self.project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
                .{ escaped_project_id, escaped_token },
            );
        } else try std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\"}}",
            .{escaped_project_id},
        );
        defer self.allocator.free(request_json);

        if (plane.workspaceStatus(self.agent_id, request_json) catch null) |status_json| {
            if (try self.workspaceStatusMatchesProject(status_json, project_id)) {
                return status_json;
            }
            self.allocator.free(status_json);
        }

        if (plane.workspaceStatus(self.agent_id, null) catch null) |status_json| {
            if (try self.workspaceStatusMatchesProject(status_json, project_id)) {
                return status_json;
            }
            self.allocator.free(status_json);
        }

        return null;
    }

    fn workspaceStatusMatchesProject(
        self: *Session,
        workspace_status_json: []const u8,
        expected_project_id: []const u8,
    ) !bool {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        const project_id_value = parsed.value.object.get("project_id") orelse return false;
        if (project_id_value != .string) return false;
        return std.mem.eql(u8, project_id_value.string, expected_project_id);
    }

    fn extractWorkspaceAvailability(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const availability_value = parsed.value.object.get("availability") orelse return null;
        if (availability_value != .object) return null;
        const rendered = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(availability_value, .{})});
        return rendered;
    }

    fn extractWorkspaceNodes(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        const NodeSummary = struct {
            node_id: []const u8,
            state_rank: u8,
            mounts: u32,
        };
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const mounts_value = parsed.value.object.get("mounts") orelse return null;
        if (mounts_value != .array) return null;

        var summaries = std.ArrayListUnmanaged(NodeSummary){};
        defer summaries.deinit(self.allocator);
        for (mounts_value.array.items) |mount_value| {
            if (mount_value != .object) continue;
            const node_id_value = mount_value.object.get("node_id") orelse continue;
            if (node_id_value != .string or node_id_value.string.len == 0) continue;
            const state = if (mount_value.object.get("state")) |value|
                if (value == .string) value.string else "unknown"
            else
                "unknown";
            const rank = mountStateRank(state);

            var merged = false;
            for (summaries.items) |*entry| {
                if (!std.mem.eql(u8, entry.node_id, node_id_value.string)) continue;
                entry.mounts +%= 1;
                if (rank > entry.state_rank) entry.state_rank = rank;
                merged = true;
                break;
            }
            if (!merged) {
                try summaries.append(self.allocator, .{
                    .node_id = node_id_value.string,
                    .state_rank = rank,
                    .mounts = 1,
                });
            }
        }

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "[");
        for (summaries.items, 0..) |entry, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const escaped_node_id = try unified.jsonEscape(self.allocator, entry.node_id);
            defer self.allocator.free(escaped_node_id);
            const state = mountStateNameFromRank(entry.state_rank);
            try out.writer(self.allocator).print(
                "{{\"node_id\":\"{s}\",\"state\":\"{s}\",\"mounts\":{d}}}",
                .{ escaped_node_id, state, entry.mounts },
            );
        }
        try out.appendSlice(self.allocator, "]");
        const rendered = try out.toOwnedSlice(self.allocator);
        return rendered;
    }

    fn mountStateRank(state: []const u8) u8 {
        if (std.mem.eql(u8, state, "missing")) return 3;
        if (std.mem.eql(u8, state, "degraded")) return 2;
        if (std.mem.eql(u8, state, "online")) return 1;
        return 0;
    }

    fn mountStateNameFromRank(rank: u8) []const u8 {
        return switch (rank) {
            3 => "missing",
            2 => "degraded",
            1 => "online",
            else => "unknown",
        };
    }

    fn extractWorkspaceMounts(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const mounts_value = parsed.value.object.get("mounts") orelse return null;
        if (mounts_value != .array) return null;
        const rendered = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(mounts_value, .{})});
        return rendered;
    }

    fn extractWorkspaceDesiredMounts(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const mounts_value = parsed.value.object.get("desired_mounts") orelse return null;
        if (mounts_value != .array) return null;
        const rendered = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(mounts_value, .{})});
        return rendered;
    }

    fn extractWorkspaceActualMounts(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const mounts_value = parsed.value.object.get("actual_mounts") orelse return null;
        if (mounts_value != .array) return null;
        const rendered = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(mounts_value, .{})});
        return rendered;
    }

    fn extractWorkspaceDrift(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const drift_value = parsed.value.object.get("drift") orelse return null;
        if (drift_value != .object) return null;
        const rendered = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(drift_value, .{})});
        return rendered;
    }

    fn extractWorkspaceReconcile(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const reconcile_state = blk: {
            if (parsed.value.object.get("reconcile_state")) |value| {
                if (value == .string and value.string.len > 0) break :blk value.string;
            }
            break :blk "unknown";
        };
        const last_reconcile_ms: i64 = blk: {
            if (parsed.value.object.get("last_reconcile_ms")) |value| {
                if (value == .integer) break :blk value.integer;
            }
            break :blk 0;
        };
        const last_success_ms: i64 = blk: {
            if (parsed.value.object.get("last_success_ms")) |value| {
                if (value == .integer) break :blk value.integer;
            }
            break :blk 0;
        };
        const queue_depth: i64 = blk: {
            if (parsed.value.object.get("queue_depth")) |value| {
                if (value == .integer and value.integer >= 0) break :blk value.integer;
            }
            break :blk 0;
        };
        const last_error_json = if (parsed.value.object.get("last_error")) |value|
            try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})})
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(last_error_json);
        const escaped_state = try unified.jsonEscape(self.allocator, reconcile_state);
        defer self.allocator.free(escaped_state);

        const rendered = try std.fmt.allocPrint(
            self.allocator,
            "{{\"reconcile_state\":\"{s}\",\"last_reconcile_ms\":{d},\"last_success_ms\":{d},\"last_error\":{s},\"queue_depth\":{d}}}",
            .{ escaped_state, last_reconcile_ms, last_success_ms, last_error_json, queue_depth },
        );
        return rendered;
    }

    fn extractWorkspaceHealth(self: *Session, workspace_status_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, workspace_status_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        var mounts_total: i64 = 0;
        var online: i64 = 0;
        var degraded: i64 = 0;
        var missing: i64 = 0;
        if (parsed.value.object.get("availability")) |availability_value| {
            if (availability_value == .object) {
                if (availability_value.object.get("mounts_total")) |value| {
                    if (value == .integer and value.integer >= 0) mounts_total = value.integer;
                }
                if (availability_value.object.get("online")) |value| {
                    if (value == .integer and value.integer >= 0) online = value.integer;
                }
                if (availability_value.object.get("degraded")) |value| {
                    if (value == .integer and value.integer >= 0) degraded = value.integer;
                }
                if (availability_value.object.get("missing")) |value| {
                    if (value == .integer and value.integer >= 0) missing = value.integer;
                }
            }
        }

        var drift_count: i64 = 0;
        if (parsed.value.object.get("drift")) |drift_value| {
            if (drift_value == .object) {
                if (drift_value.object.get("count")) |value| {
                    if (value == .integer and value.integer >= 0) drift_count = value.integer;
                }
            }
        }

        const reconcile_state = blk: {
            if (parsed.value.object.get("reconcile_state")) |value| {
                if (value == .string and value.string.len > 0) break :blk value.string;
            }
            break :blk "unknown";
        };
        const queue_depth: i64 = blk: {
            if (parsed.value.object.get("queue_depth")) |value| {
                if (value == .integer and value.integer >= 0) break :blk value.integer;
            }
            break :blk 0;
        };
        const state = blk: {
            if (missing > 0) break :blk "missing";
            if (degraded > 0 or drift_count > 0 or queue_depth > 0 or std.mem.eql(u8, reconcile_state, "degraded")) {
                break :blk "degraded";
            }
            if (std.mem.eql(u8, reconcile_state, "unknown")) break :blk "unknown";
            break :blk "healthy";
        };

        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const escaped_reconcile_state = try unified.jsonEscape(self.allocator, reconcile_state);
        defer self.allocator.free(escaped_reconcile_state);

        const rendered = try std.fmt.allocPrint(
            self.allocator,
            "{{\"state\":\"{s}\",\"availability\":{{\"mounts_total\":{d},\"online\":{d},\"degraded\":{d},\"missing\":{d}}},\"drift_count\":{d},\"reconcile_state\":\"{s}\",\"queue_depth\":{d}}}",
            .{ escaped_state, mounts_total, online, degraded, missing, drift_count, escaped_reconcile_state, queue_depth },
        );
        return rendered;
    }

    fn buildFallbackWorkspaceStatusJson(self: *Session, policy: workspace_policy.WorkspacePolicy) ![]u8 {
        const escaped_agent = try unified.jsonEscape(self.allocator, self.agent_id);
        defer self.allocator.free(escaped_agent);
        const escaped_project = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"template_id\":null,\"source\":\"policy\",\"workspace_root\":null,\"mounts\":[],\"desired_mounts\":[],\"actual_mounts\":[],\"drift\":{{\"count\":0,\"items\":[]}},\"availability\":{{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0}},\"reconcile_state\":\"unknown\",\"last_reconcile_ms\":0,\"last_success_ms\":0,\"last_error\":null,\"queue_depth\":0}}",
            .{ escaped_agent, escaped_project },
        );
    }

    const NodeResourceView = struct {
        fs: bool = false,
        camera: bool = false,
        screen: bool = false,
        user: bool = false,
        terminals: std.ArrayListUnmanaged([]u8) = .{},
        roots: std.ArrayListUnmanaged([]u8) = .{},

        fn deinit(self: *NodeResourceView, allocator: std.mem.Allocator) void {
            for (self.terminals.items) |terminal_id| allocator.free(terminal_id);
            self.terminals.deinit(allocator);
            for (self.roots.items) |root| allocator.free(root);
            self.roots.deinit(allocator);
            self.* = undefined;
        }

        fn addRoot(self: *NodeResourceView, allocator: std.mem.Allocator, root: []const u8) !void {
            if (root.len == 0) return;
            for (self.roots.items) |existing| {
                if (std.mem.eql(u8, existing, root)) return;
            }
            try self.roots.append(allocator, try allocator.dupe(u8, root));
        }

        fn observeMounts(
            self: *NodeResourceView,
            allocator: std.mem.Allocator,
            node_id: []const u8,
            mounts_json: []const u8,
        ) !void {
            if (mounts_json.len == 0) return;
            var parsed = std.json.parseFromSlice(std.json.Value, allocator, mounts_json, .{}) catch return;
            defer parsed.deinit();
            if (parsed.value != .array) return;
            for (parsed.value.array.items) |mount| {
                if (mount != .object) continue;
                const mount_path_value = mount.object.get("mount_path") orelse continue;
                if (mount_path_value != .string) continue;
                const root = nodeRootNameFromPath(node_id, mount_path_value.string) orelse continue;
                try self.addRoot(allocator, root);
            }
        }

        fn observe(
            self: *NodeResourceView,
            allocator: std.mem.Allocator,
            node_id: []const u8,
            kind: []const u8,
            venom_id: []const u8,
            endpoint: []const u8,
            mounts_json: []const u8,
        ) !void {
            var handled_terminal = false;
            if (std.mem.eql(u8, kind, "fs")) {
                self.fs = true;
                try self.addRoot(allocator, "fs");
            }
            if (std.mem.eql(u8, kind, "camera")) {
                self.camera = true;
                try self.addRoot(allocator, "camera");
            }
            if (std.mem.eql(u8, kind, "screen")) {
                self.screen = true;
                try self.addRoot(allocator, "screen");
            }
            if (std.mem.eql(u8, kind, "user")) {
                self.user = true;
                try self.addRoot(allocator, "user");
            }
            if (std.mem.eql(u8, kind, "terminal")) {
                handled_terminal = true;
                try self.addRoot(allocator, "terminal");

                const maybe_terminal_id = if (std.mem.startsWith(u8, venom_id, "terminal-") and venom_id.len > "terminal-".len)
                    venom_id["terminal-".len..]
                else
                    terminalIdFromEndpoint(endpoint);
                const terminal_id = maybe_terminal_id orelse {
                    try self.observeMounts(allocator, node_id, mounts_json);
                    return;
                };
                if (terminal_id.len == 0) {
                    try self.observeMounts(allocator, node_id, mounts_json);
                    return;
                }
                for (self.terminals.items) |existing| {
                    if (std.mem.eql(u8, existing, terminal_id)) {
                        try self.observeMounts(allocator, node_id, mounts_json);
                        return;
                    }
                }
                try self.terminals.append(allocator, try allocator.dupe(u8, terminal_id));
            }

            try self.observeMounts(allocator, node_id, mounts_json);
            if (!handled_terminal) {
                if (nodeRootNameFromPath(node_id, endpoint)) |root| {
                    try self.addRoot(allocator, root);
                }
            }
        }
    };

    fn nodeRootNameFromPath(node_id: []const u8, mount_path: []const u8) ?[]const u8 {
        if (!std.mem.startsWith(u8, mount_path, "/nodes/")) return null;
        const after_nodes = mount_path["/nodes/".len..];
        if (!std.mem.startsWith(u8, after_nodes, node_id)) return null;
        if (after_nodes.len <= node_id.len or after_nodes[node_id.len] != '/') return null;
        const tail = after_nodes[node_id.len + 1 ..];
        if (tail.len == 0) return null;
        const slash = std.mem.indexOfScalar(u8, tail, '/') orelse tail.len;
        const root = tail[0..slash];
        if (root.len == 0) return null;
        for (root) |char| {
            if (std.ascii.isAlphanumeric(char)) continue;
            if (char == '-' or char == '_' or char == '.') continue;
            return null;
        }
        return root;
    }

    fn terminalIdFromEndpoint(endpoint: []const u8) ?[]const u8 {
        if (endpoint.len == 0) return null;
        const marker = "/terminal/";
        const marker_start = std.mem.lastIndexOf(u8, endpoint, marker) orelse return null;
        const start = marker_start + marker.len;
        if (start >= endpoint.len) return null;
        const tail = endpoint[start..];
        const slash = std.mem.indexOfScalar(u8, tail, '/') orelse tail.len;
        const id = tail[0..slash];
        if (id.len == 0) return null;
        return id;
    }

    fn projectAllowsAction(self: *Session, action: control_plane_mod.ProjectAction) bool {
        const plane = self.control_plane orelse return true;
        const project_id = self.project_id orelse return true;
        return plane.projectAllowsAction(project_id, self.agent_id, action, self.project_token, self.is_admin);
    }

    fn canAccessVenomWithPermissions(self: *Session, permissions_json: []const u8) bool {
        if (!self.projectAllowsAction(.invoke)) return false;
        if (self.is_admin) return true;
        if (permissions_json.len == 0) return true;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, permissions_json, .{}) catch return true;
        defer parsed.deinit();
        if (parsed.value != .object) return true;

        const obj = parsed.value.object;

        const require_project_token = blk: {
            if (obj.get("require_project_token")) |value| {
                if (value == .bool) break :blk value.bool;
            }
            if (obj.get("project_token_required")) |value| {
                if (value == .bool) break :blk value.bool;
            }
            break :blk false;
        };
        if (require_project_token and self.project_token == null) return false;

        if (obj.get("allow_roles")) |roles| {
            if (roles == .array) {
                for (roles.array.items) |role| {
                    if (role != .string) continue;
                    if (std.mem.eql(u8, role.string, "user")) return true;
                    if (std.mem.eql(u8, role.string, "*")) return true;
                    if (std.mem.eql(u8, role.string, "all")) return true;
                }
                return false;
            }
        }

        if (obj.get("default")) |value| {
            if (value == .string) {
                if (std.mem.eql(u8, value.string, "deny-by-default")) return false;
                if (std.mem.eql(u8, value.string, "deny")) return false;
            }
        }

        return true;
    }

    pub fn canInvokeVenomDirectory(self: *Session, venom_dir_id: u32) bool {
        const permissions_id = self.lookupChild(venom_dir_id, "PERMISSIONS.json") orelse {
            return self.canAccessVenomWithPermissions("");
        };
        const permissions_node = self.nodes.get(permissions_id) orelse {
            return self.canAccessVenomWithPermissions("");
        };
        return self.canAccessVenomWithPermissions(permissions_node.content);
    }

    fn canInvokeTerminalNamespace(self: *Session, terminal_node_id: u32) bool {
        const terminal_node = self.nodes.get(terminal_node_id) orelse return false;
        const control_dir_id = terminal_node.parent orelse return false;
        const venom_dir_id = (self.nodes.get(control_dir_id) orelse return false).parent orelse return false;
        if (!self.canInvokeVenomDirectory(venom_dir_id)) return false;
        if (!self.is_admin and std.mem.eql(u8, self.actor_type, "user")) return false;
        return true;
    }

    fn isTerminalV2Special(special: SpecialKind) bool {
        return switch (special) {
            .terminal_v2_invoke,
            .terminal_v2_create,
            .terminal_v2_resume,
            .terminal_v2_close,
            .terminal_v2_exec,
            .terminal_v2_write,
            .terminal_v2_read,
            .terminal_v2_resize,
            => true,
            else => false,
        };
    }

    fn appendVenomIndexEntry(
        self: *Session,
        out: *std.ArrayListUnmanaged(u8),
        first: *bool,
        venom_id: []const u8,
        kind: []const u8,
        state: []const u8,
        endpoint: []const u8,
    ) !void {
        if (!first.*) try out.append(self.allocator, ',');
        first.* = false;
        const escaped_venom_id = try unified.jsonEscape(self.allocator, venom_id);
        defer self.allocator.free(escaped_venom_id);
        const escaped_kind = try unified.jsonEscape(self.allocator, kind);
        defer self.allocator.free(escaped_kind);
        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const escaped_endpoint = try unified.jsonEscape(self.allocator, endpoint);
        defer self.allocator.free(escaped_endpoint);
        try out.writer(self.allocator).print(
            "{{\"venom_id\":\"{s}\",\"kind\":\"{s}\",\"state\":\"{s}\",\"endpoint\":\"{s}\"}}",
            .{ escaped_venom_id, escaped_kind, escaped_state, escaped_endpoint },
        );
    }

    fn addNodeVenoms(self: *Session, node_dir: u32, node: workspace_policy.WorkspaceNodePolicy) !NodeResourceView {
        var view = NodeResourceView{};
        errdefer view.deinit(self.allocator);

        const venoms_root = try self.addDir(node_dir, "venoms", false);
        try self.addDirectoryDescriptors(
            venoms_root,
            "Node Venoms",
            "{\"kind\":\"collection\",\"entries\":\"venom_id\",\"shape\":\"/nodes/<node_id>/venoms/<venom_id>/{README.md,SCHEMA.json,TEMPLATE.json,CAPS.json,MOUNTS.json,OPS.json,RUNTIME.json,HOST.json,PERMISSIONS.json,STATUS.json}\"}",
            "{\"read\":true,\"write\":false}",
            "Node Venom descriptors mirrored from the node Venom catalog.",
        );
        var services_index = std.ArrayListUnmanaged(u8){};
        defer services_index.deinit(self.allocator);
        try services_index.append(self.allocator, '[');
        var services_index_first = true;

        switch (try self.loadNodeVenomsFromControlPlane(node.id)) {
            .catalog => |catalog_value| {
                var catalog = catalog_value;
                defer catalog.deinit(self.allocator);
                for (catalog.items.items) |venom| {
                    if (!self.canAccessVenomWithPermissions(venom.permissions_json)) continue;
                    try self.addNodeVenomEntry(
                        venoms_root,
                        venom.venom_id,
                        venom.package_id,
                        venom.instance_id,
                        venom.kind,
                        venom.version,
                        venom.state,
                        venom.provider_scope,
                        venom.categories_json,
                        venom.hosts_json,
                        venom.projection_modes_json,
                        venom.requirements_json,
                        venom.endpoint,
                        venom.caps_json,
                        venom.mounts_json,
                        venom.ops_json,
                        venom.runtime_json,
                        venom.permissions_json,
                        venom.schema_json,
                        venom.invoke_template_json,
                        venom.help_md,
                    );
                    try view.observe(
                        self.allocator,
                        node.id,
                        venom.kind,
                        venom.venom_id,
                        venom.endpoint,
                        venom.mounts_json,
                    );
                    try self.appendVenomIndexEntry(
                        &services_index,
                        &services_index_first,
                        venom.venom_id,
                        venom.kind,
                        venom.state,
                        venom.endpoint,
                    );
                }
                try services_index.append(self.allocator, ']');
                const services_index_json = try services_index.toOwnedSlice(self.allocator);
                defer self.allocator.free(services_index_json);
                _ = try self.addFile(venoms_root, "VENOMS.json", services_index_json, false, .none);
                return view;
            },
            .empty => {
                try services_index.append(self.allocator, ']');
                const services_index_json = try services_index.toOwnedSlice(self.allocator);
                defer self.allocator.free(services_index_json);
                _ = try self.addFile(venoms_root, "VENOMS.json", services_index_json, false, .none);
                return view;
            },
            .unavailable => {},
        }

        if (node.resources.fs) {
            const caps = "{\"rw\":true}";
            const mounts = try std.fmt.allocPrint(
                self.allocator,
                "[{{\"mount_id\":\"fs\",\"mount_path\":\"/nodes/{s}/fs\",\"state\":\"online\"}}]",
                .{node.id},
            );
            defer self.allocator.free(mounts);
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/fs", .{node.id});
            defer self.allocator.free(endpoint);
            const permissions = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"project\"}";
            if (self.canAccessVenomWithPermissions(permissions)) {
                try self.addNodeVenomEntry(
                    venoms_root,
                    "fs",
                    "fs",
                    "local:fs",
                    "fs",
                    "1",
                    "online",
                    "node_export",
                    "[\"filesystem\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"filesystem\"}",
                    null,
                    "Project node filesystem export.",
                );
                try self.addNodeVenomEntry(
                    venoms_root,
                    "fs",
                    "fs",
                    "local:fs",
                    "fs",
                    "1",
                    "online",
                    "node_export",
                    "[\"filesystem\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"filesystem\"}",
                    null,
                    "Project node filesystem export.",
                );
                try view.observe(self.allocator, node.id, "fs", "fs", endpoint, mounts);
                try self.appendVenomIndexEntry(&services_index, &services_index_first, "fs", "fs", "online", endpoint);
            }
        }
        if (node.resources.camera) {
            const caps = "{\"still\":true}";
            const mounts = try std.fmt.allocPrint(
                self.allocator,
                "[{{\"mount_id\":\"camera\",\"mount_path\":\"/nodes/{s}/camera\",\"state\":\"online\"}}]",
                .{node.id},
            );
            defer self.allocator.free(mounts);
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/camera", .{node.id});
            defer self.allocator.free(endpoint);
            const permissions = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"node\"}";
            if (self.canAccessVenomWithPermissions(permissions)) {
                try self.addNodeVenomEntry(
                    venoms_root,
                    "camera",
                    "camera",
                    "local:camera",
                    "camera",
                    "1",
                    "online",
                    "node_export",
                    "[\"camera\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"camera\"}",
                    null,
                    "Camera capture namespace.",
                );
                try self.addNodeVenomEntry(
                    venoms_root,
                    "camera",
                    "camera",
                    "local:camera",
                    "camera",
                    "1",
                    "online",
                    "node_export",
                    "[\"camera\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"camera\"}",
                    null,
                    "Camera capture namespace.",
                );
                try view.observe(self.allocator, node.id, "camera", "camera", endpoint, mounts);
                try self.appendVenomIndexEntry(&services_index, &services_index_first, "camera", "camera", "online", endpoint);
            }
        }
        if (node.resources.screen) {
            const caps = "{\"capture\":true}";
            const mounts = try std.fmt.allocPrint(
                self.allocator,
                "[{{\"mount_id\":\"screen\",\"mount_path\":\"/nodes/{s}/screen\",\"state\":\"online\"}}]",
                .{node.id},
            );
            defer self.allocator.free(mounts);
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/screen", .{node.id});
            defer self.allocator.free(endpoint);
            const permissions = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"node\"}";
            if (self.canAccessVenomWithPermissions(permissions)) {
                try self.addNodeVenomEntry(
                    venoms_root,
                    "screen",
                    "screen",
                    "local:screen",
                    "screen",
                    "1",
                    "online",
                    "node_export",
                    "[\"screen\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"screen\"}",
                    null,
                    "Screen capture namespace.",
                );
                try self.addNodeVenomEntry(
                    venoms_root,
                    "screen",
                    "screen",
                    "local:screen",
                    "screen",
                    "1",
                    "online",
                    "node_export",
                    "[\"screen\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"screen\"}",
                    null,
                    "Screen capture namespace.",
                );
                try view.observe(self.allocator, node.id, "screen", "screen", endpoint, mounts);
                try self.appendVenomIndexEntry(&services_index, &services_index_first, "screen", "screen", "online", endpoint);
            }
        }
        if (node.resources.user) {
            const caps = "{\"interaction\":true}";
            const mounts = try std.fmt.allocPrint(
                self.allocator,
                "[{{\"mount_id\":\"user\",\"mount_path\":\"/nodes/{s}/user\",\"state\":\"online\"}}]",
                .{node.id},
            );
            defer self.allocator.free(mounts);
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/user", .{node.id});
            defer self.allocator.free(endpoint);
            const permissions = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"node\"}";
            if (self.canAccessVenomWithPermissions(permissions)) {
                try self.addNodeVenomEntry(
                    venoms_root,
                    "user",
                    "user",
                    "local:user",
                    "user",
                    "1",
                    "online",
                    "node_export",
                    "[\"user_interaction\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"user\"}",
                    null,
                    "User interaction namespace.",
                );
                try self.addNodeVenomEntry(
                    venoms_root,
                    "user",
                    "user",
                    "local:user",
                    "user",
                    "1",
                    "online",
                    "node_export",
                    "[\"user_interaction\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"user\"}",
                    null,
                    "User interaction namespace.",
                );
                try view.observe(self.allocator, node.id, "user", "user", endpoint, mounts);
                try self.appendVenomIndexEntry(&services_index, &services_index_first, "user", "user", "online", endpoint);
            }
        }

        for (node.terminals.items) |terminal_id| {
            const venom_id = try std.fmt.allocPrint(self.allocator, "terminal-{s}", .{terminal_id});
            defer self.allocator.free(venom_id);
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/terminal/{s}", .{ node.id, terminal_id });
            defer self.allocator.free(endpoint);
            const escaped_terminal_id = try unified.jsonEscape(self.allocator, terminal_id);
            defer self.allocator.free(escaped_terminal_id);
            const caps = try std.fmt.allocPrint(
                self.allocator,
                "{{\"pty\":true,\"terminal_id\":\"{s}\"}}",
                .{escaped_terminal_id},
            );
            defer self.allocator.free(caps);
            const mounts = try std.fmt.allocPrint(
                self.allocator,
                "[{{\"mount_id\":\"{s}\",\"mount_path\":\"/nodes/{s}/terminal/{s}\",\"state\":\"online\"}}]",
                .{ venom_id, node.id, terminal_id },
            );
            defer self.allocator.free(mounts);
            const permissions = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"node\"}";
            if (self.canAccessVenomWithPermissions(permissions)) {
                try self.addNodeVenomEntry(
                    venoms_root,
                    venom_id,
                    "terminal",
                    venom_id,
                    "terminal",
                    "1",
                    "online",
                    "node_export",
                    "[\"terminal\",\"exec\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"terminal\"}",
                    null,
                    "Interactive terminal namespace.",
                );
                try self.addNodeVenomEntry(
                    venoms_root,
                    venom_id,
                    "terminal",
                    venom_id,
                    "terminal",
                    "1",
                    "online",
                    "node_export",
                    "[\"terminal\",\"exec\"]",
                    "[\"node\"]",
                    "[\"node_export\"]",
                    "{}",
                    endpoint,
                    caps,
                    mounts,
                    "{\"model\":\"namespace\"}",
                    "{\"type\":\"builtin\"}",
                    permissions,
                    "{\"model\":\"terminal\"}",
                    null,
                    "Interactive terminal namespace.",
                );
                try view.observe(self.allocator, node.id, "terminal", venom_id, endpoint, mounts);
                try self.appendVenomIndexEntry(&services_index, &services_index_first, venom_id, "terminal", "online", endpoint);
            }
        }

        try services_index.append(self.allocator, ']');
        const services_index_json = try services_index.toOwnedSlice(self.allocator);
        defer self.allocator.free(services_index_json);
        _ = try self.addFile(venoms_root, "VENOMS.json", services_index_json, false, .none);
        return view;
    }

    const NodeVenomCatalog = struct {
        const Entry = struct {
            venom_id: []u8,
            package_id: []u8,
            instance_id: ?[]u8 = null,
            kind: []u8,
            version: []u8,
            state: []u8,
            provider_scope: []u8,
            categories_json: []u8,
            hosts_json: []u8,
            projection_modes_json: []u8,
            requirements_json: []u8,
            endpoint: []u8,
            caps_json: []u8,
            mounts_json: []u8,
            ops_json: []u8,
            runtime_json: []u8,
            permissions_json: []u8,
            schema_json: []u8,
            invoke_template_json: ?[]u8 = null,
            help_md: ?[]u8 = null,

            fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
                allocator.free(self.venom_id);
                allocator.free(self.package_id);
                if (self.instance_id) |value| allocator.free(value);
                allocator.free(self.kind);
                allocator.free(self.version);
                allocator.free(self.state);
                allocator.free(self.provider_scope);
                allocator.free(self.categories_json);
                allocator.free(self.hosts_json);
                allocator.free(self.projection_modes_json);
                allocator.free(self.requirements_json);
                allocator.free(self.endpoint);
                allocator.free(self.caps_json);
                allocator.free(self.mounts_json);
                allocator.free(self.ops_json);
                allocator.free(self.runtime_json);
                allocator.free(self.permissions_json);
                allocator.free(self.schema_json);
                if (self.invoke_template_json) |value| allocator.free(value);
                if (self.help_md) |value| allocator.free(value);
                self.* = undefined;
            }
        };

        items: std.ArrayListUnmanaged(Entry) = .{},

        fn deinit(self: *NodeVenomCatalog, allocator: std.mem.Allocator) void {
            for (self.items.items) |*item| item.deinit(allocator);
            self.items.deinit(allocator);
            self.* = undefined;
        }
    };

    const NodeVenomCatalogResult = union(enum) {
        unavailable,
        empty,
        catalog: NodeVenomCatalog,
    };

    fn loadNodeVenomsFromControlPlane(self: *Session, node_id: []const u8) !NodeVenomCatalogResult {
        const plane = self.control_plane orelse return .unavailable;
        const escaped_node_id = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node_id);
        const request_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"node_id\":\"{s}\"}}",
            .{escaped_node_id},
        );
        defer self.allocator.free(request_json);

        const response_json = plane.nodeVenomGet(request_json) catch return .unavailable;
        defer self.allocator.free(response_json);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, response_json, .{}) catch return .unavailable;
        defer parsed.deinit();
        if (parsed.value != .object) return .unavailable;
        const venoms_val = parsed.value.object.get("venoms") orelse return .unavailable;
        if (venoms_val != .array) return .unavailable;
        if (venoms_val.array.items.len == 0) return .empty;

        var catalog = NodeVenomCatalog{};
        errdefer catalog.deinit(self.allocator);

        for (venoms_val.array.items) |item| {
            if (item != .object) continue;
            const venom_id_val = item.object.get("venom_id") orelse continue;
            if (venom_id_val != .string or venom_id_val.string.len == 0) continue;
            const kind_val = item.object.get("kind") orelse continue;
            if (kind_val != .string or kind_val.string.len == 0) continue;
            const state_val = item.object.get("state");
            const state = if (state_val) |value|
                if (value == .string and value.string.len > 0) value.string else "unknown"
            else
                "unknown";

            const endpoint = blk: {
                if (item.object.get("endpoints")) |raw| {
                    if (raw == .array) {
                        for (raw.array.items) |candidate| {
                            if (candidate != .string or candidate.string.len == 0) continue;
                            break :blk candidate.string;
                        }
                    }
                }
                break :blk "";
            };
            const resolved_endpoint = if (endpoint.len > 0)
                try self.allocator.dupe(u8, endpoint)
            else
                try std.fmt.allocPrint(self.allocator, "/nodes/{s}/venoms/{s}", .{ node_id, venom_id_val.string });
            errdefer self.allocator.free(resolved_endpoint);

            const package_id = if (item.object.get("package_id")) |value|
                if (value == .string and value.string.len > 0)
                    try self.allocator.dupe(u8, value.string)
                else
                    try self.allocator.dupe(u8, venom_id_val.string)
            else
                try self.allocator.dupe(u8, venom_id_val.string);
            errdefer self.allocator.free(package_id);

            const instance_id = if (item.object.get("instance_id")) |value|
                if (value == .string and value.string.len > 0)
                    try self.allocator.dupe(u8, value.string)
                else
                    null
            else
                null;
            errdefer if (instance_id) |value| self.allocator.free(value);

            const provider_scope = if (item.object.get("provider_scope")) |value|
                if (value == .string and value.string.len > 0)
                    try self.allocator.dupe(u8, value.string)
                else
                    try self.allocator.dupe(u8, "node_export")
            else
                try self.allocator.dupe(u8, "node_export");
            errdefer self.allocator.free(provider_scope);

            const categories_json = if (item.object.get("categories")) |value|
                if (value == .array)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})})
                else
                    try self.allocator.dupe(u8, "[]")
            else
                try self.allocator.dupe(u8, "[]");
            errdefer self.allocator.free(categories_json);

            const hosts_json = if (item.object.get("hosts")) |value|
                if (value == .array)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})})
                else
                    try self.allocator.dupe(u8, "[]")
            else
                try self.allocator.dupe(u8, "[]");
            errdefer self.allocator.free(hosts_json);

            const projection_modes_json = if (item.object.get("projection_modes")) |value|
                if (value == .array)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})})
                else
                    try self.allocator.dupe(u8, "[]")
            else
                try self.allocator.dupe(u8, "[]");
            errdefer self.allocator.free(projection_modes_json);

            const requirements_json = if (item.object.get("requirements")) |value|
                if (value == .object)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})})
                else
                    try self.allocator.dupe(u8, "{}")
            else
                try self.allocator.dupe(u8, "{}");
            errdefer self.allocator.free(requirements_json);

            const version = if (item.object.get("version")) |value|
                if (value == .string and value.string.len > 0)
                    try self.allocator.dupe(u8, value.string)
                else
                    try self.allocator.dupe(u8, "1")
            else
                try self.allocator.dupe(u8, "1");
            errdefer self.allocator.free(version);

            const caps_json = if (item.object.get("capabilities")) |caps|
                if (caps == .object)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(caps, .{})})
                else
                    try self.allocator.dupe(u8, "{}")
            else
                try self.allocator.dupe(u8, "{}");
            errdefer self.allocator.free(caps_json);

            const mounts_json = if (item.object.get("mounts")) |mounts|
                if (mounts == .array)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(mounts, .{})})
                else
                    try self.allocator.dupe(u8, "[]")
            else
                try self.allocator.dupe(u8, "[]");
            errdefer self.allocator.free(mounts_json);

            const ops_json = if (item.object.get("ops")) |ops|
                if (ops == .object)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(ops, .{})})
                else
                    try self.allocator.dupe(u8, "{}")
            else
                try self.allocator.dupe(u8, "{}");
            errdefer self.allocator.free(ops_json);

            const runtime_json = if (item.object.get("runtime")) |runtime|
                if (runtime == .object)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(runtime, .{})})
                else
                    try self.allocator.dupe(u8, "{}")
            else
                try self.allocator.dupe(u8, "{}");
            errdefer self.allocator.free(runtime_json);

            const permissions_json = if (item.object.get("permissions")) |permissions|
                if (permissions == .object)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(permissions, .{})})
                else
                    try self.allocator.dupe(u8, "{}")
            else
                try self.allocator.dupe(u8, "{}");
            errdefer self.allocator.free(permissions_json);

            const schema_json = if (item.object.get("schema")) |schema|
                if (schema == .object)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(schema, .{})})
                else
                    try self.allocator.dupe(u8, "{}")
            else
                try self.allocator.dupe(u8, "{}");
            errdefer self.allocator.free(schema_json);

            const invoke_template_json = if (item.object.get("invoke_template")) |invoke_template|
                if (invoke_template == .object)
                    try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(invoke_template, .{})})
                else
                    null
            else
                null;
            errdefer if (invoke_template_json) |value| self.allocator.free(value);

            const help_md = if (item.object.get("help_md")) |help|
                if (help == .string and help.string.len > 0)
                    try self.allocator.dupe(u8, help.string)
                else
                    null
            else
                null;
            errdefer if (help_md) |value| self.allocator.free(value);

            try catalog.items.append(self.allocator, .{
                .venom_id = try self.allocator.dupe(u8, venom_id_val.string),
                .package_id = package_id,
                .instance_id = instance_id,
                .kind = try self.allocator.dupe(u8, kind_val.string),
                .version = version,
                .state = try self.allocator.dupe(u8, state),
                .provider_scope = provider_scope,
                .categories_json = categories_json,
                .hosts_json = hosts_json,
                .projection_modes_json = projection_modes_json,
                .requirements_json = requirements_json,
                .endpoint = resolved_endpoint,
                .caps_json = caps_json,
                .mounts_json = mounts_json,
                .ops_json = ops_json,
                .runtime_json = runtime_json,
                .permissions_json = permissions_json,
                .schema_json = schema_json,
                .invoke_template_json = invoke_template_json,
                .help_md = help_md,
            });
        }

        if (catalog.items.items.len == 0) {
            catalog.deinit(self.allocator);
            return .empty;
        }
        return .{ .catalog = catalog };
    }

    fn addNodeVenomEntry(
        self: *Session,
        services_root: u32,
        venom_id: []const u8,
        package_id: []const u8,
        instance_id: ?[]const u8,
        kind: []const u8,
        version: []const u8,
        state: []const u8,
        provider_scope: []const u8,
        categories_json: []const u8,
        hosts_json: []const u8,
        projection_modes_json: []const u8,
        requirements_json: []const u8,
        endpoint: []const u8,
        caps_json: []const u8,
        mounts_json: []const u8,
        ops_json: []const u8,
        runtime_json: []const u8,
        permissions_json: []const u8,
        schema_json: []const u8,
        invoke_template_json: ?[]const u8,
        help_md: ?[]const u8,
    ) !void {
        const venom_dir = try self.addDir(services_root, venom_id, false);

        const escaped_venom_id = try unified.jsonEscape(self.allocator, venom_id);
        defer self.allocator.free(escaped_venom_id);
        const escaped_kind = try unified.jsonEscape(self.allocator, kind);
        defer self.allocator.free(escaped_kind);
        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const escaped_endpoint = try unified.jsonEscape(self.allocator, endpoint);
        defer self.allocator.free(escaped_endpoint);

        const readme = if (help_md) |value|
            value
        else
            "# Venom metadata for this node capability.\n";
        _ = try self.addFile(venom_dir, "README.md", readme, false, .none);
        const package_json = try self.renderNodeVenomPackageJson(
            package_id,
            kind,
            version,
            provider_scope,
            categories_json,
            hosts_json,
            projection_modes_json,
            requirements_json,
            caps_json,
            ops_json,
            runtime_json,
            permissions_json,
            schema_json,
            help_md,
        );
        defer self.allocator.free(package_json);
        _ = try self.addFile(venom_dir, "PACKAGE.json", package_json, false, .none);
        _ = try self.addFile(venom_dir, "SCHEMA.json", schema_json, false, .none);
        _ = try self.addFile(venom_dir, "CAPS.json", caps_json, false, .none);
        _ = try self.addFile(venom_dir, "MOUNTS.json", mounts_json, false, .none);
        _ = try self.addFile(venom_dir, "OPS.json", ops_json, false, .none);
        _ = try self.addFile(venom_dir, "RUNTIME.json", runtime_json, false, .none);
        if (invoke_template_json) |value| {
            _ = try self.addFile(venom_dir, "TEMPLATE.json", value, false, .none);
        }
        const host_json = try self.renderNodeVenomHostJson(runtime_json);
        defer self.allocator.free(host_json);
        _ = try self.addFile(venom_dir, "HOST.json", host_json, false, .none);
        _ = try self.addFile(venom_dir, "PERMISSIONS.json", permissions_json, false, .none);

        const escaped_package_id = try unified.jsonEscape(self.allocator, package_id);
        defer self.allocator.free(escaped_package_id);
        const escaped_provider_scope = try unified.jsonEscape(self.allocator, provider_scope);
        defer self.allocator.free(escaped_provider_scope);
        const instance_id_json = if (instance_id) |value| blk: {
            const escaped_instance_id = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped_instance_id);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped_instance_id});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(instance_id_json);

        const status = try std.fmt.allocPrint(
            self.allocator,
            "{{\"venom_id\":\"{s}\",\"package_id\":\"{s}\",\"instance_id\":{s},\"kind\":\"{s}\",\"state\":\"{s}\",\"provider_scope\":\"{s}\",\"endpoint\":\"{s}\"}}",
            .{ escaped_venom_id, escaped_package_id, instance_id_json, escaped_kind, escaped_state, escaped_provider_scope, escaped_endpoint },
        );
        defer self.allocator.free(status);
        _ = try self.addFile(venom_dir, "STATUS.json", status, false, .none);
    }

    fn renderNodeVenomPackageJson(
        self: *Session,
        venom_id: []const u8,
        kind: []const u8,
        version: []const u8,
        provider_scope: []const u8,
        categories_json: []const u8,
        hosts_json: []const u8,
        projection_modes_json: []const u8,
        requirements_json: []const u8,
        capabilities_json: []const u8,
        ops_json: []const u8,
        runtime_json: []const u8,
        permissions_json: []const u8,
        schema_json: []const u8,
        help_md: ?[]const u8,
    ) ![]u8 {
        const escaped_venom_id = try unified.jsonEscape(self.allocator, venom_id);
        defer self.allocator.free(escaped_venom_id);
        const escaped_kind = try unified.jsonEscape(self.allocator, kind);
        defer self.allocator.free(escaped_kind);
        const escaped_version = try unified.jsonEscape(self.allocator, version);
        defer self.allocator.free(escaped_version);
        const escaped_provider_scope = try unified.jsonEscape(self.allocator, provider_scope);
        defer self.allocator.free(escaped_provider_scope);

        if (help_md) |help| {
            const escaped_help = try unified.jsonEscape(self.allocator, help);
            defer self.allocator.free(escaped_help);
            return std.fmt.allocPrint(
                self.allocator,
                "{{\"venom_id\":\"{s}\",\"kind\":\"{s}\",\"version\":\"{s}\",\"categories\":{s},\"hosts\":{s},\"projection_modes\":{s},\"requirements\":{s},\"capabilities\":{s},\"ops\":{s},\"runtime\":{s},\"permissions\":{s},\"schema\":{s},\"provider_scope\":\"{s}\",\"help_md\":\"{s}\"}}",
                .{ escaped_venom_id, escaped_kind, escaped_version, categories_json, hosts_json, projection_modes_json, requirements_json, capabilities_json, ops_json, runtime_json, permissions_json, schema_json, escaped_provider_scope, escaped_help },
            );
        }

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"venom_id\":\"{s}\",\"kind\":\"{s}\",\"version\":\"{s}\",\"categories\":{s},\"hosts\":{s},\"projection_modes\":{s},\"requirements\":{s},\"capabilities\":{s},\"ops\":{s},\"runtime\":{s},\"permissions\":{s},\"schema\":{s},\"provider_scope\":\"{s}\"}}",
            .{ escaped_venom_id, escaped_kind, escaped_version, categories_json, hosts_json, projection_modes_json, requirements_json, capabilities_json, ops_json, runtime_json, permissions_json, schema_json, escaped_provider_scope },
        );
    }

    fn renderNodeVenomHostJson(self: *Session, runtime_json: []const u8) ![]u8 {
        var runtime_kind: []const u8 = "builtin";
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, runtime_json, .{}) catch {
            return shared_node.service_runtime_host.renderMetadataJson(self.allocator, runtime_kind);
        };
        defer parsed.deinit();
        if (parsed.value == .object) {
            if (parsed.value.object.get("type")) |runtime_type| {
                if (runtime_type == .string and runtime_type.string.len > 0) {
                    runtime_kind = runtime_type.string;
                }
            }
        }
        return shared_node.service_runtime_host.renderMetadataJson(self.allocator, runtime_kind);
    }

    fn copyOptionalServiceFile(self: *Session, source_dir_id: u32, target_dir_id: u32, name: []const u8) !void {
        const source_id = self.lookupChild(source_dir_id, name) orelse return;
        const source_node = self.nodes.get(source_id) orelse return;
        if (source_node.kind != .file) return;
        _ = try self.addFile(target_dir_id, name, source_node.content, false, .none);
    }

    fn seedBuiltinPackageMetadata(self: *Session, venom_dir_id: u32, venom_id: []const u8) !void {
        const spec = venom_packages.findBuiltinPackage(venom_id) orelse return;
        const package_json = try venom_packages.renderPackageMetadataJson(self.allocator, spec);
        defer self.allocator.free(package_json);
        _ = try self.addFile(venom_dir_id, "PACKAGE.json", package_json, false, .none);
    }

    fn cloneWorkerVenomPackage(self: *Session, venom_id: []const u8) !?shared_node.venom_package.VenomPackage {
        if (self.control_plane) |control_plane| {
            return control_plane.cloneVenomPackage(self.allocator, venom_id);
        }
        return venom_packages.cloneBuiltinPackage(self.allocator, venom_id);
    }

    fn seedPackageMetadata(self: *Session, venom_dir_id: u32, package: shared_node.venom_package.VenomPackage) !void {
        if (self.lookupChild(venom_dir_id, "PACKAGE.json") != null) return;
        var package_json = std.ArrayListUnmanaged(u8){};
        defer package_json.deinit(self.allocator);
        try shared_node.venom_package.appendPackageJson(self.allocator, &package_json, package);
        _ = try self.addFile(venom_dir_id, "PACKAGE.json", package_json.items, false, .none);
    }

    fn seedGenericWorkerLoopbackVenomNamespaceAt(
        self: *Session,
        venom_dir_id: u32,
        base_path: []const u8,
        worker_id: []const u8,
        agent_id: []const u8,
        package: shared_node.venom_package.VenomPackage,
    ) !void {
        const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
        defer self.allocator.free(escaped_base_path);
        const shape_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"kind\":\"venom\",\"venom_id\":\"{s}\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,PACKAGE.json,STATUS.json,status.json,result.json,control/*}}\"}}",
            .{ package.venom_id, escaped_base_path },
        );
        defer self.allocator.free(shape_json);

        const readme = package.help_md orelse "Worker-owned loopback venom projected for an attached external worker.\n";
        try self.ensureWorkerFile(venom_dir_id, "README.md", readme, false, .none);
        try self.ensureWorkerFile(venom_dir_id, "SCHEMA.json", shape_json, false, .none);
        try self.ensureWorkerFile(venom_dir_id, "CAPS.json", package.capabilities_json, false, .none);
        try self.ensureWorkerFile(venom_dir_id, "OPS.json", package.ops_json, false, .none);
        try self.ensureWorkerFile(venom_dir_id, "RUNTIME.json", package.runtime_json, false, .none);
        try self.ensureWorkerFile(venom_dir_id, "PERMISSIONS.json", package.permissions_json, false, .none);
        try self.seedPackageMetadata(venom_dir_id, package);

        const status_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"venom_id\":\"{s}\",\"state\":\"worker_loopback\",\"has_invoke\":true,\"owner\":\"worker\",\"worker_id\":\"{s}\",\"agent_id\":\"{s}\"}}",
            .{ package.venom_id, worker_id, agent_id },
        );
        defer self.allocator.free(status_json);
        try self.ensureWorkerFile(venom_dir_id, "STATUS.json", status_json, false, .none);
        try self.ensureWorkerFile(venom_dir_id, "status.json", "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}", true, .none);
        try self.ensureWorkerFile(venom_dir_id, "result.json", "{\"ok\":false,\"result\":null,\"error\":null}", true, .none);

        const control_dir = if (self.lookupChild(venom_dir_id, "control")) |existing|
            existing
        else
            try self.addDir(venom_dir_id, "control", false);
        try self.ensureWorkerFile(control_dir, "README.md", "External worker watches and writes this loopback venom namespace directly.\n", false, .none);
        try self.seedWorkerControlFilesFromOpsJson(control_dir, package.ops_json);
    }

    fn seedWorkerControlFilesFromOpsJson(self: *Session, control_dir: u32, ops_json: []const u8) !void {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, ops_json, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;
        if (parsed.value.object.get("invoke")) |invoke_value| {
            if (invoke_value == .string and invoke_value.string.len > 0) {
                try self.ensureWorkerControlFileFromPath(control_dir, invoke_value.string);
            }
        }
        if (parsed.value.object.get("paths")) |paths_value| {
            if (paths_value != .object) return;
            var it = paths_value.object.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* != .string or entry.value_ptr.string.len == 0) continue;
                try self.ensureWorkerControlFileFromPath(control_dir, entry.value_ptr.string);
            }
        }
    }

    fn ensureWorkerControlFileFromPath(self: *Session, control_dir: u32, raw_path: []const u8) !void {
        var relative = raw_path;
        if (std.mem.startsWith(u8, relative, "control/")) {
            relative = relative["control/".len..];
        }
        const name = std.fs.path.basename(relative);
        if (name.len == 0) return;
        try self.ensureWorkerFile(control_dir, name, "", true, .none);
    }

    fn seedActiveScopedVenomBindings(
        self: *Session,
        active_agent_venoms_dir: u32,
        project_venoms_dir: u32,
        active_project_id: []const u8,
    ) !void {
        const agent_prefix = try std.fmt.allocPrint(self.allocator, "/agents/{s}/venoms", .{self.agent_id});
        defer self.allocator.free(agent_prefix);
        const project_prefix = try std.fmt.allocPrint(self.allocator, "/projects/{s}/venoms", .{active_project_id});
        defer self.allocator.free(project_prefix);

        inline for ([_][]const u8{ "chat", "jobs", "events", "thoughts", "fs" }) |venom_id| {
            const preferred_agent_node_id = try self.resolvePreferredBoundVenomNodeIdForContext(
                venom_id,
                active_project_id,
                self.agent_id,
            );
            defer if (preferred_agent_node_id) |value| self.allocator.free(value);
            _ = try self.addDir(active_agent_venoms_dir, venom_id, false);
            _ = try self.registerBoundVenomAliasOnly(
                agent_prefix,
                venom_id,
                "agent_binding",
                preferred_agent_node_id,
                active_project_id,
                self.agent_id,
            );

            const preferred_project_node_id = try self.resolvePreferredBoundVenomNodeIdForContext(
                venom_id,
                active_project_id,
                null,
            );
            defer if (preferred_project_node_id) |value| self.allocator.free(value);
            _ = try self.addDir(project_venoms_dir, venom_id, false);
            _ = try self.registerBoundVenomAliasOnly(
                project_prefix,
                venom_id,
                "project_binding",
                preferred_project_node_id,
                active_project_id,
                self.agent_id,
            );
        }
    }

    fn seedBoundNodeVenomNamespace(
        self: *Session,
        global_root: u32,
        venom_id: []const u8,
        preferred_node_id: []const u8,
    ) !bool {
        return self.seedBoundNodeVenomNamespaceAt(global_root, "/global", venom_id, "global_binding", preferred_node_id);
    }

    fn seedBoundNodeVenomNamespaceAt(
        self: *Session,
        alias_root: u32,
        alias_base_path: []const u8,
        venom_id: []const u8,
        scope: []const u8,
        preferred_node_id: ?[]const u8,
    ) !bool {
        const nodes_root = self.lookupChild(self.root_id, "nodes") orelse return false;

        var selected_node_id: ?[]const u8 = null;
        var selected_venom_dir_id: ?u32 = null;

        if (preferred_node_id) |selected| {
            const preferred_node_dir_id = self.lookupChild(nodes_root, selected);
            if (preferred_node_dir_id) |node_dir_id| {
                if (self.lookupChild(node_dir_id, "venoms")) |venoms_root_id| {
                    if (self.lookupChild(venoms_root_id, venom_id)) |venom_dir_id| {
                        selected_node_id = selected;
                        selected_venom_dir_id = venom_dir_id;
                    }
                }
            }
        }

        if (selected_venom_dir_id == null) {
            const nodes_root_node = self.nodes.get(nodes_root) orelse return false;
            var node_it = nodes_root_node.children.iterator();
            while (node_it.next()) |entry| {
                const node_name = entry.key_ptr.*;
                const node_dir_id = entry.value_ptr.*;
                const venoms_root_id = self.lookupChild(node_dir_id, "venoms") orelse continue;
                const venom_dir_id = self.lookupChild(venoms_root_id, venom_id) orelse continue;
                selected_node_id = node_name;
                selected_venom_dir_id = venom_dir_id;
                break;
            }
        }

        const provider_node_id = selected_node_id orelse return false;
        const provider_dir_id = selected_venom_dir_id orelse return false;

        const alias_dir_id = try self.addDir(alias_root, venom_id, false);
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "README.md");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "SCHEMA.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "CAPS.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "MOUNTS.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "OPS.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "RUNTIME.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "TEMPLATE.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "HOST.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "PERMISSIONS.json");
        try self.copyOptionalServiceFile(provider_dir_id, alias_dir_id, "STATUS.json");

        const venom_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ alias_base_path, venom_id });
        defer self.allocator.free(venom_path);
        const provider_venom_path = try std.fmt.allocPrint(
            self.allocator,
            "/nodes/{s}/venoms/{s}",
            .{ provider_node_id, venom_id },
        );
        defer self.allocator.free(provider_venom_path);
        const endpoint_path = blk: {
            if (try self.firstVenomMountPath(provider_dir_id)) |value| break :blk value;
            break :blk try self.venomEndpointPath(provider_dir_id);
        };
        defer if (endpoint_path) |value| self.allocator.free(value);
        const invoke_path = try self.deriveVenomInvokePath(provider_node_id, venom_id, provider_dir_id);
        defer if (invoke_path) |value| self.allocator.free(value);

        try self.registerScopedVenomBinding(
            venom_id,
            scope,
            venom_path,
            provider_node_id,
            provider_venom_path,
            endpoint_path,
            invoke_path,
        );
        return true;
    }

    fn resolvePreferredBoundVenomNodeId(self: *Session, venom_id: []const u8) !?[]u8 {
        return self.resolvePreferredBoundVenomNodeIdForContext(venom_id, null, null);
    }

    fn resolvePreferredBoundVenomNodeIdForContext(
        self: *Session,
        venom_id: []const u8,
        project_id: ?[]const u8,
        agent_id: ?[]const u8,
    ) !?[]u8 {
        const plane = self.control_plane orelse return null;
        var provider = (try plane.resolvePreferredVenomProviderForContext(
            self.allocator,
            venom_id,
            &.{ "spiderapp-default", "spiderweb-local", "local" },
            project_id,
            agent_id,
        )) orelse return null;
        defer provider.deinit(self.allocator);
        return try self.allocator.dupe(u8, provider.node_id);
    }

    pub fn addDir(self: *Session, parent: ?u32, name: []const u8, writable: bool) !u32 {
        return self.addNode(parent, name, .dir, "", writable, .none);
    }

    pub fn addFile(self: *Session, parent: u32, name: []const u8, content: []const u8, writable: bool, special: SpecialKind) !u32 {
        return self.addNode(parent, name, .file, content, writable, special);
    }

    fn addNode(
        self: *Session,
        parent: ?u32,
        name: []const u8,
        kind: NodeKind,
        content: []const u8,
        writable: bool,
        special: SpecialKind,
    ) !u32 {
        const node_id = self.next_node_id;
        self.next_node_id += 1;

        const node = Node{
            .id = node_id,
            .parent = parent,
            .kind = kind,
            .name = try self.allocator.dupe(u8, name),
            .writable = writable,
            .content = try self.allocator.dupe(u8, content),
            .special = special,
        };

        try self.nodes.put(self.allocator, node_id, node);

        if (parent) |parent_id| {
            const child_name = (self.nodes.get(node_id) orelse return error.MissingNode).name;
            var parent_node = self.nodes.getPtr(parent_id) orelse return error.MissingNode;
            try parent_node.children.put(self.allocator, child_name, node_id);
        }

        return node_id;
    }

    pub fn lookupChild(self: *Session, parent_id: u32, name: []const u8) ?u32 {
        const parent = self.nodes.get(parent_id) orelse return null;
        return parent.children.get(name);
    }

    fn resolveWalkChild(self: *Session, parent_id: u32, name: []const u8) !?u32 {
        if (self.lookupChild(parent_id, name)) |child| return child;
        if (self.project_binds.items.len == 0) return null;

        const parent_path = try self.nodeAbsolutePath(parent_id);
        defer self.allocator.free(parent_path);
        const child_path = if (std.mem.eql(u8, parent_path, "/"))
            try std.fmt.allocPrint(self.allocator, "/{s}", .{name})
        else
            try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ parent_path, name });
        defer self.allocator.free(child_path);

        const resolved_path = try self.resolveBoundPath(child_path);
        defer if (resolved_path) |value| self.allocator.free(value);
        if (resolved_path == null) return null;
        return self.resolveAbsolutePathNoBinds(resolved_path.?);
    }

    fn resolveBoundPath(self: *Session, path: []const u8) !?[]u8 {
        if (self.project_binds.items.len == 0) return null;
        var selected: ?PathBind = null;
        for (self.project_binds.items) |bind| {
            if (!pathMatchesPrefixBoundary(path, bind.bind_path)) continue;
            if (selected == null or bind.bind_path.len > selected.?.bind_path.len) selected = bind;
        }
        if (selected) |bind| {
            const suffix = path[bind.bind_path.len..];
            if (suffix.len == 0) return try self.allocator.dupe(u8, bind.target_path);
            if (std.mem.eql(u8, bind.target_path, "/")) return try std.fmt.allocPrint(self.allocator, "{s}", .{suffix});
            return try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ bind.target_path, suffix });
        }
        return null;
    }

    pub fn resolvePreferredServicePath(self: *Session, service_id: []const u8, suffix: []const u8) ![]u8 {
        const workspace_path = if (suffix.len == 0)
            try std.fmt.allocPrint(self.allocator, "/services/{s}", .{service_id})
        else
            try std.fmt.allocPrint(self.allocator, "/services/{s}{s}", .{ service_id, suffix });
        errdefer self.allocator.free(workspace_path);

        const rebound = try self.resolveBoundPath(workspace_path);
        if (rebound) |value| {
            self.allocator.free(value);
            return workspace_path;
        }

        self.allocator.free(workspace_path);
        return if (suffix.len == 0)
            try std.fmt.allocPrint(self.allocator, "/global/{s}", .{service_id})
        else
            try std.fmt.allocPrint(self.allocator, "/global/{s}{s}", .{ service_id, suffix });
    }

    pub fn resolveAbsolutePathNoBinds(self: *Session, path: []const u8) ?u32 {
        if (!std.mem.startsWith(u8, path, "/")) return null;
        if (std.mem.eql(u8, path, "/")) return self.root_id;
        var node_id = self.root_id;
        var iter = std.mem.splitScalar(u8, path, '/');
        while (iter.next()) |segment| {
            if (segment.len == 0) continue;
            const next = self.lookupChild(node_id, segment) orelse return null;
            node_id = next;
        }
        return node_id;
    }

    fn nodeAbsolutePath(self: *Session, node_id: u32) ![]u8 {
        if (node_id == self.root_id) return self.allocator.dupe(u8, "/");
        var names = std.ArrayListUnmanaged([]const u8){};
        defer names.deinit(self.allocator);

        var cursor = node_id;
        while (true) {
            const node = self.nodes.get(cursor) orelse break;
            if (node.parent == null) break;
            try names.append(self.allocator, node.name);
            cursor = node.parent.?;
        }
        if (names.items.len == 0) return self.allocator.dupe(u8, "/");

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        for (names.items, 0..) |_, idx| {
            const rev_idx = names.items.len - idx - 1;
            try out.append(self.allocator, '/');
            try out.appendSlice(self.allocator, names.items[rev_idx]);
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn renderDirListing(self: *Session, node_id: u32) ![]u8 {
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        if (node.kind != .dir) return error.NotDir;

        var names = std.ArrayListUnmanaged([]const u8){};
        defer names.deinit(self.allocator);

        var collect_it = node.children.iterator();
        while (collect_it.next()) |entry| {
            try names.append(self.allocator, entry.key_ptr.*);
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
                return std.mem.lessThan(u8, lhs, rhs);
            }
        }.lessThan);

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);
        var seen = std.StringHashMapUnmanaged(void){};
        defer seen.deinit(self.allocator);

        var first = true;
        for (names.items) |name| {
            if (!first) try out.append(self.allocator, '\n');
            first = false;
            try out.appendSlice(self.allocator, name);
            try seen.put(self.allocator, name, {});
        }

        if (self.project_binds.items.len > 0) {
            const dir_path = try self.nodeAbsolutePath(node_id);
            defer self.allocator.free(dir_path);

            for (self.project_binds.items) |bind| {
                const child_name = immediateBoundChildName(dir_path, bind.bind_path) orelse continue;
                if (seen.contains(child_name)) continue;
                if (!first) try out.append(self.allocator, '\n');
                first = false;
                try out.appendSlice(self.allocator, child_name);
                try seen.put(self.allocator, child_name, {});
            }
        }

        return out.toOwnedSlice(self.allocator);
    }

    fn writeFileContentRaw(self: *Session, node_id: u32, offset: u64, data: []const u8) !void {
        const node_ptr = self.nodes.getPtr(node_id) orelse return error.MissingNode;
        if (node_ptr.kind != .file) return error.NotFile;

        const base_offset = std.math.cast(usize, offset) orelse return error.InvalidOffset;
        const required_len = std.math.add(usize, base_offset, data.len) catch return error.InvalidOffset;
        if (required_len <= node_ptr.content.len) {
            @memcpy(node_ptr.content[base_offset .. base_offset + data.len], data);
            return;
        }

        var next = try self.allocator.alloc(u8, required_len);
        @memset(next, 0);
        if (node_ptr.content.len > 0) {
            @memcpy(next[0..node_ptr.content.len], node_ptr.content);
        }
        @memcpy(next[base_offset .. base_offset + data.len], data);

        self.allocator.free(node_ptr.content);
        node_ptr.content = next;
    }

    fn writeFileContent(self: *Session, node_id: u32, offset: u64, data: []const u8) !void {
        try self.writeFileContentRaw(node_id, offset, data);
        if (self.node_aliases.get(node_id)) |alias_id| {
            if (alias_id != node_id) {
                const node = self.nodes.get(node_id) orelse return error.MissingNode;
                try self.setFileContentRaw(alias_id, node.content);
            }
        }
    }

    fn setFileContentRaw(self: *Session, node_id: u32, data: []const u8) !void {
        const node_ptr = self.nodes.getPtr(node_id) orelse return error.MissingNode;
        if (node_ptr.kind != .file) return error.NotFile;
        self.allocator.free(node_ptr.content);
        node_ptr.content = try self.allocator.dupe(u8, data);
    }

    pub fn setFileContent(self: *Session, node_id: u32, data: []const u8) !void {
        try self.setFileContentRaw(node_id, data);
        if (self.node_aliases.get(node_id)) |alias_id| {
            if (alias_id != node_id) try self.setFileContentRaw(alias_id, data);
        }
    }

    pub fn setMirroredFileContent(self: *Session, primary_id: u32, alias_id: u32, data: []const u8) !void {
        if (primary_id != 0) try self.setFileContent(primary_id, data);
        if (alias_id != 0 and alias_id != primary_id) try self.setFileContent(alias_id, data);
    }

    fn tryReadBoundVenomProxyFile(self: *Session, node_id: u32) !?[]u8 {
        const absolute_path = try self.nodeAbsolutePath(node_id);
        defer self.allocator.free(absolute_path);

        if (try self.readBoundVenomProxyFileByPath(absolute_path)) |value| return value;
        return null;
    }

    fn readBoundVenomProxyFileByPath(self: *Session, absolute_path: []const u8) !?[]u8 {
        const proxy = (try self.boundVenomProxyPathForAbsolutePath(absolute_path)) orelse return null;
        if (std.mem.eql(u8, proxy.remote_path, "/")) return null;

        var router = (try self.boundVenomRouter(proxy.venom_id, proxy.project_id, proxy.agent_id)) orelse return null;
        defer router.deinit();
        defer self.allocator.free(proxy.remote_path);
        const file = router.open(proxy.remote_path, 0) catch return null;
        defer router.close(file) catch {};
        return router.read(file, 0, 1024 * 1024) catch null;
    }

    fn tryWriteBoundVenomProxyFile(self: *Session, node_id: u32, offset: u64, data: []const u8) !?WriteOutcome {
        const absolute_path = try self.nodeAbsolutePath(node_id);
        defer self.allocator.free(absolute_path);

        if (try self.boundVenomProxyPathForAbsolutePath(absolute_path)) |proxy| {
            defer self.allocator.free(proxy.remote_path);
            if (std.mem.eql(u8, proxy.venom_id, "chat") and std.mem.eql(u8, proxy.remote_path, "/control/input")) {
                return self.writeBoundChatInputProxy(proxy.project_id, proxy.agent_id, node_id, data);
            }
            if (std.mem.eql(u8, proxy.venom_id, "events") and std.mem.eql(u8, proxy.remote_path, "/control/wait.json")) {
                return self.writeBoundSimpleProxy("events", proxy.project_id, proxy.agent_id, "/control/wait.json", data);
            }
            if (std.mem.eql(u8, proxy.venom_id, "events") and std.mem.eql(u8, proxy.remote_path, "/control/signal.json")) {
                return self.writeBoundSimpleProxy("events", proxy.project_id, proxy.agent_id, "/control/signal.json", data);
            }
            if (std.mem.eql(u8, proxy.remote_path, "/")) return null;
            return self.writeBoundGenericProxy(proxy.venom_id, proxy.project_id, proxy.agent_id, proxy.remote_path, offset, data);
        }
        return null;
    }

    fn writeBoundChatInputProxy(
        self: *Session,
        project_id: ?[]const u8,
        agent_id: ?[]const u8,
        source_node_id: u32,
        data: []const u8,
    ) !?WriteOutcome {
        var router = (try self.boundVenomRouter("chat", project_id, agent_id)) orelse return null;
        defer router.deinit();
        const file = router.open("/control/input", 1) catch return null;
        defer router.close(file) catch {};
        const result_json = router.writeResult(file, 0, data) catch return null;
        defer self.allocator.free(result_json);

        var outcome = WriteOutcome{ .written = data.len };
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, result_json, .{}) catch return outcome;
        defer parsed.deinit();
        if (parsed.value != .object) return outcome;
        const obj = parsed.value.object;
        if (obj.get("n")) |value| {
            if (value == .integer and value.integer >= 0) outcome.written = @intCast(value.integer);
        }
        if (obj.get("job")) |value| {
            if (value == .string and value.string.len > 0) {
                outcome.job_name = try self.allocator.dupe(u8, value.string);
                try self.ensureProxyJobDirectoryForSource(source_node_id, value.string);
            }
        }
        if (obj.get("correlation_id")) |value| {
            if (value == .string and value.string.len > 0) {
                outcome.correlation_id = try self.allocator.dupe(u8, value.string);
            }
        }
        return outcome;
    }

    fn writeBoundSimpleProxy(
        self: *Session,
        venom_id: []const u8,
        project_id: ?[]const u8,
        agent_id: ?[]const u8,
        remote_path: []const u8,
        data: []const u8,
    ) !?WriteOutcome {
        var router = (try self.boundVenomRouter(venom_id, project_id, agent_id)) orelse return null;
        defer router.deinit();
        const file = router.open(remote_path, 1) catch return null;
        defer router.close(file) catch {};
        const result_json = router.writeResult(file, 0, data) catch return null;
        defer self.allocator.free(result_json);

        var outcome = WriteOutcome{ .written = data.len };
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, result_json, .{}) catch return outcome;
        defer parsed.deinit();
        if (parsed.value != .object) return outcome;
        if (parsed.value.object.get("n")) |value| {
            if (value == .integer and value.integer >= 0) outcome.written = @intCast(value.integer);
        }
        return outcome;
    }

    fn writeBoundGenericProxy(
        self: *Session,
        venom_id: []const u8,
        project_id: ?[]const u8,
        agent_id: ?[]const u8,
        remote_path: []const u8,
        offset: u64,
        data: []const u8,
    ) !?WriteOutcome {
        var router = (try self.boundVenomRouter(venom_id, project_id, agent_id)) orelse return null;
        defer router.deinit();
        const file = router.open(remote_path, 1) catch return null;
        defer router.close(file) catch {};
        const result_json = router.writeResult(file, offset, data) catch return null;
        defer self.allocator.free(result_json);

        var outcome = WriteOutcome{ .written = data.len };
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, result_json, .{}) catch return outcome;
        defer parsed.deinit();
        if (parsed.value != .object) return outcome;
        if (parsed.value.object.get("n")) |value| {
            if (value == .integer and value.integer >= 0) outcome.written = @intCast(value.integer);
        }
        return outcome;
    }

    fn buildBoundVenomProxyStatPayload(self: *Session, node_id: u32) !?[]u8 {
        const absolute_path = try self.nodeAbsolutePath(node_id);
        defer self.allocator.free(absolute_path);
        const proxy = (try self.boundVenomProxyPathForAbsolutePath(absolute_path)) orelse return null;
        defer self.allocator.free(proxy.remote_path);

        var router = (try self.boundVenomRouter(proxy.venom_id, proxy.project_id, proxy.agent_id)) orelse return null;
        defer router.deinit();
        const attr_json = router.getattr(proxy.remote_path) catch return null;
        defer self.allocator.free(attr_json);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, attr_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;

        const node = self.nodes.get(node_id) orelse return null;
        const escaped_name = try unified.jsonEscape(self.allocator, node.name);
        defer self.allocator.free(escaped_name);

        const mode: u32 = if (parsed.value.object.get("m")) |value|
            switch (value) {
                .integer => if (value.integer >= 0) @intCast(value.integer) else nodeMode(node),
                else => nodeMode(node),
            }
        else
            nodeMode(node);
        const summary = parseBoundVenomProxyAttr(parsed.value) orelse BoundVenomProxyAttrSummary{
            .kind = node.kind,
            .writable = node.writable,
        };
        const size: u64 = if (parsed.value.object.get("sz")) |value|
            switch (value) {
                .integer => if (value.integer >= 0) @intCast(value.integer) else node.content.len,
                else => node.content.len,
            }
        else
            node.content.len;

        return try std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":{d},\"name\":\"{s}\",\"kind\":\"{s}\",\"size\":{d},\"mode\":{d},\"writable\":{s}}}",
            .{ node.id, escaped_name, kindName(summary.kind), size, mode, if (summary.writable) "true" else "false" },
        );
    }

    fn ensureProxyJobDirectory(self: *Session, jobs_root_id: u32, job_id: []const u8) !void {
        if (self.lookupChild(jobs_root_id, job_id) != null) return;
        const job_dir = try self.addDir(jobs_root_id, job_id, false);
        _ = try self.addFile(job_dir, "request.json", "", false, .none);
        _ = try self.addFile(job_dir, "status.json", "", false, .none);
        _ = try self.addFile(job_dir, "result.txt", "", false, .none);
        _ = try self.addFile(job_dir, "log.txt", "", false, .none);
    }

    fn ensureProxyJobDirectoryForSource(self: *Session, source_node_id: u32, job_id: []const u8) !void {
        const absolute_path = try self.nodeAbsolutePath(source_node_id);
        defer self.allocator.free(absolute_path);

        if (pathMatchesPrefixBoundary(absolute_path, "/agents/")) {
            const jobs_root = try self.jobsAliasRootForAbsolutePath(absolute_path, "agents");
            if (jobs_root) |value| {
                try self.ensureProxyJobDirectory(value, job_id);
                return;
            }
        }
        if (pathMatchesPrefixBoundary(absolute_path, "/projects/")) {
            const jobs_root = try self.jobsAliasRootForAbsolutePath(absolute_path, "projects");
            if (jobs_root) |value| {
                try self.ensureProxyJobDirectory(value, job_id);
                return;
            }
        }
        try self.ensureProxyJobDirectory(self.jobs_root_id, job_id);
    }

    fn jobsAliasRootForAbsolutePath(self: *Session, absolute_path: []const u8, scope_root: []const u8) !?u32 {
        if (std.mem.eql(u8, scope_root, "agents")) {
            const parsed = parseEntityScopedVenomAliasPrefix(absolute_path, "/agents/", "/venoms/") orelse return null;
            const agents_root = self.lookupChild(self.root_id, "agents") orelse return null;
            const agent_dir = self.lookupChild(agents_root, parsed.entity_id) orelse return null;
            const venoms_dir = self.lookupChild(agent_dir, "venoms") orelse return null;
            return self.lookupChild(venoms_dir, "jobs");
        }
        if (std.mem.eql(u8, scope_root, "projects")) {
            const parsed = parseEntityScopedVenomAliasPrefix(absolute_path, "/projects/", "/venoms/") orelse return null;
            const projects_root = self.lookupChild(self.root_id, "projects") orelse return null;
            const project_dir = self.lookupChild(projects_root, parsed.entity_id) orelse return null;
            const venoms_dir = self.lookupChild(project_dir, "venoms") orelse return null;
            return self.lookupChild(venoms_dir, "jobs");
        }
        return null;
    }

    fn buildJobResultPathForNode(self: *Session, node_id: u32, job_id: []const u8) ![]u8 {
        const absolute_path = try self.nodeAbsolutePath(node_id);
        defer self.allocator.free(absolute_path);

        if (pathMatchesPrefixBoundary(absolute_path, "/nodes/local/venoms/chat")) {
            return std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/jobs/{s}/result.txt", .{job_id});
        }
        if (parseEntityScopedVenomAliasPrefix(absolute_path, "/agents/", "/venoms/")) |parsed| {
            return std.fmt.allocPrint(
                self.allocator,
                "/agents/{s}/venoms/jobs/{s}/result.txt",
                .{ parsed.entity_id, job_id },
            );
        }
        if (parseEntityScopedVenomAliasPrefix(absolute_path, "/projects/", "/venoms/")) |parsed| {
            return std.fmt.allocPrint(
                self.allocator,
                "/projects/{s}/venoms/jobs/{s}/result.txt",
                .{ parsed.entity_id, job_id },
            );
        }
        return std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/jobs/{s}/result.txt", .{job_id});
    }

    fn boundVenomProxyPathForAbsolutePath(self: *Session, absolute_path: []const u8) !?BoundVenomProxyPath {
        const global_match = parseScopedVenomAliasPrefix(absolute_path, "/global/");
        if (global_match) |value| {
            return .{
                .venom_id = value.venom_id,
                .remote_path = try self.allocator.dupe(u8, value.remote_path),
            };
        }
        const agent_match = parseEntityScopedVenomAliasPrefix(absolute_path, "/agents/", "/venoms/");
        if (agent_match) |value| {
            return .{
                .venom_id = value.venom_id,
                .remote_path = try self.allocator.dupe(u8, value.remote_path),
                .agent_id = value.entity_id,
            };
        }
        const project_match = parseEntityScopedVenomAliasPrefix(absolute_path, "/projects/", "/venoms/");
        if (project_match) |value| {
            return .{
                .venom_id = value.venom_id,
                .remote_path = try self.allocator.dupe(u8, value.remote_path),
                .project_id = value.entity_id,
            };
        }
        return null;
    }

    fn refreshBoundVenomProxyDirectory(self: *Session, dir_id: u32) !void {
        const absolute_path = try self.nodeAbsolutePath(dir_id);
        defer self.allocator.free(absolute_path);

        const proxy = (try self.boundVenomProxyPathForAbsolutePath(absolute_path)) orelse return;
        defer self.allocator.free(proxy.remote_path);

        var router = (try self.boundVenomRouter(proxy.venom_id, proxy.project_id, proxy.agent_id)) orelse return;
        defer router.deinit();

        var seen_names = std.ArrayListUnmanaged([]u8){};
        defer {
            for (seen_names.items) |name| self.allocator.free(name);
            seen_names.deinit(self.allocator);
        }
        var cookie: u64 = 0;
        while (true) {
            const listing_json = router.readdir(proxy.remote_path, cookie, 4096) catch return;
            defer self.allocator.free(listing_json);
            cookie = try self.applyBoundVenomProxyListing(dir_id, listing_json, &seen_names);
            if (cookie == 0) break;
        }
        try self.pruneBoundVenomProxyChildren(dir_id, seen_names.items);
    }

    fn applyBoundVenomProxyListing(
        self: *Session,
        parent_id: u32,
        listing_json: []const u8,
        seen_names: *std.ArrayListUnmanaged([]u8),
    ) !u64 {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, listing_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return 0;

        const next_cookie = parseReaddirNextCookie(parsed.value.object);
        const ents = parsed.value.object.get("ents") orelse return next_cookie;
        if (ents != .array) return next_cookie;
        for (ents.array.items) |entry| {
            if (entry != .object) continue;
            const name_val = entry.object.get("name") orelse continue;
            const attr_val = entry.object.get("attr") orelse continue;
            if (name_val != .string or name_val.string.len == 0) continue;
            try self.noteBoundVenomProxyChildSeen(seen_names, name_val.string);
            try self.upsertBoundVenomProxyChild(parent_id, name_val.string, attr_val);
        }
        return next_cookie;
    }

    fn parseReaddirNextCookie(obj: std.json.ObjectMap) u64 {
        if (obj.get("next_cookie")) |value| {
            if (value == .integer and value.integer >= 0) return @intCast(value.integer);
        }
        if (obj.get("next")) |value| {
            if (value == .integer and value.integer >= 0) return @intCast(value.integer);
        }
        return 0;
    }

    fn upsertBoundVenomProxyChild(self: *Session, parent_id: u32, name: []const u8, attr_val: std.json.Value) !void {
        const summary = parseBoundVenomProxyAttr(attr_val) orelse return;
        if (self.lookupChild(parent_id, name)) |child_id| {
            const child = self.nodes.getPtr(child_id) orelse return;
            child.kind = summary.kind;
            child.writable = summary.writable;
            return;
        }
        switch (summary.kind) {
            .dir => _ = try self.addDir(parent_id, name, false),
            .file => _ = try self.addFile(parent_id, name, "", summary.writable, .none),
        }
    }

    fn noteBoundVenomProxyChildSeen(
        self: *Session,
        seen_names: *std.ArrayListUnmanaged([]u8),
        name: []const u8,
    ) !void {
        for (seen_names.items) |existing| {
            if (std.mem.eql(u8, existing, name)) return;
        }
        try seen_names.append(self.allocator, try self.allocator.dupe(u8, name));
    }

    fn pruneBoundVenomProxyChildren(self: *Session, parent_id: u32, seen_names: []const []const u8) !void {
        const parent = self.nodes.get(parent_id) orelse return;
        var doomed = std.ArrayListUnmanaged(u32){};
        defer doomed.deinit(self.allocator);

        var it = parent.children.iterator();
        while (it.next()) |entry| {
            if (containsBoundVenomProxyChildName(seen_names, entry.key_ptr.*)) continue;
            try doomed.append(self.allocator, entry.value_ptr.*);
        }
        for (doomed.items) |child_id| {
            try self.deleteNodeRecursive(child_id);
        }
    }

    fn containsBoundVenomProxyChildName(seen_names: []const []const u8, name: []const u8) bool {
        for (seen_names) |seen| {
            if (std.mem.eql(u8, seen, name)) return true;
        }
        return false;
    }

    fn boundVenomRouter(
        self: *Session,
        venom_id: []const u8,
        project_id: ?[]const u8,
        agent_id: ?[]const u8,
    ) !?acheron_router.Router {
        const plane = self.control_plane orelse return null;
        var provider = (try plane.resolvePreferredVenomProviderForContext(
            self.allocator,
            venom_id,
            &.{ "spiderapp-default", "spiderweb-local", "local" },
            project_id,
            agent_id,
        ));
        defer if (provider) |*value| value.deinit(self.allocator);
        if (provider) |value| {
            if (self.isBoundVenomNodeAllowed(project_id, agent_id, value.node_id)) {
                if (try self.boundVenomRouterForNode(plane, venom_id, value.node_id)) |router| return router;
            }
        }

        const nodes_root = self.lookupChild(self.root_id, "nodes") orelse return null;
        const nodes_root_node = self.nodes.get(nodes_root) orelse return null;
        var node_it = nodes_root_node.children.iterator();
        while (node_it.next()) |entry| {
            const node_name = entry.key_ptr.*;
            const node_dir_id = entry.value_ptr.*;
            const venoms_root_id = self.lookupChild(node_dir_id, "venoms") orelse continue;
            _ = self.lookupChild(venoms_root_id, venom_id) orelse continue;
            if (!self.isBoundVenomNodeAllowed(project_id, agent_id, node_name)) continue;
            if (try self.boundVenomRouterForNode(plane, venom_id, node_name)) |router| return router;
        }

        return null;
    }

    fn boundVenomRouterForNode(
        self: *Session,
        plane: *control_plane_mod.ControlPlane,
        venom_id: []const u8,
        node_id: []const u8,
    ) !?acheron_router.Router {
        const node_payload_req = try std.fmt.allocPrint(self.allocator, "{{\"node_id\":\"{s}\"}}", .{node_id});
        defer self.allocator.free(node_payload_req);
        const node_payload = plane.getNode(node_payload_req) catch return null;
        defer self.allocator.free(node_payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, node_payload, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const fs_url_val = parsed.value.object.get("fs_url") orelse return null;
        if (fs_url_val != .string or fs_url_val.string.len == 0) return null;

        return try acheron_router.Router.init(self.allocator, &[_]acheron_router.EndpointConfig{.{
            .name = node_id,
            .url = fs_url_val.string,
            .export_name = venom_id,
            .mount_path = "/",
        }});
    }

    fn seedBoundGlobalFsNamespace(
        self: *Session,
        global_root: u32,
        preferred_node_id: []const u8,
    ) !bool {
        const alias_dir_id = try self.addDir(global_root, "fs", false);
        _ = alias_dir_id;
        return self.registerBoundVenomAliasOnly("/global", "fs", "global_binding", preferred_node_id, null, null);
    }

    fn isBoundVenomNodeAllowed(
        self: *Session,
        project_id: ?[]const u8,
        agent_id: ?[]const u8,
        node_id: []const u8,
    ) bool {
        const scoped_project_id = project_id orelse return true;
        const plane = self.control_plane orelse return false;
        return plane.projectAllowsNodeVenomEvent(
            scoped_project_id,
            if (agent_id) |value| value else self.agent_id,
            self.project_token,
            node_id,
            self.is_admin,
        );
    }

    fn registerBoundVenomAliasOnly(
        self: *Session,
        alias_base_path: []const u8,
        venom_id: []const u8,
        scope: []const u8,
        preferred_node_id: ?[]const u8,
        project_id: ?[]const u8,
        agent_id: ?[]const u8,
    ) !bool {
        const nodes_root = self.lookupChild(self.root_id, "nodes") orelse return false;

        var selected_node_id: ?[]const u8 = null;
        var selected_venom_dir_id: ?u32 = null;

        if (preferred_node_id) |selected| {
            const preferred_node_dir_id = self.lookupChild(nodes_root, selected);
            if (preferred_node_dir_id) |node_dir_id| {
                if (self.lookupChild(node_dir_id, "venoms")) |venoms_root_id| {
                    if (self.lookupChild(venoms_root_id, venom_id)) |venom_dir_id| {
                        if (self.isBoundVenomNodeAllowed(project_id, agent_id, selected)) {
                            selected_node_id = selected;
                            selected_venom_dir_id = venom_dir_id;
                        }
                    }
                }
            }
        }

        if (selected_venom_dir_id == null) {
            const nodes_root_node = self.nodes.get(nodes_root) orelse return false;
            var node_it = nodes_root_node.children.iterator();
            while (node_it.next()) |entry| {
                const node_name = entry.key_ptr.*;
                const node_dir_id = entry.value_ptr.*;
                const venoms_root_id = self.lookupChild(node_dir_id, "venoms") orelse continue;
                const venom_dir_id = self.lookupChild(venoms_root_id, venom_id) orelse continue;
                if (!self.isBoundVenomNodeAllowed(project_id, agent_id, node_name)) continue;
                selected_node_id = node_name;
                selected_venom_dir_id = venom_dir_id;
                break;
            }
        }

        const provider_node_id = selected_node_id orelse return false;
        const provider_dir_id = selected_venom_dir_id orelse return false;
        const venom_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ alias_base_path, venom_id });
        defer self.allocator.free(venom_path);
        const provider_venom_path = try std.fmt.allocPrint(
            self.allocator,
            "/nodes/{s}/venoms/{s}",
            .{ provider_node_id, venom_id },
        );
        defer self.allocator.free(provider_venom_path);
        const endpoint_path = blk: {
            if (try self.firstVenomMountPath(provider_dir_id)) |value| break :blk value;
            break :blk try self.venomEndpointPath(provider_dir_id);
        };
        defer if (endpoint_path) |value| self.allocator.free(value);
        const invoke_path = try self.deriveVenomInvokePath(provider_node_id, venom_id, provider_dir_id);
        defer if (invoke_path) |value| self.allocator.free(value);

        try self.registerScopedVenomBinding(
            venom_id,
            scope,
            venom_path,
            provider_node_id,
            provider_venom_path,
            endpoint_path,
            invoke_path,
        );
        return true;
    }

    fn handlePairingControlWrite(self: *Session, action: PairingAction, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try pairing_venom.handleControlWrite(self, action, raw_input) };
    }

    fn seedJobsFromIndex(self: *Session) !void {
        return jobs_venom.seedFromIndex(self);
    }

    pub fn buildJobStatusJson(
        self: *Session,
        state: chat_job_index.JobState,
        correlation_id: ?[]const u8,
        error_text: ?[]const u8,
    ) ![]u8 {
        const correlation_json = if (correlation_id) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(correlation_json);

        const error_json = if (error_text) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(error_json);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"state\":\"{s}\",\"correlation_id\":{s},\"error\":{s},\"updated_at_ms\":{d}}}",
            .{
                switch (state) {
                    .queued => "queued",
                    .running => "running",
                    .done => "done",
                    .failed => "failed",
                },
                correlation_json,
                error_json,
                std.time.milliTimestamp(),
            },
        );
    }

    const JobStatusWritePayload = struct {
        state: chat_job_index.JobState,
        error_text: ?[]u8 = null,

        fn deinit(self: *JobStatusWritePayload, allocator: std.mem.Allocator) void {
            if (self.error_text) |value| allocator.free(value);
            self.* = undefined;
        }
    };

    fn handleChatInputWrite(self: *Session, msg: *const unified.ParsedMessage, raw_input: []const u8) !WriteOutcome {
        const outcome = try chat_venom.handleInputWrite(self, msg, raw_input);
        return .{
            .written = outcome.written,
            .job_name = outcome.job_name,
            .correlation_id = outcome.correlation_id,
            .chat_reply_content = outcome.chat_reply_content,
        };
    }

    fn handleJobStatusWrite(self: *Session, node_id: u32, offset: u64, raw_input: []const u8) !WriteOutcome {
        try self.writeFileContent(node_id, offset, raw_input);
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        var parsed = try self.parseJobStatusWritePayload(node.content);
        defer parsed.deinit(self.allocator);

        const job_id = try self.jobIdForJobFileNode(node_id);
        defer self.allocator.free(job_id);

        switch (parsed.state) {
            .queued => {
                if (parsed.error_text) |value| {
                    try self.job_index.updateArtifacts(job_id, null, value, null);
                }
            },
            .running => {
                try self.job_index.markRunning(job_id);
                if (parsed.error_text) |value| {
                    try self.job_index.updateArtifacts(job_id, null, value, null);
                }
            },
            .done, .failed => {
                const result_text = try self.jobSiblingContent(node_id, "result.txt");
                defer self.allocator.free(result_text);
                const log_text = try self.jobSiblingContent(node_id, "log.txt");
                defer self.allocator.free(log_text);
                try self.job_index.markCompleted(
                    job_id,
                    parsed.state == .done,
                    result_text,
                    parsed.error_text,
                    log_text,
                );
            },
        }

        return .{ .written = raw_input.len };
    }

    fn handleJobResultWrite(self: *Session, node_id: u32, offset: u64, raw_input: []const u8) !WriteOutcome {
        try self.writeFileContent(node_id, offset, raw_input);
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        const job_id = try self.jobIdForJobFileNode(node_id);
        defer self.allocator.free(job_id);
        try self.job_index.updateArtifacts(job_id, node.content, null, null);
        return .{ .written = raw_input.len };
    }

    fn handleJobLogWrite(self: *Session, node_id: u32, offset: u64, raw_input: []const u8) !WriteOutcome {
        try self.writeFileContent(node_id, offset, raw_input);
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        const job_id = try self.jobIdForJobFileNode(node_id);
        defer self.allocator.free(job_id);
        try self.job_index.updateArtifacts(job_id, null, null, node.content);
        return .{ .written = raw_input.len };
    }

    fn parseJobStatusWritePayload(self: *Session, raw_input: []const u8) !JobStatusWritePayload {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw_input, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const state_value = obj.get("state") orelse return error.InvalidPayload;
        if (state_value != .string) return error.InvalidPayload;
        const state = if (std.mem.eql(u8, state_value.string, "queued"))
            chat_job_index.JobState.queued
        else if (std.mem.eql(u8, state_value.string, "running"))
            chat_job_index.JobState.running
        else if (std.mem.eql(u8, state_value.string, "done"))
            chat_job_index.JobState.done
        else if (std.mem.eql(u8, state_value.string, "failed"))
            chat_job_index.JobState.failed
        else
            return error.InvalidPayload;

        return .{
            .state = state,
            .error_text = if (obj.get("error")) |value|
                switch (value) {
                    .null => null,
                    .string => try self.allocator.dupe(u8, value.string),
                    else => return error.InvalidPayload,
                }
            else
                null,
        };
    }

    fn jobIdForJobFileNode(self: *Session, node_id: u32) ![]u8 {
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        const job_dir_id = node.parent orelse return error.MissingNode;
        const job_dir = self.nodes.get(job_dir_id) orelse return error.MissingNode;
        return self.allocator.dupe(u8, job_dir.name);
    }

    fn jobSiblingContent(self: *Session, node_id: u32, sibling_name: []const u8) ![]u8 {
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        const job_dir_id = node.parent orelse return error.MissingNode;
        const sibling_id = self.lookupChild(job_dir_id, sibling_name) orelse return self.allocator.dupe(u8, "");
        const sibling = self.nodes.get(sibling_id) orelse return self.allocator.dupe(u8, "");
        return self.allocator.dupe(u8, sibling.content);
    }

    pub fn spawnAsyncChatRuntimeJob(
        self: *Session,
        job_name: []const u8,
        input: []const u8,
        correlation_id: ?[]const u8,
    ) !void {
        self.runtime_handle.retain();
        const ctx = try self.allocator.create(AsyncChatRuntimeContext);
        ctx.* = .{
            .allocator = self.allocator,
            .runtime_handle = self.runtime_handle,
            .job_index = self.job_index,
            .control_plane = self.control_plane,
            .emit_debug = self.shouldEmitRuntimeDebugFrames(),
        };
        errdefer ctx.deinit();

        if (ctx.emit_debug and self.control_plane != null) {
            ctx.agent_id = try self.allocator.dupe(u8, self.agent_id);
        }
        ctx.job_name = try self.allocator.dupe(u8, job_name);
        ctx.input = try self.allocator.dupe(u8, input);
        if (correlation_id) |value| {
            ctx.correlation_id = try self.allocator.dupe(u8, value);
        }

        const thread = try std.Thread.spawn(.{}, asyncChatRuntimeThreadMain, .{ctx});
        thread.detach();
    }

    fn asyncChatRuntimeThreadMain(ctx: *AsyncChatRuntimeContext) void {
        defer ctx.deinit();
        const job_name = ctx.job_name orelse return;
        const input = ctx.input orelse return;

        asyncExecuteChatRuntimeJob(ctx, job_name, input, ctx.correlation_id) catch |err| {
            const normalized = shared_exec.normalizeRuntimeFailureForAgent("runtime_error", @errorName(err));
            const failure_log_owned = std.fmt.allocPrint(
                ctx.allocator,
                "[runtime worker failure] {s}\n",
                .{@errorName(err)},
            ) catch null;
            defer if (failure_log_owned) |value| ctx.allocator.free(value);
            const failure_log = if (failure_log_owned) |value|
                value
            else
                "[runtime worker failure]\n";

            ctx.job_index.markCompleted(
                job_name,
                false,
                normalized.message,
                normalized.message,
                failure_log,
            ) catch |mark_err| {
                std.log.warn("chat job completion failed after runtime worker error: {s}", .{@errorName(mark_err)});
            };
        };
    }

    fn asyncExecuteChatRuntimeJob(
        ctx: *AsyncChatRuntimeContext,
        job_name: []const u8,
        input: []const u8,
        correlation_id: ?[]const u8,
    ) !void {
        var outcome = try shared_exec.execute(.{
            .allocator = ctx.allocator,
            .executor = .{
                .ctx = @ptrCast(ctx.runtime_handle),
                .execute = executeWithRuntimeHandle,
                .deinit_frames = deinitResponseFramesWithContext,
            },
            .request_id = job_name,
            .input = input,
            .correlation_id = correlation_id,
            .emit_debug = ctx.emit_debug,
        });
        defer outcome.deinit(ctx.allocator);

        try ctx.job_index.markCompleted(
            job_name,
            outcome.succeeded,
            outcome.result_text,
            outcome.error_text,
            outcome.log_text,
        );

        if (ctx.emit_debug and ctx.control_plane != null and ctx.agent_id != null) {
            try appendDebugEventsFromLogText(
                ctx.allocator,
                ctx.control_plane.?,
                ctx.agent_id.?,
                outcome.log_text,
            );
        }
    }

    fn handleChatReplyWrite(self: *Session, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const outcome = try chat_venom.handleReplyWrite(self, node_id, raw_input);
        return .{
            .written = outcome.written,
            .job_name = outcome.job_name,
            .correlation_id = outcome.correlation_id,
            .chat_reply_content = outcome.chat_reply_content,
        };
    }

    fn recordThoughtFrame(
        self: *Session,
        content: []const u8,
        source: ?[]const u8,
        round: ?usize,
    ) !void {
        if (self.thoughts_latest_id == 0 or self.thoughts_history_id == 0 or self.thoughts_status_id == 0) return;

        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        if (trimmed.len == 0) return;

        try self.setFileContent(self.thoughts_latest_id, trimmed);

        const now_ms = std.time.milliTimestamp();
        const seq = self.next_thought_seq;
        self.next_thought_seq +%= 1;
        if (self.next_thought_seq == 0) self.next_thought_seq = 1;

        const escaped_content = try unified.jsonEscape(self.allocator, trimmed);
        defer self.allocator.free(escaped_content);
        const source_json = if (source) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(source_json);
        const round_json = if (round) |value|
            try std.fmt.allocPrint(self.allocator, "{d}", .{value})
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(round_json);

        const line = try std.fmt.allocPrint(
            self.allocator,
            "{{\"seq\":{d},\"ts_ms\":{d},\"source\":{s},\"round\":{s},\"content\":\"{s}\"}}\n",
            .{ seq, now_ms, source_json, round_json, escaped_content },
        );
        defer self.allocator.free(line);

        const history_node = self.nodes.get(self.thoughts_history_id) orelse return error.MissingNode;
        try self.writeFileContent(self.thoughts_history_id, history_node.content.len, line);

        const status_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"count\":{d},\"updated_at_ms\":{d},\"latest_source\":{s},\"latest_round\":{s}}}",
            .{ seq, now_ms, source_json, round_json },
        );
        defer self.allocator.free(status_json);
        try self.setFileContent(self.thoughts_status_id, status_json);
    }

    fn handleSearchNamespaceWrite(
        self: *Session,
        special: SpecialKind,
        node_id: u32,
        raw_input: []const u8,
    ) !WriteOutcome {
        const written = try search_services_venom.handleNamespaceWrite(self, special, node_id, raw_input);
        return .{ .written = written };
    }

    pub fn renderJsonValueToWriter(self: *Session, writer: anytype, value: std.json.Value) !void {
        switch (value) {
            .null => try writer.writeAll("null"),
            .bool => |v| try writer.writeAll(if (v) "true" else "false"),
            .integer => |v| try writer.print("{d}", .{v}),
            .float => |v| try writer.print("{d}", .{v}),
            .number_string => |v| try writer.writeAll(v),
            .string => |v| try writeJsonString(writer, v),
            .array => |arr| {
                try writer.writeByte('[');
                for (arr.items, 0..) |item, idx| {
                    if (idx != 0) try writer.writeByte(',');
                    try self.renderJsonValueToWriter(writer, item);
                }
                try writer.writeByte(']');
            },
            .object => |obj| {
                try writer.writeByte('{');
                var first = true;
                var it = obj.iterator();
                while (it.next()) |entry| {
                    if (!first) try writer.writeByte(',');
                    first = false;
                    try writeJsonString(writer, entry.key_ptr.*);
                    try writer.writeByte(':');
                    try self.renderJsonValueToWriter(writer, entry.value_ptr.*);
                }
                try writer.writeByte('}');
            },
        }
    }

    fn handleMountsNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try mounts_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    fn handleHomeNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try home_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    fn handleWorkersNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try workers_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    fn handleVenomPackagesNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try venom_packages_service_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    pub fn normalizeLocalFsRelativePath(self: *Session, raw_path: []const u8) ![]u8 {
        return mounts_venom.normalizeLocalFsRelativePath(self, raw_path);
    }

    pub fn ensurePathExists(path: []const u8) !void {
        return mounts_venom.ensurePathExists(path);
    }

    fn handleAgentsInvokeWrite(self: *Session, invoke_node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try agents_venom.handleInvokeWrite(self, invoke_node_id, raw_input) };
    }

    fn handleAgentsListWrite(self: *Session, list_node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try agents_venom.handleListWrite(self, list_node_id, raw_input) };
    }

    fn handleAgentsCreateWrite(self: *Session, create_node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try agents_venom.handleCreateWrite(self, create_node_id, raw_input) };
    }

    const AgentAbilities = struct {
        can_create_agents: bool,
    };

    pub fn canCreateAgents(self: *Session) bool {
        const abilities = self.resolveAgentAbilities() catch return false;
        return abilities.can_create_agents;
    }

    pub fn isToolAllowedForCurrentAgent(self: *Session, tool_name: []const u8) !bool {
        const policy_agent_id = if (std.mem.eql(u8, self.actor_type, "agent") and self.actor_id.len > 0)
            self.actor_id
        else
            self.agent_id;

        var config = try agent_config.loadAgentConfigFromDir(self.allocator, self.agents_dir, policy_agent_id);
        if (config == null and !std.mem.eql(u8, policy_agent_id, self.agent_id)) {
            config = try agent_config.loadAgentConfigFromDir(self.allocator, self.agents_dir, self.agent_id);
        }
        if (config == null) return true;

        var owned_config = config.?;
        defer owned_config.deinit();

        const primary = owned_config.primary.view();

        if (primary.denied_tools) |denied_tools| {
            if (toolListContains(denied_tools, tool_name)) return false;
        }

        if (primary.allowed_tools) |allowed_tools| {
            return toolListContains(allowed_tools, tool_name);
        }

        return true;
    }

    fn resolveAgentAbilities(self: *Session) !AgentAbilities {
        var abilities = AgentAbilities{
            .can_create_agents = std.mem.eql(u8, self.agent_id, "spiderweb"),
        };

        if (try agent_config.loadAgentConfigFromDir(self.allocator, self.agents_dir, self.agent_id)) |config| {
            defer {
                var owned = config;
                owned.deinit();
            }
            if (config.primary.capabilities) |caps| {
                for (caps.items) |capability| {
                    if (capabilityMatchesAny(capability, &agent_create_capabilities)) {
                        abilities.can_create_agents = true;
                    }
                }
            }
        }

        var registry = agent_registry.AgentRegistry.init(
            self.allocator,
            ".",
            self.agents_dir,
            self.assets_dir,
        );
        defer registry.deinit();
        registry.scan() catch return abilities;
        if (registry.getAgent(self.agent_id)) |info| {
            for (info.capabilities.items) |capability| {
                switch (capability) {
                    .plan => abilities.can_create_agents = true,
                    else => {},
                }
            }
        }

        return abilities;
    }

    fn capabilityMatchesAny(capability: []const u8, accepted: []const []const u8) bool {
        for (accepted) |candidate| {
            if (std.ascii.eqlIgnoreCase(capability, candidate)) return true;
        }
        return false;
    }

    fn toolListContains(list: std.ArrayListUnmanaged([]u8), tool_name: []const u8) bool {
        for (list.items) |item| {
            if (std.mem.eql(u8, item, tool_name)) return true;
        }
        return false;
    }

    fn extractOptionalStringByNames(
        obj: std.json.ObjectMap,
        candidate_names: []const []const u8,
    ) ?[]const u8 {
        for (candidate_names) |field| {
            if (obj.get(field)) |value| {
                if (value == .string and value.string.len > 0) return value.string;
            }
        }
        return null;
    }

    pub const WorkspaceOp = workspaces_venom.Op;

    pub const GitOp = git_venom.Op;

    pub const GitHubPrOp = github_pr_venom.Op;

    pub const PrReviewOp = pr_review_venom.Op;

    fn handleWorkspacesNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try workspaces_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    pub const ParsedShellExecResult = git_venom.ParsedShellExecResult;

    pub const ShellExecOutcome = union(enum) {
        success: ParsedShellExecResult,
        failure: ToolPayloadErrorInfo,

        pub fn deinit(self: *ShellExecOutcome, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .success => |*value| value.deinit(allocator),
                .failure => |*value| value.deinit(allocator),
            }
            self.* = undefined;
        }
    };

    fn handleGitNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = switch (special) {
            .git_sync_checkout => GitOp.sync_checkout,
            .git_status => GitOp.status,
            .git_diff_range => GitOp.diff_range,
            .git_invoke => blk: {
                const op_raw = blk2: {
                    if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    break :blk2 null;
                } orelse return error.InvalidPayload;
                break :blk parseGitOp(op_raw) orelse return error.InvalidPayload;
            },
            else => return error.InvalidPayload,
        };

        const args_obj = blk: {
            if (obj.get("arguments")) |value| {
                if (value != .object) return error.InvalidPayload;
                break :blk value.object;
            }
            if (obj.get("args")) |value| {
                if (value != .object) return error.InvalidPayload;
                break :blk value.object;
            }
            break :blk obj;
        };

        return self.executeGitOp(op, args_obj, raw_input.len);
    }

    fn handleGitHubPrNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try github_pr_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    fn parseGitOp(raw: []const u8) ?GitOp {
        return git_venom.parseOp(raw);
    }

    fn gitOperationName(op: GitOp) []const u8 {
        return git_venom.operationName(op);
    }

    fn gitStatusToolName(op: GitOp) []const u8 {
        return git_venom.statusToolName(op);
    }

    fn executeGitOp(self: *Session, op: GitOp, args_obj: std.json.ObjectMap, written: usize) !WriteOutcome {
        const tool_name = gitStatusToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        try self.setMirroredFileContent(self.git_status_id, self.git_status_alias_id, running_status);

        const result_payload = self.executeGitOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.git_status_id, self.git_status_alias_id, failed_status);
            const failed_result = try self.buildGitFailureResultJson(op, "invalid_payload", error_message);
            defer self.allocator.free(failed_result);
            try self.setMirroredFileContent(self.git_result_id, self.git_result_alias_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
            defer self.allocator.free(message);
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.git_status_id, self.git_status_alias_id, failed_status);
        } else {
            const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
            defer self.allocator.free(done_status);
            try self.setMirroredFileContent(self.git_status_id, self.git_status_alias_id, done_status);
        }
        try self.setMirroredFileContent(self.git_result_id, self.git_result_alias_id, result_payload);
        return .{ .written = written };
    }

    fn executeGitOpPayload(self: *Session, op: GitOp, args_obj: std.json.ObjectMap) ![]u8 {
        return git_venom.executeOpPayload(self, op, args_obj);
    }

    pub fn buildCliCommand(self: *Session, program: []const u8, argv: []const []const u8) ![]u8 {
        return git_venom.buildCliCommand(self, program, argv);
    }

    pub fn runShellExecCommand(self: *Session, command: []const u8, cwd: ?[]const u8, timeout_ms: u64) !ShellExecOutcome {
        const args_json = try self.buildShellExecArgsJson(command, cwd, timeout_ms);
        defer self.allocator.free(args_json);
        const payload_json = try self.executeServiceToolCall("shell_exec", args_json);
        defer self.allocator.free(payload_json);

        if (try self.extractErrorInfoFromToolPayload(payload_json)) |info| {
            return .{ .failure = info };
        }
        return .{ .success = try self.parseShellExecPayload(payload_json) };
    }

    fn buildShellExecArgsJson(self: *Session, command: []const u8, cwd: ?[]const u8, timeout_ms: u64) ![]u8 {
        return git_venom.buildShellExecArgsJson(self, command, cwd, timeout_ms);
    }

    pub fn parseShellExecPayload(self: *Session, payload_json: []const u8) !ParsedShellExecResult {
        return git_venom.parseShellExecPayload(self, payload_json);
    }

    fn normalizeJsonText(self: *Session, raw: []const u8) ![]u8 {
        return git_venom.normalizeJsonText(self, raw);
    }

    pub fn buildGitSuccessResultJson(self: *Session, op: GitOp, result_json: []const u8) ![]u8 {
        return git_venom.buildGitSuccessResultJson(self, op, result_json);
    }

    pub fn buildGitFailureResultJson(self: *Session, op: GitOp, code: []const u8, message: []const u8) ![]u8 {
        return git_venom.buildGitFailureResultJson(self, op, code, message);
    }

    pub fn buildGitHubPrSuccessResultJson(self: *Session, op: GitHubPrOp, result_json: []const u8) ![]u8 {
        return github_pr_venom.buildGitHubPrSuccessResultJson(self, op, result_json);
    }

    pub fn buildGitHubPrFailureResultJson(self: *Session, op: GitHubPrOp, code: []const u8, message: []const u8) ![]u8 {
        return github_pr_venom.buildGitHubPrFailureResultJson(self, op, code, message);
    }

    fn handlePrReviewNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try pr_review_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    pub const PrReviewResolvedContract = pr_review_venom.ResolvedContract;
    pub const PrReviewContextSnapshot = pr_review_venom.ContextSnapshot;
    pub const PrReviewStateSnapshot = pr_review_venom.StateSnapshot;
    pub const PrReviewRepoConfigSnapshot = pr_review_venom.RepoConfigSnapshot;

    pub fn bootstrapPrReviewMission(self: *Session, args_obj: std.json.ObjectMap) !mission_store_mod.MissionRecord {
        return pr_review_venom.bootstrapMission(self, args_obj);
    }

    pub fn resolvePrReviewMissionContract(self: *Session, mission: mission_store_mod.MissionRecord) !PrReviewResolvedContract {
        return pr_review_venom.resolveMissionContract(self, mission);
    }

    pub fn buildPrReviewRunId(self: *Session, repo_key: []const u8, pr_number: u64) ![]u8 {
        return pr_review_venom.buildRunId(self, repo_key, pr_number);
    }

    pub fn loadConfiguredPrReviewRepo(self: *Session, repo_key: []const u8) !?PrReviewRepoConfigSnapshot {
        return pr_review_venom.loadConfiguredRepo(self, repo_key);
    }

    pub fn findActivePrReviewMissionByRunId(
        self: *Session,
        store: *mission_store_mod.MissionStore,
        run_id: []const u8,
        project_id: ?[]const u8,
    ) !?mission_store_mod.MissionRecord {
        return pr_review_venom.findActiveMissionByRunId(self, store, run_id, project_id);
    }

    pub fn normalizeLocalWorkspaceAbsolutePath(self: *Session, raw_path: []const u8) ![]u8 {
        const normalized = try self.normalizeMissionAbsolutePath(raw_path);
        errdefer self.allocator.free(normalized);
        const host_path = try self.resolveMissionContractHostPath(normalized);
        self.allocator.free(host_path);
        return normalized;
    }

    pub fn readMissionContractFile(self: *Session, absolute_path: []const u8, max_bytes: usize) ![]u8 {
        const host_path = try self.resolveMissionContractHostPath(absolute_path);
        defer self.allocator.free(host_path);
        if (std.fs.path.isAbsolute(host_path)) {
            const file = try std.fs.openFileAbsolute(host_path, .{});
            defer file.close();
            return file.readToEndAlloc(self.allocator, max_bytes);
        }
        return std.fs.cwd().readFileAlloc(self.allocator, host_path, max_bytes);
    }

    pub fn loadPrReviewContextSnapshot(self: *Session, context_path: []const u8) !PrReviewContextSnapshot {
        return pr_review_venom.loadContextSnapshot(self, context_path);
    }

    pub fn loadPrReviewStateSnapshot(self: *Session, state_path: []const u8) !PrReviewStateSnapshot {
        return pr_review_venom.loadStateSnapshot(self, state_path);
    }

    pub fn replaceOwnedString(self: *Session, target: *[]u8, value: []const u8) !void {
        const copy = try self.allocator.dupe(u8, value);
        self.allocator.free(target.*);
        target.* = copy;
    }

    pub fn replaceOptionalOwnedString(self: *Session, target: *?[]u8, value: ?[]const u8) !void {
        if (target.*) |existing| self.allocator.free(existing);
        target.* = if (value) |slice| try self.allocator.dupe(u8, slice) else null;
    }

    pub fn replaceOwnedJsonValue(self: *Session, target: *[]u8, value: std.json.Value, default_json: []const u8) !void {
        const rendered = if (value == .null)
            try self.allocator.dupe(u8, default_json)
        else
            try self.renderJsonValue(value);
        self.allocator.free(target.*);
        target.* = rendered;
    }

    pub fn findJsonObjectFieldByNames(_: *Session, obj: std.json.ObjectMap, names: []const []const u8) ?std.json.Value {
        for (names) |name| {
            if (obj.get(name)) |value| return value;
        }
        return null;
    }

    pub fn formatJsonString(self: *Session, value: []const u8) ![]u8 {
        const escaped = try unified.jsonEscape(self.allocator, value);
        defer self.allocator.free(escaped);
        return std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
    }

    fn renderPrReviewStringArg(
        self: *Session,
        overrides: ?std.json.ObjectMap,
        names: []const []const u8,
        default: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.renderPrReviewStringArg(self, overrides, names, default);
    }

    fn renderPrReviewU64Arg(
        self: *Session,
        overrides: ?std.json.ObjectMap,
        names: []const []const u8,
        default: ?u64,
    ) ![]u8 {
        return pr_review_venom.renderPrReviewU64Arg(self, overrides, names, default);
    }

    fn renderPrReviewBoolArg(
        self: *Session,
        overrides: ?std.json.ObjectMap,
        names: []const []const u8,
        default: ?bool,
    ) ![]u8 {
        return pr_review_venom.renderPrReviewBoolArg(self, overrides, names, default);
    }

    pub fn buildPrReviewGitHubSyncRequestJson(
        self: *Session,
        context: PrReviewContextSnapshot,
        overrides: ?std.json.ObjectMap,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewGitHubSyncRequestJson(self, context, overrides);
    }

    pub fn buildPrReviewGitSyncCheckoutRequestJson(
        self: *Session,
        context: PrReviewContextSnapshot,
        overrides: ?std.json.ObjectMap,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewGitSyncCheckoutRequestJson(self, context, overrides);
    }

    pub fn buildPrReviewGitStatusRequestJson(
        self: *Session,
        context: PrReviewContextSnapshot,
        overrides: ?std.json.ObjectMap,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewGitStatusRequestJson(self, context, overrides);
    }

    pub fn buildPrReviewGitDiffRangeRequestJson(
        self: *Session,
        context: PrReviewContextSnapshot,
        overrides: ?std.json.ObjectMap,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewGitDiffRangeRequestJson(self, context, overrides);
    }

    pub fn buildPrReviewGitHubPublishRequestJson(
        self: *Session,
        context: PrReviewContextSnapshot,
        recommendation_value: std.json.Value,
        review_comment: ?[]const u8,
        thread_actions_value: ?std.json.Value,
        overrides: ?std.json.ObjectMap,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewGitHubPublishRequestJson(
            self,
            context,
            recommendation_value,
            review_comment,
            thread_actions_value,
            overrides,
        );
    }

    pub fn buildPrReviewTerminalCreateRequestJson(self: *Session, checkout_path: []const u8) ![]u8 {
        return pr_review_venom.buildPrReviewTerminalCreateRequestJson(self, checkout_path);
    }

    pub fn buildPrReviewValidationExecRequestJson(
        self: *Session,
        command_value: std.json.Value,
        checkout_path: []const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewValidationExecRequestJson(self, command_value, checkout_path);
    }

    fn buildPrReviewServiceArtifactPayloadJson(
        self: *Session,
        service_path: []const u8,
        invoke_path: []const u8,
        request_payload_json: []const u8,
        result_payload_json: []const u8,
        status_payload_json: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewServiceArtifactPayloadJson(
            self,
            service_path,
            invoke_path,
            request_payload_json,
            result_payload_json,
            status_payload_json,
        );
    }

    pub fn invokePrReviewServiceCapture(
        self: *Session,
        store: *mission_store_mod.MissionStore,
        mission_id: []const u8,
        stage: []const u8,
        summary: []const u8,
        service_path: []const u8,
        invoke_path: []const u8,
        request_payload: []const u8,
        artifact_root: []const u8,
        artifact_relative_path: []const u8,
        artifact_kind: []const u8,
    ) !pr_review_venom.ServiceCapture {
        return pr_review_venom.invokePrReviewServiceCapture(
            self,
            store,
            mission_id,
            stage,
            summary,
            service_path,
            invoke_path,
            request_payload,
            artifact_root,
            artifact_relative_path,
            artifact_kind,
        );
    }

    pub fn applyPrReviewContextFromGitHubSyncPayload(
        self: *Session,
        context: *PrReviewContextSnapshot,
        state: *PrReviewStateSnapshot,
        payload_json: []const u8,
    ) !void {
        return pr_review_venom.applyPrReviewContextFromGitHubSyncPayload(self, context, state, payload_json);
    }

    pub fn extractTerminalExitCodeFromToolPayload(self: *Session, payload_json: []const u8) !?i32 {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const result_value = parsed.value.object.get("result") orelse return null;
        if (result_value != .object) return null;
        const exit_code_value = result_value.object.get("exit_code") orelse return null;
        return switch (exit_code_value) {
            .integer => @intCast(exit_code_value.integer),
            .float => |value| blk: {
                if (std.math.floor(value) != value) return error.InvalidPayload;
                break :blk @as(i32, @intFromFloat(value));
            },
            else => return error.InvalidPayload,
        };
    }

    pub fn applyPrReviewContextFromGitSyncPayload(
        self: *Session,
        context: *PrReviewContextSnapshot,
        state: *PrReviewStateSnapshot,
        payload_json: []const u8,
    ) !void {
        return pr_review_venom.applyPrReviewContextFromGitSyncPayload(self, context, state, payload_json);
    }

    pub fn applyPrReviewContextFromGitStatusPayload(
        self: *Session,
        context: *PrReviewContextSnapshot,
        state: *PrReviewStateSnapshot,
        payload_json: []const u8,
    ) !void {
        return pr_review_venom.applyPrReviewContextFromGitStatusPayload(self, context, state, payload_json);
    }

    pub fn applyPrReviewCommonStateFields(self: *Session, args_obj: std.json.ObjectMap, state: *PrReviewStateSnapshot) !void {
        return pr_review_venom.applyPrReviewCommonStateFields(self, args_obj, state);
    }

    fn resolvePrReviewArtifactPath(self: *Session, artifact_root: []const u8, artifact_relative_path: []const u8) ![]u8 {
        return pr_review_venom.resolvePrReviewArtifactPath(self, artifact_root, artifact_relative_path);
    }

    pub fn writePrReviewJsonArtifact(self: *Session, artifact_root: []const u8, artifact_relative_path: []const u8, value: std.json.Value) ![]u8 {
        return pr_review_venom.writePrReviewJsonArtifact(self, artifact_root, artifact_relative_path, value);
    }

    pub fn writePrReviewArtifactPayload(self: *Session, artifact_root: []const u8, artifact_relative_path: []const u8, payload_json: []const u8) ![]u8 {
        return pr_review_venom.writePrReviewArtifactPayload(self, artifact_root, artifact_relative_path, payload_json);
    }

    pub fn writePrReviewTextArtifact(self: *Session, artifact_root: []const u8, artifact_relative_path: []const u8, content: []const u8) ![]u8 {
        return pr_review_venom.writePrReviewTextArtifact(self, artifact_root, artifact_relative_path, content);
    }

    pub fn buildPrReviewContextPayloadJson(
        self: *Session,
        provider: []const u8,
        repo_key: []const u8,
        pr_number: u64,
        pr_url: []const u8,
        base_branch: []const u8,
        base_sha: []const u8,
        head_branch: []const u8,
        head_sha: []const u8,
        checkout_path: []const u8,
        review_policy_paths_json: []const u8,
        default_review_commands_json: []const u8,
        approval_policy_json: []const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewContextPayloadJson(
            self,
            provider,
            repo_key,
            pr_number,
            pr_url,
            base_branch,
            base_sha,
            head_branch,
            head_sha,
            checkout_path,
            review_policy_paths_json,
            default_review_commands_json,
            approval_policy_json,
        );
    }

    pub fn buildDefaultPrReviewStatePayloadJson(self: *Session, head_sha: []const u8) ![]u8 {
        return pr_review_venom.buildDefaultPrReviewStatePayloadJson(self, head_sha);
    }

    pub fn buildPrReviewStatePayloadJson(self: *Session, state: PrReviewStateSnapshot) ![]u8 {
        return pr_review_venom.buildPrReviewStatePayloadJson(self, state);
    }

    pub fn buildPrReviewStartDetailJson(
        self: *Session,
        mission_json: []const u8,
        provider: []const u8,
        repo_key: []const u8,
        pr_number: u64,
        pr_url: []const u8,
        checkout_path: []const u8,
        context_path: []const u8,
        state_path: []const u8,
        artifact_root: []const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewStartDetailJson(
            self,
            mission_json,
            provider,
            repo_key,
            pr_number,
            pr_url,
            checkout_path,
            context_path,
            state_path,
            artifact_root,
        );
    }

    pub fn buildPrReviewIntakeDetailJson(
        self: *Session,
        mission_json: []const u8,
        provider: []const u8,
        repo_key: []const u8,
        pr_number: u64,
        pr_url: []const u8,
        checkout_path: []const u8,
        context_path: []const u8,
        state_path: []const u8,
        artifact_root: []const u8,
        provider_sync_path: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewIntakeDetailJson(
            self,
            mission_json,
            provider,
            repo_key,
            pr_number,
            pr_url,
            checkout_path,
            context_path,
            state_path,
            artifact_root,
            provider_sync_path,
        );
    }

    pub fn buildPrReviewSyncDetailJson(
        self: *Session,
        mission_json: []const u8,
        phase: []const u8,
        state_path: []const u8,
        thread_actions_path: ?[]const u8,
        provider_sync_path: ?[]const u8,
        checkout_sync_path: ?[]const u8,
        repo_status_path: ?[]const u8,
        diff_range_path: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewSyncDetailJson(
            self,
            mission_json,
            phase,
            state_path,
            thread_actions_path,
            provider_sync_path,
            checkout_sync_path,
            repo_status_path,
            diff_range_path,
        );
    }

    pub fn buildPrReviewValidationDetailJson(
        self: *Session,
        mission_json: []const u8,
        phase: []const u8,
        state_path: []const u8,
        validation_path: []const u8,
        session_create_path: ?[]const u8,
        command_paths_json: []const u8,
        session_close_path: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewValidationDetailJson(
            self,
            mission_json,
            phase,
            state_path,
            validation_path,
            session_create_path,
            command_paths_json,
            session_close_path,
        );
    }

    pub fn buildPrReviewReviewDetailJson(
        self: *Session,
        mission_json: []const u8,
        phase: []const u8,
        state_path: []const u8,
        findings_path: []const u8,
        recommendation_path: []const u8,
        review_comment_path: ?[]const u8,
        thread_actions_path: ?[]const u8,
        publish_review_path: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewReviewDetailJson(
            self,
            mission_json,
            phase,
            state_path,
            findings_path,
            recommendation_path,
            review_comment_path,
            thread_actions_path,
            publish_review_path,
        );
    }

    pub fn buildPrReviewSuccessResultJson(self: *Session, op: PrReviewOp, result_json: []const u8) ![]u8 {
        return pr_review_venom.buildPrReviewSuccessResultJson(self, op, result_json);
    }

    pub fn buildPrReviewPartialFailureResultJson(
        self: *Session,
        op: PrReviewOp,
        result_json: []const u8,
        code: []const u8,
        message: []const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewPartialFailureResultJson(self, op, result_json, code, message);
    }

    pub fn buildPrReviewFailureResultJson(self: *Session, op: PrReviewOp, code: []const u8, message: []const u8) ![]u8 {
        return pr_review_venom.buildPrReviewFailureResultJson(self, op, code, message);
    }

    pub fn buildPrReviewValidationReportJson(
        self: *Session,
        status: []const u8,
        summary: []const u8,
        session_create_path: ?[]const u8,
        commands_json: []const u8,
        session_close_path: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewValidationReportJson(
            self,
            status,
            summary,
            session_create_path,
            commands_json,
            session_close_path,
        );
    }

    pub fn buildPrReviewValidationCommandEntryJson(
        self: *Session,
        index: usize,
        request_payload_json: []const u8,
        capture_path: []const u8,
        result_payload_json: []const u8,
        exit_code: ?i32,
        error_code: ?[]const u8,
        error_message: ?[]const u8,
    ) ![]u8 {
        return pr_review_venom.buildPrReviewValidationCommandEntryJson(
            self,
            index,
            request_payload_json,
            capture_path,
            result_payload_json,
            exit_code,
            error_code,
            error_message,
        );
    }

    fn seedAgentMissionsNamespace(self: *Session, missions_dir: u32) !void {
        return missions_venom.seedNamespace(self, missions_dir);
    }

    fn seedAgentMissionsNamespaceAt(self: *Session, missions_dir: u32, base_path: []const u8) !void {
        return missions_venom.seedNamespaceAt(self, missions_dir, base_path);
    }

    pub const MissionOp = missions_venom.Op;

    fn handleMissionsNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try missions_venom.handleNamespaceWrite(self, special, node_id, raw_input) };
    }

    const ResolvedMissionBootstrapContract = missions_venom.ResolvedBootstrapContract;

    pub fn parseMissionContractInput(self: *Session, args_obj: std.json.ObjectMap) !?mission_store_mod.MissionContractInput {
        return missions_venom.parseMissionContractInput(self, args_obj);
    }

    pub fn parseMissionContractUpdateInput(self: *Session, args_obj: std.json.ObjectMap) !?mission_store_mod.MissionContractUpdateInput {
        return missions_venom.parseMissionContractUpdateInput(self, args_obj);
    }

    pub fn resolveMissionBootstrapContract(
        self: *Session,
        mission: mission_store_mod.MissionRecord,
        args_obj: std.json.ObjectMap,
    ) !ResolvedMissionBootstrapContract {
        return missions_venom.resolveMissionBootstrapContract(self, mission, args_obj);
    }

    pub fn resolveMissionContractHostPath(self: *Session, absolute_path: []const u8) ![]u8 {
        return missions_venom.resolveContractHostPath(self, absolute_path);
    }

    pub fn ensureMissionContractDirectory(self: *Session, absolute_path: []const u8) !void {
        return missions_venom.ensureContractDirectory(self, absolute_path);
    }

    pub fn writeMissionContractFile(self: *Session, absolute_path: []const u8, content: []const u8) !void {
        return missions_venom.writeContractFile(self, absolute_path, content);
    }

    pub fn normalizeMissionAbsolutePath(self: *Session, raw: []const u8) ![]u8 {
        return missions_venom.normalizeMissionAbsolutePath(self, raw);
    }

    pub fn deriveMissionServiceInvokePath(self: *Session, service_path: []const u8) ![]u8 {
        return missions_venom.deriveMissionServiceInvokePath(self, service_path);
    }

    pub fn buildMissionServiceInvokeRequestPayload(self: *Session, args_obj: std.json.ObjectMap) ![]u8 {
        return missions_venom.buildMissionServiceInvokeRequestPayload(self, args_obj);
    }

    pub fn buildMissionServiceInvocationDetailJson(
        self: *Session,
        mission_json: []const u8,
        service_path: []const u8,
        invoke_path: []const u8,
        request_payload_json: []const u8,
        result_payload_json: []const u8,
        status_payload_json: ?[]const u8,
    ) ![]u8 {
        return missions_venom.buildMissionServiceInvocationDetailJson(
            self,
            mission_json,
            service_path,
            invoke_path,
            request_payload_json,
            result_payload_json,
            status_payload_json,
        );
    }

    pub fn buildMissionBootstrapContractDetailJson(
        self: *Session,
        mission_json: []const u8,
        context_path: []const u8,
        state_path: []const u8,
        artifact_root: []const u8,
    ) ![]u8 {
        return missions_venom.buildMissionBootstrapContractDetailJson(self, mission_json, context_path, state_path, artifact_root);
    }

    pub fn buildMissionSuccessResultJson(self: *Session, op: MissionOp, result_json: []const u8) ![]u8 {
        return missions_venom.buildMissionSuccessResultJson(self, op, result_json);
    }

    pub fn buildMissionPartialFailureResultJson(
        self: *Session,
        op: MissionOp,
        result_json: []const u8,
        code: []const u8,
        message: []const u8,
    ) ![]u8 {
        return missions_venom.buildMissionPartialFailureResultJson(self, op, result_json, code, message);
    }

    pub fn buildMissionListJson(self: *Session, missions: []const mission_store_mod.MissionRecord) ![]u8 {
        return missions_venom.buildMissionListJson(self, missions);
    }

    pub fn buildMissionRecordJson(self: *Session, mission: mission_store_mod.MissionRecord) ![]u8 {
        return missions_venom.buildMissionRecordJson(self, mission);
    }

    pub fn buildMissionContractJson(self: *Session, contract: mission_store_mod.MissionContract) ![]u8 {
        return missions_venom.buildMissionContractJson(self, contract);
    }

    pub fn buildMissionArtifactJson(self: *Session, artifact: mission_store_mod.MissionArtifact) ![]u8 {
        return missions_venom.buildMissionArtifactJson(self, artifact);
    }

    pub fn buildMissionEventJson(self: *Session, event: mission_store_mod.MissionEvent) ![]u8 {
        return missions_venom.buildMissionEventJson(self, event);
    }

    pub fn buildMissionApprovalJson(self: *Session, approval: mission_store_mod.MissionApproval) ![]u8 {
        return missions_venom.buildMissionApprovalJson(self, approval);
    }

    pub fn renderJsonValue(self: *Session, value: std.json.Value) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})});
    }

    fn nextInternalFsrpcIds(self: *Session) InternalFsrpcIds {
        const seq = self.next_internal_fsrpc_seq;
        self.next_internal_fsrpc_seq +%= 1;
        if (self.next_internal_fsrpc_seq == 0) self.next_internal_fsrpc_seq = 1;
        return .{
            .attach_fid = 0x7000_0000 +% (seq *% 2),
            .walk_fid = 0x7000_0001 +% (seq *% 2),
            .tag_base = 0x7100_0000 +% (seq *% 8),
        };
    }

    fn allocAbsolutePathSegments(self: *Session, absolute_path: []const u8) anyerror![][]u8 {
        if (absolute_path.len == 0 or absolute_path[0] != '/') return error.InvalidPayload;
        var count: usize = 0;
        var iter = std.mem.splitScalar(u8, absolute_path, '/');
        while (iter.next()) |segment| {
            if (segment.len == 0) continue;
            count += 1;
        }

        var segments = try self.allocator.alloc([]u8, count);
        errdefer self.allocator.free(segments);

        var index: usize = 0;
        errdefer {
            var cleanup_index: usize = 0;
            while (cleanup_index < index) : (cleanup_index += 1) self.allocator.free(segments[cleanup_index]);
        }

        iter = std.mem.splitScalar(u8, absolute_path, '/');
        while (iter.next()) |segment| {
            if (segment.len == 0) continue;
            segments[index] = try self.allocator.dupe(u8, segment);
            index += 1;
        }
        return segments;
    }

    fn internalClunk(self: *Session, fid: u32, tag: u32) void {
        var clunk = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_clunk,
            .tag = tag,
            .fid = fid,
        };
        const frame = self.handle(&clunk) catch return;
        self.allocator.free(frame);
    }

    fn parseInternalFsrpcError(self: *Session, frame: []const u8) anyerror!?InternalFsrpcErrorInfo {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, frame, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const ok_value = parsed.value.object.get("ok") orelse return error.InvalidPayload;
        if (ok_value == .bool and ok_value.bool) return null;

        const error_value = parsed.value.object.get("error") orelse return error.InvalidPayload;
        if (error_value != .object) return error.InvalidPayload;
        const code = if (error_value.object.get("code")) |value|
            if (value == .string and value.string.len > 0) value.string else "internal_error"
        else
            "internal_error";
        const message = if (error_value.object.get("message")) |value|
            if (value == .string and value.string.len > 0) value.string else "internal fsrpc request failed"
        else
            "internal fsrpc request failed";
        return .{
            .code = try self.allocator.dupe(u8, code),
            .message = try self.allocator.dupe(u8, message),
        };
    }

    pub fn writeInternalPath(self: *Session, absolute_path: []const u8, data: []const u8) anyerror!?InternalFsrpcErrorInfo {
        const ids = self.nextInternalFsrpcIds();
        const segments = try self.allocAbsolutePathSegments(absolute_path);
        defer freePathSegments(self.allocator, segments);
        defer self.internalClunk(ids.walk_fid, ids.tag_base + 4);
        defer self.internalClunk(ids.attach_fid, ids.tag_base + 5);

        var attach = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_attach,
            .tag = ids.tag_base,
            .fid = ids.attach_fid,
        };
        const attach_frame = try self.handle(&attach);
        defer self.allocator.free(attach_frame);
        if (try self.parseInternalFsrpcError(attach_frame)) |err| return err;

        var walk = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_walk,
            .tag = ids.tag_base + 1,
            .fid = ids.attach_fid,
            .newfid = ids.walk_fid,
            .path = segments,
        };
        const walk_frame = try self.handle(&walk);
        defer self.allocator.free(walk_frame);
        if (try self.parseInternalFsrpcError(walk_frame)) |err| return err;

        var open = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_open,
            .tag = ids.tag_base + 2,
            .fid = ids.walk_fid,
            .mode = @constCast("w"),
        };
        const open_frame = try self.handle(&open);
        defer self.allocator.free(open_frame);
        if (try self.parseInternalFsrpcError(open_frame)) |err| return err;

        var write = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_write,
            .tag = ids.tag_base + 3,
            .fid = ids.walk_fid,
            .offset = 0,
            .data = @constCast(data),
        };
        const write_frame = try self.handle(&write);
        defer self.allocator.free(write_frame);
        if (try self.parseInternalFsrpcError(write_frame)) |err| return err;
        return null;
    }

    pub fn tryReadInternalPath(self: *Session, absolute_path: []const u8) anyerror!?[]u8 {
        const ids = self.nextInternalFsrpcIds();
        const segments = try self.allocAbsolutePathSegments(absolute_path);
        defer freePathSegments(self.allocator, segments);
        defer self.internalClunk(ids.walk_fid, ids.tag_base + 4);
        defer self.internalClunk(ids.attach_fid, ids.tag_base + 5);

        var attach = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_attach,
            .tag = ids.tag_base,
            .fid = ids.attach_fid,
        };
        const attach_frame = try self.handle(&attach);
        defer self.allocator.free(attach_frame);
        if (try self.parseInternalFsrpcError(attach_frame)) |err| {
            var owned_err = err;
            owned_err.deinit(self.allocator);
            return null;
        }

        var walk = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_walk,
            .tag = ids.tag_base + 1,
            .fid = ids.attach_fid,
            .newfid = ids.walk_fid,
            .path = segments,
        };
        const walk_frame = try self.handle(&walk);
        defer self.allocator.free(walk_frame);
        if (try self.parseInternalFsrpcError(walk_frame)) |err| {
            var owned_err = err;
            owned_err.deinit(self.allocator);
            return null;
        }

        var open = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_open,
            .tag = ids.tag_base + 2,
            .fid = ids.walk_fid,
            .mode = @constCast("r"),
        };
        const open_frame = try self.handle(&open);
        defer self.allocator.free(open_frame);
        if (try self.parseInternalFsrpcError(open_frame)) |err| {
            var owned_err = err;
            owned_err.deinit(self.allocator);
            return null;
        }

        var read = unified.ParsedMessage{
            .channel = .acheron,
            .acheron_type = .t_read,
            .tag = ids.tag_base + 3,
            .fid = ids.walk_fid,
            .offset = 0,
            .count = 1_048_576,
        };
        const read_frame = try self.handle(&read);
        defer self.allocator.free(read_frame);
        if (try self.parseInternalFsrpcError(read_frame)) |err| {
            var owned_err = err;
            owned_err.deinit(self.allocator);
            return null;
        }
        return try self.decodeAcheronReadPayload(read_frame);
    }

    fn decodeAcheronReadPayload(self: *Session, frame: []const u8) anyerror![]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, frame, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;

        const payload = parsed.value.object.get("payload") orelse return error.InvalidPayload;
        if (payload != .object) return error.InvalidPayload;
        const data_b64 = payload.object.get("data_b64") orelse return error.InvalidPayload;
        if (data_b64 != .string) return error.InvalidPayload;

        const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_b64.string);
        const decoded = try self.allocator.alloc(u8, decoded_len);
        errdefer self.allocator.free(decoded);
        try std.base64.standard.Decoder.decode(decoded, data_b64.string);
        return decoded;
    }

    fn executeDirectBuiltinToolCall(self: *Session, tool_name: []const u8, args_json: []const u8) !?[]u8 {
        if (!std.mem.eql(u8, tool_name, "shell_exec")) return null;

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, args_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;

        const source_args = parsed.value.object;
        const command = if (source_args.get("command")) |value|
            if (value == .string) value.string else return error.InvalidPayload
        else
            return error.InvalidPayload;
        const timeout_ms = if (source_args.get("timeout_ms")) |value| switch (value) {
            .integer => |raw| blk: {
                if (raw < 0) return error.InvalidPayload;
                break :blk @as(u64, @intCast(raw));
            },
            .float => |raw| blk: {
                if (raw < 0 or std.math.floor(raw) != raw) return error.InvalidPayload;
                break :blk @as(u64, @intFromFloat(raw));
            },
            .null => null,
            else => return error.InvalidPayload,
        } else null;
        const cwd = if (source_args.get("cwd")) |value|
            if (value == .string) value.string else if (value == .null) null else return error.InvalidPayload
        else
            null;

        const resolved_cwd = if (cwd) |value|
            if (std.mem.startsWith(u8, value, local_fs_world_prefix))
                try self.resolveMissionContractHostPath(value)
            else
                try self.allocator.dupe(u8, value)
        else
            null;
        defer if (resolved_cwd) |value| self.allocator.free(value);

        const escaped_command = try unified.jsonEscape(self.allocator, command);
        defer self.allocator.free(escaped_command);
        const cwd_fragment = if (resolved_cwd) |value| blk: {
            const escaped_cwd = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped_cwd);
            break :blk try std.fmt.allocPrint(self.allocator, ",\"cwd\":\"{s}\"", .{escaped_cwd});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(cwd_fragment);
        const timeout_fragment = if (timeout_ms) |value|
            try std.fmt.allocPrint(self.allocator, ",\"timeout_ms\":{d}", .{value})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(timeout_fragment);

        const direct_args_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"command\":\"{s}\"{s}{s}}}",
            .{ escaped_command, timeout_fragment, cwd_fragment },
        );
        defer self.allocator.free(direct_args_json);

        var direct_parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, direct_args_json, .{});
        defer direct_parsed.deinit();
        if (direct_parsed.value != .object) return error.InvalidPayload;

        var result = tool_executor_mod.BuiltinTools.shellExec(self.allocator, direct_parsed.value.object);
        defer result.deinit(self.allocator);
        return switch (result) {
            .success => |success| try self.allocator.dupe(u8, success.payload_json),
            .failure => |failure| try self.buildServiceInvokeFailureResultJson(@tagName(failure.code), failure.message),
        };
    }

    pub fn executeServiceToolCall(self: *Session, tool_name: []const u8, args_json: []const u8) ![]u8 {
        if (try self.executeDirectBuiltinToolCall(tool_name, args_json)) |payload| {
            return payload;
        }

        const escaped_tool_name = try unified.jsonEscape(self.allocator, tool_name);
        defer self.allocator.free(escaped_tool_name);
        const control_payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"tool_name\":\"{s}\",\"arguments\":{s}}}",
            .{ escaped_tool_name, args_json },
        );
        defer self.allocator.free(control_payload);
        const escaped_control_payload = try unified.jsonEscape(self.allocator, control_payload);
        defer self.allocator.free(escaped_control_payload);
        const request_id = try std.fmt.allocPrint(
            self.allocator,
            "service-invoke-{s}-{d}",
            .{ escaped_tool_name, std.time.milliTimestamp() },
        );
        defer self.allocator.free(request_id);
        const escaped_request_id = try unified.jsonEscape(self.allocator, request_id);
        defer self.allocator.free(escaped_request_id);
        const runtime_req = try std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":\"{s}\",\"type\":\"agent.control\",\"action\":\"tool.call\",\"content\":\"{s}\"}}",
            .{ escaped_request_id, escaped_control_payload },
        );
        defer self.allocator.free(runtime_req);

        var responses: ?[][]u8 = null;
        if (self.runtime_handle.handleMessageFramesWithDebug(runtime_req, self.shouldEmitRuntimeDebugFrames())) |frames| {
            responses = frames;
        } else |err| {
            const normalized = shared_exec.normalizeRuntimeFailureForAgent("runtime_error", @errorName(err));
            return self.buildServiceInvokeFailureResultJson(normalized.code, normalized.message);
        }
        defer if (responses) |frames| deinitResponseFrames(self.allocator, frames);

        var content_payload: ?[]u8 = null;
        defer if (content_payload) |value| self.allocator.free(value);

        if (responses) |frames| {
            for (frames) |frame| {
                try self.recordRuntimeFrameForDebug(request_id, frame);

                var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, frame, .{}) catch continue;
                defer parsed.deinit();
                if (parsed.value != .object) continue;
                const obj = parsed.value.object;
                const type_value = obj.get("type") orelse continue;
                if (type_value != .string) continue;

                if (std.mem.eql(u8, type_value.string, "session.receive")) {
                    if (obj.get("content")) |content| {
                        if (content == .string) {
                            if (content_payload) |old| self.allocator.free(old);
                            content_payload = try self.allocator.dupe(u8, content.string);
                        }
                    }
                } else if (std.mem.eql(u8, type_value.string, "error")) {
                    const code = if (obj.get("code")) |value|
                        if (value == .string) value.string else "runtime_error"
                    else
                        "runtime_error";
                    const message = if (obj.get("message")) |value|
                        if (value == .string) value.string else "runtime tool call failed"
                    else
                        "runtime tool call failed";
                    const normalized = shared_exec.normalizeRuntimeFailureForAgent(code, message);
                    return self.buildServiceInvokeFailureResultJson(normalized.code, normalized.message);
                }
            }
        }

        if (content_payload) |payload| {
            if (shared_exec.isInternalRuntimeLoopGuardText(payload)) {
                const normalized = shared_exec.normalizeRuntimeFailureForAgent("execution_failed", payload);
                return self.buildServiceInvokeFailureResultJson(normalized.code, normalized.message);
            }
            var payload_parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch {
                return self.buildServiceInvokeFailureResultJson("invalid_result_payload", "tool payload was not valid JSON");
            };
            payload_parsed.deinit();
            return self.allocator.dupe(u8, payload);
        }
        return self.buildServiceInvokeFailureResultJson("missing_result", "tool call produced no session.receive payload");
    }

    pub fn executeAgentRun(self: *Session, goal: []const u8, resume_run_id: ?[]const u8) !AgentRunOutcome {
        const trimmed_goal = std.mem.trim(u8, goal, " \t\r\n");
        if (trimmed_goal.len == 0) {
            return .{ .failure = .{
                .code = try self.allocator.dupe(u8, "invalid_goal"),
                .message = try self.allocator.dupe(u8, "agent run goal must not be empty"),
            } };
        }

        const request_id = try std.fmt.allocPrint(self.allocator, "agent-run-{d}", .{std.time.milliTimestamp()});
        defer self.allocator.free(request_id);
        const escaped_request_id = try unified.jsonEscape(self.allocator, request_id);
        defer self.allocator.free(escaped_request_id);
        const escaped_goal = try unified.jsonEscape(self.allocator, trimmed_goal);
        defer self.allocator.free(escaped_goal);

        const runtime_req = if (resume_run_id) |run_id| blk: {
            const escaped_run_id = try unified.jsonEscape(self.allocator, run_id);
            defer self.allocator.free(escaped_run_id);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"id\":\"{s}\",\"type\":\"agent.run.resume\",\"action\":\"{s}\",\"content\":\"{s}\"}}",
                .{ escaped_request_id, escaped_run_id, escaped_goal },
            );
        } else try std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":\"{s}\",\"type\":\"agent.run.start\",\"content\":\"{s}\"}}",
            .{ escaped_request_id, escaped_goal },
        );
        defer self.allocator.free(runtime_req);

        const frames = self.runtime_handle.handleMessageFramesWithDebug(runtime_req, self.shouldEmitRuntimeDebugFrames()) catch |err| {
            const normalized = shared_exec.normalizeRuntimeFailureForAgent("runtime_error", @errorName(err));
            return .{ .failure = .{
                .code = try self.allocator.dupe(u8, normalized.code),
                .message = try self.allocator.dupe(u8, normalized.message),
            } };
        };
        defer deinitResponseFrames(self.allocator, frames);

        var run_id: ?[]u8 = null;
        defer if (run_id) |value| self.allocator.free(value);
        var state: ?[]u8 = null;
        defer if (state) |value| self.allocator.free(value);
        var assistant_output: ?[]u8 = null;
        defer if (assistant_output) |value| self.allocator.free(value);
        var step_count: u64 = 0;
        var checkpoint_seq: u64 = 0;

        for (frames) |frame| {
            try self.recordRuntimeFrameForDebug(request_id, frame);

            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, frame, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;
            const obj = parsed.value.object;
            const type_value = obj.get("type") orelse continue;
            if (type_value != .string) continue;

            if (std.mem.eql(u8, type_value.string, "error")) {
                const code = if (obj.get("code")) |value|
                    if (value == .string and value.string.len > 0) value.string else "runtime_error"
                else
                    "runtime_error";
                const message = if (obj.get("message")) |value|
                    if (value == .string and value.string.len > 0) value.string else "runtime agent run failed"
                else
                    "runtime agent run failed";
                const normalized = shared_exec.normalizeRuntimeFailureForAgent(code, message);
                return .{ .failure = .{
                    .code = try self.allocator.dupe(u8, normalized.code),
                    .message = try self.allocator.dupe(u8, normalized.message),
                } };
            }

            if (std.mem.eql(u8, type_value.string, "agent.run.ack") or std.mem.eql(u8, type_value.string, "agent.run.state")) {
                if (obj.get("run_id")) |value| {
                    if (value == .string and value.string.len > 0) {
                        if (run_id) |old| self.allocator.free(old);
                        run_id = try self.allocator.dupe(u8, value.string);
                    }
                }
                if (obj.get("state")) |value| {
                    if (value == .string and value.string.len > 0) {
                        if (state) |old| self.allocator.free(old);
                        state = try self.allocator.dupe(u8, value.string);
                    }
                }
                if (obj.get("step_count")) |value| {
                    if (value == .integer and value.integer >= 0) step_count = @intCast(value.integer);
                }
                if (obj.get("checkpoint_seq")) |value| {
                    if (value == .integer and value.integer >= 0) checkpoint_seq = @intCast(value.integer);
                }
                continue;
            }

            if (std.mem.eql(u8, type_value.string, "agent.run.event")) {
                const event_type = if (obj.get("event_type")) |value|
                    if (value == .string) value.string else ""
                else
                    "";
                if (!std.mem.eql(u8, event_type, "assistant.output")) continue;
                const payload = obj.get("payload") orelse continue;
                if (payload != .object) continue;
                const assistant = payload.object.get("assistant") orelse continue;
                if (assistant != .string) continue;
                if (assistant_output) |old| self.allocator.free(old);
                assistant_output = try self.allocator.dupe(u8, assistant.string);
            }
        }

        const owned_run_id = if (run_id) |value|
            try self.allocator.dupe(u8, value)
        else
            return .{ .failure = .{
                .code = try self.allocator.dupe(u8, "missing_run_id"),
                .message = try self.allocator.dupe(u8, "runtime agent run produced no run_id"),
            } };
        errdefer self.allocator.free(owned_run_id);
        const owned_state = if (state) |value|
            try self.allocator.dupe(u8, value)
        else
            return .{ .failure = .{
                .code = try self.allocator.dupe(u8, "missing_run_state"),
                .message = try self.allocator.dupe(u8, "runtime agent run produced no state"),
            } };
        errdefer self.allocator.free(owned_state);
        const owned_assistant_output = if (assistant_output) |value|
            try self.allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_assistant_output) |value| self.allocator.free(value);

        return .{ .success = .{
            .run_id = owned_run_id,
            .state = owned_state,
            .assistant_output = owned_assistant_output,
            .step_count = step_count,
            .checkpoint_seq = checkpoint_seq,
        } };
    }

    pub fn buildServiceInvokeStatusJson(
        self: *Session,
        state: []const u8,
        tool_name: ?[]const u8,
        error_message: ?[]const u8,
    ) ![]u8 {
        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const tool_json = if (tool_name) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(tool_json);
        const error_json = if (error_message) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(error_json);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"state\":\"{s}\",\"tool\":{s},\"updated_at_ms\":{d},\"error\":{s}}}",
            .{ escaped_state, tool_json, std.time.milliTimestamp(), error_json },
        );
    }

    pub fn buildServiceInvokeFailureResultJson(self: *Session, code: []const u8, message: []const u8) ![]u8 {
        const escaped_code = try unified.jsonEscape(self.allocator, code);
        defer self.allocator.free(escaped_code);
        const escaped_message = try unified.jsonEscape(self.allocator, message);
        defer self.allocator.free(escaped_message);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":false,\"result\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ escaped_code, escaped_message },
        );
    }

    pub fn extractErrorInfoFromToolPayload(self: *Session, payload_json: []const u8) !?ToolPayloadErrorInfo {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const error_value = parsed.value.object.get("error") orelse return null;
        if (error_value == .null) return null;
        if (error_value == .string) {
            return .{
                .code = try self.allocator.dupe(u8, "service_error"),
                .message = try self.allocator.dupe(u8, error_value.string),
            };
        }
        if (error_value != .object) return null;
        const code = if (error_value.object.get("code")) |code_value|
            if (code_value == .string and code_value.string.len > 0) code_value.string else "service_error"
        else
            "service_error";
        const message = if (error_value.object.get("message")) |message_value|
            if (message_value == .string and message_value.string.len > 0) message_value.string else "tool returned error"
        else
            "tool returned error";
        return .{
            .code = try self.allocator.dupe(u8, code),
            .message = try self.allocator.dupe(u8, message),
        };
    }

    pub fn extractErrorMessageFromToolPayload(self: *Session, payload_json: []const u8) !?[]u8 {
        if (try self.extractErrorInfoFromToolPayload(payload_json)) |info| {
            defer self.allocator.free(info.code);
            return info.message;
        }
        return null;
    }

    fn clearWaitSources(self: *Session) void {
        return events_venom.clearWaitSources(self);
    }

    fn clearSignalEvents(self: *Session) void {
        return events_venom.clearSignalEvents(self);
    }

    fn clearProjectBinds(self: *Session) void {
        for (self.project_binds.items) |*bind| bind.deinit(self.allocator);
        self.project_binds.deinit(self.allocator);
        self.project_binds = .{};
    }

    fn clearScopedVenomBindings(self: *Session) void {
        for (self.scoped_venom_bindings.items) |*binding| binding.deinit(self.allocator);
        self.scoped_venom_bindings.deinit(self.allocator);
        self.scoped_venom_bindings = .{};
    }

    fn clearThoughtJobSyncCounts(self: *Session) void {
        var it = self.thought_job_sync_counts.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.thought_job_sync_counts.deinit(self.allocator);
        self.thought_job_sync_counts = .{};
    }

    fn handleEventWaitConfigWrite(self: *Session, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try events_venom.handleWaitConfigWrite(self, node_id, raw_input) };
    }

    fn handleEventSignalWrite(self: *Session, node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try events_venom.handleSignalWrite(self, node_id, raw_input) };
    }

    fn handleEventNextRead(self: *Session) ![]u8 {
        return events_venom.handleNextRead(self);
    }

    fn refreshJobNodeFromIndex(self: *Session, node_id: u32, special: SpecialKind) !void {
        return jobs_venom.refreshNodeFromIndex(self, node_id, special);
    }

    pub fn syncThoughtFramesFromJobTelemetry(self: *Session, job_id: []const u8) !void {
        const thought_frames = try self.job_index.listThoughtFramesForJob(self.allocator, job_id);
        defer chat_job_index.deinitThoughtFrames(self.allocator, thought_frames);
        if (thought_frames.len == 0) return;

        const offset_ptr = blk: {
            const gop = try self.thought_job_sync_counts.getOrPut(self.allocator, job_id);
            if (!gop.found_existing) {
                gop.key_ptr.* = try self.allocator.dupe(u8, job_id);
                gop.value_ptr.* = 0;
            }
            break :blk gop.value_ptr;
        };

        var cursor = offset_ptr.*;
        if (cursor > thought_frames.len) cursor = 0;

        while (cursor < thought_frames.len) : (cursor += 1) {
            const frame = thought_frames[cursor];
            try self.recordThoughtFrame(frame.content, frame.source, frame.round);
        }

        offset_ptr.* = thought_frames.len;
    }

    fn refreshScopedVenomIndexes(self: *Session) !void {
        try self.refreshVenomsIndexFile(self.agent_venoms_index_id, "/global/", "global");

        if (self.active_agent_venoms_index_id != 0) {
            const prefix = try std.fmt.allocPrint(self.allocator, "/agents/{s}/venoms/", .{self.agent_id});
            defer self.allocator.free(prefix);
            try self.refreshVenomsIndexFile(self.active_agent_venoms_index_id, prefix, self.agent_id);
        }

        if (self.active_project_venoms_index_id != 0 and self.active_namespace_project_id != null) {
            const prefix = try std.fmt.allocPrint(self.allocator, "/projects/{s}/venoms/", .{self.active_namespace_project_id.?});
            defer self.allocator.free(prefix);
            try self.refreshVenomsIndexFile(self.active_project_venoms_index_id, prefix, self.active_namespace_project_id.?);
        }
    }

    fn refreshVenomsIndexFile(self: *Session, node_id: u32, binding_prefix: []const u8, binding_owner_id: []const u8) !void {
        const index_json = try self.buildScopedVenomsIndexJson(binding_prefix, binding_owner_id);
        defer self.allocator.free(index_json);
        try self.setFileContent(node_id, index_json);
    }

    fn buildScopedVenomsIndexJson(self: *Session, binding_prefix: []const u8, binding_owner_id: []const u8) ![]u8 {
        // Keep node discovery fresh so newly joined nodes are visible in service index reads.
        self.refreshDynamicDirectory(self.nodes_root_id) catch {};

        const nodes_root = self.nodes.get(self.nodes_root_id) orelse return self.allocator.dupe(u8, "[]");
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.append(self.allocator, '[');

        var first = true;
        var node_it = nodes_root.children.iterator();
        while (node_it.next()) |node_entry| {
            const node_id = node_entry.key_ptr.*;
            const node_dir_id = node_entry.value_ptr.*;
            const node_dir = self.nodes.get(node_dir_id) orelse continue;
            if (node_dir.kind != .dir) continue;

            const services_root_id = self.lookupChild(node_dir_id, "venoms") orelse continue;
            const services_root = self.nodes.get(services_root_id) orelse continue;
            if (services_root.kind != .dir) continue;

            var venom_it = services_root.children.iterator();
            while (venom_it.next()) |venom_entry| {
                const venom_id = venom_entry.key_ptr.*;
                const venom_dir_id = venom_entry.value_ptr.*;
                const venom_dir = self.nodes.get(venom_dir_id) orelse continue;
                if (venom_dir.kind != .dir) continue;

                const venom_path = try std.fmt.allocPrint(
                    self.allocator,
                    "/nodes/{s}/venoms/{s}",
                    .{ node_id, venom_id },
                );
                defer self.allocator.free(venom_path);
                const endpoint_path = blk: {
                    if (try self.firstVenomMountPath(venom_dir_id)) |value| break :blk value;
                    break :blk try self.venomEndpointPath(venom_dir_id);
                };
                defer if (endpoint_path) |value| self.allocator.free(value);
                const invoke_path = try self.deriveVenomInvokePath(node_id, venom_id, venom_dir_id);
                defer if (invoke_path) |value| self.allocator.free(value);

                try self.appendAgentVenomIndexEntry(
                    &out,
                    &first,
                    node_id,
                    venom_id,
                    venom_path,
                    endpoint_path,
                    invoke_path,
                    "node",
                    null,
                    null,
                );
            }
        }

        try self.appendScopedVenomBindingIndexEntriesForPrefix(&out, &first, binding_prefix, binding_owner_id);
        try out.append(self.allocator, ']');
        return out.toOwnedSlice(self.allocator);
    }

    fn appendAgentVenomIndexEntry(
        self: *Session,
        out: *std.ArrayListUnmanaged(u8),
        first: *bool,
        node_id: []const u8,
        venom_id: []const u8,
        venom_path: []const u8,
        endpoint_path: ?[]const u8,
        invoke_path: ?[]const u8,
        scope: []const u8,
        provider_node_id: ?[]const u8,
        provider_venom_path: ?[]const u8,
    ) !void {
        const escaped_node_id = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node_id);
        const escaped_venom_id = try unified.jsonEscape(self.allocator, venom_id);
        defer self.allocator.free(escaped_venom_id);
        const escaped_venom_path = try unified.jsonEscape(self.allocator, venom_path);
        defer self.allocator.free(escaped_venom_path);
        const escaped_scope = try unified.jsonEscape(self.allocator, scope);
        defer self.allocator.free(escaped_scope);

        const endpoint_json = if (endpoint_path) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(endpoint_json);

        const invoke_json = if (invoke_path) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(invoke_json);

        const provider_node_json = if (provider_node_id) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(provider_node_json);

        const provider_path_json = if (provider_venom_path) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(provider_path_json);

        if (!first.*) try out.append(self.allocator, ',');
        first.* = false;
        try out.writer(self.allocator).print(
            "{{\"node_id\":\"{s}\",\"venom_id\":\"{s}\",\"venom_path\":\"{s}\",\"endpoint_path\":{s},\"invoke_path\":{s},\"has_invoke\":{s},\"scope\":\"{s}\",\"provider_node_id\":{s},\"provider_venom_path\":{s}}}",
            .{
                escaped_node_id,
                escaped_venom_id,
                escaped_venom_path,
                endpoint_json,
                invoke_json,
                if (invoke_path != null) "true" else "false",
                escaped_scope,
                provider_node_json,
                provider_path_json,
            },
        );
    }

    fn appendScopedVenomBindingIndexEntriesForPrefix(
        self: *Session,
        out: *std.ArrayListUnmanaged(u8),
        first: *bool,
        binding_prefix: []const u8,
        binding_owner_id: []const u8,
    ) !void {
        for (self.scoped_venom_bindings.items) |binding| {
            if (!std.mem.startsWith(u8, binding.venom_path, binding_prefix)) continue;
            try self.appendAgentVenomIndexEntry(
                out,
                first,
                binding_owner_id,
                binding.venom_id,
                binding.venom_path,
                binding.endpoint_path,
                binding.invoke_path,
                binding.scope,
                binding.provider_node_id,
                binding.provider_venom_path,
            );
        }
    }

    fn registerScopedVenomBinding(
        self: *Session,
        venom_id: []const u8,
        scope: []const u8,
        venom_path: []const u8,
        provider_node_id: ?[]const u8,
        provider_venom_path: ?[]const u8,
        endpoint_path: ?[]const u8,
        invoke_path: ?[]const u8,
    ) !void {
        try self.scoped_venom_bindings.append(self.allocator, .{
            .venom_id = try self.allocator.dupe(u8, venom_id),
            .scope = try self.allocator.dupe(u8, scope),
            .venom_path = try self.allocator.dupe(u8, venom_path),
            .provider_node_id = if (provider_node_id) |value| try self.allocator.dupe(u8, value) else null,
            .provider_venom_path = if (provider_venom_path) |value| try self.allocator.dupe(u8, value) else null,
            .endpoint_path = if (endpoint_path) |value| try self.allocator.dupe(u8, value) else null,
            .invoke_path = if (invoke_path) |value| try self.allocator.dupe(u8, value) else null,
        });
    }

    fn registerExistingGlobalVenomBinding(
        self: *Session,
        global_root: u32,
        venom_id: []const u8,
        scope: []const u8,
    ) !void {
        const venom_dir_id = self.lookupChild(global_root, venom_id) orelse return;
        const venom_dir = self.nodes.get(venom_dir_id) orelse return;
        if (venom_dir.kind != .dir) return;

        const venom_path = try std.fmt.allocPrint(self.allocator, "/global/{s}", .{venom_id});
        defer self.allocator.free(venom_path);
        const invoke_path = if (self.venomCapsInvoke(venom_dir_id)) blk: {
            const invoke_target = try self.resolveNodeVenomInvokeTarget(venom_dir_id);
            defer self.allocator.free(invoke_target);
            break :blk try self.pathWithInvokeTarget(venom_path, invoke_target);
        } else null;
        defer if (invoke_path) |value| self.allocator.free(value);

        const local_provider_dir_id = blk: {
            const local_venoms_root = self.lookupLocalNodeVenomsRoot() orelse break :blk null;
            break :blk self.lookupChild(local_venoms_root, venom_id);
        };

        var explicit_provider = if (local_provider_dir_id == null) blk: {
            const plane = self.control_plane orelse break :blk null;
            break :blk try plane.resolveExplicitPreferredVenomProvider(self.allocator, venom_id);
        } else null;
        defer if (explicit_provider) |*value| value.deinit(self.allocator);

        const provider_node_id = if (local_provider_dir_id != null)
            try self.allocator.dupe(u8, "local")
        else if (explicit_provider) |provider|
            try self.allocator.dupe(u8, provider.node_id)
        else
            null;
        defer if (provider_node_id) |value| self.allocator.free(value);
        const provider_venom_path = if (provider_node_id) |node_id|
            try std.fmt.allocPrint(self.allocator, "/nodes/{s}/venoms/{s}", .{ node_id, venom_id })
        else
            null;
        defer if (provider_venom_path) |value| self.allocator.free(value);
        const provider_invoke_path = if (local_provider_dir_id) |provider_dir_id|
            try self.deriveVenomInvokePath("local", venom_id, provider_dir_id)
        else if (explicit_provider) |provider| blk: {
            const nodes_root = self.lookupChild(self.root_id, "nodes") orelse break :blk null;
            const node_dir_id = self.lookupChild(nodes_root, provider.node_id) orelse break :blk null;
            const venoms_root_id = self.lookupChild(node_dir_id, "venoms") orelse break :blk null;
            const provider_dir_id = self.lookupChild(venoms_root_id, venom_id) orelse break :blk null;
            break :blk try self.deriveVenomInvokePath(provider.node_id, venom_id, provider_dir_id);
        } else null;
        defer if (provider_invoke_path) |value| self.allocator.free(value);

        try self.registerScopedVenomBinding(
            venom_id,
            scope,
            venom_path,
            provider_node_id,
            provider_venom_path,
            if (provider_venom_path != null) provider_venom_path else venom_path,
            if (provider_invoke_path != null) provider_invoke_path else invoke_path,
        );
    }

    pub fn deriveVenomInvokePath(
        self: *Session,
        node_id: []const u8,
        venom_id: []const u8,
        venom_dir_id: u32,
    ) !?[]u8 {
        if (!self.venomCapsInvoke(venom_dir_id)) return null;

        const invoke_target = try self.resolveNodeVenomInvokeTarget(venom_dir_id);
        defer self.allocator.free(invoke_target);

        if (isWorldAbsolutePath(invoke_target)) {
            return try self.allocator.dupe(u8, invoke_target);
        }
        const invoke_suffix = std.mem.trimLeft(u8, invoke_target, "/");
        if (invoke_suffix.len == 0) return null;

        if (try self.firstVenomMountPath(venom_dir_id)) |mount_path| {
            defer self.allocator.free(mount_path);
            return try self.pathWithInvokeTarget(mount_path, invoke_suffix);
        }

        if (try self.venomEndpointPath(venom_dir_id)) |endpoint_path| {
            defer self.allocator.free(endpoint_path);
            return try self.pathWithInvokeTarget(endpoint_path, invoke_suffix);
        }

        return try std.fmt.allocPrint(
            self.allocator,
            "/nodes/{s}/venoms/{s}/{s}",
            .{ node_id, venom_id, invoke_suffix },
        );
    }

    pub fn pathWithInvokeSuffix(self: *Session, base_path: []const u8) ![]u8 {
        const trimmed = std.mem.trimRight(u8, base_path, "/");
        if (trimmed.len == 0) return self.allocator.dupe(u8, "/control/invoke.json");
        if (std.mem.endsWith(u8, trimmed, "/control/invoke.json")) {
            return self.allocator.dupe(u8, trimmed);
        }
        return std.fmt.allocPrint(self.allocator, "{s}/control/invoke.json", .{trimmed});
    }

    pub fn pathWithInvokeTarget(self: *Session, base_path: []const u8, invoke_suffix: []const u8) ![]u8 {
        const base_trimmed = std.mem.trimRight(u8, base_path, "/");
        if (invoke_suffix.len == 0) return self.allocator.dupe(u8, base_trimmed);
        if (base_trimmed.len == 0) {
            return std.fmt.allocPrint(self.allocator, "/{s}", .{invoke_suffix});
        }
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_trimmed, invoke_suffix });
    }

    pub fn resolveNodeVenomInvokeTarget(self: *Session, venom_dir_id: u32) ![]u8 {
        const default_target = "/control/invoke.json";
        const ops_id = self.lookupChild(venom_dir_id, "OPS.json") orelse return self.allocator.dupe(u8, default_target);
        const ops_node = self.nodes.get(ops_id) orelse return self.allocator.dupe(u8, default_target);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, ops_node.content, .{}) catch return self.allocator.dupe(u8, default_target);
        defer parsed.deinit();
        if (parsed.value != .object) return self.allocator.dupe(u8, default_target);

        const candidate = blk: {
            if (parsed.value.object.get("invoke")) |invoke_value| {
                if (invoke_value == .string and invoke_value.string.len > 0) {
                    break :blk invoke_value.string;
                }
            }
            if (parsed.value.object.get("paths")) |paths_value| {
                if (paths_value == .object) {
                    if (paths_value.object.get("invoke")) |invoke_value| {
                        if (invoke_value == .string and invoke_value.string.len > 0) {
                            break :blk invoke_value.string;
                        }
                    }
                }
            }
            break :blk null;
        };

        if (candidate) |value| {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) return self.allocator.dupe(u8, trimmed);
        }
        return self.allocator.dupe(u8, default_target);
    }

    fn firstVenomMountPath(self: *Session, venom_dir_id: u32) !?[]u8 {
        const mounts_id = self.lookupChild(venom_dir_id, "MOUNTS.json") orelse return null;
        const mounts_node = self.nodes.get(mounts_id) orelse return null;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, mounts_node.content, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .array) return null;

        for (parsed.value.array.items) |mount_value| {
            if (mount_value != .object) continue;
            const mount_path_value = mount_value.object.get("mount_path") orelse continue;
            if (mount_path_value != .string or mount_path_value.string.len == 0) continue;
            return try self.allocator.dupe(u8, mount_path_value.string);
        }
        return null;
    }

    fn venomEndpointPath(self: *Session, venom_dir_id: u32) !?[]u8 {
        const status_id = self.lookupChild(venom_dir_id, "STATUS.json") orelse return null;
        const status_node = self.nodes.get(status_id) orelse return null;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, status_node.content, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const endpoint_value = parsed.value.object.get("endpoint") orelse return null;
        if (endpoint_value != .string or endpoint_value.string.len == 0) return null;
        return try self.allocator.dupe(u8, endpoint_value.string);
    }

    fn venomCapsInvoke(self: *Session, venom_dir_id: u32) bool {
        const caps_id = self.lookupChild(venom_dir_id, "CAPS.json") orelse return false;
        const caps_node = self.nodes.get(caps_id) orelse return false;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, caps_node.content, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        const invoke_value = parsed.value.object.get("invoke") orelse return false;
        return invoke_value == .bool and invoke_value.bool;
    }

    fn clearTerminalSessions(self: *Session) void {
        if (self.current_terminal_session_id) |value| self.allocator.free(value);
        self.current_terminal_session_id = null;
        var it = self.terminal_sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var session = entry.value_ptr.*;
            session.deinit(self.allocator);
        }
        self.terminal_sessions.deinit(self.allocator);
        self.terminal_sessions = .{};
    }
};

fn isWorldAbsolutePath(path: []const u8) bool {
    return std.mem.startsWith(u8, path, "/nodes/") or
        std.mem.startsWith(u8, path, "/agents/") or
        std.mem.startsWith(u8, path, "/services/") or
        std.mem.startsWith(u8, path, "/global/") or
        std.mem.startsWith(u8, path, "/debug/");
}

fn defaultGlobalLibraryIndexMd() []const u8 {
    return "# Spiderweb Global Library\n\n" ++
        "- [Getting Started](/nodes/local/venoms/library/topics/getting-started.md)\n" ++
        "- [Service Discovery](/nodes/local/venoms/library/topics/service-discovery.md)\n" ++
        "- [Events and Waits](/nodes/local/venoms/library/topics/events-and-waits.md)\n" ++
        "- [Search Services](/nodes/local/venoms/library/topics/search-services.md)\n" ++
        "- [Terminal Workflows](/nodes/local/venoms/library/topics/terminal-workflows.md)\n" ++
        "- [Memory Workflows](/nodes/local/venoms/library/topics/memory-workflows.md)\n" ++
        "- [Project Mounts and Binds](/nodes/local/venoms/library/topics/project-mounts-and-binds.md)\n" ++
        "- [Agent Management and Sub-Brains](/nodes/local/venoms/library/topics/agent-management-and-sub-brains.md)\n";
}

fn defaultGlobalLibraryTopicGettingStarted() []const u8 {
    return "# Getting Started\n\n" ++
        "1. Discover mounted workspace services in `/meta/workspace_services.json` or `/projects/<project_id>/meta/mounted_services.json`.\n" ++
        "2. Use `/services/<venom_id>` when the workspace binds a service, then fall back to `/nodes/local/venoms/<venom_id>` for local catalog access.\n" ++
        "3. Register external workers through `/services/workers/control/register.json` before expecting worker-owned venoms like memory or sub_brains to appear.\n" ++
        "4. Read each Venom `README.md`, `SCHEMA.json`, `TEMPLATE.json`, `HOST.json`, and `CAPS.json` before using it.\n" ++
        "5. Use `/services/library` when bound, otherwise `/nodes/local/venoms/library`, for system guides.\n";
}

fn defaultGlobalLibraryTopicServiceDiscovery() []const u8 {
    return "# Venom Discovery\n\n" ++
        "- Node Venoms: `/nodes/<node_id>/venoms/<venom_id>`\n" ++
        "- Local built-in Venoms: `/nodes/local/venoms/<venom_id>`\n" ++
        "- Workspace service namespaces: `/services/<venom_id>`\n" ++
        "- Global shared namespaces: `/global/<venom_id>`\n" ++
        "- Start with `/meta/workspace_services.json`, `/projects/<project_id>/meta/mounted_services.json`, or `/nodes/local/venoms/VENOMS.json`.\n" ++
        "- Service Venoms should expose `TEMPLATE.json` and `HOST.json` alongside `SCHEMA.json`, `OPS.json`, and `STATUS.json`.\n" ++
        "- Common workspace Venoms include: workers, web_search, search_code, terminal, mounts, agents, workspaces.\n";
}

fn defaultGlobalLibraryTopicEventsAndWaits() []const u8 {
    return "# Events and Waits\n\n" ++
        "Use single-source blocking reads first for deterministic waits.\n" ++
        "Use `/services/events/control/wait.json` + `/services/events/next.json` when the workspace binds events, otherwise use `/nodes/local/venoms/events/control/wait.json` + `/nodes/local/venoms/events/next.json`.\n";
}

fn defaultGlobalLibraryTopicSearchServices() []const u8 {
    return "# Search Services\n\n" ++
        "Use `/services/search_code` for repository-local search and `/services/web_search` for external lookup when bound, otherwise use `/nodes/local/venoms/search_code` and `/nodes/local/venoms/web_search`.\n" ++
        "Drive both through `control/search.json` or `control/invoke.json`, then check `status.json` and `result.json`.\n";
}

fn defaultGlobalLibraryTopicTerminalWorkflows() []const u8 {
    return "# Terminal Workflows\n\n" ++
        "Use `/services/terminal/control/*.json` for sessionized shell execution when bound, otherwise use `/nodes/local/venoms/terminal/control/*.json`.\n" ++
        "Prefer `create` + `write/read` for interactive loops and `exec` for single command tasks.\n";
}

fn defaultGlobalLibraryTopicMemoryWorkflows() []const u8 {
    return "# Memory Workflows\n\n" ++
        "Use worker-owned memory venom paths after registering a worker node (for example `/nodes/<worker-node>/venoms/memory/control/*.json`). Spiderweb does not provide a canonical shared memory venom for Spider Monkey.\n" ++
        "Use `search` before creating duplicate memories.\n";
}

fn defaultGlobalLibraryTopicProjectMountsAndBinds() []const u8 {
    return "# Project Mounts and Binds\n\n" ++
        "Use `/services/mounts/control/mount.json`, `mkdir.json`, and `unmount.json` for project mounts when the workspace binds the mounts service.\n" ++
        "The canonical local origin is `/nodes/local/venoms/mounts/*`, with `/global/mounts/*` retained as a compatibility alias.\n" ++
        "Use `/services/mounts/control/bind.json` and `resolve.json` for stable project paths.\n";
}

fn defaultGlobalLibraryTopicAgentManagementAndSubBrains() []const u8 {
    return "# Agent Management and Sub-Brains\n\n" ++
        "Use `/global/agents` for list/create, `/global/workspaces` for list/get/up, and worker-owned `/nodes/<worker-node>/venoms/sub_brains/*` for private sub-brain control.\n" ++
        "Mutation operations depend on capability flags and service permissions.\n";
}

fn pathMatchesPrefixBoundary(path: []const u8, prefix: []const u8) bool {
    if (std.mem.eql(u8, path, prefix)) return true;
    if (prefix.len == 0) return false;
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    return path.len > prefix.len and path[prefix.len] == '/';
}

fn immediateBoundChildName(dir_path: []const u8, bind_path: []const u8) ?[]const u8 {
    const suffix = if (std.mem.eql(u8, dir_path, "/")) blk: {
        if (!std.mem.startsWith(u8, bind_path, "/")) return null;
        if (bind_path.len <= 1) return null;
        break :blk bind_path[1..];
    } else blk: {
        if (!pathMatchesPrefixBoundary(bind_path, dir_path)) return null;
        if (bind_path.len <= dir_path.len + 1) return null;
        break :blk bind_path[dir_path.len + 1 ..];
    };

    const slash_idx = std.mem.indexOfScalar(u8, suffix, '/') orelse suffix.len;
    if (slash_idx == 0) return null;
    return suffix[0..slash_idx];
}

test "immediateBoundChildName returns direct bind child for directory" {
    try std.testing.expectEqualStrings("home", immediateBoundChildName("/services", "/services/home").?);
    try std.testing.expectEqualStrings("services", immediateBoundChildName("/", "/services/home").?);
    try std.testing.expectEqualStrings("codex", immediateBoundChildName("/agents", "/agents/codex/home").?);
    try std.testing.expect(immediateBoundChildName("/services", "/nodes/local/venoms/home") == null);
    try std.testing.expect(immediateBoundChildName("/services/home", "/services/home") == null);
}

const ParsedScopedVenomAlias = struct {
    venom_id: []const u8,
    remote_path: []const u8,
};

const ParsedEntityScopedVenomAlias = struct {
    entity_id: []const u8,
    venom_id: []const u8,
    remote_path: []const u8,
};

const ParsedNodeVenomServicePath = struct {
    node_id: []const u8,
    venom_id: []const u8,
};

fn parseScopedVenomAliasPrefix(path: []const u8, prefix: []const u8) ?ParsedScopedVenomAlias {
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const tail = path[prefix.len..];
    if (tail.len == 0) return null;
    const slash_index = std.mem.indexOfScalar(u8, tail, '/') orelse tail.len;
    const venom_id = tail[0..slash_index];
    if (venom_id.len == 0) return null;
    const remote_path = if (slash_index == tail.len) "/" else tail[slash_index..];
    return .{
        .venom_id = venom_id,
        .remote_path = remote_path,
    };
}

fn parseEntityScopedVenomAliasPrefix(
    path: []const u8,
    entity_prefix: []const u8,
    venoms_segment: []const u8,
) ?ParsedEntityScopedVenomAlias {
    if (!std.mem.startsWith(u8, path, entity_prefix)) return null;
    const after_prefix = path[entity_prefix.len..];
    const entity_end = std.mem.indexOfScalar(u8, after_prefix, '/') orelse return null;
    const entity_id = after_prefix[0..entity_end];
    if (entity_id.len == 0) return null;
    const after_entity = after_prefix[entity_end..];
    if (!std.mem.startsWith(u8, after_entity, venoms_segment)) return null;
    const after_venoms = after_entity[venoms_segment.len..];
    if (after_venoms.len == 0) return null;
    const venom_end = std.mem.indexOfScalar(u8, after_venoms, '/') orelse after_venoms.len;
    const venom_id = after_venoms[0..venom_end];
    if (venom_id.len == 0) return null;
    const remote_path = if (venom_end == after_venoms.len) "/" else after_venoms[venom_end..];
    return .{
        .entity_id = entity_id,
        .venom_id = venom_id,
        .remote_path = remote_path,
    };
}

fn parseNodeVenomServicePath(path: []const u8) ?ParsedNodeVenomServicePath {
    if (!std.mem.startsWith(u8, path, "/nodes/")) return null;
    const after_prefix = path["/nodes/".len..];
    const node_end = std.mem.indexOfScalar(u8, after_prefix, '/') orelse return null;
    const node_id = after_prefix[0..node_end];
    if (node_id.len == 0) return null;
    const after_node = after_prefix[node_end..];
    if (!std.mem.startsWith(u8, after_node, "/venoms/")) return null;
    const after_venoms = after_node["/venoms/".len..];
    if (after_venoms.len == 0) return null;
    const venom_end = std.mem.indexOfScalar(u8, after_venoms, '/') orelse after_venoms.len;
    const venom_id = after_venoms[0..venom_end];
    if (venom_id.len == 0) return null;
    return .{
        .node_id = node_id,
        .venom_id = venom_id,
    };
}

fn boundVenomRemoteSuffix(allocator: std.mem.Allocator, absolute_path: []const u8, prefix: []const u8) ![]u8 {
    if (!pathMatchesPrefixBoundary(absolute_path, prefix)) return error.InvalidPath;
    if (std.mem.eql(u8, absolute_path, prefix)) return allocator.dupe(u8, "/");
    return std.fmt.allocPrint(allocator, "{s}", .{absolute_path[prefix.len..]});
}

fn parseBoundVenomProxyAttr(attr_val: std.json.Value) ?BoundVenomProxyAttrSummary {
    if (attr_val != .object) return null;

    const mode: u32 = if (attr_val.object.get("m")) |value|
        switch (value) {
            .integer => if (value.integer >= 0) @intCast(value.integer) else return null,
            else => return null,
        }
    else
        0;

    const kind: NodeKind = if (attr_val.object.get("k")) |value|
        switch (value) {
            .integer => switch (value.integer) {
                2 => .dir,
                1 => .file,
                else => if ((mode & 0o170000) == 0o040000) .dir else .file,
            },
            else => if ((mode & 0o170000) == 0o040000) .dir else .file,
        }
    else if ((mode & 0o170000) == 0o040000)
        .dir
    else
        .file;

    return .{
        .kind = kind,
        .writable = kind == .file and (mode & 0o222) != 0,
    };
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |char| {
        switch (char) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => if (char < 0x20) {
                try writer.print("\\u00{x:0>2}", .{char});
            } else {
                try writer.writeByte(char);
            },
        }
    }
    try writer.writeByte('"');
}

fn jsonObjectOptionalString(obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    if (obj.get(key)) |value| {
        if (value == .null) return null;
        if (value != .string) return error.InvalidPayload;
        return value.string;
    }
    return null;
}

fn jsonObjectOptionalBool(obj: std.json.ObjectMap, key: []const u8) !?bool {
    if (obj.get(key)) |value| {
        if (value == .null) return null;
        if (value != .bool) return error.InvalidPayload;
        return value.bool;
    }
    return null;
}

fn jsonObjectOptionalU64(obj: std.json.ObjectMap, key: []const u8) !?u64 {
    if (obj.get(key)) |value| {
        if (value == .null) return null;
        return switch (value) {
            .integer => |signed| blk: {
                if (signed < 0) return error.InvalidPayload;
                break :blk @as(u64, @intCast(signed));
            },
            .float => |float_value| blk: {
                if (float_value < 0) return error.InvalidPayload;
                if (std.math.floor(float_value) != float_value) return error.InvalidPayload;
                if (float_value > @as(f64, @floatFromInt(std.math.maxInt(u64)))) return error.InvalidPayload;
                break :blk @as(u64, @intFromFloat(float_value));
            },
            else => return error.InvalidPayload,
        };
    }
    return null;
}

fn sameOptionalString(left: ?[]const u8, right: ?[]const u8) bool {
    if (left) |left_value| {
        const right_value = right orelse return false;
        return std.mem.eql(u8, left_value, right_value);
    }
    return right == null;
}

fn isActiveMissionState(state: mission_store_mod.MissionState) bool {
    return switch (state) {
        .completed, .failed, .cancelled => false,
        else => true,
    };
}

fn kindName(kind: NodeKind) []const u8 {
    return switch (kind) {
        .dir => "dir",
        .file => "file",
    };
}

fn nodeMode(node: Node) u32 {
    return switch (node.kind) {
        .dir => 0o040755,
        .file => if (node.writable) 0o100644 else 0o100444,
    };
}

fn projectMountPathToLinkName(allocator: std.mem.Allocator, mount_path: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "mount::");

    const trimmed = std.mem.trim(u8, mount_path, "/");
    if (trimmed.len == 0) {
        try out.appendSlice(allocator, "root");
        return out.toOwnedSlice(allocator);
    }

    var part_it = std.mem.tokenizeScalar(u8, trimmed, '/');
    var first = true;
    while (part_it.next()) |part| {
        if (part.len == 0) continue;
        if (!first) try out.appendSlice(allocator, "::");
        first = false;
        try out.appendSlice(allocator, part);
    }
    if (first) try out.appendSlice(allocator, "root");
    return out.toOwnedSlice(allocator);
}

fn allocPathSegments(allocator: std.mem.Allocator, segments: []const []const u8) ![][]u8 {
    var path = try allocator.alloc([]u8, segments.len);
    errdefer allocator.free(path);
    var filled: usize = 0;
    errdefer {
        var idx: usize = 0;
        while (idx < filled) : (idx += 1) allocator.free(path[idx]);
    }
    for (segments, 0..) |segment, idx| {
        path[idx] = try allocator.dupe(u8, segment);
        filled = idx + 1;
    }
    return path;
}

fn freePathSegments(allocator: std.mem.Allocator, path: [][]u8) void {
    for (path) |segment| allocator.free(segment);
    allocator.free(path);
}

fn protocolWriteFile(
    session: *Session,
    allocator: std.mem.Allocator,
    attach_fid: u32,
    walk_fid: u32,
    segments: []const []const u8,
    data: []const u8,
    tag_base: u16,
) !void {
    var attach = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_attach,
        .tag = tag_base,
        .fid = attach_fid,
    };
    const attach_res = try session.handle(&attach);
    defer allocator.free(attach_res);
    try std.testing.expect(std.mem.indexOf(u8, attach_res, "acheron.r_attach") != null);

    const path = try allocPathSegments(allocator, segments);
    defer freePathSegments(allocator, path);
    var walk = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_walk,
        .tag = tag_base + 1,
        .fid = attach_fid,
        .newfid = walk_fid,
        .path = path,
    };
    const walk_res = try session.handle(&walk);
    defer allocator.free(walk_res);
    try std.testing.expect(std.mem.indexOf(u8, walk_res, "acheron.r_walk") != null);

    var open = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_open,
        .tag = tag_base + 2,
        .fid = walk_fid,
        .mode = "w",
    };
    const open_res = try session.handle(&open);
    defer allocator.free(open_res);
    try std.testing.expect(std.mem.indexOf(u8, open_res, "acheron.r_open") != null);

    var write = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_write,
        .tag = tag_base + 3,
        .fid = walk_fid,
        .offset = 0,
        .data = data,
    };
    const write_res = try session.handle(&write);
    defer allocator.free(write_res);
    try std.testing.expect(std.mem.indexOf(u8, write_res, "acheron.r_write") != null);
}

fn protocolWriteFileExpectError(
    session: *Session,
    allocator: std.mem.Allocator,
    attach_fid: u32,
    walk_fid: u32,
    segments: []const []const u8,
    data: []const u8,
    tag_base: u16,
    expected_error_code: []const u8,
) ![]u8 {
    var attach = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_attach,
        .tag = tag_base,
        .fid = attach_fid,
    };
    const attach_res = try session.handle(&attach);
    defer allocator.free(attach_res);
    try std.testing.expect(std.mem.indexOf(u8, attach_res, "acheron.r_attach") != null);

    const path = try allocPathSegments(allocator, segments);
    defer freePathSegments(allocator, path);
    var walk = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_walk,
        .tag = tag_base + 1,
        .fid = attach_fid,
        .newfid = walk_fid,
        .path = path,
    };
    const walk_res = try session.handle(&walk);
    defer allocator.free(walk_res);
    try std.testing.expect(std.mem.indexOf(u8, walk_res, "acheron.r_walk") != null);

    var open = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_open,
        .tag = tag_base + 2,
        .fid = walk_fid,
        .mode = "w",
    };
    const open_res = try session.handle(&open);
    defer allocator.free(open_res);
    try std.testing.expect(std.mem.indexOf(u8, open_res, "acheron.r_open") != null);

    var write = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_write,
        .tag = tag_base + 3,
        .fid = walk_fid,
        .offset = 0,
        .data = data,
    };
    const write_res = try session.handle(&write);
    errdefer allocator.free(write_res);
    try std.testing.expect(std.mem.indexOf(u8, write_res, "acheron.error") != null);
    if (expected_error_code.len > 0) {
        const pattern = try std.fmt.allocPrint(allocator, "\"code\":\"{s}\"", .{expected_error_code});
        defer allocator.free(pattern);
        try std.testing.expect(std.mem.indexOf(u8, write_res, pattern) != null);
    }
    return write_res;
}

fn protocolReadFile(
    session: *Session,
    allocator: std.mem.Allocator,
    attach_fid: u32,
    walk_fid: u32,
    segments: []const []const u8,
    tag_base: u16,
) ![]u8 {
    var attach = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_attach,
        .tag = tag_base,
        .fid = attach_fid,
    };
    const attach_res = try session.handle(&attach);
    defer allocator.free(attach_res);
    try std.testing.expect(std.mem.indexOf(u8, attach_res, "acheron.r_attach") != null);

    const path = try allocPathSegments(allocator, segments);
    defer freePathSegments(allocator, path);
    var walk = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_walk,
        .tag = tag_base + 1,
        .fid = attach_fid,
        .newfid = walk_fid,
        .path = path,
    };
    const walk_res = try session.handle(&walk);
    defer allocator.free(walk_res);
    try std.testing.expect(std.mem.indexOf(u8, walk_res, "acheron.r_walk") != null);

    var open = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_open,
        .tag = tag_base + 2,
        .fid = walk_fid,
        .mode = "r",
    };
    const open_res = try session.handle(&open);
    defer allocator.free(open_res);
    try std.testing.expect(std.mem.indexOf(u8, open_res, "acheron.r_open") != null);

    var read = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_read,
        .tag = tag_base + 3,
        .fid = walk_fid,
        .offset = 0,
        .count = 1_048_576,
    };
    const read_res = try session.handle(&read);
    defer allocator.free(read_res);
    return decodeReadResponseData(allocator, read_res);
}

fn runTestCommandCapture(
    allocator: std.mem.Allocator,
    cwd: ?[]const u8,
    argv: []const []const u8,
) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = cwd,
    });
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| {
            if (code == 0) return result.stdout;
            allocator.free(result.stdout);
            return error.TestExpectedResponse;
        },
        else => {
            allocator.free(result.stdout);
            return error.TestExpectedResponse;
        },
    }
}

fn extractMissionIdFromResultPayload(
    allocator: std.mem.Allocator,
    result_payload: []const u8,
) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResponse;
    const result_value = parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    if (result_value != .object) return error.TestExpectedResponse;
    const mission_value = result_value.object.get("mission") orelse return error.TestExpectedResponse;
    if (mission_value != .object) return error.TestExpectedResponse;
    const mission_id_value = mission_value.object.get("mission_id") orelse return error.TestExpectedResponse;
    if (mission_id_value != .string or mission_id_value.string.len == 0) return error.TestExpectedResponse;
    return allocator.dupe(u8, mission_id_value.string);
}

fn decodeReadResponseData(allocator: std.mem.Allocator, frame: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.TestExpectedResponse;

    const payload = parsed.value.object.get("payload") orelse return error.TestExpectedResponse;
    if (payload != .object) return error.TestExpectedResponse;
    const data_b64 = payload.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (data_b64 != .string) return error.TestExpectedResponse;

    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_b64.string);
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, data_b64.string);
    return decoded;
}

test "acheron_session: preferred service paths use workspace bindings when available" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const project_json = try control_plane.createProject(
        "{\"name\":\"SessionServicePaths\",\"vision\":\"SessionServicePaths\",\"template_id\":\"github\"}",
    );
    defer allocator.free(project_json);

    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer parsed_project.deinit();
    const project_id = parsed_project.value.object.get("project_id").?.string;
    const project_token = parsed_project.value.object.get("project_token").?.string;

    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createUnavailable(
        allocator,
        "execution_failed",
        "runtime unavailable",
    );
    defer runtime_handle.destroy();

    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var bound_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = project_id,
            .project_token = project_token,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .control_plane = &control_plane,
        },
    );
    defer bound_session.deinit();

    const bound_github_path = try bound_session.resolvePreferredServicePath("github_pr", "/control/sync.json");
    defer allocator.free(bound_github_path);
    try std.testing.expectEqualStrings("/services/github_pr/control/sync.json", bound_github_path);

    const bound_missions_path = try bound_session.resolvePreferredServicePath("missions", "/control/request_approval.json");
    defer allocator.free(bound_missions_path);
    try std.testing.expectEqualStrings("/services/missions/control/request_approval.json", bound_missions_path);

    var unbound_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
        },
    );
    defer unbound_session.deinit();

    const unbound_github_path = try unbound_session.resolvePreferredServicePath("github_pr", "/control/sync.json");
    defer allocator.free(unbound_github_path);
    try std.testing.expectEqualStrings("/global/github_pr/control/sync.json", unbound_github_path);
}

test "acheron_session: pr_review run_validation denied when shell_exec is blocked" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.makePath("exports");
    try tmp_dir.dir.makePath("agents");
    try tmp_dir.dir.writeFile(.{
        .sub_path = "agents/reviewer-denied_config.json",
        .data = "{\"agent_id\":\"reviewer-denied\",\"primary\":{\"denied_tools\":[\"shell_exec\"]}}",
    });

    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const exports_dir = try std.fs.path.join(allocator, &.{ root, "exports" });
    defer allocator.free(exports_dir);
    const agents_dir = try std.fs.path.join(allocator, &.{ root, "agents" });
    defer allocator.free(agents_dir);

    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createUnavailable(
        allocator,
        "execution_failed",
        "runtime unavailable",
    );
    defer runtime_handle.destroy();

    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "reviewer-host",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = exports_dir,
            .agents_dir = agents_dir,
            .actor_type = "agent",
            .actor_id = "reviewer-denied",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        732,
        733,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":129,\"default_review_commands\":[\"printf validation-ok\"]}",
        1816,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        734,
        735,
        &.{ "agents", "self", "pr_review", "result.json" },
        1817,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const validation_payload = try std.fmt.allocPrint(allocator, "{{\"mission_id\":\"{s}\"}}", .{mission_id});
    defer allocator.free(validation_payload);
    try protocolWriteFile(
        &session,
        allocator,
        736,
        737,
        &.{ "agents", "self", "pr_review", "control", "run_validation.json" },
        validation_payload,
        1818,
    );

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        738,
        739,
        &.{ "agents", "self", "pr_review", "result.json" },
        1819,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"run_validation\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"code\":\"tool_not_allowed\"") != null);

    const terminal_current = try protocolReadFile(
        &session,
        allocator,
        740,
        741,
        &.{ "nodes", "local", "venoms", "terminal", "current.json" },
        1820,
    );
    defer allocator.free(terminal_current);
    try std.testing.expect(std.mem.indexOf(u8, terminal_current, "\"session\":null") != null);
}

test "acheron_session: local fs export rejects symlink targets outside export root" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.makePath("exports");
    try tmp_dir.dir.makePath("outside");
    try tmp_dir.dir.writeFile(.{
        .sub_path = "outside/secret.txt",
        .data = "super-secret",
    });
    tmp_dir.dir.symLink("../outside/secret.txt", "exports/leak.txt", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied, error.Unsupported => return error.SkipZigTest,
        else => return err,
    };

    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const exports_dir = try std.fs.path.join(allocator, &.{ root, "exports" });
    defer allocator.free(exports_dir);

    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createUnavailable(
        allocator,
        "execution_failed",
        "runtime unavailable",
    );
    defer runtime_handle.destroy();

    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .local_fs_export_root = exports_dir,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
        },
    );
    defer session.deinit();

    const leak = try session.tryReadInternalPath("/nodes/local/fs/leak.txt");
    defer if (leak) |value| allocator.free(value);
    try std.testing.expect(leak == null);
}

test "session: parseReaddirNextCookie accepts next" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"ents\":[],\"next\":18}", .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u64, 18), Session.parseReaddirNextCookie(parsed.value.object));
}
