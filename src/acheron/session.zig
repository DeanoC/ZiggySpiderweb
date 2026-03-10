const std = @import("std");
const builtin = @import("builtin");
const unified = @import("spider-protocol").unified;
const protocol = @import("spider-protocol").protocol;
const runtime_server_mod = @import("../agents/runtime_server.zig");
const runtime_handle_mod = @import("../agents/runtime_handle.zig");
const chat_job_index = @import("../agents/chat_job_index.zig");
const chat_runtime_job = @import("../agents/chat_runtime_job.zig");
const tool_executor_mod = @import("ziggy-tool-runtime").tool_executor;
const job_projection = @import("job_projection.zig");
const shared_node = @import("spiderweb_node");
const workspace_policy = @import("../workspaces/policy.zig");
const control_plane_mod = @import("control_plane.zig");
const acheron_router = @import("router.zig");
const agent_config = @import("../agents/agent_config.zig");
const agent_registry = @import("../agents/agent_registry.zig");
const memory_ownership = @import("../agents/memory_ownership.zig");
const mission_store_mod = @import("../mission_store.zig");
const memory_venom = @import("../venoms/memory.zig");
const search_services_venom = @import("../venoms/search_services.zig");
const terminal_venom = @import("../venoms/terminal.zig");
const mounts_venom = @import("../venoms/mounts.zig");
const sub_brains_venom = @import("../venoms/sub_brains.zig");
const agents_venom = @import("../venoms/agents.zig");
const workspaces_venom = @import("../venoms/workspaces.zig");
const git_venom = @import("../venoms/git.zig");
const github_pr_venom = @import("../venoms/github_pr.zig");
const missions_venom = @import("../venoms/missions.zig");
const pr_review_venom = @import("../venoms/pr_review.zig");

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
    memory_invoke,
    memory_create,
    memory_load,
    memory_versions,
    memory_mutate,
    memory_evict,
    memory_search,
    sub_brains_invoke,
    sub_brains_list,
    sub_brains_upsert,
    sub_brains_delete,
    agents_invoke,
    agents_list,
    agents_create,
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

const default_wait_timeout_ms: i64 = 60_000;
const wait_poll_interval_ms: u64 = 100;
const debug_stream_log_max_bytes: usize = 2 * 1024 * 1024;
const max_signal_events: usize = 512;
const local_fs_world_prefix = "/nodes/local/fs";

const sub_brains_manage_capabilities = [_][]const u8{
    "sub_brains.manage",
    "subbrains.manage",
    "sub_brains",
    "subbrains",
    "can_spawn_subbrains",
    "agent_admin",
    "agent_manage",
};

const agent_create_capabilities = [_][]const u8{
    "agents.create",
    "agent.create",
    "agents.manage",
    "agent_manage",
    "agent_admin",
    "provision_agents",
    "plan",
};

const WaitSourceKind = enum {
    chat_input,
    job_status,
    job_result,
    time_after,
    time_at,
    agent_signal,
    hook_signal,
    user_signal,
};

const WaitSource = struct {
    raw_path: []u8,
    kind: WaitSourceKind,
    job_id: ?[]u8 = null,
    parameter: ?[]u8 = null,
    target_time_ms: i64 = 0,
    last_seen_updated_at_ms: i64 = 0,
    last_seen_job_event_seq: u64 = 0,
    last_seen_signal_seq: u64 = 0,

    fn deinit(self: *WaitSource, allocator: std.mem.Allocator) void {
        allocator.free(self.raw_path);
        if (self.job_id) |value| allocator.free(value);
        if (self.parameter) |value| allocator.free(value);
        self.* = undefined;
    }
};

const SignalEventType = enum {
    user,
    agent,
    hook,
};

const SignalEvent = struct {
    seq: u64,
    event_type: SignalEventType,
    parameter: ?[]u8 = null,
    payload_json: ?[]u8 = null,
    created_at_ms: i64,

    fn deinit(self: *SignalEvent, allocator: std.mem.Allocator) void {
        if (self.parameter) |value| allocator.free(value);
        if (self.payload_json) |value| allocator.free(value);
        self.* = undefined;
    }
};

const WaitCandidate = struct {
    source_index: usize,
    sort_key_ms: i64,
    payload_json: []u8,
    next_last_seen_updated_at_ms: ?i64 = null,
    next_last_seen_job_event_seq: ?u64 = null,
    next_last_seen_signal_seq: ?u64 = null,

    fn deinit(self: *WaitCandidate, allocator: std.mem.Allocator) void {
        allocator.free(self.payload_json);
        self.* = undefined;
    }
};

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

const PairingAction = enum {
    refresh,
    approve,
    deny,
    invites_refresh,
    invites_create,
};

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
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"qid\":{{\"path\":{d},\"type\":\"dir\"}},\"layout\":\"unified-v2-fs\",\"project_id\":{s},\"roots\":[\"nodes\",\"agents\",\"global\"{s}],\"dynamic_bind_paths\":{s},\"bind_count\":{d}}}",
            .{
                self.root_id,
                project_id_json,
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
        if (dir_id == self.nodes_root_id) {
            try self.addNodeDirectoriesFromControlPlane(self.nodes_root_id);
        }
        try self.refreshBoundVenomProxyDirectory(dir_id);
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
            .memory_invoke,
            .memory_create,
            .memory_load,
            .memory_versions,
            .memory_mutate,
            .memory_evict,
            .memory_search,
            => {
                const outcome = self.handleMemoryNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "memory payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "memory invoke access denied by permissions",
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
            .sub_brains_invoke => {
                const outcome = self.handleSubBrainsInvokeWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "sub_brains invoke payload must include op=list|upsert|delete and optional arguments/args",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "sub_brains mutation requires capability",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .sub_brains_list => {
                const outcome = self.handleSubBrainsListWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "sub_brains list payload must be empty or a JSON object",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .sub_brains_upsert => {
                const outcome = self.handleSubBrainsUpsertWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "sub_brains upsert payload requires brain_name (or name/id) and optional template/provider/tool fields",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "sub_brains mutation requires capability",
                        );
                    },
                    else => return err,
                };
                written = outcome.written;
            },
            .sub_brains_delete => {
                const outcome = self.handleSubBrainsDeleteWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "sub_brains delete payload requires brain_name (or name/id)",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "sub_brains mutation requires capability",
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
            "{\"kind\":\"metadata\",\"files\":[\"topology.json\",\"nodes.json\",\"agents.json\",\"sources.json\",\"contracts.json\",\"paths.json\",\"summary.json\",\"alerts.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"binds.json\",\"mounted_services.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"]}",
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
            "{\"kind\":\"meta\",\"entries\":[\"protocol.json\",\"view.json\",\"workspace_status.json\",\"workspace_availability.json\",\"workspace_health.json\",\"workspace_alerts.json\",\"workspace_binds.json\",\"workspace_services.json\"]}",
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

        try self.registerExistingGlobalVenomBinding(global_root, "chat", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "jobs", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "events", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "memory", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "web_search", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "search_code", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "terminal", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "mounts", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "sub_brains", "project_namespace");
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

        const pending_json = try self.loadPendingNodeJoinsJson();
        defer self.allocator.free(pending_json);
        const invites_json = try self.loadActiveNodeInvitesJson();
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

    fn loadPendingNodeJoinsJson(self: *Session) ![]u8 {
        const plane = self.control_plane orelse return self.allocator.dupe(u8, "{\"pending\":[]}");
        return plane.listPendingNodeJoins("{}") catch blk: {
            break :blk try self.allocator.dupe(u8, "{\"pending\":[]}");
        };
    }

    fn loadActiveNodeInvitesJson(self: *Session) ![]u8 {
        const plane = self.control_plane orelse return self.allocator.dupe(u8, "{\"invites\":[]}");
        return plane.listNodeInvites("{}") catch blk: {
            break :blk try self.allocator.dupe(u8, "{\"invites\":[]}");
        };
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

    fn ensureAliasedSubtree(self: *Session, source_id: u32) !void {
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
        _ = try self.cloneLocalCatalogVenomAlias(library_dir, global_root, "library");

        const chat_dir = try self.addDir(local_venoms_root, "chat", false);
        try self.seedChatNamespaceAt(chat_dir, "/nodes/local/venoms/chat", "/nodes/local/venoms/jobs");
        _ = try self.cloneLocalCatalogVenomAlias(chat_dir, global_root, "chat");

        const jobs_dir = try self.addDir(local_venoms_root, "jobs", false);
        try self.seedJobsNamespaceAt(jobs_dir, "/nodes/local/venoms/jobs");
        try self.seedJobsFromIndex();
        _ = try self.cloneLocalCatalogVenomAlias(jobs_dir, global_root, "jobs");

        const thoughts_dir = try self.addDir(local_venoms_root, "thoughts", false);
        try self.seedThoughtsNamespaceAt(thoughts_dir, "/nodes/local/venoms/thoughts");
        _ = try self.cloneLocalCatalogVenomAlias(thoughts_dir, global_root, "thoughts");

        const events_dir = try self.addDir(local_venoms_root, "events", false);
        try self.seedEventsNamespaceAt(events_dir, "/nodes/local/venoms/events");
        _ = try self.cloneLocalCatalogVenomAlias(events_dir, global_root, "events");

        const memory_dir = try self.addDir(local_venoms_root, "memory", false);
        try self.seedAgentMemoryNamespaceAt(memory_dir, "/nodes/local/venoms/memory");
        _ = try self.cloneLocalCatalogVenomAlias(memory_dir, global_root, "memory");

        const web_search_dir = try self.addDir(local_venoms_root, "web_search", false);
        try self.seedAgentWebSearchNamespaceAt(web_search_dir, "/nodes/local/venoms/web_search");
        _ = try self.cloneLocalCatalogVenomAlias(web_search_dir, global_root, "web_search");

        const search_code_dir = try self.addDir(local_venoms_root, "search_code", false);
        try self.seedAgentSearchCodeNamespaceAt(search_code_dir, "/nodes/local/venoms/search_code");
        _ = try self.cloneLocalCatalogVenomAlias(search_code_dir, global_root, "search_code");

        const terminal_dir = try self.addDir(local_venoms_root, "terminal", false);
        try self.seedAgentTerminalNamespaceAt(terminal_dir, "/nodes/local/venoms/terminal");
        _ = try self.cloneLocalCatalogVenomAlias(terminal_dir, global_root, "terminal");

        const mounts_dir = try self.addDir(local_venoms_root, "mounts", false);
        try self.seedAgentMountsNamespaceAt(mounts_dir, "/nodes/local/venoms/mounts");
        const mounts_alias_dir = try self.cloneLocalCatalogVenomAlias(mounts_dir, global_root, "mounts");
        self.mounts_status_alias_id = self.lookupChild(mounts_alias_dir, "status.json") orelse 0;
        self.mounts_result_alias_id = self.lookupChild(mounts_alias_dir, "result.json") orelse 0;

        const sub_brains_dir = try self.addDir(local_venoms_root, "sub_brains", false);
        try self.seedAgentSubBrainsNamespaceAt(sub_brains_dir, "/nodes/local/venoms/sub_brains");
        _ = try self.cloneLocalCatalogVenomAlias(sub_brains_dir, global_root, "sub_brains");

        const agents_dir = try self.addDir(local_venoms_root, "agents", false);
        try self.seedAgentAgentsNamespaceAt(agents_dir, "/nodes/local/venoms/agents");
        _ = try self.cloneLocalCatalogVenomAlias(agents_dir, global_root, "agents");

        const workspaces_dir = try self.addDir(local_venoms_root, "workspaces", false);
        try self.seedAgentWorkspacesNamespaceAt(workspaces_dir, "/nodes/local/venoms/workspaces");
        _ = try self.cloneLocalCatalogVenomAlias(workspaces_dir, global_root, "workspaces");

        if (self.local_fs_export_root != null) {
            const git_dir = try self.addDir(local_venoms_root, "git", false);
            try self.seedAgentGitNamespaceAt(git_dir, "/nodes/local/venoms/git");
            const git_alias_dir = try self.cloneLocalCatalogVenomAlias(git_dir, global_root, "git");
            self.git_status_alias_id = self.lookupChild(git_alias_dir, "status.json") orelse 0;
            self.git_result_alias_id = self.lookupChild(git_alias_dir, "result.json") orelse 0;

            const github_pr_dir = try self.addDir(local_venoms_root, "github_pr", false);
            try self.seedAgentGitHubPrNamespaceAt(github_pr_dir, "/nodes/local/venoms/github_pr");
            const github_pr_alias_dir = try self.cloneLocalCatalogVenomAlias(github_pr_dir, global_root, "github_pr");
            self.github_pr_status_alias_id = self.lookupChild(github_pr_alias_dir, "status.json") orelse 0;
            self.github_pr_result_alias_id = self.lookupChild(github_pr_alias_dir, "result.json") orelse 0;
        }

        if (self.mission_store != null) {
            const missions_dir = try self.addDir(local_venoms_root, "missions", false);
            try self.seedAgentMissionsNamespaceAt(missions_dir, "/nodes/local/venoms/missions");
            const missions_alias_dir = try self.cloneLocalCatalogVenomAlias(missions_dir, global_root, "missions");
            self.missions_status_alias_id = self.lookupChild(missions_alias_dir, "status.json") orelse 0;
            self.missions_result_alias_id = self.lookupChild(missions_alias_dir, "result.json") orelse 0;

            if (self.local_fs_export_root != null) {
                const pr_review_dir = try self.addDir(local_venoms_root, "pr_review", false);
                try self.seedAgentPrReviewNamespaceAt(pr_review_dir, "/nodes/local/venoms/pr_review");
                const pr_review_alias_dir = try self.cloneLocalCatalogVenomAlias(pr_review_dir, global_root, "pr_review");
                self.pr_review_status_alias_id = self.lookupChild(pr_review_alias_dir, "status.json") orelse 0;
                self.pr_review_result_alias_id = self.lookupChild(pr_review_alias_dir, "result.json") orelse 0;
            }
        }

        try self.refreshNodeVenomsIndex("local");
        try self.registerLocalCatalogVenomBinding("library", "node_catalog");
        try self.registerLocalCatalogVenomBinding("chat", "node_catalog");
        try self.registerLocalCatalogVenomBinding("jobs", "node_catalog");
        try self.registerLocalCatalogVenomBinding("thoughts", "node_catalog");
        try self.registerLocalCatalogVenomBinding("events", "node_catalog");
        try self.registerLocalCatalogVenomBinding("memory", "node_catalog");
        try self.registerLocalCatalogVenomBinding("web_search", "node_catalog");
        try self.registerLocalCatalogVenomBinding("search_code", "node_catalog");
        try self.registerLocalCatalogVenomBinding("terminal", "node_catalog");
        try self.registerLocalCatalogVenomBinding("mounts", "node_catalog");
        try self.registerLocalCatalogVenomBinding("sub_brains", "node_catalog");
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

    fn seedAgentMemoryNamespace(self: *Session, memory_dir: u32) !void {
        return memory_venom.seedNamespace(self, memory_dir);
    }

    fn seedAgentMemoryNamespaceAt(self: *Session, memory_dir: u32, base_path: []const u8) !void {
        return memory_venom.seedNamespaceAt(self, memory_dir, base_path);
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

    fn seedAgentSubBrainsNamespace(self: *Session, sub_brains_dir: u32) !void {
        return self.seedAgentSubBrainsNamespaceAt(sub_brains_dir, "/global/sub_brains");
    }

    fn seedAgentSubBrainsNamespaceAt(self: *Session, sub_brains_dir: u32, base_path: []const u8) !void {
        return sub_brains_venom.seedNamespaceAt(self, sub_brains_dir, base_path);
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
        const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
        defer self.allocator.free(escaped_base_path);
        const shape_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"kind\":\"venom\",\"venom_id\":\"chat\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,STATUS.json,meta.json,control/*,examples/*}}\"}}",
            .{escaped_base_path},
        );
        defer self.allocator.free(shape_json);
        try self.addDirectoryDescriptors(
            chat_dir,
            "Chat",
            shape_json,
            "{\"invoke\":true,\"discoverable\":true,\"job_queue\":true}",
            "Chat submit/reply namespace. Write prompts to control/input and read queued job outputs from the jobs venom.",
        );

        const control = try self.addDir(chat_dir, "control", false);
        const examples = try self.addDir(chat_dir, "examples", false);
        self.chat_input_id = try self.addFile(control, "input", "", true, .chat_input);
        _ = try self.addFile(control, "reply", "", true, .chat_reply);
        _ = try self.addFile(examples, "send.txt", shared_node.venom_contracts.chat.example_send_txt, false, .none);

        const chat_schema_json = try shared_node.venom_contracts.chat.renderSchemaJson(self.allocator, jobs_path, "control/reply");
        defer self.allocator.free(chat_schema_json);
        const chat_ops_json = try shared_node.venom_contracts.chat.renderOpsJson(self.allocator, "control/input", jobs_path, "control/reply");
        defer self.allocator.free(chat_ops_json);
        const chat_status_json = try shared_node.venom_contracts.chat.renderStatusJson(self.allocator, base_path, jobs_path);
        defer self.allocator.free(chat_status_json);
        _ = try self.addFile(chat_dir, "README.md", shared_node.venom_contracts.chat.readme_md, false, .none);
        _ = try self.addFile(chat_dir, "SCHEMA.json", chat_schema_json, false, .none);
        _ = try self.addFile(chat_dir, "CAPS.json", shared_node.venom_contracts.chat.caps_json, false, .none);
        _ = try self.addFile(chat_dir, "OPS.json", chat_ops_json, false, .none);
        _ = try self.addFile(chat_dir, "STATUS.json", chat_status_json, false, .none);

        const chat_meta_json = try shared_node.venom_contracts.chat.renderMetaJson(self.allocator, .{
            .agent_id = self.agent_id,
            .actor_type = self.actor_type,
            .actor_id = self.actor_id,
            .project_id = self.active_namespace_project_id orelse self.project_id orelse "",
        });
        defer self.allocator.free(chat_meta_json);
        _ = try self.addFile(chat_dir, "meta.json", chat_meta_json, false, .none);
    }

    fn seedJobsNamespaceAt(self: *Session, jobs_dir: u32, base_path: []const u8) !void {
        self.jobs_root_id = jobs_dir;
        try self.addDirectoryDescriptors(
            jobs_dir,
            "Jobs",
            "{\"kind\":\"collection\",\"entries\":\"job_id\",\"files\":[\"status.json\",\"result.txt\",\"log.txt\"]}",
            "{\"read\":true,\"write\":false}",
            "Chat job status and outputs.",
        );
        const jobs_schema_json = try shared_node.venom_contracts.jobs.renderSchemaJson(self.allocator, base_path);
        defer self.allocator.free(jobs_schema_json);
        const jobs_status_json = try shared_node.venom_contracts.jobs.renderStatusJson(self.allocator, base_path);
        defer self.allocator.free(jobs_status_json);
        _ = try self.addFile(jobs_dir, "README.md", shared_node.venom_contracts.jobs.readme_md, false, .none);
        _ = try self.addFile(jobs_dir, "SCHEMA.json", jobs_schema_json, false, .none);
        _ = try self.addFile(jobs_dir, "CAPS.json", shared_node.venom_contracts.jobs.caps_json, false, .none);
        _ = try self.addFile(jobs_dir, "OPS.json", shared_node.venom_contracts.jobs.ops_json, false, .none);
        _ = try self.addFile(jobs_dir, "STATUS.json", jobs_status_json, false, .none);
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
        const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
        defer self.allocator.free(escaped_base_path);
        const shape_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"kind\":\"venom\",\"venom_id\":\"events\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,STATUS.json,next.json,control/*,sources/*}}\"}}",
            .{escaped_base_path},
        );
        defer self.allocator.free(shape_json);
        const events_control_dir = try self.addDir(events_dir, "control", false);
        const events_sources_dir = try self.addDir(events_dir, "sources", false);
        try self.addDirectoryDescriptors(
            events_dir,
            "Events",
            shape_json,
            shared_node.venom_contracts.events.caps_json,
            "Event wait/signal namespace for agent runtime coordination.",
        );
        _ = try self.addFile(events_dir, "README.md", shared_node.venom_contracts.events.readme_md, false, .none);
        _ = try self.addFile(events_dir, "SCHEMA.json", shared_node.venom_contracts.events.schema_json, false, .none);
        _ = try self.addFile(events_dir, "CAPS.json", shared_node.venom_contracts.events.caps_json, false, .none);
        _ = try self.addFile(events_dir, "OPS.json", shared_node.venom_contracts.events.ops_json, false, .none);
        _ = try self.addFile(events_dir, "STATUS.json", shared_node.venom_contracts.events.status_json, false, .none);
        _ = try self.addFile(events_control_dir, "README.md", shared_node.venom_contracts.events.control_readme_md, false, .none);
        _ = try self.addFile(events_control_dir, "wait.json", shared_node.venom_contracts.events.default_wait_json, true, .event_wait_config);
        _ = try self.addFile(events_control_dir, "signal.json", shared_node.venom_contracts.events.default_signal_json, true, .event_signal);
        _ = try self.addFile(events_sources_dir, "README.md", shared_node.venom_contracts.events.sources_readme_md, false, .none);
        _ = try self.addFile(events_sources_dir, "agent.json", shared_node.venom_contracts.events.agent_source_help_md, false, .none);
        _ = try self.addFile(events_sources_dir, "hook.json", shared_node.venom_contracts.events.hook_source_help_md, false, .none);
        _ = try self.addFile(events_sources_dir, "user.json", shared_node.venom_contracts.events.user_source_help_md, false, .none);
        _ = try self.addFile(events_sources_dir, "time.json", shared_node.venom_contracts.events.time_source_help_md, false, .none);
        self.event_next_id = try self.addFile(
            events_dir,
            "next.json",
            shared_node.venom_contracts.events.initial_next_json,
            false,
            .event_next,
        );
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
            "{{\"kind\":\"venom\",\"venom_id\":\"library\",\"shape\":\"{s}/{{Index.md,README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,topics/*}}\"}}",
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
            "{\"model\":\"static_docs\",\"transport\":\"filesystem\",\"paths\":{\"index\":\"Index.md\",\"topics\":\"topics/*\"},\"operations\":{}}",
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
            "{{\"version\":\"acheron-namespace-project-contract-v2\",\"project_id\":\"{s}\",\"top_level_roots\":[\"/nodes\",\"/agents\",\"/global\",\"/services\"],\"project_metadata_files\":[\"topology.json\",\"nodes.json\",\"agents.json\",\"sources.json\",\"contracts.json\",\"paths.json\",\"summary.json\",\"alerts.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"binds.json\",\"mounted_services.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"],\"links\":{{\"nodes_root\":\"/nodes\",\"agents_root\":\"/agents\",\"global_root\":\"/global\",\"services_root\":\"/services\",\"workspace_control\":\"/global/workspaces\",\"workspace_status\":\"/global/workspaces/control/invoke.json\",\"workspace_binds\":\"/projects/{s}/meta/binds.json\",\"workspace_services\":\"/projects/{s}/meta/mounted_services.json\"}}}}",
            .{ escaped_project_id, escaped_project_id, escaped_project_id },
        );
    }

    fn buildProjectPathsJson(self: *Session, policy: workspace_policy.WorkspacePolicy) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project_id);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"nodes_root\":\"/nodes\",\"agents_root\":\"/agents\",\"services\":{{\"root\":\"/services\",\"mounted_services_meta\":\"/projects/{s}/meta/mounted_services.json\"}},\"global\":{{\"root\":\"/global\",\"library\":\"/global/library\",\"workspaces\":\"/global/workspaces\",\"chat\":\"/global/chat\",\"jobs\":\"/global/jobs\",\"mounts\":\"/global/mounts\",\"debug\":{s}}}}}",
            .{
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
                        venom.kind,
                        venom.state,
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
                    "online",
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
                    "online",
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
                    "online",
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
                    "online",
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
                    "online",
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
                    "online",
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
                    "online",
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
                    "online",
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
                    "online",
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
                    "online",
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
            kind: []u8,
            state: []u8,
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
                allocator.free(self.kind);
                allocator.free(self.state);
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
                .kind = try self.allocator.dupe(u8, kind_val.string),
                .state = try self.allocator.dupe(u8, state),
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
        kind: []const u8,
        state: []const u8,
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

        const status = try std.fmt.allocPrint(
            self.allocator,
            "{{\"venom_id\":\"{s}\",\"kind\":\"{s}\",\"state\":\"{s}\",\"endpoint\":\"{s}\"}}",
            .{ escaped_venom_id, escaped_kind, escaped_state, escaped_endpoint },
        );
        defer self.allocator.free(status);
        _ = try self.addFile(venom_dir, "STATUS.json", status, false, .none);
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
        const catalog_path = if (suffix.len == 0)
            try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/{s}", .{service_id})
        else
            try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/{s}{s}", .{ service_id, suffix });
        errdefer self.allocator.free(catalog_path);
        if (self.resolveAbsolutePathNoBinds(catalog_path) != null) return catalog_path;

        self.allocator.free(catalog_path);
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

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);

        var it = node.children.iterator();
        var first = true;
        while (it.next()) |entry| {
            if (!first) try out.append(self.allocator, '\n');
            first = false;
            try out.appendSlice(self.allocator, entry.key_ptr.*);
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

        var cookie: u64 = 0;
        while (true) {
            const listing_json = router.readdir(proxy.remote_path, cookie, 4096) catch return;
            defer self.allocator.free(listing_json);
            cookie = try self.applyBoundVenomProxyListing(dir_id, listing_json);
            if (cookie == 0) break;
        }
    }

    fn applyBoundVenomProxyListing(self: *Session, parent_id: u32, listing_json: []const u8) !u64 {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, listing_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return 0;

        const next_cookie: u64 = if (parsed.value.object.get("next_cookie")) |value|
            if (value == .integer and value.integer >= 0) @intCast(value.integer) else 0
        else
            0;
        const ents = parsed.value.object.get("ents") orelse return next_cookie;
        if (ents != .array) return next_cookie;
        for (ents.array.items) |entry| {
            if (entry != .object) continue;
            const name_val = entry.object.get("name") orelse continue;
            const attr_val = entry.object.get("attr") orelse continue;
            if (name_val != .string or name_val.string.len == 0) continue;
            try self.upsertBoundVenomProxyChild(parent_id, name_val.string, attr_val);
        }
        return next_cookie;
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
        const written = raw_input.len;
        const payload = std.mem.trim(u8, raw_input, " \t\r\n");
        if (!self.isPairingActionAuthorized(action, payload)) {
            try self.setPairingResultError(action, "OperatorAuthFailed");
            return .{ .written = written };
        }
        const plane = self.control_plane orelse {
            try self.setPairingResultError(action, "ControlPlaneUnavailable");
            return .{ .written = written };
        };

        switch (action) {
            .refresh => {
                const list_json = plane.listPendingNodeJoins(if (payload.len == 0) "{}" else payload) catch |err| {
                    try self.setPairingResultError(action, @errorName(err));
                    try self.refreshPairingPendingSnapshot();
                    return .{ .written = written };
                };
                defer self.allocator.free(list_json);
                try self.setPairingResultSuccess(action, list_json);
                try self.setPairingPendingContent(list_json);
                return .{ .written = written };
            },
            .approve => {
                const approve_json = plane.approvePendingNodeJoin(payload) catch |err| {
                    try self.setPairingResultError(action, @errorName(err));
                    try self.refreshPairingPendingSnapshot();
                    return .{ .written = written };
                };
                defer self.allocator.free(approve_json);
                try self.setPairingResultSuccess(action, approve_json);
                try self.refreshPairingPendingSnapshot();
                return .{ .written = written };
            },
            .deny => {
                const deny_json = plane.denyPendingNodeJoin(payload) catch |err| {
                    try self.setPairingResultError(action, @errorName(err));
                    try self.refreshPairingPendingSnapshot();
                    return .{ .written = written };
                };
                defer self.allocator.free(deny_json);
                try self.setPairingResultSuccess(action, deny_json);
                try self.refreshPairingPendingSnapshot();
                return .{ .written = written };
            },
            .invites_refresh => {
                const invites_json = plane.listNodeInvites(if (payload.len == 0) "{}" else payload) catch |err| {
                    try self.setPairingResultError(action, @errorName(err));
                    try self.refreshPairingInvitesSnapshot();
                    return .{ .written = written };
                };
                defer self.allocator.free(invites_json);
                try self.setPairingResultSuccess(action, invites_json);
                try self.setPairingInvitesContent(invites_json);
                return .{ .written = written };
            },
            .invites_create => {
                const create_json = plane.createNodeInvite(if (payload.len == 0) "{}" else payload) catch |err| {
                    try self.setPairingResultError(action, @errorName(err));
                    try self.refreshPairingInvitesSnapshot();
                    return .{ .written = written };
                };
                defer self.allocator.free(create_json);
                try self.setPairingResultSuccess(action, create_json);
                try self.refreshPairingInvitesSnapshot();
                return .{ .written = written };
            },
        }
    }

    fn isPairingActionAuthorized(self: *const Session, action: PairingAction, payload: []const u8) bool {
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

    fn pairingActionName(action: PairingAction) []const u8 {
        return switch (action) {
            .refresh => "refresh",
            .approve => "approve",
            .deny => "deny",
            .invites_refresh => "invites_refresh",
            .invites_create => "invites_create",
        };
    }

    fn setPairingPendingContent(self: *Session, payload: []const u8) !void {
        if (self.pairing_pending_id == 0) return;
        try self.setFileContent(self.pairing_pending_id, payload);
    }

    fn refreshPairingPendingSnapshot(self: *Session) !void {
        if (self.pairing_pending_id == 0) return;
        const payload = try self.loadPendingNodeJoinsJson();
        defer self.allocator.free(payload);
        try self.setPairingPendingContent(payload);
    }

    fn setPairingInvitesContent(self: *Session, payload: []const u8) !void {
        if (self.pairing_invites_active_id == 0) return;
        try self.setFileContent(self.pairing_invites_active_id, payload);
    }

    fn refreshPairingInvitesSnapshot(self: *Session) !void {
        if (self.pairing_invites_active_id == 0) return;
        const payload = try self.loadActiveNodeInvitesJson();
        defer self.allocator.free(payload);
        try self.setPairingInvitesContent(payload);
    }

    fn setPairingResultSuccess(self: *Session, action: PairingAction, payload: []const u8) !void {
        const result_node_id, const error_node_id = switch (action) {
            .refresh, .approve, .deny => .{ self.pairing_last_result_id, self.pairing_last_error_id },
            .invites_refresh, .invites_create => .{ self.pairing_invites_last_result_id, self.pairing_invites_last_error_id },
        };
        if (result_node_id != 0) {
            const action_name = pairingActionName(action);
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

    fn setPairingResultError(self: *Session, action: PairingAction, error_name: []const u8) !void {
        const result_node_id, const error_node_id = switch (action) {
            .refresh, .approve, .deny => .{ self.pairing_last_result_id, self.pairing_last_error_id },
            .invites_refresh, .invites_create => .{ self.pairing_invites_last_result_id, self.pairing_invites_last_error_id },
        };
        const action_name = pairingActionName(action);
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

    fn seedJobsFromIndex(self: *Session) !void {
        const jobs = try self.job_index.listJobsForAgent(self.allocator, self.agent_id);
        defer chat_job_index.deinitJobViews(self.allocator, jobs);

        for (jobs) |job| {
            if (self.lookupChild(self.jobs_root_id, job.job_id) != null) continue;
            const job_dir = try self.addDir(self.jobs_root_id, job.job_id, false);
            const status_json = try self.buildJobStatusJson(job.state, job.correlation_id, job.error_text);
            defer self.allocator.free(status_json);
            _ = try self.addFile(job_dir, "status.json", status_json, true, .job_status);
            _ = try self.addFile(job_dir, "result.txt", job.result_text orelse "", true, .job_result);
            _ = try self.addFile(job_dir, "log.txt", job.log_text orelse "", true, .job_log);
            try self.ensureAliasedSubtree(job_dir);
        }
    }

    fn buildJobStatusJson(
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

    fn handleChatInputWrite(self: *Session, msg: *const unified.ParsedMessage, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) {
            return .{ .written = 0, .job_name = null, .correlation_id = null };
        }

        const correlation_id = msg.correlation_id orelse msg.id;
        const job_name = try self.job_index.createJob(self.agent_id, correlation_id);
        defer self.allocator.free(job_name);

        const job_dir = try self.addDir(self.jobs_root_id, job_name, false);
        const queued_status = try self.buildJobStatusJson(.queued, correlation_id, null);
        defer self.allocator.free(queued_status);
        const status_id = try self.addFile(job_dir, "status.json", queued_status, true, .job_status);
        const result_id = try self.addFile(job_dir, "result.txt", "", true, .job_result);
        const log_id = try self.addFile(job_dir, "log.txt", "", true, .job_log);
        try self.ensureAliasedSubtree(job_dir);

        try self.job_index.markRunning(job_name);
        const running_status = try self.buildJobStatusJson(.running, correlation_id, null);
        defer self.allocator.free(running_status);
        try self.setFileContent(status_id, running_status);

        self.spawnAsyncChatRuntimeJob(job_name, input, correlation_id) catch |spawn_err| {
            const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("runtime_error", @errorName(spawn_err));
            const failed_status = try self.buildJobStatusJson(.failed, correlation_id, normalized.message);
            defer self.allocator.free(failed_status);

            self.setFileContent(status_id, failed_status) catch |err| {
                std.log.warn("failed to update chat status after spawn failure: {s}", .{@errorName(err)});
            };
            self.setFileContent(result_id, normalized.message) catch |err| {
                std.log.warn("failed to update chat result after spawn failure: {s}", .{@errorName(err)});
            };

            const spawn_log_owned = std.fmt.allocPrint(
                self.allocator,
                "[runtime worker spawn failure] {s}\n",
                .{@errorName(spawn_err)},
            ) catch null;
            defer if (spawn_log_owned) |value| self.allocator.free(value);
            const spawn_log = if (spawn_log_owned) |value|
                value
            else
                "[runtime worker spawn failure]\n";

            self.setFileContent(log_id, spawn_log) catch |err| {
                std.log.warn("failed to update chat log after spawn failure: {s}", .{@errorName(err)});
            };
            self.job_index.markCompleted(
                job_name,
                false,
                normalized.message,
                normalized.message,
                spawn_log,
            ) catch |err| {
                std.log.warn("chat job index completion update failed after spawn failure: {s}", .{@errorName(err)});
            };
        };

        return .{
            .written = raw_input.len,
            .job_name = try self.allocator.dupe(u8, job_name),
            .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
        };
    }

    fn spawnAsyncChatRuntimeJob(
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
            const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("runtime_error", @errorName(err));
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
        var outcome = try chat_runtime_job.execute(.{
            .allocator = ctx.allocator,
            .runtime_handle = ctx.runtime_handle,
            .job_index = ctx.job_index,
            .job_id = job_name,
            .input = input,
            .correlation_id = correlation_id,
            .emit_debug = ctx.emit_debug,
        });
        defer outcome.deinit(ctx.allocator);

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
        const reply = std.mem.trim(u8, raw_input, " \t\r\n");
        try self.setFileContent(node_id, reply);
        return .{
            .written = raw_input.len,
            .chat_reply_content = try self.allocator.dupe(u8, reply),
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

    fn handleMemoryNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const written = try memory_venom.handleNamespaceWrite(self, special, node_id, raw_input);
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

    pub fn normalizeLocalFsRelativePath(self: *Session, raw_path: []const u8) ![]u8 {
        return mounts_venom.normalizeLocalFsRelativePath(self, raw_path);
    }

    fn ensurePathExists(path: []const u8) !void {
        return mounts_venom.ensurePathExists(path);
    }

    fn handleSubBrainsInvokeWrite(self: *Session, invoke_node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try sub_brains_venom.handleInvokeWrite(self, invoke_node_id, raw_input) };
    }

    fn handleSubBrainsListWrite(self: *Session, list_node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try sub_brains_venom.handleListWrite(self, list_node_id, raw_input) };
    }

    fn handleSubBrainsUpsertWrite(self: *Session, upsert_node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try sub_brains_venom.handleUpsertWrite(self, upsert_node_id, raw_input) };
    }

    fn handleSubBrainsDeleteWrite(self: *Session, delete_node_id: u32, raw_input: []const u8) !WriteOutcome {
        return .{ .written = try sub_brains_venom.handleDeleteWrite(self, delete_node_id, raw_input) };
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
        can_manage_sub_brains: bool,
        can_create_agents: bool,
    };

    pub fn canManageSubBrains(self: *Session) bool {
        const abilities = self.resolveAgentAbilities() catch return false;
        return abilities.can_manage_sub_brains;
    }

    pub fn canCreateAgents(self: *Session) bool {
        const abilities = self.resolveAgentAbilities() catch return false;
        return abilities.can_create_agents;
    }

    fn resolveAgentAbilities(self: *Session) !AgentAbilities {
        var abilities = AgentAbilities{
            .can_manage_sub_brains = std.mem.eql(u8, self.agent_id, "mother"),
            .can_create_agents = std.mem.eql(u8, self.agent_id, "mother"),
        };

        if (try agent_config.loadAgentConfigFromDir(self.allocator, self.agents_dir, self.agent_id)) |config| {
            defer {
                var owned = config;
                owned.deinit();
            }
            if (config.primary.can_spawn_subbrains) abilities.can_manage_sub_brains = true;
            if (config.primary.capabilities) |caps| {
                for (caps.items) |capability| {
                    if (capabilityMatchesAny(capability, &sub_brains_manage_capabilities)) {
                        abilities.can_manage_sub_brains = true;
                    }
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
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = switch (special) {
            .github_pr_sync => GitHubPrOp.sync,
            .github_pr_ingest_event => GitHubPrOp.ingest_event,
            .github_pr_publish_review => GitHubPrOp.publish_review,
            .github_pr_invoke => blk: {
                const op_raw = blk2: {
                    if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    break :blk2 null;
                } orelse return error.InvalidPayload;
                break :blk parseGitHubPrOp(op_raw) orelse return error.InvalidPayload;
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

        return self.executeGitHubPrOp(op, args_obj, raw_input.len);
    }

    fn parseGitOp(raw: []const u8) ?GitOp {
        return git_venom.parseOp(raw);
    }

    fn parseGitHubPrOp(raw: []const u8) ?GitHubPrOp {
        return github_pr_venom.parseOp(raw);
    }

    fn gitOperationName(op: GitOp) []const u8 {
        return git_venom.operationName(op);
    }

    fn gitStatusToolName(op: GitOp) []const u8 {
        return git_venom.statusToolName(op);
    }

    fn gitHubPrOperationName(op: GitHubPrOp) []const u8 {
        return github_pr_venom.operationName(op);
    }

    fn gitHubPrStatusToolName(op: GitHubPrOp) []const u8 {
        return github_pr_venom.statusToolName(op);
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

    fn executeGitHubPrOp(self: *Session, op: GitHubPrOp, args_obj: std.json.ObjectMap, written: usize) !WriteOutcome {
        const tool_name = gitHubPrStatusToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        try self.setMirroredFileContent(self.github_pr_status_id, self.github_pr_status_alias_id, running_status);

        const result_payload = self.executeGitHubPrOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.github_pr_status_id, self.github_pr_status_alias_id, failed_status);
            const failed_result = try self.buildGitHubPrFailureResultJson(op, "invalid_payload", error_message);
            defer self.allocator.free(failed_result);
            try self.setMirroredFileContent(self.github_pr_result_id, self.github_pr_result_alias_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
            defer self.allocator.free(message);
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.github_pr_status_id, self.github_pr_status_alias_id, failed_status);
        } else {
            const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
            defer self.allocator.free(done_status);
            try self.setMirroredFileContent(self.github_pr_status_id, self.github_pr_status_alias_id, done_status);
        }
        try self.setMirroredFileContent(self.github_pr_result_id, self.github_pr_result_alias_id, result_payload);
        return .{ .written = written };
    }

    fn executeGitOpPayload(self: *Session, op: GitOp, args_obj: std.json.ObjectMap) ![]u8 {
        return git_venom.executeOpPayload(self, op, args_obj);
    }

    fn executeGitHubPrOpPayload(self: *Session, op: GitHubPrOp, args_obj: std.json.ObjectMap) ![]u8 {
        return github_pr_venom.executeOpPayload(self, op, args_obj);
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
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = switch (special) {
            .pr_review_configure_repo => PrReviewOp.configure_repo,
            .pr_review_get_repo => PrReviewOp.get_repo,
            .pr_review_list_repos => PrReviewOp.list_repos,
            .pr_review_intake => PrReviewOp.intake,
            .pr_review_start => PrReviewOp.start,
            .pr_review_sync => PrReviewOp.sync,
            .pr_review_run_validation => PrReviewOp.run_validation,
            .pr_review_record_validation => PrReviewOp.record_validation,
            .pr_review_draft_review => PrReviewOp.draft_review,
            .pr_review_save_draft => PrReviewOp.save_draft,
            .pr_review_record_review => PrReviewOp.record_review,
            .pr_review_advance => PrReviewOp.advance,
            .pr_review_invoke => blk: {
                const op_raw = blk2: {
                    if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    break :blk2 null;
                } orelse return error.InvalidPayload;
                break :blk parsePrReviewOp(op_raw) orelse return error.InvalidPayload;
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

        return self.executePrReviewOp(op, args_obj, raw_input.len);
    }

    fn parsePrReviewOp(raw: []const u8) ?PrReviewOp {
        return pr_review_venom.parseOp(raw);
    }

    fn executePrReviewOp(self: *Session, op: PrReviewOp, args_obj: std.json.ObjectMap, written: usize) !WriteOutcome {
        const tool_name = prReviewStatusToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, running_status);

        const result_payload = self.executePrReviewOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, failed_status);
            const failed_result = try self.buildPrReviewFailureResultJson(op, "invalid_payload", error_message);
            defer self.allocator.free(failed_result);
            try self.setMirroredFileContent(self.pr_review_result_id, self.pr_review_result_alias_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
            defer self.allocator.free(message);
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, failed_status);
        } else {
            const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
            defer self.allocator.free(done_status);
            try self.setMirroredFileContent(self.pr_review_status_id, self.pr_review_status_alias_id, done_status);
        }
        try self.setMirroredFileContent(self.pr_review_result_id, self.pr_review_result_alias_id, result_payload);
        return .{ .written = written };
    }

    fn executePrReviewOpPayload(self: *Session, op: PrReviewOp, args_obj: std.json.ObjectMap) ![]u8 {
        return pr_review_venom.executeOpPayload(self, op, args_obj);
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

    fn prReviewOperationName(op: PrReviewOp) []const u8 {
        return pr_review_venom.operationName(op);
    }

    fn prReviewStatusToolName(op: PrReviewOp) []const u8 {
        return pr_review_venom.statusToolName(op);
    }

    fn seedAgentMissionsNamespace(self: *Session, missions_dir: u32) !void {
        return missions_venom.seedNamespace(self, missions_dir);
    }

    fn seedAgentMissionsNamespaceAt(self: *Session, missions_dir: u32, base_path: []const u8) !void {
        return missions_venom.seedNamespaceAt(self, missions_dir, base_path);
    }

    pub const MissionOp = missions_venom.Op;

    fn handleMissionsNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = switch (special) {
            .missions_create => MissionOp.create,
            .missions_list => MissionOp.list,
            .missions_get => MissionOp.get,
            .missions_heartbeat => MissionOp.heartbeat,
            .missions_checkpoint => MissionOp.checkpoint,
            .missions_bootstrap_contract => MissionOp.bootstrap_contract,
            .missions_invoke_service => MissionOp.invoke_service,
            .missions_recover => MissionOp.recover,
            .missions_request_approval => MissionOp.request_approval,
            .missions_approve => MissionOp.approve,
            .missions_reject => MissionOp.reject,
            .missions_resume => MissionOp.@"resume",
            .missions_block => MissionOp.block,
            .missions_complete => MissionOp.complete,
            .missions_fail => MissionOp.fail,
            .missions_cancel => MissionOp.cancel,
            .missions_invoke => blk: {
                const op_raw = blk2: {
                    if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    break :blk2 null;
                } orelse return error.InvalidPayload;
                break :blk parseMissionOp(op_raw) orelse return error.InvalidPayload;
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
        return self.executeMissionOp(op, args_obj, raw_input.len);
    }

    fn parseMissionOp(raw: []const u8) ?MissionOp {
        return missions_venom.parseOp(raw);
    }

    fn missionToolName(op: MissionOp) []const u8 {
        return missions_venom.statusToolName(op);
    }

    fn missionOperationName(op: MissionOp) []const u8 {
        return missions_venom.operationName(op);
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
        const local_root = self.local_fs_export_root orelse return error.InvalidPayload;
        const trimmed = std.mem.trimRight(u8, absolute_path, "/");
        if (std.mem.eql(u8, trimmed, local_fs_world_prefix)) {
            return self.allocator.dupe(u8, local_root);
        }
        const relative_path = try self.normalizeLocalFsRelativePath(absolute_path);
        defer self.allocator.free(relative_path);
        return std.fs.path.join(self.allocator, &.{ local_root, relative_path });
    }

    pub fn ensureMissionContractDirectory(self: *Session, absolute_path: []const u8) !void {
        const host_path = try self.resolveMissionContractHostPath(absolute_path);
        defer self.allocator.free(host_path);
        ensurePathExists(host_path) catch |err| switch (err) {
            error.PathAlreadyExists,
            error.NotDir,
            error.AccessDenied,
            => return error.InvalidPayload,
            else => return err,
        };
    }

    pub fn writeMissionContractFile(self: *Session, absolute_path: []const u8, content: []const u8) !void {
        const host_path = try self.resolveMissionContractHostPath(absolute_path);
        defer self.allocator.free(host_path);

        const parent = std.fs.path.dirname(host_path) orelse return error.InvalidPayload;
        ensurePathExists(parent) catch |err| switch (err) {
            error.PathAlreadyExists,
            error.NotDir,
            error.AccessDenied,
            => return error.InvalidPayload,
            else => return err,
        };

        const file = if (std.fs.path.isAbsolute(host_path))
            try std.fs.createFileAbsolute(host_path, .{ .truncate = true })
        else
            try std.fs.cwd().createFile(host_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(content);
    }

    fn executeMissionOp(self: *Session, op: MissionOp, args_obj: std.json.ObjectMap, written: usize) !WriteOutcome {
        const tool_name = missionToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, running_status);

        const result_payload = self.executeMissionOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const error_code = switch (err) {
                error.AccessDenied => "forbidden",
                error.NotFound => "mission_not_found",
                else => "invalid_payload",
            };
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, failed_status);
            const failed_result = try self.buildMissionFailureResultJson(op, error_code, error_message);
            defer self.allocator.free(failed_result);
            try self.setMirroredFileContent(self.missions_result_id, self.missions_result_alias_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
            defer self.allocator.free(message);
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
            defer self.allocator.free(failed_status);
            try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, failed_status);
        } else {
            const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
            defer self.allocator.free(done_status);
            try self.setMirroredFileContent(self.missions_status_id, self.missions_status_alias_id, done_status);
        }
        try self.setMirroredFileContent(self.missions_result_id, self.missions_result_alias_id, result_payload);
        return .{ .written = written };
    }

    fn executeMissionOpPayload(self: *Session, op: MissionOp, args_obj: std.json.ObjectMap) ![]u8 {
        return missions_venom.executeOpPayload(self, op, args_obj);
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

    fn buildMissionFailureResultJson(self: *Session, op: MissionOp, code: []const u8, message: []const u8) ![]u8 {
        return missions_venom.buildMissionFailureResultJson(self, op, code, message);
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
            const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("runtime_error", @errorName(err));
            return self.buildServiceInvokeFailureResultJson(normalized.code, normalized.message);
        }
        defer if (responses) |frames| runtime_server_mod.deinitResponseFrames(self.allocator, frames);

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
                    const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent(code, message);
                    return self.buildServiceInvokeFailureResultJson(normalized.code, normalized.message);
                }
            }
        }

        if (content_payload) |payload| {
            if (chat_runtime_job.isInternalRuntimeLoopGuardText(payload)) {
                const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("execution_failed", payload);
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
            const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("runtime_error", @errorName(err));
            return .{ .failure = .{
                .code = try self.allocator.dupe(u8, normalized.code),
                .message = try self.allocator.dupe(u8, normalized.message),
            } };
        };
        defer runtime_server_mod.deinitResponseFrames(self.allocator, frames);

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
                const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent(code, message);
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
        for (self.wait_sources.items) |*source| source.deinit(self.allocator);
        self.wait_sources.deinit(self.allocator);
        self.wait_sources = .{};
    }

    fn clearSignalEvents(self: *Session) void {
        for (self.signal_events.items) |*event| event.deinit(self.allocator);
        self.signal_events.deinit(self.allocator);
        self.signal_events = .{};
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
        const written = raw_input.len;
        const trimmed = std.mem.trim(u8, raw_input, " \t\r\n");
        if (trimmed.len == 0) {
            self.clearWaitSources();
            self.wait_timeout_ms = default_wait_timeout_ms;
            try self.setFileContent(node_id, "{\"paths\":[],\"timeout_ms\":60000}");
            return .{ .written = written };
        }

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, trimmed, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;

        const obj = parsed.value.object;
        const paths_value = obj.get("paths") orelse return error.InvalidPayload;
        if (paths_value != .array or paths_value.array.items.len == 0) return error.InvalidPayload;

        var next_sources = std.ArrayListUnmanaged(WaitSource){};
        errdefer {
            for (next_sources.items) |*source| source.deinit(self.allocator);
            next_sources.deinit(self.allocator);
        }

        for (paths_value.array.items) |entry| {
            if (entry != .string or entry.string.len == 0) return error.InvalidPayload;
            var source = try self.parseWaitSourcePath(entry.string);
            try self.initializeWaitSourceCursor(&source);
            next_sources.append(self.allocator, source) catch |err| {
                source.deinit(self.allocator);
                return err;
            };
        }

        const timeout_ms = blk: {
            if (obj.get("timeout_ms")) |value| {
                if (value != .integer or value.integer < 0) return error.InvalidPayload;
                break :blk value.integer;
            }
            break :blk default_wait_timeout_ms;
        };

        self.clearWaitSources();
        self.wait_sources = next_sources;
        self.wait_timeout_ms = timeout_ms;
        self.wait_event_seq = 1;

        try self.setFileContent(node_id, trimmed);
        if (self.event_next_id != 0) {
            try self.setFileContent(self.event_next_id, "{\"configured\":true,\"waiting\":false}");
        }
        return .{ .written = written };
    }

    fn handleEventSignalWrite(self: *Session, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const written = raw_input.len;
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const type_raw = if (obj.get("event_type")) |value|
            if (value == .string and value.string.len > 0) value.string else return error.InvalidPayload
        else
            return error.InvalidPayload;
        const event_type = parseSignalEventType(type_raw) orelse return error.InvalidPayload;

        const parameter = if (obj.get("parameter")) |value| blk: {
            if (value == .string and value.string.len > 0) break :blk try self.allocator.dupe(u8, value.string);
            if (value == .null) break :blk null;
            return error.InvalidPayload;
        } else null;
        errdefer if (parameter) |value| self.allocator.free(value);

        const payload_json = if (obj.get("payload")) |value|
            try self.renderJsonValue(value)
        else
            null;
        errdefer if (payload_json) |value| self.allocator.free(value);

        if (self.signal_events.items.len >= max_signal_events) {
            var oldest = self.signal_events.orderedRemove(0);
            oldest.deinit(self.allocator);
        }

        const seq = self.next_signal_seq;
        self.next_signal_seq +%= 1;
        if (self.next_signal_seq == 0) self.next_signal_seq = 1;
        try self.signal_events.append(self.allocator, .{
            .seq = seq,
            .event_type = event_type,
            .parameter = parameter,
            .payload_json = payload_json,
            .created_at_ms = std.time.milliTimestamp(),
        });

        try self.setFileContent(node_id, input);
        return .{ .written = written };
    }

    fn parseSignalEventType(raw: []const u8) ?SignalEventType {
        if (std.ascii.eqlIgnoreCase(raw, "user")) return .user;
        if (std.ascii.eqlIgnoreCase(raw, "agent")) return .agent;
        if (std.ascii.eqlIgnoreCase(raw, "hook")) return .hook;
        return null;
    }

    fn signalEventTypeName(kind: SignalEventType) []const u8 {
        return switch (kind) {
            .user => "user",
            .agent => "agent",
            .hook => "hook",
        };
    }

    fn parseWaitSourcePath(self: *Session, path: []const u8) !WaitSource {
        inline for ([_][]const u8{
            "/global/chat/control/input",
            "/nodes/local/venoms/chat/control/input",
            "/services/chat/control/input",
        }) |candidate| {
            if (std.mem.eql(u8, path, candidate) or std.mem.endsWith(u8, path, candidate)) {
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .chat_input,
                };
            }
        }

        inline for ([_][]const u8{
            "/global/events/sources/agent.json",
            "/nodes/local/venoms/events/sources/agent.json",
            "/services/events/sources/agent.json",
        }) |candidate| {
            if (std.mem.eql(u8, path, candidate) or std.mem.endsWith(u8, path, candidate)) {
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .agent_signal,
                };
            }
        }
        inline for ([_][]const u8{
            "/global/events/sources/hook.json",
            "/nodes/local/venoms/events/sources/hook.json",
            "/services/events/sources/hook.json",
        }) |candidate| {
            if (std.mem.eql(u8, path, candidate) or std.mem.endsWith(u8, path, candidate)) {
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .hook_signal,
                };
            }
        }
        inline for ([_][]const u8{
            "/global/events/sources/user.json",
            "/nodes/local/venoms/events/sources/user.json",
            "/services/events/sources/user.json",
        }) |candidate| {
            if (std.mem.eql(u8, path, candidate) or std.mem.endsWith(u8, path, candidate)) {
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .user_signal,
                };
            }
        }
        inline for ([_][]const u8{
            "/global/events/sources/agent/",
            "/nodes/local/venoms/events/sources/agent/",
            "/services/events/sources/agent/",
        }) |marker| {
            if (std.mem.indexOf(u8, path, marker)) |prefix_index| {
                const token = path[prefix_index + marker.len ..];
                const parameter = try self.parseWaitSelectorToken(token);
                errdefer self.allocator.free(parameter);
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .agent_signal,
                    .parameter = parameter,
                };
            }
        }
        inline for ([_][]const u8{
            "/global/events/sources/hook/",
            "/nodes/local/venoms/events/sources/hook/",
            "/services/events/sources/hook/",
        }) |marker| {
            if (std.mem.indexOf(u8, path, marker)) |prefix_index| {
                const token = path[prefix_index + marker.len ..];
                const parameter = try self.parseWaitSelectorToken(token);
                errdefer self.allocator.free(parameter);
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .hook_signal,
                    .parameter = parameter,
                };
            }
        }
        inline for ([_][]const u8{
            "/global/events/sources/user/",
            "/nodes/local/venoms/events/sources/user/",
            "/services/events/sources/user/",
        }) |marker| {
            if (std.mem.indexOf(u8, path, marker)) |prefix_index| {
                const token = path[prefix_index + marker.len ..];
                const parameter = try self.parseWaitSelectorToken(token);
                errdefer self.allocator.free(parameter);
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .user_signal,
                    .parameter = parameter,
                };
            }
        }
        inline for ([_][]const u8{
            "/global/events/sources/time/after/",
            "/nodes/local/venoms/events/sources/time/after/",
            "/services/events/sources/time/after/",
        }) |marker| {
            if (std.mem.indexOf(u8, path, marker)) |prefix_index| {
                const token = path[prefix_index + marker.len ..];
                const delay_ms = try self.parseWaitSelectorMillis(token);
                const target_time_ms = std.math.add(i64, std.time.milliTimestamp(), delay_ms) catch return error.InvalidPayload;
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .time_after,
                    .target_time_ms = target_time_ms,
                };
            }
        }
        inline for ([_][]const u8{
            "/global/events/sources/time/at/",
            "/nodes/local/venoms/events/sources/time/at/",
            "/services/events/sources/time/at/",
        }) |marker| {
            if (std.mem.indexOf(u8, path, marker)) |prefix_index| {
                const token = path[prefix_index + marker.len ..];
                const target_ms = try self.parseWaitSelectorMillis(token);
                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = .time_at,
                    .target_time_ms = target_ms,
                };
            }
        }

        inline for ([_][]const u8{
            "/global/jobs/",
            "/nodes/local/venoms/jobs/",
            "/services/jobs/",
        }) |prefix| {
            if (std.mem.indexOf(u8, path, prefix)) |prefix_index| {
                const tail = path[prefix_index + prefix.len ..];
                var tokens = std.mem.tokenizeScalar(u8, tail, '/');
                const job_id = tokens.next() orelse return error.InvalidPayload;
                const leaf = tokens.next() orelse return error.InvalidPayload;
                if (tokens.next() != null) return error.InvalidPayload;

                const kind: WaitSourceKind = if (std.mem.eql(u8, leaf, "status.json"))
                    .job_status
                else if (std.mem.eql(u8, leaf, "result.txt"))
                    .job_result
                else
                    return error.InvalidPayload;

                return .{
                    .raw_path = try self.allocator.dupe(u8, path),
                    .kind = kind,
                    .job_id = try self.allocator.dupe(u8, job_id),
                };
            }
        }

        return error.InvalidPayload;
    }

    fn parseWaitSelectorToken(self: *Session, raw: []const u8) ![]u8 {
        var token = raw;
        if (std.mem.endsWith(u8, token, ".json")) token = token[0 .. token.len - ".json".len];
        if (token.len == 0) return error.InvalidPayload;
        if (std.mem.indexOfScalar(u8, token, '/')) |_| return error.InvalidPayload;
        return self.allocator.dupe(u8, token);
    }

    fn parseWaitSelectorMillis(self: *Session, raw: []const u8) !i64 {
        var token = raw;
        if (std.mem.endsWith(u8, token, ".json")) token = token[0 .. token.len - ".json".len];
        if (token.len == 0) return error.InvalidPayload;
        const value = std.fmt.parseInt(i64, token, 10) catch return error.InvalidPayload;
        if (value < 0) return error.InvalidPayload;
        _ = self;
        return value;
    }

    fn initializeWaitSourceCursor(self: *Session, source: *WaitSource) !void {
        source.last_seen_updated_at_ms = 0;
        switch (source.kind) {
            .chat_input => {
                source.last_seen_job_event_seq = try self.job_index.latestTerminalEventSeqForAgent(self.agent_id);
            },
            .job_status, .job_result => {
                const job_id = source.job_id orelse return;
                const view = try self.job_index.getJob(self.allocator, job_id);
                if (view) |owned| {
                    var job = owned;
                    defer job.deinit(self.allocator);
                    source.last_seen_updated_at_ms = job.updated_at_ms;
                }
            },
            .time_after, .time_at => {},
            .agent_signal, .hook_signal, .user_signal => {
                source.last_seen_signal_seq = if (self.signal_events.items.len == 0)
                    0
                else
                    self.signal_events.items[self.signal_events.items.len - 1].seq;
            },
        }
    }

    fn handleEventNextRead(self: *Session) ![]u8 {
        if (self.wait_sources.items.len == 0) {
            return self.allocator.dupe(
                u8,
                "{\"configured\":false,\"waiting\":false,\"error\":\"wait_not_configured\"}",
            );
        }

        const timeout_ms = if (self.wait_timeout_ms < 0) default_wait_timeout_ms else self.wait_timeout_ms;
        const start_ms = std.time.milliTimestamp();
        while (true) {
            if (try self.pollWaitSources()) |candidate| {
                var source = &self.wait_sources.items[candidate.source_index];
                if (candidate.next_last_seen_updated_at_ms) |value| source.last_seen_updated_at_ms = value;
                if (candidate.next_last_seen_job_event_seq) |value| source.last_seen_job_event_seq = value;
                if (candidate.next_last_seen_signal_seq) |value| source.last_seen_signal_seq = value;
                return candidate.payload_json;
            }

            if (timeout_ms == 0) break;
            const elapsed_ms = std.time.milliTimestamp() - start_ms;
            if (elapsed_ms >= timeout_ms) break;
            const remaining_ms = timeout_ms - elapsed_ms;
            const poll_ms = @as(i64, @intCast(wait_poll_interval_ms));
            const sleep_ms = if (remaining_ms < poll_ms) remaining_ms else poll_ms;
            std.Thread.sleep(@as(u64, @intCast(sleep_ms)) * std.time.ns_per_ms);
        }

        const waited_ms = std.time.milliTimestamp() - start_ms;
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"configured\":true,\"waiting\":true,\"timeout\":true,\"waited_ms\":{d}}}",
            .{waited_ms},
        );
    }

    fn pollWaitSources(self: *Session) !?WaitCandidate {
        var best: ?WaitCandidate = null;
        errdefer if (best) |*candidate| candidate.deinit(self.allocator);

        for (self.wait_sources.items, 0..) |source, source_index| {
            if (try self.buildWaitCandidate(source, source_index)) |candidate| {
                if (best) |*current| {
                    if (candidate.sort_key_ms < current.sort_key_ms) {
                        current.deinit(self.allocator);
                        best = candidate;
                    } else {
                        var drop = candidate;
                        drop.deinit(self.allocator);
                    }
                } else {
                    best = candidate;
                }
            }
        }
        return best;
    }

    fn buildWaitCandidate(self: *Session, source: WaitSource, source_index: usize) !?WaitCandidate {
        return switch (source.kind) {
            .job_status, .job_result => self.buildJobPathCandidate(source, source_index),
            .chat_input => self.buildChatInputCandidate(source, source_index),
            .time_after, .time_at => self.buildTimeCandidate(source, source_index),
            .agent_signal, .hook_signal, .user_signal => self.buildSignalCandidate(source, source_index),
        };
    }

    fn buildJobPathCandidate(self: *Session, source: WaitSource, source_index: usize) !?WaitCandidate {
        const job_id = source.job_id orelse return null;
        const owned_view = try self.job_index.getJob(self.allocator, job_id);
        if (owned_view == null) return null;

        var view = owned_view.?;
        errdefer view.deinit(self.allocator);
        if (!std.mem.eql(u8, view.agent_id, self.agent_id)) return null;
        if (!chat_job_index.isTerminalState(view.state)) return null;
        if (view.updated_at_ms <= source.last_seen_updated_at_ms) return null;
        try self.syncThoughtFramesFromJobTelemetry(job_id);

        const event_path = switch (source.kind) {
            .job_status => try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/jobs/{s}/status.json", .{view.job_id}),
            .job_result => try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/jobs/{s}/result.txt", .{view.job_id}),
            else => unreachable,
        };
        defer self.allocator.free(event_path);
        const payload = try job_projection.buildJobWaitEventPayload(
            self.allocator,
            self.nextWaitEventId(),
            source.raw_path,
            event_path,
            view,
        );
        const updated_at_ms = view.updated_at_ms;
        view.deinit(self.allocator);
        return .{
            .source_index = source_index,
            .sort_key_ms = updated_at_ms,
            .payload_json = payload,
            .next_last_seen_updated_at_ms = updated_at_ms,
        };
    }

    fn buildChatInputCandidate(self: *Session, source: WaitSource, source_index: usize) !?WaitCandidate {
        const owned_event = try self.job_index.firstTerminalEventForAgentAfter(
            self.allocator,
            self.agent_id,
            source.last_seen_job_event_seq,
        );
        if (owned_event == null) return null;

        var event = owned_event.?;
        defer event.deinit(self.allocator);
        try self.syncThoughtFramesFromJobTelemetry(event.job_id);

        const event_path = try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/jobs/{s}/status.json", .{event.job_id});
        defer self.allocator.free(event_path);
        const payload = try job_projection.buildTerminalJobWaitEventPayload(
            self.allocator,
            self.nextWaitEventId(),
            source.raw_path,
            event_path,
            event,
        );
        return .{
            .source_index = source_index,
            .sort_key_ms = event.created_at_ms,
            .payload_json = payload,
            .next_last_seen_job_event_seq = event.seq,
        };
    }

    fn buildTimeCandidate(self: *Session, source: WaitSource, source_index: usize) !?WaitCandidate {
        if (source.last_seen_updated_at_ms >= source.target_time_ms) return null;
        const now_ms = std.time.milliTimestamp();
        if (now_ms < source.target_time_ms) return null;
        const payload = try self.buildTimeWaitEventPayload(source.raw_path, source.target_time_ms, now_ms);
        return .{
            .source_index = source_index,
            .sort_key_ms = source.target_time_ms,
            .payload_json = payload,
            .next_last_seen_updated_at_ms = source.target_time_ms,
        };
    }

    fn buildSignalCandidate(self: *Session, source: WaitSource, source_index: usize) !?WaitCandidate {
        const target_type = switch (source.kind) {
            .agent_signal => SignalEventType.agent,
            .hook_signal => SignalEventType.hook,
            .user_signal => SignalEventType.user,
            else => return null,
        };

        var selected: ?*const SignalEvent = null;
        for (self.signal_events.items) |*event| {
            if (event.seq <= source.last_seen_signal_seq) continue;
            if (event.event_type != target_type) continue;
            if (source.parameter) |required| {
                const actual = event.parameter orelse continue;
                if (!std.mem.eql(u8, actual, required)) continue;
            }
            selected = event;
            break;
        }
        if (selected == null) return null;

        const event = selected.?;
        const event_path = switch (source.kind) {
            .agent_signal => if (event.parameter) |value|
                try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/events/sources/agent/{s}.json", .{value})
            else
                try self.allocator.dupe(u8, "/nodes/local/venoms/events/sources/agent.json"),
            .hook_signal => if (event.parameter) |value|
                try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/events/sources/hook/{s}.json", .{value})
            else
                try self.allocator.dupe(u8, "/nodes/local/venoms/events/sources/hook.json"),
            .user_signal => if (event.parameter) |value|
                try std.fmt.allocPrint(self.allocator, "/nodes/local/venoms/events/sources/user/{s}.json", .{value})
            else
                try self.allocator.dupe(u8, "/nodes/local/venoms/events/sources/user.json"),
            else => unreachable,
        };
        defer self.allocator.free(event_path);
        const payload = try self.buildSignalWaitEventPayload(source.raw_path, event_path, event.*);
        return .{
            .source_index = source_index,
            .sort_key_ms = event.created_at_ms,
            .payload_json = payload,
            .next_last_seen_signal_seq = event.seq,
        };
    }

    fn nextWaitEventId(self: *Session) u64 {
        const event_id = self.wait_event_seq;
        self.wait_event_seq +%= 1;
        if (self.wait_event_seq == 0) self.wait_event_seq = 1;
        return event_id;
    }

    fn buildTimeWaitEventPayload(
        self: *Session,
        source_path: []const u8,
        target_ms: i64,
        now_ms: i64,
    ) ![]u8 {
        const source_path_escaped = try unified.jsonEscape(self.allocator, source_path);
        defer self.allocator.free(source_path_escaped);
        const event_id = self.nextWaitEventId();
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"configured\":true,\"waiting\":false,\"event_id\":{d},\"source_path\":\"{s}\",\"event_path\":\"/nodes/local/venoms/events/sources/time\",\"updated_at_ms\":{d},\"time\":{{\"target_ms\":{d},\"now_ms\":{d},\"fired\":true}}}}",
            .{ event_id, source_path_escaped, now_ms, target_ms, now_ms },
        );
    }

    fn buildSignalWaitEventPayload(
        self: *Session,
        source_path: []const u8,
        event_path: []const u8,
        signal: SignalEvent,
    ) ![]u8 {
        const source_path_escaped = try unified.jsonEscape(self.allocator, source_path);
        defer self.allocator.free(source_path_escaped);
        const event_path_escaped = try unified.jsonEscape(self.allocator, event_path);
        defer self.allocator.free(event_path_escaped);
        const type_escaped = try unified.jsonEscape(self.allocator, signalEventTypeName(signal.event_type));
        defer self.allocator.free(type_escaped);
        const parameter_json = if (signal.parameter) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(parameter_json);
        const payload_json = if (signal.payload_json) |value|
            try self.allocator.dupe(u8, value)
        else
            try self.allocator.dupe(u8, "null");
        defer self.allocator.free(payload_json);

        const event_id = self.nextWaitEventId();
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"configured\":true,\"waiting\":false,\"event_id\":{d},\"source_path\":\"{s}\",\"event_path\":\"{s}\",\"updated_at_ms\":{d},\"signal\":{{\"seq\":{d},\"event_type\":\"{s}\",\"parameter\":{s},\"payload\":{s}}}}}",
            .{
                event_id,
                source_path_escaped,
                event_path_escaped,
                signal.created_at_ms,
                signal.seq,
                type_escaped,
                parameter_json,
                payload_json,
            },
        );
    }

    fn refreshJobNodeFromIndex(self: *Session, node_id: u32, special: SpecialKind) !void {
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        const job_dir_id = node.parent orelse return;
        const job_dir = self.nodes.get(job_dir_id) orelse return error.MissingNode;
        const job_id = job_dir.name;
        const owned_view = try self.job_index.getJob(self.allocator, job_id);
        if (owned_view == null) return;

        var view = owned_view.?;
        defer view.deinit(self.allocator);
        if (!std.mem.eql(u8, view.agent_id, self.agent_id)) return;
        try self.syncThoughtFramesFromJobTelemetry(job_id);

        switch (special) {
            .job_status => {
                const status_json = try self.buildJobStatusJson(view.state, view.correlation_id, view.error_text);
                defer self.allocator.free(status_json);
                try self.setFileContent(node_id, status_json);
            },
            .job_result => {
                try self.setFileContent(node_id, view.result_text orelse "");
            },
            .job_log => {
                try self.setFileContent(node_id, view.log_text orelse "");
            },
            else => {},
        }
    }

    fn syncThoughtFramesFromJobTelemetry(self: *Session, job_id: []const u8) !void {
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
        "3. Treat `/global/*` as a compatibility alias when older workflows still reference it.\n" ++
        "4. Read each Venom `README.md`, `SCHEMA.json`, `TEMPLATE.json`, `HOST.json`, and `CAPS.json` before using it.\n" ++
        "5. Use `/services/library` when bound, otherwise `/nodes/local/venoms/library`, for system guides.\n";
}

fn defaultGlobalLibraryTopicServiceDiscovery() []const u8 {
    return "# Venom Discovery\n\n" ++
        "- Node Venoms: `/nodes/<node_id>/venoms/<venom_id>`\n" ++
        "- Local built-in Venoms: `/nodes/local/venoms/<venom_id>`\n" ++
        "- Workspace service namespaces: `/services/<venom_id>`\n" ++
        "- Compatibility aliases: `/global/<venom_id>`\n" ++
        "- Start with `/meta/workspace_services.json`, `/projects/<project_id>/meta/mounted_services.json`, or `/nodes/local/venoms/VENOMS.json`.\n" ++
        "- Service Venoms should expose `TEMPLATE.json` and `HOST.json` alongside `SCHEMA.json`, `OPS.json`, and `STATUS.json`.\n" ++
        "- Common workspace Venoms include: memory, web_search, search_code, terminal, mounts, sub_brains, agents, workspaces.\n";
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
        "Use `/services/memory/control/*.json` when the workspace binds memory, otherwise use `/nodes/local/venoms/memory/control/*.json`, and pass `memory_path` for targeted operations.\n" ++
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
        "Use `/global/agents` for list/create, `/global/sub_brains` for list/upsert/delete, and `/global/workspaces` for list/get/up.\n" ++
        "Mutation operations depend on capability flags and service permissions.\n";
}

fn pathMatchesPrefixBoundary(path: []const u8, prefix: []const u8) bool {
    if (std.mem.eql(u8, path, prefix)) return true;
    if (prefix.len == 0) return false;
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    return path.len > prefix.len and path[prefix.len] == '/';
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

const DelayedJobCompletion = struct {
    job_index: *chat_job_index.ChatJobIndex,
    job_id: []const u8,
    delay_ms: u64,
    result_text: []const u8,
    error_text: ?[]const u8 = null,
    success: bool = true,
};

fn delayedCompleteJob(ctx: *DelayedJobCompletion) void {
    std.Thread.sleep(ctx.delay_ms * std.time.ns_per_ms);
    ctx.job_index.markCompleted(
        ctx.job_id,
        ctx.error_text == null,
        ctx.result_text,
        ctx.error_text,
        "delayed-log",
    ) catch {
        ctx.success = false;
    };
}

test "acheron_session: attach walk open read capability help" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    var attach = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_attach,
        .tag = 1,
        .fid = 1,
    };
    const attach_res = try session.handle(&attach);
    defer allocator.free(attach_res);
    try std.testing.expect(std.mem.indexOf(u8, attach_res, "acheron.r_attach") != null);

    const path = try allocator.alloc([]u8, 3);
    path[0] = try allocator.dupe(u8, "agents");
    path[1] = try allocator.dupe(u8, "self");
    path[2] = try allocator.dupe(u8, "chat");
    defer {
        allocator.free(path[0]);
        allocator.free(path[1]);
        allocator.free(path[2]);
        allocator.free(path);
    }

    var walk = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_walk,
        .tag = 2,
        .fid = 1,
        .newfid = 2,
        .path = path,
    };
    const walk_res = try session.handle(&walk);
    defer allocator.free(walk_res);
    try std.testing.expect(std.mem.indexOf(u8, walk_res, "acheron.r_walk") != null);
}

test "acheron_session: thoughts namespace exposes latest history and status files" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        321,
        322,
        &.{ "agents", "self", "thoughts", "status.json" },
        401,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"count\":0") != null);

    const latest_payload = try protocolReadFile(
        &session,
        allocator,
        323,
        324,
        &.{ "agents", "self", "thoughts", "latest.txt" },
        402,
    );
    defer allocator.free(latest_payload);
    try std.testing.expectEqualStrings("", latest_payload);

    const history_payload = try protocolReadFile(
        &session,
        allocator,
        325,
        326,
        &.{ "agents", "self", "thoughts", "history.ndjson" },
        403,
    );
    defer allocator.free(history_payload);
    try std.testing.expectEqualStrings("", history_payload);
}

test "acheron_session: job log thought frames refresh thoughts namespace once" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    const job_id = try job_index.createJob("default", "corr-thought-sync");
    defer allocator.free(job_id);
    try job_index.markCompleted(
        job_id,
        true,
        "done",
        null,
        "{\"type\":\"agent.thought\",\"source\":\"thinking\",\"round\":1,\"content\":\"drafting test plan\"}\n{\"type\":\"session.receive\",\"content\":\"done\"}\n",
    );

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const job_status_path = [_][]const u8{ "agents", "self", "jobs", job_id, "status.json" };
    const status_payload = try protocolReadFile(&session, allocator, 341, 342, job_status_path[0..], 451);
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"done\"") != null);

    const latest_payload = try protocolReadFile(
        &session,
        allocator,
        343,
        344,
        &.{ "agents", "self", "thoughts", "latest.txt" },
        452,
    );
    defer allocator.free(latest_payload);
    try std.testing.expectEqualStrings("drafting test plan", latest_payload);

    const history_payload = try protocolReadFile(
        &session,
        allocator,
        345,
        346,
        &.{ "agents", "self", "thoughts", "history.ndjson" },
        453,
    );
    defer allocator.free(history_payload);
    try std.testing.expect(std.mem.indexOf(u8, history_payload, "\"content\":\"drafting test plan\"") != null);

    const thought_status_payload = try protocolReadFile(
        &session,
        allocator,
        347,
        348,
        &.{ "agents", "self", "thoughts", "status.json" },
        454,
    );
    defer allocator.free(thought_status_payload);
    try std.testing.expect(std.mem.indexOf(u8, thought_status_payload, "\"count\":1") != null);

    const status_payload_second = try protocolReadFile(&session, allocator, 349, 350, job_status_path[0..], 455);
    defer allocator.free(status_payload_second);
    try std.testing.expect(std.mem.indexOf(u8, status_payload_second, "\"state\":\"done\"") != null);

    const thought_status_payload_second = try protocolReadFile(
        &session,
        allocator,
        351,
        352,
        &.{ "agents", "self", "thoughts", "status.json" },
        456,
    );
    defer allocator.free(thought_status_payload_second);
    try std.testing.expect(std.mem.indexOf(u8, thought_status_payload_second, "\"count\":1") != null);
}

test "acheron_session: admin debug stream logs runtime frames as synthetic debug events" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "agent-debug-admin",
        .{
            .is_admin = true,
        },
    );
    defer session.deinit();

    try session.recordRuntimeFrameForDebug(
        "req-1",
        "{\"type\":\"session.receive\",\"content\":\"hello\"}",
    );

    const stream_log = try protocolReadFile(
        &session,
        allocator,
        301,
        302,
        &.{ "debug", "stream.log" },
        301,
    );
    defer allocator.free(stream_log);
    try std.testing.expect(std.mem.indexOf(u8, stream_log, "\"category\":\"runtime.frame\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stream_log, "\"frame_type\":\"session.receive\"") != null);
}

test "acheron_session: debug stream ingests debug.event lines from completed job logs" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    try Session.appendDebugEventsFromLogText(allocator, &control_plane, "agent-debug-admin",
        \\{"type":"agent.thought","content":"draft"}
        \\{"type":"debug.event","timestamp":123,"category":"wasm.fixture","payload":{"message":"hello"}}
        \\not-json
    );

    const snapshot = try control_plane.snapshotDebugStream(allocator, "agent-debug-admin");
    defer allocator.free(snapshot);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"type\":\"debug.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"category\":\"wasm.fixture\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "\"type\":\"agent.thought\"") == null);
}

test "acheron_session: events wait returns next completed chat job" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        80,
        81,
        &.{ "agents", "self", "events", "control", "wait.json" },
        "{\"paths\":[\"/global/chat/control/input\"],\"timeout_ms\":2000}",
        700,
    );

    try protocolWriteFile(
        &session,
        allocator,
        82,
        83,
        &.{ "agents", "self", "chat", "control", "input" },
        "event wait smoke",
        710,
    );

    const next_payload = try protocolReadFile(
        &session,
        allocator,
        84,
        85,
        &.{ "agents", "self", "events", "next.json" },
        720,
    );
    defer allocator.free(next_payload);

    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"configured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"source_path\":\"/global/chat/control/input\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_path\":\"/nodes/local/venoms/jobs/job-") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"job_id\":\"job-") != null);
}

test "acheron_session: events wait reports timeout when no source event is available" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        90,
        91,
        &.{ "agents", "self", "events", "control", "wait.json" },
        "{\"paths\":[\"/nodes/local/venoms/jobs/job-missing/status.json\"],\"timeout_ms\":0}",
        730,
    );

    const next_payload = try protocolReadFile(
        &session,
        allocator,
        92,
        93,
        &.{ "agents", "self", "events", "next.json" },
        740,
    );
    defer allocator.free(next_payload);

    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"timeout\":true") != null);
}

test "acheron_session: events wait supports time source selectors" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        94,
        95,
        &.{ "agents", "self", "events", "control", "wait.json" },
        "{\"paths\":[\"/nodes/local/venoms/events/sources/time/after/0.json\"],\"timeout_ms\":0}",
        745,
    );

    const next_payload = try protocolReadFile(
        &session,
        allocator,
        96,
        97,
        &.{ "agents", "self", "events", "next.json" },
        746,
    );
    defer allocator.free(next_payload);

    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"configured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_path\":\"/nodes/local/venoms/events/sources/time\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"time\":{") != null);
}

test "acheron_session: events wait supports agent signal source selectors" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        98,
        99,
        &.{ "agents", "self", "events", "control", "wait.json" },
        "{\"paths\":[\"/global/events/sources/agent/build.json\"],\"timeout_ms\":0}",
        747,
    );
    try protocolWriteFile(
        &session,
        allocator,
        100,
        101,
        &.{ "agents", "self", "events", "control", "signal.json" },
        "{\"event_type\":\"agent\",\"parameter\":\"build\",\"payload\":{\"status\":\"ok\"}}",
        748,
    );

    const next_payload = try protocolReadFile(
        &session,
        allocator,
        102,
        103,
        &.{ "agents", "self", "events", "next.json" },
        749,
    );
    defer allocator.free(next_payload);

    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"configured\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_type\":\"agent\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"parameter\":\"build\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"payload\":{\"status\":\"ok\"}") != null);
}

test "acheron_session: job status read returns current state without waiting for terminal state" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    const job_id = try job_index.createJob("default", "corr-blocking-status");
    defer allocator.free(job_id);
    try job_index.markRunning(job_id);

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();
    session.wait_timeout_ms = 2_000;

    var delayed = DelayedJobCompletion{
        .job_index = &job_index,
        .job_id = job_id,
        .delay_ms = 800,
        .result_text = "status-ready",
    };
    const worker = try std.Thread.spawn(.{}, delayedCompleteJob, .{&delayed});
    defer worker.join();

    const start_ms = std.time.milliTimestamp();
    var status_segments = [_][]const u8{ "agents", "self", "jobs", job_id, "status.json" };
    const status_payload = try protocolReadFile(
        &session,
        allocator,
        94,
        95,
        &status_segments,
        750,
    );
    defer allocator.free(status_payload);
    const elapsed_ms = std.time.milliTimestamp() - start_ms;

    try std.testing.expect(delayed.success);
    try std.testing.expect(elapsed_ms < 250);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"running\"") != null);
}

test "acheron_session: blocking read on job result waits for terminal payload" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    const job_id = try job_index.createJob("default", "corr-blocking-result");
    defer allocator.free(job_id);
    try job_index.markRunning(job_id);

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();
    session.wait_timeout_ms = 2_000;

    var delayed = DelayedJobCompletion{
        .job_index = &job_index,
        .job_id = job_id,
        .delay_ms = 200,
        .result_text = "delayed-result-text",
    };
    const worker = try std.Thread.spawn(.{}, delayedCompleteJob, .{&delayed});
    defer worker.join();

    const start_ms = std.time.milliTimestamp();
    var result_segments = [_][]const u8{ "agents", "self", "jobs", job_id, "result.txt" };
    const result_payload = try protocolReadFile(
        &session,
        allocator,
        96,
        97,
        &result_segments,
        760,
    );
    defer allocator.free(result_payload);
    const elapsed_ms = std.time.milliTimestamp() - start_ms;

    try std.testing.expect(delayed.success);
    try std.testing.expect(elapsed_ms >= 120);
    try std.testing.expectEqualStrings("delayed-result-text", result_payload);
}

test "acheron_session: debug pairing queue supports refresh approve deny actions" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const req_a_json = try control_plane.nodeJoinRequest(
        "{\"node_name\":\"desk-a\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\",\"platform\":{\"os\":\"linux\",\"arch\":\"amd64\",\"runtime_kind\":\"native\"}}",
    );
    defer allocator.free(req_a_json);
    var req_a = try std.json.parseFromSlice(std.json.Value, allocator, req_a_json, .{});
    defer req_a.deinit();
    if (req_a.value != .object) return error.TestExpectedResponse;
    const request_a = req_a.value.object.get("request_id") orelse return error.TestExpectedResponse;
    if (request_a != .string) return error.TestExpectedResponse;

    const req_b_json = try control_plane.nodeJoinRequest(
        "{\"node_name\":\"desk-b\",\"fs_url\":\"ws://127.0.0.1:28891/v2/fs\",\"platform\":{\"os\":\"windows\",\"arch\":\"amd64\",\"runtime_kind\":\"native\"}}",
    );
    defer allocator.free(req_b_json);
    var req_b = try std.json.parseFromSlice(std.json.Value, allocator, req_b_json, .{});
    defer req_b.deinit();
    if (req_b.value != .object) return error.TestExpectedResponse;
    const request_b = req_b.value.object.get("request_id") orelse return error.TestExpectedResponse;
    if (request_b != .string) return error.TestExpectedResponse;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "mother", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "mother",
        .{
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const debug_root = session.lookupChild(session.root_id, "debug") orelse return error.TestExpectedResponse;
    const pairing_dir = session.lookupChild(debug_root, "pairing") orelse return error.TestExpectedResponse;
    const pending_id = session.lookupChild(pairing_dir, "pending.json") orelse return error.TestExpectedResponse;
    const last_result_id = session.lookupChild(pairing_dir, "last_result.json") orelse return error.TestExpectedResponse;
    const last_error_id = session.lookupChild(pairing_dir, "last_error.json") orelse return error.TestExpectedResponse;
    const pending_before = session.nodes.get(pending_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, pending_before.content, request_a.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, pending_before.content, request_b.string) != null);

    const escaped_request_a = try unified.jsonEscape(allocator, request_a.string);
    defer allocator.free(escaped_request_a);
    const approve_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"request_id\":\"{s}\",\"lease_ttl_ms\":900000}}",
        .{escaped_request_a},
    );
    defer allocator.free(approve_payload);
    try protocolWriteFile(
        &session,
        allocator,
        40,
        41,
        &.{ "debug", "pairing", "control", "approve.json" },
        approve_payload,
        400,
    );

    const pending_after_approve = session.nodes.get(pending_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, pending_after_approve.content, request_a.string) == null);
    try std.testing.expect(std.mem.indexOf(u8, pending_after_approve.content, request_b.string) != null);

    const last_result_after_approve = session.nodes.get(last_result_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_approve.content, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_approve.content, "\"action\":\"approve\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_approve.content, "\"node_name\":\"desk-a\"") != null);
    const last_error_after_approve = session.nodes.get(last_error_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.eql(u8, last_error_after_approve.content, "null"));

    const req_c_json = try control_plane.nodeJoinRequest(
        "{\"node_name\":\"desk-c\",\"fs_url\":\"ws://127.0.0.1:38891/v2/fs\",\"platform\":{\"os\":\"android\",\"arch\":\"arm64\",\"runtime_kind\":\"mobile\"}}",
    );
    defer allocator.free(req_c_json);
    var req_c = try std.json.parseFromSlice(std.json.Value, allocator, req_c_json, .{});
    defer req_c.deinit();
    if (req_c.value != .object) return error.TestExpectedResponse;
    const request_c = req_c.value.object.get("request_id") orelse return error.TestExpectedResponse;
    if (request_c != .string) return error.TestExpectedResponse;

    try protocolWriteFile(
        &session,
        allocator,
        42,
        43,
        &.{ "debug", "pairing", "control", "refresh" },
        "{}",
        410,
    );

    const pending_after_refresh = session.nodes.get(pending_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, pending_after_refresh.content, request_b.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, pending_after_refresh.content, request_c.string) != null);

    const escaped_request_b = try unified.jsonEscape(allocator, request_b.string);
    defer allocator.free(escaped_request_b);
    const deny_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"request_id\":\"{s}\"}}",
        .{escaped_request_b},
    );
    defer allocator.free(deny_payload);
    try protocolWriteFile(
        &session,
        allocator,
        44,
        45,
        &.{ "debug", "pairing", "control", "deny.json" },
        deny_payload,
        420,
    );

    const pending_after_deny = session.nodes.get(pending_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, pending_after_deny.content, request_b.string) == null);
    try std.testing.expect(std.mem.indexOf(u8, pending_after_deny.content, request_c.string) != null);

    const last_result_after_deny = session.nodes.get(last_result_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_deny.content, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_deny.content, "\"action\":\"deny\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_deny.content, "\"denied\":true") != null);

    try protocolWriteFile(
        &session,
        allocator,
        46,
        47,
        &.{ "debug", "pairing", "control", "deny.json" },
        deny_payload,
        430,
    );
    const last_error_after_repeat_deny = session.nodes.get(last_error_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_error_after_repeat_deny.content, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_error_after_repeat_deny.content, "\"action\":\"deny\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_error_after_repeat_deny.content, "PendingJoinNotFound") != null);
}

test "acheron_session: debug pairing approve requires operator token when configured" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const req_json = try control_plane.nodeJoinRequest(
        "{\"node_name\":\"desk-auth\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\",\"platform\":{\"os\":\"linux\",\"arch\":\"amd64\",\"runtime_kind\":\"native\"}}",
    );
    defer allocator.free(req_json);
    var req = try std.json.parseFromSlice(std.json.Value, allocator, req_json, .{});
    defer req.deinit();
    if (req.value != .object) return error.TestExpectedResponse;
    const request = req.value.object.get("request_id") orelse return error.TestExpectedResponse;
    if (request != .string) return error.TestExpectedResponse;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "mother", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "mother",
        .{
            .control_plane = &control_plane,
            .control_operator_token = "operator-secret",
        },
    );
    defer session.deinit();

    const debug_root = session.lookupChild(session.root_id, "debug") orelse return error.TestExpectedResponse;
    const pairing_dir = session.lookupChild(debug_root, "pairing") orelse return error.TestExpectedResponse;
    const pending_id = session.lookupChild(pairing_dir, "pending.json") orelse return error.TestExpectedResponse;
    const last_result_id = session.lookupChild(pairing_dir, "last_result.json") orelse return error.TestExpectedResponse;

    const escaped_request = try unified.jsonEscape(allocator, request.string);
    defer allocator.free(escaped_request);
    const approve_no_token = try std.fmt.allocPrint(
        allocator,
        "{{\"request_id\":\"{s}\",\"lease_ttl_ms\":900000}}",
        .{escaped_request},
    );
    defer allocator.free(approve_no_token);
    try protocolWriteFile(
        &session,
        allocator,
        70,
        71,
        &.{ "debug", "pairing", "control", "approve.json" },
        approve_no_token,
        600,
    );

    const pending_after_denied = session.nodes.get(pending_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, pending_after_denied.content, request.string) != null);
    const last_result_after_denied = session.nodes.get(last_result_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_denied.content, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_denied.content, "OperatorAuthFailed") != null);

    const req_refresh_json = try control_plane.nodeJoinRequest(
        "{\"node_name\":\"desk-refresh\",\"fs_url\":\"ws://127.0.0.1:28891/v2/fs\",\"platform\":{\"os\":\"linux\",\"arch\":\"amd64\",\"runtime_kind\":\"native\"}}",
    );
    defer allocator.free(req_refresh_json);
    var req_refresh = try std.json.parseFromSlice(std.json.Value, allocator, req_refresh_json, .{});
    defer req_refresh.deinit();
    if (req_refresh.value != .object) return error.TestExpectedResponse;
    const refresh_request = req_refresh.value.object.get("request_id") orelse return error.TestExpectedResponse;
    if (refresh_request != .string) return error.TestExpectedResponse;

    try protocolWriteFile(
        &session,
        allocator,
        74,
        75,
        &.{ "debug", "pairing", "control", "refresh" },
        "{}",
        605,
    );

    const pending_after_unauthorized_refresh = session.nodes.get(pending_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, pending_after_unauthorized_refresh.content, refresh_request.string) == null);
    const last_result_after_refresh_denied = session.nodes.get(last_result_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_refresh_denied.content, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_refresh_denied.content, "\"action\":\"refresh\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_refresh_denied.content, "OperatorAuthFailed") != null);

    const approve_with_token = try std.fmt.allocPrint(
        allocator,
        "{{\"request_id\":\"{s}\",\"lease_ttl_ms\":900000,\"operator_token\":\"operator-secret\"}}",
        .{escaped_request},
    );
    defer allocator.free(approve_with_token);
    try protocolWriteFile(
        &session,
        allocator,
        76,
        77,
        &.{ "debug", "pairing", "control", "approve.json" },
        approve_with_token,
        610,
    );

    const pending_after_approved = session.nodes.get(pending_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, pending_after_approved.content, request.string) == null);
    const last_result_after_approved = session.nodes.get(last_result_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_approved.content, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_approved.content, "\"action\":\"approve\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_approved.content, "\"node_name\":\"desk-auth\"") != null);
}

test "acheron_session: debug pairing invites support create and refresh actions" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const invite_seed_json = try control_plane.createNodeInvite("{\"expires_in_ms\":900000}");
    defer allocator.free(invite_seed_json);
    try std.testing.expect(std.mem.indexOf(u8, invite_seed_json, "\"invite_id\":\"invite-1\"") != null);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "mother", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "mother",
        .{
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const debug_root = session.lookupChild(session.root_id, "debug") orelse return error.TestExpectedResponse;
    const pairing_dir = session.lookupChild(debug_root, "pairing") orelse return error.TestExpectedResponse;
    const invites_dir = session.lookupChild(pairing_dir, "invites") orelse return error.TestExpectedResponse;
    const active_id = session.lookupChild(invites_dir, "active.json") orelse return error.TestExpectedResponse;
    const last_result_id = session.lookupChild(invites_dir, "last_result.json") orelse return error.TestExpectedResponse;
    const last_error_id = session.lookupChild(invites_dir, "last_error.json") orelse return error.TestExpectedResponse;
    const active_before = session.nodes.get(active_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, active_before.content, "\"invite_id\":\"invite-1\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        60,
        61,
        &.{ "debug", "pairing", "invites", "control", "create.json" },
        "{\"expires_in_ms\":600000}",
        500,
    );

    const active_after_create = session.nodes.get(active_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, active_after_create.content, "\"invite_id\":\"invite-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, active_after_create.content, "\"invite_id\":\"invite-2\"") != null);
    const last_result_after_create = session.nodes.get(last_result_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_create.content, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_create.content, "\"action\":\"invites_create\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_create.content, "\"invite_token\":\"") != null);
    const last_error_after_create = session.nodes.get(last_error_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.eql(u8, last_error_after_create.content, "null"));

    const invite_external_json = try control_plane.createNodeInvite("{\"expires_in_ms\":300000}");
    defer allocator.free(invite_external_json);
    try std.testing.expect(std.mem.indexOf(u8, invite_external_json, "\"invite_id\":\"invite-3\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        62,
        63,
        &.{ "debug", "pairing", "invites", "control", "refresh" },
        "{}",
        510,
    );

    const active_after_refresh = session.nodes.get(active_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, active_after_refresh.content, "\"invite_id\":\"invite-3\"") != null);
    const last_result_after_refresh = session.nodes.get(last_result_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_refresh.content, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_result_after_refresh.content, "\"action\":\"invites_refresh\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        64,
        65,
        &.{ "debug", "pairing", "invites", "control", "create.json" },
        "{\"expires_in_ms\":-1}",
        520,
    );
    const last_error_after_invalid = session.nodes.get(last_error_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, last_error_after_invalid.content, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_error_after_invalid.content, "\"action\":\"invites_create\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last_error_after_invalid.content, "InvalidPayload") != null);
}

test "acheron_session: setRuntimeBinding reseeds namespace and clears stale state" {
    const allocator = std.testing.allocator;

    const runtime_server_a = try runtime_server_mod.RuntimeServer.create(allocator, "agent-a", .{});
    const runtime_server_b = try runtime_server_mod.RuntimeServer.create(allocator, "agent-b", .{});
    const runtime_handle_a = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server_a);
    defer runtime_handle_a.destroy();
    const runtime_handle_b = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server_b);
    defer runtime_handle_b.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    const job_a = try job_index.createJob("agent-a", "corr-a");
    defer allocator.free(job_a);
    try job_index.markCompleted(job_a, true, "result-a", null, "log-a");
    const job_b = try job_index.createJob("agent-b", "corr-b");
    defer allocator.free(job_b);
    try job_index.markCompleted(job_b, true, "result-b", null, "log-b");

    var session = try Session.init(allocator, runtime_handle_a, &job_index, "agent-a");
    defer session.deinit();

    try std.testing.expect(session.lookupChild(session.jobs_root_id, job_a) != null);
    try std.testing.expect(session.lookupChild(session.jobs_root_id, job_b) == null);

    var attach = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_attach,
        .tag = 11,
        .fid = 77,
    };
    const attach_res = try session.handle(&attach);
    defer allocator.free(attach_res);
    try std.testing.expectEqual(@as(usize, 1), session.fids.count());

    try session.setRuntimeBinding(runtime_handle_b, "agent-b");

    try std.testing.expect(std.mem.eql(u8, session.agent_id, "agent-b"));
    try std.testing.expectEqual(@as(usize, 0), session.fids.count());
    try std.testing.expect(session.lookupChild(session.jobs_root_id, job_a) == null);
    try std.testing.expect(session.lookupChild(session.jobs_root_id, job_b) != null);
}

test "acheron_session: node services namespace exposes service descriptors" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const local_node = session.lookupChild(nodes_root, "local") orelse return error.TestExpectedResponse;
    const node_status = session.lookupChild(local_node, "STATUS.json") orelse return error.TestExpectedResponse;
    const services_root = session.lookupChild(local_node, "venoms") orelse return error.TestExpectedResponse;
    const venoms_root = session.lookupChild(local_node, "venoms") orelse return error.TestExpectedResponse;
    const services_index_id = session.lookupChild(services_root, "VENOMS.json") orelse return error.TestExpectedResponse;
    const venoms_index_id = session.lookupChild(venoms_root, "VENOMS.json") orelse return error.TestExpectedResponse;
    const fs_service = session.lookupChild(services_root, "fs") orelse return error.TestExpectedResponse;
    const fs_venom = session.lookupChild(venoms_root, "fs") orelse return error.TestExpectedResponse;
    const terminal_service = session.lookupChild(services_root, "terminal-1") orelse return error.TestExpectedResponse;

    const fs_status = session.lookupChild(fs_service, "STATUS.json") orelse return error.TestExpectedResponse;
    const fs_caps = session.lookupChild(fs_service, "CAPS.json") orelse return error.TestExpectedResponse;
    const terminal_caps = session.lookupChild(terminal_service, "CAPS.json") orelse return error.TestExpectedResponse;
    const agents_root = session.lookupChild(session.root_id, "agents") orelse return error.TestExpectedResponse;
    const self_agent = session.lookupChild(agents_root, "self") orelse return error.TestExpectedResponse;
    const self_services_dir = session.lookupChild(self_agent, "venoms") orelse return error.TestExpectedResponse;
    const self_services_index_id = session.lookupChild(self_services_dir, "VENOMS.json") orelse return error.TestExpectedResponse;

    const fs_status_node = session.nodes.get(fs_status) orelse return error.TestExpectedResponse;
    const fs_caps_node = session.nodes.get(fs_caps) orelse return error.TestExpectedResponse;
    const terminal_caps_node = session.nodes.get(terminal_caps) orelse return error.TestExpectedResponse;
    const node_status_node = session.nodes.get(node_status) orelse return error.TestExpectedResponse;
    const services_index_node = session.nodes.get(services_index_id) orelse return error.TestExpectedResponse;
    const venoms_index_node = session.nodes.get(venoms_index_id) orelse return error.TestExpectedResponse;
    const self_services_index_node = session.nodes.get(self_services_index_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, node_status_node.content, "\"state\":\"configured\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index_node.content, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index_node.content, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index_node.content, "\"venom_id\":\"terminal-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, venoms_index_node.content, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_status_node.content, "\"state\":\"online\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_status_node.content, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_status_node.content, "/nodes/local/fs") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_caps_node.content, "\"rw\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, terminal_caps_node.content, "\"terminal_id\":\"1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"node_id\":\"local\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"venom_path\":\"/nodes/local/venoms/fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"venom_path\":\"/nodes/local/venoms/fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"has_invoke\":false") != null);
    _ = fs_venom;
}

test "acheron_session: protocol read exposes agent services discovery index" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        100,
        101,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        770,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"node_id\":\"local\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/fs\"") != null);
}

test "acheron_session: agent services index includes first-class namespaces only" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        102,
        103,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        780,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"search_code\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"terminal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"mounts\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"workspaces\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"library\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/search_code\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/mounts\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/workspaces\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/library\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"node_catalog\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"has_invoke\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/venoms/contracts/") == null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"agent_contract\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"has_invoke\":true") != null);
}

test "acheron_session: global venoms index mirrors Venom discovery entries" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        104,
        105,
        &.{ "global", "venoms", "VENOMS.json" },
        781,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"chat\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/chat/control/input\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"events\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/events/control/wait.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"endpoint_path\":\"/nodes/local/fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"provider_node_id\":\"local\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"provider_venom_path\":\"/nodes/local/venoms/fs\"") != null);
}

test "acheron_session: control-plane preferred fs provider drives global fs binding" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const local_joined = try control_plane.ensureNode("spiderweb-local", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(local_joined);
    var local_parsed = try std.json.parseFromSlice(std.json.Value, allocator, local_joined, .{});
    defer local_parsed.deinit();
    const local_node_id = local_parsed.value.object.get("node_id").?.string;
    const local_node_secret = local_parsed.value.object.get("node_secret").?.string;

    const remote_joined = try control_plane.ensureNode("edge-remote", "ws://127.0.0.1:28891/v2/fs", 60_000);
    defer allocator.free(remote_joined);
    var remote_parsed = try std.json.parseFromSlice(std.json.Value, allocator, remote_joined, .{});
    defer remote_parsed.deinit();
    const remote_node_id = remote_parsed.value.object.get("node_id").?.string;
    const remote_node_secret = remote_parsed.value.object.get("node_secret").?.string;

    const local_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fs\"],\"capabilities\":{{\"rw\":true}},\"mounts\":[{{\"mount_id\":\"fs\",\"mount_path\":\"/nodes/{s}/fs\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}}}}]}}",
        .{ local_node_id, local_node_secret, local_node_id, local_node_id },
    );
    defer allocator.free(local_upsert);
    const local_upserted = try control_plane.nodeVenomUpsert(local_upsert);
    defer allocator.free(local_upserted);

    const remote_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fs\"],\"capabilities\":{{\"rw\":true}},\"mounts\":[{{\"mount_id\":\"fs\",\"mount_path\":\"/nodes/{s}/fs\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}}}}]}}",
        .{ remote_node_id, remote_node_secret, remote_node_id, remote_node_id },
    );
    defer allocator.free(remote_upsert);
    const remote_upserted = try control_plane.nodeVenomUpsert(remote_upsert);
    defer allocator.free(remote_upserted);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
        },
    );
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        204,
        205,
        &.{ "global", "venoms", "VENOMS.json" },
        781,
    );
    defer allocator.free(payload);

    const expected_endpoint = try std.fmt.allocPrint(allocator, "\"endpoint_path\":\"/nodes/{s}/fs\"", .{local_node_id});
    defer allocator.free(expected_endpoint);
    const expected_provider_node = try std.fmt.allocPrint(allocator, "\"provider_node_id\":\"{s}\"", .{local_node_id});
    defer allocator.free(expected_provider_node);
    const expected_provider_path = try std.fmt.allocPrint(allocator, "\"provider_venom_path\":\"/nodes/{s}/venoms/fs\"", .{local_node_id});
    defer allocator.free(expected_provider_path);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, expected_endpoint) != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, expected_provider_node) != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, expected_provider_path) != null);
}

test "acheron_session: agent and project venoms indexes surface scoped bindings" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const local_joined = try control_plane.ensureNode("spiderweb-local", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(local_joined);
    var local_parsed = try std.json.parseFromSlice(std.json.Value, allocator, local_joined, .{});
    defer local_parsed.deinit();
    const local_node_id = local_parsed.value.object.get("node_id").?.string;
    const local_node_secret = local_parsed.value.object.get("node_secret").?.string;

    const app_joined = try control_plane.ensureNode("spiderapp-default", "", 60_000);
    defer allocator.free(app_joined);
    var app_parsed = try std.json.parseFromSlice(std.json.Value, allocator, app_joined, .{});
    defer app_parsed.deinit();
    const app_node_id = app_parsed.value.object.get("node_id").?.string;
    const app_node_secret = app_parsed.value.object.get("node_secret").?.string;

    const local_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"chat\",\"kind\":\"chat\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/chat\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"chat\",\"mount_path\":\"/nodes/{s}/chat\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"invoke\":\"control/input\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-chat-v1\"}}}},{{\"venom_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fs\"],\"capabilities\":{{\"rw\":true}},\"mounts\":[{{\"mount_id\":\"fs\",\"mount_path\":\"/nodes/{s}/fs\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}}}}]}}",
        .{ local_node_id, local_node_secret, local_node_id, local_node_id, local_node_id, local_node_id },
    );
    defer allocator.free(local_upsert);
    _ = try control_plane.nodeVenomUpsert(local_upsert);

    const app_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"chat\",\"kind\":\"chat\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/chat\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"chat\",\"mount_path\":\"/nodes/{s}/chat\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"invoke\":\"control/input\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-chat-v1\"}}}},{{\"venom_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fs\"],\"capabilities\":{{\"rw\":true}},\"mounts\":[{{\"mount_id\":\"fs\",\"mount_path\":\"/nodes/{s}/fs\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}}}}]}}",
        .{ app_node_id, app_node_secret, app_node_id, app_node_id, app_node_id, app_node_id },
    );
    defer allocator.free(app_upsert);
    _ = try control_plane.nodeVenomUpsert(app_upsert);

    const bind_project = try std.fmt.allocPrint(
        allocator,
        "{{\"venom_id\":\"chat\",\"scope\":\"project\",\"project_id\":\"{s}\",\"node_id\":\"{s}\"}}",
        .{ control_plane_mod.spider_web_project_id, app_node_id },
    );
    defer allocator.free(bind_project);
    _ = try control_plane.bindPreferredVenomProvider(bind_project);

    const bind_agent = try std.fmt.allocPrint(
        allocator,
        "{{\"venom_id\":\"chat\",\"scope\":\"agent\",\"agent_id\":\"default\",\"node_id\":\"{s}\"}}",
        .{local_node_id},
    );
    defer allocator.free(bind_agent);
    _ = try control_plane.bindPreferredVenomProvider(bind_agent);

    const bind_global_fs = try std.fmt.allocPrint(
        allocator,
        "{{\"venom_id\":\"fs\",\"scope\":\"global\",\"node_id\":\"{s}\"}}",
        .{app_node_id},
    );
    defer allocator.free(bind_global_fs);
    _ = try control_plane.bindPreferredVenomProvider(bind_global_fs);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .project_id = control_plane_mod.spider_web_project_id,
        },
    );
    defer session.deinit();

    const agent_payload = try protocolReadFile(
        &session,
        allocator,
        304,
        305,
        &.{ "agents", "default", "venoms", "VENOMS.json" },
        781,
    );
    defer allocator.free(agent_payload);
    const expected_agent_provider = try std.fmt.allocPrint(allocator, "\"provider_node_id\":\"{s}\"", .{local_node_id});
    defer allocator.free(expected_agent_provider);
    try std.testing.expect(std.mem.indexOf(u8, agent_payload, "\"venom_path\":\"/agents/default/venoms/chat\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agent_payload, expected_agent_provider) != null);

    const project_payload = try protocolReadFile(
        &session,
        allocator,
        306,
        307,
        &.{ "projects", control_plane_mod.spider_web_project_id, "venoms", "VENOMS.json" },
        781,
    );
    defer allocator.free(project_payload);
    const expected_project_provider = try std.fmt.allocPrint(allocator, "\"provider_node_id\":\"{s}\"", .{app_node_id});
    defer allocator.free(expected_project_provider);
    try std.testing.expect(std.mem.indexOf(u8, project_payload, "\"venom_path\":\"/projects/system/venoms/chat\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, project_payload, expected_project_provider) != null);
}

test "acheron_session: scoped venom bindings skip disallowed project nodes" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const local_joined = try control_plane.ensureNode("spiderweb-local", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(local_joined);
    var local_parsed = try std.json.parseFromSlice(std.json.Value, allocator, local_joined, .{});
    defer local_parsed.deinit();
    const local_node_id = local_parsed.value.object.get("node_id").?.string;
    const local_node_secret = local_parsed.value.object.get("node_secret").?.string;

    const app_joined = try control_plane.ensureNode("spiderapp-default", "", 60_000);
    defer allocator.free(app_joined);
    var app_parsed = try std.json.parseFromSlice(std.json.Value, allocator, app_joined, .{});
    defer app_parsed.deinit();
    const app_node_id = app_parsed.value.object.get("node_id").?.string;
    const app_node_secret = app_parsed.value.object.get("node_secret").?.string;

    const local_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"chat\",\"kind\":\"chat\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/chat\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"chat\",\"mount_path\":\"/nodes/{s}/chat\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"invoke\":\"control/input\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-chat-v1\"}}}},{{\"venom_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fs\"],\"capabilities\":{{\"rw\":true}},\"mounts\":[{{\"mount_id\":\"fs\",\"mount_path\":\"/nodes/{s}/fs\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}}}}]}}",
        .{ local_node_id, local_node_secret, local_node_id, local_node_id, local_node_id, local_node_id },
    );
    defer allocator.free(local_upsert);
    _ = try control_plane.nodeVenomUpsert(local_upsert);

    const app_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"chat\",\"kind\":\"chat\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/chat\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"chat\",\"mount_path\":\"/nodes/{s}/chat\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"invoke\":\"control/input\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-chat-v1\"}}}},{{\"venom_id\":\"fs\",\"kind\":\"fs\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fs\"],\"capabilities\":{{\"rw\":true}},\"mounts\":[{{\"mount_id\":\"fs\",\"mount_path\":\"/nodes/{s}/fs\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"builtin\",\"abi\":\"venom-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}}}}]}}",
        .{ app_node_id, app_node_secret, app_node_id, app_node_id, app_node_id, app_node_id },
    );
    defer allocator.free(app_upsert);
    _ = try control_plane.nodeVenomUpsert(app_upsert);

    const project_created = try control_plane.createProject(
        "{\"name\":\"ScopedVenomProject\",\"vision\":\"ScopedVenomProject\",\"access_policy\":{\"actions\":{\"observe\":\"open\"}}}",
    );
    defer allocator.free(project_created);
    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_created, .{});
    defer project_parsed.deinit();
    const project_id_value = project_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_id_value != .string) return error.TestExpectedResponse;
    const project_id = try allocator.dupe(u8, project_id_value.string);
    defer allocator.free(project_id);

    const mount_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"mount_path\":\"/nodes/{s}/fs\",\"node_id\":\"{s}\",\"export_name\":\"fs\"}}",
        .{ project_id, local_node_id, local_node_id },
    );
    defer allocator.free(mount_payload);
    const mount_result = try control_plane.setProjectMountWithRole(mount_payload, true);
    defer allocator.free(mount_result);

    const bind_project = try std.fmt.allocPrint(
        allocator,
        "{{\"venom_id\":\"chat\",\"scope\":\"project\",\"project_id\":\"{s}\",\"node_id\":\"{s}\"}}",
        .{ project_id, app_node_id },
    );
    defer allocator.free(bind_project);
    _ = try control_plane.bindPreferredVenomProvider(bind_project);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .project_id = project_id,
        },
    );
    defer session.deinit();

    const project_payload = try protocolReadFile(
        &session,
        allocator,
        308,
        309,
        &.{ "projects", project_id, "venoms", "VENOMS.json" },
        782,
    );
    defer allocator.free(project_payload);
    const expected_provider = try std.fmt.allocPrint(allocator, "\"provider_node_id\":\"{s}\"", .{local_node_id});
    defer allocator.free(expected_provider);
    const forbidden_provider = try std.fmt.allocPrint(allocator, "\"provider_node_id\":\"{s}\"", .{app_node_id});
    defer allocator.free(forbidden_provider);
    try std.testing.expect(std.mem.indexOf(u8, project_payload, expected_provider) != null);
    try std.testing.expect(std.mem.indexOf(u8, project_payload, forbidden_provider) == null);

    var router = (try session.boundVenomRouter("chat", project_id, null)) orelse return error.TestExpectedResponse;
    defer router.deinit();
    try std.testing.expectEqualStrings(local_node_id, router.endpointName(0) orelse return error.TestExpectedResponse);
}

test "acheron_session: scoped venom aliases fail closed without control plane" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    const project_id = "offline-project";
    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .project_id = project_id,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const local_node_dir = try session.addDir(nodes_root, "spiderweb-local", false);
    const venoms_root = try session.addDir(local_node_dir, "venoms", false);
    const chat_dir = try session.addDir(venoms_root, "chat", false);
    _ = try session.addFile(chat_dir, "STATUS.json", "{\"endpoint\":\"/nodes/spiderweb-local/venoms/chat\"}", false, .none);

    const previous_len = session.scoped_venom_bindings.items.len;
    try std.testing.expect(!try session.registerBoundVenomAliasOnly(
        "/projects/offline-project/venoms",
        "chat",
        "project_binding",
        "spiderweb-local",
        project_id,
        null,
    ));
    try std.testing.expectEqual(previous_len, session.scoped_venom_bindings.items.len);
}

test "acheron_session: scoped venom aliases preserve template and host metadata" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const node_dir = try session.addDir(nodes_root, "edge-1", false);
    const venoms_root = try session.addDir(node_dir, "venoms", false);
    const tool_dir = try session.addDir(venoms_root, "tool-main", false);
    _ = try session.addFile(tool_dir, "STATUS.json", "{\"endpoint\":\"/nodes/edge-1/venoms/tool-main\"}", false, .none);
    _ = try session.addFile(tool_dir, "OPS.json", "{\"model\":\"namespace\",\"invoke\":\"control/invoke.json\"}", false, .none);
    _ = try session.addFile(tool_dir, "RUNTIME.json", "{\"type\":\"native_proc\"}", false, .none);
    _ = try session.addFile(tool_dir, "TEMPLATE.json", "{\"tool_name\":\"shell_exec\",\"arguments\":{\"command\":\"pwd\"}}", false, .none);
    _ = try session.addFile(tool_dir, "HOST.json", "{\"runtime_kind\":\"native_proc\"}", false, .none);

    const alias_root = try session.addDir(session.root_id, "alias-tests", false);
    try std.testing.expect(try session.seedBoundNodeVenomNamespaceAt(
        alias_root,
        "/alias-tests",
        "tool-main",
        "global_binding",
        "edge-1",
    ));

    const alias_dir = session.lookupChild(alias_root, "tool-main") orelse return error.TestExpectedResponse;
    const template_id = session.lookupChild(alias_dir, "TEMPLATE.json") orelse return error.TestExpectedResponse;
    const host_id = session.lookupChild(alias_dir, "HOST.json") orelse return error.TestExpectedResponse;
    const template_node = session.nodes.get(template_id) orelse return error.TestExpectedResponse;
    const host_node = session.nodes.get(host_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, template_node.content, "\"shell_exec\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, host_node.content, "\"native_proc\"") != null);
}

test "acheron_session: scoped venom aliases shape proxy paths and job result paths" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .project_id = control_plane_mod.spider_web_project_id,
        },
    );
    defer session.deinit();

    const global_chat_id = session.resolveAbsolutePathNoBinds("/global/chat") orelse return error.TestExpectedResponse;
    const global_result_path = try session.buildJobResultPathForNode(global_chat_id, "job-global");
    defer allocator.free(global_result_path);
    try std.testing.expectEqualStrings("/nodes/local/venoms/jobs/job-global/result.txt", global_result_path);

    const agent_chat_id = session.resolveAbsolutePathNoBinds("/agents/default/venoms/chat") orelse return error.TestExpectedResponse;
    const agent_result_path = try session.buildJobResultPathForNode(agent_chat_id, "job-agent");
    defer allocator.free(agent_result_path);
    try std.testing.expectEqualStrings("/agents/default/venoms/jobs/job-agent/result.txt", agent_result_path);

    const project_chat_id = session.resolveAbsolutePathNoBinds("/projects/system/venoms/chat") orelse return error.TestExpectedResponse;
    const project_result_path = try session.buildJobResultPathForNode(project_chat_id, "job-project");
    defer allocator.free(project_result_path);
    try std.testing.expectEqualStrings("/projects/system/venoms/jobs/job-project/result.txt", project_result_path);

    const parsed_agent = (try session.boundVenomProxyPathForAbsolutePath("/agents/default/venoms/fs/src/main.zig")) orelse return error.TestExpectedResponse;
    defer allocator.free(parsed_agent.remote_path);
    try std.testing.expectEqualStrings("fs", parsed_agent.venom_id);
    try std.testing.expectEqualStrings("default", parsed_agent.agent_id.?);
    try std.testing.expectEqualStrings("/src/main.zig", parsed_agent.remote_path);

    const parsed_project = (try session.boundVenomProxyPathForAbsolutePath("/projects/system/venoms/events/control/wait.json")) orelse return error.TestExpectedResponse;
    defer allocator.free(parsed_project.remote_path);
    try std.testing.expectEqualStrings("events", parsed_project.venom_id);
    try std.testing.expectEqualStrings("system", parsed_project.project_id.?);
    try std.testing.expectEqualStrings("/control/wait.json", parsed_project.remote_path);
}

test "acheron_session: global library namespace exposes index and topic guides" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const index_payload = try protocolReadFile(
        &session,
        allocator,
        104,
        105,
        &.{ "global", "library", "Index.md" },
        781,
    );
    defer allocator.free(index_payload);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, "Spiderweb Global Library") != null);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, "/global/library/topics/getting-started.md") != null);

    const topic_payload = try protocolReadFile(
        &session,
        allocator,
        106,
        107,
        &.{ "global", "library", "topics", "service-discovery.md" },
        782,
    );
    defer allocator.free(topic_payload);
    try std.testing.expect(std.mem.indexOf(u8, topic_payload, "/global/<venom_id>") != null);
    try std.testing.expect(std.mem.indexOf(u8, topic_payload, "VENOMS.json") != null);
}

test "acheron_session: global library loads guides from assets_dir filesystem" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const assets_dir = try std.fmt.allocPrint(allocator, "{s}/assets", .{root});
    defer allocator.free(assets_dir);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);

    const library_topics_dir = try std.fmt.allocPrint(allocator, "{s}/library/topics", .{assets_dir});
    defer allocator.free(library_topics_dir);
    try std.fs.cwd().makePath(library_topics_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(projects_dir);

    const custom_index_path = try std.fmt.allocPrint(allocator, "{s}/library/Index.md", .{assets_dir});
    defer allocator.free(custom_index_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = custom_index_path,
        .data = "# Custom Global Library\n\n- [Custom Topic](topics/custom.md)\n",
    });

    const custom_topic_path = try std.fmt.allocPrint(allocator, "{s}/library/topics/custom.md", .{assets_dir});
    defer allocator.free(custom_topic_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = custom_topic_path,
        .data = "# Custom Topic\n\nThis guide is loaded from assets_dir.\n",
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .assets_dir = assets_dir,
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
        },
    );
    defer session.deinit();

    const index_payload = try protocolReadFile(
        &session,
        allocator,
        108,
        109,
        &.{ "global", "library", "Index.md" },
        783,
    );
    defer allocator.free(index_payload);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, "Custom Global Library") != null);

    const topic_payload = try protocolReadFile(
        &session,
        allocator,
        110,
        111,
        &.{ "global", "library", "topics", "custom.md" },
        784,
    );
    defer allocator.free(topic_payload);
    try std.testing.expect(std.mem.indexOf(u8, topic_payload, "loaded from assets_dir") != null);
}

test "acheron_session: local venom aliases mirror canonical and compatibility writes" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const local_status_id = session.resolveAbsolutePathNoBinds("/nodes/local/venoms/memory/status.json") orelse return error.TestExpectedResponse;
    const global_status_id = session.resolveAbsolutePathNoBinds("/global/memory/status.json") orelse return error.TestExpectedResponse;

    try session.setFileContent(local_status_id, "{\"state\":\"canonical\"}");
    const global_status_after_canonical = session.nodes.get(global_status_id) orelse return error.TestExpectedResponse;
    try std.testing.expectEqualStrings("{\"state\":\"canonical\"}", global_status_after_canonical.content);

    try session.setFileContent(global_status_id, "{\"state\":\"compat\"}");
    const local_status_after_global = session.nodes.get(local_status_id) orelse return error.TestExpectedResponse;
    try std.testing.expectEqualStrings("{\"state\":\"compat\"}", local_status_after_global.content);
}

test "acheron_session: agent services index includes first-class memory namespace entry" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        110,
        111,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        820,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"project_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/nodes/local/venoms/memory/control/invoke.json\"") != null);
}

test "acheron_session: agent services index includes first-class web_search namespace entry" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        132,
        133,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        855,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"project_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/nodes/local/venoms/web_search/control/invoke.json\"") != null);
}

test "acheron_session: agent services index includes first-class terminal namespace entry" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        232,
        233,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        905,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"project_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/terminal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/nodes/local/venoms/terminal/control/invoke.json\"") != null);
}

test "acheron_session: agent services index includes first-class sub_brains namespace entry" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        248,
        249,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        916,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"project_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/sub_brains\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/nodes/local/venoms/sub_brains/control/invoke.json\"") != null);
}

test "acheron_session: agent services index includes first-class agents namespace entry" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        272,
        273,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        926,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"project_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/agents\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/nodes/local/venoms/agents/control/invoke.json\"") != null);
}

test "acheron_session: agent services index includes first-class projects namespace entry" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        272,
        273,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        926,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"project_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/workspaces\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/nodes/local/venoms/workspaces/control/invoke.json\"") != null);
}

test "acheron_session: agent services index includes first-class missions namespace entry" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
        },
    );
    defer session.deinit();

    const payload = try protocolReadFile(
        &session,
        allocator,
        294,
        295,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        936,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"project_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/nodes/local/venoms/missions\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/nodes/local/venoms/missions/control/invoke.json\"") != null);
}

test "acheron_session: missions namespace tracks lifecycle checkpoint and recovery state" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .actor_type = "agent",
            .actor_id = "worker-a",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        296,
        297,
        &.{ "agents", "self", "missions", "control", "create.json" },
        "{\"use_case\":\"pr_review\",\"title\":\"Review PR 15\",\"stage\":\"planning\",\"contract\":{\"contract_id\":\"spider_monkey/pr_review@v1\",\"context_path\":\"/nodes/local/fs/pr-review/state/pr-15/context.json\"}}",
        937,
    );

    const create_result = try protocolReadFile(
        &session,
        allocator,
        298,
        299,
        &.{ "agents", "self", "missions", "result.json" },
        938,
    );
    defer allocator.free(create_result);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"operation\":\"create\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"ok\":true") != null);
    const mission_id = try extractMissionIdFromResultPayload(allocator, create_result);
    defer allocator.free(mission_id);

    const resume_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"stage\":\"collecting_context\",\"contract\":{{\"state_path\":\"/nodes/local/fs/pr-review/state/pr-15/state.json\"}}}}",
        .{mission_id},
    );
    defer allocator.free(resume_payload);
    try protocolWriteFile(
        &session,
        allocator,
        300,
        301,
        &.{ "agents", "self", "missions", "control", "resume.json" },
        resume_payload,
        939,
    );

    const checkpoint_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"stage\":\"reviewing\",\"summary\":\"Scanned changed files\",\"artifact\":{{\"kind\":\"notes\",\"path\":\"artifacts/review.md\",\"summary\":\"review notes\"}},\"contract\":{{\"artifact_root\":\"/nodes/local/fs/pr-review/runs/pr-15\"}}}}",
        .{mission_id},
    );
    defer allocator.free(checkpoint_payload);
    try protocolWriteFile(
        &session,
        allocator,
        302,
        303,
        &.{ "agents", "self", "missions", "control", "checkpoint.json" },
        checkpoint_payload,
        940,
    );

    const recover_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"reason\":\"runtime_restart\",\"stage\":\"restoring_context\",\"summary\":\"Resuming review\"}}",
        .{mission_id},
    );
    defer allocator.free(recover_payload);
    try protocolWriteFile(
        &session,
        allocator,
        304,
        305,
        &.{ "agents", "self", "missions", "control", "recover.json" },
        recover_payload,
        941,
    );

    const get_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\"}}",
        .{mission_id},
    );
    defer allocator.free(get_payload);
    try protocolWriteFile(
        &session,
        allocator,
        306,
        307,
        &.{ "agents", "self", "missions", "control", "get.json" },
        get_payload,
        942,
    );

    const get_result = try protocolReadFile(
        &session,
        allocator,
        308,
        309,
        &.{ "agents", "self", "missions", "result.json" },
        943,
    );
    defer allocator.free(get_result);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"operation\":\"get\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, mission_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"state\":\"recovering\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"checkpoint_seq\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"recovery_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"stage\":\"restoring_context\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"kind\":\"notes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"contract_id\":\"spider_monkey/pr_review@v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"context_path\":\"/nodes/local/fs/pr-review/state/pr-15/context.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"state_path\":\"/nodes/local/fs/pr-review/state/pr-15/state.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"artifact_root\":\"/nodes/local/fs/pr-review/runs/pr-15\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        310,
        311,
        &.{ "agents", "self", "missions", "control", "list.json" },
        "{\"state\":\"recovering\"}",
        944,
    );

    const list_result = try protocolReadFile(
        &session,
        allocator,
        312,
        313,
        &.{ "agents", "self", "missions", "result.json" },
        945,
    );
    defer allocator.free(list_result);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"operation\":\"list\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_result, mission_id) != null);
}

test "acheron_session: missions namespace requires admin approval for resolution" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var user_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .actor_type = "agent",
            .actor_id = "worker-a",
            .is_admin = false,
        },
    );
    defer user_session.deinit();

    try protocolWriteFile(
        &user_session,
        allocator,
        314,
        315,
        &.{ "agents", "self", "missions", "control", "create.json" },
        "{\"use_case\":\"pr_review\",\"title\":\"Review PR 22\"}",
        946,
    );
    const create_result = try protocolReadFile(
        &user_session,
        allocator,
        316,
        317,
        &.{ "agents", "self", "missions", "result.json" },
        947,
    );
    defer allocator.free(create_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, create_result);
    defer allocator.free(mission_id);

    const request_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"action_kind\":\"push_branch\",\"message\":\"Push review branch to origin\"}}",
        .{mission_id},
    );
    defer allocator.free(request_payload);
    try protocolWriteFile(
        &user_session,
        allocator,
        318,
        319,
        &.{ "agents", "self", "missions", "control", "request_approval.json" },
        request_payload,
        948,
    );

    const approve_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"note\":\"ship it\"}}",
        .{mission_id},
    );
    defer allocator.free(approve_payload);
    const approve_error = try protocolWriteFileExpectError(
        &user_session,
        allocator,
        320,
        321,
        &.{ "agents", "self", "missions", "control", "approve.json" },
        approve_payload,
        949,
        "eperm",
    );
    defer allocator.free(approve_error);

    const failed_result = try protocolReadFile(
        &user_session,
        allocator,
        322,
        323,
        &.{ "agents", "self", "missions", "result.json" },
        950,
    );
    defer allocator.free(failed_result);
    try std.testing.expect(std.mem.indexOf(u8, failed_result, "\"code\":\"forbidden\"") != null);

    const admin_runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const admin_runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, admin_runtime_server);
    defer admin_runtime_handle.destroy();
    var admin_job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer admin_job_index.deinit();

    var admin_session = try Session.initWithOptions(
        allocator,
        admin_runtime_handle,
        &admin_job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .actor_type = "admin",
            .actor_id = "operator-1",
            .is_admin = true,
        },
    );
    defer admin_session.deinit();

    try protocolWriteFile(
        &admin_session,
        allocator,
        324,
        325,
        &.{ "agents", "self", "missions", "control", "approve.json" },
        approve_payload,
        951,
    );

    const admin_result = try protocolReadFile(
        &admin_session,
        allocator,
        326,
        327,
        &.{ "agents", "self", "missions", "result.json" },
        952,
    );
    defer allocator.free(admin_result);
    try std.testing.expect(std.mem.indexOf(u8, admin_result, "\"operation\":\"approve\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, admin_result, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, admin_result, "\"pending_approval\":null") != null);
}

test "acheron_session: missions invoke_service records successful venom step" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .actor_type = "agent",
            .actor_id = "worker-a",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        328,
        329,
        &.{ "agents", "self", "missions", "control", "create.json" },
        "{\"use_case\":\"pr_review\",\"title\":\"Review PR 48\",\"contract\":{\"contract_id\":\"spider_monkey/pr_review@v1\",\"context_path\":\"/nodes/local/fs/pr-review/state/pr-48/context.json\"}}",
        953,
    );
    const create_result = try protocolReadFile(
        &session,
        allocator,
        330,
        331,
        &.{ "agents", "self", "missions", "result.json" },
        954,
    );
    defer allocator.free(create_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, create_result);
    defer allocator.free(mission_id);

    const resume_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"stage\":\"running_review\"}}",
        .{mission_id},
    );
    defer allocator.free(resume_payload);
    try protocolWriteFile(
        &session,
        allocator,
        332,
        333,
        &.{ "agents", "self", "missions", "control", "resume.json" },
        resume_payload,
        955,
    );

    const invoke_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"service_path\":\"/global/memory\",\"stage\":\"collecting_context\",\"summary\":\"Created review memory\",\"op\":\"create\",\"arguments\":{{\"name\":\"mission-review-note\",\"kind\":\"note\",\"content\":{{\"text\":\"mission bridge ok\"}}}},\"contract\":{{\"artifact_root\":\"/nodes/local/fs/pr-review/runs/pr-48\"}}}}",
        .{mission_id},
    );
    defer allocator.free(invoke_payload);
    try protocolWriteFile(
        &session,
        allocator,
        334,
        335,
        &.{ "agents", "self", "missions", "control", "invoke_service.json" },
        invoke_payload,
        956,
    );

    const mission_status = try protocolReadFile(
        &session,
        allocator,
        336,
        337,
        &.{ "agents", "self", "missions", "status.json" },
        957,
    );
    defer allocator.free(mission_status);
    try std.testing.expect(std.mem.indexOf(u8, mission_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_status, "\"tool\":\"missions_invoke_service\"") != null);

    const mission_result = try protocolReadFile(
        &session,
        allocator,
        338,
        339,
        &.{ "agents", "self", "missions", "result.json" },
        958,
    );
    defer allocator.free(mission_result);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"operation\":\"invoke_service\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"service_path\":\"/global/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"invoke_path\":\"/global/memory/control/invoke.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"mission_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"memory_path\":\"/nodes/local/venoms/memory/items/mission-review-note\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"event_type\":\"mission.service_invoked\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"kind\":\"service_result\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"artifact_root\":\"/nodes/local/fs/pr-review/runs/pr-48\"") != null);
}

test "acheron_session: missions bootstrap_contract materializes contract files in local export root" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "worker-a",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        352,
        353,
        &.{ "agents", "self", "missions", "control", "create.json" },
        "{\"use_case\":\"pr_review\",\"title\":\"Review PR 77\",\"contract\":{\"contract_id\":\"spider_monkey/pr_review@v1\",\"context_path\":\"/nodes/local/fs/pr-review/state/pr-77/context.json\",\"state_path\":\"/nodes/local/fs/pr-review/state/pr-77/state.json\",\"artifact_root\":\"/nodes/local/fs/pr-review/runs/pr-77\"}}",
        965,
    );
    const create_result = try protocolReadFile(
        &session,
        allocator,
        354,
        355,
        &.{ "agents", "self", "missions", "result.json" },
        966,
    );
    defer allocator.free(create_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, create_result);
    defer allocator.free(mission_id);

    const bootstrap_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"stage\":\"bootstrap_context\",\"context\":{{\"repo\":\"DeanoC/Spiderweb\",\"pr_number\":77}},\"state\":{{\"stage\":\"intake\",\"artifacts\":[]}}}}",
        .{mission_id},
    );
    defer allocator.free(bootstrap_payload);
    try protocolWriteFile(
        &session,
        allocator,
        356,
        357,
        &.{ "agents", "self", "missions", "control", "bootstrap_contract.json" },
        bootstrap_payload,
        967,
    );

    const mission_status = try protocolReadFile(
        &session,
        allocator,
        358,
        359,
        &.{ "agents", "self", "missions", "status.json" },
        968,
    );
    defer allocator.free(mission_status);
    try std.testing.expect(std.mem.indexOf(u8, mission_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_status, "\"tool\":\"missions_bootstrap_contract\"") != null);

    const mission_result = try protocolReadFile(
        &session,
        allocator,
        360,
        361,
        &.{ "agents", "self", "missions", "result.json" },
        969,
    );
    defer allocator.free(mission_result);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"operation\":\"bootstrap_contract\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"stage\":\"bootstrap_context\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"contract_id\":\"spider_monkey/pr_review@v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"context_path\":\"/nodes/local/fs/pr-review/state/pr-77/context.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"state_path\":\"/nodes/local/fs/pr-review/state/pr-77/state.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"artifact_root\":\"/nodes/local/fs/pr-review/runs/pr-77\"") != null);

    const context_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "pr-77", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"repo\":\"DeanoC/Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"pr_number\":77") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "pr-77", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"stage\":\"intake\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"artifacts\":[]") != null);

    const artifact_root_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "pr-77" });
    defer allocator.free(artifact_root_host_path);
    var artifact_root_dir = try std.fs.openDirAbsolute(artifact_root_host_path, .{});
    artifact_root_dir.close();
}

test "acheron_session: pr_review venom starts a mission and bootstraps contract files" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-a",
        },
    );
    defer session.deinit();

    const venoms_payload = try protocolReadFile(
        &session,
        allocator,
        362,
        363,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        970,
    );
    defer allocator.free(venoms_payload);
    try std.testing.expect(std.mem.indexOf(u8, venoms_payload, "\"venom_path\":\"/nodes/local/venoms/pr_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, venoms_payload, "\"invoke_path\":\"/nodes/local/venoms/pr_review/control/invoke.json\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        364,
        365,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":123,\"head_sha\":\"abc123\",\"default_review_commands\":[\"zig build\",\"zig build test\"]}",
        971,
    );

    const pr_review_status = try protocolReadFile(
        &session,
        allocator,
        366,
        367,
        &.{ "agents", "self", "pr_review", "status.json" },
        972,
    );
    defer allocator.free(pr_review_status);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"tool\":\"pr_review_start\"") != null);

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        368,
        369,
        &.{ "agents", "self", "pr_review", "result.json" },
        973,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"use_case\":\"pr_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"repo_key\":\"DeanoC/Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"checkout_path\":\"/nodes/local/fs/pr-review/repos/DeanoC__Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"context_path\":\"/nodes/local/fs/pr-review/state/DeanoC__Spiderweb/pr-123/context.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"state_path\":\"/nodes/local/fs/pr-review/state/DeanoC__Spiderweb/pr-123/state.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"artifact_root\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-123\"") != null);

    const context_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-123", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"repo_key\":\"DeanoC/Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"pr_url\":\"https://github.com/DeanoC/Spiderweb/pull/123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"default_review_commands\":[\"zig build\",\"zig build test\"]") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-123", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"last_synced_head_sha\":\"abc123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"latest_recommendation\":{\"status\":\"pending\"") != null);

    const artifact_root_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-123" });
    defer allocator.free(artifact_root_host_path);
    var artifact_root_dir = try std.fs.openDirAbsolute(artifact_root_host_path, .{});
    artifact_root_dir.close();
}

test "acheron_session: pr_review repo onboarding persists config and start uses defaults" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-config",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        390,
        391,
        &.{ "agents", "self", "pr_review", "control", "configure_repo.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"provider\":\"github\",\"default_branch\":\"stable\",\"checkout_path\":\"/nodes/local/fs/pr-review/repos/spiderweb-configured\",\"review_policy_paths\":[\"/nodes/local/fs/policy/pr-review.md\"],\"default_review_commands\":[\"zig build test\"],\"approval_policy\":{\"push_fix_requires_approval\":true,\"merge_requires_approval\":false},\"auto_intake\":true,\"project_id\":\"proj-review\",\"agent_id\":\"reviewer-config\",\"workspace_root\":\"/nodes/local/fs/pr-review/workspaces/spiderweb-configured\",\"worktree_name\":\"review-pr\"}",
        981,
    );

    const configure_status = try protocolReadFile(
        &session,
        allocator,
        392,
        393,
        &.{ "agents", "self", "pr_review", "status.json" },
        982,
    );
    defer allocator.free(configure_status);
    try std.testing.expect(std.mem.indexOf(u8, configure_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, configure_status, "\"tool\":\"pr_review_configure_repo\"") != null);

    const configure_result = try protocolReadFile(
        &session,
        allocator,
        394,
        395,
        &.{ "agents", "self", "pr_review", "result.json" },
        983,
    );
    defer allocator.free(configure_result);
    try std.testing.expect(std.mem.indexOf(u8, configure_result, "\"operation\":\"configure_repo\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, configure_result, "\"repo_key\":\"DeanoC/Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, configure_result, "\"repositories_count\":1") != null);

    const get_payload = "{\"repo_key\":\"DeanoC/Spiderweb\"}";
    try protocolWriteFile(
        &session,
        allocator,
        396,
        397,
        &.{ "agents", "self", "pr_review", "control", "get_repo.json" },
        get_payload,
        984,
    );

    const get_result = try protocolReadFile(
        &session,
        allocator,
        398,
        399,
        &.{ "agents", "self", "pr_review", "result.json" },
        985,
    );
    defer allocator.free(get_result);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"operation\":\"get_repo\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"default_branch\":\"stable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, get_result, "\"auto_intake\":true") != null);

    try protocolWriteFile(
        &session,
        allocator,
        400,
        401,
        &.{ "agents", "self", "pr_review", "control", "list_repos.json" },
        "{}",
        986,
    );

    const list_result = try protocolReadFile(
        &session,
        allocator,
        402,
        403,
        &.{ "agents", "self", "pr_review", "result.json" },
        987,
    );
    defer allocator.free(list_result);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"operation\":\"list_repos\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"repositories\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"repo_key\":\"DeanoC/Spiderweb\"") != null);

    const repo_catalog_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "repos.json" });
    defer allocator.free(repo_catalog_host_path);
    const repo_catalog_content = try std.fs.cwd().readFileAlloc(allocator, repo_catalog_host_path, 64 * 1024);
    defer allocator.free(repo_catalog_content);
    try std.testing.expect(std.mem.indexOf(u8, repo_catalog_content, "\"repo_key\":\"DeanoC/Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, repo_catalog_content, "\"auto_intake\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, repo_catalog_content, "\"checkout_path\":\"/nodes/local/fs/pr-review/repos/spiderweb-configured\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        404,
        405,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":223,\"head_sha\":\"cfg223\"}",
        988,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        406,
        407,
        &.{ "agents", "self", "pr_review", "result.json" },
        989,
    );
    defer allocator.free(start_result);
    try std.testing.expect(std.mem.indexOf(u8, start_result, "\"operation\":\"start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_result, "\"checkout_path\":\"/nodes/local/fs/pr-review/repos/spiderweb-configured\"") != null);

    const context_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-223", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"base_branch\":\"stable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"checkout_path\":\"/nodes/local/fs/pr-review/repos/spiderweb-configured\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"default_review_commands\":[\"zig build test\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"review_policy_paths\":[\"/nodes/local/fs/policy/pr-review.md\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"push_fix_requires_approval\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"merge_requires_approval\":false") != null);
}

test "acheron_session: pr_review repo onboarding accepts workspace root checkout path" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-root",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        408,
        409,
        &.{ "agents", "self", "pr_review", "control", "configure_repo.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"provider\":\"github\",\"checkout_path\":\"/nodes/local/fs\",\"default_review_commands\":[\"zig build test\"],\"workspace_root\":\"/nodes/local/fs\",\"worktree_name\":\"root-review\"}",
        990,
    );

    const configure_result = try protocolReadFile(
        &session,
        allocator,
        410,
        411,
        &.{ "agents", "self", "pr_review", "result.json" },
        991,
    );
    defer allocator.free(configure_result);
    try std.testing.expect(std.mem.indexOf(u8, configure_result, "\"operation\":\"configure_repo\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, configure_result, "\"checkout_path\":\"/nodes/local/fs\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        412,
        413,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":224,\"head_sha\":\"cfg224\"}",
        992,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        414,
        415,
        &.{ "agents", "self", "pr_review", "result.json" },
        993,
    );
    defer allocator.free(start_result);
    try std.testing.expect(std.mem.indexOf(u8, start_result, "\"operation\":\"start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_result, "\"checkout_path\":\"/nodes/local/fs\"") != null);

    const context_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-224", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"checkout_path\":\"/nodes/local/fs\"") != null);
}

test "acheron_session: pr_review venom intake bootstraps mission from provider sync" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-intake",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        369,
        370,
        &.{ "agents", "self", "pr_review", "control", "intake.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":125,\"provider_sync\":{\"dry_run\":true},\"default_review_commands\":[\"zig build test\"]}",
        973,
    );

    const pr_review_status = try protocolReadFile(
        &session,
        allocator,
        371,
        372,
        &.{ "agents", "self", "pr_review", "status.json" },
        974,
    );
    defer allocator.free(pr_review_status);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"tool\":\"pr_review_intake\"") != null);

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        373,
        374,
        &.{ "agents", "self", "pr_review", "result.json" },
        975,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"intake\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"use_case\":\"pr_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"provider_sync_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-125/services/provider-sync.json\"") != null);

    const context_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-125", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"repo_key\":\"DeanoC/Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"default_review_commands\":[\"zig build test\"]") != null);

    const provider_sync_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-125", "services", "provider-sync.json" });
    defer allocator.free(provider_sync_path);
    const provider_sync_content = try std.fs.cwd().readFileAlloc(allocator, provider_sync_path, 64 * 1024);
    defer allocator.free(provider_sync_content);
    try std.testing.expect(std.mem.indexOf(u8, provider_sync_content, "\"service_path\":\"/nodes/local/venoms/github_pr\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, provider_sync_content, "\"dry_run\":true") != null);
}

test "acheron_session: github_pr ingest_event uses configured repo onboarding defaults" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-ingest-config",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        408,
        409,
        &.{ "agents", "self", "pr_review", "control", "configure_repo.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"default_branch\":\"release\",\"checkout_path\":\"/nodes/local/fs/pr-review/repos/ingest-defaults\",\"default_review_commands\":[\"zig build\"],\"approval_policy\":{\"push_fix_requires_approval\":false,\"merge_requires_approval\":true},\"auto_intake\":true}",
        990,
    );

    try protocolWriteFile(
        &session,
        allocator,
        410,
        411,
        &.{ "agents", "self", "github_pr", "control", "ingest_event.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":129,\"action\":\"edited\",\"title\":\"Config-backed intake\",\"head_sha\":\"def129\"}",
        991,
    );

    const github_pr_result = try protocolReadFile(
        &session,
        allocator,
        412,
        413,
        &.{ "agents", "self", "github_pr", "result.json" },
        992,
    );
    defer allocator.free(github_pr_result);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_result, "\"operation\":\"ingest_event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_result, "\"mission_action\":\"created\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_result, "\"run_id\":\"pr_review:DeanoC__Spiderweb:129\"") != null);

    const mission_id = try extractMissionIdFromResultPayload(allocator, github_pr_result);
    defer allocator.free(mission_id);
    try std.testing.expect(mission_id.len > 0);

    const context_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-129", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"base_branch\":\"release\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"checkout_path\":\"/nodes/local/fs/pr-review/repos/ingest-defaults\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"default_review_commands\":[\"zig build\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"pr_url\":\"https://github.com/DeanoC/Spiderweb/pull/129\"") != null);
}

test "acheron_session: pr_review venom syncs state and records review artifacts" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-a",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        370,
        371,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":124,\"head_sha\":\"abc124\"}",
        974,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        372,
        373,
        &.{ "agents", "self", "pr_review", "result.json" },
        975,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const sync_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"phase\":\"ready_for_checkout\",\"current_focus\":\"Fetch PR branch\",\"open_threads\":[{{\"id\":\"thread-1\",\"status\":\"open\"}}],\"notes\":[\"queued for checkout\"],\"thread_actions\":[{{\"thread_id\":\"thread-1\",\"action\":\"observe\"}}]}}",
        .{mission_id},
    );
    defer allocator.free(sync_payload);
    try protocolWriteFile(
        &session,
        allocator,
        374,
        375,
        &.{ "agents", "self", "pr_review", "control", "sync.json" },
        sync_payload,
        976,
    );

    const validation_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"head_sha\":\"def456\",\"validation\":{{\"status\":\"passed\",\"summary\":\"zig build test passed\",\"commands\":[\"zig build test\"]}}}}",
        .{mission_id},
    );
    defer allocator.free(validation_payload);
    try protocolWriteFile(
        &session,
        allocator,
        376,
        377,
        &.{ "agents", "self", "pr_review", "control", "record_validation.json" },
        validation_payload,
        977,
    );

    const review_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"findings\":[{{\"severity\":\"high\",\"type\":\"correctness\",\"path\":\"src/example.zig\",\"line\":42,\"message\":\"Handle null response\"}}],\"recommendation\":{{\"decision\":\"request_changes\",\"summary\":\"One correctness issue remains\"}},\"review_comment\":\"Please handle the null response before merging.\",\"thread_actions\":[{{\"thread_id\":\"thread-1\",\"action\":\"comment\"}}]}}",
        .{mission_id},
    );
    defer allocator.free(review_payload);
    try protocolWriteFile(
        &session,
        allocator,
        378,
        379,
        &.{ "agents", "self", "pr_review", "control", "record_review.json" },
        review_payload,
        978,
    );

    const pr_review_status = try protocolReadFile(
        &session,
        allocator,
        380,
        381,
        &.{ "agents", "self", "pr_review", "status.json" },
        979,
    );
    defer allocator.free(pr_review_status);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"tool\":\"pr_review_record_review\"") != null);

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        382,
        383,
        &.{ "agents", "self", "pr_review", "result.json" },
        980,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"record_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"phase\":\"awaiting_author\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"findings_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-124/findings.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"recommendation_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-124/recommendation.json\"") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-124", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"phase\":\"awaiting_author\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"last_synced_head_sha\":\"def456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"current_focus\":\"Fetch PR branch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"latest_validation\":{\"status\":\"passed\",\"summary\":\"zig build test passed\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"latest_recommendation\":{\"status\":\"request_changes\",\"summary\":\"One correctness issue remains\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"open_threads\":[{\"id\":\"thread-1\",\"status\":\"open\"}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"notes\":[\"queued for checkout\"]") != null);

    const validation_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-124", "validation.json" });
    defer allocator.free(validation_host_path);
    const validation_content = try std.fs.cwd().readFileAlloc(allocator, validation_host_path, 64 * 1024);
    defer allocator.free(validation_content);
    try std.testing.expect(std.mem.indexOf(u8, validation_content, "\"status\":\"passed\"") != null);

    const findings_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-124", "findings.json" });
    defer allocator.free(findings_host_path);
    const findings_content = try std.fs.cwd().readFileAlloc(allocator, findings_host_path, 64 * 1024);
    defer allocator.free(findings_content);
    try std.testing.expect(std.mem.indexOf(u8, findings_content, "\"severity\":\"high\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, findings_content, "\"message\":\"Handle null response\"") != null);

    const recommendation_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-124", "recommendation.json" });
    defer allocator.free(recommendation_host_path);
    const recommendation_content = try std.fs.cwd().readFileAlloc(allocator, recommendation_host_path, 64 * 1024);
    defer allocator.free(recommendation_content);
    try std.testing.expect(std.mem.indexOf(u8, recommendation_content, "\"decision\":\"request_changes\"") != null);

    const review_comment_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-124", "review-comment.md" });
    defer allocator.free(review_comment_host_path);
    const review_comment_content = try std.fs.cwd().readFileAlloc(allocator, review_comment_host_path, 64 * 1024);
    defer allocator.free(review_comment_content);
    try std.testing.expectEqualStrings("Please handle the null response before merging.", review_comment_content);

    const thread_actions_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-124", "thread-actions.json" });
    defer allocator.free(thread_actions_host_path);
    const thread_actions_content = try std.fs.cwd().readFileAlloc(allocator, thread_actions_host_path, 64 * 1024);
    defer allocator.free(thread_actions_content);
    try std.testing.expect(std.mem.indexOf(u8, thread_actions_content, "\"action\":\"comment\"") != null);
}

test "acheron_session: pr_review venom orchestrates repo services and review publication" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const exports_dir = try std.fmt.allocPrint(allocator, "{s}/exports", .{root});
    defer allocator.free(exports_dir);
    const seed_dir = try std.fmt.allocPrint(allocator, "{s}/seed", .{root});
    defer allocator.free(seed_dir);
    const remote_dir = try std.fmt.allocPrint(allocator, "{s}/remote.git", .{root});
    defer allocator.free(remote_dir);
    try std.fs.cwd().makePath(exports_dir);

    _ = try runTestCommandCapture(allocator, root, &.{ "git", "init", "seed" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "config", "user.email", "spider@example.com" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "config", "user.name", "Spider Monkey" });

    const readme_path = try std.fmt.allocPrint(allocator, "{s}/README.md", .{seed_dir});
    defer allocator.free(readme_path);
    try std.fs.cwd().writeFile(.{ .sub_path = readme_path, .data = "hello\n" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "add", "README.md" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "commit", "-m", "initial" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "branch", "-M", "main" });

    const first_sha_raw = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "rev-parse", "HEAD" });
    defer allocator.free(first_sha_raw);
    const first_sha = std.mem.trim(u8, first_sha_raw, " \t\r\n");

    const src_dir = try std.fmt.allocPrint(allocator, "{s}/src", .{seed_dir});
    defer allocator.free(src_dir);
    try std.fs.cwd().makePath(src_dir);
    const app_path = try std.fmt.allocPrint(allocator, "{s}/src/app.txt", .{seed_dir});
    defer allocator.free(app_path);
    try std.fs.cwd().writeFile(.{ .sub_path = app_path, .data = "second\n" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "add", "src/app.txt" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "commit", "-m", "second" });

    const second_sha_raw = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "rev-parse", "HEAD" });
    defer allocator.free(second_sha_raw);
    const second_sha = std.mem.trim(u8, second_sha_raw, " \t\r\n");

    _ = try runTestCommandCapture(allocator, root, &.{ "git", "init", "--bare", "remote.git" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "remote", "add", "origin", remote_dir });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "push", "-u", "origin", "main" });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = exports_dir,
            .actor_type = "agent",
            .actor_id = "reviewer-b",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        700,
        701,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":77,\"head_sha\":\"pending\"}",
        1800,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        702,
        703,
        &.{ "agents", "self", "pr_review", "result.json" },
        1801,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const sync_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"phase\":\"ready_for_checkout\",\"current_focus\":\"Sync repo services\",\"provider_sync\":{{\"dry_run\":true}},\"sync_checkout\":{{\"repo_url\":\"{s}\",\"pr_number\":null,\"head_branch\":\"main\"}},\"repo_status\":{{\"base_ref\":\"{s}\"}},\"diff_range\":{{\"base_ref\":\"{s}\",\"head_ref\":\"HEAD\"}}}}",
        .{ mission_id, remote_dir, first_sha, first_sha },
    );
    defer allocator.free(sync_payload);
    try protocolWriteFile(
        &session,
        allocator,
        704,
        705,
        &.{ "agents", "self", "pr_review", "control", "sync.json" },
        sync_payload,
        1802,
    );

    const sync_result = try protocolReadFile(
        &session,
        allocator,
        706,
        707,
        &.{ "agents", "self", "pr_review", "result.json" },
        1803,
    );
    defer allocator.free(sync_result);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"operation\":\"sync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"provider_sync_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-77/services/provider-sync.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"checkout_sync_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-77/services/checkout.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"repo_status_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-77/services/repo-status.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"diff_range_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-77/services/diff-range.json\"") != null);

    const context_host_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "state", "DeanoC__Spiderweb", "pr-77", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"head_branch\":\"main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, second_sha) != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "state", "DeanoC__Spiderweb", "pr-77", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, second_sha) != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"provider_sync\":\"services/provider-sync.json\"") != null);

    const provider_sync_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-77", "services", "provider-sync.json" });
    defer allocator.free(provider_sync_path);
    const provider_sync_content = try std.fs.cwd().readFileAlloc(allocator, provider_sync_path, 64 * 1024);
    defer allocator.free(provider_sync_content);
    try std.testing.expect(std.mem.indexOf(u8, provider_sync_content, "\"service_path\":\"/nodes/local/venoms/github_pr\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, provider_sync_content, "\"dry_run\":true") != null);

    const checkout_capture_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-77", "services", "checkout.json" });
    defer allocator.free(checkout_capture_path);
    const checkout_capture_content = try std.fs.cwd().readFileAlloc(allocator, checkout_capture_path, 64 * 1024);
    defer allocator.free(checkout_capture_content);
    try std.testing.expect(std.mem.indexOf(u8, checkout_capture_content, "\"service_path\":\"/nodes/local/venoms/git\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, checkout_capture_content, second_sha) != null);

    const repo_status_capture_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-77", "services", "repo-status.json" });
    defer allocator.free(repo_status_capture_path);
    const repo_status_capture_content = try std.fs.cwd().readFileAlloc(allocator, repo_status_capture_path, 64 * 1024);
    defer allocator.free(repo_status_capture_content);
    try std.testing.expect(std.mem.indexOf(u8, repo_status_capture_content, "\"changed_files\":[\"src/app.txt\"]") != null);

    const diff_range_capture_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-77", "services", "diff-range.json" });
    defer allocator.free(diff_range_capture_path);
    const diff_range_capture_content = try std.fs.cwd().readFileAlloc(allocator, diff_range_capture_path, 64 * 1024);
    defer allocator.free(diff_range_capture_content);
    try std.testing.expect(std.mem.indexOf(u8, diff_range_capture_content, "\"changed_files\":[\"src/app.txt\"]") != null);

    const review_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"findings\":[{{\"severity\":\"medium\",\"type\":\"maintainability\",\"path\":\"src/app.txt\",\"line\":1,\"message\":\"Add coverage for PR review orchestration\"}}],\"recommendation\":{{\"decision\":\"request_changes\",\"summary\":\"Capture the missing regression tests\"}},\"review_comment\":\"Please add regression coverage before merging.\",\"thread_actions\":[{{\"thread_id\":\"t-77\",\"action\":\"comment\"}}],\"publish_review\":{{\"dry_run\":true}}}}",
        .{mission_id},
    );
    defer allocator.free(review_payload);
    try protocolWriteFile(
        &session,
        allocator,
        708,
        709,
        &.{ "agents", "self", "pr_review", "control", "record_review.json" },
        review_payload,
        1804,
    );

    const review_result = try protocolReadFile(
        &session,
        allocator,
        710,
        711,
        &.{ "agents", "self", "pr_review", "result.json" },
        1805,
    );
    defer allocator.free(review_result);
    try std.testing.expect(std.mem.indexOf(u8, review_result, "\"operation\":\"record_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, review_result, "\"publish_review_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-77/services/publish-review.json\"") != null);

    const publish_review_capture_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-77", "services", "publish-review.json" });
    defer allocator.free(publish_review_capture_path);
    const publish_review_capture_content = try std.fs.cwd().readFileAlloc(allocator, publish_review_capture_path, 64 * 1024);
    defer allocator.free(publish_review_capture_content);
    try std.testing.expect(std.mem.indexOf(u8, publish_review_capture_content, "\"service_path\":\"/nodes/local/venoms/github_pr\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, publish_review_capture_content, "\"decision\":\"request_changes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, publish_review_capture_content, "\"thread_actions_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, publish_review_capture_content, "\"dry_run\":true") != null);
}

test "acheron_session: pr_review run_validation executes configured review commands" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-validation",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        712,
        713,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":126,\"default_review_commands\":[\"printf validation-ok\"]}",
        1806,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        714,
        715,
        &.{ "agents", "self", "pr_review", "result.json" },
        1807,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const checkout_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "repos", "DeanoC__Spiderweb" });
    defer allocator.free(checkout_host_path);
    try std.fs.cwd().makePath(checkout_host_path);

    const validation_payload = try std.fmt.allocPrint(allocator, "{{\"mission_id\":\"{s}\"}}", .{mission_id});
    defer allocator.free(validation_payload);
    try protocolWriteFile(
        &session,
        allocator,
        716,
        717,
        &.{ "agents", "self", "pr_review", "control", "run_validation.json" },
        validation_payload,
        1808,
    );

    const pr_review_status = try protocolReadFile(
        &session,
        allocator,
        718,
        719,
        &.{ "agents", "self", "pr_review", "status.json" },
        1809,
    );
    defer allocator.free(pr_review_status);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"tool\":\"pr_review_run_validation\"") != null);

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        720,
        721,
        &.{ "agents", "self", "pr_review", "result.json" },
        1810,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"run_validation\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"validation_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-126/validation.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"validation_command_paths\":[\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-126/services/validation-command-001.json\"]") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-126", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"latest_validation\":{\"status\":\"passed\",\"summary\":\"1 review command passed\"}") != null);

    const validation_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-126", "validation.json" });
    defer allocator.free(validation_host_path);
    const validation_content = try std.fs.cwd().readFileAlloc(allocator, validation_host_path, 64 * 1024);
    defer allocator.free(validation_content);
    try std.testing.expect(std.mem.indexOf(u8, validation_content, "\"status\":\"passed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, validation_content, "\"exit_code\":0") != null);

    const validation_command_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-126", "services", "validation-command-001.json" });
    defer allocator.free(validation_command_path);
    const validation_command_content = try std.fs.cwd().readFileAlloc(allocator, validation_command_path, 64 * 1024);
    defer allocator.free(validation_command_content);
    try std.testing.expect(std.mem.indexOf(u8, validation_command_content, "\"service_path\":\"/global/terminal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, validation_command_content, "\"exit_code\":0") != null);
}

test "acheron_session: pr_review run_validation fails on non-zero command exits" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-validation-fail",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        722,
        723,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":127,\"default_review_commands\":[\"false\"]}",
        1811,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        724,
        725,
        &.{ "agents", "self", "pr_review", "result.json" },
        1812,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const checkout_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "repos", "DeanoC__Spiderweb" });
    defer allocator.free(checkout_host_path);
    try std.fs.cwd().makePath(checkout_host_path);

    const validation_payload = try std.fmt.allocPrint(allocator, "{{\"mission_id\":\"{s}\"}}", .{mission_id});
    defer allocator.free(validation_payload);
    try protocolWriteFile(
        &session,
        allocator,
        726,
        727,
        &.{ "agents", "self", "pr_review", "control", "run_validation.json" },
        validation_payload,
        1813,
    );

    const pr_review_status = try protocolReadFile(
        &session,
        allocator,
        728,
        729,
        &.{ "agents", "self", "pr_review", "status.json" },
        1814,
    );
    defer allocator.free(pr_review_status);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"state\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"tool\":\"pr_review_run_validation\"") != null);

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        730,
        731,
        &.{ "agents", "self", "pr_review", "result.json" },
        1815,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"run_validation\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"code\":\"execution_failed\"") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-127", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"latest_validation\":{\"status\":\"failed\",\"summary\":\"Validation command 1 exited with code 1\"}") != null);

    const validation_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "runs", "DeanoC__Spiderweb", "pr-127", "validation.json" });
    defer allocator.free(validation_host_path);
    const validation_content = try std.fs.cwd().readFileAlloc(allocator, validation_host_path, 64 * 1024);
    defer allocator.free(validation_content);
    try std.testing.expect(std.mem.indexOf(u8, validation_content, "\"status\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, validation_content, "\"exit_code\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, validation_content, "\"code\":\"execution_failed\"") != null);
}

test "acheron_session: seeded pr_review eval propagates checkout failure" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const exports_dir = try std.fmt.allocPrint(allocator, "{s}/exports", .{root});
    defer allocator.free(exports_dir);
    try std.fs.cwd().makePath(exports_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = exports_dir,
            .actor_type = "agent",
            .actor_id = "reviewer-c",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        720,
        721,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":91}",
        1810,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        722,
        723,
        &.{ "agents", "self", "pr_review", "result.json" },
        1811,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const missing_remote = try std.fmt.allocPrint(allocator, "{s}/missing-remote.git", .{root});
    defer allocator.free(missing_remote);
    const sync_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"phase\":\"ready_for_checkout\",\"sync_checkout\":{{\"repo_url\":\"{s}\",\"pr_number\":null,\"head_branch\":\"main\"}}}}",
        .{ mission_id, missing_remote },
    );
    defer allocator.free(sync_payload);
    try protocolWriteFile(
        &session,
        allocator,
        724,
        725,
        &.{ "agents", "self", "pr_review", "control", "sync.json" },
        sync_payload,
        1812,
    );

    const pr_review_status = try protocolReadFile(
        &session,
        allocator,
        726,
        727,
        &.{ "agents", "self", "pr_review", "status.json" },
        1813,
    );
    defer allocator.free(pr_review_status);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"state\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"tool\":\"pr_review_sync\"") != null);

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        728,
        729,
        &.{ "agents", "self", "pr_review", "result.json" },
        1814,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"sync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"code\":\"execution_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"checkout_sync_path\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-91/services/checkout.json\"") != null);

    const checkout_capture_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-91", "services", "checkout.json" });
    defer allocator.free(checkout_capture_path);
    const checkout_capture_content = try std.fs.cwd().readFileAlloc(allocator, checkout_capture_path, 64 * 1024);
    defer allocator.free(checkout_capture_content);
    try std.testing.expect(std.mem.indexOf(u8, checkout_capture_content, "\"service_path\":\"/nodes/local/venoms/git\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, checkout_capture_content, "\"code\":\"execution_failed\"") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "state", "DeanoC__Spiderweb", "pr-91", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"phase\":\"ready_for_checkout\"") != null);
}

test "acheron_session: pr_review advance primes checkout and validation for review" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const exports_dir = try std.fmt.allocPrint(allocator, "{s}/exports", .{root});
    defer allocator.free(exports_dir);
    try std.fs.cwd().makePath(exports_dir);

    const seed_dir = try std.fmt.allocPrint(allocator, "{s}/seed", .{root});
    defer allocator.free(seed_dir);
    const remote_dir = try std.fmt.allocPrint(allocator, "{s}/remote.git", .{root});
    defer allocator.free(remote_dir);
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "init", "seed" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "config", "user.email", "spider@example.com" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "config", "user.name", "Spider Monkey" });
    const readme_path = try std.fmt.allocPrint(allocator, "{s}/README.md", .{seed_dir});
    defer allocator.free(readme_path);
    try std.fs.cwd().writeFile(.{ .sub_path = readme_path, .data = "first\n" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "add", "README.md" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "commit", "-m", "initial" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "branch", "-M", "main" });
    const first_sha_raw = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "rev-parse", "HEAD" });
    defer allocator.free(first_sha_raw);
    const first_sha = std.mem.trim(u8, first_sha_raw, " \t\r\n");

    const src_dir = try std.fmt.allocPrint(allocator, "{s}/src", .{seed_dir});
    defer allocator.free(src_dir);
    try std.fs.cwd().makePath(src_dir);
    const app_path = try std.fmt.allocPrint(allocator, "{s}/src/app.txt", .{seed_dir});
    defer allocator.free(app_path);
    try std.fs.cwd().writeFile(.{ .sub_path = app_path, .data = "second\n" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "add", "src/app.txt" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "commit", "-m", "second" });
    const second_sha_raw = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "rev-parse", "HEAD" });
    defer allocator.free(second_sha_raw);
    const second_sha = std.mem.trim(u8, second_sha_raw, " \t\r\n");

    _ = try runTestCommandCapture(allocator, root, &.{ "git", "init", "--bare", "remote.git" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "remote", "add", "origin", remote_dir });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "push", "-u", "origin", "main" });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = exports_dir,
            .actor_type = "agent",
            .actor_id = "reviewer-runner",
        },
    );
    defer session.deinit();

    const start_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":130,\"head_sha\":\"{s}\",\"default_review_commands\":[\"git status --short\"]}}",
        .{second_sha},
    );
    defer allocator.free(start_payload);
    try protocolWriteFile(
        &session,
        allocator,
        740,
        741,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        start_payload,
        1820,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        742,
        743,
        &.{ "agents", "self", "pr_review", "result.json" },
        1821,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const advance_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"provider_sync\":false,\"sync_checkout\":{{\"repo_url\":\"{s}\",\"base_branch\":\"main\"}},\"repo_status\":{{\"base_ref\":\"{s}\"}},\"diff_range\":{{\"base_ref\":\"{s}\",\"head_ref\":\"HEAD\"}},\"commands\":[\"git status --short\"]}}",
        .{ mission_id, remote_dir, first_sha, first_sha },
    );
    defer allocator.free(advance_payload);
    try protocolWriteFile(
        &session,
        allocator,
        744,
        745,
        &.{ "agents", "self", "pr_review", "control", "advance.json" },
        advance_payload,
        1822,
    );

    const pr_review_status = try protocolReadFile(
        &session,
        allocator,
        746,
        747,
        &.{ "agents", "self", "pr_review", "status.json" },
        1823,
    );
    defer allocator.free(pr_review_status);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_status, "\"tool\":\"pr_review_advance\"") != null);

    const pr_review_result = try protocolReadFile(
        &session,
        allocator,
        748,
        749,
        &.{ "agents", "self", "pr_review", "result.json" },
        1824,
    );
    defer allocator.free(pr_review_result);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"advance\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"status\":\"ready_for_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"next_action\":\"draft_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"sync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"operation\":\"run_validation\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"context_path\":\"/nodes/local/fs/pr-review/state/DeanoC__Spiderweb/pr-130/context.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"state_path\":\"/nodes/local/fs/pr-review/state/DeanoC__Spiderweb/pr-130/state.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pr_review_result, "\"artifact_root\":\"/nodes/local/fs/pr-review/runs/DeanoC__Spiderweb/pr-130\"") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "state", "DeanoC__Spiderweb", "pr-130", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"phase\":\"reviewing\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"latest_validation\":{\"status\":\"passed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, state_content, second_sha) != null);

    var mission = (try mission_store.getOwned(allocator, mission_id)) orelse return error.TestExpectedResponse;
    defer mission.deinit(allocator);
    try std.testing.expectEqual(mission_store_mod.MissionState.running, mission.state);
}

test "acheron_session: pr_review advance waits for github_pr events and resumes" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const exports_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(exports_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = exports_dir,
            .actor_type = "agent",
            .actor_id = "reviewer-wait",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        750,
        751,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":131}",
        1825,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        752,
        753,
        &.{ "agents", "self", "pr_review", "result.json" },
        1826,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const review_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"findings\":[],\"recommendation\":{{\"decision\":\"request_changes\",\"summary\":\"Needs follow-up\"}}}}",
        .{mission_id},
    );
    defer allocator.free(review_payload);
    try protocolWriteFile(
        &session,
        allocator,
        754,
        755,
        &.{ "agents", "self", "pr_review", "control", "record_review.json" },
        review_payload,
        1827,
    );

    const wait_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"run_validation\":false,\"wait_timeout_ms\":0}}",
        .{mission_id},
    );
    defer allocator.free(wait_payload);
    try protocolWriteFile(
        &session,
        allocator,
        756,
        757,
        &.{ "agents", "self", "pr_review", "control", "advance.json" },
        wait_payload,
        1828,
    );

    const waiting_result = try protocolReadFile(
        &session,
        allocator,
        758,
        759,
        &.{ "agents", "self", "pr_review", "result.json" },
        1829,
    );
    defer allocator.free(waiting_result);
    try std.testing.expect(std.mem.indexOf(u8, waiting_result, "\"status\":\"waiting_for_event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, waiting_result, "\"next_action\":\"wait_for_github_event\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        760,
        761,
        &.{ "agents", "self", "events", "control", "signal.json" },
        "{\"event_type\":\"agent\",\"parameter\":\"github_pr\",\"payload\":{\"event_name\":\"pr.synchronized\"}}",
        1830,
    );

    const resume_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"run_validation\":false,\"provider_sync\":false,\"sync_checkout\":false,\"repo_status\":false,\"diff_range\":false,\"wait_timeout_ms\":0}}",
        .{mission_id},
    );
    defer allocator.free(resume_payload);
    try protocolWriteFile(
        &session,
        allocator,
        762,
        763,
        &.{ "agents", "self", "pr_review", "control", "advance.json" },
        resume_payload,
        1831,
    );

    const resumed_result = try protocolReadFile(
        &session,
        allocator,
        764,
        765,
        &.{ "agents", "self", "pr_review", "result.json" },
        1832,
    );
    defer allocator.free(resumed_result);
    try std.testing.expect(std.mem.indexOf(u8, resumed_result, "\"status\":\"ready_for_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resumed_result, "\"next_action\":\"draft_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resumed_result, "\"event_type\":\"agent\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resumed_result, "\"parameter\":\"github_pr\"") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "state", "DeanoC__Spiderweb", "pr-131", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"phase\":\"reviewing\"") != null);
}

test "acheron_session: pr_review save_draft persists revision history and advance requests revision" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const exports_dir = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(exports_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = exports_dir,
            .actor_type = "agent",
            .actor_id = "reviewer-draft",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        766,
        767,
        &.{ "agents", "self", "pr_review", "control", "start.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":132}",
        1833,
    );

    const start_result = try protocolReadFile(
        &session,
        allocator,
        768,
        769,
        &.{ "agents", "self", "pr_review", "result.json" },
        1834,
    );
    defer allocator.free(start_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, start_result);
    defer allocator.free(mission_id);

    const first_draft_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"phase\":\"reviewing\",\"summary\":\"First draft\",\"current_focus\":\"Inspect policy edge cases\",\"findings\":[{{\"path\":\"src/main.zig\",\"summary\":\"Check mount behavior\"}}],\"recommendation\":{{\"decision\":\"comment\",\"summary\":\"Still gathering evidence\"}},\"review_comment\":\"Draft review note one.\"}}",
        .{mission_id},
    );
    defer allocator.free(first_draft_payload);
    try protocolWriteFile(
        &session,
        allocator,
        770,
        771,
        &.{ "agents", "self", "pr_review", "control", "save_draft.json" },
        first_draft_payload,
        1835,
    );

    const second_draft_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"summary\":\"Second draft\",\"findings\":[{{\"path\":\"src/main.zig\",\"summary\":\"Check mount behavior\"}},{{\"path\":\"src/router.zig\",\"summary\":\"Need follow-up on proxy path\"}}],\"review_comment\":\"Draft review note two.\"}}",
        .{mission_id},
    );
    defer allocator.free(second_draft_payload);
    try protocolWriteFile(
        &session,
        allocator,
        772,
        773,
        &.{ "agents", "self", "pr_review", "control", "save_draft.json" },
        second_draft_payload,
        1836,
    );

    const save_draft_result = try protocolReadFile(
        &session,
        allocator,
        774,
        775,
        &.{ "agents", "self", "pr_review", "result.json" },
        1837,
    );
    defer allocator.free(save_draft_result);
    try std.testing.expect(std.mem.indexOf(u8, save_draft_result, "\"operation\":\"save_draft\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, save_draft_result, "\"draft_revision\":2") != null);

    const draft_host_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-132", "draft-review.json" });
    defer allocator.free(draft_host_path);
    const draft_content = try std.fs.cwd().readFileAlloc(allocator, draft_host_path, 64 * 1024);
    defer allocator.free(draft_content);
    try std.testing.expect(std.mem.indexOf(u8, draft_content, "\"revision\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, draft_content, "Draft review note two.") != null);

    const draft_history_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "runs", "DeanoC__Spiderweb", "pr-132", "drafts", "review-draft-001.json" });
    defer allocator.free(draft_history_path);
    const draft_history_content = try std.fs.cwd().readFileAlloc(allocator, draft_history_path, 64 * 1024);
    defer allocator.free(draft_history_content);
    try std.testing.expect(std.mem.indexOf(u8, draft_history_content, "\"revision\":1") != null);

    const state_host_path = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "state", "DeanoC__Spiderweb", "pr-132", "state.json" });
    defer allocator.free(state_host_path);
    const state_content = try std.fs.cwd().readFileAlloc(allocator, state_host_path, 64 * 1024);
    defer allocator.free(state_content);
    try std.testing.expect(std.mem.indexOf(u8, state_content, "\"latest_draft\":{\"status\":\"revised\",\"summary\":\"Second draft\",\"revision\":2}") != null);

    const advance_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"run_validation\":false,\"provider_sync\":false,\"sync_checkout\":false,\"repo_status\":false,\"diff_range\":false}}",
        .{mission_id},
    );
    defer allocator.free(advance_payload);
    try protocolWriteFile(
        &session,
        allocator,
        776,
        777,
        &.{ "agents", "self", "pr_review", "control", "advance.json" },
        advance_payload,
        1838,
    );

    const advance_result = try protocolReadFile(
        &session,
        allocator,
        778,
        779,
        &.{ "agents", "self", "pr_review", "result.json" },
        1839,
    );
    defer allocator.free(advance_result);
    try std.testing.expect(std.mem.indexOf(u8, advance_result, "\"next_action\":\"revise_review\"") != null);
}

test "acheron_session: github_pr ingest_event emits agent event and auto-intakes pr_review mission" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-ingest",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        740,
        741,
        &.{ "agents", "self", "events", "control", "wait.json" },
        "{\"paths\":[\"/nodes/local/venoms/events/sources/agent/github_pr.json\"],\"timeout_ms\":0}",
        1816,
    );

    try protocolWriteFile(
        &session,
        allocator,
        742,
        743,
        &.{ "agents", "self", "github_pr", "control", "ingest_event.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":128,\"action\":\"opened\",\"title\":\"Add agent loop\",\"pr_url\":\"https://github.com/DeanoC/Spiderweb/pull/128\",\"base_branch\":\"main\",\"base_sha\":\"abc\",\"head_branch\":\"feature/agent-loop\",\"head_sha\":\"def\",\"default_review_commands\":[\"zig build test\"]}",
        1817,
    );

    const github_pr_status = try protocolReadFile(
        &session,
        allocator,
        744,
        745,
        &.{ "agents", "self", "github_pr", "status.json" },
        1818,
    );
    defer allocator.free(github_pr_status);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_status, "\"tool\":\"github_pr_ingest_event\"") != null);

    const github_pr_result = try protocolReadFile(
        &session,
        allocator,
        746,
        747,
        &.{ "agents", "self", "github_pr", "result.json" },
        1819,
    );
    defer allocator.free(github_pr_result);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_result, "\"operation\":\"ingest_event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_result, "\"mission_action\":\"created\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_result, "\"signal_path\":\"/nodes/local/venoms/events/sources/agent/github_pr.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, github_pr_result, "\"run_id\":\"pr_review:DeanoC__Spiderweb:128\"") != null);

    const mission_id = try extractMissionIdFromResultPayload(allocator, github_pr_result);
    defer allocator.free(mission_id);

    const next_payload = try protocolReadFile(
        &session,
        allocator,
        748,
        749,
        &.{ "agents", "self", "events", "next.json" },
        1820,
    );
    defer allocator.free(next_payload);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_type\":\"agent\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"parameter\":\"github_pr\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_name\":\"pr.opened\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"mission_action\":\"created\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, mission_id) != null);

    const missions = try mission_store.listOwned(allocator, .{ .use_case = "pr_review" });
    defer {
        for (missions) |*item| item.deinit(allocator);
        allocator.free(missions);
    }
    try std.testing.expectEqual(@as(usize, 1), missions.len);
    try std.testing.expectEqualStrings("pr_review:DeanoC__Spiderweb:128", missions[0].run_id orelse return error.TestExpectedResponse);

    const context_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "pr-review", "state", "DeanoC__Spiderweb", "pr-128", "context.json" });
    defer allocator.free(context_host_path);
    const context_content = try std.fs.cwd().readFileAlloc(allocator, context_host_path, 64 * 1024);
    defer allocator.free(context_content);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"repo_key\":\"DeanoC/Spiderweb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context_content, "\"default_review_commands\":[\"zig build test\"]") != null);
}

test "acheron_session: github_pr ingest_event reuses existing active pr_review mission" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .local_fs_export_root = local_export_root,
            .actor_type = "agent",
            .actor_id = "reviewer-ingest-reuse",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        750,
        751,
        &.{ "agents", "self", "github_pr", "control", "ingest_event.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":129,\"action\":\"opened\",\"title\":\"Open PR review loop\",\"head_sha\":\"aaa\"}",
        1821,
    );

    const first_result = try protocolReadFile(
        &session,
        allocator,
        752,
        753,
        &.{ "agents", "self", "github_pr", "result.json" },
        1822,
    );
    defer allocator.free(first_result);
    const first_mission_id = try extractMissionIdFromResultPayload(allocator, first_result);
    defer allocator.free(first_mission_id);
    try std.testing.expect(std.mem.indexOf(u8, first_result, "\"mission_action\":\"created\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        754,
        755,
        &.{ "agents", "self", "github_pr", "control", "ingest_event.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":129,\"action\":\"synchronize\",\"title\":\"Open PR review loop\",\"head_sha\":\"bbb\"}",
        1823,
    );

    const second_result = try protocolReadFile(
        &session,
        allocator,
        756,
        757,
        &.{ "agents", "self", "github_pr", "result.json" },
        1824,
    );
    defer allocator.free(second_result);
    const second_mission_id = try extractMissionIdFromResultPayload(allocator, second_result);
    defer allocator.free(second_mission_id);
    try std.testing.expect(std.mem.indexOf(u8, second_result, "\"mission_action\":\"existing\"") != null);
    try std.testing.expectEqualStrings(first_mission_id, second_mission_id);
    try std.testing.expect(std.mem.indexOf(u8, second_result, "\"event_name\":\"pr.synchronized\"") != null);

    const missions = try mission_store.listOwned(allocator, .{ .use_case = "pr_review" });
    defer {
        for (missions) |*item| item.deinit(allocator);
        allocator.free(missions);
    }

    var matching_active: usize = 0;
    for (missions) |mission| {
        const mission_run_id = mission.run_id orelse continue;
        if (!std.mem.eql(u8, mission_run_id, "pr_review:DeanoC__Spiderweb:129")) continue;
        if (!isActiveMissionState(mission.state)) continue;
        matching_active += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), matching_active);
}

test "acheron_session: missions invoke_service records downstream service failures" {
    const allocator = std.testing.allocator;

    var mission_store = try mission_store_mod.MissionStore.initWithPath(allocator, null);
    defer mission_store.deinit();

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .mission_store = &mission_store,
            .actor_type = "agent",
            .actor_id = "worker-a",
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        340,
        341,
        &.{ "agents", "self", "missions", "control", "create.json" },
        "{\"use_case\":\"pr_review\",\"title\":\"Review PR 49\"}",
        959,
    );
    const create_result = try protocolReadFile(
        &session,
        allocator,
        342,
        343,
        &.{ "agents", "self", "missions", "result.json" },
        960,
    );
    defer allocator.free(create_result);
    const mission_id = try extractMissionIdFromResultPayload(allocator, create_result);
    defer allocator.free(mission_id);

    const resume_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"stage\":\"running_review\"}}",
        .{mission_id},
    );
    defer allocator.free(resume_payload);
    try protocolWriteFile(
        &session,
        allocator,
        344,
        345,
        &.{ "agents", "self", "missions", "control", "resume.json" },
        resume_payload,
        961,
    );

    const invoke_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"mission_id\":\"{s}\",\"service_path\":\"/global/memory\",\"stage\":\"collecting_context\",\"summary\":\"Tried invalid memory request\",\"payload\":{{}}}}",
        .{mission_id},
    );
    defer allocator.free(invoke_payload);
    try protocolWriteFile(
        &session,
        allocator,
        346,
        347,
        &.{ "agents", "self", "missions", "control", "invoke_service.json" },
        invoke_payload,
        962,
    );

    const mission_status = try protocolReadFile(
        &session,
        allocator,
        348,
        349,
        &.{ "agents", "self", "missions", "status.json" },
        963,
    );
    defer allocator.free(mission_status);
    try std.testing.expect(std.mem.indexOf(u8, mission_status, "\"state\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_status, "\"tool\":\"missions_invoke_service\"") != null);

    const mission_result = try protocolReadFile(
        &session,
        allocator,
        350,
        351,
        &.{ "agents", "self", "missions", "result.json" },
        964,
    );
    defer allocator.free(mission_result);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"operation\":\"invoke_service\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"code\":\"invalid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"service_path\":\"/global/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mission_result, "\"event_type\":\"mission.service_invoked\"") != null);
}

test "acheron_session: git venom syncs checkout and reports changed files" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const exports_dir = try std.fmt.allocPrint(allocator, "{s}/exports", .{root});
    defer allocator.free(exports_dir);
    const seed_dir = try std.fmt.allocPrint(allocator, "{s}/seed", .{root});
    defer allocator.free(seed_dir);
    const remote_dir = try std.fmt.allocPrint(allocator, "{s}/remote.git", .{root});
    defer allocator.free(remote_dir);
    try std.fs.cwd().makePath(exports_dir);

    _ = try runTestCommandCapture(allocator, root, &.{ "git", "init", "seed" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "config", "user.email", "spider@example.com" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "config", "user.name", "Spider Monkey" });

    const readme_path = try std.fmt.allocPrint(allocator, "{s}/README.md", .{seed_dir});
    defer allocator.free(readme_path);
    try std.fs.cwd().writeFile(.{ .sub_path = readme_path, .data = "hello\n" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "add", "README.md" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "commit", "-m", "initial" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "branch", "-M", "main" });

    const first_sha_raw = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "rev-parse", "HEAD" });
    defer allocator.free(first_sha_raw);
    const first_sha = std.mem.trim(u8, first_sha_raw, " \t\r\n");

    const src_dir = try std.fmt.allocPrint(allocator, "{s}/src", .{seed_dir});
    defer allocator.free(src_dir);
    try std.fs.cwd().makePath(src_dir);
    const app_path = try std.fmt.allocPrint(allocator, "{s}/src/app.txt", .{seed_dir});
    defer allocator.free(app_path);
    try std.fs.cwd().writeFile(.{ .sub_path = app_path, .data = "second\n" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "add", "src/app.txt" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "commit", "-m", "second" });

    const second_sha_raw = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "rev-parse", "HEAD" });
    defer allocator.free(second_sha_raw);
    const second_sha = std.mem.trim(u8, second_sha_raw, " \t\r\n");

    _ = try runTestCommandCapture(allocator, root, &.{ "git", "init", "--bare", "remote.git" });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "remote", "add", "origin", remote_dir });
    _ = try runTestCommandCapture(allocator, root, &.{ "git", "-C", seed_dir, "push", "-u", "origin", "main" });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
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
        },
    );
    defer session.deinit();

    const checkout_world_path = "/nodes/local/fs/pr-review/repos/test-repo";
    const sync_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"repo_url\":\"{s}\",\"checkout_path\":\"{s}\",\"base_branch\":\"main\"}}",
        .{ remote_dir, checkout_world_path },
    );
    defer allocator.free(sync_payload);
    try protocolWriteFile(
        &session,
        allocator,
        600,
        601,
        &.{ "agents", "self", "git", "control", "sync_checkout.json" },
        sync_payload,
        1600,
    );

    const git_status = try protocolReadFile(
        &session,
        allocator,
        602,
        603,
        &.{ "agents", "self", "git", "status.json" },
        1601,
    );
    defer allocator.free(git_status);
    try std.testing.expect(std.mem.indexOf(u8, git_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, git_status, "\"tool\":\"git_sync_checkout\"") != null);

    const sync_result = try protocolReadFile(
        &session,
        allocator,
        604,
        605,
        &.{ "agents", "self", "git", "result.json" },
        1602,
    );
    defer allocator.free(sync_result);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"operation\":\"sync_checkout\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, second_sha) != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"reused_checkout\":false") != null);

    const host_checkout_file = try std.fs.path.join(allocator, &.{ exports_dir, "pr-review", "repos", "test-repo", "src", "app.txt" });
    defer allocator.free(host_checkout_file);
    const host_checkout_content = try std.fs.cwd().readFileAlloc(allocator, host_checkout_file, 64 * 1024);
    defer allocator.free(host_checkout_content);
    try std.testing.expectEqualStrings("second\n", host_checkout_content);

    const status_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"checkout_path\":\"{s}\",\"base_ref\":\"{s}\"}}",
        .{ checkout_world_path, first_sha },
    );
    defer allocator.free(status_payload);
    try protocolWriteFile(
        &session,
        allocator,
        606,
        607,
        &.{ "agents", "self", "git", "control", "status.json" },
        status_payload,
        1603,
    );

    const status_result = try protocolReadFile(
        &session,
        allocator,
        608,
        609,
        &.{ "agents", "self", "git", "result.json" },
        1604,
    );
    defer allocator.free(status_result);
    try std.testing.expect(std.mem.indexOf(u8, status_result, "\"operation\":\"status\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_result, "\"changed_files\":[\"src/app.txt\"]") != null);

    const diff_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"checkout_path\":\"{s}\",\"base_ref\":\"{s}\",\"head_ref\":\"HEAD\"}}",
        .{ checkout_world_path, first_sha },
    );
    defer allocator.free(diff_payload);
    try protocolWriteFile(
        &session,
        allocator,
        610,
        611,
        &.{ "agents", "self", "git", "control", "diff_range.json" },
        diff_payload,
        1605,
    );

    const diff_result = try protocolReadFile(
        &session,
        allocator,
        612,
        613,
        &.{ "agents", "self", "git", "result.json" },
        1606,
    );
    defer allocator.free(diff_result);
    try std.testing.expect(std.mem.indexOf(u8, diff_result, "\"operation\":\"diff_range\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, diff_result, "\"changed_files\":[\"src/app.txt\"]") != null);
}

test "acheron_session: github_pr venom dry run surfaces provider API requests" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const exports_dir = try std.fmt.allocPrint(allocator, "{s}/exports", .{root});
    defer allocator.free(exports_dir);
    try std.fs.cwd().makePath(exports_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
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
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        620,
        621,
        &.{ "agents", "self", "github_pr", "control", "sync.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":42,\"dry_run\":true}",
        1610,
    );

    const github_status = try protocolReadFile(
        &session,
        allocator,
        622,
        623,
        &.{ "agents", "self", "github_pr", "status.json" },
        1611,
    );
    defer allocator.free(github_status);
    try std.testing.expect(std.mem.indexOf(u8, github_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, github_status, "\"tool\":\"github_pr_sync\"") != null);

    const sync_result = try protocolReadFile(
        &session,
        allocator,
        624,
        625,
        &.{ "agents", "self", "github_pr", "result.json" },
        1612,
    );
    defer allocator.free(sync_result);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"operation\":\"sync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "\"dry_run\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, sync_result, "https://api.github.com/repos/DeanoC/Spiderweb/pulls/42") != null);

    try protocolWriteFile(
        &session,
        allocator,
        626,
        627,
        &.{ "agents", "self", "github_pr", "control", "publish_review.json" },
        "{\"repo_key\":\"DeanoC/Spiderweb\",\"pr_number\":42,\"decision\":\"request_changes\",\"review_comment\":\"Please fix the regression.\",\"dry_run\":true,\"thread_actions\":[{\"thread_id\":\"t1\",\"action\":\"comment\"}]}",
        1613,
    );

    const publish_result = try protocolReadFile(
        &session,
        allocator,
        628,
        629,
        &.{ "agents", "self", "github_pr", "result.json" },
        1614,
    );
    defer allocator.free(publish_result);
    try std.testing.expect(std.mem.indexOf(u8, publish_result, "\"operation\":\"publish_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, publish_result, "\"decision\":\"request_changes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, publish_result, "\"thread_actions_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, publish_result, "\"thread_actions_supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, publish_result, "https://api.github.com/repos/DeanoC/Spiderweb/pulls/42/reviews") != null);
}

test "acheron_session: mother can upsert project from system context without project token" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "mother", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "mother",
        .{
            .project_id = control_plane_mod.spider_web_project_id,
            .control_plane = &control_plane,
            .is_admin = false,
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        332,
        333,
        &.{ "agents", "self", "workspaces", "control", "up.json" },
        "{\"name\":\"ZiggyPR\",\"vision\":\"Bootstrap project setup\",\"activate\":false}",
        954,
    );

    const status = try protocolReadFile(
        &session,
        allocator,
        334,
        335,
        &.{ "agents", "self", "workspaces", "status.json" },
        955,
    );
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"tool\":\"workspaces_up\"") != null);

    const result = try protocolReadFile(
        &session,
        allocator,
        336,
        337,
        &.{ "agents", "self", "workspaces", "result.json" },
        956,
    );
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"operation\":\"up\"") != null);
}

test "acheron_session: agents namespace create/list provisions new agent when capability is present" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(projects_dir);
    const allow_agents_create_config = try std.fmt.allocPrint(
        allocator,
        "{s}/default_config.json",
        .{agents_dir},
    );
    defer allocator.free(allow_agents_create_config);
    try std.fs.cwd().writeFile(.{
        .sub_path = allow_agents_create_config,
        .data = "{\"agent_id\":\"default\",\"primary\":{\"capabilities\":[\"agents.create\"]}}",
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        274,
        275,
        &.{ "agents", "self", "agents", "control", "create.json" },
        "{\"agent_id\":\"builder\",\"name\":\"Builder\",\"description\":\"Delivery specialist\",\"capabilities\":[\"code\",\"plan\"]}",
        927,
    );

    const create_status = try protocolReadFile(
        &session,
        allocator,
        276,
        277,
        &.{ "agents", "self", "agents", "status.json" },
        928,
    );
    defer allocator.free(create_status);
    try std.testing.expect(std.mem.indexOf(u8, create_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_status, "\"tool\":\"agents_create\"") != null);

    const create_result = try protocolReadFile(
        &session,
        allocator,
        278,
        279,
        &.{ "agents", "self", "agents", "result.json" },
        929,
    );
    defer allocator.free(create_result);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"operation\":\"create\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"agent_id\":\"builder\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"project_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"activated\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"activation_error\":null") != null);

    const soul_path = try std.fs.path.join(allocator, &.{ agents_dir, "builder", "SOUL.md" });
    defer allocator.free(soul_path);
    const soul_content = try std.fs.cwd().readFileAlloc(allocator, soul_path, 64 * 1024);
    defer allocator.free(soul_content);
    try std.testing.expect(soul_content.len > 0);

    const metadata_path = try std.fs.path.join(allocator, &.{ agents_dir, "builder", "agent.json" });
    defer allocator.free(metadata_path);
    const metadata_content = try std.fs.cwd().readFileAlloc(allocator, metadata_path, 64 * 1024);
    defer allocator.free(metadata_content);
    try std.testing.expect(std.mem.indexOf(u8, metadata_content, "\"persona_pack\":\"default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metadata_content, "\"name\":\"Builder\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metadata_content, "\"capabilities\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        280,
        281,
        &.{ "agents", "self", "agents", "control", "list.json" },
        "{}",
        930,
    );
    const list_result = try protocolReadFile(
        &session,
        allocator,
        282,
        283,
        &.{ "agents", "self", "agents", "result.json" },
        931,
    );
    defer allocator.free(list_result);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"operation\":\"list\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"agent_id\":\"builder\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"persona_pack\":\"default\"") != null);
}

test "acheron_session: agents namespace create can activate a new agent into a requested project" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();
    const created_project = try control_plane.createProject("{\"name\":\"Build Project\",\"vision\":\"Build Project\"}");
    defer allocator.free(created_project);
    var created_project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, created_project, .{});
    defer created_project_parsed.deinit();
    const project_id_val = created_project_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_id_val != .string) return error.TestExpectedResponse;
    const project_id = project_id_val.string;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(projects_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "mother", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "mother",
        .{
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
            .is_admin = true,
        },
    );
    defer session.deinit();

    const create_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"agent_id\":\"builder-activation\",\"project_id\":\"{s}\"}}",
        .{project_id},
    );
    defer allocator.free(create_payload);
    try protocolWriteFile(
        &session,
        allocator,
        283,
        284,
        &.{ "agents", "self", "agents", "control", "create.json" },
        create_payload,
        934,
    );

    const create_result = try protocolReadFile(
        &session,
        allocator,
        285,
        286,
        &.{ "agents", "self", "agents", "result.json" },
        935,
    );
    defer allocator.free(create_result);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"agent_id\":\"builder-activation\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"activated\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"activation_error\":null") != null);

    const workspace_req = try std.fmt.allocPrint(allocator, "{{\"project_id\":\"{s}\"}}", .{project_id});
    defer allocator.free(workspace_req);
    const workspace_status = try control_plane.workspaceStatus("builder-activation", workspace_req);
    defer allocator.free(workspace_status);
    try std.testing.expect(std.mem.indexOf(u8, workspace_status, "\"project_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, workspace_status, project_id) != null);
}

test "acheron_session: agents namespace create reports activation errors without failing creation" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(projects_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "mother", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "mother",
        .{
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
            .is_admin = true,
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        287,
        288,
        &.{ "agents", "self", "agents", "control", "create.json" },
        "{\"agent_id\":\"builder-missing-project\",\"project_id\":\"proj-missing\"}",
        936,
    );

    const create_result = try protocolReadFile(
        &session,
        allocator,
        289,
        290,
        &.{ "agents", "self", "agents", "result.json" },
        937,
    );
    defer allocator.free(create_result);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"agent_id\":\"builder-missing-project\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"activated\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, create_result, "\"activation_error\":\"ProjectNotFound\"") != null);

    const soul_path = try std.fs.path.join(allocator, &.{ agents_dir, "builder-missing-project", "SOUL.md" });
    defer allocator.free(soul_path);
    const soul_content = try std.fs.cwd().readFileAlloc(allocator, soul_path, 64 * 1024);
    defer allocator.free(soul_content);
    try std.testing.expect(soul_content.len > 0);
}

test "acheron_session: agents namespace create denies invoke without capability" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(projects_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
        },
    );
    defer session.deinit();

    const write_error = try protocolWriteFileExpectError(
        &session,
        allocator,
        284,
        285,
        &.{ "agents", "self", "agents", "control", "invoke.json" },
        "{\"op\":\"create\",\"arguments\":{\"agent_id\":\"blocked\"}}",
        932,
        "eperm",
    );
    defer allocator.free(write_error);

    const result = try protocolReadFile(
        &session,
        allocator,
        286,
        287,
        &.{ "agents", "self", "agents", "result.json" },
        933,
    );
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"code\":\"forbidden\"") != null);
}

test "acheron_session: sub_brains namespace upsert/list/delete persists config and updates state" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(projects_dir);
    const allow_sub_brains_config = try std.fmt.allocPrint(
        allocator,
        "{s}/default_config.json",
        .{agents_dir},
    );
    defer allocator.free(allow_sub_brains_config);
    try std.fs.cwd().writeFile(.{
        .sub_path = allow_sub_brains_config,
        .data = "{\"agent_id\":\"default\",\"primary\":{\"can_spawn_subbrains\":true}}",
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
        },
    );
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        250,
        251,
        &.{ "agents", "self", "sub_brains", "control", "upsert.json" },
        "{\"brain_name\":\"research\",\"template\":\"researcher\",\"provider\":{\"name\":\"openai-codex\",\"model\":\"gpt-5.3-codex\",\"think_level\":\"high\"},\"personality\":{\"creature\":\"Knowledge seeker\",\"vibe\":\"Thorough, analytical\",\"emoji\":\"🔍\"}}",
        917,
    );

    const upsert_status = try protocolReadFile(
        &session,
        allocator,
        252,
        253,
        &.{ "agents", "self", "sub_brains", "status.json" },
        918,
    );
    defer allocator.free(upsert_status);
    try std.testing.expect(std.mem.indexOf(u8, upsert_status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, upsert_status, "\"tool\":\"sub_brains_upsert\"") != null);

    const upsert_result = try protocolReadFile(
        &session,
        allocator,
        254,
        255,
        &.{ "agents", "self", "sub_brains", "result.json" },
        919,
    );
    defer allocator.free(upsert_result);
    try std.testing.expect(std.mem.indexOf(u8, upsert_result, "\"operation\":\"upsert\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, upsert_result, "\"brain_name\":\"research\"") != null);

    const config_path = try std.fs.path.join(allocator, &.{ agents_dir, "default_config.json" });
    defer allocator.free(config_path);
    const saved_config = try std.fs.cwd().readFileAlloc(allocator, config_path, 1024 * 1024);
    defer allocator.free(saved_config);
    try std.testing.expect(std.mem.indexOf(u8, saved_config, "\"sub_brains\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, saved_config, "\"research\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        256,
        257,
        &.{ "agents", "self", "sub_brains", "control", "list.json" },
        "{}",
        920,
    );
    const list_result = try protocolReadFile(
        &session,
        allocator,
        258,
        259,
        &.{ "agents", "self", "sub_brains", "result.json" },
        921,
    );
    defer allocator.free(list_result);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"operation\":\"list\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_result, "\"brain_name\":\"research\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        260,
        261,
        &.{ "agents", "self", "sub_brains", "control", "delete.json" },
        "{\"brain_name\":\"research\"}",
        922,
    );
    const delete_result = try protocolReadFile(
        &session,
        allocator,
        262,
        263,
        &.{ "agents", "self", "sub_brains", "result.json" },
        923,
    );
    defer allocator.free(delete_result);
    try std.testing.expect(std.mem.indexOf(u8, delete_result, "\"operation\":\"delete\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, delete_result, "\"removed\":true") != null);
}

test "acheron_session: sub_brains namespace mutation denies invoke without capability" {
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    try std.fs.cwd().makePath(agents_dir);
    try std.fs.cwd().makePath(projects_dir);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
        },
    );
    defer session.deinit();

    const write_error = try protocolWriteFileExpectError(
        &session,
        allocator,
        288,
        289,
        &.{ "agents", "self", "sub_brains", "control", "invoke.json" },
        "{\"op\":\"upsert\",\"arguments\":{\"brain_name\":\"research\"}}",
        934,
        "eperm",
    );
    defer allocator.free(write_error);

    const result = try protocolReadFile(
        &session,
        allocator,
        290,
        291,
        &.{ "agents", "self", "sub_brains", "result.json" },
        935,
    );
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"code\":\"forbidden\"") != null);
}

test "acheron_session: first-class memory namespace operation file maps to runtime tool" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        112,
        113,
        &.{ "agents", "self", "memory", "control", "create.json" },
        "{\"name\":\"ns-memory\",\"kind\":\"note\",\"content\":{\"text\":\"ns bridge ok\"}}",
        830,
    );

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        114,
        115,
        &.{ "agents", "self", "memory", "result.json" },
        840,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"memory_path\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"ownership\":\"working_memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"name\":\"ns-memory\"") != null);

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        116,
        117,
        &.{ "agents", "self", "memory", "status.json" },
        850,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"tool\":\"memory_create\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"error\":null") != null);
}

test "acheron_session: memory load accepts memory_path identity" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        118,
        119,
        &.{ "agents", "self", "memory", "control", "create.json" },
        "{\"name\":\"mem-path\",\"kind\":\"note\",\"content\":{\"text\":\"path identity\"}}",
        862,
    );

    const created_payload = try protocolReadFile(
        &session,
        allocator,
        120,
        121,
        &.{ "agents", "self", "memory", "result.json" },
        863,
    );
    defer allocator.free(created_payload);
    var created = try std.json.parseFromSlice(std.json.Value, allocator, created_payload, .{});
    defer created.deinit();
    const result_obj = created.value.object.get("result") orelse return error.TestExpectedResponse;
    if (result_obj != .object) return error.TestExpectedResponse;
    const memory_path_value = result_obj.object.get("memory_path") orelse return error.TestExpectedResponse;
    if (memory_path_value != .string or memory_path_value.string.len == 0) return error.TestExpectedResponse;

    const escaped_memory_path = try unified.jsonEscape(allocator, memory_path_value.string);
    defer allocator.free(escaped_memory_path);
    const load_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"memory_path\":\"{s}\"}}",
        .{escaped_memory_path},
    );
    defer allocator.free(load_payload);
    try protocolWriteFile(
        &session,
        allocator,
        122,
        123,
        &.{ "agents", "self", "memory", "control", "load.json" },
        load_payload,
        864,
    );

    const loaded_payload = try protocolReadFile(
        &session,
        allocator,
        124,
        125,
        &.{ "agents", "self", "memory", "result.json" },
        865,
    );
    defer allocator.free(loaded_payload);
    try std.testing.expect(std.mem.indexOf(u8, loaded_payload, "\"memory_path\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, loaded_payload, "\"ownership\":\"working_memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, loaded_payload, memory_path_value.string) != null);
}

test "acheron_session: first-class web_search namespace operation file maps to runtime tool" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        134,
        135,
        &.{ "agents", "self", "web_search", "control", "search.json" },
        "{\"query\":\"zig language\"}",
        856,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        136,
        137,
        &.{ "agents", "self", "web_search", "status.json" },
        857,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"tool\":\"web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"idle\"") == null);

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        138,
        139,
        &.{ "agents", "self", "web_search", "result.json" },
        858,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(result_payload.len > 2);
    try std.testing.expect(result_payload[0] == '{');
}

test "acheron_session: first-class terminal namespace operation file maps to runtime tool" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        234,
        235,
        &.{ "agents", "self", "terminal", "control", "exec.json" },
        "{\"command\":\"echo terminal-namespace\"}",
        906,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        236,
        237,
        &.{ "agents", "self", "terminal", "status.json" },
        907,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"tool\":\"shell_exec\"") != null);

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        238,
        239,
        &.{ "agents", "self", "terminal", "result.json" },
        908,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "terminal-namespace") != null);
}

test "acheron_session: first-class terminal namespace denies user actor shell access" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .actor_type = "user",
        },
    );
    defer session.deinit();

    const response = try protocolWriteFileExpectError(
        &session,
        allocator,
        240,
        241,
        &.{ "agents", "self", "terminal", "control", "exec.json" },
        "{\"command\":\"echo terminal-namespace\"}",
        909,
        "eperm",
    );
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "terminal invoke access denied by permissions") != null);
}

test "acheron_session: terminal-v2 session lifecycle updates current and sessions state" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        300,
        301,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"build\",\"cwd\":\".\"}",
        920,
    );

    const current_after_create = try protocolReadFile(
        &session,
        allocator,
        302,
        303,
        &.{ "agents", "self", "terminal", "current.json" },
        921,
    );
    defer allocator.free(current_after_create);
    try std.testing.expect(std.mem.indexOf(u8, current_after_create, "\"session_id\":\"build\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        304,
        305,
        &.{ "agents", "self", "terminal", "control", "exec.json" },
        "{\"session_id\":\"build\",\"command\":\"echo terminal-v2\"}",
        922,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        306,
        307,
        &.{ "agents", "self", "terminal", "status.json" },
        923,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"session_id\":\"build\"") != null);

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        308,
        309,
        &.{ "agents", "self", "terminal", "result.json" },
        924,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"operation\":\"exec\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"data_b64\":") != null);

    var result_parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_payload, .{});
    defer result_parsed.deinit();
    const result_obj = result_parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    if (result_obj != .object) return error.TestExpectedResponse;
    const data_b64 = result_obj.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (data_b64 != .string) return error.TestExpectedResponse;
    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_b64.string);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, data_b64.string);
    try std.testing.expect(std.mem.indexOf(u8, decoded, "terminal-v2") != null);

    try protocolWriteFile(
        &session,
        allocator,
        310,
        311,
        &.{ "agents", "self", "terminal", "control", "close.json" },
        "{\"session_id\":\"build\"}",
        925,
    );

    const current_after_close = try protocolReadFile(
        &session,
        allocator,
        312,
        313,
        &.{ "agents", "self", "terminal", "current.json" },
        926,
    );
    defer allocator.free(current_after_close);
    try std.testing.expect(std.mem.indexOf(u8, current_after_close, "\"session\":null") != null);

    const close_status_payload = try protocolReadFile(
        &session,
        allocator,
        314,
        315,
        &.{ "agents", "self", "terminal", "status.json" },
        927,
    );
    defer allocator.free(close_status_payload);
    try std.testing.expect(std.mem.indexOf(u8, close_status_payload, "\"tool\":\"terminal_session_close\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, close_status_payload, "\"session_id\":\"build\"") != null);

    const close_result_payload = try protocolReadFile(
        &session,
        allocator,
        316,
        317,
        &.{ "agents", "self", "terminal", "result.json" },
        928,
    );
    defer allocator.free(close_result_payload);
    try std.testing.expect(std.mem.indexOf(u8, close_result_payload, "\"operation\":\"close\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, close_result_payload, "\"session_id\":\"build\"") != null);

    const sessions_payload = try protocolReadFile(
        &session,
        allocator,
        318,
        319,
        &.{ "agents", "self", "terminal", "sessions.json" },
        929,
    );
    defer allocator.free(sessions_payload);
    try std.testing.expect(std.mem.indexOf(u8, sessions_payload, "\"session_id\":\"build\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sessions_payload, "\"state\":\"closed\"") != null);
}

test "acheron_session: terminal-v2 invoke envelope routes create and exec operations" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        316,
        317,
        &.{ "agents", "self", "terminal", "control", "invoke.json" },
        "{\"op\":\"create\",\"arguments\":{\"session_id\":\"inv\"}}",
        928,
    );

    try protocolWriteFile(
        &session,
        allocator,
        318,
        319,
        &.{ "agents", "self", "terminal", "control", "invoke.json" },
        "{\"op\":\"exec\",\"arguments\":{\"session_id\":\"inv\",\"command\":\"echo invoke-v2\"}}",
        929,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        320,
        321,
        &.{ "agents", "self", "terminal", "status.json" },
        930,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"session_id\":\"inv\"") != null);

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        322,
        323,
        &.{ "agents", "self", "terminal", "result.json" },
        931,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"operation\":\"exec\"") != null);
}

test "acheron_session: terminal-v2 write read resize operations update status and result" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        324,
        325,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"io\",\"shell\":\"/bin/sh\"}",
        932,
    );

    try protocolWriteFile(
        &session,
        allocator,
        326,
        327,
        &.{ "agents", "self", "terminal", "control", "write.json" },
        "{\"session_id\":\"io\",\"input\":\"echo wr-marker\",\"append_newline\":true}",
        933,
    );

    try protocolWriteFile(
        &session,
        allocator,
        328,
        329,
        &.{ "agents", "self", "terminal", "control", "resize.json" },
        "{\"session_id\":\"io\",\"cols\":120,\"rows\":40}",
        934,
    );

    try protocolWriteFile(
        &session,
        allocator,
        330,
        331,
        &.{ "agents", "self", "terminal", "control", "read.json" },
        "{\"session_id\":\"io\",\"timeout_ms\":1000,\"max_bytes\":65536}",
        935,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        332,
        333,
        &.{ "agents", "self", "terminal", "status.json" },
        936,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"tool\":\"terminal_session_read\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"session_id\":\"io\"") != null);

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        334,
        335,
        &.{ "agents", "self", "terminal", "result.json" },
        937,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"operation\":\"read\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"data_b64\":") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_payload, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(.object, parsed.value);
    const result_obj = parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    try std.testing.expectEqual(.object, result_obj);
    const data_b64_value = result_obj.object.get("data_b64") orelse return error.TestExpectedResponse;
    try std.testing.expectEqual(.string, data_b64_value);
    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_b64_value.string);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, data_b64_value.string);
    try std.testing.expect(std.mem.indexOf(u8, decoded, "wr-marker") != null);

    try protocolWriteFile(
        &session,
        allocator,
        336,
        337,
        &.{ "agents", "self", "terminal", "control", "close.json" },
        "{\"session_id\":\"io\"}",
        938,
    );
}

test "acheron_session: terminal-v2 buffered output survives partial reads and multiple writes" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        340,
        341,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"buf\"}",
        939,
    );

    const terminal_session = session.terminal_sessions.getPtr("buf") orelse return error.TestExpectedResponse;
    terminal_session.buffered_result = try allocator.dupe(u8, "abcdefgh");

    try protocolWriteFile(
        &session,
        allocator,
        342,
        343,
        &.{ "agents", "self", "terminal", "control", "read.json" },
        "{\"session_id\":\"buf\",\"max_bytes\":3}",
        940,
    );

    const first_read_payload = try protocolReadFile(
        &session,
        allocator,
        344,
        345,
        &.{ "agents", "self", "terminal", "result.json" },
        941,
    );
    defer allocator.free(first_read_payload);

    var first_parsed = try std.json.parseFromSlice(std.json.Value, allocator, first_read_payload, .{});
    defer first_parsed.deinit();
    const first_result = first_parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    if (first_result != .object) return error.TestExpectedResponse;
    const first_b64 = first_result.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (first_b64 != .string) return error.TestExpectedResponse;
    const first_decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(first_b64.string);
    const first_decoded = try allocator.alloc(u8, first_decoded_len);
    defer allocator.free(first_decoded);
    try std.base64.standard.Decoder.decode(first_decoded, first_b64.string);
    try std.testing.expectEqualStrings("abc", first_decoded);

    try protocolWriteFile(
        &session,
        allocator,
        346,
        347,
        &.{ "agents", "self", "terminal", "control", "read.json" },
        "{\"session_id\":\"buf\",\"max_bytes\":3}",
        942,
    );

    const second_read_payload = try protocolReadFile(
        &session,
        allocator,
        348,
        349,
        &.{ "agents", "self", "terminal", "result.json" },
        943,
    );
    defer allocator.free(second_read_payload);

    var second_parsed = try std.json.parseFromSlice(std.json.Value, allocator, second_read_payload, .{});
    defer second_parsed.deinit();
    const second_result = second_parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    if (second_result != .object) return error.TestExpectedResponse;
    const second_b64 = second_result.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (second_b64 != .string) return error.TestExpectedResponse;
    const second_decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(second_b64.string);
    const second_decoded = try allocator.alloc(u8, second_decoded_len);
    defer allocator.free(second_decoded);
    try std.base64.standard.Decoder.decode(second_decoded, second_b64.string);
    try std.testing.expectEqualStrings("def", second_decoded);

    try protocolWriteFile(
        &session,
        allocator,
        350,
        351,
        &.{ "agents", "self", "terminal", "control", "read.json" },
        "{\"session_id\":\"buf\",\"max_bytes\":8}",
        944,
    );

    const third_read_payload = try protocolReadFile(
        &session,
        allocator,
        352,
        353,
        &.{ "agents", "self", "terminal", "result.json" },
        945,
    );
    defer allocator.free(third_read_payload);

    var third_parsed = try std.json.parseFromSlice(std.json.Value, allocator, third_read_payload, .{});
    defer third_parsed.deinit();
    const third_result = third_parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    if (third_result != .object) return error.TestExpectedResponse;
    const third_b64 = third_result.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (third_b64 != .string) return error.TestExpectedResponse;
    const third_decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(third_b64.string);
    const third_decoded = try allocator.alloc(u8, third_decoded_len);
    defer allocator.free(third_decoded);
    try std.base64.standard.Decoder.decode(third_decoded, third_b64.string);
    try std.testing.expectEqualStrings("gh", third_decoded);
}

test "acheron_session: terminal-v2 write accepts binary-safe data_b64 input" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        368,
        369,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"bin\"}",
        953,
    );

    const raw_bytes = [_]u8{ ':', ' ', '#', 0xff, '\n' };
    const encoded = try std.base64.standard.Encoder.allocEncode(allocator, &raw_bytes);
    defer allocator.free(encoded);
    const write_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"session_id\":\"bin\",\"data_b64\":\"{s}\"}}",
        .{encoded},
    );
    defer allocator.free(write_payload);

    try protocolWriteFile(
        &session,
        allocator,
        370,
        371,
        &.{ "agents", "self", "terminal", "control", "write.json" },
        write_payload,
        954,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        372,
        373,
        &.{ "agents", "self", "terminal", "status.json" },
        955,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"session_id\":\"bin\"") != null);
}

test "acheron_session: terminal-v2 preserves shell state across writes" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        374,
        375,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"state\",\"cwd\":\".\"}",
        956,
    );

    try protocolWriteFile(
        &session,
        allocator,
        376,
        377,
        &.{ "agents", "self", "terminal", "control", "write.json" },
        "{\"session_id\":\"state\",\"input\":\"cd src\",\"append_newline\":true}",
        957,
    );

    try protocolWriteFile(
        &session,
        allocator,
        378,
        379,
        &.{ "agents", "self", "terminal", "control", "write.json" },
        "{\"session_id\":\"state\",\"input\":\"pwd\",\"append_newline\":true}",
        958,
    );

    try protocolWriteFile(
        &session,
        allocator,
        380,
        381,
        &.{ "agents", "self", "terminal", "control", "read.json" },
        "{\"session_id\":\"state\",\"timeout_ms\":100,\"max_bytes\":65536}",
        959,
    );

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        382,
        383,
        &.{ "agents", "self", "terminal", "result.json" },
        960,
    );
    defer allocator.free(result_payload);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_payload, .{});
    defer parsed.deinit();
    const result_obj = parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    if (result_obj != .object) return error.TestExpectedResponse;
    const data_b64 = result_obj.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (data_b64 != .string) return error.TestExpectedResponse;
    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_b64.string);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, data_b64.string);
    try std.testing.expect(std.mem.indexOf(u8, decoded, "/src") != null);
}

test "acheron_session: terminal-v2 exec output is not replayed by read" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        384,
        385,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"execdup\"}",
        961,
    );

    try protocolWriteFile(
        &session,
        allocator,
        386,
        387,
        &.{ "agents", "self", "terminal", "control", "exec.json" },
        "{\"session_id\":\"execdup\",\"command\":\"echo once\"}",
        962,
    );

    try protocolWriteFile(
        &session,
        allocator,
        388,
        389,
        &.{ "agents", "self", "terminal", "control", "read.json" },
        "{\"session_id\":\"execdup\",\"timeout_ms\":50,\"max_bytes\":65536}",
        963,
    );

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        390,
        391,
        &.{ "agents", "self", "terminal", "result.json" },
        964,
    );
    defer allocator.free(result_payload);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_payload, .{});
    defer parsed.deinit();
    const result_obj = parsed.value.object.get("result") orelse return error.TestExpectedResponse;
    if (result_obj != .object) return error.TestExpectedResponse;
    const data_b64 = result_obj.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (data_b64 != .string) return error.TestExpectedResponse;
    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_b64.string);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, data_b64.string);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "acheron_session: terminal-v2 read honors timeout_ms when idle" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        392,
        393,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"idle\"}",
        965,
    );

    const started_at_ms = std.time.milliTimestamp();
    try protocolWriteFile(
        &session,
        allocator,
        394,
        395,
        &.{ "agents", "self", "terminal", "control", "read.json" },
        "{\"session_id\":\"idle\",\"timeout_ms\":150,\"max_bytes\":65536}",
        966,
    );
    const elapsed_ms = std.time.milliTimestamp() - started_at_ms;
    try std.testing.expect(elapsed_ms >= 100);
}

test "acheron_session: terminal-v2 write and exec surface shell_exec failures" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    try protocolWriteFile(
        &session,
        allocator,
        354,
        355,
        &.{ "agents", "self", "terminal", "control", "create.json" },
        "{\"session_id\":\"fail\",\"cwd\":\"/definitely/not/a/real/dir\"}",
        946,
    );

    try protocolWriteFile(
        &session,
        allocator,
        356,
        357,
        &.{ "agents", "self", "terminal", "control", "write.json" },
        "{\"session_id\":\"fail\",\"input\":\"echo should-fail\",\"append_newline\":true}",
        947,
    );

    const write_status_payload = try protocolReadFile(
        &session,
        allocator,
        358,
        359,
        &.{ "agents", "self", "terminal", "status.json" },
        948,
    );
    defer allocator.free(write_status_payload);
    try std.testing.expect(std.mem.indexOf(u8, write_status_payload, "\"state\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, write_status_payload, "\"tool\":\"terminal_session_write\"") != null);

    const write_result_payload = try protocolReadFile(
        &session,
        allocator,
        360,
        361,
        &.{ "agents", "self", "terminal", "result.json" },
        949,
    );
    defer allocator.free(write_result_payload);
    try std.testing.expect(std.mem.indexOf(u8, write_result_payload, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, write_result_payload, "\"operation\":\"write\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        362,
        363,
        &.{ "agents", "self", "terminal", "control", "exec.json" },
        "{\"session_id\":\"fail\",\"command\":\"echo still-fails\"}",
        950,
    );

    const exec_status_payload = try protocolReadFile(
        &session,
        allocator,
        364,
        365,
        &.{ "agents", "self", "terminal", "status.json" },
        951,
    );
    defer allocator.free(exec_status_payload);
    try std.testing.expect(std.mem.indexOf(u8, exec_status_payload, "\"state\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, exec_status_payload, "\"tool\":\"shell_exec\"") != null);

    const exec_result_payload = try protocolReadFile(
        &session,
        allocator,
        366,
        367,
        &.{ "agents", "self", "terminal", "result.json" },
        952,
    );
    defer allocator.free(exec_result_payload);
    try std.testing.expect(std.mem.indexOf(u8, exec_result_payload, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, exec_result_payload, "\"operation\":\"exec\"") != null);

    try protocolWriteFile(
        &session,
        allocator,
        368,
        369,
        &.{ "agents", "self", "terminal", "control", "exec.json" },
        "{\"command\":\"echo implicit-still-fails\"}",
        953,
    );

    const implicit_exec_result_payload = try protocolReadFile(
        &session,
        allocator,
        370,
        371,
        &.{ "agents", "self", "terminal", "result.json" },
        954,
    );
    defer allocator.free(implicit_exec_result_payload);
    try std.testing.expect(std.mem.indexOf(u8, implicit_exec_result_payload, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, implicit_exec_result_payload, "\"operation\":\"exec\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, implicit_exec_result_payload, "\"session_id\":\"fail\"") != null);
}

test "acheron_session: first-class memory namespace rejects unknown invoke op" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const response = try protocolWriteFileExpectError(
        &session,
        allocator,
        140,
        141,
        &.{ "agents", "self", "memory", "control", "invoke.json" },
        "{\"op\":\"nope\",\"arguments\":{}}",
        859,
        "invalid",
    );
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "memory payload is invalid") != null);
}

test "acheron_session: first-class memory namespace invoke does not accept non-memory tool aliases" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const response = try protocolWriteFileExpectError(
        &session,
        allocator,
        142,
        143,
        &.{ "agents", "self", "memory", "control", "invoke.json" },
        "{\"tool_name\":\"web_search\",\"arguments\":{\"query\":\"zig\"}}",
        860,
        "invalid",
    );
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "memory payload is invalid") != null);
}

test "acheron_session: first-class namespace invoke honors PERMISSIONS policy" {
    const allocator = std.testing.allocator;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.init(allocator, runtime_handle, &job_index, "default");
    defer session.deinit();

    const agents_root = session.lookupChild(session.root_id, "agents") orelse return error.TestExpectedResponse;
    const self_agent = session.lookupChild(agents_root, "self") orelse return error.TestExpectedResponse;
    const memory_dir = session.lookupChild(self_agent, "memory") orelse return error.TestExpectedResponse;
    const permissions_id = session.lookupChild(memory_dir, "PERMISSIONS.json") orelse return error.TestExpectedResponse;
    try session.setFileContent(permissions_id, "{\"default\":\"deny-by-default\",\"allow_roles\":[]}");

    const response = try protocolWriteFileExpectError(
        &session,
        allocator,
        144,
        145,
        &.{ "agents", "self", "memory", "control", "create.json" },
        "{\"name\":\"blocked-memory\",\"kind\":\"note\",\"content\":{\"text\":\"blocked\"}}",
        861,
        "eperm",
    );
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "memory invoke access denied by permissions") != null);
}

test "acheron_session: mounts namespace manages mount bind and resolve operations" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const joined = try control_plane.ensureNode("mounts-node", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(joined);
    var joined_parsed = try std.json.parseFromSlice(std.json.Value, allocator, joined, .{});
    defer joined_parsed.deinit();
    const node_id = joined_parsed.value.object.get("node_id").?.string;

    const project_json = try control_plane.createProject("{\"name\":\"MountSvc\",\"vision\":\"MountSvc\"}");
    defer allocator.free(project_json);
    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project_parsed.deinit();
    const project_id = project_parsed.value.object.get("project_id").?.string;
    const project_token = project_parsed.value.object.get("project_token").?.string;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = project_id,
            .project_token = project_token,
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const escaped_node_id = try unified.jsonEscape(allocator, node_id);
    defer allocator.free(escaped_node_id);
    const escaped_project_id = try unified.jsonEscape(allocator, project_id);
    defer allocator.free(escaped_project_id);
    const escaped_project_token = try unified.jsonEscape(allocator, project_token);
    defer allocator.free(escaped_project_token);
    const mount_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/nodes/local/fs\"}}",
        .{ escaped_project_id, escaped_project_token, escaped_node_id },
    );
    defer allocator.free(mount_payload);
    try protocolWriteFile(
        &session,
        allocator,
        150,
        151,
        &.{ "agents", "self", "mounts", "control", "mount.json" },
        mount_payload,
        866,
    );

    const bind_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"bind_path\":\"/repo\",\"target_path\":\"/nodes/local/fs\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(bind_payload);
    try protocolWriteFile(
        &session,
        allocator,
        152,
        153,
        &.{ "agents", "self", "mounts", "control", "bind.json" },
        bind_payload,
        867,
    );

    const resolve_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"path\":\"/repo/src\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(resolve_payload);
    try protocolWriteFile(
        &session,
        allocator,
        154,
        155,
        &.{ "agents", "self", "mounts", "control", "resolve.json" },
        resolve_payload,
        868,
    );

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        156,
        157,
        &.{ "agents", "self", "mounts", "result.json" },
        869,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"operation\":\"resolve\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"matched\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"resolved_path\":\"/nodes/local/fs/src\"") != null);

    const repo_listing = try protocolReadFile(
        &session,
        allocator,
        158,
        159,
        &.{"repo"},
        870,
    );
    defer allocator.free(repo_listing);
}

test "acheron_session: mounts namespace mkdir creates local export folders" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const project_json = try control_plane.createProject("{\"name\":\"MountMkdir\",\"vision\":\"MountMkdir\"}");
    defer allocator.free(project_json);
    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project_parsed.deinit();
    const project_id = project_parsed.value.object.get("project_id").?.string;
    const project_token = project_parsed.value.object.get("project_token").?.string;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const local_export_root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(local_export_root);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = project_id,
            .project_token = project_token,
            .control_plane = &control_plane,
            .local_fs_export_root = local_export_root,
        },
    );
    defer session.deinit();

    const escaped_project_id = try unified.jsonEscape(allocator, project_id);
    defer allocator.free(escaped_project_id);
    const escaped_project_token = try unified.jsonEscape(allocator, project_token);
    defer allocator.free(escaped_project_token);
    const mkdir_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"path\":\"new-project/root\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(mkdir_payload);
    try protocolWriteFile(
        &session,
        allocator,
        170,
        171,
        &.{ "agents", "self", "mounts", "control", "mkdir.json" },
        mkdir_payload,
        875,
    );

    const created_payload = try protocolReadFile(
        &session,
        allocator,
        172,
        173,
        &.{ "agents", "self", "mounts", "result.json" },
        876,
    );
    defer allocator.free(created_payload);
    try std.testing.expect(std.mem.indexOf(u8, created_payload, "\"operation\":\"mkdir\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, created_payload, "\"path\":\"/nodes/local/fs/new-project/root\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, created_payload, "\"created\":true") != null);

    const created_host_path = try std.fs.path.join(allocator, &.{ local_export_root, "new-project", "root" });
    defer allocator.free(created_host_path);
    var created_dir = try std.fs.openDirAbsolute(created_host_path, .{});
    created_dir.close();

    const mkdir_existing_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"path\":\"/nodes/local/fs/new-project/root\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(mkdir_existing_payload);
    try protocolWriteFile(
        &session,
        allocator,
        174,
        175,
        &.{ "agents", "self", "mounts", "control", "mkdir.json" },
        mkdir_existing_payload,
        877,
    );

    const existing_payload = try protocolReadFile(
        &session,
        allocator,
        176,
        177,
        &.{ "agents", "self", "mounts", "result.json" },
        878,
    );
    defer allocator.free(existing_payload);
    try std.testing.expect(std.mem.indexOf(u8, existing_payload, "\"created\":false") != null);

    const mkdir_invalid_payload = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"path\":\"../escape\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(mkdir_invalid_payload);
    const invalid_response = try protocolWriteFileExpectError(
        &session,
        allocator,
        178,
        179,
        &.{ "agents", "self", "mounts", "control", "mkdir.json" },
        mkdir_invalid_payload,
        879,
        "invalid",
    );
    defer allocator.free(invalid_response);
}

test "acheron_session: node services namespace prefers control-plane catalog" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-a", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"terminal-9\",\"kind\":\"terminal\",\"version\":\"1\",\"state\":\"degraded\",\"endpoints\":[\"/nodes/{s}/terminal/9\"],\"capabilities\":{{\"pty\":true,\"terminal_id\":\"9\"}}}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-test", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(project_dir);

    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-test\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = "proj-test",
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const node_dir = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const node_caps_id = session.lookupChild(node_dir, "CAPS.json") orelse return error.TestExpectedResponse;
    const node_caps = session.nodes.get(node_caps_id) orelse return error.TestExpectedResponse;
    const services_root = session.lookupChild(node_dir, "venoms") orelse return error.TestExpectedResponse;
    const services_index_id = session.lookupChild(services_root, "VENOMS.json") orelse return error.TestExpectedResponse;
    const services_index = session.nodes.get(services_index_id) orelse return error.TestExpectedResponse;
    const terminal = session.lookupChild(services_root, "terminal-9") orelse return error.TestExpectedResponse;
    const status_id = session.lookupChild(terminal, "STATUS.json") orelse return error.TestExpectedResponse;
    const status_node = session.nodes.get(status_id) orelse return error.TestExpectedResponse;
    const caps_id = session.lookupChild(terminal, "CAPS.json") orelse return error.TestExpectedResponse;
    const caps_node = session.nodes.get(caps_id) orelse return error.TestExpectedResponse;
    const agents_root = session.lookupChild(session.root_id, "agents") orelse return error.TestExpectedResponse;
    const self_agent = session.lookupChild(agents_root, "self") orelse return error.TestExpectedResponse;
    const self_services_dir = session.lookupChild(self_agent, "venoms") orelse return error.TestExpectedResponse;
    const self_services_index_id = session.lookupChild(self_services_dir, "VENOMS.json") orelse return error.TestExpectedResponse;
    const self_services_index = session.nodes.get(self_services_index_id) orelse return error.TestExpectedResponse;
    const node_service_events_payload = try protocolReadFile(
        &session,
        allocator,
        140,
        141,
        &.{ "global", "venoms", "node-venom-events.ndjson" },
        142,
    );
    defer allocator.free(node_service_events_payload);

    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"fs\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"terminal\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index.content, "\"venom_id\":\"terminal-9\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_node.content, "\"state\":\"degraded\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, caps_node.content, "\"terminal_id\":\"9\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index.content, "\"node_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index.content, "\"venom_id\":\"terminal-9\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_service_events_payload, "\"node_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_service_events_payload, "\"venom_delta\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_service_events_payload, "\"venom_id\":\"terminal-9\"") != null);
}

test "acheron_session: node Venom events file returns full retained feed" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.initWithOptions(allocator, .{
        .node_venom_event_history_max = 520,
    });
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-retained-feed", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);

    for (0..513) |idx| {
        const upsert_req = try std.fmt.allocPrint(
            allocator,
            "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"terminal-main\",\"kind\":\"terminal\",\"version\":\"{d}\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/terminal/main\"],\"capabilities\":{{\"pty\":true}}}}]}}",
            .{ escaped_node_id, escaped_node_secret, idx, escaped_node_id },
        );
        defer allocator.free(upsert_req);
        const upserted = try control_plane.nodeVenomUpsert(upsert_req);
        defer allocator.free(upserted);
    }

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .is_admin = true,
        },
    );
    defer session.deinit();

    const node_service_events_payload = try protocolReadFile(
        &session,
        allocator,
        240,
        241,
        &.{ "global", "venoms", "node-venom-events.ndjson" },
        242,
    );
    defer allocator.free(node_service_events_payload);

    const line_count: usize = if (node_service_events_payload.len == 0) 0 else std.mem.count(u8, node_service_events_payload, "\n") + 1;
    try std.testing.expectEqual(@as(usize, 513), line_count);
    try std.testing.expect(std.mem.indexOf(u8, node_service_events_payload, "\"version\":\"512\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_service_events_payload, "\"version\":\"0\"") != null);
}

test "acheron_session: empty control-plane Venom catalog suppresses policy fallback roots" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-empty-services", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[]}}",
        .{ escaped_node_id, escaped_node_secret },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-empty", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(project_dir);

    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-empty\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[\"1\"]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = "proj-empty",
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const node_dir = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const node_caps_id = session.lookupChild(node_dir, "CAPS.json") orelse return error.TestExpectedResponse;
    const node_caps = session.nodes.get(node_caps_id) orelse return error.TestExpectedResponse;
    const services_root = session.lookupChild(node_dir, "venoms") orelse return error.TestExpectedResponse;
    const services_index_id = session.lookupChild(services_root, "VENOMS.json") orelse return error.TestExpectedResponse;
    const services_index = session.nodes.get(services_index_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(session.lookupChild(services_root, "fs") == null);
    try std.testing.expect(session.lookupChild(services_root, "terminal-1") == null);
    try std.testing.expect(session.lookupChild(node_dir, "fs") == null);
    try std.testing.expect(session.lookupChild(node_dir, "terminal") == null);
    try std.testing.expect(std.mem.eql(u8, services_index.content, "[]"));
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"fs\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"terminal\":false") != null);
}

test "acheron_session: project meta includes control-plane workspace status" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-meta", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const created_project = try control_plane.createProject("{\"name\":\"MetaWorldFS\",\"vision\":\"MetaWorldFS\"}");
    defer allocator.free(created_project);
    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, created_project, .{});
    defer project_parsed.deinit();
    if (project_parsed.value != .object) return error.TestExpectedResponse;
    const project_id = project_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_id != .string) return error.TestExpectedResponse;
    const project_token = project_parsed.value.object.get("project_token") orelse return error.TestExpectedResponse;
    if (project_token != .string) return error.TestExpectedResponse;

    const escaped_project_id = try unified.jsonEscape(allocator, project_id.string);
    defer allocator.free(escaped_project_id);
    const escaped_project_token = try unified.jsonEscape(allocator, project_token.string);
    defer allocator.free(escaped_project_token);
    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);

    const mount_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ escaped_project_id, escaped_project_token, escaped_node_id },
    );
    defer allocator.free(mount_req);
    const mounted = try control_plane.setProjectMount(mount_req);
    defer allocator.free(mounted);

    const up_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(up_req);
    const up = try control_plane.projectUp("default", up_req);
    defer allocator.free(up);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ projects_dir, project_id.string });
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(project_dir);

    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[{{\"name\":\"{s}::fs\",\"node_id\":\"{s}\",\"resource\":\"fs\"}}]}}",
        .{ escaped_project_id, escaped_node_id, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = project_id.string,
            .project_token = project_token.string,
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const projects_root = session.lookupChild(session.root_id, "projects") orelse return error.TestExpectedResponse;
    const project_node = session.lookupChild(projects_root, project_id.string) orelse return error.TestExpectedResponse;
    const project_fs_node = session.lookupChild(project_node, "fs") orelse return error.TestExpectedResponse;
    const project_nodes_node = session.lookupChild(project_node, "nodes") orelse return error.TestExpectedResponse;
    const project_fs_schema_id = session.lookupChild(project_fs_node, "SCHEMA.json") orelse return error.TestExpectedResponse;
    const project_nodes_schema_id = session.lookupChild(project_nodes_node, "SCHEMA.json") orelse return error.TestExpectedResponse;
    const project_agents_node = session.lookupChild(project_node, "agents") orelse return error.TestExpectedResponse;
    const project_agents_caps_id = session.lookupChild(project_agents_node, "CAPS.json") orelse return error.TestExpectedResponse;
    const meta_node = session.lookupChild(project_node, "meta") orelse return error.TestExpectedResponse;
    const meta_schema_id = session.lookupChild(meta_node, "SCHEMA.json") orelse return error.TestExpectedResponse;
    const root_meta_node = session.lookupChild(session.root_id, "meta") orelse return error.TestExpectedResponse;
    const root_meta_schema_id = session.lookupChild(root_meta_node, "SCHEMA.json") orelse return error.TestExpectedResponse;
    const root_workspace_status_id = session.lookupChild(root_meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
    const root_workspace_availability_id = session.lookupChild(root_meta_node, "workspace_availability.json") orelse return error.TestExpectedResponse;
    const root_workspace_health_id = session.lookupChild(root_meta_node, "workspace_health.json") orelse return error.TestExpectedResponse;
    const root_workspace_alerts_id = session.lookupChild(root_meta_node, "workspace_alerts.json") orelse return error.TestExpectedResponse;
    const mount_link_id = session.lookupChild(project_fs_node, "mount::src") orelse return error.TestExpectedResponse;
    const node_link_id = session.lookupChild(project_nodes_node, node_id.string) orelse return error.TestExpectedResponse;
    const topology_id = session.lookupChild(meta_node, "topology.json") orelse return error.TestExpectedResponse;
    const nodes_meta_id = session.lookupChild(meta_node, "nodes.json") orelse return error.TestExpectedResponse;
    const agents_meta_id = session.lookupChild(meta_node, "agents.json") orelse return error.TestExpectedResponse;
    const sources_id = session.lookupChild(meta_node, "sources.json") orelse return error.TestExpectedResponse;
    const contracts_id = session.lookupChild(meta_node, "contracts.json") orelse return error.TestExpectedResponse;
    const paths_id = session.lookupChild(meta_node, "paths.json") orelse return error.TestExpectedResponse;
    const summary_id = session.lookupChild(meta_node, "summary.json") orelse return error.TestExpectedResponse;
    const alerts_id = session.lookupChild(meta_node, "alerts.json") orelse return error.TestExpectedResponse;
    const workspace_id = session.lookupChild(meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
    const mounts_id = session.lookupChild(meta_node, "mounts.json") orelse return error.TestExpectedResponse;
    const desired_mounts_id = session.lookupChild(meta_node, "desired_mounts.json") orelse return error.TestExpectedResponse;
    const actual_mounts_id = session.lookupChild(meta_node, "actual_mounts.json") orelse return error.TestExpectedResponse;
    const drift_id = session.lookupChild(meta_node, "drift.json") orelse return error.TestExpectedResponse;
    const reconcile_id = session.lookupChild(meta_node, "reconcile.json") orelse return error.TestExpectedResponse;
    const availability_id = session.lookupChild(meta_node, "availability.json") orelse return error.TestExpectedResponse;
    const health_id = session.lookupChild(meta_node, "health.json") orelse return error.TestExpectedResponse;

    const project_fs_schema = session.nodes.get(project_fs_schema_id) orelse return error.TestExpectedResponse;
    const project_nodes_schema = session.nodes.get(project_nodes_schema_id) orelse return error.TestExpectedResponse;
    const project_agents_caps = session.nodes.get(project_agents_caps_id) orelse return error.TestExpectedResponse;
    const meta_schema = session.nodes.get(meta_schema_id) orelse return error.TestExpectedResponse;
    const root_meta_schema = session.nodes.get(root_meta_schema_id) orelse return error.TestExpectedResponse;
    const root_workspace_status_node = session.nodes.get(root_workspace_status_id) orelse return error.TestExpectedResponse;
    const root_workspace_availability_node = session.nodes.get(root_workspace_availability_id) orelse return error.TestExpectedResponse;
    const root_workspace_health_node = session.nodes.get(root_workspace_health_id) orelse return error.TestExpectedResponse;
    const root_workspace_alerts_node = session.nodes.get(root_workspace_alerts_id) orelse return error.TestExpectedResponse;
    const mount_link_node = session.nodes.get(mount_link_id) orelse return error.TestExpectedResponse;
    const node_link_node = session.nodes.get(node_link_id) orelse return error.TestExpectedResponse;
    const topology_node = session.nodes.get(topology_id) orelse return error.TestExpectedResponse;
    const nodes_meta_node = session.nodes.get(nodes_meta_id) orelse return error.TestExpectedResponse;
    const agents_meta_node = session.nodes.get(agents_meta_id) orelse return error.TestExpectedResponse;
    const sources_node = session.nodes.get(sources_id) orelse return error.TestExpectedResponse;
    const contracts_node = session.nodes.get(contracts_id) orelse return error.TestExpectedResponse;
    const paths_node = session.nodes.get(paths_id) orelse return error.TestExpectedResponse;
    const summary_node = session.nodes.get(summary_id) orelse return error.TestExpectedResponse;
    const alerts_node = session.nodes.get(alerts_id) orelse return error.TestExpectedResponse;
    const workspace_node = session.nodes.get(workspace_id) orelse return error.TestExpectedResponse;
    const mounts_node = session.nodes.get(mounts_id) orelse return error.TestExpectedResponse;
    const desired_mounts_node = session.nodes.get(desired_mounts_id) orelse return error.TestExpectedResponse;
    const actual_mounts_node = session.nodes.get(actual_mounts_id) orelse return error.TestExpectedResponse;
    const drift_node = session.nodes.get(drift_id) orelse return error.TestExpectedResponse;
    const reconcile_node = session.nodes.get(reconcile_id) orelse return error.TestExpectedResponse;
    const availability_node = session.nodes.get(availability_id) orelse return error.TestExpectedResponse;
    const health_node = session.nodes.get(health_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, project_fs_schema.content, "\"kind\":\"collection\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, project_nodes_schema.content, "\"kind\":\"collection\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, project_agents_caps.content, "\"read\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"workspace_status.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"nodes.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"agents.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"sources.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"contracts.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"paths.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"summary.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"alerts.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"desired_mounts.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"actual_mounts.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"drift.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"reconcile.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"health.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_meta_schema.content, "\"workspace_status.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_meta_schema.content, "\"workspace_availability.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_meta_schema.content, "\"workspace_health.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_meta_schema.content, "\"workspace_alerts.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_workspace_status_node.content, "\"project_id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_workspace_availability_node.content, "\"mounts_total\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_workspace_health_node.content, "\"state\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_workspace_alerts_node.content, "[") != null);
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/fs") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_link_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_link_node.content, node_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, topology_node.content, "\"project_links\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, topology_node.content, node_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, nodes_meta_node.content, "\"node_id\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, nodes_meta_node.content, node_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, nodes_meta_node.content, "\"state\":\"online\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, nodes_meta_node.content, "\"mounts\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"name\":\"default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"target\":\"/agents/") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "/agents/default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"version\":\"acheron-namespace-project-contract-v2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"top_level_roots\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"project_metadata_files\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"agents_root\":\"/agents\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"sources.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"project_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"nodes_root\":\"/nodes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"agents_root\":\"/agents\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"library\":\"/global/library\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"workspace_status\":\"control_plane\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_mount_links\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_node_links\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_agent_links\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"state\":\"healthy\"") != null);
    try std.testing.expect(std.mem.eql(u8, alerts_node.content, "[]"));
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"workspace_status\":\"control_plane\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"project_fs\":\"workspace_mounts\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"project_nodes\":\"workspace_mounts\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"nodes_meta\":\"workspace_mounts\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, workspace_node.content, "\"mount_path\":\"/src\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mounts_node.content, "\"mount_path\":\"/src\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, desired_mounts_node.content, "\"mount_path\":\"/src\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, actual_mounts_node.content, "\"mount_path\":\"/src\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, drift_node.content, "\"count\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, reconcile_node.content, "\"reconcile_state\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, reconcile_node.content, "\"queue_depth\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, workspace_node.content, "\"state\":\"online\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, availability_node.content, "\"mounts_total\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_node.content, "\"availability\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_node.content, "\"mounts_total\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, health_node.content, "\"drift_count\":0") != null);
}

test "acheron_session: project workspace mount links are filtered by policy" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-discovered", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const created_project = try control_plane.createProject("{\"name\":\"DiscoveredNodeProject\",\"vision\":\"DiscoveredNodeProject\"}");
    defer allocator.free(created_project);
    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, created_project, .{});
    defer project_parsed.deinit();
    if (project_parsed.value != .object) return error.TestExpectedResponse;
    const project_id = project_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_id != .string) return error.TestExpectedResponse;
    const project_token = project_parsed.value.object.get("project_token") orelse return error.TestExpectedResponse;
    if (project_token != .string) return error.TestExpectedResponse;

    const escaped_project_id = try unified.jsonEscape(allocator, project_id.string);
    defer allocator.free(escaped_project_id);
    const escaped_project_token = try unified.jsonEscape(allocator, project_token.string);
    defer allocator.free(escaped_project_token);
    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);

    const mount_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/code\"}}",
        .{ escaped_project_id, escaped_project_token, escaped_node_id },
    );
    defer allocator.free(mount_req);
    const mounted = try control_plane.setProjectMount(mount_req);
    defer allocator.free(mounted);

    const up_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(up_req);
    const up = try control_plane.projectUp("default", up_req);
    defer allocator.free(up);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = project_id.string,
            .project_token = project_token.string,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    try std.testing.expect(session.lookupChild(nodes_root, node_id.string) == null);

    const projects_root = session.lookupChild(session.root_id, "projects") orelse return error.TestExpectedResponse;
    const project_node = session.lookupChild(projects_root, project_id.string) orelse return error.TestExpectedResponse;
    const project_fs_node = session.lookupChild(project_node, "fs") orelse return error.TestExpectedResponse;
    try std.testing.expect(session.lookupChild(project_fs_node, "mount::code") == null);
    const project_nodes_node = session.lookupChild(project_node, "nodes") orelse return error.TestExpectedResponse;
    try std.testing.expect(session.lookupChild(project_nodes_node, node_id.string) == null);

    const meta_node = session.lookupChild(project_node, "meta") orelse return error.TestExpectedResponse;
    const sources_id = session.lookupChild(meta_node, "sources.json") orelse return error.TestExpectedResponse;
    const summary_id = session.lookupChild(meta_node, "summary.json") orelse return error.TestExpectedResponse;
    const mounts_id = session.lookupChild(meta_node, "mounts.json") orelse return error.TestExpectedResponse;
    const workspace_id = session.lookupChild(meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
    const sources_node = session.nodes.get(sources_id) orelse return error.TestExpectedResponse;
    const summary_node = session.nodes.get(summary_id) orelse return error.TestExpectedResponse;
    const mounts_node = session.nodes.get(mounts_id) orelse return error.TestExpectedResponse;
    const workspace_node = session.nodes.get(workspace_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"workspace_status\":\"control_plane\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"project_fs\":\"policy_links\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"project_nodes\":\"policy_nodes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_mount_links\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_node_links\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, mounts_node.content, "\"mount_path\":\"/code\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, workspace_node.content, node_id.string) != null);
}

test "acheron_session: workspace mount links backfill policy-approved fs targets" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-no-fs-url", "", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const node_dir = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    try std.testing.expect(session.lookupChild(node_dir, "fs") == null);

    const project_fs_dir = try session.addDir(session.root_id, "project-fs-test", false);
    var policy = workspace_policy.WorkspacePolicy{
        .project_id = try allocator.dupe(u8, "proj-fs-target"),
    };
    defer policy.deinit(allocator);
    try policy.nodes.append(allocator, .{
        .id = try allocator.dupe(u8, node_id.string),
        .resources = .{
            .fs = true,
            .camera = false,
            .screen = false,
            .user = false,
        },
    });

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const workspace_status_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-fs-target\",\"mounts\":[{{\"node_id\":\"{s}\",\"mount_path\":\"/src\"}}]}}",
        .{escaped_node_id},
    );
    defer allocator.free(workspace_status_json);

    try std.testing.expect(try session.addProjectFsLinksFromWorkspaceStatus(project_fs_dir, nodes_root, policy, workspace_status_json));

    const fs_dir = session.lookupChild(node_dir, "fs");
    try std.testing.expect(fs_dir != null);
    const mount_link = session.lookupChild(project_fs_dir, "mount::src") orelse return error.TestExpectedResponse;
    const mount_link_node = session.nodes.get(mount_link) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/fs") != null);
}

test "acheron_session: project meta summary and alerts reflect degraded and missing mounts" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-alerts", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const created_project = try control_plane.createProject("{\"name\":\"ProjectAlertsState\",\"vision\":\"ProjectAlertsState\"}");
    defer allocator.free(created_project);
    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, created_project, .{});
    defer project_parsed.deinit();
    if (project_parsed.value != .object) return error.TestExpectedResponse;
    const project_id = project_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_id != .string) return error.TestExpectedResponse;
    const project_token = project_parsed.value.object.get("project_token") orelse return error.TestExpectedResponse;
    if (project_token != .string) return error.TestExpectedResponse;

    const escaped_project_id = try unified.jsonEscape(allocator, project_id.string);
    defer allocator.free(escaped_project_id);
    const escaped_project_token = try unified.jsonEscape(allocator, project_token.string);
    defer allocator.free(escaped_project_token);
    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);

    const mount_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ escaped_project_id, escaped_project_token, escaped_node_id },
    );
    defer allocator.free(mount_req);
    const mounted = try control_plane.setProjectMount(mount_req);
    defer allocator.free(mounted);

    const up_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ escaped_project_id, escaped_project_token },
    );
    defer allocator.free(up_req);
    const up = try control_plane.projectUp("default", up_req);
    defer allocator.free(up);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ projects_dir, project_id.string });
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(project_dir);

    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[{{\"name\":\"{s}::fs\",\"node_id\":\"{s}\",\"resource\":\"fs\"}}]}}",
        .{ escaped_project_id, escaped_node_id, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    const stale_now = std.time.milliTimestamp();
    control_plane.mutex.lock();
    if (control_plane.nodes.getPtr(node_id.string)) |node| node.lease_expires_at_ms = stale_now - 1_000;
    control_plane.mutex.unlock();

    {
        var degraded_session = try Session.initWithOptions(
            allocator,
            runtime_handle,
            &job_index,
            "default",
            .{
                .project_id = project_id.string,
                .project_token = project_token.string,
                .agents_dir = agents_dir,
                .projects_dir = projects_dir,
                .control_plane = &control_plane,
            },
        );
        defer degraded_session.deinit();

        const projects_root = degraded_session.lookupChild(degraded_session.root_id, "projects") orelse return error.TestExpectedResponse;
        const project_node = degraded_session.lookupChild(projects_root, project_id.string) orelse return error.TestExpectedResponse;
        const meta_node = degraded_session.lookupChild(project_node, "meta") orelse return error.TestExpectedResponse;
        const summary_id = degraded_session.lookupChild(meta_node, "summary.json") orelse return error.TestExpectedResponse;
        const alerts_id = degraded_session.lookupChild(meta_node, "alerts.json") orelse return error.TestExpectedResponse;
        const workspace_id = degraded_session.lookupChild(meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
        const availability_id = degraded_session.lookupChild(meta_node, "availability.json") orelse return error.TestExpectedResponse;

        const summary_node = degraded_session.nodes.get(summary_id) orelse return error.TestExpectedResponse;
        const alerts_node = degraded_session.nodes.get(alerts_id) orelse return error.TestExpectedResponse;
        const workspace_node = degraded_session.nodes.get(workspace_id) orelse return error.TestExpectedResponse;
        const availability_node = degraded_session.nodes.get(availability_id) orelse return error.TestExpectedResponse;

        try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"state\":\"degraded\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"degraded_mounts\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"workspace_drift\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"reconcile_queue\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"missing_mounts\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, workspace_node.content, "\"state\":\"degraded\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, availability_node.content, "\"degraded\":1") != null);
        try std.testing.expect(std.mem.indexOf(u8, availability_node.content, "\"missing\":0") != null);
    }

    control_plane.mutex.lock();
    if (control_plane.nodes.fetchRemove(node_id.string)) |removed| {
        var node = removed.value;
        node.deinit(allocator);
    }
    control_plane.mutex.unlock();

    {
        var missing_session = try Session.initWithOptions(
            allocator,
            runtime_handle,
            &job_index,
            "default",
            .{
                .project_id = project_id.string,
                .project_token = project_token.string,
                .agents_dir = agents_dir,
                .projects_dir = projects_dir,
                .control_plane = &control_plane,
            },
        );
        defer missing_session.deinit();

        const projects_root = missing_session.lookupChild(missing_session.root_id, "projects") orelse return error.TestExpectedResponse;
        const project_node = missing_session.lookupChild(projects_root, project_id.string) orelse return error.TestExpectedResponse;
        const meta_node = missing_session.lookupChild(project_node, "meta") orelse return error.TestExpectedResponse;
        const summary_id = missing_session.lookupChild(meta_node, "summary.json") orelse return error.TestExpectedResponse;
        const alerts_id = missing_session.lookupChild(meta_node, "alerts.json") orelse return error.TestExpectedResponse;
        const workspace_id = missing_session.lookupChild(meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
        const availability_id = missing_session.lookupChild(meta_node, "availability.json") orelse return error.TestExpectedResponse;

        const summary_node = missing_session.nodes.get(summary_id) orelse return error.TestExpectedResponse;
        const alerts_node = missing_session.nodes.get(alerts_id) orelse return error.TestExpectedResponse;
        const workspace_node = missing_session.nodes.get(workspace_id) orelse return error.TestExpectedResponse;
        const availability_node = missing_session.nodes.get(availability_id) orelse return error.TestExpectedResponse;

        try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"state\":\"missing\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"missing_mounts\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"workspace_drift\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"reconcile_queue\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, alerts_node.content, "\"id\":\"degraded_mounts\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, workspace_node.content, "\"state\":\"missing\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, availability_node.content, "\"missing\":1") != null);
        try std.testing.expect(std.mem.indexOf(u8, availability_node.content, "\"degraded\":0") != null);
    }
}

test "acheron_session: project workspace fallback is scoped to requested project" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-leak-test", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const project_a = try control_plane.createProject("{\"name\":\"ScopedA\",\"vision\":\"ScopedA\"}");
    defer allocator.free(project_a);
    var project_a_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_a, .{});
    defer project_a_parsed.deinit();
    if (project_a_parsed.value != .object) return error.TestExpectedResponse;
    const project_a_id = project_a_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_a_id != .string) return error.TestExpectedResponse;

    const project_b = try control_plane.createProject("{\"name\":\"ScopedB\",\"vision\":\"ScopedB\"}");
    defer allocator.free(project_b);
    var project_b_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_b, .{});
    defer project_b_parsed.deinit();
    if (project_b_parsed.value != .object) return error.TestExpectedResponse;
    const project_b_id = project_b_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_b_id != .string) return error.TestExpectedResponse;
    const project_b_token = project_b_parsed.value.object.get("project_token") orelse return error.TestExpectedResponse;
    if (project_b_token != .string) return error.TestExpectedResponse;

    const escaped_project_b_id = try unified.jsonEscape(allocator, project_b_id.string);
    defer allocator.free(escaped_project_b_id);
    const escaped_project_b_token = try unified.jsonEscape(allocator, project_b_token.string);
    defer allocator.free(escaped_project_b_token);
    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const mount_b_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/leak\"}}",
        .{ escaped_project_b_id, escaped_project_b_token, escaped_node_id },
    );
    defer allocator.free(mount_b_req);
    const mounted = try control_plane.setProjectMount(mount_b_req);
    defer allocator.free(mounted);

    const activate_b_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ escaped_project_b_id, escaped_project_b_token },
    );
    defer allocator.free(activate_b_req);
    const up_b = try control_plane.projectUp("default", activate_b_req);
    defer allocator.free(up_b);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_a_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ projects_dir, project_a_id.string });
    defer allocator.free(project_a_dir);
    try std.fs.cwd().makePath(project_a_dir);

    const escaped_project_a_id = try unified.jsonEscape(allocator, project_a_id.string);
    defer allocator.free(escaped_project_a_id);
    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_a_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"nodes\":[{{\"id\":\"local\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[\"1\"]}}],\"visible_agents\":[\"default\"],\"project_links\":[{{\"name\":\"local::fs\",\"node_id\":\"local\",\"resource\":\"fs\"}}]}}",
        .{escaped_project_a_id},
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = project_a_id.string,
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const projects_root = session.lookupChild(session.root_id, "projects") orelse return error.TestExpectedResponse;
    const project_node = session.lookupChild(projects_root, project_a_id.string) orelse return error.TestExpectedResponse;
    const project_fs_node = session.lookupChild(project_node, "fs") orelse return error.TestExpectedResponse;
    const project_nodes_node = session.lookupChild(project_node, "nodes") orelse return error.TestExpectedResponse;
    const leaked_mount_link = session.lookupChild(project_fs_node, "mount::leak");
    try std.testing.expect(leaked_mount_link == null);
    const local_node_link = session.lookupChild(project_nodes_node, "local") orelse return error.TestExpectedResponse;
    _ = local_node_link;
    const leaked_node_link = session.lookupChild(project_nodes_node, node_id.string);
    try std.testing.expect(leaked_node_link == null);

    const meta_node = session.lookupChild(project_node, "meta") orelse return error.TestExpectedResponse;
    const nodes_meta_id = session.lookupChild(meta_node, "nodes.json") orelse return error.TestExpectedResponse;
    const agents_meta_id = session.lookupChild(meta_node, "agents.json") orelse return error.TestExpectedResponse;
    const sources_id = session.lookupChild(meta_node, "sources.json") orelse return error.TestExpectedResponse;
    const contracts_id = session.lookupChild(meta_node, "contracts.json") orelse return error.TestExpectedResponse;
    const paths_id = session.lookupChild(meta_node, "paths.json") orelse return error.TestExpectedResponse;
    const summary_id = session.lookupChild(meta_node, "summary.json") orelse return error.TestExpectedResponse;
    const alerts_id = session.lookupChild(meta_node, "alerts.json") orelse return error.TestExpectedResponse;
    const workspace_id = session.lookupChild(meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
    const mounts_id = session.lookupChild(meta_node, "mounts.json") orelse return error.TestExpectedResponse;
    const desired_mounts_id = session.lookupChild(meta_node, "desired_mounts.json") orelse return error.TestExpectedResponse;
    const actual_mounts_id = session.lookupChild(meta_node, "actual_mounts.json") orelse return error.TestExpectedResponse;
    const drift_id = session.lookupChild(meta_node, "drift.json") orelse return error.TestExpectedResponse;
    const reconcile_id = session.lookupChild(meta_node, "reconcile.json") orelse return error.TestExpectedResponse;
    const health_id = session.lookupChild(meta_node, "health.json") orelse return error.TestExpectedResponse;
    const nodes_meta_node = session.nodes.get(nodes_meta_id) orelse return error.TestExpectedResponse;
    const agents_meta_node = session.nodes.get(agents_meta_id) orelse return error.TestExpectedResponse;
    const sources_node = session.nodes.get(sources_id) orelse return error.TestExpectedResponse;
    const contracts_node = session.nodes.get(contracts_id) orelse return error.TestExpectedResponse;
    const paths_node = session.nodes.get(paths_id) orelse return error.TestExpectedResponse;
    const summary_node = session.nodes.get(summary_id) orelse return error.TestExpectedResponse;
    const alerts_node = session.nodes.get(alerts_id) orelse return error.TestExpectedResponse;
    const workspace_node = session.nodes.get(workspace_id) orelse return error.TestExpectedResponse;
    const mounts_node = session.nodes.get(mounts_id) orelse return error.TestExpectedResponse;
    const desired_mounts_node = session.nodes.get(desired_mounts_id) orelse return error.TestExpectedResponse;
    const actual_mounts_node = session.nodes.get(actual_mounts_id) orelse return error.TestExpectedResponse;
    const drift_node = session.nodes.get(drift_id) orelse return error.TestExpectedResponse;
    const reconcile_node = session.nodes.get(reconcile_id) orelse return error.TestExpectedResponse;
    const health_node = session.nodes.get(health_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, nodes_meta_node.content, "\"node_id\":\"local\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, nodes_meta_node.content, "\"state\":\"unknown\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, nodes_meta_node.content, node_id.string) == null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"name\":\"default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"target\":\"/agents/") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "/agents/default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"version\":\"acheron-namespace-project-contract-v2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"project_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, project_a_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"project_metadata_files\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"agents_root\":\"/agents\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"project_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, project_a_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"global\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"library\":\"/global/library\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"debug\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"workspace_status\":\"policy\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_mount_links\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_node_links\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_agent_links\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"state\":\"unknown\"") != null);
    try std.testing.expect(std.mem.eql(u8, alerts_node.content, "[]"));
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"workspace_status\":\"policy\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"project_fs\":\"policy_links\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"project_nodes\":\"policy_nodes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sources_node.content, "\"nodes_meta\":\"policy_nodes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, workspace_node.content, "\"source\":\"policy\"") != null);
    try std.testing.expect(std.mem.eql(u8, mounts_node.content, "[]"));
    try std.testing.expect(std.mem.eql(u8, desired_mounts_node.content, "[]"));
    try std.testing.expect(std.mem.eql(u8, actual_mounts_node.content, "[]"));
    try std.testing.expect(std.mem.eql(u8, drift_node.content, "{\"count\":0,\"items\":[]}"));
    try std.testing.expect(std.mem.eql(u8, reconcile_node.content, "{\"reconcile_state\":\"unknown\",\"last_reconcile_ms\":0,\"last_success_ms\":0,\"last_error\":null,\"queue_depth\":0}"));
    try std.testing.expect(std.mem.eql(u8, health_node.content, "{\"state\":\"unknown\",\"availability\":{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0},\"drift_count\":0,\"reconcile_state\":\"unknown\",\"queue_depth\":0}"));
    try std.testing.expect(std.mem.indexOf(u8, workspace_node.content, project_b_id.string) == null);
}

test "acheron_session: node roots are derived from control-plane service kinds" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-service-roots", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"camera\",\"kind\":\"camera\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/camera\"],\"capabilities\":{{\"still\":true}}}},{{\"venom_id\":\"terminal-3\",\"kind\":\"terminal\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/terminal/3\"],\"capabilities\":{{\"pty\":true}}}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-roots", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(project_dir);

    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-roots\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = "proj-roots",
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const node_dir = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const node_caps_id = session.lookupChild(node_dir, "CAPS.json") orelse return error.TestExpectedResponse;
    const node_caps = session.nodes.get(node_caps_id) orelse return error.TestExpectedResponse;
    const camera_dir = session.lookupChild(node_dir, "camera");
    const fs_dir = session.lookupChild(node_dir, "fs");
    const terminal_root = session.lookupChild(node_dir, "terminal") orelse return error.TestExpectedResponse;
    const terminal_3 = session.lookupChild(terminal_root, "3") orelse return error.TestExpectedResponse;
    _ = terminal_3;

    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"camera\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"fs\":false") != null);
    try std.testing.expect(camera_dir != null);
    try std.testing.expect(fs_dir == null);
}

test "acheron_session: control-plane mounts expose custom node roots and metadata files" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-custom-mounts", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"gdrive-main\",\"kind\":\"gdrive\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/venoms/gdrive-main\"],\"capabilities\":{{\"provider\":\"google\"}},\"mounts\":[{{\"mount_id\":\"drive-main\",\"mount_path\":\"/nodes/{s}/drive/main\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}},\"invoke_template\":{{\"tool_name\":\"gdrive_sync\",\"arguments\":{{\"drive\":\"main\"}}}},\"help_md\":\"Google Drive namespace mount\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-custom-mounts", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(project_dir);

    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-custom-mounts\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = "proj-custom-mounts",
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const node_dir = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const drive_root = session.lookupChild(node_dir, "drive") orelse return error.TestExpectedResponse;
    _ = drive_root;
    const services_root = session.lookupChild(node_dir, "venoms") orelse return error.TestExpectedResponse;
    const gdrive_service = session.lookupChild(services_root, "gdrive-main") orelse return error.TestExpectedResponse;
    const mounts_id = session.lookupChild(gdrive_service, "MOUNTS.json") orelse return error.TestExpectedResponse;
    const ops_id = session.lookupChild(gdrive_service, "OPS.json") orelse return error.TestExpectedResponse;
    const runtime_id = session.lookupChild(gdrive_service, "RUNTIME.json") orelse return error.TestExpectedResponse;
    const template_id = session.lookupChild(gdrive_service, "TEMPLATE.json") orelse return error.TestExpectedResponse;
    const host_id = session.lookupChild(gdrive_service, "HOST.json") orelse return error.TestExpectedResponse;
    const permissions_id = session.lookupChild(gdrive_service, "PERMISSIONS.json") orelse return error.TestExpectedResponse;
    const readme_id = session.lookupChild(gdrive_service, "README.md") orelse return error.TestExpectedResponse;
    const mounts_node = session.nodes.get(mounts_id) orelse return error.TestExpectedResponse;
    const ops_node = session.nodes.get(ops_id) orelse return error.TestExpectedResponse;
    const runtime_node = session.nodes.get(runtime_id) orelse return error.TestExpectedResponse;
    const template_node = session.nodes.get(template_id) orelse return error.TestExpectedResponse;
    const host_node = session.nodes.get(host_id) orelse return error.TestExpectedResponse;
    const permissions_node = session.nodes.get(permissions_id) orelse return error.TestExpectedResponse;
    const readme_node = session.nodes.get(readme_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, mounts_node.content, "\"mount_path\":\"/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, ops_node.content, "\"model\":\"namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, runtime_node.content, "\"type\":\"native_proc\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, template_node.content, "\"tool_name\":\"gdrive_sync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, host_node.content, "\"runtime_kind\":\"native_proc\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, permissions_node.content, "\"deny-by-default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, readme_node.content, "Google Drive namespace mount") != null);
}

test "acheron_session: service permissions enforce deny-by-default with admin bypass" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-secure-service", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"secure-main\",\"kind\":\"secure\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/secure/main\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"secure-main\",\"mount_path\":\"/nodes/{s}/secure/main\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"deny-by-default\"}},\"schema\":{{\"model\":\"namespace-mount\"}},\"help_md\":\"Secure namespace mount\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-secure", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(project_dir);

    const project_policy_path = try std.fmt.allocPrint(allocator, "{s}/project_policy.json", .{project_dir});
    defer allocator.free(project_policy_path);
    const project_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-secure\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(project_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = project_policy_path,
        .data = project_policy_json,
    });

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var user_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = "proj-secure",
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
            .is_admin = false,
        },
    );
    defer user_session.deinit();

    const user_nodes_root = user_session.lookupChild(user_session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const user_node_dir = user_session.lookupChild(user_nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const user_services_root = user_session.lookupChild(user_node_dir, "venoms") orelse return error.TestExpectedResponse;
    try std.testing.expect(user_session.lookupChild(user_services_root, "secure-main") == null);
    try std.testing.expect(user_session.lookupChild(user_node_dir, "secure") == null);

    var admin_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = "proj-secure",
            .agents_dir = agents_dir,
            .projects_dir = projects_dir,
            .control_plane = &control_plane,
            .is_admin = true,
        },
    );
    defer admin_session.deinit();

    const admin_nodes_root = admin_session.lookupChild(admin_session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const admin_node_dir = admin_session.lookupChild(admin_nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const admin_services_root = admin_session.lookupChild(admin_node_dir, "venoms") orelse return error.TestExpectedResponse;
    try std.testing.expect(admin_session.lookupChild(admin_services_root, "secure-main") != null);
    try std.testing.expect(admin_session.lookupChild(admin_node_dir, "secure") != null);
}

test "acheron_session: project access policy gates invoke visibility per agent" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-policy-invoke", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"tool-main\",\"kind\":\"tool\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/tool/main\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"tool-main\",\"mount_path\":\"/nodes/{s}/tool/main\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Policy-gated invoke service\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    const project_json = try control_plane.createProject(
        "{\"name\":\"InvokePolicy\",\"access_policy\":{\"actions\":{\"invoke\":\"open\"},\"agents\":{\"default\":{\"invoke\":\"deny\"},\"worker\":{\"invoke\":\"open\"}}}}",
    );
    defer allocator.free(project_json);
    var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project_parsed.deinit();
    if (project_parsed.value != .object) return error.TestExpectedResponse;
    const project_id = project_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_id != .string) return error.TestExpectedResponse;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var default_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .project_id = project_id.string,
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .is_admin = false,
        },
    );
    defer default_session.deinit();

    const default_nodes_root = default_session.lookupChild(default_session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const default_node_dir = default_session.lookupChild(default_nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const default_services_root = default_session.lookupChild(default_node_dir, "venoms") orelse return error.TestExpectedResponse;
    try std.testing.expect(default_session.lookupChild(default_services_root, "tool-main") == null);
    try std.testing.expect(default_session.lookupChild(default_node_dir, "tool") == null);
    const default_index_payload = try protocolReadFile(
        &default_session,
        allocator,
        220,
        221,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        830,
    );
    defer allocator.free(default_index_payload);
    try std.testing.expect(std.mem.indexOf(u8, default_index_payload, "\"venom_id\":\"tool-main\"") == null);

    var worker_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "worker",
        .{
            .project_id = project_id.string,
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .is_admin = false,
        },
    );
    defer worker_session.deinit();

    const worker_nodes_root = worker_session.lookupChild(worker_session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const worker_node_dir = worker_session.lookupChild(worker_nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const worker_services_root = worker_session.lookupChild(worker_node_dir, "venoms") orelse return error.TestExpectedResponse;
    try std.testing.expect(worker_session.lookupChild(worker_services_root, "tool-main") != null);
    try std.testing.expect(worker_session.lookupChild(worker_node_dir, "tool") != null);
    const worker_index_payload = try protocolReadFile(
        &worker_session,
        allocator,
        222,
        223,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        840,
    );
    defer allocator.free(worker_index_payload);
    const expected_invoke_path = try std.fmt.allocPrint(
        allocator,
        "\"invoke_path\":\"/nodes/{s}/tool/main/control/invoke.json\"",
        .{node_id.string},
    );
    defer allocator.free(expected_invoke_path);
    try std.testing.expect(std.mem.indexOf(u8, worker_index_payload, "\"venom_id\":\"tool-main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, worker_index_payload, "\"has_invoke\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, worker_index_payload, expected_invoke_path) != null);
}

test "acheron_session: node service invoke path uses OPS metadata with safe fallback" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-ops-invoke", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[" ++
            "{{\"venom_id\":\"tool-rel\",\"kind\":\"tool\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/tool/rel\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"tool-rel\",\"mount_path\":\"/nodes/{s}/tool/rel\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"invoke\":\"control/run.json\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Relative invoke target\"}}," ++
            "{{\"venom_id\":\"tool-abs\",\"kind\":\"tool\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/tool/abs\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"tool-abs\",\"mount_path\":\"/nodes/{s}/tool/abs\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"invoke\":\"/nodes/{s}/tool/abs/custom/exec.json\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Absolute invoke target\"}}," ++
            "{{\"venom_id\":\"tool-fallback\",\"kind\":\"tool\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/tool/fallback\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"tool-fallback\",\"mount_path\":\"/nodes/{s}/tool/fallback\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"invoke\":123}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Fallback invoke target\"}}" ++
            "]}}",
        .{
            escaped_node_id,
            escaped_node_secret,
            escaped_node_id,
            escaped_node_id,
            escaped_node_id,
            escaped_node_id,
            escaped_node_id,
            escaped_node_id,
            escaped_node_id,
            escaped_node_id,
        },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .is_admin = false,
        },
    );
    defer session.deinit();

    const index_payload = try protocolReadFile(
        &session,
        allocator,
        224,
        225,
        &.{ "agents", "self", "venoms", "VENOMS.json" },
        850,
    );
    defer allocator.free(index_payload);

    const expected_rel = try std.fmt.allocPrint(
        allocator,
        "\"invoke_path\":\"/nodes/{s}/tool/rel/control/run.json\"",
        .{node_id.string},
    );
    defer allocator.free(expected_rel);
    const expected_abs = try std.fmt.allocPrint(
        allocator,
        "\"invoke_path\":\"/nodes/{s}/tool/abs/custom/exec.json\"",
        .{node_id.string},
    );
    defer allocator.free(expected_abs);
    const expected_fallback = try std.fmt.allocPrint(
        allocator,
        "\"invoke_path\":\"/nodes/{s}/tool/fallback/control/invoke.json\"",
        .{node_id.string},
    );
    defer allocator.free(expected_fallback);

    try std.testing.expect(std.mem.indexOf(u8, index_payload, "\"venom_id\":\"tool-rel\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, expected_rel) != null);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, "\"venom_id\":\"tool-abs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, expected_abs) != null);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, "\"venom_id\":\"tool-fallback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, index_payload, expected_fallback) != null);
}

test "acheron_session: control-plane registered nodes appear under global nodes namespace" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-global-node", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const discovered_node = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const discovered_status_id = session.lookupChild(discovered_node, "STATUS.json") orelse return error.TestExpectedResponse;
    const discovered_status = session.nodes.get(discovered_status_id) orelse return error.TestExpectedResponse;
    const discovered_fs = session.lookupChild(discovered_node, "fs");

    const projects_root = session.lookupChild(session.root_id, "projects") orelse return error.TestExpectedResponse;
    const system_project = session.lookupChild(projects_root, "system") orelse return error.TestExpectedResponse;
    const system_project_nodes = session.lookupChild(system_project, "nodes") orelse return error.TestExpectedResponse;
    const system_project_node_link = session.lookupChild(system_project_nodes, node_id.string);

    try std.testing.expect(discovered_fs != null);
    try std.testing.expect(std.mem.indexOf(u8, discovered_status.content, "\"source\":\"control_plane\"") != null);
    try std.testing.expect(system_project_node_link == null);
}

test "acheron_session: global nodes directory discovers late control-plane nodes on read" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .control_plane = &control_plane,
        },
    );
    defer session.deinit();

    const ensured = try control_plane.ensureNode("late-discovered-node", "ws://127.0.0.1:19991/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    var attach = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_attach,
        .tag = 1,
        .fid = 101,
    };
    const attach_res = try session.handle(&attach);
    defer allocator.free(attach_res);
    try std.testing.expect(std.mem.indexOf(u8, attach_res, "acheron.r_attach") != null);

    const path = try allocPathSegments(allocator, &.{"nodes"});
    defer freePathSegments(allocator, path);
    var walk = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_walk,
        .tag = 2,
        .fid = 101,
        .newfid = 102,
        .path = path,
    };
    const walk_res = try session.handle(&walk);
    defer allocator.free(walk_res);
    try std.testing.expect(std.mem.indexOf(u8, walk_res, "acheron.r_walk") != null);

    var open = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_open,
        .tag = 3,
        .fid = 102,
        .mode = "r",
    };
    const open_res = try session.handle(&open);
    defer allocator.free(open_res);
    try std.testing.expect(std.mem.indexOf(u8, open_res, "acheron.r_open") != null);

    var read = unified.ParsedMessage{
        .channel = .acheron,
        .acheron_type = .t_read,
        .tag = 4,
        .fid = 102,
        .offset = 0,
        .count = 16 * 1024,
    };
    const read_res = try session.handle(&read);
    defer allocator.free(read_res);
    try std.testing.expect(std.mem.indexOf(u8, read_res, "acheron.r_read") != null);

    var read_parsed = try std.json.parseFromSlice(std.json.Value, allocator, read_res, .{});
    defer read_parsed.deinit();
    if (read_parsed.value != .object) return error.TestExpectedResponse;
    const payload_value = read_parsed.value.object.get("payload") orelse return error.TestExpectedResponse;
    if (payload_value != .object) return error.TestExpectedResponse;
    const data_b64_value = payload_value.object.get("data_b64") orelse return error.TestExpectedResponse;
    if (data_b64_value != .string) return error.TestExpectedResponse;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(data_b64_value.string) catch return error.TestExpectedResponse;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    _ = std.base64.standard.Decoder.decode(decoded, data_b64_value.string) catch return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, decoded, node_id.string) != null);

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    try std.testing.expect(session.lookupChild(nodes_root, node_id.string) != null);
}

test "acheron_session: pairing catalog visibility and node invoke integration flow" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const spiderweb_node = @import("spiderweb_node");

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-integration", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;
    const node_secret = ensured_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (node_secret != .string) return error.TestExpectedResponse;

    const escaped_node_id = try unified.jsonEscape(allocator, node_id.string);
    defer allocator.free(escaped_node_id);
    const escaped_node_secret = try unified.jsonEscape(allocator, node_secret.string);
    defer allocator.free(escaped_node_secret);
    const upsert_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"echo-main\",\"kind\":\"utility\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/echo\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"echo-main\",\"mount_path\":\"/nodes/{s}/echo\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"style\":\"plan9\"}},\"runtime\":{{\"type\":\"native_proc\",\"abi\":\"namespace-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Echo integration service\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeVenomUpsert(upsert_req);
    defer allocator.free(upserted);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .is_admin = false,
        },
    );
    defer session.deinit();

    const nodes_root = session.lookupChild(session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const node_dir = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const services_root = session.lookupChild(node_dir, "venoms") orelse return error.TestExpectedResponse;
    const echo_service = session.lookupChild(services_root, "echo-main") orelse return error.TestExpectedResponse;
    _ = echo_service;
    const echo_root = session.lookupChild(node_dir, "echo") orelse return error.TestExpectedResponse;
    _ = echo_root;

    var node_service = try spiderweb_node.fs_node_service.NodeService.init(
        allocator,
        &[_]spiderweb_node.fs_node_ops.ExportSpec{
            .{
                .name = "svc-echo-main",
                .path = "service:echo-main",
                .source_kind = .namespace,
                .source_id = "service:echo-main",
                .ro = false,
                .namespace_venom = .{
                    .venom_id = "echo-main",
                    .runtime_kind = .native_proc,
                    .executable_path = "/bin/cat",
                    .args = &.{},
                    .timeout_ms = 10_000,
                },
            },
        },
    );
    defer node_service.deinit();

    var exports_res = try node_service.handleRequestJsonWithEvents(
        "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_exports\",\"tag\":1,\"payload\":{}}",
    );
    defer exports_res.deinit(allocator);
    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_res.response_json, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("payload").?.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const control_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":2,\"node\":{d},\"payload\":{{\"name\":\"control\"}}}}",
        .{root_id},
    );
    defer allocator.free(control_lookup_req);
    var control_lookup_res = try node_service.handleRequestJsonWithEvents(control_lookup_req);
    defer control_lookup_res.deinit(allocator);
    var control_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, control_lookup_res.response_json, .{});
    defer control_lookup_parsed.deinit();
    const control_id = control_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const invoke_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":3,\"node\":{d},\"payload\":{{\"name\":\"invoke.json\"}}}}",
        .{control_id},
    );
    defer allocator.free(invoke_lookup_req);
    var invoke_lookup_res = try node_service.handleRequestJsonWithEvents(invoke_lookup_req);
    defer invoke_lookup_res.deinit(allocator);
    var invoke_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, invoke_lookup_res.response_json, .{});
    defer invoke_lookup_parsed.deinit();
    const invoke_id = invoke_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const open_invoke_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":4,\"node\":{d},\"payload\":{{\"flags\":2}}}}",
        .{invoke_id},
    );
    defer allocator.free(open_invoke_req);
    var open_invoke_res = try node_service.handleRequestJsonWithEvents(open_invoke_req);
    defer open_invoke_res.deinit(allocator);
    var open_invoke_parsed = try std.json.parseFromSlice(std.json.Value, allocator, open_invoke_res.response_json, .{});
    defer open_invoke_parsed.deinit();
    const invoke_handle = open_invoke_parsed.value.object.get("payload").?.object.get("h").?.integer;

    const payload_json = "{\"ping\":\"pong\"}";
    const payload_b64_len = std.base64.standard.Encoder.calcSize(payload_json.len);
    const payload_b64 = try allocator.alloc(u8, payload_b64_len);
    defer allocator.free(payload_b64);
    _ = std.base64.standard.Encoder.encode(payload_b64, payload_json);
    const write_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_write\",\"tag\":5,\"h\":{d},\"payload\":{{\"off\":0,\"data_b64\":\"{s}\"}}}}",
        .{ invoke_handle, payload_b64 },
    );
    defer allocator.free(write_req);
    var write_res = try node_service.handleRequestJsonWithEvents(write_req);
    defer write_res.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, write_res.response_json, "\"ok\":true") != null);

    const result_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":6,\"node\":{d},\"payload\":{{\"name\":\"result.json\"}}}}",
        .{root_id},
    );
    defer allocator.free(result_lookup_req);
    var result_lookup_res = try node_service.handleRequestJsonWithEvents(result_lookup_req);
    defer result_lookup_res.deinit(allocator);
    var result_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, result_lookup_res.response_json, .{});
    defer result_lookup_parsed.deinit();
    const result_id = result_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const open_result_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":7,\"node\":{d},\"payload\":{{\"flags\":0}}}}",
        .{result_id},
    );
    defer allocator.free(open_result_req);
    var open_result_res = try node_service.handleRequestJsonWithEvents(open_result_req);
    defer open_result_res.deinit(allocator);
    var open_result_parsed = try std.json.parseFromSlice(std.json.Value, allocator, open_result_res.response_json, .{});
    defer open_result_parsed.deinit();
    const result_handle = open_result_parsed.value.object.get("payload").?.object.get("h").?.integer;

    const read_result_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_read\",\"tag\":8,\"h\":{d},\"payload\":{{\"off\":0,\"len\":4096}}}}",
        .{result_handle},
    );
    defer allocator.free(read_result_req);
    var read_result_res = try node_service.handleRequestJsonWithEvents(read_result_req);
    defer read_result_res.deinit(allocator);
    var read_result_parsed = try std.json.parseFromSlice(std.json.Value, allocator, read_result_res.response_json, .{});
    defer read_result_parsed.deinit();
    const result_data_b64 = read_result_parsed.value.object.get("payload").?.object.get("data_b64").?.string;
    const result_len = std.base64.standard.Decoder.calcSizeForSlice(result_data_b64) catch return error.TestExpectedResponse;
    const result_decoded = try allocator.alloc(u8, result_len);
    defer allocator.free(result_decoded);
    _ = std.base64.standard.Decoder.decode(result_decoded, result_data_b64) catch return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, result_decoded, "\"ping\":\"pong\"") != null);

    const status_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":9,\"node\":{d},\"payload\":{{\"name\":\"status.json\"}}}}",
        .{root_id},
    );
    defer allocator.free(status_lookup_req);
    var status_lookup_res = try node_service.handleRequestJsonWithEvents(status_lookup_req);
    defer status_lookup_res.deinit(allocator);
    var status_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, status_lookup_res.response_json, .{});
    defer status_lookup_parsed.deinit();
    const status_id = status_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const open_status_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":10,\"node\":{d},\"payload\":{{\"flags\":0}}}}",
        .{status_id},
    );
    defer allocator.free(open_status_req);
    var open_status_res = try node_service.handleRequestJsonWithEvents(open_status_req);
    defer open_status_res.deinit(allocator);
    var open_status_parsed = try std.json.parseFromSlice(std.json.Value, allocator, open_status_res.response_json, .{});
    defer open_status_parsed.deinit();
    const status_handle = open_status_parsed.value.object.get("payload").?.object.get("h").?.integer;

    const read_status_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_read\",\"tag\":11,\"h\":{d},\"payload\":{{\"off\":0,\"len\":4096}}}}",
        .{status_handle},
    );
    defer allocator.free(read_status_req);
    var read_status_res = try node_service.handleRequestJsonWithEvents(read_status_req);
    defer read_status_res.deinit(allocator);
    var read_status_parsed = try std.json.parseFromSlice(std.json.Value, allocator, read_status_res.response_json, .{});
    defer read_status_parsed.deinit();
    const status_data_b64 = read_status_parsed.value.object.get("payload").?.object.get("data_b64").?.string;
    const status_len = std.base64.standard.Decoder.calcSizeForSlice(status_data_b64) catch return error.TestExpectedResponse;
    const status_decoded = try allocator.alloc(u8, status_len);
    defer allocator.free(status_decoded);
    _ = std.base64.standard.Decoder.decode(status_decoded, status_data_b64) catch return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, status_decoded, "\"state\":\"ok\"") != null);
}

test "acheron_session: multi-node discovery invoke supervision reconnect flow" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const spiderweb_node = @import("spiderweb_node");

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured_alpha = try control_plane.ensureNode("edge-alpha", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured_alpha);
    var alpha_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured_alpha, .{});
    defer alpha_parsed.deinit();
    if (alpha_parsed.value != .object) return error.TestExpectedResponse;
    const alpha_node_id = alpha_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    const alpha_node_secret = alpha_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (alpha_node_id != .string or alpha_node_secret != .string) return error.TestExpectedResponse;

    const ensured_beta = try control_plane.ensureNode("edge-beta", "ws://127.0.0.1:18892/v2/fs", 60_000);
    defer allocator.free(ensured_beta);
    var beta_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured_beta, .{});
    defer beta_parsed.deinit();
    if (beta_parsed.value != .object) return error.TestExpectedResponse;
    const beta_node_id = beta_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    const beta_node_secret = beta_parsed.value.object.get("node_secret") orelse return error.TestExpectedResponse;
    if (beta_node_id != .string or beta_node_secret != .string) return error.TestExpectedResponse;

    const escaped_alpha_id = try unified.jsonEscape(allocator, alpha_node_id.string);
    defer allocator.free(escaped_alpha_id);
    const escaped_alpha_secret = try unified.jsonEscape(allocator, alpha_node_secret.string);
    defer allocator.free(escaped_alpha_secret);
    const escaped_beta_id = try unified.jsonEscape(allocator, beta_node_id.string);
    defer allocator.free(escaped_beta_id);
    const escaped_beta_secret = try unified.jsonEscape(allocator, beta_node_secret.string);
    defer allocator.free(escaped_beta_secret);

    const alpha_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"echo-main\",\"kind\":\"utility\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/echo\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"echo-main\",\"mount_path\":\"/nodes/{s}/echo\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"style\":\"plan9\"}},\"runtime\":{{\"type\":\"native_proc\",\"abi\":\"namespace-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Echo main service\"}}]}}",
        .{ escaped_alpha_id, escaped_alpha_secret, escaped_alpha_id, escaped_alpha_id },
    );
    defer allocator.free(alpha_upsert);
    const alpha_upserted = try control_plane.nodeVenomUpsert(alpha_upsert);
    defer allocator.free(alpha_upserted);

    const beta_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"fail-main\",\"kind\":\"utility\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fail\"],\"capabilities\":{{\"invoke\":true,\"supervision\":true}},\"mounts\":[{{\"mount_id\":\"fail-main\",\"mount_path\":\"/nodes/{s}/fail\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"style\":\"plan9\"}},\"runtime\":{{\"type\":\"native_proc\",\"abi\":\"namespace-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Failing service\"}}]}}",
        .{ escaped_beta_id, escaped_beta_secret, escaped_beta_id, escaped_beta_id },
    );
    defer allocator.free(beta_upsert);
    const beta_upserted = try control_plane.nodeVenomUpsert(beta_upsert);
    defer allocator.free(beta_upserted);

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var discovered_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .is_admin = false,
        },
    );
    defer discovered_session.deinit();

    const nodes_root = discovered_session.lookupChild(discovered_session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const alpha_dir = discovered_session.lookupChild(nodes_root, alpha_node_id.string) orelse return error.TestExpectedResponse;
    const beta_dir = discovered_session.lookupChild(nodes_root, beta_node_id.string) orelse return error.TestExpectedResponse;
    const alpha_services = discovered_session.lookupChild(alpha_dir, "venoms") orelse return error.TestExpectedResponse;
    const beta_services = discovered_session.lookupChild(beta_dir, "venoms") orelse return error.TestExpectedResponse;
    try std.testing.expect(discovered_session.lookupChild(alpha_services, "echo-main") != null);
    try std.testing.expect(discovered_session.lookupChild(beta_services, "fail-main") != null);

    var node_service = try spiderweb_node.fs_node_service.NodeService.init(
        allocator,
        &[_]spiderweb_node.fs_node_ops.ExportSpec{
            .{
                .name = "svc-fail-main",
                .path = "service:fail-main",
                .source_kind = .namespace,
                .source_id = "service:fail-main",
                .ro = false,
                .namespace_venom = .{
                    .venom_id = "fail-main",
                    .runtime_kind = .native_proc,
                    .executable_path = "sh",
                    .args = &.{ "-lc", "exit 9" },
                    .timeout_ms = 2_000,
                },
            },
        },
    );
    defer node_service.deinit();

    var exports_res = try node_service.handleRequestJsonWithEvents(
        "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_exports\",\"tag\":1,\"payload\":{}}",
    );
    defer exports_res.deinit(allocator);
    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_res.response_json, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("payload").?.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const config_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":2,\"node\":{d},\"payload\":{{\"name\":\"config.json\"}}}}",
        .{root_id},
    );
    defer allocator.free(config_lookup_req);
    var config_lookup_res = try node_service.handleRequestJsonWithEvents(config_lookup_req);
    defer config_lookup_res.deinit(allocator);
    var config_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, config_lookup_res.response_json, .{});
    defer config_lookup_parsed.deinit();
    const config_id = config_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const open_config_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":3,\"node\":{d},\"payload\":{{\"flags\":2}}}}",
        .{config_id},
    );
    defer allocator.free(open_config_req);
    var open_config_res = try node_service.handleRequestJsonWithEvents(open_config_req);
    defer open_config_res.deinit(allocator);
    var open_config_parsed = try std.json.parseFromSlice(std.json.Value, allocator, open_config_res.response_json, .{});
    defer open_config_parsed.deinit();
    const config_handle = open_config_parsed.value.object.get("payload").?.object.get("h").?.integer;

    const config_payload = "{\"supervision\":{\"cooldown_ms\":60000,\"auto_disable_on_threshold\":false}}";
    const config_b64_len = std.base64.standard.Encoder.calcSize(config_payload.len);
    const config_b64 = try allocator.alloc(u8, config_b64_len);
    defer allocator.free(config_b64);
    _ = std.base64.standard.Encoder.encode(config_b64, config_payload);
    const config_write_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_write\",\"tag\":4,\"h\":{d},\"payload\":{{\"off\":0,\"data_b64\":\"{s}\"}}}}",
        .{ config_handle, config_b64 },
    );
    defer allocator.free(config_write_req);
    var config_write_res = try node_service.handleRequestJsonWithEvents(config_write_req);
    defer config_write_res.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, config_write_res.response_json, "\"ok\":true") != null);

    const control_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":5,\"node\":{d},\"payload\":{{\"name\":\"control\"}}}}",
        .{root_id},
    );
    defer allocator.free(control_lookup_req);
    var control_lookup_res = try node_service.handleRequestJsonWithEvents(control_lookup_req);
    defer control_lookup_res.deinit(allocator);
    var control_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, control_lookup_res.response_json, .{});
    defer control_lookup_parsed.deinit();
    const control_id = control_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const invoke_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":6,\"node\":{d},\"payload\":{{\"name\":\"invoke.json\"}}}}",
        .{control_id},
    );
    defer allocator.free(invoke_lookup_req);
    var invoke_lookup_res = try node_service.handleRequestJsonWithEvents(invoke_lookup_req);
    defer invoke_lookup_res.deinit(allocator);
    var invoke_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, invoke_lookup_res.response_json, .{});
    defer invoke_lookup_parsed.deinit();
    const invoke_id = invoke_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const open_invoke_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":7,\"node\":{d},\"payload\":{{\"flags\":2}}}}",
        .{invoke_id},
    );
    defer allocator.free(open_invoke_req);
    var open_invoke_res = try node_service.handleRequestJsonWithEvents(open_invoke_req);
    defer open_invoke_res.deinit(allocator);
    var open_invoke_parsed = try std.json.parseFromSlice(std.json.Value, allocator, open_invoke_res.response_json, .{});
    defer open_invoke_parsed.deinit();
    const invoke_handle = open_invoke_parsed.value.object.get("payload").?.object.get("h").?.integer;

    const invoke_payload = "{}";
    const invoke_b64_len = std.base64.standard.Encoder.calcSize(invoke_payload.len);
    const invoke_b64 = try allocator.alloc(u8, invoke_b64_len);
    defer allocator.free(invoke_b64);
    _ = std.base64.standard.Encoder.encode(invoke_b64, invoke_payload);

    const invoke_write_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_write\",\"tag\":8,\"h\":{d},\"payload\":{{\"off\":0,\"data_b64\":\"{s}\"}}}}",
        .{ invoke_handle, invoke_b64 },
    );
    defer allocator.free(invoke_write_req);
    var invoke_write_res = try node_service.handleRequestJsonWithEvents(invoke_write_req);
    defer invoke_write_res.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, invoke_write_res.response_json, "\"ok\":true") != null);

    const invoke_retry_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_write\",\"tag\":9,\"h\":{d},\"payload\":{{\"off\":0,\"data_b64\":\"{s}\"}}}}",
        .{ invoke_handle, invoke_b64 },
    );
    defer allocator.free(invoke_retry_req);
    var invoke_retry_res = try node_service.handleRequestJsonWithEvents(invoke_retry_req);
    defer invoke_retry_res.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, invoke_retry_res.response_json, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, invoke_retry_res.response_json, "\"errno\":11") != null);

    const stale_now = std.time.milliTimestamp();
    control_plane.mutex.lock();
    if (control_plane.nodes.getPtr(beta_node_id.string)) |node| {
        node.lease_expires_at_ms = stale_now - 1_000;
    }
    control_plane.mutex.unlock();

    var degraded_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .is_admin = false,
        },
    );
    defer degraded_session.deinit();

    const degraded_nodes_root = degraded_session.lookupChild(degraded_session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const degraded_beta_dir = degraded_session.lookupChild(degraded_nodes_root, beta_node_id.string) orelse return error.TestExpectedResponse;
    const degraded_status_id = degraded_session.lookupChild(degraded_beta_dir, "STATUS.json") orelse return error.TestExpectedResponse;
    const degraded_status_node = degraded_session.nodes.get(degraded_status_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, degraded_status_node.content, "\"state\":\"degraded\"") != null);

    const refresh_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"fs_url\":\"ws://127.0.0.1:18892/v2/fs\",\"lease_ttl_ms\":60000}}",
        .{ escaped_beta_id, escaped_beta_secret },
    );
    defer allocator.free(refresh_req);
    const refresh_res = try control_plane.refreshNodeLease(refresh_req);
    defer allocator.free(refresh_res);

    var recovered_session = try Session.initWithOptions(
        allocator,
        runtime_handle,
        &job_index,
        "default",
        .{
            .control_plane = &control_plane,
            .agents_dir = ".does-not-exist",
            .projects_dir = ".does-not-exist",
            .is_admin = false,
        },
    );
    defer recovered_session.deinit();

    const recovered_nodes_root = recovered_session.lookupChild(recovered_session.root_id, "nodes") orelse return error.TestExpectedResponse;
    const recovered_beta_dir = recovered_session.lookupChild(recovered_nodes_root, beta_node_id.string) orelse return error.TestExpectedResponse;
    const recovered_status_id = recovered_session.lookupChild(recovered_beta_dir, "STATUS.json") orelse return error.TestExpectedResponse;
    const recovered_status_node = recovered_session.nodes.get(recovered_status_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, recovered_status_node.content, "\"state\":\"online\"") != null);
}

test "acheron_session: runtime failure normalization redacts provider details" {
    const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("provider_request_invalid", "provider request invalid");
    try std.testing.expectEqualStrings("runtime_internal_limit", normalized.code);
    try std.testing.expectEqualStrings("Temporary internal runtime limit reached; retry this request.", normalized.message);
}

test "acheron_session: project metadata exposes workspace binds and mounted services" {
    const allocator = std.testing.allocator;

    var control_plane = control_plane_mod.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const project_json = try control_plane.createProject(
        "{\"name\":\"SessionTemplateGitHub\",\"vision\":\"SessionTemplateGitHub\",\"template_id\":\"github\"}",
    );
    defer allocator.free(project_json);
    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer parsed_project.deinit();
    const project_id = parsed_project.value.object.get("project_id").?.string;
    const project_token = parsed_project.value.object.get("project_token").?.string;

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
    defer runtime_handle.destroy();
    var job_index = chat_job_index.ChatJobIndex.init(allocator, "");
    defer job_index.deinit();

    var session = try Session.initWithOptions(
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
    defer session.deinit();

    const projects_root = session.lookupChild(session.root_id, "projects") orelse return error.TestExpectedResponse;
    const project_dir = session.lookupChild(projects_root, project_id) orelse return error.TestExpectedResponse;
    const meta_dir = session.lookupChild(project_dir, "meta") orelse return error.TestExpectedResponse;
    const binds_id = session.lookupChild(meta_dir, "binds.json") orelse return error.TestExpectedResponse;
    const binds_node = session.nodes.get(binds_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, binds_node.content, "\"bind_path\":\"/services/mounts\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, binds_node.content, "\"bind_path\":\"/services/github_pr\"") != null);

    const mounted_services_id = session.lookupChild(meta_dir, "mounted_services.json") orelse return error.TestExpectedResponse;
    const mounted_services_node = session.nodes.get(mounted_services_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, mounted_services_node.content, "\"path\":\"/services/git\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mounted_services_node.content, "\"target_path\":\"/nodes/local/venoms/github_pr\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mounted_services_node.content, "\"venom_id\":\"pr_review\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mounted_services_node.content, "\"exposure\":\"project_bind\"") != null);

    const root_meta_dir = session.lookupChild(session.root_id, "meta") orelse return error.TestExpectedResponse;
    const workspace_services_id = session.lookupChild(root_meta_dir, "workspace_services.json") orelse return error.TestExpectedResponse;
    const workspace_services_node = session.nodes.get(workspace_services_id) orelse return error.TestExpectedResponse;
    try std.testing.expect(std.mem.indexOf(u8, workspace_services_node.content, "\"path\":\"/services/missions\"") != null);
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

    const runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    const runtime_handle = try runtime_handle_mod.RuntimeHandle.createLocal(allocator, runtime_server);
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
    try std.testing.expectEqualStrings("/nodes/local/venoms/github_pr/control/sync.json", unbound_github_path);
}

test "acheron_session: missing provider API key is surfaced directly" {
    const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("execution_failed", "missing provider api key");
    try std.testing.expectEqualStrings("execution_failed", normalized.code);
    try std.testing.expectEqualStrings("missing provider api key", normalized.message);
}

test "acheron_session: runtime loop-guard text is classified as internal failure" {
    try std.testing.expect(chat_runtime_job.isInternalRuntimeLoopGuardText("I hit an internal reasoning loop while preparing that response. Please retry."));
    const normalized = chat_runtime_job.normalizeRuntimeFailureForAgent("execution_failed", "provider tool loop exceeded limits");
    try std.testing.expectEqualStrings("runtime_protocol_error", normalized.code);
    try std.testing.expect(std.mem.indexOf(u8, normalized.message, "tool-call contract") != null);
}
