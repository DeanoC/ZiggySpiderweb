const std = @import("std");
const builtin = @import("builtin");
const unified = @import("spider-protocol").unified;
const protocol = @import("spider-protocol").protocol;
const runtime_server_mod = @import("../agents/runtime_server.zig");
const runtime_handle_mod = @import("../agents/runtime_handle.zig");
const chat_job_index = @import("../agents/chat_job_index.zig");
const chat_runtime_job = @import("../agents/chat_runtime_job.zig");
const job_projection = @import("job_projection.zig");
const shared_node = @import("spiderweb_node");
const workspace_policy = @import("../workspaces/policy.zig");
const control_plane_mod = @import("control_plane.zig");
const acheron_router = @import("router.zig");
const agent_config = @import("../agents/agent_config.zig");
const agent_registry = @import("../agents/agent_registry.zig");

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
const max_agent_id_len: usize = 64;
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

const TerminalInvokeOp = enum {
    exec,
    create_session,
    resume_session,
    close_session,
    write_session,
    read_session,
    resize_session,
};

const TerminalSession = struct {
    label: ?[]u8 = null,
    cwd: ?[]u8 = null,
    buffered_result: ?[]u8 = null,
    created_at_ms: i64 = 0,
    updated_at_ms: i64 = 0,
    last_exec_at_ms: i64 = 0,
    last_read_at_ms: i64 = 0,
    closed_at_ms: i64 = 0,
    exec_count: u64 = 0,
    write_count: u64 = 0,
    read_count: u64 = 0,

    fn deinit(self: *TerminalSession, allocator: std.mem.Allocator) void {
        if (self.label) |value| allocator.free(value);
        if (self.cwd) |value| allocator.free(value);
        if (self.buffered_result) |value| allocator.free(value);
        self.* = undefined;
    }

    fn isClosed(self: TerminalSession) bool {
        return self.closed_at_ms != 0;
    }
};

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

pub const Session = struct {
    pub const NamespaceOptions = struct {
        project_id: ?[]const u8 = null,
        project_token: ?[]const u8 = null,
        agents_dir: []const u8 = "agents",
        assets_dir: []const u8 = "templates",
        projects_dir: []const u8 = "projects",
        local_fs_export_root: ?[]const u8 = null,
        control_plane: ?*control_plane_mod.ControlPlane = null,
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
    control_operator_token: ?[]u8 = null,
    is_admin: bool = false,

    nodes: std.AutoHashMapUnmanaged(u32, Node) = .{},
    fids: std.AutoHashMapUnmanaged(u32, FidState) = .{},
    next_node_id: u32 = 1,

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
    mounts_status_id: u32 = 0,
    mounts_result_id: u32 = 0,
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
                const outcome = self.handleProjectsNamespaceWrite(node.special, state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "projects payload is invalid for requested operation",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "projects operation denied by policy",
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
        const global_library_dir = try self.addDir(global_root, "library", false);
        try self.seedGlobalLibraryNamespace(global_library_dir);

        try self.addNodeDirectoriesFromControlPlane(nodes_root);
        for (policy.nodes.items) |node| {
            if (self.lookupChild(nodes_root, node.id) != null) continue;
            try self.addNodeDirectory(nodes_root, node, false);
        }

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
        const chat = try self.addDir(global_root, "chat", false);
        const control = try self.addDir(chat, "control", false);
        const examples = try self.addDir(chat, "examples", false);
        self.chat_input_id = try self.addFile(control, "input", "", true, .chat_input);
        _ = try self.addFile(control, "reply", "", true, .chat_reply);
        _ = try self.addFile(examples, "send.txt", shared_node.venom_contracts.chat.example_send_txt, false, .none);

        const chat_schema_json = try shared_node.venom_contracts.chat.renderSchemaJson(self.allocator, "/global/jobs", "control/reply");
        defer self.allocator.free(chat_schema_json);
        const chat_ops_json = try shared_node.venom_contracts.chat.renderOpsJson(self.allocator, "control/input", "/global/jobs", "control/reply");
        defer self.allocator.free(chat_ops_json);
        const chat_status_json = try shared_node.venom_contracts.chat.renderStatusJson(self.allocator, "/global/chat", "/global/jobs");
        defer self.allocator.free(chat_status_json);
        _ = try self.addFile(chat, "README.md", shared_node.venom_contracts.chat.readme_md, false, .none);
        _ = try self.addFile(chat, "SCHEMA.json", chat_schema_json, false, .none);
        _ = try self.addFile(chat, "CAPS.json", shared_node.venom_contracts.chat.caps_json, false, .none);
        _ = try self.addFile(chat, "OPS.json", chat_ops_json, false, .none);
        _ = try self.addFile(chat, "STATUS.json", chat_status_json, false, .none);

        const chat_meta_json = try shared_node.venom_contracts.chat.renderMetaJson(self.allocator, .{
            .agent_id = self.agent_id,
            .actor_type = self.actor_type,
            .actor_id = self.actor_id,
            .project_id = policy.project_id,
        });
        defer self.allocator.free(chat_meta_json);
        _ = try self.addFile(chat, "meta.json", chat_meta_json, false, .none);

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

        const memory_dir = try self.addDir(global_root, "memory", false);
        try self.seedAgentMemoryNamespace(memory_dir);
        const web_search_dir = try self.addDir(global_root, "web_search", false);
        try self.seedAgentWebSearchNamespace(web_search_dir);
        const search_code_dir = try self.addDir(global_root, "search_code", false);
        try self.seedAgentSearchCodeNamespace(search_code_dir);
        const terminal_dir = try self.addDir(global_root, "terminal", false);
        try self.seedAgentTerminalNamespace(terminal_dir);
        const mounts_dir = try self.addDir(global_root, "mounts", false);
        try self.seedAgentMountsNamespace(mounts_dir);
        const sub_brains_dir = try self.addDir(global_root, "sub_brains", false);
        try self.seedAgentSubBrainsNamespace(sub_brains_dir);
        const agents_control_dir = try self.addDir(global_root, "agents", false);
        try self.seedAgentAgentsNamespace(agents_control_dir);
        const projects_control_dir = try self.addDir(global_root, "projects", false);
        try self.seedAgentProjectsNamespace(projects_control_dir);

        self.jobs_root_id = try self.addDir(global_root, "jobs", false);
        try self.addDirectoryDescriptors(
            self.jobs_root_id,
            "Jobs",
            "{\"kind\":\"collection\",\"entries\":\"job_id\",\"files\":[\"status.json\",\"result.txt\",\"log.txt\"]}",
            "{\"read\":true,\"write\":false}",
            "Chat job status and outputs.",
        );
        const jobs_schema_json = try shared_node.venom_contracts.jobs.renderSchemaJson(self.allocator, "/global/jobs");
        defer self.allocator.free(jobs_schema_json);
        const jobs_status_json = try shared_node.venom_contracts.jobs.renderStatusJson(self.allocator, "/global/jobs");
        defer self.allocator.free(jobs_status_json);
        _ = try self.addFile(self.jobs_root_id, "README.md", shared_node.venom_contracts.jobs.readme_md, false, .none);
        _ = try self.addFile(self.jobs_root_id, "SCHEMA.json", jobs_schema_json, false, .none);
        _ = try self.addFile(self.jobs_root_id, "CAPS.json", shared_node.venom_contracts.jobs.caps_json, false, .none);
        _ = try self.addFile(self.jobs_root_id, "OPS.json", shared_node.venom_contracts.jobs.ops_json, false, .none);
        _ = try self.addFile(self.jobs_root_id, "STATUS.json", jobs_status_json, false, .none);
        try self.seedJobsFromIndex();

        const thoughts_dir = try self.addDir(global_root, "thoughts", false);
        try self.addDirectoryDescriptors(
            thoughts_dir,
            "Thoughts",
            "{\"kind\":\"stream\",\"files\":[\"latest.txt\",\"history.ndjson\",\"status.json\"]}",
            "{\"read\":true,\"write\":false}",
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

        const events_dir = try self.addDir(global_root, "events", false);
        const events_control_dir = try self.addDir(events_dir, "control", false);
        const events_sources_dir = try self.addDir(events_dir, "sources", false);
        _ = try self.addFile(events_dir, "README.md", shared_node.venom_contracts.events.readme_md, false, .none);
        _ = try self.addFile(
            events_dir,
            "SCHEMA.json",
            shared_node.venom_contracts.events.schema_json,
            false,
            .none,
        );
        _ = try self.addFile(
            events_dir,
            "CAPS.json",
            shared_node.venom_contracts.events.caps_json,
            false,
            .none,
        );
        _ = try self.addFile(events_dir, "OPS.json", shared_node.venom_contracts.events.ops_json, false, .none);
        _ = try self.addFile(events_dir, "STATUS.json", shared_node.venom_contracts.events.status_json, false, .none);
        _ = try self.addFile(
            events_control_dir,
            "README.md",
            shared_node.venom_contracts.events.control_readme_md,
            false,
            .none,
        );
        _ = try self.addFile(
            events_control_dir,
            "wait.json",
            shared_node.venom_contracts.events.default_wait_json,
            true,
            .event_wait_config,
        );
        _ = try self.addFile(
            events_control_dir,
            "signal.json",
            shared_node.venom_contracts.events.default_signal_json,
            true,
            .event_signal,
        );
        _ = try self.addFile(
            events_sources_dir,
            "README.md",
            shared_node.venom_contracts.events.sources_readme_md,
            false,
            .none,
        );
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
            "{\"kind\":\"metadata\",\"files\":[\"topology.json\",\"nodes.json\",\"agents.json\",\"sources.json\",\"contracts.json\",\"paths.json\",\"summary.json\",\"alerts.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"]}",
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
            "{\"kind\":\"meta\",\"entries\":[\"protocol.json\",\"view.json\",\"workspace_status.json\",\"workspace_availability.json\",\"workspace_health.json\",\"workspace_alerts.json\"]}",
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
        try self.registerExistingGlobalVenomBinding(global_root, "projects", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "thoughts", "project_namespace");
        try self.registerExistingGlobalVenomBinding(global_root, "library", "global_namespace");
        const preferred_fs_node_id = try self.resolvePreferredBoundVenomNodeId("fs");
        defer if (preferred_fs_node_id) |value| self.allocator.free(value);
        _ = try self.seedBoundGlobalFsNamespace(global_root, preferred_fs_node_id orelse "local");
        try self.seedActiveScopedVenomBindings(active_agent_venoms_dir, project_venoms_dir, policy.project_id);
        try self.refreshScopedVenomIndexes();
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

    fn refreshProjectBindsFromControlPlane(self: *Session) !void {
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

    fn addDirectoryDescriptors(
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
        try self.addDirectoryDescriptors(
            memory_dir,
            "Memory",
            "{\"kind\":\"venom\",\"venom_id\":\"memory\",\"shape\":\"/global/memory/{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"memory_create\",\"memory_load\",\"memory_versions\",\"memory_mutate\",\"memory_evict\",\"memory_search\"],\"discoverable\":true}",
            "First-class memory namespace. Write operation payloads to control/*.json, then read status.json/result.json.",
        );
        _ = try self.addFile(
            memory_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"create\":\"control/create.json\",\"load\":\"control/load.json\",\"versions\":\"control/versions.json\",\"mutate\":\"control/mutate.json\",\"evict\":\"control/evict.json\",\"search\":\"control/search.json\"},\"operations\":{\"create\":\"create\",\"load\":\"load\",\"versions\":\"versions\",\"mutate\":\"mutate\",\"evict\":\"evict\",\"search\":\"search\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            memory_dir,
            "RUNTIME.json",
            "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"agent_memory\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            memory_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            memory_dir,
            "STATUS.json",
            "{\"venom_id\":\"memory\",\"state\":\"namespace\",\"has_invoke\":true}",
            false,
            .none,
        );
        _ = try self.addFile(
            memory_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        _ = try self.addFile(
            memory_dir,
            "result.json",
            "{\"ok\":false,\"result\":null,\"error\":null}",
            false,
            .none,
        );

        const control_dir = try self.addDir(memory_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Write JSON payloads to operation files. Generic invoke is available at invoke.json.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .memory_invoke);
        _ = try self.addFile(control_dir, "create.json", "", true, .memory_create);
        _ = try self.addFile(control_dir, "load.json", "", true, .memory_load);
        _ = try self.addFile(control_dir, "versions.json", "", true, .memory_versions);
        _ = try self.addFile(control_dir, "mutate.json", "", true, .memory_mutate);
        _ = try self.addFile(control_dir, "evict.json", "", true, .memory_evict);
        _ = try self.addFile(control_dir, "search.json", "", true, .memory_search);
    }

    fn seedAgentWebSearchNamespace(self: *Session, web_search_dir: u32) !void {
        try self.addDirectoryDescriptors(
            web_search_dir,
            "Web Search",
            "{\"kind\":\"venom\",\"venom_id\":\"web_search\",\"shape\":\"/global/web_search/{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"web_search\"],\"discoverable\":true,\"network\":true}",
            "First-class web search namespace. Write search payloads to control/search.json (or invoke.json), then read status.json/result.json.",
        );
        _ = try self.addFile(
            web_search_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"search\":\"control/search.json\"},\"operations\":{\"search\":\"search\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            web_search_dir,
            "RUNTIME.json",
            "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"web_search\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            web_search_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            web_search_dir,
            "STATUS.json",
            "{\"venom_id\":\"web_search\",\"state\":\"namespace\",\"has_invoke\":true}",
            false,
            .none,
        );
        _ = try self.addFile(
            web_search_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        _ = try self.addFile(
            web_search_dir,
            "result.json",
            "{\"ok\":false,\"result\":null,\"error\":null}",
            false,
            .none,
        );

        const control_dir = try self.addDir(web_search_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Write search payloads to search.json (or explicit envelopes to invoke.json). Read result.json and status.json.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .web_search_invoke);
        _ = try self.addFile(control_dir, "search.json", "", true, .web_search_search);
    }

    fn seedAgentSearchCodeNamespace(self: *Session, search_code_dir: u32) !void {
        try self.addDirectoryDescriptors(
            search_code_dir,
            "Search Code",
            "{\"kind\":\"venom\",\"venom_id\":\"search_code\",\"shape\":\"/global/search_code/{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"search_code\"],\"discoverable\":true}",
            "First-class code search namespace. Write search payloads to control/search.json (or invoke.json), then read status.json/result.json.",
        );
        _ = try self.addFile(
            search_code_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"search\":\"control/search.json\"},\"operations\":{\"search\":\"search\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            search_code_dir,
            "RUNTIME.json",
            "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"search_code\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            search_code_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            search_code_dir,
            "STATUS.json",
            "{\"venom_id\":\"search_code\",\"state\":\"namespace\",\"has_invoke\":true}",
            false,
            .none,
        );
        _ = try self.addFile(
            search_code_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        _ = try self.addFile(
            search_code_dir,
            "result.json",
            "{\"ok\":false,\"result\":null,\"error\":null}",
            false,
            .none,
        );

        const control_dir = try self.addDir(search_code_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Write search payloads to search.json (or explicit envelopes to invoke.json). Read result.json and status.json.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .search_code_invoke);
        _ = try self.addFile(control_dir, "search.json", "", true, .search_code_search);
    }

    fn seedAgentTerminalNamespace(self: *Session, terminal_dir: u32) !void {
        try self.addDirectoryDescriptors(
            terminal_dir,
            "Terminal",
            "{\"kind\":\"venom\",\"venom_id\":\"terminal-v2\",\"shape\":\"/global/terminal/{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,sessions.json,current.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"terminal_session_create\",\"terminal_session_resume\",\"terminal_session_close\",\"terminal_session_write\",\"terminal_session_read\",\"terminal_session_resize\",\"shell_exec\"],\"discoverable\":true,\"interactive\":true,\"sessionized\":true,\"pty\":true}",
            "Sessionized terminal namespace. Create/resume/close PTY sessions and use write/read/resize for interactive workflows.",
        );
        _ = try self.addFile(
            terminal_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"create\":\"control/create.json\",\"resume\":\"control/resume.json\",\"close\":\"control/close.json\",\"write\":\"control/write.json\",\"read\":\"control/read.json\",\"resize\":\"control/resize.json\",\"exec\":\"control/exec.json\"},\"operations\":{\"create\":\"create\",\"resume\":\"resume\",\"close\":\"close\",\"write\":\"write\",\"read\":\"read\",\"resize\":\"resize\",\"exec\":\"exec\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            terminal_dir,
            "RUNTIME.json",
            "{\"type\":\"runtime_tool\",\"tool\":\"shell_exec\",\"session_model\":\"terminal-v2\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            terminal_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            terminal_dir,
            "STATUS.json",
            "{\"venom_id\":\"terminal-v2\",\"state\":\"namespace\",\"has_invoke\":true,\"sessionized\":true}",
            false,
            .none,
        );
        self.terminal_status_id = try self.addFile(
            terminal_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"session_id\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        self.terminal_result_id = try self.addFile(
            terminal_dir,
            "result.json",
            "{\"ok\":false,\"result\":null,\"error\":null}",
            false,
            .none,
        );
        self.terminal_sessions_id = try self.addFile(
            terminal_dir,
            "sessions.json",
            "{\"sessions\":[]}",
            false,
            .none,
        );
        self.terminal_current_id = try self.addFile(
            terminal_dir,
            "current.json",
            "{\"session\":null}",
            false,
            .none,
        );

        const control_dir = try self.addDir(terminal_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Use create/resume/close to manage PTY sessions. Use write/read/resize for interactive I/O. exec is a convenience write+read command path. invoke.json accepts op=create|resume|close|write|read|resize|exec envelopes.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .terminal_v2_invoke);
        _ = try self.addFile(control_dir, "create.json", "", true, .terminal_v2_create);
        _ = try self.addFile(control_dir, "resume.json", "", true, .terminal_v2_resume);
        _ = try self.addFile(control_dir, "close.json", "", true, .terminal_v2_close);
        _ = try self.addFile(control_dir, "write.json", "", true, .terminal_v2_write);
        _ = try self.addFile(control_dir, "read.json", "", true, .terminal_v2_read);
        _ = try self.addFile(control_dir, "resize.json", "", true, .terminal_v2_resize);
        _ = try self.addFile(control_dir, "exec.json", "", true, .terminal_v2_exec);
    }

    fn seedAgentMountsNamespace(self: *Session, mounts_dir: u32) !void {
        try self.addDirectoryDescriptors(
            mounts_dir,
            "Mounts and Binds",
            "{\"kind\":\"venom\",\"venom_id\":\"mounts\",\"shape\":\"/global/mounts/{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"list\",\"mount\",\"mkdir\",\"unmount\",\"bind\",\"unbind\",\"resolve\"],\"discoverable\":true,\"project_scope\":true}",
            "Manage project mounts and path binds through Acheron control files.",
        );
        _ = try self.addFile(
            mounts_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"mount\":\"control/mount.json\",\"mkdir\":\"control/mkdir.json\",\"unmount\":\"control/unmount.json\",\"bind\":\"control/bind.json\",\"unbind\":\"control/unbind.json\",\"resolve\":\"control/resolve.json\"},\"operations\":{\"list\":\"list\",\"mount\":\"mount\",\"mkdir\":\"mkdir\",\"unmount\":\"unmount\",\"bind\":\"bind\",\"unbind\":\"unbind\",\"resolve\":\"resolve\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            mounts_dir,
            "RUNTIME.json",
            "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"project_mounts_binds\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            mounts_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"project\",\"project_token_required\":false}",
            false,
            .none,
        );
        _ = try self.addFile(
            mounts_dir,
            "STATUS.json",
            "{\"venom_id\":\"mounts\",\"state\":\"namespace\",\"has_invoke\":true}",
            false,
            .none,
        );
        self.mounts_status_id = try self.addFile(
            mounts_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        const initial_result = try self.buildMountsListResultJson(null, null);
        defer self.allocator.free(initial_result);
        self.mounts_result_id = try self.addFile(
            mounts_dir,
            "result.json",
            initial_result,
            false,
            .none,
        );

        const control_dir = try self.addDir(mounts_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Use list/mount/mkdir/unmount/bind/unbind/resolve operation files, or invoke.json with op plus arguments.\nMount, mkdir, and bind operations require project mount permission.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .mounts_invoke);
        _ = try self.addFile(control_dir, "list.json", "", true, .mounts_list);
        _ = try self.addFile(control_dir, "mount.json", "", true, .mounts_mount);
        _ = try self.addFile(control_dir, "mkdir.json", "", true, .mounts_mkdir);
        _ = try self.addFile(control_dir, "unmount.json", "", true, .mounts_unmount);
        _ = try self.addFile(control_dir, "bind.json", "", true, .mounts_bind);
        _ = try self.addFile(control_dir, "unbind.json", "", true, .mounts_unbind);
        _ = try self.addFile(control_dir, "resolve.json", "", true, .mounts_resolve);
    }

    fn seedAgentSubBrainsNamespace(self: *Session, sub_brains_dir: u32) !void {
        const can_manage_sub_brains = self.canManageSubBrains();
        const caps_json = if (can_manage_sub_brains)
            "{\"invoke\":true,\"operations\":[\"sub_brains_list\",\"sub_brains_upsert\",\"sub_brains_delete\"],\"discoverable\":true,\"config_mutation\":true,\"manage_allowed\":true}"
        else
            "{\"invoke\":true,\"operations\":[\"sub_brains_list\"],\"discoverable\":true,\"config_mutation\":false,\"manage_allowed\":false}";
        try self.addDirectoryDescriptors(
            sub_brains_dir,
            "Sub-Brains",
            "{\"kind\":\"venom\",\"venom_id\":\"sub_brains\",\"shape\":\"/global/sub_brains/{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            caps_json,
            "Manage sub-brain configuration for this agent through Acheron control files.",
        );
        _ = try self.addFile(
            sub_brains_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"upsert\":\"control/upsert.json\",\"delete\":\"control/delete.json\"},\"operations\":{\"list\":\"sub_brains_list\",\"upsert\":\"sub_brains_upsert\",\"delete\":\"sub_brains_delete\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            sub_brains_dir,
            "RUNTIME.json",
            "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"agent_sub_brains\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            sub_brains_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\",\"project_token_required\":false}",
            false,
            .none,
        );
        _ = try self.addFile(
            sub_brains_dir,
            "STATUS.json",
            "{\"venom_id\":\"sub_brains\",\"state\":\"namespace\",\"has_invoke\":true}",
            false,
            .none,
        );
        self.sub_brains_status_id = try self.addFile(
            sub_brains_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        const initial_result = try self.buildSubBrainListResultJson();
        defer self.allocator.free(initial_result);
        self.sub_brains_result_id = try self.addFile(
            sub_brains_dir,
            "result.json",
            initial_result,
            false,
            .none,
        );

        const control_dir = try self.addDir(sub_brains_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Use list/upsert/delete operation files, or invoke.json with op=list|upsert|delete plus arguments. Upsert/delete require sub-brain management capability.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .sub_brains_invoke);
        _ = try self.addFile(control_dir, "list.json", "", true, .sub_brains_list);
        _ = try self.addFile(control_dir, "upsert.json", "", can_manage_sub_brains, .sub_brains_upsert);
        _ = try self.addFile(control_dir, "delete.json", "", can_manage_sub_brains, .sub_brains_delete);
    }

    fn seedAgentAgentsNamespace(self: *Session, agents_dir: u32) !void {
        const can_create_agents = self.canCreateAgents();
        const caps_json = if (can_create_agents)
            "{\"invoke\":true,\"operations\":[\"agents_list\",\"agents_create\"],\"discoverable\":true,\"create_allowed\":true}"
        else
            "{\"invoke\":true,\"operations\":[\"agents_list\"],\"discoverable\":true,\"create_allowed\":false}";
        try self.addDirectoryDescriptors(
            agents_dir,
            "Agents Management",
            "{\"kind\":\"venom\",\"venom_id\":\"agents\",\"shape\":\"/global/agents/{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            caps_json,
            "List and create agent workspaces through Acheron control files.",
        );
        _ = try self.addFile(
            agents_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"create\":\"control/create.json\"},\"operations\":{\"list\":\"agents_list\",\"create\":\"agents_create\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            agents_dir,
            "RUNTIME.json",
            "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"agent_registry\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            agents_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\",\"project_token_required\":false}",
            false,
            .none,
        );
        _ = try self.addFile(
            agents_dir,
            "STATUS.json",
            "{\"venom_id\":\"agents\",\"state\":\"namespace\",\"has_invoke\":true}",
            false,
            .none,
        );
        self.agents_status_id = try self.addFile(
            agents_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        const initial_result = try self.buildAgentListResultJson();
        defer self.allocator.free(initial_result);
        self.agents_result_id = try self.addFile(
            agents_dir,
            "result.json",
            initial_result,
            false,
            .none,
        );

        const control_dir = try self.addDir(agents_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Use list/create operation files, or invoke.json with op=list|create plus arguments. Create requires agent provisioning capability.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .agents_invoke);
        _ = try self.addFile(control_dir, "list.json", "", true, .agents_list);
        _ = try self.addFile(control_dir, "create.json", "", can_create_agents, .agents_create);
    }

    fn seedAgentProjectsNamespace(self: *Session, projects_dir: u32) !void {
        try self.addDirectoryDescriptors(
            projects_dir,
            "Projects Management",
            "{\"kind\":\"venom\",\"venom_id\":\"projects\",\"shape\":\"/global/projects/{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"projects_list\",\"projects_get\",\"projects_up\"],\"discoverable\":true}",
            "List, inspect, and create/update projects through Acheron control files.",
        );
        _ = try self.addFile(
            projects_dir,
            "OPS.json",
            "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"get\":\"control/get.json\",\"up\":\"control/up.json\"},\"operations\":{\"list\":\"projects_list\",\"get\":\"projects_get\",\"up\":\"projects_up\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            projects_dir,
            "RUNTIME.json",
            "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"control_plane_projects\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            projects_dir,
            "PERMISSIONS.json",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"project_control_plane\"}",
            false,
            .none,
        );
        _ = try self.addFile(
            projects_dir,
            "STATUS.json",
            "{\"venom_id\":\"projects\",\"state\":\"namespace\",\"has_invoke\":true}",
            false,
            .none,
        );
        self.projects_status_id = try self.addFile(
            projects_dir,
            "status.json",
            "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
            false,
            .none,
        );
        const initial_result = try self.buildProjectListResultJson();
        defer self.allocator.free(initial_result);
        self.projects_result_id = try self.addFile(
            projects_dir,
            "result.json",
            initial_result,
            false,
            .none,
        );

        const control_dir = try self.addDir(projects_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Use list/get/up operation files, or invoke.json with op=list|get|up plus arguments. For Mother bootstrap provisioning, use up with activate=false.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .projects_invoke);
        _ = try self.addFile(control_dir, "list.json", "", true, .projects_list);
        _ = try self.addFile(control_dir, "get.json", "", true, .projects_get);
        _ = try self.addFile(control_dir, "up.json", "", true, .projects_up);
    }

    fn seedGlobalLibraryNamespace(self: *Session, library_dir: u32) !void {
        try self.addDirectoryDescriptors(
            library_dir,
            "Global Library",
            "{\"kind\":\"venom\",\"venom_id\":\"library\",\"shape\":\"/global/library/{Index.md,README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,topics/*}\"}",
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
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(invoke_node_id, input);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = self.terminalInvokeOperationFromPayload(obj) orelse return error.InvalidPayload;

        const operation_payload = blk: {
            if (obj.get("arguments")) |value| break :blk try self.renderJsonValue(value);
            if (obj.get("args")) |value| break :blk try self.renderJsonValue(value);
            break :blk try self.allocator.dupe(u8, input);
        };
        defer self.allocator.free(operation_payload);

        return switch (op) {
            .create_session => self.terminalV2Create(operation_payload),
            .resume_session => self.terminalV2Resume(operation_payload),
            .close_session => self.terminalV2Close(operation_payload),
            .write_session => self.terminalV2Write(operation_payload),
            .read_session => self.terminalV2Read(operation_payload),
            .resize_session => self.terminalV2Resize(operation_payload),
            .exec => self.terminalV2Exec(operation_payload),
        };
    }

    fn handleTerminalV2CreateWrite(self: *Session, create_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(create_node_id, payload);
        return self.terminalV2Create(payload);
    }

    fn handleTerminalV2ResumeWrite(self: *Session, resume_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(resume_node_id, input);
        return self.terminalV2Resume(input);
    }

    fn handleTerminalV2CloseWrite(self: *Session, close_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(close_node_id, payload);
        return self.terminalV2Close(payload);
    }

    fn handleTerminalV2WriteWrite(self: *Session, write_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(write_node_id, input);
        return self.terminalV2Write(input);
    }

    fn handleTerminalV2ReadWrite(self: *Session, read_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(read_node_id, payload);
        return self.terminalV2Read(payload);
    }

    fn handleTerminalV2ResizeWrite(self: *Session, resize_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(resize_node_id, input);
        return self.terminalV2Resize(input);
    }

    fn handleTerminalV2ExecWrite(self: *Session, exec_node_id: u32, raw_input: []const u8) anyerror!WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(exec_node_id, input);
        return self.terminalV2Exec(input);
    }

    fn terminalV2Create(self: *Session, payload: []const u8) !WriteOutcome {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const maybe_session_id = try jsonObjectOptionalString(obj, "session_id");
        const label = try jsonObjectOptionalString(obj, "label");
        const cwd = try jsonObjectOptionalString(obj, "cwd");
        _ = try jsonObjectOptionalString(obj, "shell");

        const session_id_owned = if (maybe_session_id) |value|
            try self.allocator.dupe(u8, value)
        else
            try self.generateTerminalSessionId();
        errdefer self.allocator.free(session_id_owned);
        if (self.terminal_sessions.contains(session_id_owned)) return error.InvalidPayload;

        var session = TerminalSession{
            .label = if (label) |value| try self.allocator.dupe(u8, value) else null,
            .cwd = if (cwd) |value| try self.allocator.dupe(u8, value) else null,
            .created_at_ms = std.time.milliTimestamp(),
            .updated_at_ms = std.time.milliTimestamp(),
        };
        errdefer session.deinit(self.allocator);

        try self.terminal_sessions.putNoClobber(self.allocator, session_id_owned, session);
        try self.setCurrentTerminalSession(session_id_owned);
        try self.refreshTerminalV2StateFiles();
        try self.updateTerminalV2StatusAndResult(
            "done",
            "terminal_session_create",
            session_id_owned,
            null,
            "create",
            "{\"state\":\"open\",\"backend\":\"runtime_tool\"}",
        );
        return .{ .written = payload.len };
    }

    fn terminalV2Resume(self: *Session, payload: []const u8) !WriteOutcome {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;
        const session_id = (try jsonObjectOptionalString(obj, "session_id")) orelse return error.InvalidPayload;
        var session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
        if (session.isClosed()) return error.TerminalSessionClosed;

        session.updated_at_ms = std.time.milliTimestamp();
        try self.setCurrentTerminalSession(session_id);
        try self.refreshTerminalV2StateFiles();
        try self.updateTerminalV2StatusAndResult("done", "terminal_session_resume", session_id, null, "resume", "{\"state\":\"open\"}");
        return .{ .written = payload.len };
    }

    fn terminalV2Close(self: *Session, payload: []const u8) !WriteOutcome {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;
        const selected_id = blk: {
            if (try jsonObjectOptionalString(obj, "session_id")) |value| break :blk value;
            if (self.current_terminal_session_id) |value| break :blk value;
            break :blk null;
        } orelse return error.InvalidPayload;

        var session = self.terminal_sessions.getPtr(selected_id) orelse return error.TerminalSessionNotFound;
        const now_ms = std.time.milliTimestamp();
        if (session.buffered_result) |old| {
            self.allocator.free(old);
            session.buffered_result = null;
        }
        session.closed_at_ms = now_ms;
        session.updated_at_ms = now_ms;
        if (self.current_terminal_session_id) |current| {
            if (std.mem.eql(u8, current, selected_id)) try self.setCurrentTerminalSession(null);
        }
        try self.refreshTerminalV2StateFiles();
        try self.updateTerminalV2StatusAndResult("done", "terminal_session_close", selected_id, null, "close", "{\"state\":\"closed\"}");
        return .{ .written = payload.len };
    }

    fn terminalV2Write(self: *Session, payload: []const u8) !WriteOutcome {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const session_id = try self.resolveTerminalSessionIdForPayload(obj) orelse return error.InvalidPayload;
        var session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
        if (session.isClosed()) return error.TerminalSessionClosed;

        const write_bytes = try self.parseTerminalWriteBytes(obj);
        defer self.allocator.free(write_bytes);
        if (write_bytes.len == 0) return error.InvalidPayload;

        const runtime_args = try self.buildTerminalWriteArgsJson(session.cwd, write_bytes);
        defer self.allocator.free(runtime_args);

        const runtime_payload = try self.executeServiceToolCall("shell_exec", runtime_args);
        defer self.allocator.free(runtime_payload);
        if (try self.extractErrorMessageFromToolPayload(runtime_payload)) |message| {
            defer self.allocator.free(message);
            session.updated_at_ms = std.time.milliTimestamp();
            try self.setCurrentTerminalSession(session_id);
            try self.refreshTerminalV2StateFiles();
            try self.updateTerminalV2StatusAndResult("failed", "terminal_session_write", session_id, message, "write", "null");
            return .{ .written = payload.len };
        }
        const terminal_output = try self.extractTerminalOutputBytesFromToolPayload(runtime_payload);
        defer self.allocator.free(terminal_output);
        try self.appendTerminalBufferedResult(session, terminal_output);

        const now_ms = std.time.milliTimestamp();
        session.updated_at_ms = now_ms;
        session.last_exec_at_ms = now_ms;
        session.write_count +%= 1;
        session.exec_count +%= 1;
        try self.setCurrentTerminalSession(session_id);
        try self.refreshTerminalV2StateFiles();

        const write_result = try std.fmt.allocPrint(self.allocator, "{{\"written\":{d}}}", .{write_bytes.len});
        defer self.allocator.free(write_result);
        try self.updateTerminalV2StatusAndResult("done", "terminal_session_write", session_id, null, "write", write_result);
        return .{ .written = payload.len };
    }

    fn terminalV2Read(self: *Session, payload: []const u8) !WriteOutcome {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const session_id = try self.resolveTerminalSessionIdForPayload(obj) orelse return error.InvalidPayload;
        var session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
        if (session.isClosed()) return error.TerminalSessionClosed;

        const timeout_ms = blk: {
            if (try jsonObjectOptionalU64(obj, "timeout_ms")) |value| break :blk @as(i32, @intCast(@min(value, @as(u64, std.math.maxInt(i32)))));
            break :blk @as(i32, 100);
        };
        const max_bytes = blk: {
            if (try jsonObjectOptionalU64(obj, "max_bytes")) |value| {
                const clamped = @max(@as(u64, 1), @min(value, @as(u64, 1024 * 1024)));
                break :blk @as(usize, @intCast(clamped));
            }
            break :blk @as(usize, 64 * 1024);
        };

        _ = timeout_ms;
        const visible_bytes = try self.consumeTerminalBufferedResult(session, max_bytes);
        defer self.allocator.free(visible_bytes);

        const now_ms = std.time.milliTimestamp();
        session.updated_at_ms = now_ms;
        session.last_read_at_ms = now_ms;
        session.read_count +%= 1;
        try self.setCurrentTerminalSession(session_id);
        try self.refreshTerminalV2StateFiles();

        const read_result = try self.buildTerminalOutputResultJson(visible_bytes, false);
        defer self.allocator.free(read_result);
        try self.updateTerminalV2StatusAndResult("done", "terminal_session_read", session_id, null, "read", read_result);
        return .{ .written = payload.len };
    }

    fn terminalV2Resize(self: *Session, payload: []const u8) !WriteOutcome {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const cols = (try jsonObjectOptionalU64(obj, "cols")) orelse return error.InvalidPayload;
        const rows = (try jsonObjectOptionalU64(obj, "rows")) orelse return error.InvalidPayload;
        if (cols == 0 or rows == 0) return error.InvalidPayload;

        const session_id = try self.resolveTerminalSessionIdForPayload(obj) orelse return error.InvalidPayload;
        var session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
        if (session.isClosed()) return error.TerminalSessionClosed;

        session.updated_at_ms = std.time.milliTimestamp();
        try self.setCurrentTerminalSession(session_id);
        try self.refreshTerminalV2StateFiles();
        const resize_result = try std.fmt.allocPrint(self.allocator, "{{\"cols\":{d},\"rows\":{d}}}", .{ cols, rows });
        defer self.allocator.free(resize_result);
        try self.updateTerminalV2StatusAndResult("done", "terminal_session_resize", session_id, null, "resize", resize_result);
        return .{ .written = payload.len };
    }

    fn terminalV2Exec(self: *Session, payload: []const u8) !WriteOutcome {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const explicit_session_id = try jsonObjectOptionalString(obj, "session_id");
        var selected_session_id: ?[]const u8 = explicit_session_id;
        if (selected_session_id == null) selected_session_id = self.current_terminal_session_id;

        if (selected_session_id) |session_id| {
            var session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
            if (session.isClosed()) return error.TerminalSessionClosed;

            const args_json = try self.buildTerminalExecArgsJson(obj, session.cwd);
            defer self.allocator.free(args_json);
            const runtime_payload = try self.executeServiceToolCall("shell_exec", args_json);
            defer self.allocator.free(runtime_payload);

            const now_ms = std.time.milliTimestamp();
            session.updated_at_ms = now_ms;
            session.last_exec_at_ms = now_ms;
            session.exec_count +%= 1;
            session.write_count +%= 1;
            session.read_count +%= 1;
            if (try jsonObjectOptionalString(obj, "cwd")) |next_cwd| {
                if (session.cwd) |old| self.allocator.free(old);
                session.cwd = try self.allocator.dupe(u8, next_cwd);
            }
            if (try self.extractErrorMessageFromToolPayload(runtime_payload)) |message| {
                defer self.allocator.free(message);
                try self.setCurrentTerminalSession(session_id);
                try self.refreshTerminalV2StateFiles();
                try self.updateTerminalV2StatusAndResult("failed", "shell_exec", session_id, message, "exec", "null");
                return .{ .written = payload.len };
            }
            const terminal_output = try self.extractTerminalOutputBytesFromToolPayload(runtime_payload);
            defer self.allocator.free(terminal_output);
            try self.appendTerminalBufferedResult(session, terminal_output);
            try self.setCurrentTerminalSession(session_id);
            try self.refreshTerminalV2StateFiles();

            const exec_result = try self.buildTerminalOutputResultJson(terminal_output, false);
            defer self.allocator.free(exec_result);
            try self.updateTerminalV2StatusAndResult("done", "shell_exec", session_id, null, "exec", exec_result);
            return .{ .written = payload.len };
        }

        // Acheron terminal-v2 requires an explicit or current session context.
        return error.InvalidPayload;
    }

    fn appendTerminalBufferedResult(self: *Session, session: *TerminalSession, payload: []const u8) !void {
        if (payload.len == 0) return;
        if (session.buffered_result) |existing| {
            const merged = try self.allocator.alloc(u8, existing.len + payload.len);
            @memcpy(merged[0..existing.len], existing);
            @memcpy(merged[existing.len..], payload);
            self.allocator.free(existing);
            session.buffered_result = merged;
            return;
        }
        session.buffered_result = try self.allocator.dupe(u8, payload);
    }

    fn buildTerminalWriteArgsJson(self: *Session, cwd: ?[]const u8, write_bytes: []const u8) ![]u8 {
        const shell_command = try self.buildTerminalWriteShellCommand(write_bytes);
        defer self.allocator.free(shell_command);
        const escaped_command = try unified.jsonEscape(self.allocator, shell_command);
        defer self.allocator.free(escaped_command);

        var runtime_args = std.ArrayListUnmanaged(u8){};
        errdefer runtime_args.deinit(self.allocator);
        try runtime_args.writer(self.allocator).print("{{\"command\":\"{s}\"", .{escaped_command});
        if (cwd) |value| {
            const escaped_cwd = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped_cwd);
            try runtime_args.writer(self.allocator).print(",\"cwd\":\"{s}\"", .{escaped_cwd});
        }
        try runtime_args.append(self.allocator, '}');
        return runtime_args.toOwnedSlice(self.allocator);
    }

    fn buildTerminalWriteShellCommand(self: *Session, write_bytes: []const u8) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "eval $'");
        for (write_bytes) |byte| {
            switch (byte) {
                '\\' => try out.appendSlice(self.allocator, "\\\\"),
                '\'' => try out.appendSlice(self.allocator, "\\'"),
                '\n' => try out.appendSlice(self.allocator, "\\n"),
                '\r' => try out.appendSlice(self.allocator, "\\r"),
                '\t' => try out.appendSlice(self.allocator, "\\t"),
                0x20...0x26, 0x28...0x5b, 0x5d...0x7e => try out.append(self.allocator, byte),
                else => try out.writer(self.allocator).print("\\x{x:0>2}", .{byte}),
            }
        }
        try out.append(self.allocator, '\'');
        return out.toOwnedSlice(self.allocator);
    }

    fn extractTerminalOutputBytesFromToolPayload(self: *Session, payload_json: []const u8) ![]u8 {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;
        const stdout = if (obj.get("stdout")) |value|
            if (value == .string) value.string else return error.InvalidPayload
        else
            "";
        const stderr = if (obj.get("stderr")) |value|
            if (value == .string) value.string else return error.InvalidPayload
        else
            "";

        const merged = try self.allocator.alloc(u8, stdout.len + stderr.len);
        @memcpy(merged[0..stdout.len], stdout);
        @memcpy(merged[stdout.len..], stderr);
        return merged;
    }

    fn buildTerminalOutputResultJson(self: *Session, output: []const u8, eof: bool) ![]u8 {
        const output_b64 = try unified.encodeDataB64(self.allocator, output);
        defer self.allocator.free(output_b64);
        const escaped_b64 = try unified.jsonEscape(self.allocator, output_b64);
        defer self.allocator.free(escaped_b64);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"n\":{d},\"data_b64\":\"{s}\",\"eof\":{s}}}",
            .{
                output.len,
                escaped_b64,
                if (eof) "true" else "false",
            },
        );
    }

    fn consumeTerminalBufferedResult(self: *Session, session: *TerminalSession, max_bytes: usize) ![]u8 {
        const existing = session.buffered_result orelse return self.allocator.dupe(u8, "");
        const visible_len = @min(existing.len, max_bytes);
        const visible = try self.allocator.dupe(u8, existing[0..visible_len]);

        if (visible_len == existing.len) {
            self.allocator.free(existing);
            session.buffered_result = null;
            return visible;
        }

        const tail = try self.allocator.dupe(u8, existing[visible_len..]);
        self.allocator.free(existing);
        session.buffered_result = tail;
        return visible;
    }

    fn parseTerminalWriteBytes(self: *Session, obj: std.json.ObjectMap) ![]u8 {
        const append_newline = (try jsonObjectOptionalBool(obj, "append_newline")) orelse false;
        if (try jsonObjectOptionalString(obj, "command")) |command| {
            var buf = std.ArrayListUnmanaged(u8){};
            errdefer buf.deinit(self.allocator);
            try buf.appendSlice(self.allocator, command);
            if (command.len == 0 or command[command.len - 1] != '\n') try buf.append(self.allocator, '\n');
            return buf.toOwnedSlice(self.allocator);
        }
        if (try jsonObjectOptionalString(obj, "input")) |input| {
            var buf = std.ArrayListUnmanaged(u8){};
            errdefer buf.deinit(self.allocator);
            try buf.appendSlice(self.allocator, input);
            if (append_newline and (input.len == 0 or input[input.len - 1] != '\n')) try buf.append(self.allocator, '\n');
            return buf.toOwnedSlice(self.allocator);
        }
        if (try jsonObjectOptionalString(obj, "data_b64")) |data_b64| {
            const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(data_b64);
            const decoded = try self.allocator.alloc(u8, decoded_len);
            errdefer self.allocator.free(decoded);
            try std.base64.standard.Decoder.decode(decoded, data_b64);
            if (!append_newline) return decoded;
            var buf = std.ArrayListUnmanaged(u8){};
            errdefer buf.deinit(self.allocator);
            try buf.appendSlice(self.allocator, decoded);
            self.allocator.free(decoded);
            if (buf.items.len == 0 or buf.items[buf.items.len - 1] != '\n') try buf.append(self.allocator, '\n');
            return buf.toOwnedSlice(self.allocator);
        }
        return error.InvalidPayload;
    }

    fn resolveTerminalSessionIdForPayload(self: *Session, obj: std.json.ObjectMap) !?[]const u8 {
        if (try jsonObjectOptionalString(obj, "session_id")) |value| return value;
        if (self.current_terminal_session_id) |value| return value;
        return null;
    }

    fn buildTerminalExecArgsJson(
        self: *Session,
        obj: std.json.ObjectMap,
        session_cwd: ?[]const u8,
    ) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.append(self.allocator, '{');
        var first = true;
        var has_command = false;
        var has_argv = false;
        var has_cwd = false;

        var it = obj.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (std.mem.eql(u8, key, "session_id") or
                std.mem.eql(u8, key, "op") or
                std.mem.eql(u8, key, "operation") or
                std.mem.eql(u8, key, "tool") or
                std.mem.eql(u8, key, "tool_name") or
                std.mem.eql(u8, key, "arguments") or
                std.mem.eql(u8, key, "args"))
            {
                continue;
            }
            if (std.mem.eql(u8, key, "command")) has_command = true;
            if (std.mem.eql(u8, key, "argv")) has_argv = true;
            if (std.mem.eql(u8, key, "cwd")) has_cwd = true;

            if (!first) try out.append(self.allocator, ',');
            first = false;
            const escaped_key = try unified.jsonEscape(self.allocator, key);
            defer self.allocator.free(escaped_key);
            const value_json = try self.renderJsonValue(entry.value_ptr.*);
            defer self.allocator.free(value_json);
            try out.writer(self.allocator).print("\"{s}\":{s}", .{ escaped_key, value_json });
        }

        if (!has_cwd and session_cwd != null) {
            if (!first) try out.append(self.allocator, ',');
            const escaped_cwd = try unified.jsonEscape(self.allocator, session_cwd.?);
            defer self.allocator.free(escaped_cwd);
            try out.writer(self.allocator).print("\"cwd\":\"{s}\"", .{escaped_cwd});
        }
        try out.append(self.allocator, '}');
        if (!has_command and !has_argv) return error.InvalidPayload;
        return out.toOwnedSlice(self.allocator);
    }

    fn terminalInvokeOperationFromPayload(self: *Session, obj: std.json.ObjectMap) ?TerminalInvokeOp {
        _ = self;
        if (obj.get("op")) |value| {
            if (value == .string) return parseTerminalInvokeOp(value.string);
        }
        if (obj.get("operation")) |value| {
            if (value == .string) return parseTerminalInvokeOp(value.string);
        }
        if (obj.get("tool_name")) |value| {
            if (value == .string and std.mem.eql(u8, value.string, "shell_exec")) return .exec;
        }
        if (obj.get("tool")) |value| {
            if (value == .string and std.mem.eql(u8, value.string, "shell_exec")) return .exec;
        }
        if (obj.get("command") != null or obj.get("argv") != null) return .exec;
        if (obj.get("arguments")) |value| {
            if (value == .object) {
                if (value.object.get("command") != null or value.object.get("argv") != null) return .exec;
            }
        }
        if (obj.get("args")) |value| {
            if (value == .object) {
                if (value.object.get("command") != null or value.object.get("argv") != null) return .exec;
            }
        }
        return null;
    }

    fn updateTerminalV2StatusAndResult(
        self: *Session,
        state: []const u8,
        tool_name: []const u8,
        session_id: ?[]const u8,
        error_message: ?[]const u8,
        operation: []const u8,
        result_json: []const u8,
    ) !void {
        const status = try self.buildTerminalV2StatusJson(state, tool_name, session_id, error_message);
        defer self.allocator.free(status);
        try self.setFileContent(self.terminal_status_id, status);

        const result = try self.buildTerminalV2ResultEnvelope(operation, session_id, error_message == null, result_json, error_message);
        defer self.allocator.free(result);
        try self.setFileContent(self.terminal_result_id, result);
    }

    fn buildTerminalV2StatusJson(
        self: *Session,
        state: []const u8,
        tool_name: []const u8,
        session_id: ?[]const u8,
        error_message: ?[]const u8,
    ) ![]u8 {
        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const escaped_tool = try unified.jsonEscape(self.allocator, tool_name);
        defer self.allocator.free(escaped_tool);
        const session_json = if (session_id) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(session_json);
        const error_json = if (error_message) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(error_json);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"state\":\"{s}\",\"tool\":\"{s}\",\"session_id\":{s},\"updated_at_ms\":{d},\"error\":{s}}}",
            .{ escaped_state, escaped_tool, session_json, std.time.milliTimestamp(), error_json },
        );
    }

    fn buildTerminalV2ResultEnvelope(
        self: *Session,
        operation: []const u8,
        session_id: ?[]const u8,
        ok: bool,
        result_json: []const u8,
        error_message: ?[]const u8,
    ) ![]u8 {
        const escaped_op = try unified.jsonEscape(self.allocator, operation);
        defer self.allocator.free(escaped_op);
        const session_json = if (session_id) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(session_json);

        const error_json = if (error_message) |message| blk: {
            const escaped = try unified.jsonEscape(self.allocator, message);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"code\":\"terminal_v2\",\"message\":\"{s}\"}}",
                .{escaped},
            );
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(error_json);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":{s},\"operation\":\"{s}\",\"session_id\":{s},\"result\":{s},\"error\":{s}}}",
            .{
                if (ok) "true" else "false",
                escaped_op,
                session_json,
                result_json,
                error_json,
            },
        );
    }

    fn refreshTerminalV2StateFiles(self: *Session) !void {
        if (self.terminal_sessions_id == 0 or self.terminal_current_id == 0) return;
        const sessions_json = try self.buildTerminalSessionsJson();
        defer self.allocator.free(sessions_json);
        try self.setFileContent(self.terminal_sessions_id, sessions_json);

        const current_json = try self.buildTerminalCurrentJson();
        defer self.allocator.free(current_json);
        try self.setFileContent(self.terminal_current_id, current_json);
    }

    fn buildTerminalSessionsJson(self: *Session) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"sessions\":[");
        var first = true;
        var it = self.terminal_sessions.iterator();
        while (it.next()) |entry| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            const session_id = entry.key_ptr.*;
            const session = entry.value_ptr.*;
            const escaped_id = try unified.jsonEscape(self.allocator, session_id);
            defer self.allocator.free(escaped_id);
            const state = if (session.isClosed()) "closed" else "open";
            const escaped_state = try unified.jsonEscape(self.allocator, state);
            defer self.allocator.free(escaped_state);
            const label_json = if (session.label) |value| blk: {
                const escaped = try unified.jsonEscape(self.allocator, value);
                defer self.allocator.free(escaped);
                break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(label_json);
            const cwd_json = if (session.cwd) |value| blk: {
                const escaped = try unified.jsonEscape(self.allocator, value);
                defer self.allocator.free(escaped);
                break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(cwd_json);
            try out.writer(self.allocator).print(
                "{{\"session_id\":\"{s}\",\"state\":\"{s}\",\"label\":{s},\"cwd\":{s},\"created_at_ms\":{d},\"updated_at_ms\":{d},\"last_exec_at_ms\":{d},\"closed_at_ms\":{d},\"exec_count\":{d}}}",
                .{
                    escaped_id,
                    escaped_state,
                    label_json,
                    cwd_json,
                    session.created_at_ms,
                    session.updated_at_ms,
                    session.last_exec_at_ms,
                    session.closed_at_ms,
                    session.exec_count,
                },
            );
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    fn buildTerminalCurrentJson(self: *Session) ![]u8 {
        if (self.current_terminal_session_id == null) return self.allocator.dupe(u8, "{\"session\":null}");
        const session_id = self.current_terminal_session_id.?;
        const session = self.terminal_sessions.get(session_id) orelse return self.allocator.dupe(u8, "{\"session\":null}");
        const escaped_id = try unified.jsonEscape(self.allocator, session_id);
        defer self.allocator.free(escaped_id);
        const state = if (session.isClosed()) "closed" else "open";
        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const cwd_json = if (session.cwd) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(cwd_json);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"session\":{{\"session_id\":\"{s}\",\"state\":\"{s}\",\"cwd\":{s},\"updated_at_ms\":{d}}}}}",
            .{ escaped_id, escaped_state, cwd_json, session.updated_at_ms },
        );
    }

    fn setCurrentTerminalSession(self: *Session, session_id: ?[]const u8) !void {
        if (self.current_terminal_session_id) |existing| self.allocator.free(existing);
        self.current_terminal_session_id = if (session_id) |value|
            try self.allocator.dupe(u8, value)
        else
            null;
    }

    fn generateTerminalSessionId(self: *Session) ![]u8 {
        const id = try std.fmt.allocPrint(self.allocator, "term-{d}", .{self.next_terminal_session_seq});
        self.next_terminal_session_seq +%= 1;
        if (self.next_terminal_session_seq == 0) self.next_terminal_session_seq = 1;
        return id;
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
            "{{\"version\":\"acheron-namespace-project-contract-v2\",\"project_id\":\"{s}\",\"top_level_roots\":[\"/nodes\",\"/agents\",\"/global\"],\"project_metadata_files\":[\"topology.json\",\"nodes.json\",\"agents.json\",\"sources.json\",\"contracts.json\",\"paths.json\",\"summary.json\",\"alerts.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"],\"links\":{{\"nodes_root\":\"/nodes\",\"agents_root\":\"/agents\",\"global_root\":\"/global\",\"project_control\":\"/global/projects\",\"workspace_status\":\"/global/projects/control/invoke.json\"}}}}",
            .{escaped_project_id},
        );
    }

    fn buildProjectPathsJson(self: *Session, policy: workspace_policy.WorkspacePolicy) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project_id);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"nodes_root\":\"/nodes\",\"agents_root\":\"/agents\",\"global\":{{\"root\":\"/global\",\"library\":\"/global/library\",\"projects\":\"/global/projects\",\"chat\":\"/global/chat\",\"jobs\":\"/global/jobs\",\"mounts\":\"/global/mounts\",\"debug\":{s}}}}}",
            .{
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
            "{{\"project_id\":\"{s}\",\"workspace_status\":\"{s}\",\"project_fs\":\"{s}\",\"project_nodes\":\"{s}\",\"nodes_meta\":\"{s}\"}}",
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
            "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"source\":\"policy\",\"workspace_root\":null,\"mounts\":[],\"desired_mounts\":[],\"actual_mounts\":[],\"drift\":{{\"count\":0,\"items\":[]}},\"availability\":{{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0}},\"reconcile_state\":\"unknown\",\"last_reconcile_ms\":0,\"last_success_ms\":0,\"last_error\":null,\"queue_depth\":0}}",
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

    fn canInvokeVenomDirectory(self: *Session, venom_dir_id: u32) bool {
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
            "{\"kind\":\"collection\",\"entries\":\"venom_id\",\"shape\":\"/nodes/<node_id>/venoms/<venom_id>/{SCHEMA.json,STATUS.json,CAPS.json,MOUNTS.json,OPS.json,RUNTIME.json,PERMISSIONS.json}\"}",
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
        _ = try self.addFile(venom_dir, "PERMISSIONS.json", permissions_json, false, .none);

        const status = try std.fmt.allocPrint(
            self.allocator,
            "{{\"venom_id\":\"{s}\",\"kind\":\"{s}\",\"state\":\"{s}\",\"endpoint\":\"{s}\"}}",
            .{ escaped_venom_id, escaped_kind, escaped_state, escaped_endpoint },
        );
        defer self.allocator.free(status);
        _ = try self.addFile(venom_dir, "STATUS.json", status, false, .none);
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

    fn addDir(self: *Session, parent: ?u32, name: []const u8, writable: bool) !u32 {
        return self.addNode(parent, name, .dir, "", writable, .none);
    }

    fn addFile(self: *Session, parent: u32, name: []const u8, content: []const u8, writable: bool, special: SpecialKind) !u32 {
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

    fn lookupChild(self: *Session, parent_id: u32, name: []const u8) ?u32 {
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

    fn resolveAbsolutePathNoBinds(self: *Session, path: []const u8) ?u32 {
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

    fn writeFileContent(self: *Session, node_id: u32, offset: u64, data: []const u8) !void {
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

    fn setFileContent(self: *Session, node_id: u32, data: []const u8) !void {
        const node_ptr = self.nodes.getPtr(node_id) orelse return error.MissingNode;
        if (node_ptr.kind != .file) return error.NotFile;
        self.allocator.free(node_ptr.content);
        node_ptr.content = try self.allocator.dupe(u8, data);
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
        return std.fmt.allocPrint(self.allocator, "/global/jobs/{s}/result.txt", .{job_id});
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
        )) orelse return null;
        defer provider.deinit(self.allocator);

        const node_payload_req = try std.fmt.allocPrint(self.allocator, "{{\"node_id\":\"{s}\"}}", .{provider.node_id});
        defer self.allocator.free(node_payload_req);
        const node_payload = plane.getNode(node_payload_req) catch return null;
        defer self.allocator.free(node_payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, node_payload, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const fs_url_val = parsed.value.object.get("fs_url") orelse return null;
        if (fs_url_val != .string or fs_url_val.string.len == 0) return null;

        return try acheron_router.Router.init(self.allocator, &[_]acheron_router.EndpointConfig{.{
            .name = provider.node_id,
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
        return self.registerBoundVenomAliasOnly("/global", "fs", "global_binding", preferred_node_id);
    }

    fn registerBoundVenomAliasOnly(
        self: *Session,
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

    const SearchNamespace = enum {
        web_search,
        search_code,
    };

    const SearchRequest = struct {
        tool_name: []const u8,
        args_json: []u8,

        fn deinit(self: *SearchRequest, allocator: std.mem.Allocator) void {
            allocator.free(self.args_json);
            self.* = undefined;
        }
    };

    fn handleSearchNamespaceWrite(
        self: *Session,
        special: SpecialKind,
        node_id: u32,
        raw_input: []const u8,
    ) !WriteOutcome {
        const invoke_node = self.nodes.get(node_id) orelse return error.MissingNode;
        const control_dir_id = invoke_node.parent orelse return error.MissingNode;
        const venom_dir_id = (self.nodes.get(control_dir_id) orelse return error.MissingNode).parent orelse return error.MissingNode;
        if (!self.canInvokeVenomDirectory(venom_dir_id)) return error.AccessDenied;
        const status_runtime_id = self.lookupChild(venom_dir_id, "status.json") orelse return error.MissingNode;
        const result_id = self.lookupChild(venom_dir_id, "result.json") orelse return error.MissingNode;

        var request = self.parseSearchRequest(special, invoke_node.name, raw_input) catch return error.InvalidPayload;
        defer request.deinit(self.allocator);

        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        try self.setFileContent(node_id, input);

        const running_status = try self.buildServiceInvokeStatusJson("running", request.tool_name, null);
        defer self.allocator.free(running_status);
        try self.setFileContent(status_runtime_id, running_status);

        const result_payload = try self.executeServiceToolCall(request.tool_name, request.args_json);
        defer self.allocator.free(result_payload);
        if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
            defer self.allocator.free(message);
            const status = try self.buildServiceInvokeStatusJson("failed", request.tool_name, message);
            defer self.allocator.free(status);
            try self.setFileContent(status_runtime_id, status);
        } else {
            const status = try self.buildServiceInvokeStatusJson("done", request.tool_name, null);
            defer self.allocator.free(status);
            try self.setFileContent(status_runtime_id, status);
        }
        try self.setFileContent(result_id, result_payload);
        return .{ .written = raw_input.len };
    }

    fn parseSearchRequest(
        self: *Session,
        special: SpecialKind,
        invoke_file_name: []const u8,
        raw_input: []const u8,
    ) !SearchRequest {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const service = searchNamespaceFromSpecial(special) orelse return error.InvalidPayload;
        if (!searchNamespaceMatchesInvokeFile(special, invoke_file_name)) return error.InvalidPayload;

        if (extractOptionalStringByNames(obj, &.{ "op", "operation", "tool", "tool_name" })) |raw_op| {
            if (!isValidSearchNamespaceOperation(service, raw_op)) return error.InvalidPayload;
        }

        const args_json = if (obj.get("arguments")) |value| blk: {
            if (value != .object) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        } else if (obj.get("args")) |value| blk: {
            if (value != .object) return error.InvalidPayload;
            break :blk try self.renderJsonValue(value);
        } else try self.renderJsonValue(parsed.value);

        return .{
            .tool_name = searchNamespaceRuntimeTool(service),
            .args_json = args_json,
        };
    }

    fn searchNamespaceFromSpecial(special: SpecialKind) ?SearchNamespace {
        return switch (special) {
            .web_search_invoke, .web_search_search => .web_search,
            .search_code_invoke, .search_code_search => .search_code,
            else => null,
        };
    }

    fn searchNamespaceMatchesInvokeFile(special: SpecialKind, invoke_file_name: []const u8) bool {
        return switch (special) {
            .web_search_invoke, .search_code_invoke => std.mem.eql(u8, invoke_file_name, "invoke.json"),
            .web_search_search, .search_code_search => std.mem.eql(u8, invoke_file_name, "search.json"),
            else => false,
        };
    }

    fn searchNamespaceRuntimeTool(namespace: SearchNamespace) []const u8 {
        return switch (namespace) {
            .web_search => "web_search",
            .search_code => "search_code",
        };
    }

    fn isValidSearchNamespaceOperation(namespace: SearchNamespace, raw_operation: []const u8) bool {
        const op = std.mem.trim(u8, raw_operation, " \t\r\n");
        return switch (namespace) {
            .web_search => std.mem.eql(u8, op, "search") or std.mem.eql(u8, op, "web_search"),
            .search_code => std.mem.eql(u8, op, "search") or std.mem.eql(u8, op, "search_code"),
        };
    }

    const MemoryOp = enum {
        create,
        load,
        versions,
        mutate,
        evict,
        search,
    };

    fn handleMemoryNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const invoke_node = self.nodes.get(node_id) orelse return error.MissingNode;
        const control_dir_id = invoke_node.parent orelse return error.MissingNode;
        const venom_dir_id = (self.nodes.get(control_dir_id) orelse return error.MissingNode).parent orelse return error.MissingNode;
        if (!self.canInvokeVenomDirectory(venom_dir_id)) return error.AccessDenied;
        const status_runtime_id = self.lookupChild(venom_dir_id, "status.json") orelse return error.MissingNode;
        const result_id = self.lookupChild(venom_dir_id, "result.json") orelse return error.MissingNode;

        const parsed = self.parseMemoryRequest(special, invoke_node.name, raw_input) catch return error.InvalidPayload;
        defer {
            self.allocator.free(parsed.args_json);
        }

        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        try self.setFileContent(node_id, if (input.len == 0) "{}" else input);

        const tool_name = memoryRuntimeTool(parsed.op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        try self.setFileContent(status_runtime_id, running_status);

        const runtime_args = try self.normalizeMemoryArgsForRuntime(parsed.op, parsed.args_json);
        defer self.allocator.free(runtime_args);
        const runtime_payload = try self.executeServiceToolCall(tool_name, runtime_args);
        defer self.allocator.free(runtime_payload);
        const transformed_payload = try self.transformMemoryResultPayload(runtime_payload);
        defer self.allocator.free(transformed_payload);

        if (try self.extractErrorMessageFromToolPayload(transformed_payload)) |message| {
            defer self.allocator.free(message);
            const status = try self.buildServiceInvokeStatusJson("failed", tool_name, message);
            defer self.allocator.free(status);
            try self.setFileContent(status_runtime_id, status);
        } else {
            const status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
            defer self.allocator.free(status);
            try self.setFileContent(status_runtime_id, status);
        }
        try self.setFileContent(result_id, transformed_payload);
        return .{ .written = raw_input.len };
    }

    const MemoryRequest = struct {
        op: MemoryOp,
        args_json: []u8,
    };

    fn parseMemoryRequest(
        self: *Session,
        special: SpecialKind,
        invoke_file_name: []const u8,
        raw_input: []const u8,
    ) !MemoryRequest {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = switch (special) {
            .memory_create => MemoryOp.create,
            .memory_load => MemoryOp.load,
            .memory_versions => MemoryOp.versions,
            .memory_mutate => MemoryOp.mutate,
            .memory_evict => MemoryOp.evict,
            .memory_search => MemoryOp.search,
            .memory_invoke => blk: {
                const op_raw = blk2: {
                    if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    break :blk2 null;
                } orelse return error.InvalidPayload;
                break :blk parseMemoryOp(op_raw) orelse return error.InvalidPayload;
            },
            else => return error.InvalidPayload,
        };

        const args_json = if (obj.get("arguments")) |value|
            try self.renderJsonValue(value)
        else if (obj.get("args")) |value|
            try self.renderJsonValue(value)
        else if (special == .memory_invoke)
            try self.renderJsonValue(parsed.value)
        else
            try self.renderJsonValue(parsed.value);

        _ = invoke_file_name;
        return .{ .op = op, .args_json = args_json };
    }

    fn parseMemoryOp(raw: []const u8) ?MemoryOp {
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, value, "create") or std.mem.eql(u8, value, "memory_create")) return .create;
        if (std.mem.eql(u8, value, "load") or std.mem.eql(u8, value, "memory_load")) return .load;
        if (std.mem.eql(u8, value, "versions") or std.mem.eql(u8, value, "memory_versions")) return .versions;
        if (std.mem.eql(u8, value, "mutate") or std.mem.eql(u8, value, "memory_mutate")) return .mutate;
        if (std.mem.eql(u8, value, "evict") or std.mem.eql(u8, value, "memory_evict")) return .evict;
        if (std.mem.eql(u8, value, "search") or std.mem.eql(u8, value, "memory_search")) return .search;
        return null;
    }

    fn memoryRuntimeTool(op: MemoryOp) []const u8 {
        return switch (op) {
            .create => "memory_create",
            .load => "memory_load",
            .versions => "memory_versions",
            .mutate => "memory_mutate",
            .evict => "memory_evict",
            .search => "memory_search",
        };
    }

    fn memoryOpNeedsMemId(op: MemoryOp) bool {
        return switch (op) {
            .load, .versions, .mutate, .evict => true,
            else => false,
        };
    }

    fn normalizeMemoryArgsForRuntime(self: *Session, op: MemoryOp, args_json: []const u8) ![]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, args_json, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;
        if (!memoryOpNeedsMemId(op)) return self.allocator.dupe(u8, args_json);

        var mem_id: ?[]const u8 = null;
        var mem_id_owned = false;
        if (obj.get("mem_id")) |value| {
            if (value == .string and value.string.len > 0) mem_id = value.string;
        }
        if (mem_id == null) {
            if (obj.get("memory_path")) |value| {
                if (value != .string or value.string.len == 0) return error.InvalidPayload;
                mem_id = try decodeMemIdFromPath(self.allocator, value.string);
                mem_id_owned = true;
            }
        }
        const resolved_mem_id = mem_id orelse return error.InvalidPayload;
        defer if (mem_id_owned) self.allocator.free(resolved_mem_id);

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        const writer = out.writer(self.allocator);
        try writer.writeByte('{');
        var first = true;
        var has_mem_id = false;
        var it = obj.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, "memory_path")) continue;
            if (std.mem.eql(u8, entry.key_ptr.*, "mem_id")) {
                has_mem_id = true;
            }
            if (!first) try writer.writeByte(',');
            first = false;
            try writeJsonString(writer, entry.key_ptr.*);
            try writer.writeByte(':');
            if (std.mem.eql(u8, entry.key_ptr.*, "mem_id")) {
                try writeJsonString(writer, resolved_mem_id);
            } else {
                try self.renderJsonValueToWriter(writer, entry.value_ptr.*);
            }
        }
        if (!has_mem_id) {
            if (!first) try writer.writeByte(',');
            try writer.writeAll("\"mem_id\":");
            try writeJsonString(writer, resolved_mem_id);
        }
        try writer.writeByte('}');
        return out.toOwnedSlice(self.allocator);
    }

    fn transformMemoryResultPayload(self: *Session, runtime_payload: []const u8) ![]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, runtime_payload, .{}) catch {
            return self.allocator.dupe(u8, runtime_payload);
        };
        defer parsed.deinit();
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        const writer = out.writer(self.allocator);
        try self.renderJsonValueWithMemoryPaths(writer, parsed.value);
        return out.toOwnedSlice(self.allocator);
    }

    fn renderJsonValueToWriter(self: *Session, writer: anytype, value: std.json.Value) !void {
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

    fn renderJsonValueWithMemoryPaths(self: *Session, writer: anytype, value: std.json.Value) !void {
        switch (value) {
            .null, .bool, .integer, .float, .number_string, .string => try self.renderJsonValueToWriter(writer, value),
            .array => |arr| {
                try writer.writeByte('[');
                for (arr.items, 0..) |item, idx| {
                    if (idx != 0) try writer.writeByte(',');
                    try self.renderJsonValueWithMemoryPaths(writer, item);
                }
                try writer.writeByte(']');
            },
            .object => |obj| {
                try writer.writeByte('{');
                var first = true;
                var it = obj.iterator();
                while (it.next()) |entry| {
                    if (std.mem.eql(u8, entry.key_ptr.*, "mem_id")) {
                        if (entry.value_ptr.* == .string and entry.value_ptr.*.string.len > 0) {
                            const memory_path = try buildMemoryPathFromMemId(self.allocator, entry.value_ptr.*.string);
                            defer self.allocator.free(memory_path);
                            if (!first) try writer.writeByte(',');
                            first = false;
                            try writer.writeAll("\"memory_path\":");
                            try writeJsonString(writer, memory_path);
                            continue;
                        }
                    }
                    if (!first) try writer.writeByte(',');
                    first = false;
                    try writeJsonString(writer, entry.key_ptr.*);
                    try writer.writeByte(':');
                    try self.renderJsonValueWithMemoryPaths(writer, entry.value_ptr.*);
                }
                try writer.writeByte('}');
            },
        }
    }

    const MountsOp = enum {
        list,
        mount,
        mkdir,
        unmount,
        bind,
        unbind,
        resolve,
    };

    fn handleMountsNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = switch (special) {
            .mounts_list => MountsOp.list,
            .mounts_mount => MountsOp.mount,
            .mounts_mkdir => MountsOp.mkdir,
            .mounts_unmount => MountsOp.unmount,
            .mounts_bind => MountsOp.bind,
            .mounts_unbind => MountsOp.unbind,
            .mounts_resolve => MountsOp.resolve,
            .mounts_invoke => blk: {
                const op_raw = blk2: {
                    if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    break :blk2 null;
                } orelse return error.InvalidPayload;
                break :blk parseMountsOp(op_raw) orelse return error.InvalidPayload;
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
        return self.executeMountsOp(op, args_obj, raw_input.len);
    }

    fn parseMountsOp(raw: []const u8) ?MountsOp {
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, value, "list")) return .list;
        if (std.mem.eql(u8, value, "mount")) return .mount;
        if (std.mem.eql(u8, value, "mkdir") or std.mem.eql(u8, value, "create_folder")) return .mkdir;
        if (std.mem.eql(u8, value, "unmount")) return .unmount;
        if (std.mem.eql(u8, value, "bind")) return .bind;
        if (std.mem.eql(u8, value, "unbind")) return .unbind;
        if (std.mem.eql(u8, value, "resolve")) return .resolve;
        return null;
    }

    const MountProjectScope = struct {
        project_id: []const u8,
        project_token: ?[]const u8,
    };

    fn resolveMountProjectScope(self: *Session, args_obj: std.json.ObjectMap) !MountProjectScope {
        _ = self;
        const project_id_raw = extractOptionalStringByNames(args_obj, &[_][]const u8{"project_id"}) orelse
            return error.InvalidPayload;
        const project_id = std.mem.trim(u8, project_id_raw, " \t\r\n");
        if (project_id.len == 0) return error.InvalidPayload;
        return .{
            .project_id = project_id,
            .project_token = extractOptionalStringByNames(args_obj, &[_][]const u8{"project_token"}),
        };
    }

    fn normalizeLocalFsRelativePath(self: *Session, raw_path: []const u8) ![]u8 {
        var path = std.mem.trim(u8, raw_path, " \t\r\n");
        if (path.len == 0) return error.InvalidPayload;

        if (std.mem.startsWith(u8, path, local_fs_world_prefix)) {
            path = path[local_fs_world_prefix.len..];
            if (path.len == 0) return error.InvalidPayload;
            if (path[0] != '/') return error.InvalidPayload;
            path = path[1..];
        } else if (path[0] == '/') {
            return error.InvalidPayload;
        }

        var normalized = std.ArrayListUnmanaged(u8){};
        errdefer normalized.deinit(self.allocator);

        var token_it = std.mem.tokenizeAny(u8, path, "/\\");
        var first = true;
        while (token_it.next()) |segment| {
            if (segment.len == 0) continue;
            if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return error.InvalidPayload;
            if (std.mem.indexOfScalar(u8, segment, ':') != null) return error.InvalidPayload;
            if (!first) try normalized.append(self.allocator, '/');
            first = false;
            try normalized.appendSlice(self.allocator, segment);
        }

        if (normalized.items.len == 0) return error.InvalidPayload;
        return normalized.toOwnedSlice(self.allocator);
    }

    fn buildLocalFsWorldPath(allocator: std.mem.Allocator, relative_path: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ local_fs_world_prefix, relative_path });
    }

    fn pathExistsAsDirectory(path: []const u8) !bool {
        if (std.fs.path.isAbsolute(path)) {
            var dir = std.fs.openDirAbsolute(path, .{}) catch |err| switch (err) {
                error.FileNotFound => return false,
                else => return err,
            };
            defer dir.close();
            return true;
        }

        var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer dir.close();
        return true;
    }

    fn ensurePathExists(path: []const u8) !void {
        if (path.len == 0) return error.InvalidPath;
        if (std.fs.path.isAbsolute(path)) {
            var root_dir = try std.fs.openDirAbsolute("/", .{});
            defer root_dir.close();
            const rel_path = std.mem.trimLeft(u8, path, "/");
            if (rel_path.len == 0) return;
            try root_dir.makePath(rel_path);
            return;
        }
        try std.fs.cwd().makePath(path);
    }

    fn executeMountsOp(self: *Session, op: MountsOp, args_obj: std.json.ObjectMap, written: usize) !WriteOutcome {
        const status_tool = mountsStatusToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", status_tool, null);
        defer self.allocator.free(running_status);
        if (self.mounts_status_id != 0) try self.setFileContent(self.mounts_status_id, running_status);

        const result_payload = self.executeMountsOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const code = switch (err) {
                error.AccessDenied => "forbidden",
                else => "invalid_payload",
            };
            const failed_status = try self.buildServiceInvokeStatusJson("failed", status_tool, error_message);
            defer self.allocator.free(failed_status);
            if (self.mounts_status_id != 0) try self.setFileContent(self.mounts_status_id, failed_status);
            const failed_result = try self.buildMountsFailureResultJson(op, code, error_message);
            defer self.allocator.free(failed_result);
            if (self.mounts_result_id != 0) try self.setFileContent(self.mounts_result_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        const done_status = try self.buildServiceInvokeStatusJson("done", status_tool, null);
        defer self.allocator.free(done_status);
        if (self.mounts_status_id != 0) try self.setFileContent(self.mounts_status_id, done_status);
        if (self.mounts_result_id != 0) try self.setFileContent(self.mounts_result_id, result_payload);
        return .{ .written = written };
    }

    fn executeMountsOpPayload(self: *Session, op: MountsOp, args_obj: std.json.ObjectMap) ![]u8 {
        const scope = try self.resolveMountProjectScope(args_obj);
        switch (op) {
            .list => return self.buildMountsListResultJson(scope.project_id, scope.project_token),
            .mount => {
                const node_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"node_id"}) orelse return error.InvalidPayload;
                const export_name = extractOptionalStringByNames(args_obj, &[_][]const u8{"export_name"}) orelse return error.InvalidPayload;
                const mount_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"mount_path"}) orelse return error.InvalidPayload;
                const payload = try self.buildProjectScopedMountPayload(scope.project_id, scope.project_token, node_id, export_name, mount_path);
                defer self.allocator.free(payload);
                const plane = self.control_plane orelse return error.InvalidPayload;
                const result = plane.setProjectMountWithRole(payload, self.is_admin) catch |err| switch (err) {
                    control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                    control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                    control_plane_mod.ControlPlaneError.ProjectProtected,
                    control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                    => return error.AccessDenied,
                    control_plane_mod.ControlPlaneError.MissingField,
                    control_plane_mod.ControlPlaneError.InvalidPayload,
                    => return error.InvalidPayload,
                    else => return err,
                };
                defer self.allocator.free(result);
                try self.refreshProjectBindsFromControlPlane();
                return self.buildMountsSuccessResultJson(op, result);
            },
            .unmount => {
                const mount_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"mount_path"}) orelse return error.InvalidPayload;
                const node_id = extractOptionalStringByNames(args_obj, &[_][]const u8{"node_id"});
                const export_name = extractOptionalStringByNames(args_obj, &[_][]const u8{"export_name"});
                const payload = try self.buildProjectScopedUnmountPayload(scope.project_id, scope.project_token, mount_path, node_id, export_name);
                defer self.allocator.free(payload);
                const plane = self.control_plane orelse return error.InvalidPayload;
                const result = plane.removeProjectMountWithRole(payload, self.is_admin) catch |err| switch (err) {
                    control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                    control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                    control_plane_mod.ControlPlaneError.ProjectProtected,
                    control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                    => return error.AccessDenied,
                    control_plane_mod.ControlPlaneError.MissingField,
                    control_plane_mod.ControlPlaneError.InvalidPayload,
                    control_plane_mod.ControlPlaneError.MountNotFound,
                    => return error.InvalidPayload,
                    else => return err,
                };
                defer self.allocator.free(result);
                return self.buildMountsSuccessResultJson(op, result);
            },
            .bind => {
                const bind_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"bind_path"}) orelse return error.InvalidPayload;
                const target_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"target_path"}) orelse return error.InvalidPayload;
                const payload = try self.buildProjectScopedBindPayload(scope.project_id, scope.project_token, bind_path, target_path);
                defer self.allocator.free(payload);
                const plane = self.control_plane orelse return error.InvalidPayload;
                const result = plane.setProjectBindWithRole(payload, self.is_admin) catch |err| switch (err) {
                    control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                    control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                    control_plane_mod.ControlPlaneError.ProjectProtected,
                    control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                    => return error.AccessDenied,
                    control_plane_mod.ControlPlaneError.MissingField,
                    control_plane_mod.ControlPlaneError.InvalidPayload,
                    control_plane_mod.ControlPlaneError.BindConflict,
                    => return error.InvalidPayload,
                    else => return err,
                };
                defer self.allocator.free(result);
                try self.refreshProjectBindsFromControlPlane();
                return self.buildMountsSuccessResultJson(op, result);
            },
            .unbind => {
                const bind_path = extractOptionalStringByNames(args_obj, &[_][]const u8{"bind_path"}) orelse return error.InvalidPayload;
                const payload = try self.buildProjectScopedUnbindPayload(scope.project_id, scope.project_token, bind_path);
                defer self.allocator.free(payload);
                const plane = self.control_plane orelse return error.InvalidPayload;
                const result = plane.removeProjectBindWithRole(payload, self.is_admin) catch |err| switch (err) {
                    control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                    control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                    control_plane_mod.ControlPlaneError.ProjectProtected,
                    control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                    => return error.AccessDenied,
                    control_plane_mod.ControlPlaneError.MissingField,
                    control_plane_mod.ControlPlaneError.InvalidPayload,
                    control_plane_mod.ControlPlaneError.BindNotFound,
                    => return error.InvalidPayload,
                    else => return err,
                };
                defer self.allocator.free(result);
                try self.refreshProjectBindsFromControlPlane();
                return self.buildMountsSuccessResultJson(op, result);
            },
            .mkdir => {
                const plane = self.control_plane orelse return error.InvalidPayload;
                if (!plane.projectAllowsAction(scope.project_id, self.agent_id, .mount, scope.project_token, self.is_admin)) {
                    return error.AccessDenied;
                }
                const path = extractOptionalStringByNames(args_obj, &[_][]const u8{ "path", "folder", "relative_path" }) orelse return error.InvalidPayload;
                const local_root = self.local_fs_export_root orelse return error.InvalidPayload;
                const relative_path = try self.normalizeLocalFsRelativePath(path);
                defer self.allocator.free(relative_path);
                const host_path = try std.fs.path.join(self.allocator, &.{ local_root, relative_path });
                defer self.allocator.free(host_path);

                const exists_before = pathExistsAsDirectory(host_path) catch |err| switch (err) {
                    error.NotDir => return error.InvalidPayload,
                    else => return err,
                };
                if (!exists_before) {
                    ensurePathExists(host_path) catch |err| switch (err) {
                        error.PathAlreadyExists,
                        error.NotDir,
                        error.AccessDenied,
                        => return error.InvalidPayload,
                        else => return err,
                    };
                }

                const world_path = try buildLocalFsWorldPath(self.allocator, relative_path);
                defer self.allocator.free(world_path);
                const escaped_world_path = try unified.jsonEscape(self.allocator, world_path);
                defer self.allocator.free(escaped_world_path);
                const detail = try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"path\":\"{s}\",\"created\":{}}}",
                    .{ escaped_world_path, !exists_before },
                );
                defer self.allocator.free(detail);
                return self.buildMountsSuccessResultJson(op, detail);
            },
            .resolve => {
                const path = extractOptionalStringByNames(args_obj, &[_][]const u8{ "path", "mount_path", "bind_path" }) orelse return error.InvalidPayload;
                const payload = try self.buildProjectScopedResolvePayload(scope.project_id, scope.project_token, path);
                defer self.allocator.free(payload);
                const plane = self.control_plane orelse return error.InvalidPayload;
                const result = plane.resolveProjectPathWithRole(payload, self.is_admin) catch |err| switch (err) {
                    control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                    control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                    control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                    => return error.AccessDenied,
                    control_plane_mod.ControlPlaneError.MissingField,
                    control_plane_mod.ControlPlaneError.InvalidPayload,
                    => return error.InvalidPayload,
                    else => return err,
                };
                defer self.allocator.free(result);
                return self.buildMountsSuccessResultJson(op, result);
            },
        }
    }

    fn buildProjectScopedMountPayload(
        self: *Session,
        project_id: []const u8,
        project_token: ?[]const u8,
        node_id: []const u8,
        export_name: []const u8,
        mount_path: []const u8,
    ) ![]u8 {
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_node = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node);
        const escaped_export = try unified.jsonEscape(self.allocator, export_name);
        defer self.allocator.free(escaped_export);
        const escaped_path = try unified.jsonEscape(self.allocator, mount_path);
        defer self.allocator.free(escaped_path);
        const token_fragment = if (project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(token_fragment);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",{s}\"node_id\":\"{s}\",\"export_name\":\"{s}\",\"mount_path\":\"{s}\"}}",
            .{ escaped_project, token_fragment, escaped_node, escaped_export, escaped_path },
        );
    }

    fn buildProjectScopedBindPayload(self: *Session, project_id: []const u8, project_token: ?[]const u8, bind_path: []const u8, target_path: []const u8) ![]u8 {
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_bind = try unified.jsonEscape(self.allocator, bind_path);
        defer self.allocator.free(escaped_bind);
        const escaped_target = try unified.jsonEscape(self.allocator, target_path);
        defer self.allocator.free(escaped_target);
        const token_fragment = if (project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(token_fragment);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",{s}\"bind_path\":\"{s}\",\"target_path\":\"{s}\"}}",
            .{ escaped_project, token_fragment, escaped_bind, escaped_target },
        );
    }

    fn buildProjectScopedUnbindPayload(self: *Session, project_id: []const u8, project_token: ?[]const u8, bind_path: []const u8) ![]u8 {
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_bind = try unified.jsonEscape(self.allocator, bind_path);
        defer self.allocator.free(escaped_bind);
        const token_fragment = if (project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(token_fragment);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",{s}\"bind_path\":\"{s}\"}}",
            .{ escaped_project, token_fragment, escaped_bind },
        );
    }

    fn buildProjectScopedResolvePayload(self: *Session, project_id: []const u8, project_token: ?[]const u8, path: []const u8) ![]u8 {
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_path = try unified.jsonEscape(self.allocator, path);
        defer self.allocator.free(escaped_path);
        const token_fragment = if (project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(token_fragment);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",{s}\"path\":\"{s}\"}}",
            .{ escaped_project, token_fragment, escaped_path },
        );
    }

    fn buildProjectScopedUnmountPayload(
        self: *Session,
        project_id: []const u8,
        project_token: ?[]const u8,
        mount_path: []const u8,
        node_id: ?[]const u8,
        export_name: ?[]const u8,
    ) ![]u8 {
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_mount = try unified.jsonEscape(self.allocator, mount_path);
        defer self.allocator.free(escaped_mount);
        const token_fragment = if (project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(self.allocator, "\"project_token\":\"{s}\",", .{escaped_token});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(token_fragment);
        const node_fragment = if (node_id) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, ",\"node_id\":\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(node_fragment);
        const export_fragment = if (export_name) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, ",\"export_name\":\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(export_fragment);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",{s}\"mount_path\":\"{s}\"{s}{s}}}",
            .{ escaped_project, token_fragment, escaped_mount, node_fragment, export_fragment },
        );
    }

    fn buildMountsSuccessResultJson(self: *Session, op: MountsOp, detail_json: []const u8) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, mountsOperationName(op));
        defer self.allocator.free(escaped_operation);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
            .{ escaped_operation, detail_json },
        );
    }

    fn buildMountsFailureResultJson(self: *Session, op: MountsOp, code: []const u8, message: []const u8) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, mountsOperationName(op));
        defer self.allocator.free(escaped_operation);
        const escaped_code = try unified.jsonEscape(self.allocator, code);
        defer self.allocator.free(escaped_code);
        const escaped_message = try unified.jsonEscape(self.allocator, message);
        defer self.allocator.free(escaped_message);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":false,\"operation\":\"{s}\",\"result\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ escaped_operation, escaped_code, escaped_message },
        );
    }

    fn mountsOperationName(op: MountsOp) []const u8 {
        return switch (op) {
            .list => "list",
            .mount => "mount",
            .mkdir => "mkdir",
            .unmount => "unmount",
            .bind => "bind",
            .unbind => "unbind",
            .resolve => "resolve",
        };
    }

    fn mountsStatusToolName(op: MountsOp) []const u8 {
        return switch (op) {
            .list => "mounts_list",
            .mount => "mounts_mount",
            .mkdir => "mounts_mkdir",
            .unmount => "mounts_unmount",
            .bind => "mounts_bind",
            .unbind => "mounts_unbind",
            .resolve => "mounts_resolve",
        };
    }

    fn buildMountsListResultJson(self: *Session, project_id_override: ?[]const u8, project_token_override: ?[]const u8) ![]u8 {
        const plane = self.control_plane orelse return self.buildMountsSuccessResultJson(.list, "{\"project_id\":null,\"mounts\":[],\"binds\":[]}");
        const project_id = project_id_override orelse self.project_id orelse return self.buildMountsSuccessResultJson(.list, "{\"project_id\":null,\"mounts\":[],\"binds\":[]}");
        const project_token = if (project_token_override) |value| value else self.project_token;
        const escaped_project = try unified.jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const payload = if (project_token) |token| blk: {
            const escaped_token = try unified.jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
                .{ escaped_project, escaped_token },
            );
        } else try std.fmt.allocPrint(self.allocator, "{{\"project_id\":\"{s}\"}}", .{escaped_project});
        defer self.allocator.free(payload);

        const mounts_json = plane.listProjectMountsWithRole(payload, self.is_admin) catch |err| switch (err) {
            control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
            control_plane_mod.ControlPlaneError.ProjectAuthFailed,
            control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
            => return error.AccessDenied,
            else => return err,
        };
        defer self.allocator.free(mounts_json);
        const binds_json = plane.listProjectBindsWithRole(payload, self.is_admin) catch |err| switch (err) {
            control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
            control_plane_mod.ControlPlaneError.ProjectAuthFailed,
            control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
            => return error.AccessDenied,
            else => return err,
        };
        defer self.allocator.free(binds_json);

        const mounts_array = try extractObjectArrayJson(self.allocator, mounts_json, "mounts");
        defer self.allocator.free(mounts_array);
        const binds_array = try extractObjectArrayJson(self.allocator, binds_json, "binds");
        defer self.allocator.free(binds_array);
        const result_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"mounts\":{s},\"binds\":{s}}}",
            .{ escaped_project, mounts_array, binds_array },
        );
        defer self.allocator.free(result_json);
        return self.buildMountsSuccessResultJson(.list, result_json);
    }

    fn extractObjectArrayJson(allocator: std.mem.Allocator, json_text: []const u8, field_name: []const u8) ![]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch {
            return allocator.dupe(u8, "[]");
        };
        defer parsed.deinit();
        if (parsed.value != .object) return allocator.dupe(u8, "[]");
        const field = parsed.value.object.get(field_name) orelse return allocator.dupe(u8, "[]");
        if (field != .array) return allocator.dupe(u8, "[]");
        return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(field, .{})});
    }

    const SubBrainOp = enum {
        list,
        upsert,
        delete,
    };

    fn handleSubBrainsInvokeWrite(self: *Session, invoke_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(invoke_node_id, input);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op_raw = blk: {
            if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            break :blk null;
        } orelse return error.InvalidPayload;
        const op = parseSubBrainOp(op_raw) orelse return error.InvalidPayload;

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
        return self.executeSubBrainOp(op, args_obj, raw_input.len);
    }

    fn handleSubBrainsListWrite(self: *Session, list_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(list_node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        return self.executeSubBrainOp(.list, parsed.value.object, raw_input.len);
    }

    fn handleSubBrainsUpsertWrite(self: *Session, upsert_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(upsert_node_id, input);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        return self.executeSubBrainOp(.upsert, parsed.value.object, raw_input.len);
    }

    fn handleSubBrainsDeleteWrite(self: *Session, delete_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(delete_node_id, input);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        return self.executeSubBrainOp(.delete, parsed.value.object, raw_input.len);
    }

    fn executeSubBrainOp(
        self: *Session,
        op: SubBrainOp,
        args_obj: std.json.ObjectMap,
        written: usize,
    ) !WriteOutcome {
        const tool_name = subBrainToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        if (self.sub_brains_status_id != 0) try self.setFileContent(self.sub_brains_status_id, running_status);

        const result_payload = self.executeSubBrainOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const error_code = switch (err) {
                error.AccessDenied => "forbidden",
                else => "invalid_payload",
            };
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
            defer self.allocator.free(failed_status);
            if (self.sub_brains_status_id != 0) try self.setFileContent(self.sub_brains_status_id, failed_status);
            const failed_result = try self.buildSubBrainFailureResultJson(op, error_code, error_message);
            defer self.allocator.free(failed_result);
            if (self.sub_brains_result_id != 0) try self.setFileContent(self.sub_brains_result_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
        defer self.allocator.free(done_status);
        if (self.sub_brains_status_id != 0) try self.setFileContent(self.sub_brains_status_id, done_status);
        if (self.sub_brains_result_id != 0) try self.setFileContent(self.sub_brains_result_id, result_payload);
        return .{ .written = written };
    }

    fn executeSubBrainOpPayload(self: *Session, op: SubBrainOp, args_obj: std.json.ObjectMap) ![]u8 {
        return switch (op) {
            .list => self.executeSubBrainListOp(),
            .upsert => self.executeSubBrainUpsertOp(args_obj),
            .delete => self.executeSubBrainDeleteOp(args_obj),
        };
    }

    fn executeSubBrainListOp(self: *Session) ![]u8 {
        var config = try self.loadOrInitSelfAgentConfig();
        defer config.deinit();
        const inventory = try self.buildSubBrainInventoryJson(&config);
        defer self.allocator.free(inventory);
        return self.buildSubBrainSuccessResultJson(.list, inventory);
    }

    fn executeSubBrainUpsertOp(self: *Session, args_obj: std.json.ObjectMap) ![]u8 {
        if (!self.canManageSubBrains()) return error.AccessDenied;
        const brain_name = extractSubBrainName(args_obj) orelse return error.InvalidPayload;
        if (std.mem.eql(u8, brain_name, "primary")) return error.InvalidPayload;

        const config_obj = blk: {
            if (args_obj.get("config")) |value| {
                if (value != .object) return error.InvalidPayload;
                break :blk value.object;
            }
            break :blk args_obj;
        };

        var new_sub = try self.parseSubBrainConfigFromObject(config_obj);
        var new_sub_owned = true;
        errdefer if (new_sub_owned) new_sub.deinit(self.allocator);

        var config = try self.loadOrInitSelfAgentConfig();
        defer config.deinit();

        if (config.sub_brains.getPtr(brain_name)) |existing| {
            existing.deinit(self.allocator);
            existing.* = new_sub;
            new_sub_owned = false;
        } else {
            const key = try self.allocator.dupe(u8, brain_name);
            errdefer self.allocator.free(key);
            try config.sub_brains.put(self.allocator, key, new_sub);
            new_sub_owned = false;
        }

        try std.fs.cwd().makePath(self.agents_dir);
        try agent_config.saveAgentConfig(self.allocator, self.agents_dir, self.agent_id, &config);

        const inventory = try self.buildSubBrainInventoryJson(&config);
        defer self.allocator.free(inventory);
        const escaped_brain = try unified.jsonEscape(self.allocator, brain_name);
        defer self.allocator.free(escaped_brain);
        const detail = try std.fmt.allocPrint(
            self.allocator,
            "{{\"brain_name\":\"{s}\",\"updated\":true,\"inventory\":{s}}}",
            .{ escaped_brain, inventory },
        );
        defer self.allocator.free(detail);
        return self.buildSubBrainSuccessResultJson(.upsert, detail);
    }

    fn executeSubBrainDeleteOp(self: *Session, args_obj: std.json.ObjectMap) ![]u8 {
        if (!self.canManageSubBrains()) return error.AccessDenied;
        const brain_name = extractSubBrainName(args_obj) orelse return error.InvalidPayload;
        if (std.mem.eql(u8, brain_name, "primary")) return error.InvalidPayload;

        var config = try self.loadOrInitSelfAgentConfig();
        defer config.deinit();

        var removed = false;
        if (config.sub_brains.fetchRemove(brain_name)) |entry| {
            self.allocator.free(entry.key);
            var value = entry.value;
            value.deinit(self.allocator);
            removed = true;
        }

        try std.fs.cwd().makePath(self.agents_dir);
        try agent_config.saveAgentConfig(self.allocator, self.agents_dir, self.agent_id, &config);

        const inventory = try self.buildSubBrainInventoryJson(&config);
        defer self.allocator.free(inventory);
        const escaped_brain = try unified.jsonEscape(self.allocator, brain_name);
        defer self.allocator.free(escaped_brain);
        const detail = try std.fmt.allocPrint(
            self.allocator,
            "{{\"brain_name\":\"{s}\",\"removed\":{},\"inventory\":{s}}}",
            .{ escaped_brain, removed, inventory },
        );
        defer self.allocator.free(detail);
        return self.buildSubBrainSuccessResultJson(.delete, detail);
    }

    const AgentOp = enum {
        list,
        create,
    };

    fn handleAgentsInvokeWrite(self: *Session, invoke_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(invoke_node_id, input);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op_raw = blk: {
            if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            break :blk null;
        } orelse return error.InvalidPayload;
        const op = parseAgentOp(op_raw) orelse return error.InvalidPayload;

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
        return self.executeAgentOp(op, args_obj, raw_input.len);
    }

    fn handleAgentsListWrite(self: *Session, list_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(list_node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        return self.executeAgentOp(.list, parsed.value.object, raw_input.len);
    }

    fn handleAgentsCreateWrite(self: *Session, create_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;
        try self.setFileContent(create_node_id, input);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        return self.executeAgentOp(.create, parsed.value.object, raw_input.len);
    }

    fn executeAgentOp(
        self: *Session,
        op: AgentOp,
        args_obj: std.json.ObjectMap,
        written: usize,
    ) !WriteOutcome {
        const tool_name = agentToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        if (self.agents_status_id != 0) try self.setFileContent(self.agents_status_id, running_status);

        const result_payload = self.executeAgentOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const error_code = switch (err) {
                error.AccessDenied => "forbidden",
                error.AlreadyExists => "already_exists",
                error.InvalidAgentId => "invalid_agent_id",
                else => "invalid_payload",
            };
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
            defer self.allocator.free(failed_status);
            if (self.agents_status_id != 0) try self.setFileContent(self.agents_status_id, failed_status);
            const failed_result = try self.buildAgentFailureResultJson(op, error_code, error_message);
            defer self.allocator.free(failed_result);
            if (self.agents_result_id != 0) try self.setFileContent(self.agents_result_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
        defer self.allocator.free(done_status);
        if (self.agents_status_id != 0) try self.setFileContent(self.agents_status_id, done_status);
        if (self.agents_result_id != 0) try self.setFileContent(self.agents_result_id, result_payload);
        return .{ .written = written };
    }

    fn executeAgentOpPayload(self: *Session, op: AgentOp, args_obj: std.json.ObjectMap) ![]u8 {
        return switch (op) {
            .list => self.executeAgentListOp(),
            .create => self.executeAgentCreateOp(args_obj),
        };
    }

    fn executeAgentListOp(self: *Session) ![]u8 {
        const inventory = try self.buildAgentInventoryJson();
        defer self.allocator.free(inventory);
        return self.buildAgentSuccessResultJson(.list, inventory);
    }

    fn executeAgentCreateOp(self: *Session, args_obj: std.json.ObjectMap) ![]u8 {
        if (!self.canCreateAgents()) return error.AccessDenied;
        const new_agent_id = extractAgentId(args_obj) orelse return error.InvalidPayload;
        if (!isValidManagedAgentId(new_agent_id)) return error.InvalidAgentId;
        if (std.mem.eql(u8, new_agent_id, "self")) return error.InvalidAgentId;

        const template_path = extractOptionalStringByNames(args_obj, &.{ "template_path", "template" });
        const desired_project_id = extractOptionalStringByNames(args_obj, &.{"project_id"});
        const desired_project_token = extractOptionalStringByNames(args_obj, &.{"project_token"});

        var registry = agent_registry.AgentRegistry.init(
            self.allocator,
            ".",
            self.agents_dir,
            self.assets_dir,
        );
        defer registry.deinit();
        try registry.scan();
        if (registry.getAgent(new_agent_id) != null) return error.AlreadyExists;
        try registry.createAgent(new_agent_id, template_path);

        const metadata_written = try self.maybeWriteAgentMetadataFile(new_agent_id, args_obj);
        var activated = false;
        var activation_error: ?[]u8 = null;
        defer if (activation_error) |value| self.allocator.free(value);

        if (desired_project_id) |project_id| {
            if (self.control_plane) |plane| {
                const activation_payload = try buildAgentProjectActivationPayload(self.allocator, project_id, desired_project_token);
                defer self.allocator.free(activation_payload);
                const activation_result = plane.activateProjectWithRole(new_agent_id, activation_payload, self.is_admin) catch |err| blk: {
                    activation_error = try self.allocator.dupe(u8, @errorName(err));
                    break :blk null;
                };
                if (activation_result) |payload| {
                    defer plane.allocator.free(payload);
                    activated = true;
                }
            } else {
                activation_error = try self.allocator.dupe(u8, "ControlPlaneUnavailable");
            }
        }

        const inventory = try self.buildAgentInventoryJson();
        defer self.allocator.free(inventory);
        const escaped_agent = try unified.jsonEscape(self.allocator, new_agent_id);
        defer self.allocator.free(escaped_agent);
        const project_json = if (desired_project_id) |project_id| blk: {
            const escaped = try unified.jsonEscape(self.allocator, project_id);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(project_json);
        const activation_error_json = if (activation_error) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(activation_error_json);
        const detail = try std.fmt.allocPrint(
            self.allocator,
            "{{\"agent_id\":\"{s}\",\"created\":true,\"metadata_updated\":{},\"project_id\":{s},\"activated\":{},\"activation_error\":{s},\"inventory\":{s}}}",
            .{ escaped_agent, metadata_written, project_json, activated, activation_error_json, inventory },
        );
        defer self.allocator.free(detail);
        return self.buildAgentSuccessResultJson(.create, detail);
    }

    fn buildAgentProjectActivationPayload(
        allocator: std.mem.Allocator,
        project_id: []const u8,
        project_token: ?[]const u8,
    ) ![]u8 {
        const escaped_project = try unified.jsonEscape(allocator, project_id);
        defer allocator.free(escaped_project);
        if (project_token) |token| {
            const escaped_token = try unified.jsonEscape(allocator, token);
            defer allocator.free(escaped_token);
            return std.fmt.allocPrint(
                allocator,
                "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
                .{ escaped_project, escaped_token },
            );
        }
        return std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\"}}",
            .{escaped_project},
        );
    }

    fn buildAgentListResultJson(self: *Session) ![]u8 {
        const inventory = try self.buildAgentInventoryJson();
        defer self.allocator.free(inventory);
        return self.buildAgentSuccessResultJson(.list, inventory);
    }

    fn buildAgentInventoryJson(self: *Session) ![]u8 {
        const create_allowed = self.canCreateAgents();
        var registry = agent_registry.AgentRegistry.init(
            self.allocator,
            ".",
            self.agents_dir,
            self.assets_dir,
        );
        defer registry.deinit();
        try registry.scan();

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        const writer = out.writer(self.allocator);

        try writer.writeAll("{\"agents\":[");
        const agents = registry.listAgents();
        for (agents, 0..) |agent, idx| {
            if (idx > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try writer.writeAll("\"agent_id\":");
            try writeJsonString(writer, agent.id);
            try writer.writeAll(",\"name\":");
            try writeJsonString(writer, agent.name);
            try writer.writeAll(",\"description\":");
            try writeJsonString(writer, agent.description);
            try writer.writeAll(",\"is_default\":");
            try writer.print("{}", .{agent.is_default});
            try writer.writeAll(",\"identity_loaded\":");
            try writer.print("{}", .{agent.identity_loaded});
            try writer.writeAll(",\"needs_hatching\":");
            try writer.print("{}", .{agent.needs_hatching});
            try writer.writeAll(",\"capabilities\":[");
            for (agent.capabilities.items, 0..) |capability, cap_idx| {
                if (cap_idx > 0) try writer.writeByte(',');
                try writeJsonString(writer, managedAgentCapabilityName(capability));
            }
            try writer.writeAll("]}");
        }
        try writer.print("],\"count\":{d},\"create_allowed\":{}}}", .{ agents.len, create_allowed });
        return out.toOwnedSlice(self.allocator);
    }

    fn buildAgentSuccessResultJson(self: *Session, op: AgentOp, result_json: []const u8) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, agentOperationName(op));
        defer self.allocator.free(escaped_operation);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
            .{ escaped_operation, result_json },
        );
    }

    fn buildAgentFailureResultJson(
        self: *Session,
        op: AgentOp,
        code: []const u8,
        message: []const u8,
    ) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, agentOperationName(op));
        defer self.allocator.free(escaped_operation);
        const escaped_code = try unified.jsonEscape(self.allocator, code);
        defer self.allocator.free(escaped_code);
        const escaped_message = try unified.jsonEscape(self.allocator, message);
        defer self.allocator.free(escaped_message);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":false,\"operation\":\"{s}\",\"result\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ escaped_operation, escaped_code, escaped_message },
        );
    }

    fn maybeWriteAgentMetadataFile(
        self: *Session,
        target_agent_id: []const u8,
        args_obj: std.json.ObjectMap,
    ) !bool {
        const metadata_obj = blk: {
            if (args_obj.get("agent")) |value| {
                if (value != .object) return error.InvalidPayload;
                break :blk value.object;
            }
            break :blk args_obj;
        };

        var name_value: ?[]const u8 = null;
        var description_value: ?[]const u8 = null;
        var has_capabilities = false;
        var capabilities_value: ?std.json.Value = null;

        if (metadata_obj.get("name")) |value| {
            if (value == .string) name_value = value.string else if (value != .null) return error.InvalidPayload;
        }
        if (metadata_obj.get("description")) |value| {
            if (value == .string) description_value = value.string else if (value != .null) return error.InvalidPayload;
        }
        if (metadata_obj.get("capabilities")) |value| {
            if (value == .array) {
                has_capabilities = true;
                for (value.array.items) |entry| {
                    if (entry != .string) return error.InvalidPayload;
                }
                capabilities_value = value;
            } else if (value != .null) {
                return error.InvalidPayload;
            }
        }

        if (name_value == null and description_value == null and !has_capabilities) return false;

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);
        const writer = out.writer(self.allocator);
        try writer.writeByte('{');
        var first = true;

        if (name_value) |value| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writeJsonString(writer, "name");
            try writer.writeByte(':');
            try writeJsonString(writer, value);
        }
        if (description_value) |value| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writeJsonString(writer, "description");
            try writer.writeByte(':');
            try writeJsonString(writer, value);
        }
        if (has_capabilities) {
            if (!first) try writer.writeByte(',');
            try writeJsonString(writer, "capabilities");
            try writer.writeByte(':');
            try writer.writeByte('[');
            if (capabilities_value) |caps_raw| {
                const caps = caps_raw.array;
                for (caps.items, 0..) |entry, idx| {
                    if (idx > 0) try writer.writeByte(',');
                    try writeJsonString(writer, entry.string);
                }
            }
            try writer.writeByte(']');
        }
        try writer.writeByte('}');

        const metadata_json = try out.toOwnedSlice(self.allocator);
        defer self.allocator.free(metadata_json);
        const agent_dir = try std.fs.path.join(self.allocator, &.{ self.agents_dir, target_agent_id });
        defer self.allocator.free(agent_dir);
        try std.fs.cwd().makePath(agent_dir);
        const metadata_path = try std.fs.path.join(self.allocator, &.{ agent_dir, "agent.json" });
        defer self.allocator.free(metadata_path);
        try std.fs.cwd().writeFile(.{
            .sub_path = metadata_path,
            .data = metadata_json,
        });
        return true;
    }

    const AgentAbilities = struct {
        can_manage_sub_brains: bool,
        can_create_agents: bool,
    };

    fn canManageSubBrains(self: *Session) bool {
        const abilities = self.resolveAgentAbilities() catch return false;
        return abilities.can_manage_sub_brains;
    }

    fn canCreateAgents(self: *Session) bool {
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

    fn isValidManagedAgentId(agent_id: []const u8) bool {
        if (agent_id.len == 0 or agent_id.len > max_agent_id_len) return false;
        if (std.mem.eql(u8, agent_id, ".")) return false;
        for (agent_id) |char| {
            if (std.ascii.isAlphanumeric(char)) continue;
            if (char == '_' or char == '-') continue;
            return false;
        }
        return true;
    }

    fn managedAgentCapabilityName(value: agent_registry.AgentCapability) []const u8 {
        return switch (value) {
            .chat => "chat",
            .code => "code",
            .plan => "plan",
            .research => "research",
        };
    }

    fn loadOrInitSelfAgentConfig(self: *Session) !agent_config.AgentConfig {
        if (try agent_config.loadAgentConfigFromDir(self.allocator, self.agents_dir, self.agent_id)) |config| {
            return config;
        }
        var config = agent_config.AgentConfig.init(self.allocator);
        config.agent_id = try self.allocator.dupe(u8, self.agent_id);
        return config;
    }

    fn parseSubBrainConfigFromObject(self: *Session, obj: std.json.ObjectMap) !agent_config.SubBrainConfig {
        var out = agent_config.SubBrainConfig.init(self.allocator);
        errdefer out.deinit(self.allocator);

        if (obj.get("template")) |value| {
            if (value == .string) out.base.template = try self.allocator.dupe(u8, value.string) else if (value != .null) return error.InvalidPayload;
        }
        if (obj.get("provider")) |value| {
            switch (value) {
                .string => {
                    out.base.provider.name = try self.allocator.dupe(u8, value.string);
                },
                .object => {
                    if (value.object.get("name")) |field| {
                        if (field == .string) out.base.provider.name = try self.allocator.dupe(u8, field.string) else if (field != .null) return error.InvalidPayload;
                    }
                    if (value.object.get("model")) |field| {
                        if (field == .string) out.base.provider.model = try self.allocator.dupe(u8, field.string) else if (field != .null) return error.InvalidPayload;
                    }
                    if (value.object.get("think_level")) |field| {
                        if (field == .string) out.base.provider.think_level = try self.allocator.dupe(u8, field.string) else if (field != .null) return error.InvalidPayload;
                    }
                },
                .null => {},
                else => return error.InvalidPayload,
            }
        }
        if (obj.get("can_spawn_subbrains")) |value| {
            if (value == .bool) out.base.can_spawn_subbrains = value.bool else if (value != .null) return error.InvalidPayload;
        }

        try self.copyStringArrayConfigField(obj, "allowed_tools", &(out.base.allowed_tools));
        try self.copyStringArrayConfigField(obj, "denied_tools", &(out.base.denied_tools));
        try self.copyStringArrayConfigField(obj, "capabilities", &(out.base.capabilities));
        try self.copyRomOverridesConfigField(obj, "rom_overrides", &(out.base.rom_overrides));

        if (obj.get("personality")) |value| {
            if (value == .object) {
                if (value.object.get("name")) |field| {
                    if (field == .string) try self.setBrainRomOverride(&(out.base), "system:personality_name", field.string) else if (field != .null) return error.InvalidPayload;
                }
                if (value.object.get("description")) |field| {
                    if (field == .string) try self.setBrainRomOverride(&(out.base), "system:personality_description", field.string) else if (field != .null) return error.InvalidPayload;
                }
                if (value.object.get("creature")) |field| {
                    if (field == .string) try self.setBrainRomOverride(&(out.base), "system:personality_creature", field.string) else if (field != .null) return error.InvalidPayload;
                }
                if (value.object.get("vibe")) |field| {
                    if (field == .string) try self.setBrainRomOverride(&(out.base), "system:personality_vibe", field.string) else if (field != .null) return error.InvalidPayload;
                }
                if (value.object.get("emoji")) |field| {
                    if (field == .string) try self.setBrainRomOverride(&(out.base), "system:personality_emoji", field.string) else if (field != .null) return error.InvalidPayload;
                }
            } else if (value != .null) {
                return error.InvalidPayload;
            }
        }
        if (obj.get("creature")) |value| {
            if (value == .string) try self.setBrainRomOverride(&(out.base), "system:personality_creature", value.string) else if (value != .null) return error.InvalidPayload;
        }
        if (obj.get("vibe")) |value| {
            if (value == .string) try self.setBrainRomOverride(&(out.base), "system:personality_vibe", value.string) else if (value != .null) return error.InvalidPayload;
        }
        if (obj.get("emoji")) |value| {
            if (value == .string) try self.setBrainRomOverride(&(out.base), "system:personality_emoji", value.string) else if (value != .null) return error.InvalidPayload;
        }

        return out;
    }

    fn copyStringArrayConfigField(
        self: *Session,
        obj: std.json.ObjectMap,
        field_name: []const u8,
        target: *?std.ArrayListUnmanaged([]u8),
    ) !void {
        const value = obj.get(field_name) orelse return;
        if (value == .null) return;
        if (value != .array) return error.InvalidPayload;
        target.* = .{};
        for (value.array.items) |entry| {
            if (entry != .string) return error.InvalidPayload;
            try target.*.?.append(self.allocator, try self.allocator.dupe(u8, entry.string));
        }
    }

    fn copyRomOverridesConfigField(
        self: *Session,
        obj: std.json.ObjectMap,
        field_name: []const u8,
        target: *?std.ArrayListUnmanaged(agent_config.RomEntry),
    ) !void {
        const value = obj.get(field_name) orelse return;
        if (value == .null) return;
        if (value != .array) return error.InvalidPayload;
        target.* = .{};
        for (value.array.items) |entry| {
            if (entry != .object) return error.InvalidPayload;
            const key = entry.object.get("key") orelse return error.InvalidPayload;
            const val = entry.object.get("value") orelse return error.InvalidPayload;
            if (key != .string or val != .string) return error.InvalidPayload;
            try target.*.?.append(self.allocator, .{
                .key = try self.allocator.dupe(u8, key.string),
                .value = try self.allocator.dupe(u8, val.string),
            });
        }
    }

    fn setBrainRomOverride(
        self: *Session,
        cfg: *agent_config.BrainConfig,
        key: []const u8,
        value: []const u8,
    ) !void {
        if (cfg.rom_overrides == null) cfg.rom_overrides = .{};
        for (cfg.rom_overrides.?.items) |*entry| {
            if (!std.mem.eql(u8, entry.key, key)) continue;
            self.allocator.free(entry.value);
            entry.value = try self.allocator.dupe(u8, value);
            return;
        }
        try cfg.rom_overrides.?.append(self.allocator, .{
            .key = try self.allocator.dupe(u8, key),
            .value = try self.allocator.dupe(u8, value),
        });
    }

    fn buildSubBrainInventoryJson(self: *Session, config: *const agent_config.AgentConfig) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        const writer = out.writer(self.allocator);

        try writer.writeAll("{\"sub_brains\":[");
        var names = std.ArrayListUnmanaged([]const u8){};
        defer names.deinit(self.allocator);
        var it = config.sub_brains.iterator();
        while (it.next()) |entry| try names.append(self.allocator, entry.key_ptr.*);
        std.mem.sort([]const u8, names.items, {}, struct {
            fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
                return std.mem.lessThan(u8, lhs, rhs);
            }
        }.lessThan);

        for (names.items, 0..) |name, idx| {
            if (idx > 0) try writer.writeByte(',');
            const sub = config.sub_brains.get(name) orelse continue;
            try writer.writeByte('{');
            try writer.writeAll("\"brain_name\":");
            try writeJsonString(writer, name);
            try writer.writeAll(",\"template\":");
            if (sub.base.template) |value| {
                try writeJsonString(writer, value);
            } else {
                try writer.writeAll("null");
            }
            try writer.writeAll(",\"can_spawn_subbrains\":");
            try writer.print("{}", .{sub.base.can_spawn_subbrains});
            try writer.writeAll(",\"provider\":{");
            var provider_first = true;
            if (sub.base.provider.name) |value| {
                if (!provider_first) try writer.writeByte(',');
                provider_first = false;
                try writer.writeAll("\"name\":");
                try writeJsonString(writer, value);
            }
            if (sub.base.provider.model) |value| {
                if (!provider_first) try writer.writeByte(',');
                provider_first = false;
                try writer.writeAll("\"model\":");
                try writeJsonString(writer, value);
            }
            if (sub.base.provider.think_level) |value| {
                if (!provider_first) try writer.writeByte(',');
                provider_first = false;
                try writer.writeAll("\"think_level\":");
                try writeJsonString(writer, value);
            }
            try writer.writeByte('}');
            try writer.writeByte('}');
        }

        try writer.print("],\"count\":{d}}}", .{names.items.len});
        return out.toOwnedSlice(self.allocator);
    }

    fn buildSubBrainSuccessResultJson(self: *Session, op: SubBrainOp, result_json: []const u8) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, subBrainOperationName(op));
        defer self.allocator.free(escaped_operation);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
            .{ escaped_operation, result_json },
        );
    }

    fn buildSubBrainFailureResultJson(
        self: *Session,
        op: SubBrainOp,
        code: []const u8,
        message: []const u8,
    ) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, subBrainOperationName(op));
        defer self.allocator.free(escaped_operation);
        const escaped_code = try unified.jsonEscape(self.allocator, code);
        defer self.allocator.free(escaped_code);
        const escaped_message = try unified.jsonEscape(self.allocator, message);
        defer self.allocator.free(escaped_message);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":false,\"operation\":\"{s}\",\"result\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ escaped_operation, escaped_code, escaped_message },
        );
    }

    fn buildSubBrainListResultJson(self: *Session) ![]u8 {
        var config = try self.loadOrInitSelfAgentConfig();
        defer config.deinit();
        const inventory = try self.buildSubBrainInventoryJson(&config);
        defer self.allocator.free(inventory);
        return self.buildSubBrainSuccessResultJson(.list, inventory);
    }

    fn parseSubBrainOp(raw: []const u8) ?SubBrainOp {
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "sub_brains_list")) return .list;
        if (std.mem.eql(u8, value, "upsert") or std.mem.eql(u8, value, "sub_brains_upsert")) return .upsert;
        if (std.mem.eql(u8, value, "delete") or std.mem.eql(u8, value, "sub_brains_delete")) return .delete;
        return null;
    }

    fn subBrainToolName(op: SubBrainOp) []const u8 {
        return switch (op) {
            .list => "sub_brains_list",
            .upsert => "sub_brains_upsert",
            .delete => "sub_brains_delete",
        };
    }

    fn subBrainOperationName(op: SubBrainOp) []const u8 {
        return switch (op) {
            .list => "list",
            .upsert => "upsert",
            .delete => "delete",
        };
    }

    fn extractSubBrainName(obj: std.json.ObjectMap) ?[]const u8 {
        const candidates = [_][]const u8{ "brain_name", "name", "brain_id", "id", "sub_brain", "sub_brain_id" };
        inline for (candidates) |field| {
            if (obj.get(field)) |value| {
                if (value == .string and value.string.len > 0) return value.string;
            }
        }
        return null;
    }

    fn parseAgentOp(raw: []const u8) ?AgentOp {
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "agents_list")) return .list;
        if (std.mem.eql(u8, value, "create") or std.mem.eql(u8, value, "agents_create")) return .create;
        return null;
    }

    fn agentToolName(op: AgentOp) []const u8 {
        return switch (op) {
            .list => "agents_list",
            .create => "agents_create",
        };
    }

    fn agentOperationName(op: AgentOp) []const u8 {
        return switch (op) {
            .list => "list",
            .create => "create",
        };
    }

    fn extractAgentId(obj: std.json.ObjectMap) ?[]const u8 {
        const candidates = [_][]const u8{ "agent_id", "id" };
        inline for (candidates) |field| {
            if (obj.get(field)) |value| {
                if (value == .string and value.string.len > 0) return value.string;
            }
        }
        return null;
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

    const ProjectsOp = enum {
        list,
        get,
        up,
    };

    fn handleProjectsNamespaceWrite(self: *Session, special: SpecialKind, node_id: u32, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        const payload = if (input.len == 0) "{}" else input;
        try self.setFileContent(node_id, payload);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const op = switch (special) {
            .projects_list => ProjectsOp.list,
            .projects_get => ProjectsOp.get,
            .projects_up => ProjectsOp.up,
            .projects_invoke => blk: {
                const op_raw = blk2: {
                    if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk2 value.string;
                    break :blk2 null;
                } orelse return error.InvalidPayload;
                break :blk parseProjectsOp(op_raw) orelse return error.InvalidPayload;
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

        return self.executeProjectsOp(op, args_obj, raw_input.len);
    }

    fn parseProjectsOp(raw: []const u8) ?ProjectsOp {
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "projects_list")) return .list;
        if (std.mem.eql(u8, value, "get") or std.mem.eql(u8, value, "projects_get")) return .get;
        if (std.mem.eql(u8, value, "up") or std.mem.eql(u8, value, "project_up") or std.mem.eql(u8, value, "projects_up")) return .up;
        return null;
    }

    fn executeProjectsOp(self: *Session, op: ProjectsOp, args_obj: std.json.ObjectMap, written: usize) !WriteOutcome {
        const tool_name = projectsStatusToolName(op);
        const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
        defer self.allocator.free(running_status);
        if (self.projects_status_id != 0) try self.setFileContent(self.projects_status_id, running_status);

        const result_payload = self.executeProjectsOpPayload(op, args_obj) catch |err| {
            const error_message = @errorName(err);
            const error_code = switch (err) {
                error.AccessDenied => "forbidden",
                else => "invalid_payload",
            };
            const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
            defer self.allocator.free(failed_status);
            if (self.projects_status_id != 0) try self.setFileContent(self.projects_status_id, failed_status);
            const failed_result = try self.buildProjectFailureResultJson(op, error_code, error_message);
            defer self.allocator.free(failed_result);
            if (self.projects_result_id != 0) try self.setFileContent(self.projects_result_id, failed_result);
            return err;
        };
        defer self.allocator.free(result_payload);

        const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
        defer self.allocator.free(done_status);
        if (self.projects_status_id != 0) try self.setFileContent(self.projects_status_id, done_status);
        if (self.projects_result_id != 0) try self.setFileContent(self.projects_result_id, result_payload);
        return .{ .written = written };
    }

    fn executeProjectsOpPayload(self: *Session, op: ProjectsOp, args_obj: std.json.ObjectMap) ![]u8 {
        const plane = self.control_plane orelse return error.InvalidPayload;
        return switch (op) {
            .list => self.buildProjectListResultJson(),
            .get => blk: {
                const project_id = extractOptionalStringByNames(args_obj, &[_][]const u8{ "project_id", "id" }) orelse return error.InvalidPayload;
                const escaped_project = try unified.jsonEscape(self.allocator, project_id);
                defer self.allocator.free(escaped_project);
                const token_fragment = if (extractOptionalStringByNames(args_obj, &[_][]const u8{"project_token"})) |token| blk2: {
                    const escaped = try unified.jsonEscape(self.allocator, token);
                    defer self.allocator.free(escaped);
                    break :blk2 try std.fmt.allocPrint(self.allocator, ",\"project_token\":\"{s}\"", .{escaped});
                } else if (self.project_token) |token| blk2: {
                    const escaped = try unified.jsonEscape(self.allocator, token);
                    defer self.allocator.free(escaped);
                    break :blk2 try std.fmt.allocPrint(self.allocator, ",\"project_token\":\"{s}\"", .{escaped});
                } else try self.allocator.dupe(u8, "");
                defer self.allocator.free(token_fragment);
                const payload = try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"project_id\":\"{s}\"{s}}}",
                    .{ escaped_project, token_fragment },
                );
                defer self.allocator.free(payload);
                const result = plane.getProjectWithRole(payload, self.is_admin) catch |err| switch (err) {
                    control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                    control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                    control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                    => return error.AccessDenied,
                    control_plane_mod.ControlPlaneError.MissingField,
                    control_plane_mod.ControlPlaneError.InvalidPayload,
                    control_plane_mod.ControlPlaneError.ProjectNotFound,
                    => return error.InvalidPayload,
                    else => return err,
                };
                defer self.allocator.free(result);
                break :blk self.buildProjectSuccessResultJson(.get, result);
            },
            .up => blk: {
                const payload = try self.renderProjectUpPayload(args_obj);
                defer self.allocator.free(payload);
                const result = plane.projectUpWithRole(self.agent_id, payload, self.is_admin) catch |err| switch (err) {
                    control_plane_mod.ControlPlaneError.ProjectPolicyForbidden,
                    control_plane_mod.ControlPlaneError.ProjectAuthFailed,
                    control_plane_mod.ControlPlaneError.ProjectAssignmentForbidden,
                    control_plane_mod.ControlPlaneError.ProjectProtected,
                    => return error.AccessDenied,
                    control_plane_mod.ControlPlaneError.MissingField,
                    control_plane_mod.ControlPlaneError.InvalidPayload,
                    control_plane_mod.ControlPlaneError.ProjectNotFound,
                    control_plane_mod.ControlPlaneError.NodeNotFound,
                    control_plane_mod.ControlPlaneError.MountConflict,
                    => return error.InvalidPayload,
                    else => return err,
                };
                defer self.allocator.free(result);
                break :blk self.buildProjectSuccessResultJson(.up, result);
            },
        };
    }

    fn renderProjectUpPayload(self: *Session, args_obj: std.json.ObjectMap) ![]u8 {
        if (!std.mem.eql(u8, self.agent_id, "mother")) {
            return self.renderJsonValue(.{ .object = args_obj });
        }
        if (args_obj.get("activate") != null) {
            return self.renderJsonValue(.{ .object = args_obj });
        }

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        const writer = out.writer(self.allocator);
        try writer.writeByte('{');
        var first = true;
        var it = args_obj.iterator();
        while (it.next()) |entry| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writeJsonString(writer, entry.key_ptr.*);
            try writer.writeByte(':');
            try writer.print("{f}", .{std.json.fmt(entry.value_ptr.*, .{})});
        }
        if (!first) try writer.writeByte(',');
        try writer.writeAll("\"activate\":false");
        try writer.writeByte('}');
        return out.toOwnedSlice(self.allocator);
    }

    fn buildProjectListResultJson(self: *Session) ![]u8 {
        const plane = self.control_plane orelse return self.buildProjectSuccessResultJson(.list, "{\"projects\":[]}");
        const result = try plane.listProjects();
        defer self.allocator.free(result);
        return self.buildProjectSuccessResultJson(.list, result);
    }

    fn buildProjectSuccessResultJson(self: *Session, op: ProjectsOp, result_json: []const u8) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, projectsOperationName(op));
        defer self.allocator.free(escaped_operation);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
            .{ escaped_operation, result_json },
        );
    }

    fn buildProjectFailureResultJson(self: *Session, op: ProjectsOp, code: []const u8, message: []const u8) ![]u8 {
        const escaped_operation = try unified.jsonEscape(self.allocator, projectsOperationName(op));
        defer self.allocator.free(escaped_operation);
        const escaped_code = try unified.jsonEscape(self.allocator, code);
        defer self.allocator.free(escaped_code);
        const escaped_message = try unified.jsonEscape(self.allocator, message);
        defer self.allocator.free(escaped_message);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"ok\":false,\"operation\":\"{s}\",\"result\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ escaped_operation, escaped_code, escaped_message },
        );
    }

    fn projectsOperationName(op: ProjectsOp) []const u8 {
        return switch (op) {
            .list => "list",
            .get => "get",
            .up => "up",
        };
    }

    fn projectsStatusToolName(op: ProjectsOp) []const u8 {
        return switch (op) {
            .list => "projects_list",
            .get => "projects_get",
            .up => "projects_up",
        };
    }

    fn renderJsonValue(self: *Session, value: std.json.Value) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})});
    }

    fn executeServiceToolCall(self: *Session, tool_name: []const u8, args_json: []const u8) ![]u8 {
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

    fn buildServiceInvokeStatusJson(
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

    fn buildServiceInvokeFailureResultJson(self: *Session, code: []const u8, message: []const u8) ![]u8 {
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

    fn extractErrorMessageFromToolPayload(self: *Session, payload_json: []const u8) !?[]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const error_value = parsed.value.object.get("error") orelse return null;
        if (error_value == .string) return @as(?[]u8, try self.allocator.dupe(u8, error_value.string));
        if (error_value != .object) return null;
        if (error_value.object.get("message")) |message| {
            if (message == .string) return @as(?[]u8, try self.allocator.dupe(u8, message.string));
        }
        return @as(?[]u8, try self.allocator.dupe(u8, "tool returned error"));
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
        if (std.mem.eql(u8, path, "/global/chat/control/input") or
            std.mem.endsWith(u8, path, "/global/chat/control/input"))
        {
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .chat_input,
            };
        }

        if (std.mem.eql(u8, path, "/global/events/sources/agent.json") or
            std.mem.endsWith(u8, path, "/global/events/sources/agent.json"))
        {
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .agent_signal,
            };
        }
        if (std.mem.eql(u8, path, "/global/events/sources/hook.json") or
            std.mem.endsWith(u8, path, "/global/events/sources/hook.json"))
        {
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .hook_signal,
            };
        }
        if (std.mem.eql(u8, path, "/global/events/sources/user.json") or
            std.mem.endsWith(u8, path, "/global/events/sources/user.json"))
        {
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .user_signal,
            };
        }
        if (std.mem.indexOf(u8, path, "/global/events/sources/agent/")) |prefix_index| {
            const marker = "/global/events/sources/agent/";
            const token = path[prefix_index + marker.len ..];
            const parameter = try self.parseWaitSelectorToken(token);
            errdefer self.allocator.free(parameter);
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .agent_signal,
                .parameter = parameter,
            };
        }
        if (std.mem.indexOf(u8, path, "/global/events/sources/hook/")) |prefix_index| {
            const marker = "/global/events/sources/hook/";
            const token = path[prefix_index + marker.len ..];
            const parameter = try self.parseWaitSelectorToken(token);
            errdefer self.allocator.free(parameter);
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .hook_signal,
                .parameter = parameter,
            };
        }
        if (std.mem.indexOf(u8, path, "/global/events/sources/user/")) |prefix_index| {
            const marker = "/global/events/sources/user/";
            const token = path[prefix_index + marker.len ..];
            const parameter = try self.parseWaitSelectorToken(token);
            errdefer self.allocator.free(parameter);
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .user_signal,
                .parameter = parameter,
            };
        }
        if (std.mem.indexOf(u8, path, "/global/events/sources/time/after/")) |prefix_index| {
            const marker = "/global/events/sources/time/after/";
            const token = path[prefix_index + marker.len ..];
            const delay_ms = try self.parseWaitSelectorMillis(token);
            const target_time_ms = std.math.add(i64, std.time.milliTimestamp(), delay_ms) catch return error.InvalidPayload;
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .time_after,
                .target_time_ms = target_time_ms,
            };
        }
        if (std.mem.indexOf(u8, path, "/global/events/sources/time/at/")) |prefix_index| {
            const marker = "/global/events/sources/time/at/";
            const token = path[prefix_index + marker.len ..];
            const target_ms = try self.parseWaitSelectorMillis(token);
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .time_at,
                .target_time_ms = target_ms,
            };
        }

        if (std.mem.indexOf(u8, path, "/global/jobs/")) |prefix_index| {
            const prefix = "/global/jobs/";
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
            .job_status => try std.fmt.allocPrint(self.allocator, "/global/jobs/{s}/status.json", .{view.job_id}),
            .job_result => try std.fmt.allocPrint(self.allocator, "/global/jobs/{s}/result.txt", .{view.job_id}),
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

        const event_path = try std.fmt.allocPrint(self.allocator, "/global/jobs/{s}/status.json", .{event.job_id});
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
                try std.fmt.allocPrint(self.allocator, "/global/events/sources/agent/{s}.json", .{value})
            else
                try self.allocator.dupe(u8, "/global/events/sources/agent.json"),
            .hook_signal => if (event.parameter) |value|
                try std.fmt.allocPrint(self.allocator, "/global/events/sources/hook/{s}.json", .{value})
            else
                try self.allocator.dupe(u8, "/global/events/sources/hook.json"),
            .user_signal => if (event.parameter) |value|
                try std.fmt.allocPrint(self.allocator, "/global/events/sources/user/{s}.json", .{value})
            else
                try self.allocator.dupe(u8, "/global/events/sources/user.json"),
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
            "{{\"configured\":true,\"waiting\":false,\"event_id\":{d},\"source_path\":\"{s}\",\"event_path\":\"/global/events/sources/time\",\"updated_at_ms\":{d},\"time\":{{\"target_ms\":{d},\"now_ms\":{d},\"fired\":true}}}}",
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

        var explicit_provider = blk: {
            const plane = self.control_plane orelse break :blk null;
            break :blk try plane.resolveExplicitPreferredVenomProvider(self.allocator, venom_id);
        };
        defer if (explicit_provider) |*value| value.deinit(self.allocator);

        const provider_node_id = if (explicit_provider) |provider|
            try self.allocator.dupe(u8, provider.node_id)
        else
            null;
        defer if (provider_node_id) |value| self.allocator.free(value);
        const provider_venom_path = if (provider_node_id) |node_id|
            try std.fmt.allocPrint(self.allocator, "/nodes/{s}/venoms/{s}", .{ node_id, venom_id })
        else
            null;
        defer if (provider_venom_path) |value| self.allocator.free(value);
        const provider_invoke_path = if (explicit_provider) |provider| blk: {
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

    fn deriveVenomInvokePath(
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

    fn pathWithInvokeSuffix(self: *Session, base_path: []const u8) ![]u8 {
        const trimmed = std.mem.trimRight(u8, base_path, "/");
        if (trimmed.len == 0) return self.allocator.dupe(u8, "/control/invoke.json");
        if (std.mem.endsWith(u8, trimmed, "/control/invoke.json")) {
            return self.allocator.dupe(u8, trimmed);
        }
        return std.fmt.allocPrint(self.allocator, "{s}/control/invoke.json", .{trimmed});
    }

    fn pathWithInvokeTarget(self: *Session, base_path: []const u8, invoke_suffix: []const u8) ![]u8 {
        const base_trimmed = std.mem.trimRight(u8, base_path, "/");
        if (invoke_suffix.len == 0) return self.allocator.dupe(u8, base_trimmed);
        if (base_trimmed.len == 0) {
            return std.fmt.allocPrint(self.allocator, "/{s}", .{invoke_suffix});
        }
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ base_trimmed, invoke_suffix });
    }

    fn resolveNodeVenomInvokeTarget(self: *Session, venom_dir_id: u32) ![]u8 {
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
        std.mem.startsWith(u8, path, "/global/") or
        std.mem.startsWith(u8, path, "/debug/");
}

fn defaultGlobalLibraryIndexMd() []const u8 {
    return "# Spiderweb Global Library\n\n" ++
        "- [Getting Started](/global/library/topics/getting-started.md)\n" ++
        "- [Service Discovery](/global/library/topics/service-discovery.md)\n" ++
        "- [Events and Waits](/global/library/topics/events-and-waits.md)\n" ++
        "- [Search Services](/global/library/topics/search-services.md)\n" ++
        "- [Terminal Workflows](/global/library/topics/terminal-workflows.md)\n" ++
        "- [Memory Workflows](/global/library/topics/memory-workflows.md)\n" ++
        "- [Project Mounts and Binds](/global/library/topics/project-mounts-and-binds.md)\n" ++
        "- [Agent Management and Sub-Brains](/global/library/topics/agent-management-and-sub-brains.md)\n";
}

fn defaultGlobalLibraryTopicGettingStarted() []const u8 {
    return "# Getting Started\n\n" ++
        "1. Discover Venoms in `/global/venoms/VENOMS.json`.\n" ++
        "2. Read each Venom `README.md`, `SCHEMA.json`, and `CAPS.json` before using it.\n" ++
        "3. Use `/global/library` for system guides.\n";
}

fn defaultGlobalLibraryTopicServiceDiscovery() []const u8 {
    return "# Venom Discovery\n\n" ++
        "- Node Venoms: `/nodes/<node_id>/venoms/<venom_id>`\n" ++
        "- Project namespaces: `/global/<venom_id>`\n" ++
        "- Global namespaces: `/global/<venom_id>`\n" ++
        "- Start with `/global/venoms/VENOMS.json`.\n" ++
        "- Common project Venoms include: memory, web_search, search_code, terminal, mounts, sub_brains, agents, projects.\n";
}

fn defaultGlobalLibraryTopicEventsAndWaits() []const u8 {
    return "# Events and Waits\n\n" ++
        "Use single-source blocking reads first for deterministic waits.\n" ++
        "Use `/global/events/control/wait.json` + `/global/events/next.json` for one-of-many waits.\n";
}

fn defaultGlobalLibraryTopicSearchServices() []const u8 {
    return "# Search Services\n\n" ++
        "Use `/global/search_code` for repository-local search and `/global/web_search` for external lookup.\n" ++
        "Drive both through `control/search.json` or `control/invoke.json`, then check `status.json` and `result.json`.\n";
}

fn defaultGlobalLibraryTopicTerminalWorkflows() []const u8 {
    return "# Terminal Workflows\n\n" ++
        "Use `/global/terminal/control/*.json` for sessionized shell execution.\n" ++
        "Prefer `create` + `write/read` for interactive loops and `exec` for single command tasks.\n";
}

fn defaultGlobalLibraryTopicMemoryWorkflows() []const u8 {
    return "# Memory Workflows\n\n" ++
        "Use `/global/memory/control/*.json` and pass `memory_path` for targeted operations.\n" ++
        "Use `search` before creating duplicate memories.\n";
}

fn defaultGlobalLibraryTopicProjectMountsAndBinds() []const u8 {
    return "# Project Mounts and Binds\n\n" ++
        "Use `/global/mounts/control/mount.json`, `mkdir.json`, and `unmount.json` for project mounts.\n" ++
        "Use `/global/mounts/control/bind.json` and `resolve.json` for stable project paths.\n";
}

fn defaultGlobalLibraryTopicAgentManagementAndSubBrains() []const u8 {
    return "# Agent Management and Sub-Brains\n\n" ++
        "Use `/global/agents` for list/create, `/global/sub_brains` for list/upsert/delete, and `/global/projects` for list/get/up.\n" ++
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

fn hexDigitUpper(value: u8) u8 {
    return if (value < 10) ('0' + value) else ('A' + (value - 10));
}

fn parseHexNibble(value: u8) ?u8 {
    if (value >= '0' and value <= '9') return value - '0';
    if (value >= 'A' and value <= 'F') return value - 'A' + 10;
    if (value >= 'a' and value <= 'f') return value - 'a' + 10;
    return null;
}

fn urlPathEncode(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char) or char == '-' or char == '_' or char == '.' or char == '~') {
            try out.append(allocator, char);
            continue;
        }
        try out.append(allocator, '%');
        try out.append(allocator, hexDigitUpper((char >> 4) & 0x0F));
        try out.append(allocator, hexDigitUpper(char & 0x0F));
    }
    return out.toOwnedSlice(allocator);
}

fn urlPathDecode(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < value.len) {
        const char = value[i];
        if (char == '%') {
            if (i + 2 >= value.len) return error.InvalidPayload;
            const hi = parseHexNibble(value[i + 1]) orelse return error.InvalidPayload;
            const lo = parseHexNibble(value[i + 2]) orelse return error.InvalidPayload;
            try out.append(allocator, (hi << 4) | lo);
            i += 3;
            continue;
        }
        try out.append(allocator, char);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

fn buildMemoryPathFromMemId(allocator: std.mem.Allocator, mem_id: []const u8) ![]u8 {
    const encoded = try urlPathEncode(allocator, mem_id);
    defer allocator.free(encoded);
    return std.fmt.allocPrint(allocator, "/global/memory/items/{s}", .{encoded});
}

fn decodeMemIdFromPath(allocator: std.mem.Allocator, path_or_mem_id: []const u8) ![]u8 {
    const prefix = "/global/memory/items/";
    if (!std.mem.startsWith(u8, path_or_mem_id, prefix)) {
        return allocator.dupe(u8, path_or_mem_id);
    }
    const tail = path_or_mem_id[prefix.len..];
    if (tail.len == 0) return error.InvalidPayload;
    const slash = std.mem.indexOfScalar(u8, tail, '/') orelse tail.len;
    if (slash == 0) return error.InvalidPayload;
    return urlPathDecode(allocator, tail[0..slash]);
}

fn parseTerminalInvokeOp(raw: []const u8) ?TerminalInvokeOp {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "exec") or std.mem.eql(u8, value, "shell_exec")) return .exec;
    if (std.mem.eql(u8, value, "create") or std.mem.eql(u8, value, "terminal_session_create")) return .create_session;
    if (std.mem.eql(u8, value, "resume") or std.mem.eql(u8, value, "terminal_session_resume")) return .resume_session;
    if (std.mem.eql(u8, value, "close") or std.mem.eql(u8, value, "terminal_session_close")) return .close_session;
    if (std.mem.eql(u8, value, "write") or std.mem.eql(u8, value, "terminal_session_write")) return .write_session;
    if (std.mem.eql(u8, value, "read") or std.mem.eql(u8, value, "terminal_session_read")) return .read_session;
    if (std.mem.eql(u8, value, "resize") or std.mem.eql(u8, value, "terminal_session_resize")) return .resize_session;
    return null;
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
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_path\":\"/global/jobs/job-") != null);
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
        "{\"paths\":[\"/global/jobs/job-missing/status.json\"],\"timeout_ms\":0}",
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
        "{\"paths\":[\"/global/events/sources/time/after/0.json\"],\"timeout_ms\":0}",
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
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_path\":\"/global/events/sources/time\"") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"projects\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_id\":\"library\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/search_code\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/search_code\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/mounts\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/projects\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/library\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"global_namespace\"") != null);
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
    try std.testing.expectEqualStrings("/global/jobs/job-global/result.txt", global_result_path);

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
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/memory/control/invoke.json\"") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/web_search/control/invoke.json\"") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/terminal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/terminal/control/invoke.json\"") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/sub_brains\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/sub_brains/control/invoke.json\"") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/agents\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/agents/control/invoke.json\"") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"venom_path\":\"/global/projects\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/global/projects/control/invoke.json\"") != null);
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
        &.{ "agents", "self", "projects", "control", "up.json" },
        "{\"name\":\"ZiggyPR\",\"vision\":\"Bootstrap project setup\",\"activate\":false}",
        954,
    );

    const status = try protocolReadFile(
        &session,
        allocator,
        334,
        335,
        &.{ "agents", "self", "projects", "status.json" },
        955,
    );
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"tool\":\"projects_up\"") != null);

    const result = try protocolReadFile(
        &session,
        allocator,
        336,
        337,
        &.{ "agents", "self", "projects", "result.json" },
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

    const hatch_path = try std.fs.path.join(allocator, &.{ agents_dir, "builder", "HATCH.md" });
    defer allocator.free(hatch_path);
    const hatch_content = try std.fs.cwd().readFileAlloc(allocator, hatch_path, 64 * 1024);
    defer allocator.free(hatch_content);
    try std.testing.expect(hatch_content.len > 0);

    const metadata_path = try std.fs.path.join(allocator, &.{ agents_dir, "builder", "agent.json" });
    defer allocator.free(metadata_path);
    const metadata_content = try std.fs.cwd().readFileAlloc(allocator, metadata_path, 64 * 1024);
    defer allocator.free(metadata_content);
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

    const hatch_path = try std.fs.path.join(allocator, &.{ agents_dir, "builder-missing-project", "HATCH.md" });
    defer allocator.free(hatch_path);
    const hatch_content = try std.fs.cwd().readFileAlloc(allocator, hatch_path, 64 * 1024);
    defer allocator.free(hatch_content);
    try std.testing.expect(hatch_content.len > 0);
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

    const sessions_payload = try protocolReadFile(
        &session,
        allocator,
        314,
        315,
        &.{ "agents", "self", "terminal", "sessions.json" },
        927,
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
    try session.appendTerminalBufferedResult(terminal_session, "abcdef");
    try session.appendTerminalBufferedResult(terminal_session, "gh");

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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"venoms\":[{{\"venom_id\":\"gdrive-main\",\"kind\":\"gdrive\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/venoms/gdrive-main\"],\"capabilities\":{{\"provider\":\"google\"}},\"mounts\":[{{\"mount_id\":\"drive-main\",\"mount_path\":\"/nodes/{s}/drive/main\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}},\"help_md\":\"Google Drive namespace mount\"}}]}}",
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
    const permissions_id = session.lookupChild(gdrive_service, "PERMISSIONS.json") orelse return error.TestExpectedResponse;
    const readme_id = session.lookupChild(gdrive_service, "README.md") orelse return error.TestExpectedResponse;
    const mounts_node = session.nodes.get(mounts_id) orelse return error.TestExpectedResponse;
    const ops_node = session.nodes.get(ops_id) orelse return error.TestExpectedResponse;
    const runtime_node = session.nodes.get(runtime_id) orelse return error.TestExpectedResponse;
    const permissions_node = session.nodes.get(permissions_id) orelse return error.TestExpectedResponse;
    const readme_node = session.nodes.get(readme_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, mounts_node.content, "\"mount_path\":\"/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, ops_node.content, "\"model\":\"namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, runtime_node.content, "\"type\":\"native_proc\"") != null);
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
