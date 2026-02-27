const std = @import("std");
const unified = @import("ziggy-spider-protocol").unified;
const runtime_server_mod = @import("runtime_server.zig");
const runtime_handle_mod = @import("runtime_handle.zig");
const chat_job_index = @import("chat_job_index.zig");
const world_policy = @import("world_policy.zig");
const fs_control_plane = @import("fs_control_plane.zig");

const NodeKind = enum {
    dir,
    file,
};

const SpecialKind = enum {
    none,
    chat_input,
    job_status,
    job_result,
    job_log,
    agent_services_index,
    agent_contract_invoke,
    event_wait_config,
    event_next,
    pairing_refresh,
    pairing_approve,
    pairing_deny,
    pairing_invites_refresh,
    pairing_invites_create,
};

const default_wait_timeout_ms: i64 = 60_000;
const wait_poll_interval_ms: u64 = 100;

const WaitSourceKind = enum {
    chat_input,
    job_status,
    job_result,
};

const WaitSource = struct {
    raw_path: []u8,
    kind: WaitSourceKind,
    job_id: ?[]u8 = null,
    last_seen_updated_at_ms: i64 = 0,

    fn deinit(self: *WaitSource, allocator: std.mem.Allocator) void {
        allocator.free(self.raw_path);
        if (self.job_id) |value| allocator.free(value);
        self.* = undefined;
    }
};

const WaitCandidate = struct {
    source_index: usize,
    event_path: []u8,
    view: chat_job_index.JobView,

    fn deinit(self: *WaitCandidate, allocator: std.mem.Allocator) void {
        allocator.free(self.event_path);
        self.view.deinit(allocator);
        self.* = undefined;
    }
};

const WriteOutcome = struct {
    written: usize,
    job_name: ?[]u8 = null,
    correlation_id: ?[]u8 = null,
};

const ContractInvokeRequest = struct {
    tool_name: []u8,
    args_json: []u8,

    fn deinit(self: *ContractInvokeRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.tool_name);
        allocator.free(self.args_json);
        self.* = undefined;
    }
};

const ServiceInvokeMetadata = struct {
    runtime_tool: ?[]u8 = null,
    runtime_tool_family: ?[]u8 = null,
    operation_tools: std.StringHashMapUnmanaged([]u8) = .{},
    has_operation_mappings: bool = false,

    fn deinit(self: *ServiceInvokeMetadata, allocator: std.mem.Allocator) void {
        if (self.runtime_tool) |value| allocator.free(value);
        if (self.runtime_tool_family) |value| allocator.free(value);
        var it = self.operation_tools.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.operation_tools.deinit(allocator);
        self.* = undefined;
    }

    fn toolForOperation(self: *const ServiceInvokeMetadata, operation_name: []const u8) ?[]const u8 {
        return self.operation_tools.get(operation_name);
    }

    fn containsTool(self: *const ServiceInvokeMetadata, tool_name: []const u8) bool {
        var it = self.operation_tools.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.*, tool_name)) return true;
        }
        return false;
    }

    fn allowsTool(self: *const ServiceInvokeMetadata, operation_name: ?[]const u8, tool_name: []const u8) bool {
        if (self.runtime_tool) |value| {
            if (!std.mem.eql(u8, value, tool_name)) return false;
        }

        if (self.runtime_tool_family) |family| {
            if (!(tool_name.len > family.len + 1 and
                std.mem.startsWith(u8, tool_name, family) and
                tool_name[family.len] == '_'))
            {
                return false;
            }
        }

        if (operation_name) |op| {
            if (self.toolForOperation(op)) |mapped| {
                return std.mem.eql(u8, mapped, tool_name);
            }
        }

        if (self.runtime_tool != null or self.runtime_tool_family != null) return true;
        if (self.has_operation_mappings) return self.containsTool(tool_name);
        return true;
    }
};

const PairingAction = enum {
    refresh,
    approve,
    deny,
    invites_refresh,
    invites_create,
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
        projects_dir: []const u8 = "projects",
        control_plane: ?*fs_control_plane.ControlPlane = null,
        is_admin: bool = false,
    };

    allocator: std.mem.Allocator,
    runtime_handle: *runtime_handle_mod.RuntimeHandle,
    job_index: *chat_job_index.ChatJobIndex,
    agent_id: []u8,
    project_id: ?[]u8 = null,
    project_token: ?[]u8 = null,
    agents_dir: []u8,
    projects_dir: []u8,
    control_plane: ?*fs_control_plane.ControlPlane = null,
    is_admin: bool = false,

    nodes: std.AutoHashMapUnmanaged(u32, Node) = .{},
    fids: std.AutoHashMapUnmanaged(u32, FidState) = .{},
    pending_debug_frames: std.ArrayListUnmanaged([]u8) = .{},
    debug_stream_enabled: bool = false,

    next_node_id: u32 = 1,

    root_id: u32 = 0,
    nodes_root_id: u32 = 0,
    jobs_root_id: u32 = 0,
    chat_input_id: u32 = 0,
    agent_services_index_id: u32 = 0,
    event_next_id: u32 = 0,
    pairing_pending_id: u32 = 0,
    pairing_last_result_id: u32 = 0,
    pairing_last_error_id: u32 = 0,
    pairing_invites_active_id: u32 = 0,
    pairing_invites_last_result_id: u32 = 0,
    pairing_invites_last_error_id: u32 = 0,
    wait_sources: std.ArrayListUnmanaged(WaitSource) = .{},
    wait_timeout_ms: i64 = default_wait_timeout_ms,
    wait_event_seq: u64 = 1,

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
        const owned_agents_dir = try allocator.dupe(u8, options.agents_dir);
        errdefer allocator.free(owned_agents_dir);
        const owned_projects_dir = try allocator.dupe(u8, options.projects_dir);
        errdefer allocator.free(owned_projects_dir);
        runtime_handle.retain();
        errdefer runtime_handle.release();

        var self = Session{
            .allocator = allocator,
            .runtime_handle = runtime_handle,
            .job_index = job_index,
            .agent_id = owned_agent,
            .project_id = owned_project,
            .project_token = owned_project_token,
            .agents_dir = owned_agents_dir,
            .projects_dir = owned_projects_dir,
            .control_plane = options.control_plane,
            .is_admin = options.is_admin,
        };
        try self.seedNamespace();
        return self;
    }

    pub fn deinit(self: *Session) void {
        self.clearWaitSources();
        self.clearPendingDebugFrames();
        var it = self.nodes.iterator();
        while (it.next()) |entry| {
            var node = entry.value_ptr.*;
            node.deinit(self.allocator);
        }
        self.nodes.deinit(self.allocator);
        self.fids.deinit(self.allocator);
        self.allocator.free(self.agent_id);
        if (self.project_id) |value| self.allocator.free(value);
        if (self.project_token) |value| self.allocator.free(value);
        self.allocator.free(self.agents_dir);
        self.allocator.free(self.projects_dir);
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
                .projects_dir = self.projects_dir,
                .control_plane = self.control_plane,
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
        var rebound = try Session.initWithOptions(self.allocator, runtime_handle, self.job_index, agent_id, options);
        rebound.debug_stream_enabled = self.debug_stream_enabled;

        var previous = self.*;
        self.* = rebound;
        previous.deinit();
    }

    pub fn setDebugStreamEnabled(self: *Session, enabled: bool) void {
        self.debug_stream_enabled = enabled;
        if (!enabled) self.clearPendingDebugFrames();
    }

    pub fn drainPendingDebugFrames(self: *Session) ![][]u8 {
        if (self.pending_debug_frames.items.len == 0) return &.{};
        const owned = try self.pending_debug_frames.toOwnedSlice(self.allocator);
        self.pending_debug_frames = .{};
        return owned;
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

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"qid\":{{\"path\":{d},\"type\":\"dir\"}}}}",
            .{self.root_id},
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
            const next = self.lookupChild(node_id, segment) orelse {
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
                if (offset == 0) {
                    switch (node.special) {
                        .job_status, .job_result => {
                            try self.waitForJobTerminalState(state.node_id);
                            try self.refreshJobNodeFromIndex(state.node_id, node.special);
                        },
                        .job_log => {
                            try self.refreshJobNodeFromIndex(state.node_id, node.special);
                        },
                        .agent_services_index => {
                            try self.refreshAgentServicesIndex(state.node_id);
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
        if (dir_id != self.nodes_root_id) return;
        try self.addNodeDirectoriesFromControlPlane(self.nodes_root_id);
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
        defer if (job_name) |value| self.allocator.free(value);
        defer if (correlation_id) |value| self.allocator.free(value);
        switch (node.special) {
            .chat_input => {
                const outcome = try self.handleChatInputWrite(msg, data);
                written = outcome.written;
                job_name = outcome.job_name;
                correlation_id = outcome.correlation_id;
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
            .agent_contract_invoke => {
                const outcome = self.handleAgentContractInvokeWrite(state.node_id, data) catch |err| switch (err) {
                    error.InvalidPayload => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "invalid",
                            "invoke payload must include tool/tool_name/op and optional arguments/args",
                        );
                    },
                    error.AccessDenied => {
                        return unified.buildFsrpcError(
                            self.allocator,
                            msg.tag,
                            "eperm",
                            "invoke access denied by permissions",
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
            if (correlation_id) |corr| {
                const escaped_corr = try unified.jsonEscape(self.allocator, corr);
                defer self.allocator.free(escaped_corr);
                break :blk try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"n\":{d},\"job\":\"{s}\",\"result_path\":\"/agents/self/jobs/{s}/result.txt\",\"correlation_id\":\"{s}\"}}",
                    .{ written, escaped, escaped, escaped_corr },
                );
            }
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"n\":{d},\"job\":\"{s}\",\"result_path\":\"/agents/self/jobs/{s}/result.txt\"}}",
                .{ written, escaped, escaped },
            );
        } else try std.fmt.allocPrint(self.allocator, "{{\"n\":{d}}}", .{written});
        defer self.allocator.free(payload);
        return unified.buildFsrpcResponse(self.allocator, .r_write, msg.tag, payload);
    }

    fn handleStat(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const fid = msg.fid orelse return unified.buildFsrpcError(self.allocator, msg.tag, "invalid", "fid is required");
        const state = self.fids.get(fid) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "enoent", "unknown fid");
        const node = self.nodes.get(state.node_id) orelse return unified.buildFsrpcError(self.allocator, msg.tag, "eio", "missing node");

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
        var policy = try world_policy.load(
            self.allocator,
            .{
                .agent_id = self.agent_id,
                .project_id = self.project_id,
                .agents_dir = self.agents_dir,
                .projects_dir = self.projects_dir,
            },
        );
        defer policy.deinit(self.allocator);

        self.root_id = try self.addDir(null, "/", false);
        const nodes_root = try self.addDir(self.root_id, "nodes", false);
        self.nodes_root_id = nodes_root;
        const agents_root = try self.addDir(self.root_id, "agents", false);
        const projects_root = try self.addDir(self.root_id, "projects", false);
        const meta_root = try self.addDir(self.root_id, "meta", false);
        const debug_root: ?u32 = if (policy.show_debug)
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
            "{\"kind\":\"collection\",\"entries\":\"agent directories\",\"self\":\"/agents/self\"}",
            "{\"read\":true,\"write\":true}",
            "Agent-visible chat/jobs/memory views.",
        );
        try self.addDirectoryDescriptors(
            projects_root,
            "Projects",
            "{\"kind\":\"collection\",\"entries\":\"project directories\",\"shape\":\"/projects/<project_id>/{fs,agents,meta}\"}",
            "{\"read\":true,\"write\":false}",
            "Project-centric cross-node and agent views.",
        );

        try self.addNodeDirectoriesFromControlPlane(nodes_root);
        for (policy.nodes.items) |node| {
            if (self.lookupChild(nodes_root, node.id) != null) continue;
            try self.addNodeDirectory(nodes_root, node, false);
        }

        const self_agent_dir = try self.addDir(agents_root, "self", false);
        const chat = try self.addDir(self_agent_dir, "chat", false);
        const control = try self.addDir(chat, "control", false);
        const examples = try self.addDir(chat, "examples", false);
        self.chat_input_id = try self.addFile(control, "input", "", true, .chat_input);
        _ = try self.addFile(examples, "send.txt", "hello from acheron chat", false, .none);

        const chat_help_md =
            "# Chat Capability\n\n" ++
            "Write UTF-8 text to `control/input` to create a chat job.\n" ++
            "Read `/agents/self/jobs/<job-id>/result.txt` for assistant output.\n";
        _ = try self.addFile(chat, "README.md", chat_help_md, false, .none);
        _ = try self.addFile(chat, "SCHEMA.json", "{\"name\":\"chat\",\"input\":\"control/input\",\"jobs\":\"/agents/self/jobs\",\"result\":\"result.txt\"}", false, .none);
        _ = try self.addFile(chat, "CAPS.json", "{\"write_input\":true,\"read_jobs\":true}", false, .none);

        const escaped_agent = try unified.jsonEscape(self.allocator, self.agent_id);
        defer self.allocator.free(escaped_agent);
        const escaped_project = if (policy.project_id.len > 0) blk: {
            break :blk try unified.jsonEscape(self.allocator, policy.project_id);
        } else try self.allocator.dupe(u8, "");
        defer self.allocator.free(escaped_project);
        const chat_meta_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"name\":\"chat\",\"version\":\"1\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"cost_hint\":\"provider-dependent\",\"latency_hint\":\"seconds\"}}",
            .{ escaped_agent, escaped_project },
        );
        defer self.allocator.free(chat_meta_json);
        _ = try self.addFile(chat, "meta.json", chat_meta_json, false, .none);

        const agent_services_dir = try self.addDir(self_agent_dir, "services", false);
        try self.addDirectoryDescriptors(
            agent_services_dir,
            "Agent Services",
            "{\"kind\":\"service_index\",\"files\":[\"SERVICES.json\"],\"roots\":[\"/nodes/<node_id>/services/<service_id>\",\"/agents/self/services/contracts/<service_id>\"]}",
            "{\"discover\":true,\"invoke_via_paths\":true,\"contract_services\":true}",
            "Service discovery index for this agent. Use listed paths to inspect/invoke service endpoints.",
        );
        try self.seedAgentServiceContracts(agent_services_dir);
        const initial_agent_services_index = try self.buildAgentServicesIndexJson();
        defer self.allocator.free(initial_agent_services_index);
        self.agent_services_index_id = try self.addFile(
            agent_services_dir,
            "SERVICES.json",
            initial_agent_services_index,
            false,
            .agent_services_index,
        );

        const memory_dir = try self.addDir(self_agent_dir, "memory", false);
        try self.seedAgentMemoryNamespace(memory_dir);
        const web_search_dir = try self.addDir(self_agent_dir, "web_search", false);
        try self.seedAgentWebSearchNamespace(web_search_dir);

        self.jobs_root_id = try self.addDir(self_agent_dir, "jobs", false);
        try self.addDirectoryDescriptors(
            self.jobs_root_id,
            "Jobs",
            "{\"kind\":\"collection\",\"entries\":\"job_id\",\"files\":[\"status.json\",\"result.txt\",\"log.txt\"]}",
            "{\"read\":true,\"write\":false}",
            "Chat job status and outputs.",
        );
        try self.seedJobsFromIndex();

        const events_dir = try self.addDir(self_agent_dir, "events", false);
        const events_control_dir = try self.addDir(events_dir, "control", false);
        const events_help =
            "# Event Waiting\n\n" ++
            "1. Write selector JSON to `control/wait.json`.\n" ++
            "2. Read `next.json` to block until the first matching event.\n\n" ++
            "Single-event waits can also use a direct blocking read on that endpoint when supported.\n";
        _ = try self.addFile(events_dir, "README.md", events_help, false, .none);
        _ = try self.addFile(
            events_dir,
            "SCHEMA.json",
            "{\"wait_config\":{\"paths\":[\"/agents/self/chat/control/input\",\"/agents/self/jobs/<job-id>/status.json\"],\"timeout_ms\":60000},\"event\":{\"event_id\":1,\"source_path\":\"...\",\"event_path\":\"...\",\"updated_at_ms\":0,\"job\":{}}}",
            false,
            .none,
        );
        _ = try self.addFile(
            events_dir,
            "CAPS.json",
            "{\"sources\":[\"/agents/self/chat/control/input\",\"/agents/self/jobs/<job-id>/status.json\",\"/agents/self/jobs/<job-id>/result.txt\"],\"multi_wait\":true,\"single_blocking_read\":true}",
            false,
            .none,
        );
        _ = try self.addFile(
            events_control_dir,
            "README.md",
            "Write wait selector JSON to wait.json. Required: paths[]. Optional: timeout_ms.\n",
            false,
            .none,
        );
        _ = try self.addFile(
            events_control_dir,
            "wait.json",
            "{\"paths\":[],\"timeout_ms\":60000}",
            true,
            .event_wait_config,
        );
        self.event_next_id = try self.addFile(
            events_dir,
            "next.json",
            "{\"configured\":false,\"waiting\":false}",
            false,
            .event_next,
        );

        if (!std.mem.eql(u8, self.agent_id, "self")) {
            const agent_dir = try self.addDir(agents_root, self.agent_id, false);
            _ = try self.addFile(agent_dir, "README.md", "Primary agent path. Canonical interactive path is /agents/self.\n", false, .none);
            _ = try self.addFile(agent_dir, "LINK.txt", "/agents/self\n", false, .none);
        }

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
        try self.addDirectoryDescriptors(
            project_dir,
            "Project",
            "{\"kind\":\"project\",\"children\":[\"fs\",\"nodes\",\"agents\",\"meta\"]}",
            "{\"read\":true,\"write\":false}",
            "Project-composed world view.",
        );
        try self.addDirectoryDescriptors(
            project_fs_dir,
            "Project Mounts",
            "{\"kind\":\"collection\",\"entries\":\"mount links\",\"source\":\"control.workspace_status mounts\"}",
            "{\"read\":true,\"write\":false}",
            "Mount links for the active project workspace view.",
        );
        try self.addDirectoryDescriptors(
            project_nodes_dir,
            "Project Nodes",
            "{\"kind\":\"collection\",\"entries\":\"node links\",\"source\":\"control.workspace_status selected mounts\"}",
            "{\"read\":true,\"write\":false}",
            "Node links for the active project workspace view.",
        );
        try self.addDirectoryDescriptors(
            project_agents_dir,
            "Project Agents",
            "{\"kind\":\"collection\",\"entries\":\"agent links\",\"self\":\"/agents/self\"}",
            "{\"read\":true,\"write\":false}",
            "Agent links visible within this project context.",
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
            try self.addProjectFsLinksFromWorkspaceStatus(project_fs_dir, nodes_root, json)
        else
            false;
        if (!loaded_live_mounts) try self.addProjectFsLinksFromPolicy(project_fs_dir, policy);
        try self.addProjectNodeLinksFromPolicy(project_nodes_dir, policy);
        const loaded_live_nodes = if (workspace_status_json) |json|
            try self.addProjectNodeLinksFromWorkspaceStatus(project_nodes_dir, json)
        else
            false;

        _ = try self.addFile(project_agents_dir, "self", "/agents/self\n", false, .none);
        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
            const target = try std.fmt.allocPrint(self.allocator, "/agents/{s}\n", .{agent_name});
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
            _ = try self.addFile(dir_id, "stream.log", "", false, .none);
            try self.addDebugPairingSurface(dir_id);
        }

        try self.addDirectoryDescriptors(
            meta_root,
            "Meta",
            "{\"kind\":\"meta\",\"entries\":[\"protocol.json\",\"view.json\",\"workspace_status.json\",\"workspace_availability.json\",\"workspace_health.json\",\"workspace_alerts.json\"]}",
            "{\"read\":true,\"write\":false}",
            "Protocol and effective view metadata.",
        );
        const protocol_json =
            "{\"channel\":\"acheron\",\"version\":\"acheron-1\",\"layout\":\"world-v1\",\"ops\":[\"t_version\",\"t_attach\",\"t_walk\",\"t_open\",\"t_read\",\"t_write\",\"t_stat\",\"t_clunk\",\"t_flush\"]}";
        _ = try self.addFile(meta_root, "protocol.json", protocol_json, false, .none);
        const view_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"show_debug\":{s},\"nodes\":{d},\"visible_agents\":{d},\"project_links\":{d}}}",
            .{
                escaped_agent,
                escaped_project,
                if (policy.show_debug) "true" else "false",
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
    }

    fn addProjectMetaFiles(
        self: *Session,
        project_meta_dir: u32,
        policy: world_policy.Policy,
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

            var discovered = world_policy.NodePolicy{
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
        policy: world_policy.Policy,
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
            const mount_path_value = mount_value.object.get("mount_path") orelse continue;
            if (mount_path_value != .string or mount_path_value.string.len == 0) continue;

            try self.ensureWorkspaceNodeForProjectMount(nodes_root, node_id_value.string);
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

    fn addProjectNodeLinksFromPolicy(
        self: *Session,
        project_nodes_dir: u32,
        policy: world_policy.Policy,
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
            if (self.lookupChild(project_nodes_dir, node_id_value.string) != null) continue;
            const target = try std.fmt.allocPrint(self.allocator, "/nodes/{s}\n", .{node_id_value.string});
            defer self.allocator.free(target);
            _ = try self.addFile(project_nodes_dir, node_id_value.string, target, false, .none);
            added = true;
        }
        return added;
    }

    fn ensureWorkspaceNodeForProjectMount(
        self: *Session,
        nodes_root: u32,
        node_id: []const u8,
    ) !void {
        if (self.lookupChild(nodes_root, node_id)) |node_dir| {
            if (self.lookupChild(node_dir, "fs") == null) {
                _ = try self.addDir(node_dir, "fs", false);
            }
            return;
        }

        var discovered = world_policy.NodePolicy{
            .id = try self.allocator.dupe(u8, node_id),
            .resources = .{
                .fs = true,
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
        try self.addNodeDirectory(nodes_root, discovered, true);
    }

    fn addNodeDirectory(
        self: *Session,
        nodes_root: u32,
        node: world_policy.NodePolicy,
        discovered_from_workspace: bool,
    ) !void {
        const node_dir = try self.addDir(nodes_root, node.id, false);
        var resource_view = try self.addNodeServices(node_dir, node);
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

    fn seedAgentServiceContracts(self: *Session, agent_services_dir: u32) !void {
        const contracts_dir = try self.addDir(agent_services_dir, "contracts", false);
        try self.addDirectoryDescriptors(
            contracts_dir,
            "Agent Service Contracts",
            "{\"kind\":\"collection\",\"entries\":\"service_id\",\"shape\":\"/agents/self/services/contracts/<service_id>/{README.md,SCHEMA.json,CAPS.json,MOUNTS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/invoke.json}\"}",
            "{\"contract_only\":true,\"read\":true,\"write\":false}",
            "Contract-first definitions for runtime-managed services with invoke endpoints.",
        );
        try self.addAgentServiceContract(
            contracts_dir,
            "memory",
            "Memory Service Contract",
            "{\"model\":\"acheron.service.contract.v1\",\"service\":\"memory\",\"operations\":[\"memory_create\",\"memory_load\",\"memory_versions\",\"memory_mutate\",\"memory_evict\",\"memory_search\"]}",
            "{\"contract_only\":true,\"invoke\":true,\"operations\":[\"memory_create\",\"memory_load\",\"memory_versions\",\"memory_mutate\",\"memory_evict\",\"memory_search\"]}",
            "{\"model\":\"tool_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"runtime-tool\",\"operations\":{\"create\":\"memory_create\",\"load\":\"memory_load\",\"versions\":\"memory_versions\",\"mutate\":\"memory_mutate\",\"evict\":\"memory_evict\",\"search\":\"memory_search\"}}",
            "{\"type\":\"runtime_tool\",\"tool_family\":\"memory\"}",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
            "Memory tool bridge. Write JSON to control/invoke.json and read result.json/status.json.",
        );
        try self.addAgentServiceContract(
            contracts_dir,
            "web_search",
            "Web Search Service Contract",
            "{\"model\":\"acheron.service.contract.v1\",\"service\":\"web_search\",\"input\":{\"query\":\"string\"},\"output\":{\"results\":[{\"title\":\"string\",\"url\":\"string\",\"snippet\":\"string\"}]}}",
            "{\"contract_only\":true,\"invoke\":true,\"network\":true,\"search\":true}",
            "{\"model\":\"tool_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"runtime-tool\",\"operations\":{\"search\":\"web_search\"}}",
            "{\"type\":\"runtime_tool\",\"tool\":\"web_search\"}",
            "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\"}",
            "Web search tool bridge. Write JSON to control/invoke.json and read result.json/status.json.",
        );
    }

    fn addAgentServiceContract(
        self: *Session,
        contracts_dir: u32,
        service_id: []const u8,
        title: []const u8,
        schema_json: []const u8,
        caps_json: []const u8,
        ops_json: []const u8,
        runtime_json: []const u8,
        permissions_json: []const u8,
        instructions: []const u8,
    ) !void {
        const service_dir = try self.addDir(contracts_dir, service_id, false);
        try self.addDirectoryDescriptors(
            service_dir,
            title,
            schema_json,
            caps_json,
            instructions,
        );
        _ = try self.addFile(service_dir, "MOUNTS.json", "[]", false, .none);
        _ = try self.addFile(service_dir, "OPS.json", ops_json, false, .none);
        _ = try self.addFile(service_dir, "RUNTIME.json", runtime_json, false, .none);
        _ = try self.addFile(service_dir, "PERMISSIONS.json", permissions_json, false, .none);
        const control_dir = try self.addDir(service_dir, "control", false);
        _ = try self.addFile(
            control_dir,
            "README.md",
            "Write invoke payload JSON to invoke.json. Read result.json and status.json for outputs.\n",
            false,
            .none,
        );
        _ = try self.addFile(control_dir, "invoke.json", "", true, .agent_contract_invoke);
        const escaped_service_id = try unified.jsonEscape(self.allocator, service_id);
        defer self.allocator.free(escaped_service_id);
        const metadata_status_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"service_id\":\"{s}\",\"state\":\"contract\",\"has_invoke\":true}}",
            .{escaped_service_id},
        );
        defer self.allocator.free(metadata_status_json);
        _ = try self.addFile(service_dir, "STATUS.json", metadata_status_json, false, .none);
        _ = try self.addFile(service_dir, "status.json", "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}", false, .none);
        _ = try self.addFile(service_dir, "result.json", "{\"ok\":false,\"result\":null,\"error\":null}", false, .none);
    }

    fn seedAgentMemoryNamespace(self: *Session, memory_dir: u32) !void {
        try self.addDirectoryDescriptors(
            memory_dir,
            "Memory",
            "{\"kind\":\"service\",\"service_id\":\"memory\",\"shape\":\"/agents/self/memory/{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"memory_create\",\"memory_load\",\"memory_versions\",\"memory_mutate\",\"memory_evict\",\"memory_search\"],\"discoverable\":true}",
            "First-class memory namespace. Write operation payloads to control/*.json, then read status.json/result.json.",
        );
        _ = try self.addFile(
            memory_dir,
            "OPS.json",
            "{\"model\":\"tool_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"runtime-tool\",\"paths\":{\"create\":\"control/create.json\",\"load\":\"control/load.json\",\"versions\":\"control/versions.json\",\"mutate\":\"control/mutate.json\",\"evict\":\"control/evict.json\",\"search\":\"control/search.json\"},\"operations\":{\"create\":\"memory_create\",\"load\":\"memory_load\",\"versions\":\"memory_versions\",\"mutate\":\"memory_mutate\",\"evict\":\"memory_evict\",\"search\":\"memory_search\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            memory_dir,
            "RUNTIME.json",
            "{\"type\":\"runtime_tool\",\"tool_family\":\"memory\"}",
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
            "{\"service_id\":\"memory\",\"state\":\"namespace\",\"has_invoke\":true}",
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
        _ = try self.addFile(control_dir, "invoke.json", "", true, .agent_contract_invoke);
        _ = try self.addFile(control_dir, "create.json", "", true, .agent_contract_invoke);
        _ = try self.addFile(control_dir, "load.json", "", true, .agent_contract_invoke);
        _ = try self.addFile(control_dir, "versions.json", "", true, .agent_contract_invoke);
        _ = try self.addFile(control_dir, "mutate.json", "", true, .agent_contract_invoke);
        _ = try self.addFile(control_dir, "evict.json", "", true, .agent_contract_invoke);
        _ = try self.addFile(control_dir, "search.json", "", true, .agent_contract_invoke);
    }

    fn seedAgentWebSearchNamespace(self: *Session, web_search_dir: u32) !void {
        try self.addDirectoryDescriptors(
            web_search_dir,
            "Web Search",
            "{\"kind\":\"service\",\"service_id\":\"web_search\",\"shape\":\"/agents/self/web_search/{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}\"}",
            "{\"invoke\":true,\"operations\":[\"web_search\"],\"discoverable\":true,\"network\":true}",
            "First-class web search namespace. Write search payloads to control/search.json (or invoke.json), then read status.json/result.json.",
        );
        _ = try self.addFile(
            web_search_dir,
            "OPS.json",
            "{\"model\":\"tool_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"runtime-tool\",\"paths\":{\"search\":\"control/search.json\"},\"operations\":{\"search\":\"web_search\"}}",
            false,
            .none,
        );
        _ = try self.addFile(
            web_search_dir,
            "RUNTIME.json",
            "{\"type\":\"runtime_tool\",\"tool\":\"web_search\"}",
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
            "{\"service_id\":\"web_search\",\"state\":\"namespace\",\"has_invoke\":true}",
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
        _ = try self.addFile(control_dir, "invoke.json", "", true, .agent_contract_invoke);
        _ = try self.addFile(control_dir, "search.json", "", true, .agent_contract_invoke);
    }

    fn buildProjectTopologyJson(self: *Session, policy: world_policy.Policy) ![]u8 {
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

    fn buildFallbackProjectNodesJson(self: *Session, policy: world_policy.Policy) ![]u8 {
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

    fn buildProjectAgentsJson(self: *Session, policy: world_policy.Policy) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "[");
        try out.appendSlice(self.allocator, "{\"name\":\"self\",\"target\":\"/agents/self\",\"kind\":\"self\"}");
        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
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
            "{{\"version\":\"acheron-worldfs-project-contract-v1\",\"project_id\":\"{s}\",\"project_dirs\":[\"fs\",\"nodes\",\"agents\",\"meta\"],\"meta_files\":[\"topology.json\",\"nodes.json\",\"agents.json\",\"sources.json\",\"contracts.json\",\"paths.json\",\"summary.json\",\"alerts.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"],\"links\":{{\"fs\":\"/nodes/<node_id>/fs\",\"nodes\":\"/nodes/<node_id>\",\"agents\":\"/agents/<agent_id>\"}}}}",
            .{escaped_project_id},
        );
    }

    fn buildProjectPathsJson(self: *Session, policy: world_policy.Policy) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project_id);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_root\":\"/projects/{s}\",\"fs_root\":\"/projects/{s}/fs\",\"nodes_root\":\"/projects/{s}/nodes\",\"agents_root\":\"/projects/{s}/agents\",\"meta_root\":\"/projects/{s}/meta\",\"global\":{{\"nodes\":\"/nodes\",\"agents\":\"/agents\",\"meta\":\"/meta\",\"debug\":{s}}}}}",
            .{
                escaped_project_id,
                escaped_project_id,
                escaped_project_id,
                escaped_project_id,
                escaped_project_id,
                if (policy.show_debug) "\"/debug\"" else "null",
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
        policy: world_policy.Policy,
        workspace_status_json: ?[]const u8,
        loaded_live_mounts: bool,
        loaded_live_nodes: bool,
        nodes_meta_from_workspace: bool,
    ) ![]u8 {
        const escaped_project_id = try unified.jsonEscape(self.allocator, policy.project_id);
        defer self.allocator.free(escaped_project_id);

        var policy_agent_links: usize = 1;
        for (policy.visible_agents.items) |agent_name| {
            if (!std.mem.eql(u8, agent_name, "self")) policy_agent_links += 1;
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

    fn buildFallbackWorkspaceStatusJson(self: *Session, policy: world_policy.Policy) ![]u8 {
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
            service_id: []const u8,
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

                const maybe_terminal_id = if (std.mem.startsWith(u8, service_id, "terminal-") and service_id.len > "terminal-".len)
                    service_id["terminal-".len..]
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

    fn projectAllowsAction(self: *Session, action: fs_control_plane.ProjectAction) bool {
        const plane = self.control_plane orelse return true;
        const project_id = self.project_id orelse return true;
        return plane.projectAllowsAction(project_id, self.agent_id, action, self.project_token, self.is_admin);
    }

    fn canAccessServiceWithPermissions(self: *Session, permissions_json: []const u8) bool {
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

    fn canInvokeServiceDirectory(self: *Session, service_dir_id: u32) bool {
        const permissions_id = self.lookupChild(service_dir_id, "PERMISSIONS.json") orelse {
            return self.canAccessServiceWithPermissions("");
        };
        const permissions_node = self.nodes.get(permissions_id) orelse {
            return self.canAccessServiceWithPermissions("");
        };
        return self.canAccessServiceWithPermissions(permissions_node.content);
    }

    fn operationNameForInvokeFile(self: *Session, file_name: []const u8) ?[]const u8 {
        _ = self;
        if (std.mem.eql(u8, file_name, "invoke.json")) return null;
        if (std.mem.endsWith(u8, file_name, ".json")) {
            const op = file_name[0 .. file_name.len - ".json".len];
            if (op.len > 0) return op;
        }
        return null;
    }

    fn loadServiceInvokeMetadata(self: *Session, service_dir_id: u32) !ServiceInvokeMetadata {
        var metadata = ServiceInvokeMetadata{};
        errdefer metadata.deinit(self.allocator);

        if (self.lookupChild(service_dir_id, "RUNTIME.json")) |runtime_id| {
            if (self.nodes.get(runtime_id)) |runtime_node| {
                var runtime_parsed = std.json.parseFromSlice(std.json.Value, self.allocator, runtime_node.content, .{}) catch null;
                if (runtime_parsed) |*parsed| {
                    defer parsed.deinit();
                    if (parsed.value == .object) {
                        if (parsed.value.object.get("tool")) |tool_value| {
                            if (tool_value == .string and tool_value.string.len > 0) {
                                metadata.runtime_tool = try self.allocator.dupe(u8, tool_value.string);
                            }
                        }
                        if (parsed.value.object.get("tool_family")) |tool_family_value| {
                            if (tool_family_value == .string and tool_family_value.string.len > 0) {
                                metadata.runtime_tool_family = try self.allocator.dupe(u8, tool_family_value.string);
                            }
                        }
                    }
                }
            }
        }

        if (self.lookupChild(service_dir_id, "OPS.json")) |ops_id| {
            if (self.nodes.get(ops_id)) |ops_node| {
                var ops_parsed = std.json.parseFromSlice(std.json.Value, self.allocator, ops_node.content, .{}) catch null;
                if (ops_parsed) |*parsed| {
                    defer parsed.deinit();
                    if (parsed.value == .object) {
                        const operations_value = parsed.value.object.get("operations") orelse null;
                        if (operations_value != null and operations_value.? == .object) {
                            var it = operations_value.?.object.iterator();
                            while (it.next()) |entry| {
                                if (entry.value_ptr.* != .string or entry.value_ptr.*.string.len == 0) continue;
                                metadata.has_operation_mappings = true;
                                const op_name = try self.allocator.dupe(u8, entry.key_ptr.*);
                                errdefer self.allocator.free(op_name);
                                const runtime_tool = try self.allocator.dupe(u8, entry.value_ptr.*.string);
                                errdefer self.allocator.free(runtime_tool);
                                try metadata.operation_tools.putNoClobber(self.allocator, op_name, runtime_tool);
                            }
                        }
                    }
                }
            }
        }

        return metadata;
    }

    fn appendServiceIndexEntry(
        self: *Session,
        out: *std.ArrayListUnmanaged(u8),
        first: *bool,
        service_id: []const u8,
        kind: []const u8,
        state: []const u8,
        endpoint: []const u8,
    ) !void {
        if (!first.*) try out.append(self.allocator, ',');
        first.* = false;
        const escaped_service_id = try unified.jsonEscape(self.allocator, service_id);
        defer self.allocator.free(escaped_service_id);
        const escaped_kind = try unified.jsonEscape(self.allocator, kind);
        defer self.allocator.free(escaped_kind);
        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const escaped_endpoint = try unified.jsonEscape(self.allocator, endpoint);
        defer self.allocator.free(escaped_endpoint);
        try out.writer(self.allocator).print(
            "{{\"service_id\":\"{s}\",\"kind\":\"{s}\",\"state\":\"{s}\",\"endpoint\":\"{s}\"}}",
            .{ escaped_service_id, escaped_kind, escaped_state, escaped_endpoint },
        );
    }

    fn addNodeServices(self: *Session, node_dir: u32, node: world_policy.NodePolicy) !NodeResourceView {
        var view = NodeResourceView{};
        errdefer view.deinit(self.allocator);

        const services_root = try self.addDir(node_dir, "services", false);
        try self.addDirectoryDescriptors(
            services_root,
            "Node Services",
            "{\"kind\":\"collection\",\"entries\":\"service_id\",\"shape\":\"/nodes/<node_id>/services/<service_id>/{SCHEMA.json,STATUS.json,CAPS.json,MOUNTS.json,OPS.json,RUNTIME.json,PERMISSIONS.json}\"}",
            "{\"read\":true,\"write\":false}",
            "Node service descriptors. This view prefers control-plane catalog data and falls back to policy.",
        );
        var services_index = std.ArrayListUnmanaged(u8){};
        defer services_index.deinit(self.allocator);
        try services_index.append(self.allocator, '[');
        var services_index_first = true;

        switch (try self.loadNodeServicesFromControlPlane(node.id)) {
            .catalog => |catalog_value| {
                var catalog = catalog_value;
                defer catalog.deinit(self.allocator);
                for (catalog.items.items) |service| {
                    if (!self.canAccessServiceWithPermissions(service.permissions_json)) continue;
                    try self.addNodeServiceEntry(
                        services_root,
                        service.service_id,
                        service.kind,
                        service.state,
                        service.endpoint,
                        service.caps_json,
                        service.mounts_json,
                        service.ops_json,
                        service.runtime_json,
                        service.permissions_json,
                        service.schema_json,
                        service.help_md,
                    );
                    try view.observe(
                        self.allocator,
                        node.id,
                        service.kind,
                        service.service_id,
                        service.endpoint,
                        service.mounts_json,
                    );
                    try self.appendServiceIndexEntry(
                        &services_index,
                        &services_index_first,
                        service.service_id,
                        service.kind,
                        service.state,
                        service.endpoint,
                    );
                }
                try services_index.append(self.allocator, ']');
                const services_index_json = try services_index.toOwnedSlice(self.allocator);
                defer self.allocator.free(services_index_json);
                _ = try self.addFile(services_root, "SERVICES.json", services_index_json, false, .none);
                return view;
            },
            .empty => {
                try services_index.append(self.allocator, ']');
                const services_index_json = try services_index.toOwnedSlice(self.allocator);
                defer self.allocator.free(services_index_json);
                _ = try self.addFile(services_root, "SERVICES.json", services_index_json, false, .none);
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
            if (self.canAccessServiceWithPermissions(permissions)) {
                try self.addNodeServiceEntry(
                    services_root,
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
                try self.appendServiceIndexEntry(&services_index, &services_index_first, "fs", "fs", "online", endpoint);
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
            if (self.canAccessServiceWithPermissions(permissions)) {
                try self.addNodeServiceEntry(
                    services_root,
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
                try self.appendServiceIndexEntry(&services_index, &services_index_first, "camera", "camera", "online", endpoint);
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
            if (self.canAccessServiceWithPermissions(permissions)) {
                try self.addNodeServiceEntry(
                    services_root,
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
                try self.appendServiceIndexEntry(&services_index, &services_index_first, "screen", "screen", "online", endpoint);
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
            if (self.canAccessServiceWithPermissions(permissions)) {
                try self.addNodeServiceEntry(
                    services_root,
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
                try self.appendServiceIndexEntry(&services_index, &services_index_first, "user", "user", "online", endpoint);
            }
        }

        for (node.terminals.items) |terminal_id| {
            const service_id = try std.fmt.allocPrint(self.allocator, "terminal-{s}", .{terminal_id});
            defer self.allocator.free(service_id);
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
                .{ service_id, node.id, terminal_id },
            );
            defer self.allocator.free(mounts);
            const permissions = "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"node\"}";
            if (self.canAccessServiceWithPermissions(permissions)) {
                try self.addNodeServiceEntry(
                    services_root,
                    service_id,
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
                try view.observe(self.allocator, node.id, "terminal", service_id, endpoint, mounts);
                try self.appendServiceIndexEntry(&services_index, &services_index_first, service_id, "terminal", "online", endpoint);
            }
        }

        try services_index.append(self.allocator, ']');
        const services_index_json = try services_index.toOwnedSlice(self.allocator);
        defer self.allocator.free(services_index_json);
        _ = try self.addFile(services_root, "SERVICES.json", services_index_json, false, .none);
        return view;
    }

    const NodeServiceCatalog = struct {
        const Entry = struct {
            service_id: []u8,
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
                allocator.free(self.service_id);
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

        fn deinit(self: *NodeServiceCatalog, allocator: std.mem.Allocator) void {
            for (self.items.items) |*item| item.deinit(allocator);
            self.items.deinit(allocator);
            self.* = undefined;
        }
    };

    const NodeServiceCatalogResult = union(enum) {
        unavailable,
        empty,
        catalog: NodeServiceCatalog,
    };

    fn loadNodeServicesFromControlPlane(self: *Session, node_id: []const u8) !NodeServiceCatalogResult {
        const plane = self.control_plane orelse return .unavailable;
        const escaped_node_id = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node_id);
        const request_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"node_id\":\"{s}\"}}",
            .{escaped_node_id},
        );
        defer self.allocator.free(request_json);

        const response_json = plane.nodeServiceGet(request_json) catch return .unavailable;
        defer self.allocator.free(response_json);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, response_json, .{}) catch return .unavailable;
        defer parsed.deinit();
        if (parsed.value != .object) return .unavailable;
        const services_val = parsed.value.object.get("services") orelse return .unavailable;
        if (services_val != .array) return .unavailable;
        if (services_val.array.items.len == 0) return .empty;

        var catalog = NodeServiceCatalog{};
        errdefer catalog.deinit(self.allocator);

        for (services_val.array.items) |item| {
            if (item != .object) continue;
            const service_id_val = item.object.get("service_id") orelse continue;
            if (service_id_val != .string or service_id_val.string.len == 0) continue;
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
                try std.fmt.allocPrint(self.allocator, "/nodes/{s}/{s}", .{ node_id, service_id_val.string });
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
                .service_id = try self.allocator.dupe(u8, service_id_val.string),
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

    fn addNodeServiceEntry(
        self: *Session,
        services_root: u32,
        service_id: []const u8,
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
        const service_dir = try self.addDir(services_root, service_id, false);

        const escaped_service_id = try unified.jsonEscape(self.allocator, service_id);
        defer self.allocator.free(escaped_service_id);
        const escaped_kind = try unified.jsonEscape(self.allocator, kind);
        defer self.allocator.free(escaped_kind);
        const escaped_state = try unified.jsonEscape(self.allocator, state);
        defer self.allocator.free(escaped_state);
        const escaped_endpoint = try unified.jsonEscape(self.allocator, endpoint);
        defer self.allocator.free(escaped_endpoint);

        const readme = if (help_md) |value|
            value
        else
            "# Service metadata for this node capability.\n";
        _ = try self.addFile(service_dir, "README.md", readme, false, .none);
        _ = try self.addFile(service_dir, "SCHEMA.json", schema_json, false, .none);
        _ = try self.addFile(service_dir, "CAPS.json", caps_json, false, .none);
        _ = try self.addFile(service_dir, "MOUNTS.json", mounts_json, false, .none);
        _ = try self.addFile(service_dir, "OPS.json", ops_json, false, .none);
        _ = try self.addFile(service_dir, "RUNTIME.json", runtime_json, false, .none);
        _ = try self.addFile(service_dir, "PERMISSIONS.json", permissions_json, false, .none);

        const status = try std.fmt.allocPrint(
            self.allocator,
            "{{\"service_id\":\"{s}\",\"kind\":\"{s}\",\"state\":\"{s}\",\"endpoint\":\"{s}\"}}",
            .{ escaped_service_id, escaped_kind, escaped_state, escaped_endpoint },
        );
        defer self.allocator.free(status);
        _ = try self.addFile(service_dir, "STATUS.json", status, false, .none);
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

    fn handlePairingControlWrite(self: *Session, action: PairingAction, raw_input: []const u8) !WriteOutcome {
        const written = raw_input.len;
        const payload = std.mem.trim(u8, raw_input, " \t\r\n");
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

        const escaped = try unified.jsonEscape(self.allocator, input);
        defer self.allocator.free(escaped);
        const runtime_req = if (correlation_id) |value| blk: {
            const escaped_corr = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped_corr);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"id\":\"{s}\",\"type\":\"session.send\",\"content\":\"{s}\",\"correlation_id\":\"{s}\"}}",
                .{ job_name, escaped, escaped_corr },
            );
        } else try std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":\"{s}\",\"type\":\"session.send\",\"content\":\"{s}\"}}",
            .{ job_name, escaped },
        );
        defer self.allocator.free(runtime_req);

        var log_buf = std.ArrayListUnmanaged(u8){};
        defer log_buf.deinit(self.allocator);

        var result_text = try self.allocator.dupe(u8, "");
        defer self.allocator.free(result_text);

        var failed = false;
        var failure_message: []const u8 = "";
        var failure_message_owned: ?[]u8 = null;
        defer if (failure_message_owned) |owned| self.allocator.free(owned);

        var responses: ?[][]u8 = null;
        if (self.runtime_handle.handleMessageFramesWithDebug(runtime_req, self.debug_stream_enabled)) |frames| {
            responses = frames;
        } else |err| {
            failed = true;
            if (failure_message_owned) |owned| {
                self.allocator.free(owned);
                failure_message_owned = null;
            }
            failure_message = @errorName(err);
        }
        defer if (responses) |frames| runtime_server_mod.deinitResponseFrames(self.allocator, frames);

        if (responses) |frames| {
            for (frames) |frame| {
                try log_buf.appendSlice(self.allocator, frame);
                try log_buf.append(self.allocator, '\n');
                if (self.debug_stream_enabled and std.mem.indexOf(u8, frame, "\"type\":\"debug.event\"") != null) {
                    try self.pending_debug_frames.append(self.allocator, try self.allocator.dupe(u8, frame));
                }

                const maybe = std.json.parseFromSlice(std.json.Value, self.allocator, frame, .{}) catch null;
                if (maybe) |parsed| {
                    defer parsed.deinit();
                    if (parsed.value != .object) continue;
                    const obj = parsed.value.object;
                    const type_value = obj.get("type") orelse continue;
                    if (type_value != .string) continue;

                    if (std.mem.eql(u8, type_value.string, "session.receive")) {
                        if (obj.get("content")) |content| {
                            if (content == .string) {
                                self.allocator.free(result_text);
                                result_text = try self.allocator.dupe(u8, content.string);
                            }
                        } else if (obj.get("payload")) |payload| {
                            if (payload == .object) {
                                if (payload.object.get("content")) |content| {
                                    if (content == .string) {
                                        self.allocator.free(result_text);
                                        result_text = try self.allocator.dupe(u8, content.string);
                                    }
                                }
                            }
                        }
                    } else if (std.mem.eql(u8, type_value.string, "error")) {
                        failed = true;
                        if (obj.get("message")) |err_msg| {
                            if (err_msg == .string) {
                                if (failure_message_owned) |owned| self.allocator.free(owned);
                                failure_message_owned = try self.allocator.dupe(u8, err_msg.string);
                                failure_message = failure_message_owned.?;
                            }
                        }
                    }
                }
            }
        }

        if (failed) {
            const status = try self.buildJobStatusJson(.failed, correlation_id, failure_message);
            defer self.allocator.free(status);
            try self.setFileContent(status_id, status);
            try self.setFileContent(result_id, failure_message);
        } else {
            const status = try self.buildJobStatusJson(.done, correlation_id, null);
            defer self.allocator.free(status);
            try self.setFileContent(status_id, status);
            try self.setFileContent(result_id, result_text);
        }

        const log_content = try log_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(log_content);
        try self.setFileContent(log_id, log_content);
        self.job_index.markCompleted(
            job_name,
            !failed,
            if (failed) failure_message else result_text,
            if (failed) failure_message else null,
            log_content,
        ) catch |err| {
            std.log.warn("chat job index completion update failed: {s}", .{@errorName(err)});
        };

        return .{
            .written = raw_input.len,
            .job_name = try self.allocator.dupe(u8, job_name),
            .correlation_id = if (correlation_id) |value| try self.allocator.dupe(u8, value) else null,
        };
    }

    fn handleAgentContractInvokeWrite(self: *Session, invoke_node_id: u32, raw_input: []const u8) !WriteOutcome {
        const invoke_node = self.nodes.get(invoke_node_id) orelse return error.MissingNode;
        const control_dir_id = invoke_node.parent orelse return error.MissingNode;
        const service_dir_id = (self.nodes.get(control_dir_id) orelse return error.MissingNode).parent orelse return error.MissingNode;
        if (!self.canInvokeServiceDirectory(service_dir_id)) return error.AccessDenied;
        const status_runtime_id = self.lookupChild(service_dir_id, "status.json") orelse return error.MissingNode;
        const result_id = self.lookupChild(service_dir_id, "result.json") orelse return error.MissingNode;

        const parsed = self.parseAgentContractInvokeRequest(service_dir_id, invoke_node.name, raw_input) catch return error.InvalidPayload;
        var request = parsed;
        defer request.deinit(self.allocator);

        const invoke_text = std.mem.trim(u8, raw_input, " \t\r\n");
        try self.setFileContent(invoke_node_id, invoke_text);

        const running_status = try self.buildContractInvokeStatusJson("running", request.tool_name, null);
        defer self.allocator.free(running_status);
        try self.setFileContent(status_runtime_id, running_status);

        const result_payload = try self.executeAgentContractToolCall(request.tool_name, request.args_json);
        defer self.allocator.free(result_payload);
        var failed = false;
        var failure_message: ?[]u8 = null;
        defer if (failure_message) |value| self.allocator.free(value);

        if (try self.extractErrorMessageFromToolPayload(result_payload)) |message| {
            failed = true;
            failure_message = message;
        }

        if (failed) {
            const status = try self.buildContractInvokeStatusJson("failed", request.tool_name, failure_message.?);
            defer self.allocator.free(status);
            try self.setFileContent(status_runtime_id, status);
        } else {
            const status = try self.buildContractInvokeStatusJson("done", request.tool_name, null);
            defer self.allocator.free(status);
            try self.setFileContent(status_runtime_id, status);
        }
        try self.setFileContent(result_id, result_payload);
        return .{ .written = raw_input.len };
    }

    fn parseAgentContractInvokeRequest(
        self: *Session,
        service_dir_id: u32,
        invoke_file_name: []const u8,
        raw_input: []const u8,
    ) !ContractInvokeRequest {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) return error.InvalidPayload;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const obj = parsed.value.object;

        const explicit_tool = blk: {
            if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
            break :blk null;
        };

        const operation_name = self.operationNameForInvokeFile(invoke_file_name);
        var metadata = try self.loadServiceInvokeMetadata(service_dir_id);
        defer metadata.deinit(self.allocator);

        const tool_name_owned = if (explicit_tool) |value|
            try self.allocator.dupe(u8, value)
        else if (operation_name) |op|
            if (metadata.toolForOperation(op)) |mapped| try self.allocator.dupe(u8, mapped) else if (metadata.runtime_tool) |runtime_tool| try self.allocator.dupe(u8, runtime_tool) else return error.InvalidPayload
        else if (metadata.runtime_tool) |runtime_tool|
            try self.allocator.dupe(u8, runtime_tool)
        else
            return error.InvalidPayload;
        errdefer self.allocator.free(tool_name_owned);

        if (!metadata.allowsTool(operation_name, tool_name_owned)) return error.InvalidPayload;

        const args_json = if (obj.get("arguments")) |value|
            try self.renderJsonValue(value)
        else if (obj.get("args")) |value|
            try self.renderJsonValue(value)
        else if (explicit_tool == null)
            try self.renderJsonValue(parsed.value)
        else
            try self.allocator.dupe(u8, "{}");

        return .{
            .tool_name = tool_name_owned,
            .args_json = args_json,
        };
    }

    fn renderJsonValue(self: *Session, value: std.json.Value) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(value, .{})});
    }

    fn executeAgentContractToolCall(self: *Session, tool_name: []const u8, args_json: []const u8) ![]u8 {
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
            "contract-invoke-{s}-{d}",
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
        if (self.runtime_handle.handleMessageFramesWithDebug(runtime_req, self.debug_stream_enabled)) |frames| {
            responses = frames;
        } else |err| {
            return self.buildContractInvokeFailureResultJson("runtime_error", @errorName(err));
        }
        defer if (responses) |frames| runtime_server_mod.deinitResponseFrames(self.allocator, frames);

        var content_payload: ?[]u8 = null;
        defer if (content_payload) |value| self.allocator.free(value);

        if (responses) |frames| {
            for (frames) |frame| {
                if (self.debug_stream_enabled and std.mem.indexOf(u8, frame, "\"type\":\"debug.event\"") != null) {
                    try self.pending_debug_frames.append(self.allocator, try self.allocator.dupe(u8, frame));
                }

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
                    return self.buildContractInvokeFailureResultJson(code, message);
                }
            }
        }

        if (content_payload) |payload| {
            var payload_parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch {
                return self.buildContractInvokeFailureResultJson("invalid_result_payload", "tool payload was not valid JSON");
            };
            payload_parsed.deinit();
            return self.allocator.dupe(u8, payload);
        }
        return self.buildContractInvokeFailureResultJson("missing_result", "tool call produced no session.receive payload");
    }

    fn buildContractInvokeStatusJson(
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

    fn buildContractInvokeFailureResultJson(self: *Session, code: []const u8, message: []const u8) ![]u8 {
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

    fn waitForJobTerminalState(self: *Session, node_id: u32) !void {
        const node = self.nodes.get(node_id) orelse return error.MissingNode;
        const job_dir_id = node.parent orelse return;
        const job_dir = self.nodes.get(job_dir_id) orelse return error.MissingNode;
        const job_id = job_dir.name;

        const timeout_ms = if (self.wait_timeout_ms > 0) self.wait_timeout_ms else default_wait_timeout_ms;
        const start_ms = std.time.milliTimestamp();
        while (true) {
            const owned_view = try self.job_index.getJob(self.allocator, job_id);
            if (owned_view) |owned| {
                var view = owned;
                defer view.deinit(self.allocator);
                if (!std.mem.eql(u8, view.agent_id, self.agent_id)) return;
                if (isTerminalJobState(view.state)) return;
            } else {
                return;
            }

            if (timeout_ms == 0) return;
            const elapsed_ms = std.time.milliTimestamp() - start_ms;
            if (elapsed_ms >= timeout_ms) return;
            const remaining_ms = timeout_ms - elapsed_ms;
            const poll_ms = @as(i64, @intCast(wait_poll_interval_ms));
            const sleep_ms = if (remaining_ms < poll_ms) remaining_ms else poll_ms;
            std.Thread.sleep(@as(u64, @intCast(sleep_ms)) * std.time.ns_per_ms);
        }
    }

    fn clearWaitSources(self: *Session) void {
        for (self.wait_sources.items) |*source| source.deinit(self.allocator);
        self.wait_sources.deinit(self.allocator);
        self.wait_sources = .{};
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

    fn parseWaitSourcePath(self: *Session, path: []const u8) !WaitSource {
        if (std.mem.eql(u8, path, "/agents/self/chat/control/input") or
            std.mem.endsWith(u8, path, "/agents/self/chat/control/input"))
        {
            return .{
                .raw_path = try self.allocator.dupe(u8, path),
                .kind = .chat_input,
            };
        }

        if (std.mem.indexOf(u8, path, "/agents/self/jobs/")) |prefix_index| {
            const prefix = "/agents/self/jobs/";
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

    fn initializeWaitSourceCursor(self: *Session, source: *WaitSource) !void {
        source.last_seen_updated_at_ms = 0;
        switch (source.kind) {
            .chat_input => {
                const jobs = try self.job_index.listJobsForAgent(self.allocator, self.agent_id);
                defer chat_job_index.deinitJobViews(self.allocator, jobs);
                var max_seen: i64 = 0;
                for (jobs) |job| {
                    if (!isTerminalJobState(job.state)) continue;
                    if (job.updated_at_ms > max_seen) max_seen = job.updated_at_ms;
                }
                source.last_seen_updated_at_ms = max_seen;
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
            if (try self.pollWaitSources()) |candidate_owned| {
                var candidate = candidate_owned;
                defer candidate.deinit(self.allocator);

                var source = &self.wait_sources.items[candidate.source_index];
                source.last_seen_updated_at_ms = candidate.view.updated_at_ms;
                const payload = try self.buildWaitEventPayload(source.raw_path, candidate.event_path, candidate.view);
                return payload;
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
                    if (candidate.view.updated_at_ms < current.view.updated_at_ms) {
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
        };
    }

    fn buildJobPathCandidate(self: *Session, source: WaitSource, source_index: usize) !?WaitCandidate {
        const job_id = source.job_id orelse return null;
        const owned_view = try self.job_index.getJob(self.allocator, job_id);
        if (owned_view == null) return null;

        var view = owned_view.?;
        errdefer view.deinit(self.allocator);
        if (!std.mem.eql(u8, view.agent_id, self.agent_id)) return null;
        if (!isTerminalJobState(view.state)) return null;
        if (view.updated_at_ms <= source.last_seen_updated_at_ms) return null;

        const event_path = switch (source.kind) {
            .job_status => try std.fmt.allocPrint(self.allocator, "/agents/self/jobs/{s}/status.json", .{view.job_id}),
            .job_result => try std.fmt.allocPrint(self.allocator, "/agents/self/jobs/{s}/result.txt", .{view.job_id}),
            else => unreachable,
        };
        return .{
            .source_index = source_index,
            .event_path = event_path,
            .view = view,
        };
    }

    fn buildChatInputCandidate(self: *Session, source: WaitSource, source_index: usize) !?WaitCandidate {
        const jobs = try self.job_index.listJobsForAgent(self.allocator, self.agent_id);
        if (jobs.len == 0) {
            chat_job_index.deinitJobViews(self.allocator, jobs);
            return null;
        }

        var selected_idx: ?usize = null;
        var selected_updated_at_ms: i64 = 0;
        for (jobs, 0..) |job, idx| {
            if (!isTerminalJobState(job.state)) continue;
            if (job.updated_at_ms <= source.last_seen_updated_at_ms) continue;
            if (selected_idx == null or job.updated_at_ms < selected_updated_at_ms) {
                selected_idx = idx;
                selected_updated_at_ms = job.updated_at_ms;
            }
        }

        if (selected_idx == null) {
            chat_job_index.deinitJobViews(self.allocator, jobs);
            return null;
        }

        const chosen_idx = selected_idx.?;
        const selected = jobs[chosen_idx];
        for (jobs, 0..) |*job, idx| {
            if (idx == chosen_idx) continue;
            job.deinit(self.allocator);
        }
        self.allocator.free(jobs);

        const event_path = try std.fmt.allocPrint(self.allocator, "/agents/self/jobs/{s}/status.json", .{selected.job_id});
        return .{
            .source_index = source_index,
            .event_path = event_path,
            .view = selected,
        };
    }

    fn buildWaitEventPayload(
        self: *Session,
        source_path: []const u8,
        event_path: []const u8,
        view: chat_job_index.JobView,
    ) ![]u8 {
        const source_path_escaped = try unified.jsonEscape(self.allocator, source_path);
        defer self.allocator.free(source_path_escaped);
        const event_path_escaped = try unified.jsonEscape(self.allocator, event_path);
        defer self.allocator.free(event_path_escaped);
        const job_id_escaped = try unified.jsonEscape(self.allocator, view.job_id);
        defer self.allocator.free(job_id_escaped);
        const state_escaped = try unified.jsonEscape(self.allocator, jobStateLabel(view.state));
        defer self.allocator.free(state_escaped);
        const status_path = try std.fmt.allocPrint(self.allocator, "/agents/self/jobs/{s}/status.json", .{view.job_id});
        defer self.allocator.free(status_path);
        const result_path = try std.fmt.allocPrint(self.allocator, "/agents/self/jobs/{s}/result.txt", .{view.job_id});
        defer self.allocator.free(result_path);
        const status_path_escaped = try unified.jsonEscape(self.allocator, status_path);
        defer self.allocator.free(status_path_escaped);
        const result_path_escaped = try unified.jsonEscape(self.allocator, result_path);
        defer self.allocator.free(result_path_escaped);

        const correlation_json = if (view.correlation_id) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(correlation_json);

        const result_json = if (view.result_text) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(result_json);

        const error_json = if (view.error_text) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(error_json);

        const event_id = self.wait_event_seq;
        self.wait_event_seq +%= 1;
        if (self.wait_event_seq == 0) self.wait_event_seq = 1;

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"configured\":true,\"waiting\":false,\"event_id\":{d},\"source_path\":\"{s}\",\"event_path\":\"{s}\",\"updated_at_ms\":{d},\"job\":{{\"job_id\":\"{s}\",\"state\":\"{s}\",\"correlation_id\":{s},\"status_path\":\"{s}\",\"result_path\":\"{s}\",\"result\":{s},\"error\":{s}}}}}",
            .{
                event_id,
                source_path_escaped,
                event_path_escaped,
                view.updated_at_ms,
                job_id_escaped,
                state_escaped,
                correlation_json,
                status_path_escaped,
                result_path_escaped,
                result_json,
                error_json,
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

    fn refreshAgentServicesIndex(self: *Session, node_id: u32) !void {
        const index_json = try self.buildAgentServicesIndexJson();
        defer self.allocator.free(index_json);
        try self.setFileContent(node_id, index_json);
    }

    fn buildAgentServicesIndexJson(self: *Session) ![]u8 {
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

            const services_root_id = self.lookupChild(node_dir_id, "services") orelse continue;
            const services_root = self.nodes.get(services_root_id) orelse continue;
            if (services_root.kind != .dir) continue;

            var service_it = services_root.children.iterator();
            while (service_it.next()) |service_entry| {
                const service_id = service_entry.key_ptr.*;
                const service_dir_id = service_entry.value_ptr.*;
                const service_dir = self.nodes.get(service_dir_id) orelse continue;
                if (service_dir.kind != .dir) continue;

                const service_path = try std.fmt.allocPrint(
                    self.allocator,
                    "/nodes/{s}/services/{s}",
                    .{ node_id, service_id },
                );
                defer self.allocator.free(service_path);
                const invoke_path = try self.deriveServiceInvokePath(node_id, service_id, service_dir_id);
                defer if (invoke_path) |value| self.allocator.free(value);

                try self.appendAgentServiceIndexEntry(
                    &out,
                    &first,
                    node_id,
                    service_id,
                    service_path,
                    invoke_path,
                    "node",
                );
            }
        }

        try self.appendAgentNamespaceServiceIndexEntries(&out, &first);
        try self.appendAgentContractServiceIndexEntries(&out, &first);
        try out.append(self.allocator, ']');
        return out.toOwnedSlice(self.allocator);
    }

    fn appendAgentServiceIndexEntry(
        self: *Session,
        out: *std.ArrayListUnmanaged(u8),
        first: *bool,
        node_id: []const u8,
        service_id: []const u8,
        service_path: []const u8,
        invoke_path: ?[]const u8,
        scope: []const u8,
    ) !void {
        const escaped_node_id = try unified.jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_node_id);
        const escaped_service_id = try unified.jsonEscape(self.allocator, service_id);
        defer self.allocator.free(escaped_service_id);
        const escaped_service_path = try unified.jsonEscape(self.allocator, service_path);
        defer self.allocator.free(escaped_service_path);
        const escaped_scope = try unified.jsonEscape(self.allocator, scope);
        defer self.allocator.free(escaped_scope);

        const invoke_json = if (invoke_path) |value| blk: {
            const escaped = try unified.jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(invoke_json);

        if (!first.*) try out.append(self.allocator, ',');
        first.* = false;
        try out.writer(self.allocator).print(
            "{{\"node_id\":\"{s}\",\"service_id\":\"{s}\",\"service_path\":\"{s}\",\"invoke_path\":{s},\"has_invoke\":{s},\"scope\":\"{s}\"}}",
            .{
                escaped_node_id,
                escaped_service_id,
                escaped_service_path,
                invoke_json,
                if (invoke_path != null) "true" else "false",
                escaped_scope,
            },
        );
    }

    fn appendAgentContractServiceIndexEntries(
        self: *Session,
        out: *std.ArrayListUnmanaged(u8),
        first: *bool,
    ) !void {
        const agents_root = self.lookupChild(self.root_id, "agents") orelse return;
        const self_agent_dir = self.lookupChild(agents_root, "self") orelse return;
        const services_dir = self.lookupChild(self_agent_dir, "services") orelse return;
        const contracts_dir = self.lookupChild(services_dir, "contracts") orelse return;
        const contracts_node = self.nodes.get(contracts_dir) orelse return;
        if (contracts_node.kind != .dir) return;

        var contract_it = contracts_node.children.iterator();
        while (contract_it.next()) |entry| {
            const contract_id = entry.key_ptr.*;
            const contract_dir_id = entry.value_ptr.*;
            const contract_dir = self.nodes.get(contract_dir_id) orelse continue;
            if (contract_dir.kind != .dir) continue;

            const service_path = try std.fmt.allocPrint(
                self.allocator,
                "/agents/self/services/contracts/{s}",
                .{contract_id},
            );
            defer self.allocator.free(service_path);
            const invoke_path = if (self.serviceCapsInvoke(contract_dir_id))
                try self.pathWithInvokeSuffix(service_path)
            else
                null;
            defer if (invoke_path) |value| self.allocator.free(value);
            try self.appendAgentServiceIndexEntry(
                out,
                first,
                "self",
                contract_id,
                service_path,
                invoke_path,
                "agent_contract",
            );
        }
    }

    fn appendAgentNamespaceServiceIndexEntries(
        self: *Session,
        out: *std.ArrayListUnmanaged(u8),
        first: *bool,
    ) !void {
        const agents_root = self.lookupChild(self.root_id, "agents") orelse return;
        const self_agent_dir = self.lookupChild(agents_root, "self") orelse return;
        const namespace_services = [_][]const u8{ "memory", "web_search" };
        for (namespace_services) |service_id| {
            const service_dir_id = self.lookupChild(self_agent_dir, service_id) orelse continue;
            const service_dir = self.nodes.get(service_dir_id) orelse continue;
            if (service_dir.kind != .dir) continue;

            const service_path = try std.fmt.allocPrint(
                self.allocator,
                "/agents/self/{s}",
                .{service_id},
            );
            defer self.allocator.free(service_path);

            const invoke_path = if (self.serviceCapsInvoke(service_dir_id))
                try self.pathWithInvokeSuffix(service_path)
            else
                null;
            defer if (invoke_path) |value| self.allocator.free(value);

            try self.appendAgentServiceIndexEntry(
                out,
                first,
                "self",
                service_id,
                service_path,
                invoke_path,
                "agent_namespace",
            );
        }
    }

    fn deriveServiceInvokePath(
        self: *Session,
        node_id: []const u8,
        service_id: []const u8,
        service_dir_id: u32,
    ) !?[]u8 {
        if (!self.serviceCapsInvoke(service_dir_id)) return null;

        if (try self.firstServiceMountPath(service_dir_id)) |mount_path| {
            defer self.allocator.free(mount_path);
            return try self.pathWithInvokeSuffix(mount_path);
        }

        if (try self.serviceEndpointPath(service_dir_id)) |endpoint_path| {
            defer self.allocator.free(endpoint_path);
            return try self.pathWithInvokeSuffix(endpoint_path);
        }

        return try std.fmt.allocPrint(
            self.allocator,
            "/nodes/{s}/services/{s}/control/invoke.json",
            .{ node_id, service_id },
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

    fn firstServiceMountPath(self: *Session, service_dir_id: u32) !?[]u8 {
        const mounts_id = self.lookupChild(service_dir_id, "MOUNTS.json") orelse return null;
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

    fn serviceEndpointPath(self: *Session, service_dir_id: u32) !?[]u8 {
        const status_id = self.lookupChild(service_dir_id, "STATUS.json") orelse return null;
        const status_node = self.nodes.get(status_id) orelse return null;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, status_node.content, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const endpoint_value = parsed.value.object.get("endpoint") orelse return null;
        if (endpoint_value != .string or endpoint_value.string.len == 0) return null;
        return try self.allocator.dupe(u8, endpoint_value.string);
    }

    fn serviceCapsInvoke(self: *Session, service_dir_id: u32) bool {
        const caps_id = self.lookupChild(service_dir_id, "CAPS.json") orelse return false;
        const caps_node = self.nodes.get(caps_id) orelse return false;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, caps_node.content, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        const invoke_value = parsed.value.object.get("invoke") orelse return false;
        return invoke_value == .bool and invoke_value.bool;
    }

    fn clearPendingDebugFrames(self: *Session) void {
        for (self.pending_debug_frames.items) |payload| self.allocator.free(payload);
        self.pending_debug_frames.deinit(self.allocator);
        self.pending_debug_frames = .{};
    }
};

fn isTerminalJobState(state: chat_job_index.JobState) bool {
    return state == .done or state == .failed;
}

fn jobStateLabel(state: chat_job_index.JobState) []const u8 {
    return switch (state) {
        .queued => "queued",
        .running => "running",
        .done => "done",
        .failed => "failed",
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

test "fsrpc_session: attach walk open read capability help" {
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

test "fsrpc_session: events wait returns next completed chat job" {
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
        "{\"paths\":[\"/agents/self/chat/control/input\"],\"timeout_ms\":0}",
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
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"source_path\":\"/agents/self/chat/control/input\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"event_path\":\"/agents/self/jobs/job-") != null);
    try std.testing.expect(std.mem.indexOf(u8, next_payload, "\"job_id\":\"job-") != null);
}

test "fsrpc_session: events wait reports timeout when no source event is available" {
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
        "{\"paths\":[\"/agents/self/jobs/job-missing/status.json\"],\"timeout_ms\":0}",
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

test "fsrpc_session: blocking read on job status waits for terminal state" {
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
        .delay_ms = 200,
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
    try std.testing.expect(elapsed_ms >= 120);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"done\"") != null);
}

test "fsrpc_session: blocking read on job result waits for terminal payload" {
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

test "fsrpc_session: debug pairing queue supports refresh approve deny actions" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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

test "fsrpc_session: debug pairing invites support create and refresh actions" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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

test "fsrpc_session: setRuntimeBinding reseeds namespace and clears stale state" {
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

test "fsrpc_session: node services namespace exposes service descriptors" {
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
    const services_root = session.lookupChild(local_node, "services") orelse return error.TestExpectedResponse;
    const services_index_id = session.lookupChild(services_root, "SERVICES.json") orelse return error.TestExpectedResponse;
    const fs_service = session.lookupChild(services_root, "fs") orelse return error.TestExpectedResponse;
    const terminal_service = session.lookupChild(services_root, "terminal-1") orelse return error.TestExpectedResponse;

    const fs_status = session.lookupChild(fs_service, "STATUS.json") orelse return error.TestExpectedResponse;
    const fs_caps = session.lookupChild(fs_service, "CAPS.json") orelse return error.TestExpectedResponse;
    const terminal_caps = session.lookupChild(terminal_service, "CAPS.json") orelse return error.TestExpectedResponse;
    const agents_root = session.lookupChild(session.root_id, "agents") orelse return error.TestExpectedResponse;
    const self_agent = session.lookupChild(agents_root, "self") orelse return error.TestExpectedResponse;
    const self_services_dir = session.lookupChild(self_agent, "services") orelse return error.TestExpectedResponse;
    const self_services_index_id = session.lookupChild(self_services_dir, "SERVICES.json") orelse return error.TestExpectedResponse;

    const fs_status_node = session.nodes.get(fs_status) orelse return error.TestExpectedResponse;
    const fs_caps_node = session.nodes.get(fs_caps) orelse return error.TestExpectedResponse;
    const terminal_caps_node = session.nodes.get(terminal_caps) orelse return error.TestExpectedResponse;
    const node_status_node = session.nodes.get(node_status) orelse return error.TestExpectedResponse;
    const services_index_node = session.nodes.get(services_index_id) orelse return error.TestExpectedResponse;
    const self_services_index_node = session.nodes.get(self_services_index_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, node_status_node.content, "\"state\":\"configured\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index_node.content, "\"service_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index_node.content, "\"service_id\":\"terminal-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_status_node.content, "\"state\":\"online\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_status_node.content, "/nodes/local/fs") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_caps_node.content, "\"rw\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, terminal_caps_node.content, "\"terminal_id\":\"1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"node_id\":\"local\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"service_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"service_path\":\"/nodes/local/services/fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index_node.content, "\"has_invoke\":false") != null);
}

test "fsrpc_session: protocol read exposes agent services discovery index" {
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
        &.{ "agents", "self", "services", "SERVICES.json" },
        770,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"node_id\":\"local\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_path\":\"/nodes/local/services/fs\"") != null);
}

test "fsrpc_session: agent services index includes memory and web_search contracts" {
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
        &.{ "agents", "self", "services", "SERVICES.json" },
        780,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_id\":\"memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_id\":\"web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_path\":\"/agents/self/services/contracts/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"agent_contract\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/agents/self/services/contracts/memory/control/invoke.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"has_invoke\":true") != null);
}

test "fsrpc_session: memory contract invoke bridge executes tool and updates status/result files" {
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
        104,
        105,
        &.{ "agents", "self", "services", "contracts", "memory", "control", "invoke.json" },
        "{\"tool_name\":\"memory_create\",\"arguments\":{\"name\":\"contract-memory\",\"kind\":\"note\",\"content\":{\"text\":\"bridge ok\"}}}",
        790,
    );

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        106,
        107,
        &.{ "agents", "self", "services", "contracts", "memory", "result.json" },
        800,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"mem_id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"name\":\"contract-memory\"") != null);

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        108,
        109,
        &.{ "agents", "self", "services", "contracts", "memory", "status.json" },
        810,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"tool\":\"memory_create\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"error\":null") != null);
}

test "fsrpc_session: agent services index includes first-class memory namespace entry" {
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
        &.{ "agents", "self", "services", "SERVICES.json" },
        820,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"agent_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_path\":\"/agents/self/memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/agents/self/memory/control/invoke.json\"") != null);
}

test "fsrpc_session: agent services index includes first-class web_search namespace entry" {
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
        &.{ "agents", "self", "services", "SERVICES.json" },
        855,
    );
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"scope\":\"agent_namespace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"service_path\":\"/agents/self/web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"invoke_path\":\"/agents/self/web_search/control/invoke.json\"") != null);
}

test "fsrpc_session: first-class memory namespace operation file maps to runtime tool" {
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
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"mem_id\"") != null);
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

test "fsrpc_session: first-class web_search namespace operation file maps to runtime tool" {
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

test "fsrpc_session: first-class memory namespace enforces operation tool mapping" {
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
        &.{ "agents", "self", "memory", "control", "create.json" },
        "{\"tool_name\":\"memory_load\",\"arguments\":{\"mem_id\":\"any\"}}",
        859,
        "invalid",
    );
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "invoke payload must include tool/tool_name/op") != null);
}

test "fsrpc_session: first-class memory namespace rejects non-memory tools on invoke" {
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
    try std.testing.expect(std.mem.indexOf(u8, response, "invoke payload must include tool/tool_name/op") != null);
}

test "fsrpc_session: first-class namespace invoke honors PERMISSIONS policy" {
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
    try std.testing.expect(std.mem.indexOf(u8, response, "invoke access denied by permissions") != null);
}

test "fsrpc_session: web_search contract invoke accepts query payload and updates state/result" {
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
        &.{ "agents", "self", "services", "contracts", "web_search", "control", "invoke.json" },
        "{\"query\":\"zig language\"}",
        860,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        120,
        121,
        &.{ "agents", "self", "services", "contracts", "web_search", "status.json" },
        870,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"tool\":\"web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"idle\"") == null);

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        122,
        123,
        &.{ "agents", "self", "services", "contracts", "web_search", "result.json" },
        880,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(result_payload.len > 2);
    try std.testing.expect(result_payload[0] == '{');
}

test "fsrpc_session: web_search contract invoke rejects invalid payload envelope" {
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
        124,
        125,
        &.{ "agents", "self", "services", "contracts", "web_search", "control", "invoke.json" },
        "{bad-json",
        890,
        "invalid",
    );
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "invoke payload must include tool/tool_name/op") != null);
}

test "fsrpc_session: web_search contract invoke surfaces runtime tool errors in status/result" {
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
        126,
        127,
        &.{ "agents", "self", "services", "contracts", "web_search", "control", "invoke.json" },
        "{\"tool_name\":\"web_search\",\"arguments\":{\"query\":123}}",
        900,
    );

    const status_payload = try protocolReadFile(
        &session,
        allocator,
        128,
        129,
        &.{ "agents", "self", "services", "contracts", "web_search", "status.json" },
        910,
    );
    defer allocator.free(status_payload);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"state\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"tool\":\"web_search\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_payload, "\"error\":null") == null);

    const result_payload = try protocolReadFile(
        &session,
        allocator,
        130,
        131,
        &.{ "agents", "self", "services", "contracts", "web_search", "result.json" },
        920,
    );
    defer allocator.free(result_payload);
    try std.testing.expect(std.mem.indexOf(u8, result_payload, "\"error\"") != null);
}

test "fsrpc_session: node services namespace prefers control-plane catalog" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"terminal-9\",\"kind\":\"terminal\",\"version\":\"1\",\"state\":\"degraded\",\"endpoints\":[\"/nodes/{s}/terminal/9\"],\"capabilities\":{{\"pty\":true,\"terminal_id\":\"9\"}}}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeServiceUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-test", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_dir);

    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-test\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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
    const services_root = session.lookupChild(node_dir, "services") orelse return error.TestExpectedResponse;
    const services_index_id = session.lookupChild(services_root, "SERVICES.json") orelse return error.TestExpectedResponse;
    const services_index = session.nodes.get(services_index_id) orelse return error.TestExpectedResponse;
    const terminal = session.lookupChild(services_root, "terminal-9") orelse return error.TestExpectedResponse;
    const status_id = session.lookupChild(terminal, "STATUS.json") orelse return error.TestExpectedResponse;
    const status_node = session.nodes.get(status_id) orelse return error.TestExpectedResponse;
    const caps_id = session.lookupChild(terminal, "CAPS.json") orelse return error.TestExpectedResponse;
    const caps_node = session.nodes.get(caps_id) orelse return error.TestExpectedResponse;
    const agents_root = session.lookupChild(session.root_id, "agents") orelse return error.TestExpectedResponse;
    const self_agent = session.lookupChild(agents_root, "self") orelse return error.TestExpectedResponse;
    const self_services_dir = session.lookupChild(self_agent, "services") orelse return error.TestExpectedResponse;
    const self_services_index_id = session.lookupChild(self_services_dir, "SERVICES.json") orelse return error.TestExpectedResponse;
    const self_services_index = session.nodes.get(self_services_index_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"fs\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"terminal\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index.content, "\"service_id\":\"terminal-9\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_node.content, "\"state\":\"degraded\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, caps_node.content, "\"terminal_id\":\"9\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index.content, "\"node_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, self_services_index.content, "\"service_id\":\"terminal-9\"") != null);
}

test "fsrpc_session: empty control-plane service catalog suppresses policy fallback roots" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[]}}",
        .{ escaped_node_id, escaped_node_secret },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeServiceUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-empty", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_dir);

    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-empty\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[\"1\"]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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
    const services_root = session.lookupChild(node_dir, "services") orelse return error.TestExpectedResponse;
    const services_index_id = session.lookupChild(services_root, "SERVICES.json") orelse return error.TestExpectedResponse;
    const services_index = session.nodes.get(services_index_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(session.lookupChild(services_root, "fs") == null);
    try std.testing.expect(session.lookupChild(services_root, "terminal-1") == null);
    try std.testing.expect(session.lookupChild(node_dir, "fs") == null);
    try std.testing.expect(session.lookupChild(node_dir, "terminal") == null);
    try std.testing.expect(std.mem.eql(u8, services_index.content, "[]"));
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"fs\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"terminal\":false") != null);
}

test "fsrpc_session: project meta includes control-plane workspace status" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-meta", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const created_project = try control_plane.createProject("{\"name\":\"MetaWorldFS\"}");
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
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ projects_dir, project_id.string });
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_dir);

    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[{{\"name\":\"{s}::fs\",\"node_id\":\"{s}\",\"resource\":\"fs\"}}]}}",
        .{ escaped_project_id, escaped_node_id, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"name\":\"self\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"target\":\"/agents/self\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"name\":\"default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"target\":\"/agents/default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"version\":\"acheron-worldfs-project-contract-v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"project_dirs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"meta_files\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"sources.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"project_root\":\"/projects/") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"fs_root\":\"/projects/") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"nodes\":\"/nodes\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"workspace_status\":\"control_plane\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_mount_links\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_node_links\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary_node.content, "\"project_agent_links\":2") != null);
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

test "fsrpc_session: project workspace mount nodes are discovered outside policy" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-discovered", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const created_project = try control_plane.createProject("{\"name\":\"DiscoveredNodeProject\"}");
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
    const discovered_node_dir = session.lookupChild(nodes_root, node_id.string) orelse return error.TestExpectedResponse;
    const discovered_fs = session.lookupChild(discovered_node_dir, "fs") orelse return error.TestExpectedResponse;
    _ = discovered_fs;
    const discovered_readme_id = session.lookupChild(discovered_node_dir, "README.md") orelse return error.TestExpectedResponse;
    const discovered_status_id = session.lookupChild(discovered_node_dir, "STATUS.json") orelse return error.TestExpectedResponse;
    const discovered_node_meta_id = session.lookupChild(discovered_node_dir, "NODE.json") orelse return error.TestExpectedResponse;
    const discovered_readme = session.nodes.get(discovered_readme_id) orelse return error.TestExpectedResponse;
    const discovered_status = session.nodes.get(discovered_status_id) orelse return error.TestExpectedResponse;
    const discovered_node_meta = session.nodes.get(discovered_node_meta_id) orelse return error.TestExpectedResponse;

    const projects_root = session.lookupChild(session.root_id, "projects") orelse return error.TestExpectedResponse;
    const project_node = session.lookupChild(projects_root, project_id.string) orelse return error.TestExpectedResponse;
    const project_fs_node = session.lookupChild(project_node, "fs") orelse return error.TestExpectedResponse;
    const mount_link_id = session.lookupChild(project_fs_node, "mount::code") orelse return error.TestExpectedResponse;
    const mount_link_node = session.nodes.get(mount_link_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, discovered_readme.content, "discovered from live project workspace mounts") != null);
    try std.testing.expect(std.mem.indexOf(u8, discovered_status.content, "\"state\":\"online\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, discovered_status.content, "\"source\":\"control_plane\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, discovered_node_meta.content, "\"node\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, discovered_node_meta.content, node_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/fs") != null);
}

test "fsrpc_session: project meta summary and alerts reflect degraded and missing mounts" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-alerts", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const created_project = try control_plane.createProject("{\"name\":\"ProjectAlertsState\"}");
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
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ projects_dir, project_id.string });
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_dir);

    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[{{\"name\":\"{s}::fs\",\"node_id\":\"{s}\",\"resource\":\"fs\"}}]}}",
        .{ escaped_project_id, escaped_node_id, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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

test "fsrpc_session: project workspace fallback is scoped to requested project" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
    defer control_plane.deinit();

    const ensured = try control_plane.ensureNode("edge-leak-test", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(ensured);
    var ensured_parsed = try std.json.parseFromSlice(std.json.Value, allocator, ensured, .{});
    defer ensured_parsed.deinit();
    if (ensured_parsed.value != .object) return error.TestExpectedResponse;
    const node_id = ensured_parsed.value.object.get("node_id") orelse return error.TestExpectedResponse;
    if (node_id != .string) return error.TestExpectedResponse;

    const project_a = try control_plane.createProject("{\"name\":\"ScopedA\"}");
    defer allocator.free(project_a);
    var project_a_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_a, .{});
    defer project_a_parsed.deinit();
    if (project_a_parsed.value != .object) return error.TestExpectedResponse;
    const project_a_id = project_a_parsed.value.object.get("project_id") orelse return error.TestExpectedResponse;
    if (project_a_id != .string) return error.TestExpectedResponse;

    const project_b = try control_plane.createProject("{\"name\":\"ScopedB\"}");
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
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_a_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ projects_dir, project_a_id.string });
    defer allocator.free(project_a_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_a_dir);

    const escaped_project_a_id = try unified.jsonEscape(allocator, project_a_id.string);
    defer allocator.free(escaped_project_a_id);
    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"nodes\":[{{\"id\":\"local\",\"resources\":{{\"fs\":true,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[\"1\"]}}],\"visible_agents\":[\"default\"],\"project_links\":[{{\"name\":\"local::fs\",\"node_id\":\"local\",\"resource\":\"fs\"}}]}}",
        .{escaped_project_a_id},
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"name\":\"self\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"target\":\"/agents/self\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"name\":\"default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_meta_node.content, "\"target\":\"/agents/default\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"version\":\"acheron-worldfs-project-contract-v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"project_id\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, project_a_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, contracts_node.content, "\"meta_files\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"project_root\":\"/projects/") != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, project_a_id.string) != null);
    try std.testing.expect(std.mem.indexOf(u8, paths_node.content, "\"global\":") != null);
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

test "fsrpc_session: node roots are derived from control-plane service kinds" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"camera\",\"kind\":\"camera\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/camera\"],\"capabilities\":{{\"still\":true}}}},{{\"service_id\":\"terminal-3\",\"kind\":\"terminal\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/terminal/3\"],\"capabilities\":{{\"pty\":true}}}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeServiceUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-roots", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_dir);

    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-roots\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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

test "fsrpc_session: control-plane mounts expose custom node roots and metadata files" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"gdrive-main\",\"kind\":\"gdrive\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/services/gdrive-main\"],\"capabilities\":{{\"provider\":\"google\"}},\"mounts\":[{{\"mount_id\":\"drive-main\",\"mount_path\":\"/nodes/{s}/drive/main\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-mount\"}},\"help_md\":\"Google Drive namespace mount\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeServiceUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-custom-mounts", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_dir);

    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-custom-mounts\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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
    const services_root = session.lookupChild(node_dir, "services") orelse return error.TestExpectedResponse;
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

test "fsrpc_session: service permissions enforce deny-by-default with admin bypass" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"secure-main\",\"kind\":\"secure\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/secure/main\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"secure-main\",\"mount_path\":\"/nodes/{s}/secure/main\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"deny-by-default\"}},\"schema\":{{\"model\":\"namespace-mount\"}},\"help_md\":\"Secure namespace mount\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeServiceUpsert(upsert_req);
    defer allocator.free(upserted);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const agents_dir = try std.fmt.allocPrint(allocator, "{s}/agents", .{root});
    defer allocator.free(agents_dir);
    const projects_dir = try std.fmt.allocPrint(allocator, "{s}/projects", .{root});
    defer allocator.free(projects_dir);
    const agent_policy_dir = try std.fmt.allocPrint(allocator, "{s}/default", .{agents_dir});
    defer allocator.free(agent_policy_dir);
    const project_dir = try std.fmt.allocPrint(allocator, "{s}/proj-secure", .{projects_dir});
    defer allocator.free(project_dir);
    try std.fs.cwd().makePath(agent_policy_dir);
    try std.fs.cwd().makePath(project_dir);

    const agent_policy_path = try std.fmt.allocPrint(allocator, "{s}/agent_policy.json", .{agent_policy_dir});
    defer allocator.free(agent_policy_path);
    const agent_policy_json = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"proj-secure\",\"nodes\":[{{\"id\":\"{s}\",\"resources\":{{\"fs\":false,\"camera\":false,\"screen\":false,\"user\":false}},\"terminals\":[]}}],\"visible_agents\":[\"default\"],\"project_links\":[]}}",
        .{escaped_node_id},
    );
    defer allocator.free(agent_policy_json);
    try std.fs.cwd().writeFile(.{
        .sub_path = agent_policy_path,
        .data = agent_policy_json,
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
    const user_services_root = user_session.lookupChild(user_node_dir, "services") orelse return error.TestExpectedResponse;
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
    const admin_services_root = admin_session.lookupChild(admin_node_dir, "services") orelse return error.TestExpectedResponse;
    try std.testing.expect(admin_session.lookupChild(admin_services_root, "secure-main") != null);
    try std.testing.expect(admin_session.lookupChild(admin_node_dir, "secure") != null);
}

test "fsrpc_session: project access policy gates invoke visibility per agent" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"tool-main\",\"kind\":\"tool\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/tool/main\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"tool-main\",\"mount_path\":\"/nodes/{s}/tool/main\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\"}},\"runtime\":{{\"type\":\"native_proc\"}},\"permissions\":{{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Policy-gated invoke service\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeServiceUpsert(upsert_req);
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
    const default_services_root = default_session.lookupChild(default_node_dir, "services") orelse return error.TestExpectedResponse;
    try std.testing.expect(default_session.lookupChild(default_services_root, "tool-main") == null);
    try std.testing.expect(default_session.lookupChild(default_node_dir, "tool") == null);
    const default_index_payload = try protocolReadFile(
        &default_session,
        allocator,
        220,
        221,
        &.{ "agents", "self", "services", "SERVICES.json" },
        830,
    );
    defer allocator.free(default_index_payload);
    try std.testing.expect(std.mem.indexOf(u8, default_index_payload, "\"service_id\":\"tool-main\"") == null);

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
    const worker_services_root = worker_session.lookupChild(worker_node_dir, "services") orelse return error.TestExpectedResponse;
    try std.testing.expect(worker_session.lookupChild(worker_services_root, "tool-main") != null);
    try std.testing.expect(worker_session.lookupChild(worker_node_dir, "tool") != null);
    const worker_index_payload = try protocolReadFile(
        &worker_session,
        allocator,
        222,
        223,
        &.{ "agents", "self", "services", "SERVICES.json" },
        840,
    );
    defer allocator.free(worker_index_payload);
    const expected_invoke_path = try std.fmt.allocPrint(
        allocator,
        "\"invoke_path\":\"/nodes/{s}/tool/main/control/invoke.json\"",
        .{node_id.string},
    );
    defer allocator.free(expected_invoke_path);
    try std.testing.expect(std.mem.indexOf(u8, worker_index_payload, "\"service_id\":\"tool-main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, worker_index_payload, "\"has_invoke\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, worker_index_payload, expected_invoke_path) != null);
}

test "fsrpc_session: control-plane registered nodes appear under global nodes namespace" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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

test "fsrpc_session: global nodes directory discovers late control-plane nodes on read" {
    const allocator = std.testing.allocator;

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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

test "fsrpc_session: pairing catalog visibility and node invoke integration flow" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const spiderweb_node = @import("spiderweb_node");

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"echo-main\",\"kind\":\"utility\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/echo\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"echo-main\",\"mount_path\":\"/nodes/{s}/echo\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"style\":\"plan9\"}},\"runtime\":{{\"type\":\"native_proc\",\"abi\":\"namespace-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Echo integration service\"}}]}}",
        .{ escaped_node_id, escaped_node_secret, escaped_node_id, escaped_node_id },
    );
    defer allocator.free(upsert_req);
    const upserted = try control_plane.nodeServiceUpsert(upsert_req);
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
    const services_root = session.lookupChild(node_dir, "services") orelse return error.TestExpectedResponse;
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
                .namespace_service = .{
                    .service_id = "echo-main",
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

test "fsrpc_session: multi-node discovery invoke supervision reconnect flow" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const spiderweb_node = @import("spiderweb_node");

    var control_plane = fs_control_plane.ControlPlane.init(allocator);
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
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"echo-main\",\"kind\":\"utility\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/echo\"],\"capabilities\":{{\"invoke\":true}},\"mounts\":[{{\"mount_id\":\"echo-main\",\"mount_path\":\"/nodes/{s}/echo\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"style\":\"plan9\"}},\"runtime\":{{\"type\":\"native_proc\",\"abi\":\"namespace-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Echo main service\"}}]}}",
        .{ escaped_alpha_id, escaped_alpha_secret, escaped_alpha_id, escaped_alpha_id },
    );
    defer allocator.free(alpha_upsert);
    const alpha_upserted = try control_plane.nodeServiceUpsert(alpha_upsert);
    defer allocator.free(alpha_upserted);

    const beta_upsert = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"services\":[{{\"service_id\":\"fail-main\",\"kind\":\"utility\",\"version\":\"1\",\"state\":\"online\",\"endpoints\":[\"/nodes/{s}/fail\"],\"capabilities\":{{\"invoke\":true,\"supervision\":true}},\"mounts\":[{{\"mount_id\":\"fail-main\",\"mount_path\":\"/nodes/{s}/fail\",\"state\":\"online\"}}],\"ops\":{{\"model\":\"namespace\",\"style\":\"plan9\"}},\"runtime\":{{\"type\":\"native_proc\",\"abi\":\"namespace-driver-v1\"}},\"permissions\":{{\"default\":\"deny-by-default\",\"allow_roles\":[\"admin\",\"user\"]}},\"schema\":{{\"model\":\"namespace-service-v1\"}},\"help_md\":\"Failing service\"}}]}}",
        .{ escaped_beta_id, escaped_beta_secret, escaped_beta_id, escaped_beta_id },
    );
    defer allocator.free(beta_upsert);
    const beta_upserted = try control_plane.nodeServiceUpsert(beta_upsert);
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
    const alpha_services = discovered_session.lookupChild(alpha_dir, "services") orelse return error.TestExpectedResponse;
    const beta_services = discovered_session.lookupChild(beta_dir, "services") orelse return error.TestExpectedResponse;
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
                .namespace_service = .{
                    .service_id = "fail-main",
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
