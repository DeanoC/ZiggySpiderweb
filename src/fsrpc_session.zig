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
};

const WriteOutcome = struct {
    written: usize,
    job_name: ?[]u8 = null,
    correlation_id: ?[]u8 = null,
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

    nodes: std.AutoHashMapUnmanaged(u32, Node) = .{},
    fids: std.AutoHashMapUnmanaged(u32, FidState) = .{},
    pending_debug_frames: std.ArrayListUnmanaged([]u8) = .{},
    debug_stream_enabled: bool = false,

    next_node_id: u32 = 1,

    root_id: u32 = 0,
    jobs_root_id: u32 = 0,
    chat_input_id: u32 = 0,

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
        };
        try self.seedNamespace();
        return self;
    }

    pub fn deinit(self: *Session) void {
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

        var data_owned: ?[]u8 = null;
        defer if (data_owned) |value| self.allocator.free(value);

        const data = switch (node.kind) {
            .dir => blk: {
                data_owned = try self.renderDirListing(state.node_id);
                break :blk data_owned.?;
            },
            .file => node.content,
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

        for (policy.nodes.items) |node| try self.addNodeDirectory(nodes_root, node, false);

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

        self.jobs_root_id = try self.addDir(self_agent_dir, "jobs", false);
        try self.addDirectoryDescriptors(
            self.jobs_root_id,
            "Jobs",
            "{\"kind\":\"collection\",\"entries\":\"job_id\",\"files\":[\"status.json\",\"result.txt\",\"log.txt\"]}",
            "{\"read\":true,\"write\":false}",
            "Chat job status and outputs.",
        );
        try self.seedJobsFromIndex();

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
        const project_agents_dir = try self.addDir(project_dir, "agents", false);
        const project_meta_dir = try self.addDir(project_dir, "meta", false);
        try self.addDirectoryDescriptors(
            project_dir,
            "Project",
            "{\"kind\":\"project\",\"children\":[\"fs\",\"agents\",\"meta\"]}",
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
            project_agents_dir,
            "Project Agents",
            "{\"kind\":\"collection\",\"entries\":\"agent links\",\"self\":\"/agents/self\"}",
            "{\"read\":true,\"write\":false}",
            "Agent links visible within this project context.",
        );
        try self.addDirectoryDescriptors(
            project_meta_dir,
            "Project Metadata",
            "{\"kind\":\"metadata\",\"files\":[\"topology.json\",\"workspace_status.json\",\"mounts.json\",\"desired_mounts.json\",\"actual_mounts.json\",\"drift.json\",\"reconcile.json\",\"availability.json\",\"health.json\"]}",
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

        _ = try self.addFile(project_agents_dir, "self", "/agents/self\n", false, .none);
        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
            const target = try std.fmt.allocPrint(self.allocator, "/agents/{s}\n", .{agent_name});
            defer self.allocator.free(target);
            _ = try self.addFile(project_agents_dir, agent_name, target, false, .none);
        }

        try self.addProjectMetaFiles(project_meta_dir, policy, workspace_status_json);

        if (debug_root) |dir_id| {
            try self.addDirectoryDescriptors(
                dir_id,
                "Debug",
                "{\"kind\":\"debug\",\"entries\":[\"README.md\",\"stream.log\"]}",
                "{\"read\":true,\"write\":false}",
                "Privileged debug surface.",
            );
            _ = try self.addFile(dir_id, "stream.log", "", false, .none);
        }

        try self.addDirectoryDescriptors(
            meta_root,
            "Meta",
            "{\"kind\":\"meta\",\"entries\":[\"protocol.json\",\"view.json\"]}",
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
    }

    fn addProjectMetaFiles(
        self: *Session,
        project_meta_dir: u32,
        policy: world_policy.Policy,
        workspace_status_json: ?[]const u8,
    ) !void {
        const topology_json = try self.buildProjectTopologyJson(policy);
        defer self.allocator.free(topology_json);
        _ = try self.addFile(project_meta_dir, "topology.json", topology_json, false, .none);

        if (workspace_status_json) |status_json| {
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
        _ = try self.addFile(project_meta_dir, "workspace_status.json", fallback_status, false, .none);
        _ = try self.addFile(project_meta_dir, "mounts.json", "[]", false, .none);
        _ = try self.addFile(project_meta_dir, "desired_mounts.json", "[]", false, .none);
        _ = try self.addFile(project_meta_dir, "actual_mounts.json", "[]", false, .none);
        _ = try self.addFile(project_meta_dir, "drift.json", "{\"count\":0,\"items\":[]}", false, .none);
        _ = try self.addFile(project_meta_dir, "reconcile.json", "{\"reconcile_state\":\"unknown\",\"last_reconcile_ms\":0,\"last_success_ms\":0,\"last_error\":null,\"queue_depth\":0}", false, .none);
        _ = try self.addFile(project_meta_dir, "availability.json", "{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0}", false, .none);
        _ = try self.addFile(project_meta_dir, "health.json", "{\"state\":\"unknown\",\"availability\":{\"mounts_total\":0,\"online\":0,\"degraded\":0,\"missing\":0},\"drift_count\":0,\"reconcile_state\":\"unknown\",\"queue_depth\":0}", false, .none);
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

        const node_schema = "{\"kind\":\"node\",\"children\":[\"services\",\"fs\",\"camera\",\"screen\",\"user\",\"terminal\"]}";
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

        if (resource_view.fs) _ = try self.addDir(node_dir, "fs", false);
        if (resource_view.camera) _ = try self.addDir(node_dir, "camera", false);
        if (resource_view.screen) _ = try self.addDir(node_dir, "screen", false);
        if (resource_view.user) _ = try self.addDir(node_dir, "user", false);
        if (resource_view.terminals.items.len > 0) {
            const terminal_root = try self.addDir(node_dir, "terminal", false);
            for (resource_view.terminals.items) |terminal_id| {
                _ = try self.addDir(terminal_root, terminal_id, false);
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

        fn deinit(self: *NodeResourceView, allocator: std.mem.Allocator) void {
            for (self.terminals.items) |terminal_id| allocator.free(terminal_id);
            self.terminals.deinit(allocator);
            self.* = undefined;
        }

        fn observe(self: *NodeResourceView, allocator: std.mem.Allocator, kind: []const u8, service_id: []const u8, endpoint: []const u8) !void {
            if (std.mem.eql(u8, kind, "fs")) {
                self.fs = true;
                return;
            }
            if (std.mem.eql(u8, kind, "camera")) {
                self.camera = true;
                return;
            }
            if (std.mem.eql(u8, kind, "screen")) {
                self.screen = true;
                return;
            }
            if (std.mem.eql(u8, kind, "user")) {
                self.user = true;
                return;
            }
            if (!std.mem.eql(u8, kind, "terminal")) return;

            const maybe_terminal_id = if (std.mem.startsWith(u8, service_id, "terminal-") and service_id.len > "terminal-".len)
                service_id["terminal-".len..]
            else
                terminalIdFromEndpoint(endpoint);
            const terminal_id = maybe_terminal_id orelse return;
            if (terminal_id.len == 0) return;
            for (self.terminals.items) |existing| {
                if (std.mem.eql(u8, existing, terminal_id)) return;
            }
            try self.terminals.append(allocator, try allocator.dupe(u8, terminal_id));
        }
    };

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
            "{\"kind\":\"collection\",\"entries\":\"service_id\",\"shape\":\"/nodes/<node_id>/services/<service_id>/{SCHEMA.json,STATUS.json,CAPS.json}\"}",
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
                    try self.addNodeServiceEntry(
                        services_root,
                        service.service_id,
                        service.kind,
                        service.state,
                        service.endpoint,
                        service.caps_json,
                    );
                    try view.observe(self.allocator, service.kind, service.service_id, service.endpoint);
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
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/fs", .{node.id});
            defer self.allocator.free(endpoint);
            try self.addNodeServiceEntry(services_root, "fs", "fs", "online", endpoint, caps);
            try view.observe(self.allocator, "fs", "fs", endpoint);
            try self.appendServiceIndexEntry(&services_index, &services_index_first, "fs", "fs", "online", endpoint);
        }
        if (node.resources.camera) {
            const caps = "{\"still\":true}";
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/camera", .{node.id});
            defer self.allocator.free(endpoint);
            try self.addNodeServiceEntry(services_root, "camera", "camera", "online", endpoint, caps);
            try view.observe(self.allocator, "camera", "camera", endpoint);
            try self.appendServiceIndexEntry(&services_index, &services_index_first, "camera", "camera", "online", endpoint);
        }
        if (node.resources.screen) {
            const caps = "{\"capture\":true}";
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/screen", .{node.id});
            defer self.allocator.free(endpoint);
            try self.addNodeServiceEntry(services_root, "screen", "screen", "online", endpoint, caps);
            try view.observe(self.allocator, "screen", "screen", endpoint);
            try self.appendServiceIndexEntry(&services_index, &services_index_first, "screen", "screen", "online", endpoint);
        }
        if (node.resources.user) {
            const caps = "{\"interaction\":true}";
            const endpoint = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/user", .{node.id});
            defer self.allocator.free(endpoint);
            try self.addNodeServiceEntry(services_root, "user", "user", "online", endpoint, caps);
            try view.observe(self.allocator, "user", "user", endpoint);
            try self.appendServiceIndexEntry(&services_index, &services_index_first, "user", "user", "online", endpoint);
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
            try self.addNodeServiceEntry(services_root, service_id, "terminal", "online", endpoint, caps);
            try view.observe(self.allocator, "terminal", service_id, endpoint);
            try self.appendServiceIndexEntry(&services_index, &services_index_first, service_id, "terminal", "online", endpoint);
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

            fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
                allocator.free(self.service_id);
                allocator.free(self.kind);
                allocator.free(self.state);
                allocator.free(self.endpoint);
                allocator.free(self.caps_json);
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

            try catalog.items.append(self.allocator, .{
                .service_id = try self.allocator.dupe(u8, service_id_val.string),
                .kind = try self.allocator.dupe(u8, kind_val.string),
                .state = try self.allocator.dupe(u8, state),
                .endpoint = resolved_endpoint,
                .caps_json = caps_json,
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

        const schema = try std.fmt.allocPrint(
            self.allocator,
            "{{\"service_id\":\"{s}\",\"kind\":\"{s}\",\"version\":\"1\",\"endpoint\":\"{s}\"}}",
            .{ escaped_service_id, escaped_kind, escaped_endpoint },
        );
        defer self.allocator.free(schema);
        const readme = try std.fmt.allocPrint(
            self.allocator,
            "# Service `{s}`\n\nService metadata for this node capability.\n",
            .{service_id},
        );
        defer self.allocator.free(readme);
        _ = try self.addFile(service_dir, "README.md", readme, false, .none);
        _ = try self.addFile(service_dir, "SCHEMA.json", schema, false, .none);
        _ = try self.addFile(service_dir, "CAPS.json", caps_json, false, .none);

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

    fn clearPendingDebugFrames(self: *Session) void {
        for (self.pending_debug_frames.items) |payload| self.allocator.free(payload);
        self.pending_debug_frames.deinit(self.allocator);
        self.pending_debug_frames = .{};
    }
};

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

    const fs_status_node = session.nodes.get(fs_status) orelse return error.TestExpectedResponse;
    const fs_caps_node = session.nodes.get(fs_caps) orelse return error.TestExpectedResponse;
    const terminal_caps_node = session.nodes.get(terminal_caps) orelse return error.TestExpectedResponse;
    const node_status_node = session.nodes.get(node_status) orelse return error.TestExpectedResponse;
    const services_index_node = session.nodes.get(services_index_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, node_status_node.content, "\"state\":\"configured\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index_node.content, "\"service_id\":\"fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index_node.content, "\"service_id\":\"terminal-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_status_node.content, "\"state\":\"online\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_status_node.content, "/nodes/local/fs") != null);
    try std.testing.expect(std.mem.indexOf(u8, fs_caps_node.content, "\"rw\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, terminal_caps_node.content, "\"terminal_id\":\"1\"") != null);
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

    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"fs\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, node_caps.content, "\"terminal\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, services_index.content, "\"service_id\":\"terminal-9\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_node.content, "\"state\":\"degraded\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, caps_node.content, "\"terminal_id\":\"9\"") != null);
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
    const project_fs_schema_id = session.lookupChild(project_fs_node, "SCHEMA.json") orelse return error.TestExpectedResponse;
    const project_agents_node = session.lookupChild(project_node, "agents") orelse return error.TestExpectedResponse;
    const project_agents_caps_id = session.lookupChild(project_agents_node, "CAPS.json") orelse return error.TestExpectedResponse;
    const meta_node = session.lookupChild(project_node, "meta") orelse return error.TestExpectedResponse;
    const meta_schema_id = session.lookupChild(meta_node, "SCHEMA.json") orelse return error.TestExpectedResponse;
    const mount_link_id = session.lookupChild(project_fs_node, "mount::src") orelse return error.TestExpectedResponse;
    const topology_id = session.lookupChild(meta_node, "topology.json") orelse return error.TestExpectedResponse;
    const workspace_id = session.lookupChild(meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
    const mounts_id = session.lookupChild(meta_node, "mounts.json") orelse return error.TestExpectedResponse;
    const desired_mounts_id = session.lookupChild(meta_node, "desired_mounts.json") orelse return error.TestExpectedResponse;
    const actual_mounts_id = session.lookupChild(meta_node, "actual_mounts.json") orelse return error.TestExpectedResponse;
    const drift_id = session.lookupChild(meta_node, "drift.json") orelse return error.TestExpectedResponse;
    const reconcile_id = session.lookupChild(meta_node, "reconcile.json") orelse return error.TestExpectedResponse;
    const availability_id = session.lookupChild(meta_node, "availability.json") orelse return error.TestExpectedResponse;
    const health_id = session.lookupChild(meta_node, "health.json") orelse return error.TestExpectedResponse;

    const project_fs_schema = session.nodes.get(project_fs_schema_id) orelse return error.TestExpectedResponse;
    const project_agents_caps = session.nodes.get(project_agents_caps_id) orelse return error.TestExpectedResponse;
    const meta_schema = session.nodes.get(meta_schema_id) orelse return error.TestExpectedResponse;
    const mount_link_node = session.nodes.get(mount_link_id) orelse return error.TestExpectedResponse;
    const topology_node = session.nodes.get(topology_id) orelse return error.TestExpectedResponse;
    const workspace_node = session.nodes.get(workspace_id) orelse return error.TestExpectedResponse;
    const mounts_node = session.nodes.get(mounts_id) orelse return error.TestExpectedResponse;
    const desired_mounts_node = session.nodes.get(desired_mounts_id) orelse return error.TestExpectedResponse;
    const actual_mounts_node = session.nodes.get(actual_mounts_id) orelse return error.TestExpectedResponse;
    const drift_node = session.nodes.get(drift_id) orelse return error.TestExpectedResponse;
    const reconcile_node = session.nodes.get(reconcile_id) orelse return error.TestExpectedResponse;
    const availability_node = session.nodes.get(availability_id) orelse return error.TestExpectedResponse;
    const health_node = session.nodes.get(health_id) orelse return error.TestExpectedResponse;

    try std.testing.expect(std.mem.indexOf(u8, project_fs_schema.content, "\"kind\":\"collection\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, project_agents_caps.content, "\"read\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"workspace_status.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"desired_mounts.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"actual_mounts.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"drift.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"reconcile.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta_schema.content, "\"health.json\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/nodes/") != null);
    try std.testing.expect(std.mem.indexOf(u8, mount_link_node.content, "/fs") != null);
    try std.testing.expect(std.mem.indexOf(u8, topology_node.content, "\"project_links\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, topology_node.content, node_id.string) != null);
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
    const leaked_mount_link = session.lookupChild(project_fs_node, "mount::leak");
    try std.testing.expect(leaked_mount_link == null);

    const meta_node = session.lookupChild(project_node, "meta") orelse return error.TestExpectedResponse;
    const workspace_id = session.lookupChild(meta_node, "workspace_status.json") orelse return error.TestExpectedResponse;
    const mounts_id = session.lookupChild(meta_node, "mounts.json") orelse return error.TestExpectedResponse;
    const desired_mounts_id = session.lookupChild(meta_node, "desired_mounts.json") orelse return error.TestExpectedResponse;
    const actual_mounts_id = session.lookupChild(meta_node, "actual_mounts.json") orelse return error.TestExpectedResponse;
    const drift_id = session.lookupChild(meta_node, "drift.json") orelse return error.TestExpectedResponse;
    const reconcile_id = session.lookupChild(meta_node, "reconcile.json") orelse return error.TestExpectedResponse;
    const health_id = session.lookupChild(meta_node, "health.json") orelse return error.TestExpectedResponse;
    const workspace_node = session.nodes.get(workspace_id) orelse return error.TestExpectedResponse;
    const mounts_node = session.nodes.get(mounts_id) orelse return error.TestExpectedResponse;
    const desired_mounts_node = session.nodes.get(desired_mounts_id) orelse return error.TestExpectedResponse;
    const actual_mounts_node = session.nodes.get(actual_mounts_id) orelse return error.TestExpectedResponse;
    const drift_node = session.nodes.get(drift_id) orelse return error.TestExpectedResponse;
    const reconcile_node = session.nodes.get(reconcile_id) orelse return error.TestExpectedResponse;
    const health_node = session.nodes.get(health_id) orelse return error.TestExpectedResponse;
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
