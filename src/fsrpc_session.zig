const std = @import("std");
const unified = @import("ziggy-spider-protocol").unified;
const runtime_server_mod = @import("runtime_server.zig");
const runtime_handle_mod = @import("runtime_handle.zig");
const chat_job_index = @import("chat_job_index.zig");
const world_policy = @import("world_policy.zig");

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
        agents_dir: []const u8 = "agents",
        projects_dir: []const u8 = "projects",
    };

    allocator: std.mem.Allocator,
    runtime_handle: *runtime_handle_mod.RuntimeHandle,
    job_index: *chat_job_index.ChatJobIndex,
    agent_id: []u8,
    project_id: ?[]u8 = null,
    agents_dir: []u8,
    projects_dir: []u8,

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
            .agents_dir = owned_agents_dir,
            .projects_dir = owned_projects_dir,
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
                .agents_dir = self.agents_dir,
                .projects_dir = self.projects_dir,
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
            "{\"kind\":\"collection\",\"entries\":\"node directories\",\"shape\":\"/nodes/<node_id>/{fs,camera,screen,user,terminal}\"}",
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

        for (policy.nodes.items) |node| {
            const node_dir = try self.addDir(nodes_root, node.id, false);
            const node_schema = "{\"kind\":\"node\",\"resources\":[\"fs\",\"camera\",\"screen\",\"user\",\"terminal\"]}";
            const node_caps = try std.fmt.allocPrint(
                self.allocator,
                "{{\"fs\":{s},\"camera\":{s},\"screen\":{s},\"user\":{s},\"terminal\":{s}}}",
                .{
                    if (node.resources.fs) "true" else "false",
                    if (node.resources.camera) "true" else "false",
                    if (node.resources.screen) "true" else "false",
                    if (node.resources.user) "true" else "false",
                    if (node.terminals.items.len > 0) "true" else "false",
                },
            );
            defer self.allocator.free(node_caps);
            try self.addDirectoryDescriptors(
                node_dir,
                "Node Endpoint",
                node_schema,
                node_caps,
                "Node resource roots. Entries may be unavailable based on policy.",
            );

            if (node.resources.fs) _ = try self.addDir(node_dir, "fs", false);
            if (node.resources.camera) _ = try self.addDir(node_dir, "camera", false);
            if (node.resources.screen) _ = try self.addDir(node_dir, "screen", false);
            if (node.resources.user) _ = try self.addDir(node_dir, "user", false);
            if (node.terminals.items.len > 0) {
                const terminal_root = try self.addDir(node_dir, "terminal", false);
                for (node.terminals.items) |terminal_id| {
                    _ = try self.addDir(terminal_root, terminal_id, false);
                }
            }
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

        for (policy.project_links.items) |link| {
            const target = try std.fmt.allocPrint(self.allocator, "/nodes/{s}/{s}\n", .{ link.node_id, link.resource });
            defer self.allocator.free(target);
            _ = try self.addFile(project_fs_dir, link.name, target, false, .none);
        }

        _ = try self.addFile(project_agents_dir, "self", "/agents/self\n", false, .none);
        for (policy.visible_agents.items) |agent_name| {
            if (std.mem.eql(u8, agent_name, "self")) continue;
            const target = try std.fmt.allocPrint(self.allocator, "/agents/{s}\n", .{agent_name});
            defer self.allocator.free(target);
            _ = try self.addFile(project_agents_dir, agent_name, target, false, .none);
        }

        _ = try self.addFile(project_meta_dir, "README.md", "Project metadata and link topology.\n", false, .none);

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
